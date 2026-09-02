package workloadapi

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	meshattestpb "github.com/spiffe/go-spiffe/v2/proto/hushmesh/workload/v1"
)

// gcmNonceLen is the IV width hmc_encrypt (c-libraries/hushmesh-crypto/hm_crypt.c) prepends to
// every AES-256-GCM ciphertext. The mesh lays a sealed body out as IV || ciphertext || tag, and
// Go's Seal already appends the tag, so only the IV has to be moved by hand.
const gcmNonceLen = 12

// envelopeAAD mirrors EnvelopeAad in actors/actor-spiffe-agent/src/envelope.rs, field for field
// and in order.
//
// The Rust side encodes it with common_types::cbor::to_vec_packed, which is serde_cbor's packed
// format: a struct becomes a CBOR MAP whose keys are the field's ordinal rather than its name,
// and a unit enum variant becomes its variant index. So this is a 4-entry map with integer keys
// 0..3 -- not an array -- and the field ORDER is the contract, because it is what assigns the
// keys. Getting this wrong produces an AEAD failure with nothing else to see.
type envelopeAAD struct {
	GRPCPath        string `cbor:"0,keyasint"`
	Suite           uint32 `cbor:"1,keyasint"`
	RecipientKeyID  []byte `cbor:"2,keyasint"`
	EncapsulatedKey []byte `cbor:"3,keyasint"`
}

func (a envelopeAAD) marshal() ([]byte, error) {
	return cbor.Marshal(a)
}

// envelopeSession is one sealed channel to the mesh's advertised envelope key.
//
// One session per gRPC call. grpcPath is the only part of the binding that separates the two
// enveloped methods, so reusing a session across them would make a sealed body portable between
// them -- the hazard EnvelopeSession::open_request documents on the mesh side.
type envelopeSession struct {
	requestKey             []byte
	responseKey            []byte
	aad                    []byte
	senderECCPublicKeySPKI []byte
	encapsulatedKey        []byte
	recipientKeyID         []byte
}

func establishEnvelopeSession(ad *verifiedAdvertisement, grpcPath string) (*envelopeSession, error) {
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating the ephemeral P-256 key failed: %w", err)
	}
	senderSPKI, err := x509.MarshalPKIXPublicKey(ephemeral.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("encoding the ephemeral P-256 public key as SPKI failed: %w", err)
	}

	remote, err := parseECDHPublicKeySPKI(ad.eccPublicKeySPKI)
	if err != nil {
		return nil, fmt.Errorf("the advertised ECC public key (%d bytes) is unusable: %w", len(ad.eccPublicKeySPKI), err)
	}
	ecdhSecret, err := ephemeral.ECDH(remote)
	if err != nil {
		return nil, fmt.Errorf("ECDH against the advertised key failed: %w", err)
	}

	encapsulationKey, err := mlkem.NewEncapsulationKey768(ad.mlkemPublicKey)
	if err != nil {
		return nil, fmt.Errorf("the advertised ML-KEM-768 public key (%d bytes) is unusable: %w", len(ad.mlkemPublicKey), err)
	}
	mlkemSecret, encapsulatedKey := encapsulationKey.Encapsulate()

	// hmc_create_shared_ecc_mlkem_hybrid_secret, hm_crypt.c: plain concatenation of the raw ECDH
	// X coordinate and the ML-KEM shared secret, then one SHA-256. There is no KDF label here;
	// the direction labels below are what separate the two keys.
	combined := make([]byte, 0, len(ecdhSecret)+len(mlkemSecret))
	combined = append(combined, ecdhSecret...)
	combined = append(combined, mlkemSecret...)
	hybrid := sha256.Sum256(combined)

	aad, err := envelopeAAD{
		GRPCPath:        grpcPath,
		Suite:           envelopeSuiteVariantIndex,
		RecipientKeyID:  ad.keyID,
		EncapsulatedKey: encapsulatedKey,
	}.marshal()
	if err != nil {
		return nil, fmt.Errorf("encoding the envelope AAD failed: %w", err)
	}

	return &envelopeSession{
		requestKey:             meshDeriveKeyFromVec(hybrid[:], envelopeLabelW2M),
		responseKey:            meshDeriveKeyFromVec(hybrid[:], envelopeLabelM2W),
		aad:                    aad,
		senderECCPublicKeySPKI: senderSPKI,
		encapsulatedKey:        encapsulatedKey,
		recipientKeyID:         ad.keyID,
	}, nil
}

func (s *envelopeSession) sealRequest(plaintext []byte) (*meshattestpb.SealedRequest, error) {
	ciphertext, err := meshEncrypt(s.requestKey, plaintext, s.aad)
	if err != nil {
		return nil, err
	}
	return &meshattestpb.SealedRequest{
		Suite:                  envelopeSuiteEccP256MlKem768Aes256Gcm,
		RecipientKeyId:         s.recipientKeyID,
		EncapsulatedKey:        s.encapsulatedKey,
		Ciphertext:             ciphertext,
		SenderEccPublicKeySpki: s.senderECCPublicKeySPKI,
	}, nil
}

// openResponse reuses the request's AAD verbatim. There is no key id or encapsulation on
// SealedResponse to rebuild it from, which is what keeps the response bound to the request that
// established the context rather than to a field a relay could restate.
func (s *envelopeSession) openResponse(ciphertext []byte) ([]byte, error) {
	return meshDecrypt(s.responseKey, ciphertext, s.aad)
}

// meshEncrypt is hmc_encrypt: AES-256-GCM laid out as IV || ciphertext || tag, with the AAD
// carried out of band.
func meshEncrypt(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newMeshGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcmNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating the AES-GCM IV failed: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func meshDecrypt(key, sealed, aad []byte) ([]byte, error) {
	gcm, err := newMeshGCM(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcmNonceLen+gcm.Overhead() {
		return nil, fmt.Errorf("sealed body is %d bytes, shorter than an IV and a tag", len(sealed))
	}
	plaintext, err := gcm.Open(nil, sealed[:gcmNonceLen], sealed[gcmNonceLen:], aad)
	if err != nil {
		return nil, fmt.Errorf("opening the sealed body failed: %w", err)
	}
	return plaintext, nil
}

func newMeshGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("the envelope key is unusable as AES-256: %w", err)
	}
	return cipher.NewGCM(block)
}

func parseECDHPublicKeySPKI(spki []byte) (*ecdh.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, err
	}
	switch key := parsed.(type) {
	case *ecdh.PublicKey:
		return key, nil
	case *ecdsa.PublicKey:
		return key.ECDH()
	default:
		return nil, errors.New("not an elliptic curve public key")
	}
}
