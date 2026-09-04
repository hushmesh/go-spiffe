package workloadapi

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	meshattestpb "github.com/spiffe/go-spiffe/v2/proto/hushmesh/workload/v1"
)

// The AAD is the single highest-risk value in this client. common_types::cbor::to_vec_packed is
// serde_cbor's packed format, which writes a struct as a CBOR MAP keyed by field ordinal and a
// unit enum variant as its variant index -- not, as the "packed" name suggests, as an array. This
// pins the whole layout: an array here would produce an AEAD failure with nothing else to see.
func TestEnvelopeAADIsAPackedCBORMapWithIntegerKeys(t *testing.T) {
	keyID := make([]byte, meshIDLen)
	for i := range keyID {
		keyID[i] = byte(i)
	}
	encapsulatedKey := make([]byte, 1088)
	for i := range encapsulatedKey {
		encapsulatedKey[i] = byte(i % 251)
	}

	encoded, err := envelopeAAD{
		GRPCPath:        getAttestationChallengePath,
		Suite:           envelopeSuiteVariantIndex,
		RecipientKeyID:  keyID,
		EncapsulatedKey: encapsulatedKey,
	}.marshal()
	require.NoError(t, err)

	var expected bytes.Buffer
	expected.WriteByte(0xa4) // map(4)
	expected.WriteByte(0x00) // key 0: grpc_path
	expected.Write([]byte{0x78, byte(len(getAttestationChallengePath))})
	expected.WriteString(getAttestationChallengePath)
	expected.WriteByte(0x01) // key 1: suite
	expected.WriteByte(0x00) // unit variant index 0
	expected.WriteByte(0x02) // key 2: recipient_key_id
	expected.Write([]byte{0x58, 0x20})
	expected.Write(keyID)
	expected.WriteByte(0x03) // key 3: encapsulated_key
	expected.Write([]byte{0x59, 0x04, 0x40})
	expected.Write(encapsulatedKey)

	assert.Equal(t, expected.Bytes(), encoded)
	assert.Len(t, getAttestationChallengePath, 76, "the path length is part of the encoding this test pins")
}

func TestEnvelopeAADNamesTheMethodTheBodyTravelsOn(t *testing.T) {
	aadFor := func(path string) []byte {
		encoded, err := envelopeAAD{GRPCPath: path, RecipientKeyID: make([]byte, meshIDLen)}.marshal()
		require.NoError(t, err)
		return encoded
	}
	assert.NotEqual(t, aadFor(getAttestationChallengePath), aadFor(attestWorkloadPath),
		"without the path in the aad a sealed body is portable between the two methods")
}

func TestMeshDeriveKeyIsHMACSHA256(t *testing.T) {
	key := []byte("a key")
	input := []byte("an input")
	mac := hmac.New(sha256.New, key)
	mac.Write(input)
	assert.Equal(t, mac.Sum(nil), meshDeriveKey(key, input))
}

func TestMeshDeriveKeyFromVecFoldsOneStepPerPart(t *testing.T) {
	key := []byte("start")
	folded := meshDeriveKeyFromVec(key, []byte("a"), []byte("b"), []byte("c"))
	assert.Equal(t, meshDeriveKey(meshDeriveKey(meshDeriveKey(key, []byte("a")), []byte("b")), []byte("c")), folded)
	assert.NotEqual(t, meshDeriveKeyFromVec(key, []byte("ab"), []byte("c")), folded,
		"each part is its own keyed step, so a byte cannot shift across a part boundary")
	assert.Equal(t, key, meshDeriveKeyFromVec(key), "an empty fold is the key itself")
}

func TestAdvertisementSigningInputCoversEveryFieldAtItsOwnStep(t *testing.T) {
	const trustDomain = "abc123.spiffe.example.mesh.in"
	keyID := bytes.Repeat([]byte{9}, meshIDLen)
	baseline := advertisementSigningInput(keyID, []byte("ecc spki"), []byte("mlkem pub"), 1_700_000_000, trustDomain)

	assert.NotEqual(t, baseline, advertisementSigningInput(keyID, []byte("ecc spki"), []byte("mlkem pub"), 1_700_000_000, "other.spiffe.example.mesh.in"),
		"the advertisement leaf is byte-identical for every trust domain the agent hosts, so this field is the only thing separating one entity's advertisement from another's")

	assert.NotEqual(t,
		advertisementSigningInput(keyID, []byte("abcd"), []byte("ef"), 7, trustDomain),
		advertisementSigningInput(keyID, []byte("abc"), []byte("def"), 7, trustDomain),
		"these collide under a bare concatenation, which is why every field gets a step")
}

func TestAdvertisementSigningInputPutsTrustDomainLast(t *testing.T) {
	const trustDomain = "abc123.spiffe.example.mesh.in"
	keyID := bytes.Repeat([]byte{9}, meshIDLen)

	var expiry [8]byte
	binary.BigEndian.PutUint64(expiry[:], 1_700_000_000)
	fourFields := meshDeriveKeyFromVec(meshHashToID(envelopeAdvertisementDomain), keyID, []byte("ecc spki"), []byte("mlkem pub"), expiry[:])

	assert.Equal(t,
		meshDeriveKeyFromVec(fourFields, []byte(trustDomain)),
		advertisementSigningInput(keyID, []byte("ecc spki"), []byte("mlkem pub"), 1_700_000_000, trustDomain),
		"trust_domain folds last, behind the fixed-width expires_at, at its own tag position")
}

func TestEveryComponentMovesTheAttestationNonce(t *testing.T) {
	const unsName = "in.mesh.example.vm-billing"
	seed := bytes.Repeat([]byte{3}, meshIDLen)
	spki := []byte("envelope spki bytes")
	csr := []byte("csr der bytes")

	baseline, err := deriveWorkloadAttestationNonce(seed, unsName, spki, csr)
	require.NoError(t, err)
	assert.Len(t, baseline, meshIDLen)

	for name, args := range map[string][4]any{
		"challenge seed": {bytes.Repeat([]byte{4}, meshIDLen), unsName, spki, csr},
		"uns name":       {seed, "in.mesh.example.vm-other", spki, csr},
		"envelope spki":  {seed, unsName, []byte("other spki bytes"), csr},
		"csr":            {seed, unsName, spki, []byte("other csr bytes")},
	} {
		derived, err := deriveWorkloadAttestationNonce(args[0].([]byte), args[1].(string), args[2].([]byte), args[3].([]byte))
		require.NoError(t, err)
		assert.NotEqual(t, baseline, derived, "%s is outside the binding, so a relay may substitute it", name)
	}

	shifted, err := deriveWorkloadAttestationNonce(seed, "ab", spki, []byte("cd"))
	require.NoError(t, err)
	unshifted, err := deriveWorkloadAttestationNonce(seed, "a", spki, []byte("bcd"))
	require.NoError(t, err)
	assert.NotEqual(t, shifted, unshifted, "each part is its own keyed step")

	_, err = deriveWorkloadAttestationNonce(seed[:8], unsName, spki, csr)
	assert.Error(t, err, "a short challenge seed must fail rather than fold a truncated key")
}

func TestMeshEncryptLaysOutIVCiphertextTag(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	plaintext := []byte("issued svid")
	aad := []byte("aad")

	sealed, err := meshEncrypt(key, plaintext, aad)
	require.NoError(t, err)
	assert.Len(t, sealed, gcmNonceLen+len(plaintext)+16, "hmc_encrypt emits IV || ciphertext || tag")

	opened, err := meshDecrypt(key, sealed, aad)
	require.NoError(t, err)
	assert.Equal(t, plaintext, opened)

	_, err = meshDecrypt(key, sealed, []byte("other aad"))
	assert.Error(t, err, "the aad is authenticated, not decorative")

	tampered := bytes.Clone(sealed)
	tampered[0] ^= 1
	_, err = meshDecrypt(key, tampered, aad)
	assert.Error(t, err)
}

// The hybrid combiner is behind FFI on the mesh side, so this reproduces it from the C:
// SHA-256(ecdh_shared || mlkem_shared), with the ECDH secret the raw X coordinate.
func TestEnvelopeSessionDerivesTheHybridSecretTheMeshWillDerive(t *testing.T) {
	meshECC, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	meshECCSPKI, err := x509.MarshalPKIXPublicKey(meshECC.PublicKey())
	require.NoError(t, err)

	meshMLKEM, err := mlkem.GenerateKey768()
	require.NoError(t, err)

	advertisement := &verifiedAdvertisement{
		keyID:            bytes.Repeat([]byte{5}, meshIDLen),
		eccPublicKeySPKI: meshECCSPKI,
		mlkemPublicKey:   meshMLKEM.EncapsulationKey().Bytes(),
	}

	session, err := establishEnvelopeSession(advertisement, attestWorkloadPath)
	require.NoError(t, err)
	assert.NotEqual(t, session.requestKey, session.responseKey,
		"a shared key would let a reflected message decrypt as one the workload sent")

	sealed, err := session.sealRequest([]byte("evidence"))
	require.NoError(t, err)
	assert.EqualValues(t, envelopeSuiteEccP256MlKem768Aes256Gcm, sealed.GetSuite())
	assert.NotEmpty(t, sealed.GetSenderEccPublicKeySpki(), "tag 5 is the ECDH half of the agreement")
	assert.NotEmpty(t, sealed.GetEncapsulatedKey(), "tag 3 is the ML-KEM half")

	// The mesh's half of the agreement, done here with the mesh's private keys.
	senderPublic, err := parseECDHPublicKeySPKI(sealed.GetSenderEccPublicKeySpki())
	require.NoError(t, err)
	ecdhSecret, err := meshECC.ECDH(senderPublic)
	require.NoError(t, err)
	mlkemSecret, err := meshMLKEM.Decapsulate(sealed.GetEncapsulatedKey())
	require.NoError(t, err)
	hybrid := sha256.Sum256(append(append([]byte{}, ecdhSecret...), mlkemSecret...))

	requestKey := meshDeriveKeyFromVec(hybrid[:], envelopeLabelW2M)
	responseKey := meshDeriveKeyFromVec(hybrid[:], envelopeLabelM2W)
	assert.Equal(t, requestKey, session.requestKey)
	assert.Equal(t, responseKey, session.responseKey)

	aad, err := envelopeAAD{
		GRPCPath:        attestWorkloadPath,
		Suite:           envelopeSuiteVariantIndex,
		RecipientKeyID:  advertisement.keyID,
		EncapsulatedKey: sealed.GetEncapsulatedKey(),
	}.marshal()
	require.NoError(t, err)

	opened, err := meshDecrypt(requestKey, sealed.GetCiphertext(), aad)
	require.NoError(t, err)
	assert.Equal(t, []byte("evidence"), opened)

	reflected, err := meshEncrypt(requestKey, []byte("reflected"), aad)
	require.NoError(t, err)
	_, err = session.openResponse(reflected)
	assert.Error(t, err, "our own request replayed back at us must not open as a mesh response")

	answer, err := meshEncrypt(responseKey, []byte("issued svid"), aad)
	require.NoError(t, err)
	opened, err = session.openResponse(answer)
	require.NoError(t, err)
	assert.Equal(t, []byte("issued svid"), opened)
}

func TestWorkloadCSRCommonNameIsTheLastBytesOfTheUNSName(t *testing.T) {
	longName := "in.mesh.org21." + string(bytes.Repeat([]byte{'a'}, 200))
	_, csrDER, err := generateWorkloadKeyAndCSR(longName)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)
	require.NoError(t, csr.CheckSignature())
	assert.Len(t, csr.Subject.CommonName, maxCertCommonNameLen)
	assert.Equal(t, longName[len(longName)-maxCertCommonNameLen:], csr.Subject.CommonName,
		"identity travels in the URI SAN the mesh adds; the CN is decoration bounded by wolfSSL's CTC_NAME_SIZE")

	shortName := "in.mesh.org21.svc"
	_, csrDER, err = generateWorkloadKeyAndCSR(shortName)
	require.NoError(t, err)
	csr, err = x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)
	assert.Equal(t, shortName, csr.Subject.CommonName)
}

func TestStubEvidenceDeclaresAbsentRatherThanClaimingADigest(t *testing.T) {
	now := time.Now()
	request := &MeshEvidenceRequest{
		Nonce:                bytes.Repeat([]byte{1}, meshIDLen),
		PCRNonce:             bytes.Repeat([]byte{2}, meshIDLen),
		PCRSelectionBitfield: 0x1_ffff,
		ChallengeExpiresAt:   now.Unix() + 120,
		CollectedAt:          now,
	}

	evidence, err := stubEvidenceProvider{}.CollectEvidence(context.Background(), request)
	require.NoError(t, err)
	assert.EqualValues(t, varDataOperationAbsent, evidence.GetVarDataOperation())
	assert.Empty(t, evidence.GetVarData())
	assert.Empty(t, evidence.GetQuote())
	assert.Nil(t, evidence.GetTpmQuote())

	userData := evidence.GetUserData()
	require.Len(t, userData, reportDataLen)
	assert.Equal(t, request.Nonce, userData[:meshIDLen])
	assert.EqualValues(t, now.Unix(), binary.LittleEndian.Uint64(userData[meshIDLen:meshIDLen+8]))
	assert.Equal(t, make([]byte, 24), userData[meshIDLen+8:], "verify_quote_data rejects a non-zero reserved1 twice over")
}

func TestUnanswerableChallengeIsRefusedBeforeAQuoteIsSpent(t *testing.T) {
	now := time.Now()
	answerable := func() *MeshEvidenceRequest {
		return &MeshEvidenceRequest{
			Nonce:                bytes.Repeat([]byte{1}, meshIDLen),
			PCRNonce:             bytes.Repeat([]byte{2}, meshIDLen),
			PCRSelectionBitfield: 0x1_ffff,
			ChallengeExpiresAt:   now.Unix() + 120,
			CollectedAt:          now,
		}
	}
	require.NoError(t, answerable().CheckAnswerable())

	noSlots := answerable()
	noSlots.PCRSelectionBitfield = 0
	assert.Error(t, noSlots.CheckAnswerable())

	zeroNonce := answerable()
	zeroNonce.PCRNonce = make([]byte, meshIDLen)
	assert.Error(t, zeroNonce.CheckAnswerable())

	expired := answerable()
	expired.ChallengeExpiresAt = now.Unix() - 1
	assert.Error(t, expired.CheckAnswerable())
	_, err := stubEvidenceProvider{}.CollectEvidence(context.Background(), expired)
	assert.Error(t, err, "a bypass here would let the stub reach the wire on a challenge a quote could not")
}

// meshAdvertisementFixture builds a chain and a signed advertisement the way the mesh does: a
// P-384 leaf key, an ECDSA signature over SHA-384 of the fold, emitted as fixed r||s.
type meshAdvertisementFixture struct {
	response *meshattestpb.GetEnvelopeKeyResponse
	rootDER  []byte
	rootSPKI []byte
}

func newMeshAdvertisementFixture(t *testing.T, agentFQDN, trustDomain string) *meshAdvertisementFixture {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Mesh Test Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Mesh Test Agent"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		URIs:         []*url.URL{mustParseURI(t, agentServerSPIFFEID(agentFQDN))},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)

	response := &meshattestpb.GetEnvelopeKeyResponse{
		KeyId:            bytes.Repeat([]byte{9}, meshIDLen),
		EccPublicKeySpki: []byte("ecc spki"),
		MlkemPublicKey:   []byte("mlkem pub"),
		ExpiresAt:        time.Now().Add(24 * time.Hour).Unix(),
		CertChain:        [][]byte{leafDER, rootDER},
		TrustDomain:      trustDomain,
	}
	digest := sha512.Sum384(advertisementSigningInput(response.KeyId, response.EccPublicKeySpki, response.MlkemPublicKey, response.ExpiresAt, response.TrustDomain))
	r, s, err := ecdsa.Sign(rand.Reader, leafKey, digest[:])
	require.NoError(t, err)
	signature := make([]byte, 2*p384ComponentLen)
	r.FillBytes(signature[:p384ComponentLen])
	s.FillBytes(signature[p384ComponentLen:])
	response.Signature = signature

	return &meshAdvertisementFixture{response: response, rootDER: rootDER, rootSPKI: spkiSHA256(root)}
}

func (f *meshAdvertisementFixture) anchors() *MeshTrustAnchors {
	return &MeshTrustAnchors{
		PinnedRootSPKISHA256: [][]byte{f.rootSPKI},
		RootCertificates:     [][]byte{f.rootDER},
	}
}

func TestAdvertisementVerificationAcceptsAGenuineAdvertisement(t *testing.T) {
	const agentFQDN = "localtest.mesh.in"
	const trustDomain = "abc123.spiffe.example.mesh.in"
	fixture := newMeshAdvertisementFixture(t, agentFQDN, trustDomain)

	verified, err := verifyAdvertisement(fixture.response, fixture.anchors(), agentFQDN, trustDomain, time.Now())
	require.NoError(t, err)
	assert.Equal(t, trustDomain, verified.trustDomain)
	assert.Equal(t, fixture.response.KeyId, verified.keyID)
}

func TestAdvertisementVerificationRefusesTheThingsItMust(t *testing.T) {
	const agentFQDN = "localtest.mesh.in"
	const trustDomain = "abc123.spiffe.example.mesh.in"

	t.Run("another trust domain", func(t *testing.T) {
		fixture := newMeshAdvertisementFixture(t, agentFQDN, "other.spiffe.example.mesh.in")
		_, err := verifyAdvertisement(fixture.response, fixture.anchors(), agentFQDN, trustDomain, time.Now())
		assert.ErrorIs(t, err, ErrAdvertisementRefused)
	})

	t.Run("another agent", func(t *testing.T) {
		fixture := newMeshAdvertisementFixture(t, "elsewhere.mesh.in", trustDomain)
		_, err := verifyAdvertisement(fixture.response, fixture.anchors(), agentFQDN, trustDomain, time.Now())
		assert.ErrorIs(t, err, ErrAdvertisementRefused)
	})

	t.Run("a tampered signed field", func(t *testing.T) {
		fixture := newMeshAdvertisementFixture(t, agentFQDN, trustDomain)
		fixture.response.ExpiresAt++
		_, err := verifyAdvertisement(fixture.response, fixture.anchors(), agentFQDN, trustDomain, time.Now())
		assert.ErrorIs(t, err, ErrAdvertisementRefused)
	})

	t.Run("an anchor outside the pinned set", func(t *testing.T) {
		fixture := newMeshAdvertisementFixture(t, agentFQDN, trustDomain)
		anchors := fixture.anchors()
		anchors.PinnedRootSPKISHA256 = [][]byte{bytes.Repeat([]byte{3}, sha256.Size)}
		_, err := verifyAdvertisement(fixture.response, anchors, agentFQDN, trustDomain, time.Now())
		assert.ErrorIs(t, err, ErrAdvertisementRefused, "the pinned hash set is the authority; the certificate file only carries key bytes")
	})

	t.Run("an unparseable anchor", func(t *testing.T) {
		anchors := &MeshTrustAnchors{
			PinnedRootSPKISHA256: [][]byte{bytes.Repeat([]byte{3}, sha256.Size)},
			RootCertificates:     [][]byte{[]byte("not a certificate")},
		}
		_, err := anchors.pinnedRoots()
		assert.Error(t, err, "skipping a junk anchor would silently shrink the set")
	})

	t.Run("a substituted chain terminal", func(t *testing.T) {
		fixture := newMeshAdvertisementFixture(t, agentFQDN, trustDomain)
		unrelated := newMeshAdvertisementFixture(t, agentFQDN, trustDomain)
		fixture.response.CertChain[1] = unrelated.rootDER
		err := verifyAdvertisementExceptChainAnchor(fixture.response, agentFQDN, trustDomain, time.Now())
		assert.ErrorIs(t, err, ErrAdvertisementRefused,
			"cert_chain is outside the signed input, so a relay can keep the genuine leaf and swap the element a pin is taken against")
	})

	t.Run("an issuer that is not a CA", func(t *testing.T) {
		fixture := newMeshAdvertisementFixture(t, agentFQDN, trustDomain)
		leaf := fixture.response.CertChain[0]
		err := verifyChainLinkage([][]byte{leaf, leaf}, time.Now())
		assert.ErrorIs(t, err, ErrAdvertisementRefused,
			"a signature check answers whether a signature verifies, never whether that key was allowed to sign certificates")
	})

	t.Run("an overlong chain", func(t *testing.T) {
		fixture := newMeshAdvertisementFixture(t, agentFQDN, trustDomain)
		for len(fixture.response.CertChain) <= maxAdvertisementChainLen {
			fixture.response.CertChain = append(fixture.response.CertChain, fixture.rootDER)
		}
		_, err := verifyAdvertisement(fixture.response, fixture.anchors(), agentFQDN, trustDomain, time.Now())
		assert.ErrorIs(t, err, ErrAdvertisementRefused)
	})

	t.Run("a key expiring inside the challenge window", func(t *testing.T) {
		fixture := newMeshAdvertisementFixture(t, agentFQDN, trustDomain)
		now := time.Unix(fixture.response.ExpiresAt, 0).Add(-minAdvertisementRemainingLifetime)
		_, err := verifyAdvertisement(fixture.response, fixture.anchors(), agentFQDN, trustDomain, now)
		assert.ErrorIs(t, err, ErrAdvertisementRefused)
	})
}

func TestParseMeshTrustAnchorsIsStrictAboutThePEMFile(t *testing.T) {
	fixture := newMeshAdvertisementFixture(t, "localtest.mesh.in", "abc123.spiffe.example.mesh.in")
	pemBytes := certificatePEM(t, fixture.rootDER) + certificatePEM(t, fixture.rootDER)

	anchors, err := ParseMeshTrustAnchors([]byte(pemBytes), []string{hexString(fixture.rootSPKI)})
	require.NoError(t, err)
	assert.Len(t, anchors.RootCertificates, 2, "a multi-certificate anchor file must not fold into one anchor")
	assert.Len(t, anchors.PinnedRootSPKISHA256, 1)

	_, err = ParseMeshTrustAnchors(nil, nil)
	assert.Error(t, err)
	_, err = ParseMeshTrustAnchors([]byte("garbage\n"+pemBytes), nil)
	assert.Error(t, err, "anything before the first BEGIN means the file is not what we think it is")
	_, err = ParseMeshTrustAnchors([]byte(pemBytes), []string{"not hex"})
	assert.Error(t, err)
	_, err = ParseMeshTrustAnchors([]byte(pemBytes), []string{"00ff"})
	assert.Error(t, err, "a pin that is not 32 bytes cannot match any SPKI digest")
}

func mustParseURI(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	require.NoError(t, err)
	return parsed
}

func certificatePEM(t *testing.T, der []byte) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func hexString(raw []byte) string {
	return hex.EncodeToString(raw)
}

// An expired certificate in the advertised chain must be refused. crypto/x509.CheckSignature does
// not consult validity dates, and this package does not use Certificate.Verify, so nothing else in
// the walk would catch it -- a relay holding any endpoint key that ever existed could otherwise
// replay a retired leaf forever and receive the workload's sealed CSR and quote.
func TestExpiredCertificateInTheAdvertisedChainIsRefused(t *testing.T) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	expiredDER, rootDER := expiredLeafUnderRoot(t, rootKey)

	if err := verifyChainLinkage([][]byte{expiredDER, rootDER}, time.Now()); err == nil {
		t.Fatal("an expired leaf must be refused; CheckSignature alone accepts it forever")
	}
	// The same chain, evaluated while the leaf was still valid, must pass -- otherwise the test
	// proves only that something is broken, not that expiry is what was caught.
	if err := verifyChainLinkage([][]byte{expiredDER, rootDER}, time.Now().Add(-48*time.Hour)); err != nil {
		t.Fatalf("the chain must verify inside the leaf's validity window: %v", err)
	}
}

func expiredLeafUnderRoot(t *testing.T, rootKey *ecdsa.PrivateKey) (leafDER, rootDER []byte) {
	t.Helper()
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "root"},
		NotBefore:             time.Now().Add(-72 * time.Hour),
		NotAfter:              time.Now().Add(72 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "retired leaf"},
		NotBefore:    time.Now().Add(-72 * time.Hour),
		NotAfter:     time.Now().Add(-1 * time.Hour),
	}
	leafDER, err = x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return leafDER, rootDER
}
