package workloadapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	meshattestpb "github.com/spiffe/go-spiffe/v2/proto/hushmesh/workload/v1"
)

// maxAdvertisementChainLen bounds the served chain before any signature work: every certificate
// costs a parse and a verify, and the real chain is two elements.
const maxAdvertisementChainLen = 8

// minAdvertisementRemainingLifetime is how long an advertisement must still have. The challenge
// TTL is CHALLENGE_TTL_SECONDS (actors/actor-spiffe-agent/src/attestation.rs) and a TDX quote
// plus a vTPM quote sit inside it, so a key expiring sooner than this cannot complete a flow.
const minAdvertisementRemainingLifetime = 120 * time.Second

// p384ComponentLen is the width of r and of s in the fixed-format signature the mesh emits.
// hmc_create_ecc_signature never produces DER, so a DER-expecting verifier would fail closed with
// nothing to debug.
const p384ComponentLen = 48

const spiffeURIPrefix = "spiffe://"

// ErrAdvertisementRefused is returned for every advertisement that fails verification. It carries
// no distinction between the reasons, mirroring refuse_workload_attestation on the mesh side; the
// specific reason is wrapped for the log and never for the caller to branch on.
var ErrAdvertisementRefused = errors.New("envelope advertisement refused")

// verifiedAdvertisement is what the workload may encrypt to, once every check has passed. It is a
// separate type from the wire response so nothing downstream can reach the advertised key
// material without having gone through verifyAdvertisement.
type verifiedAdvertisement struct {
	keyID            []byte
	eccPublicKeySPKI []byte
	mlkemPublicKey   []byte
	expiresAt        int64
	trustDomain      string
}

// MeshTrustAnchors are the anchors compiled or configured into a workload. ADR-0043 Decision 5
// requires the pinned SPKI hash set to be the authority: RootCertificates only supplies the public
// key bytes needed to check a signature, and an entry whose SPKI hash is not in
// PinnedRootSPKISHA256 is discarded. An attacker who can rewrite the certificate file therefore
// cannot move the trust anchor.
type MeshTrustAnchors struct {
	// PinnedRootSPKISHA256 holds the SHA-256 of each accepted root's SubjectPublicKeyInfo.
	// More than one may be listed so a root rotation can be staged.
	PinnedRootSPKISHA256 [][]byte

	// RootCertificates are the candidate roots, in DER.
	RootCertificates [][]byte
}

// ParseMeshTrustAnchors builds the anchor set from a PEM file's bytes and hex-encoded SPKI
// digests.
func ParseMeshTrustAnchors(rootCAPEM []byte, pinnedRootSPKISHA256Hex []string) (*MeshTrustAnchors, error) {
	certificates, err := parseCertificatePEMBlocks(rootCAPEM)
	if err != nil {
		return nil, err
	}
	anchors := &MeshTrustAnchors{RootCertificates: certificates}
	for _, encoded := range pinnedRootSPKISHA256Hex {
		digest, err := hex.DecodeString(strings.TrimSpace(encoded))
		if err != nil {
			return nil, fmt.Errorf("pinned SPKI hash %q is not hex: %w", encoded, err)
		}
		if len(digest) != sha256.Size {
			return nil, fmt.Errorf("pinned SPKI hash %q is %d bytes, not %d", encoded, len(digest), sha256.Size)
		}
		anchors.PinnedRootSPKISHA256 = append(anchors.PinnedRootSPKISHA256, digest)
	}
	return anchors, nil
}

// pinnedRoots is the subset of RootCertificates whose SPKI hash is pinned. A certificate that
// will not parse fails the whole set closed rather than being skipped, because skipping would
// silently shrink the anchor set.
func (a *MeshTrustAnchors) pinnedRoots() ([]*x509.Certificate, error) {
	var roots []*x509.Certificate
	for _, der := range a.RootCertificates {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: a configured root certificate will not parse: %w", ErrAdvertisementRefused, err)
		}
		if a.isPinned(certificate) {
			roots = append(roots, certificate)
		}
	}
	return roots, nil
}

func (a *MeshTrustAnchors) isPinned(certificate *x509.Certificate) bool {
	digest := spkiSHA256(certificate)
	for _, pinned := range a.PinnedRootSPKISHA256 {
		if bytes.Equal(pinned, digest) {
			return true
		}
	}
	return false
}

// spkiSHA256 is the value an operator pins. It is taken over the certificate's SubjectPublicKeyInfo
// exactly as it appeared on the wire, never over a re-encoding of the same key.
func spkiSHA256(certificate *x509.Certificate) []byte {
	digest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return digest[:]
}

// verifyAdvertisement runs three checks, all required.
//
// ADR-0043 Decision 5's two -- a chain reaching a pinned root, and the leaf naming this agent's
// spire server -- establish that a mesh agent we shipped a root for answered. Neither says WHICH
// entity: the advertisement leaf is the agent's endpoint certificate, byte-identical for every
// trust domain that agent hosts, and every entity CA in this PKI shares one external intermediate
// with no pathLenConstraint anywhere (ADR-0018). So a relay could serve entity B's
// genuinely-signed advertisement to a workload that dialled entity A and both Decision 5 checks
// would pass. expectedTrustDomain is the third check and the only one that separates them.
func verifyAdvertisement(resp *meshattestpb.GetEnvelopeKeyResponse, anchors *MeshTrustAnchors, agentFQDN, expectedTrustDomain string, now time.Time) (*verifiedAdvertisement, error) {
	if _, err := advertisementLeaf(resp); err != nil {
		return nil, err
	}
	if err := verifyChainToPinnedRoot(resp.GetCertChain(), anchors, now); err != nil {
		return nil, err
	}
	if err := verifyAdvertisementExceptChainAnchor(resp, agentFQDN, expectedTrustDomain, now); err != nil {
		return nil, err
	}
	if len(resp.GetKeyId()) != meshIDLen {
		return nil, refusedAdvertisement("advertised key id is %d bytes, not %d", len(resp.GetKeyId()), meshIDLen)
	}
	// The only construction site, so the type's guarantee holds by construction.
	return &verifiedAdvertisement{
		keyID:            resp.GetKeyId(),
		eccPublicKeySPKI: resp.GetEccPublicKeySpki(),
		mlkemPublicKey:   resp.GetMlkemPublicKey(),
		expiresAt:        resp.GetExpiresAt(),
		trustDomain:      resp.GetTrustDomain(),
	}, nil
}

// verifyAdvertisementExceptChainAnchor runs every check in verifyAdvertisement except the walk to
// a pinned anchor, and deliberately returns nothing: the advertised key material is reachable only
// through verifyAdvertisement, which is strictly stronger.
//
// This exists for the one caller that does not yet HAVE an anchor -- the bootstrap that prints a
// pin for an operator to ship. What it establishes there is less than it looks: the chain is
// internally consistent AND UNANCHORED. Every certificate is issued by the next, the leaf names
// the agent asked for, the signature verifies under that leaf, and the trust domain is the one
// dialled -- but nothing says the chain belongs to the mesh rather than to whoever answered.
//
// The linkage walk is not optional here even though no pin is involved. cert_chain is tag 5 and
// sits OUTSIDE advertisementSigningInput, so a relay may replay a genuine response verbatim, keep
// the real leaf -- which it must, or the signature and SAN checks fail -- and substitute the LAST
// element, which is exactly what the bootstrap prints as the value to pin.
func verifyAdvertisementExceptChainAnchor(resp *meshattestpb.GetEnvelopeKeyResponse, agentFQDN, expectedTrustDomain string, now time.Time) error {
	leaf, err := advertisementLeaf(resp)
	if err != nil {
		return err
	}
	if err := verifyChainLinkage(resp.GetCertChain(), now); err != nil {
		return err
	}
	if err := verifyLeafNamesTheAgent(leaf, agentFQDN); err != nil {
		return err
	}
	if err := verifySignatureOverKeyMaterial(resp, leaf); err != nil {
		return err
	}

	// After the signature, so a mismatch is a statement about an authentic advertisement rather
	// than about an unauthenticated string a relay chose.
	if resp.GetTrustDomain() != expectedTrustDomain {
		return refusedAdvertisement("advertisement is for trust domain %q, not the %q that was dialled", resp.GetTrustDomain(), expectedTrustDomain)
	}

	deadline := now.Add(minAdvertisementRemainingLifetime).Unix()
	if resp.GetExpiresAt() <= deadline {
		return refusedAdvertisement("advertised envelope key expires at %d, too soon to complete an attestation started at %d", resp.GetExpiresAt(), now.Unix())
	}
	return nil
}

// advertisementLeaf is the leaf, once the chain is known to be a plausible length. Bounding first
// is what keeps a caller-supplied chain from costing one parse and one signature verify per
// element.
func advertisementLeaf(resp *meshattestpb.GetEnvelopeKeyResponse) (*x509.Certificate, error) {
	chain := resp.GetCertChain()
	if len(chain) > maxAdvertisementChainLen {
		return nil, refusedAdvertisement("advertisement chain has %d certificates, past the bound of %d", len(chain), maxAdvertisementChainLen)
	}
	if len(chain) == 0 {
		return nil, refusedAdvertisement("advertisement carries no certificate chain")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, refusedAdvertisement("advertisement leaf will not parse: %v", err)
	}
	return leaf, nil
}

// advertisementChainTerminal is the certificate a pin is taken against: the chain terminates at
// the shared external intermediate rather than at a root (build_server_certificate_chain,
// actors/actor-spiffe-agent/src/lib.rs, appends exactly the issuing CA), so this is the last
// element and not the leaf.
func advertisementChainTerminal(resp *meshattestpb.GetEnvelopeKeyResponse) (*x509.Certificate, error) {
	if _, err := advertisementLeaf(resp); err != nil {
		return nil, err
	}
	chain := resp.GetCertChain()
	terminal, err := x509.ParseCertificate(chain[len(chain)-1])
	if err != nil {
		return nil, refusedAdvertisement("advertisement chain terminal will not parse: %v", err)
	}
	return terminal, nil
}

// verifyChainLinkage checks that every certificate is issued by the next AND that every alleged
// issuer was permitted to issue. Both halves are needed and neither implies the other. This is a
// property of the served chain alone: it needs no anchor, and it is what stops a relay from
// swapping the element a pin would be taken against while keeping the signed fields intact.
//
// The issuer test is applied to every element EXCEPT the first. The leaf is an end-entity endpoint
// certificate that is correctly not a CA, so testing it would refuse every genuine advertisement.
// refuseExpiredCertificate rejects a certificate outside its validity period.
//
// crypto/x509.CheckSignature answers only "this signature verifies under that key" -- it never
// consults NotBefore or NotAfter; only Certificate.Verify does, and this package deliberately does
// not use it (the pinned SPKI set is the authority, not a system or bundle chain). So without this,
// a retired agent endpoint leaf verifies forever.
//
// That matters because the advertisement is fetched THROUGH the relay, which is the party the
// pinned-anchor design exists to defend against, and because the endpoint certificate is rotated by
// design -- the mesh memoises its advertisement signature keyed on that certificate's expiry
// precisely because renewal happens. Retired leaves therefore exist. Holding any endpoint key that
// ever existed, a relay could otherwise serve [old_leaf, real_intermediate] with a fold signed
// under the key it holds and pass every other check, and the workload would seal its CSR, UNS name
// and quote to the relay's own envelope key.
//
// The mesh's own Rust client checks this: mesh_certificate_verify reaches wc_ParseCert(..., VERIFY),
// wolfSSL's date-validating mode. Two implementations of one wire contract must not disagree about
// whether an expired chain is acceptable.
func refuseExpiredCertificate(certificate *x509.Certificate, position int, now time.Time) error {
	if now.Before(certificate.NotBefore) {
		return refusedAdvertisement("certificate %d in the advertised chain is not valid until %s", position, certificate.NotBefore)
	}
	if now.After(certificate.NotAfter) {
		return refusedAdvertisement("certificate %d in the advertised chain expired at %s", position, certificate.NotAfter)
	}
	return nil
}

func verifyChainLinkage(chain [][]byte, now time.Time) error {
	for i := 0; i+1 < len(chain); i++ {
		child, err := x509.ParseCertificate(chain[i])
		if err != nil {
			return refusedAdvertisement("certificate %d in the advertised chain will not parse: %v", i, err)
		}
		issuer, err := x509.ParseCertificate(chain[i+1])
		if err != nil {
			return refusedAdvertisement("certificate %d in the advertised chain will not parse: %v", i+1, err)
		}
		if err := refuseExpiredCertificate(child, i, now); err != nil {
			return err
		}
		if err := refuseExpiredCertificate(issuer, i+1, now); err != nil {
			return err
		}
		if err := verifyIssuerMayIssue(issuer, i+1); err != nil {
			return err
		}
		if err := issuer.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature); err != nil {
			return refusedAdvertisement("certificate %d in the advertised chain is not issued by certificate %d: %v", i, i+1, err)
		}
	}
	return nil
}

// verifyIssuerMayIssue requires an alleged issuer to be a CA that may sign certificates. It is
// separate from the signature check on purpose: a signature check answers "this signature verifies
// under that key", never "that key was allowed to sign certificates". Without this, the linkage
// walk is satisfied by a chain any holder of an SVID under the pinned PKI can mint for itself --
// forge a leaf carrying spiffe://<agent fqdn>/spire/server, sign it with the SVID's own key, and
// serve [forged_leaf, their_svid, entity_ca, terminal]. Every pair links, every signed field is
// genuine, the terminal is the real one, and the forger holds both directions of the envelope.
//
// An absent keyUsage extension places no constraint under X.509, so it is not a refusal on its
// own; IsCA is the check that stands in that case, and it is the load-bearing half. Verified
// against the mesh's own certificates: an intermediate carries keyUsage with keyCertSign, a root
// carries none at all, so refusing on absence would refuse genuine issuers.
func verifyIssuerMayIssue(issuer *x509.Certificate, index int) error {
	if !issuer.IsCA {
		return refusedAdvertisement("certificate %d in the advertised chain issued the one before it without being a CA", index)
	}
	if issuer.KeyUsage != 0 && issuer.KeyUsage&x509.KeyUsageCertSign == 0 {
		return refusedAdvertisement("certificate %d in the advertised chain is a CA not permitted to sign certificates", index)
	}
	return nil
}

// verifyChainToPinnedRoot walks the served chain, which is leaf first (certificate_pem_blocks,
// actors/actor-spiffe-agent/src/envelope_advertisement_handler.rs) and terminates at the shared
// external intermediate rather than at a root -- so the last element is checked against a pinned
// anchor rather than against itself.
func verifyChainToPinnedRoot(chain [][]byte, anchors *MeshTrustAnchors, now time.Time) error {
	pinnedRoots, err := anchors.pinnedRoots()
	if err != nil {
		return err
	}
	if len(pinnedRoots) == 0 {
		return refusedAdvertisement("none of the %d configured root certificates matches the %d pinned SPKI hashes", len(anchors.RootCertificates), len(anchors.PinnedRootSPKISHA256))
	}
	if err := verifyChainLinkage(chain, now); err != nil {
		return err
	}
	if len(chain) == 0 {
		return refusedAdvertisement("advertisement carries no certificate chain")
	}

	terminal, err := x509.ParseCertificate(chain[len(chain)-1])
	if err != nil {
		return refusedAdvertisement("advertisement chain terminal will not parse: %v", err)
	}
	if err := refuseExpiredCertificate(terminal, len(chain)-1, now); err != nil {
		return err
	}
	if anchors.isPinned(terminal) {
		return nil
	}
	for _, root := range pinnedRoots {
		if err := root.CheckSignature(terminal.SignatureAlgorithm, terminal.RawTBSCertificate, terminal.Signature); err == nil {
			return nil
		}
	}
	return refusedAdvertisement("the advertised chain does not reach a root in the pinned SPKI hash set")
}

func verifyLeafNamesTheAgent(leaf *x509.Certificate, agentFQDN string) error {
	var spiffeURIs []string
	for _, uri := range leaf.URIs {
		if strings.HasPrefix(uri.String(), spiffeURIPrefix) {
			spiffeURIs = append(spiffeURIs, uri.String())
		}
	}
	expected := agentServerSPIFFEID(agentFQDN)
	if len(spiffeURIs) != 1 || spiffeURIs[0] != expected {
		return refusedAdvertisement("advertisement leaf carries SPIFFE URI SANs %v, not exactly %q", spiffeURIs, expected)
	}
	return nil
}

// verifySignatureOverKeyMaterial checks the mesh's signature over the advertised key material.
// mesh_create_signature(HmcKeyType::Ecc384, ...) signs SHA-384 of the 32-byte fold output and
// emits fixed r||s (96 bytes), never DER -- hmc_create_ecc_signature,
// c-libraries/hushmesh-crypto/hm_crypt.c.
func verifySignatureOverKeyMaterial(resp *meshattestpb.GetEnvelopeKeyResponse, leaf *x509.Certificate) error {
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return refusedAdvertisement("advertisement leaf does not carry an ECDSA public key")
	}
	signature := resp.GetSignature()
	if len(signature) != 2*p384ComponentLen {
		return refusedAdvertisement("advertisement signature is %d bytes, not the %d of a fixed P-384 r||s", len(signature), 2*p384ComponentLen)
	}

	signingInput := advertisementSigningInput(
		resp.GetKeyId(),
		resp.GetEccPublicKeySpki(),
		resp.GetMlkemPublicKey(),
		resp.GetExpiresAt(),
		resp.GetTrustDomain(),
	)
	digest := sha512.Sum384(signingInput)

	r := new(big.Int).SetBytes(signature[:p384ComponentLen])
	s := new(big.Int).SetBytes(signature[p384ComponentLen:])
	if !ecdsa.Verify(publicKey, digest[:], r, s) {
		return refusedAdvertisement("advertisement signature does not verify under the leaf key")
	}
	return nil
}

// parseCertificatePEMBlocks is deliberately strict: anything that is not a run of CERTIFICATE
// blocks means the file is not what we think it is, and a silently-shorter anchor set is the
// failure this cannot be allowed to produce.
func parseCertificatePEMBlocks(data []byte) ([][]byte, error) {
	var ders [][]byte
	rest := bytes.TrimSpace(data)
	for len(rest) > 0 {
		// pem.Decode skips whatever precedes the first BEGIN line. Anything there means the file is
		// not the run of certificates it is being read as, so it is refused rather than skipped.
		if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
			return nil, errors.New("certificate file has content outside a PEM block")
		}
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("certificate file has a block that is not PEM")
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("certificate file has a %q block where a CERTIFICATE was expected", block.Type)
		}
		ders = append(ders, block.Bytes)
		rest = bytes.TrimSpace(rest)
	}
	if len(ders) == 0 {
		return nil, errors.New("certificate file holds no certificates")
	}
	return ders, nil
}

func refusedAdvertisement(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrAdvertisementRefused, fmt.Sprintf(format, args...))
}
