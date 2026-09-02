// Mesh-attested workload identity: the client end of the path the hushmesh SPIFFE agent serves on
// /hushmesh.api.server.workload.v1.WorkloadAttestation, reached through a SPIRE agent that relays
// it on its Workload API socket.
//
// The mesh gates the two enveloped routes on a client certificate whose SPIFFE SAN verifies
// against the entity's published CA. A bare workload has no such certificate -- an SVID is what it
// is asking for -- so the relay lends its node SVID and copies the sealed bodies through untouched
// in both directions. Everything above the transport is this package's business: the advertisement
// and its pinning, the hybrid envelope, the challenge, the ADR-0041 nonce and the evidence.
//
// The order is fixed and each step feeds the next:
//
//  1. fetch the envelope advertisement and verify BOTH halves of ADR-0043 Decision 5;
//  2. generate the workload keypair and CSR, then seal call 1 to the advertised key;
//  3. derive the effective nonce over the challenge and the bound request fields (ADR-0041);
//  4. produce evidence carrying that nonce plus a vTPM PCR quote over the challenge's values;
//  5. seal call 2 and open the response into an X509-SVID.

package workloadapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	meshattestpb "github.com/spiffe/go-spiffe/v2/proto/hushmesh/workload/v1"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// meshAttestCallTimeout bounds each of the three calls. Without one, a relay that accepts the
// connection and never answers hangs the workload forever. It is sized well above a real round
// trip -- the mesh does quote verification and up to two UNS lookups inside AttestWorkload -- so it
// fires only for a peer that has genuinely stopped answering.
const meshAttestCallTimeout = 60 * time.Second

// The retry budget for a relay that answers ResourceExhausted. The relay bounds how many local
// callers may hold a slot on the agent's single server connection and rejects rather than queues,
// so this one status means retry, not denied. The budget is bounded well inside
// meshAttestCallTimeout: a budget that could outlive it would convert a fast, accurate "relay is
// busy" into a slow, uninformative timeout.
const (
	relayBusyRetries        = 5
	relayBusyBackoffInitial = 100 * time.Millisecond
)

// maxCertCommonNameLen is MAX_CERT_COMMON_NAME_LEN (crates/crate-common-crypto/src/certificate.rs),
// which is wolfSSL's CTC_NAME_SIZE. A workload UNS name is bounded at 512, so the full name does
// not fit and the issuer refuses a longer CN with a status that names nothing.
const maxCertCommonNameLen = 63

// MeshAttestParams is what a workload must know before it can ask for its first SVID. None of it
// is discoverable from the relay: the trust domain and the agent fqdn are what the advertisement
// is checked against, and the anchors are a build input under ADR-0043 Decision 5.
type MeshAttestParams struct {
	// AgentFQDN is the fqdn the advertisement LEAF must name as spiffe://<fqdn>/spire/server.
	// This is a different certificate from the one TLS presents: the connection carries the entity
	// server certificate while the advertisement leaf is the agent's own.
	AgentFQDN string

	// TrustDomain is the trust domain this workload intends to join. It is compared against the
	// advertisement's signed trust_domain field, which is the only check that separates one
	// entity's advertisement from another's.
	TrustDomain spiffeid.TrustDomain

	// WorkloadUNSName is this workload's UNS name. It is bound into the quote and must be the
	// byte-exact name the factory registered, since the mesh derives the nonce from the name as
	// received.
	WorkloadUNSName string

	// Anchors are the pinned mesh roots. Required.
	Anchors *MeshTrustAnchors

	// StubEvidence sends an empty evidence bundle instead of a real quote. It cannot pass
	// verification against a production mesh; it exists to exercise the envelope and the wire
	// assembly off a TDX host.
	StubEvidence bool
}

// MeshAttestation is what the mesh issued.
type MeshAttestation struct {
	// SVID carries the issued chain, its SPIFFE ID and the private key generated in this process.
	// The key never leaves the process except through whatever the caller writes it to.
	SVID *x509svid.SVID

	// Bundles are the X.509 trust bundles the mesh returned alongside the SVID.
	Bundles *x509bundle.Set
}

// MeshAdvertisementAnchor is the certificate an operator pins, in the two forms a build input
// wants.
type MeshAdvertisementAnchor struct {
	// Certificate is the terminal of the served advertisement chain.
	Certificate *x509.Certificate

	// SPKISHA256 is the SHA-256 of that certificate's SubjectPublicKeyInfo.
	SPKISHA256 []byte
}

// AttestMeshWorkload obtains an X509-SVID from the mesh by attesting through the relay this client
// is connected to.
func (c *Client) AttestMeshWorkload(ctx context.Context, params MeshAttestParams) (*MeshAttestation, error) {
	if params.Anchors == nil {
		return nil, errors.New("mesh attestation needs trust anchors; nothing else establishes that the mesh answered")
	}
	if params.WorkloadUNSName == "" {
		return nil, errors.New("mesh attestation needs the workload's UNS name; the mesh derives the nonce from the name as received")
	}
	// Before the first call rather than after the challenge: a challenge is single-use state on the
	// mesh side, and spending one only to discover this build cannot answer it is a refusal the
	// caller would have to read out of a later, less specific failure.
	if !params.StubEvidence {
		return nil, errors.New("real TDX/vTPM evidence collection is not implemented in this client; set StubEvidence to exercise the path without a quote")
	}

	advertisement, err := c.fetchMeshAdvertisement(ctx, params.Anchors, params.AgentFQDN, params.TrustDomain)
	if err != nil {
		return nil, err
	}

	privateKey, csrDER, err := generateWorkloadKeyAndCSR(params.WorkloadUNSName)
	if err != nil {
		return nil, err
	}

	challenge, err := c.requestMeshAttestationChallenge(ctx, advertisement)
	if err != nil {
		return nil, err
	}

	nonce, err := deriveWorkloadAttestationNonce(challenge.GetChallengeSeed(), params.WorkloadUNSName, advertisement.eccPublicKeySPKI, csrDER)
	if err != nil {
		return nil, err
	}

	request := &evidenceRequest{
		Nonce:    nonce,
		PCRNonce: challenge.GetPcrNonce(),
		// The mesh seals PcrSelection::Range { pcr_max_inclusive: 16 } and compares the vTPM quote
		// against the bitfield it widens to, so the wire bitfield selects the identical slots.
		PCRSelectionBitfield: challenge.GetPcrSelectionBitfield(),
		ChallengeExpiresAt:   challenge.GetExpiresAt(),
	}
	evidence, err := stubEvidence(request, time.Now())
	if err != nil {
		return nil, err
	}

	issued, err := c.attestMeshWorkload(ctx, advertisement, challenge, params.WorkloadUNSName, csrDER, evidence)
	if err != nil {
		return nil, err
	}
	return buildMeshAttestation(issued, privateKey)
}

// FetchMeshAdvertisementAnchor fetches the advertisement and returns the certificate a pin is
// taken against, without attesting. This is where a pin comes from the FIRST time, and it is trust
// on first use: the returned anchor is whatever answered this call. Everything except the walk to a
// pinned root is checked before returning, so a chain signed by someone else's leaf, or naming
// another agent or trust domain, is refused here -- but a peer that held a leaf naming this agent
// would be returned just as happily. Confirm the value out of band before shipping it as a build
// input.
func (c *Client) FetchMeshAdvertisementAnchor(ctx context.Context, agentFQDN string, trustDomain spiffeid.TrustDomain) (*MeshAdvertisementAnchor, error) {
	resp := new(meshattestpb.GetEnvelopeKeyResponse)
	if err := c.invokeMesh(ctx, getEnvelopeKeyPath, new(meshattestpb.GetEnvelopeKeyRequest), resp); err != nil {
		return nil, err
	}
	if err := verifyAdvertisementExceptChainAnchor(resp, agentFQDN, trustDomain.Name(), time.Now()); err != nil {
		return nil, err
	}
	terminal, err := advertisementChainTerminal(resp)
	if err != nil {
		return nil, err
	}
	return &MeshAdvertisementAnchor{Certificate: terminal, SPKISHA256: spkiSHA256(terminal)}, nil
}

func (c *Client) fetchMeshAdvertisement(ctx context.Context, anchors *MeshTrustAnchors, agentFQDN string, trustDomain spiffeid.TrustDomain) (*verifiedAdvertisement, error) {
	resp := new(meshattestpb.GetEnvelopeKeyResponse)
	if err := c.invokeMesh(ctx, getEnvelopeKeyPath, new(meshattestpb.GetEnvelopeKeyRequest), resp); err != nil {
		return nil, err
	}
	return verifyAdvertisement(resp, anchors, agentFQDN, trustDomain.Name(), time.Now())
}

func (c *Client) requestMeshAttestationChallenge(ctx context.Context, advertisement *verifiedAdvertisement) (*meshattestpb.AttestationChallengeResponseInner, error) {
	session, err := establishEnvelopeSession(advertisement, getAttestationChallengePath)
	if err != nil {
		return nil, err
	}
	clientRequestID, err := newClientRequestID()
	if err != nil {
		return nil, err
	}

	inner, err := proto.Marshal(&meshattestpb.AttestationChallengeRequestInner{
		AttestationType: attestationTypeMeshTdxVtpm,
		ClientRequestId: clientRequestID,
		ClientTimestamp: time.Now().Unix(),
	})
	if err != nil {
		return nil, fmt.Errorf("encoding the challenge request failed: %w", err)
	}

	challenge := new(meshattestpb.AttestationChallengeResponseInner)
	if err := c.sealedRoundTrip(ctx, session, getAttestationChallengePath, inner, challenge); err != nil {
		return nil, err
	}
	if !bytesEqual(challenge.GetClientRequestId(), clientRequestID) {
		return nil, errors.New("the challenge echoed a different client_request_id than the one sent")
	}
	return challenge, nil
}

func (c *Client) attestMeshWorkload(
	ctx context.Context,
	advertisement *verifiedAdvertisement,
	challenge *meshattestpb.AttestationChallengeResponseInner,
	workloadUNSName string,
	csrDER []byte,
	evidence *meshattestpb.AttestationEvidence,
) (*meshattestpb.AttestWorkloadResponseInner, error) {
	// A second session, not the challenge leg's: the AAD names the method, so reusing one would
	// make the sealed body portable between the two routes.
	session, err := establishEnvelopeSession(advertisement, attestWorkloadPath)
	if err != nil {
		return nil, err
	}
	clientRequestID, err := newClientRequestID()
	if err != nil {
		return nil, err
	}

	inner, err := proto.Marshal(&meshattestpb.AttestWorkloadRequestInner{
		Challenge:       challenge.GetChallenge(),
		Csr:             csrDER,
		WorkloadUnsName: workloadUNSName,
		Evidence:        evidence,
		ClientRequestId: clientRequestID,
	})
	if err != nil {
		return nil, fmt.Errorf("encoding the attestation request failed: %w", err)
	}

	issued := new(meshattestpb.AttestWorkloadResponseInner)
	if err := c.sealedRoundTrip(ctx, session, attestWorkloadPath, inner, issued); err != nil {
		return nil, err
	}
	if !bytesEqual(issued.GetClientRequestId(), clientRequestID) {
		return nil, errors.New("the attestation echoed a different client_request_id than the one sent")
	}
	return issued, nil
}

func (c *Client) sealedRoundTrip(ctx context.Context, session *envelopeSession, path string, inner []byte, out proto.Message) error {
	sealed, err := session.sealRequest(inner)
	if err != nil {
		return err
	}
	response := new(meshattestpb.SealedResponse)
	if err := c.invokeMesh(ctx, path, sealed, response); err != nil {
		return err
	}
	if response.GetSuite() != envelopeSuiteEccP256MlKem768Aes256Gcm {
		return fmt.Errorf("%s answered with envelope suite %d, which this client does not know", path, response.GetSuite())
	}
	plaintext, err := session.openResponse(response.GetCiphertext())
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := proto.Unmarshal(plaintext, out); err != nil {
		return fmt.Errorf("%s answered with a sealed body that will not decode: %w", path, err)
	}
	return nil
}

// invokeMesh makes one unary call on the relay's socket. The security header goes on every method:
// the relay enforces it itself, because upstream's verifySecurityHeader only guards methods under
// /SpiffeWorkloadAPI/ and this service is outside that prefix.
//
// Every mesh refusal is one uniform PermissionDenied, deliberately, so this reports the gRPC code
// verbatim rather than translating it. The one status that is NOT a refusal is ResourceExhausted,
// which is a purely local capacity condition on this host's relay; a caller that could not tell it
// from a refusal would give up permanently on a condition that clears as soon as another workload
// finishes.
func (c *Client) invokeMesh(ctx context.Context, path string, req, resp proto.Message) error {
	backoff := relayBusyBackoffInitial
	for attempt := 0; ; attempt++ {
		callCtx, cancel := context.WithTimeout(withHeader(ctx), meshAttestCallTimeout)
		err := c.conn.Invoke(callCtx, path, req, resp)
		cancel()
		if err == nil {
			return nil
		}
		if status.Code(err) == codes.ResourceExhausted && attempt < relayBusyRetries {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
			continue
		}
		return fmt.Errorf("%s failed with gRPC status %s: %w", path, status.Code(err), err)
	}
}

// generateWorkloadKeyAndCSR produces the key this workload will hold and the CSR the issuer will
// sign. The CSR's DER is what the quote commits to and what the issuer signs over, so it is carried
// as DER from here to the wire without a PEM round trip: re-encoding it anywhere between would
// change the derived nonce and the mesh would refuse with no indication why.
func generateWorkloadKeyAndCSR(workloadUNSName string) (*ecdsa.PrivateKey, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating the workload P-256 key failed: %w", err)
	}

	// The CN is decoration: the mesh takes the identity from its own registration and puts it in
	// the URI SAN, and sign_entity_svid refuses a CN past this same ceiling. A UNS name is bounded
	// at MAX_WORKLOAD_UNS_NAME_LEN (512), so the full name does not fit and wolfSSL refuses it with
	// a status that names nothing. UNS names are ASCII by normalize_workload_uns_name, so a byte
	// cut is a character cut.
	commonName := workloadUNSName
	if len(commonName) > maxCertCommonNameLen {
		commonName = commonName[len(commonName)-maxCertCommonNameLen:]
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: commonName},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("building the CSR failed for a %d-byte common name: %w", len(commonName), err)
	}
	return privateKey, csrDER, nil
}

func buildMeshAttestation(issued *meshattestpb.AttestWorkloadResponseInner, privateKey *ecdsa.PrivateKey) (*MeshAttestation, error) {
	svid := issued.GetSvid()
	if svid == nil {
		return nil, errors.New("the mesh accepted the attestation but returned no SVID")
	}
	certificates, err := parseCertificates(svid.GetCertChain())
	if err != nil {
		return nil, fmt.Errorf("the issued SVID chain will not parse: %w", err)
	}
	if len(certificates) == 0 {
		return nil, errors.New("the issued SVID carries no certificates")
	}

	id, err := spiffeid.FromString(spiffeURIPrefix + svid.GetId().GetTrustDomain() + svid.GetId().GetPath())
	if err != nil {
		return nil, fmt.Errorf("the issued SVID names an unusable SPIFFE ID: %w", err)
	}

	attestation := &MeshAttestation{
		SVID: &x509svid.SVID{
			ID:           id,
			Certificates: certificates,
			PrivateKey:   privateKey,
			Hint:         svid.GetHint(),
		},
		Bundles: x509bundle.NewSet(),
	}

	if bundle := issued.GetBundle(); bundle != nil {
		var authorities []*x509.Certificate
		for _, authority := range bundle.GetX509Authorities() {
			certificate, err := x509.ParseCertificate(authority.GetAsn1())
			if err != nil {
				return nil, fmt.Errorf("a returned trust bundle authority will not parse: %w", err)
			}
			authorities = append(authorities, certificate)
		}
		trustDomain, err := spiffeid.TrustDomainFromString(bundle.GetTrustDomain())
		if err != nil {
			return nil, fmt.Errorf("the returned trust bundle names an unusable trust domain: %w", err)
		}
		attestation.Bundles.Add(x509bundle.FromX509Authorities(trustDomain, authorities))
	}
	return attestation, nil
}

func parseCertificates(ders [][]byte) ([]*x509.Certificate, error) {
	certificates := make([]*x509.Certificate, 0, len(ders))
	for _, der := range ders {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
	}
	return certificates, nil
}

// newClientRequestID stays inside the bound the mesh enforces. bounded_client_request_id
// (actors/actor-spiffe-agent/src/workload_attestation_handler.rs) refuses an oversized id before
// echoing it, and that refusal is the same opaque status as a failed quote.
func newClientRequestID() ([]byte, error) {
	size := clientRequestIDLen
	if size > maxClientRequestIDLen {
		size = maxClientRequestIDLen
	}
	id := make([]byte, size)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("generating a client request id failed: %w", err)
	}
	return id, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
