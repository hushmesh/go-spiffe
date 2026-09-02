package workloadapi

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	meshattestpb "github.com/spiffe/go-spiffe/v2/proto/hushmesh/workload/v1"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const (
	fakeMeshAgentFQDN   = "localtest.mesh.in"
	fakeMeshTrustDomain = "abc123.spiffe.example.mesh.in"
	fakeMeshUNSName     = "in.mesh.org21.e2e-attested"
	fakeMeshSVIDPath    = "/mesh-attested/e2e-attested"
)

// fakeMesh stands in for the mesh's SPIFFE agent behind the relay. It runs the mesh half of every
// construction this client implements -- the hybrid agreement, the AAD, the two direction keys,
// the ADR-0041 nonce -- so a divergence in any of them fails here rather than as an opaque status
// against a live mesh.
type fakeMesh struct {
	t *testing.T

	rootKey *ecdsa.PrivateKey
	root    *x509.Certificate

	leafKey *ecdsa.PrivateKey
	leafDER []byte

	envelopeKeyID []byte
	envelopeECC   *ecdh.PrivateKey
	envelopeMLKEM *mlkem.DecapsulationKey768

	issuedChallenge []byte
	challengeSeed   []byte
	pcrNonce        []byte

	// seenSecurityHeader records whether the caller sent the Workload API security header, which
	// the relay requires on all three methods.
	seenSecurityHeader bool
}

func newFakeMesh(t *testing.T) *fakeMesh {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Mesh External Root CA"},
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
	agentURI, err := url.Parse(agentServerSPIFFEID(fakeMeshAgentFQDN))
	require.NoError(t, err)
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Mesh SPIFFE Agent"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		URIs:         []*url.URL{agentURI},
	}, root, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)

	envelopeECC, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	envelopeMLKEM, err := mlkem.GenerateKey768()
	require.NoError(t, err)

	return &fakeMesh{
		t:             t,
		rootKey:       rootKey,
		root:          root,
		leafKey:       leafKey,
		leafDER:       leafDER,
		envelopeKeyID: randomBytes(t, meshIDLen),
		envelopeECC:   envelopeECC,
		envelopeMLKEM: envelopeMLKEM,
		challengeSeed: randomBytes(t, meshIDLen),
		pcrNonce:      randomBytes(t, meshIDLen),
	}
}

func (m *fakeMesh) anchors() *MeshTrustAnchors {
	return &MeshTrustAnchors{
		PinnedRootSPKISHA256: [][]byte{spkiSHA256(m.root)},
		RootCertificates:     [][]byte{m.root.Raw},
	}
}

func (m *fakeMesh) advertisement() *meshattestpb.GetEnvelopeKeyResponse {
	eccSPKI, err := x509.MarshalPKIXPublicKey(m.envelopeECC.PublicKey())
	require.NoError(m.t, err)

	resp := &meshattestpb.GetEnvelopeKeyResponse{
		KeyId:            m.envelopeKeyID,
		EccPublicKeySpki: eccSPKI,
		MlkemPublicKey:   m.envelopeMLKEM.EncapsulationKey().Bytes(),
		ExpiresAt:        time.Now().Add(24 * time.Hour).Unix(),
		CertChain:        [][]byte{m.leafDER, m.root.Raw},
		TrustDomain:      fakeMeshTrustDomain,
	}
	digest := sha512.Sum384(advertisementSigningInput(resp.KeyId, resp.EccPublicKeySpki, resp.MlkemPublicKey, resp.ExpiresAt, resp.TrustDomain))
	r, s, err := ecdsa.Sign(rand.Reader, m.leafKey, digest[:])
	require.NoError(m.t, err)
	signature := make([]byte, 2*p384ComponentLen)
	r.FillBytes(signature[:p384ComponentLen])
	s.FillBytes(signature[p384ComponentLen:])
	resp.Signature = signature
	return resp
}

// openSealed runs the mesh's half of the envelope: decapsulate, agree, rebuild the AAD from the
// fields the request carries, and open under the workload-to-mesh key.
func (m *fakeMesh) openSealed(req *meshattestpb.SealedRequest, grpcPath string) (plaintext, responseKey, aad []byte, err error) {
	if req.GetSuite() != envelopeSuiteEccP256MlKem768Aes256Gcm {
		return nil, nil, nil, errors.New("unsupported envelope suite")
	}
	if string(req.GetRecipientKeyId()) != string(m.envelopeKeyID) {
		return nil, nil, nil, errors.New("envelope names a different recipient key")
	}
	senderPublic, err := parseECDHPublicKeySPKI(req.GetSenderEccPublicKeySpki())
	if err != nil {
		return nil, nil, nil, err
	}
	ecdhSecret, err := m.envelopeECC.ECDH(senderPublic)
	if err != nil {
		return nil, nil, nil, err
	}
	mlkemSecret, err := m.envelopeMLKEM.Decapsulate(req.GetEncapsulatedKey())
	if err != nil {
		return nil, nil, nil, err
	}
	hybrid := sha256.Sum256(append(append([]byte{}, ecdhSecret...), mlkemSecret...))

	aad, err = envelopeAAD{
		GRPCPath:        grpcPath,
		Suite:           envelopeSuiteVariantIndex,
		RecipientKeyID:  m.envelopeKeyID,
		EncapsulatedKey: req.GetEncapsulatedKey(),
	}.marshal()
	if err != nil {
		return nil, nil, nil, err
	}

	plaintext, err = meshDecrypt(meshDeriveKeyFromVec(hybrid[:], envelopeLabelW2M), req.GetCiphertext(), aad)
	if err != nil {
		return nil, nil, nil, err
	}
	return plaintext, meshDeriveKeyFromVec(hybrid[:], envelopeLabelM2W), aad, nil
}

func (m *fakeMesh) sealResponse(responseKey, aad []byte, message proto.Message) (*meshattestpb.SealedResponse, error) {
	body, err := proto.Marshal(message)
	if err != nil {
		return nil, err
	}
	ciphertext, err := meshEncrypt(responseKey, body, aad)
	if err != nil {
		return nil, err
	}
	return &meshattestpb.SealedResponse{Suite: envelopeSuiteEccP256MlKem768Aes256Gcm, Ciphertext: ciphertext}, nil
}

func (m *fakeMesh) recordSecurityHeader(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok || len(md.Get("workload.spiffe.io")) != 1 || md.Get("workload.spiffe.io")[0] != "true" {
		return status.Error(codes.InvalidArgument, "security header required")
	}
	m.seenSecurityHeader = true
	return nil
}

func (m *fakeMesh) GetEnvelopeKey(ctx context.Context, _ *meshattestpb.GetEnvelopeKeyRequest) (*meshattestpb.GetEnvelopeKeyResponse, error) {
	if err := m.recordSecurityHeader(ctx); err != nil {
		return nil, err
	}
	return m.advertisement(), nil
}

func (m *fakeMesh) GetAttestationChallenge(ctx context.Context, req *meshattestpb.SealedRequest) (*meshattestpb.SealedResponse, error) {
	if err := m.recordSecurityHeader(ctx); err != nil {
		return nil, err
	}
	plaintext, responseKey, aad, err := m.openSealed(req, getAttestationChallengePath)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, "refused")
	}
	inner := new(meshattestpb.AttestationChallengeRequestInner)
	if err := proto.Unmarshal(plaintext, inner); err != nil {
		return nil, status.Error(codes.PermissionDenied, "refused")
	}
	if inner.GetAttestationType() != attestationTypeMeshTdxVtpm {
		return nil, status.Error(codes.PermissionDenied, "refused")
	}

	m.issuedChallenge = randomBytes(m.t, 48)
	return m.sealResponseOrRefuse(responseKey, aad, &meshattestpb.AttestationChallengeResponseInner{
		ClientRequestId:      inner.GetClientRequestId(),
		Challenge:            m.issuedChallenge,
		ChallengeSeed:        m.challengeSeed,
		PcrNonce:             m.pcrNonce,
		PcrSelectionBitfield: 0x1_ffff,
		ExpiresAt:            time.Now().Add(2 * time.Minute).Unix(),
	})
}

func (m *fakeMesh) AttestWorkload(ctx context.Context, req *meshattestpb.SealedRequest) (*meshattestpb.SealedResponse, error) {
	if err := m.recordSecurityHeader(ctx); err != nil {
		return nil, err
	}
	plaintext, responseKey, aad, err := m.openSealed(req, attestWorkloadPath)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, "refused")
	}
	inner := new(meshattestpb.AttestWorkloadRequestInner)
	if err := proto.Unmarshal(plaintext, inner); err != nil {
		return nil, status.Error(codes.PermissionDenied, "refused")
	}
	if string(inner.GetChallenge()) != string(m.issuedChallenge) {
		return nil, status.Error(codes.PermissionDenied, "refused")
	}

	eccSPKI, err := x509.MarshalPKIXPublicKey(m.envelopeECC.PublicKey())
	require.NoError(m.t, err)
	expectedNonce, err := deriveWorkloadAttestationNonce(m.challengeSeed, inner.GetWorkloadUnsName(), eccSPKI, inner.GetCsr())
	require.NoError(m.t, err)
	// The whole point of the fold: the mesh recomputes it from what it received and compares it to
	// what the quote committed to. A client that derived it over anything else fails right here.
	if string(inner.GetEvidence().GetUserData()[:meshIDLen]) != string(expectedNonce) {
		return nil, status.Error(codes.PermissionDenied, "refused")
	}

	svidDER := m.issueSVID(inner.GetCsr())
	return m.sealResponseOrRefuse(responseKey, aad, &meshattestpb.AttestWorkloadResponseInner{
		ClientRequestId: inner.GetClientRequestId(),
		Svid: &meshattestpb.X509SVID{
			CertChain: [][]byte{svidDER, m.root.Raw},
			Id:        &meshattestpb.SPIFFEID{TrustDomain: fakeMeshTrustDomain, Path: fakeMeshSVIDPath},
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
		Bundle: &meshattestpb.Bundle{
			TrustDomain:     fakeMeshTrustDomain,
			X509Authorities: []*meshattestpb.X509Certificate{{Asn1: m.root.Raw}},
		},
	})
}

func (m *fakeMesh) sealResponseOrRefuse(responseKey, aad []byte, message proto.Message) (*meshattestpb.SealedResponse, error) {
	sealed, err := m.sealResponse(responseKey, aad, message)
	if err != nil {
		return nil, status.Error(codes.Internal, "sealing failed")
	}
	return sealed, nil
}

func (m *fakeMesh) issueSVID(csrDER []byte) []byte {
	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(m.t, err)
	require.NoError(m.t, csr.CheckSignature())

	svidURI, err := url.Parse("spiffe://" + fakeMeshTrustDomain + fakeMeshSVIDPath)
	require.NoError(m.t, err)
	svidDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		URIs:         []*url.URL{svidURI},
	}, m.root, csr.PublicKey, m.rootKey)
	require.NoError(m.t, err)
	return svidDER
}

var fakeMeshServiceDesc = grpc.ServiceDesc{
	ServiceName: "hushmesh.api.server.workload.v1.WorkloadAttestation",
	HandlerType: (*any)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetEnvelopeKey",
			Handler: func(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
				in := new(meshattestpb.GetEnvelopeKeyRequest)
				if err := dec(in); err != nil {
					return nil, err
				}
				return srv.(*fakeMesh).GetEnvelopeKey(ctx, in)
			},
		},
		{
			MethodName: "GetAttestationChallenge",
			Handler: func(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
				in := new(meshattestpb.SealedRequest)
				if err := dec(in); err != nil {
					return nil, err
				}
				return srv.(*fakeMesh).GetAttestationChallenge(ctx, in)
			},
		},
		{
			MethodName: "AttestWorkload",
			Handler: func(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
				in := new(meshattestpb.SealedRequest)
				if err := dec(in); err != nil {
					return nil, err
				}
				return srv.(*fakeMesh).AttestWorkload(ctx, in)
			},
		},
	},
	Metadata: "workload_attestation.proto",
}

func serveFakeMesh(t *testing.T, mesh *fakeMesh) string {
	t.Helper()
	// Not t.TempDir(): its path is long enough on macOS to exceed the 104-byte sun_path limit, and
	// the bind then fails with nothing but "invalid argument".
	dir, err := os.MkdirTemp("", "ma")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	socketPath := filepath.Join(dir, "a.sock")
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)

	server := grpc.NewServer()
	server.RegisterService(&fakeMeshServiceDesc, mesh)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	return "unix://" + socketPath
}

func TestAttestMeshWorkloadCompletesTheWholeFlow(t *testing.T) {
	mesh := newFakeMesh(t)
	address := serveFakeMesh(t, mesh)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := New(ctx, WithAddr(address))
	require.NoError(t, err)
	defer client.Close()

	attestation, err := client.AttestMeshWorkload(ctx, MeshAttestParams{
		AgentFQDN:       fakeMeshAgentFQDN,
		TrustDomain:     spiffeid.RequireTrustDomainFromString(fakeMeshTrustDomain),
		WorkloadUNSName: fakeMeshUNSName,
		Anchors:         mesh.anchors(),
		StubEvidence:    true,
	})
	require.NoError(t, err)

	assert.True(t, mesh.seenSecurityHeader, "the relay requires the Workload API security header on all three methods")
	assert.Equal(t, "spiffe://"+fakeMeshTrustDomain+fakeMeshSVIDPath, attestation.SVID.ID.String())
	assert.Len(t, attestation.SVID.Certificates, 2)
	assert.NotNil(t, attestation.SVID.PrivateKey)

	bundle, ok := attestation.Bundles.Get(spiffeid.RequireTrustDomainFromString(fakeMeshTrustDomain))
	require.True(t, ok)
	assert.Len(t, bundle.X509Authorities(), 1)

	// The issued leaf must be for the key this process generated, or the workload holds an SVID it
	// cannot use.
	leafPublic, ok := attestation.SVID.Certificates[0].PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.True(t, leafPublic.Equal(attestation.SVID.PrivateKey.Public()))
}

func TestFetchMeshAdvertisementAnchorReturnsTheChainTerminal(t *testing.T) {
	mesh := newFakeMesh(t)
	address := serveFakeMesh(t, mesh)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := New(ctx, WithAddr(address))
	require.NoError(t, err)
	defer client.Close()

	anchor, err := client.FetchMeshAdvertisementAnchor(ctx, fakeMeshAgentFQDN, spiffeid.RequireTrustDomainFromString(fakeMeshTrustDomain))
	require.NoError(t, err)
	assert.Equal(t, mesh.root.Raw, anchor.Certificate.Raw, "the chain terminates at the issuing CA, so the pin is taken against the last element")
	assert.Equal(t, spkiSHA256(mesh.root), anchor.SPKISHA256)

	// The bootstrap's output must be usable as the next run's input, or every run silently fails
	// the chain check.
	anchors := &MeshTrustAnchors{PinnedRootSPKISHA256: [][]byte{anchor.SPKISHA256}, RootCertificates: [][]byte{anchor.Certificate.Raw}}
	_, err = verifyAdvertisement(mesh.advertisement(), anchors, fakeMeshAgentFQDN, fakeMeshTrustDomain, time.Now())
	assert.NoError(t, err)
}

func TestAttestMeshWorkloadRefusesAnAdvertisementForAnotherTrustDomain(t *testing.T) {
	mesh := newFakeMesh(t)
	address := serveFakeMesh(t, mesh)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := New(ctx, WithAddr(address))
	require.NoError(t, err)
	defer client.Close()

	_, err = client.AttestMeshWorkload(ctx, MeshAttestParams{
		AgentFQDN:       fakeMeshAgentFQDN,
		TrustDomain:     spiffeid.RequireTrustDomainFromString("other.spiffe.example.mesh.in"),
		WorkloadUNSName: fakeMeshUNSName,
		Anchors:         mesh.anchors(),
		StubEvidence:    true,
	})
	assert.ErrorIs(t, err, ErrAdvertisementRefused)
}

func randomBytes(t *testing.T, size int) []byte {
	t.Helper()
	buf := make([]byte, size)
	_, err := rand.Read(buf)
	require.NoError(t, err)
	return buf
}
