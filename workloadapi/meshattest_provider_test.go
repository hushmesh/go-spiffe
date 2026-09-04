package workloadapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	meshattestpb "github.com/spiffe/go-spiffe/v2/proto/hushmesh/workload/v1"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// testProvider stands in for a platform this library has never seen: it implements the exported
// interface and nothing else, which is the property the whole seam exists to have.
type testProvider struct {
	name            string
	attestationType string
	available       error
	collect         func(ctx context.Context, request *MeshEvidenceRequest) (*meshattestpb.AttestationEvidence, error)
	seen            *MeshEvidenceRequest
	collectCalls    int
}

func (p *testProvider) Name() string { return p.name }

func (p *testProvider) AttestationType() string {
	if p.attestationType == "" {
		return MeshAttestationTypeTDXVTPM
	}
	return p.attestationType
}

func (p *testProvider) Available() error { return p.available }

func (p *testProvider) CollectEvidence(ctx context.Context, request *MeshEvidenceRequest) (*meshattestpb.AttestationEvidence, error) {
	p.seen, p.collectCalls = request, p.collectCalls+1
	if p.collect != nil {
		return p.collect(ctx, request)
	}
	if err := request.CheckAnswerable(); err != nil {
		return nil, err
	}
	userData, err := request.ReportData()
	if err != nil {
		return nil, err
	}
	varData, err := json.Marshal(map[string]any{"user-data": hex.EncodeToString(userData)})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(varData)
	return &meshattestpb.AttestationEvidence{
		Quote:            digest[:],
		UserData:         userData,
		VarData:          varData,
		VarDataOperation: varDataOperationSha256,
		TpmQuote:         &meshattestpb.TpmQuoteEvidence{Report: []byte("attest"), Signature: []byte("sig")},
	}, nil
}

var _ MeshEvidenceProvider = (*testProvider)(nil)

// The point of the exercise: a provider written outside this package reaches the wire, and the
// bundle the mesh receives is the one it produced.
func TestAThirdPartyProviderCollectsTheEvidenceThatReachesTheMesh(t *testing.T) {
	mesh := newFakeMesh(t)
	address := serveFakeMesh(t, mesh)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := New(ctx, WithAddr(address))
	require.NoError(t, err)
	defer client.Close()

	provider := &testProvider{name: "someone-elses-platform"}
	attestation, err := client.AttestMeshWorkload(ctx, MeshAttestParams{
		AgentFQDN:         fakeMeshAgentFQDN,
		TrustDomain:       spiffeid.RequireTrustDomainFromString(fakeMeshTrustDomain),
		WorkloadUNSName:   fakeMeshUNSName,
		Anchors:           mesh.anchors(),
		EvidenceProviders: []MeshEvidenceProvider{provider},
	})
	require.NoError(t, err)
	assert.Equal(t, "spiffe://"+fakeMeshTrustDomain+fakeMeshSVIDPath, attestation.SVID.ID.String())

	require.Equal(t, 1, provider.collectCalls)
	require.NotNil(t, provider.seen)
	assert.Len(t, provider.seen.Nonce, meshIDLen, "the ADR-0041 fold output is the provider's to commit to")
	assert.Equal(t, mesh.pcrNonce, provider.seen.PCRNonce)
	assert.NotZero(t, provider.seen.PCRSelectionBitfield)
	assert.False(t, provider.seen.CollectedAt.IsZero(), "report data needs a wall clock the mesh can range-check")
	assert.NoError(t, provider.seen.CheckAnswerable())
}

// The attestation type is the provider's to declare rather than the client's to hardcode -- but
// the mesh implements exactly one, and a provider that invents another is refused with the same
// status a bad quote gets. Both halves of that are worth pinning.
func TestTheProviderDeclaresTheAttestationTypeAndTheMeshKnowsOne(t *testing.T) {
	for _, provider := range BuiltinMeshEvidenceProviders() {
		assert.Equal(t, MeshAttestationTypeTDXVTPM, provider.AttestationType(), provider.Name())
	}
	assert.Equal(t, MeshAttestationTypeTDXVTPM, stubEvidenceProvider{}.AttestationType())

	mesh := newFakeMesh(t)
	address := serveFakeMesh(t, mesh)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := New(ctx, WithAddr(address))
	require.NoError(t, err)
	defer client.Close()

	_, err = client.AttestMeshWorkload(ctx, MeshAttestParams{
		AgentFQDN:         fakeMeshAgentFQDN,
		TrustDomain:       spiffeid.RequireTrustDomainFromString(fakeMeshTrustDomain),
		WorkloadUNSName:   fakeMeshUNSName,
		Anchors:           mesh.anchors(),
		EvidenceProviders: []MeshEvidenceProvider{&testProvider{name: "future", attestationType: "mesh_something_else"}},
	})
	assert.Error(t, err, "the mesh re-checks the type on the attest leg, so an unknown one cannot be smuggled past the challenge")
}

// The availability check is a pre-flight, not a first step: a challenge is single-use mesh state,
// so a host that cannot answer must be discovered before the mesh is asked for one.
func TestAnUnavailableProviderStopsBeforeTheMeshIsCalled(t *testing.T) {
	mesh := newFakeMesh(t)
	address := serveFakeMesh(t, mesh)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := New(ctx, WithAddr(address))
	require.NoError(t, err)
	defer client.Close()

	provider := &testProvider{name: "no-hardware-here", available: errors.New("no quoting device")}
	_, err = client.AttestMeshWorkload(ctx, MeshAttestParams{
		AgentFQDN:         fakeMeshAgentFQDN,
		TrustDomain:       spiffeid.RequireTrustDomainFromString(fakeMeshTrustDomain),
		WorkloadUNSName:   fakeMeshUNSName,
		Anchors:           mesh.anchors(),
		EvidenceProviders: []MeshEvidenceProvider{provider},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no-hardware-here", "the refusal must name which provider declined and why")
	assert.Contains(t, err.Error(), "no quoting device")
	assert.Zero(t, provider.collectCalls)
	assert.False(t, mesh.seenSecurityHeader, "not one RPC may be spent on a host that cannot answer")
}

func TestProviderSelectionTakesTheFirstAvailableInOrder(t *testing.T) {
	first := &testProvider{name: "first", available: errors.New("not this host")}
	second := &testProvider{name: "second"}
	third := &testProvider{name: "third"}

	chosen, err := resolveMeshEvidenceProvider(MeshAttestParams{
		EvidenceProviders: []MeshEvidenceProvider{first, second, third},
	})
	require.NoError(t, err)
	assert.Equal(t, "second", chosen.Name())

	_, err = resolveMeshEvidenceProvider(MeshAttestParams{
		EvidenceProviders: []MeshEvidenceProvider{
			first,
			&testProvider{name: "also-not", available: errors.New("nor this one")},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not this host")
	assert.Contains(t, err.Error(), "nor this one", "every declined provider's reason survives, or detection failures are undebuggable")
	assert.Contains(t, err.Error(), "StubEvidence", "the one way forward on a host with no hardware belongs in the refusal")
}

func TestStubEvidenceStaysAnExplicitOptIn(t *testing.T) {
	for _, provider := range BuiltinMeshEvidenceProviders() {
		assert.NotEqual(t, stubEvidenceProvider{}.Name(), provider.Name(),
			"a bundle that verifies nowhere must never be reachable by detection")
	}

	chosen, err := resolveMeshEvidenceProvider(MeshAttestParams{StubEvidence: true})
	require.NoError(t, err)
	assert.Equal(t, "stub", chosen.Name())

	_, err = resolveMeshEvidenceProvider(MeshAttestParams{
		StubEvidence:      true,
		EvidenceProviders: []MeshEvidenceProvider{&testProvider{name: "real"}},
	})
	assert.Error(t, err, "two contradictory answers to what to send is a configuration bug, not a precedence question")

	_, err = resolveMeshEvidenceProvider(MeshAttestParams{
		EvidenceProviders: []MeshEvidenceProvider{nil},
	})
	assert.Error(t, err)
}

func TestBuiltinSelectionFallsBackToTheAzureProvider(t *testing.T) {
	builtins := BuiltinMeshEvidenceProviders()
	require.Len(t, builtins, 1, "ship the providers that can be exercised; a placeholder produces unverifiable evidence silently")
	assert.Equal(t, "azure-tdx-vtpm", builtins[0].Name())

	// Whether detection succeeds depends on the host, so what is pinned here is that an empty
	// params consults the built-in list at all rather than defaulting to something else.
	chosen, err := resolveMeshEvidenceProvider(MeshAttestParams{})
	if err == nil {
		assert.Equal(t, builtins[0].Name(), chosen.Name())
	} else {
		assert.Contains(t, err.Error(), builtins[0].Name())
	}
}

func TestReportDataIsTheValueBothHalvesOfTheBindingUse(t *testing.T) {
	now := time.Now()
	request := &MeshEvidenceRequest{
		Nonce:                bytes.Repeat([]byte{7}, meshIDLen),
		PCRNonce:             bytes.Repeat([]byte{2}, meshIDLen),
		PCRSelectionBitfield: 0x1_ffff,
		ChallengeExpiresAt:   now.Unix() + 120,
		CollectedAt:          now,
	}
	reportData, err := request.ReportData()
	require.NoError(t, err)

	expected, err := meshReportData(request.Nonce, now)
	require.NoError(t, err)
	assert.Equal(t, expected, reportData)
	assert.Len(t, reportData, reportDataLen)

	request.Nonce = bytes.Repeat([]byte{7}, meshIDLen-1)
	_, err = request.ReportData()
	assert.Error(t, err)
	assert.Error(t, request.CheckAnswerable(), "a short nonce cannot fill the field the quote commits to")
}

// UserData is the only field of the bundle the client can check for itself, and the first thing
// CollectEvidence's contract asks for. A provider that gets it wrong otherwise spends a single-use
// challenge to learn nothing.
func TestUserDataThatIsNotTheDerivedReportDataIsRefusedLocally(t *testing.T) {
	mesh := newFakeMesh(t)
	address := serveFakeMesh(t, mesh)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := New(ctx, WithAddr(address))
	require.NoError(t, err)
	defer client.Close()

	attest := func(collect func(context.Context, *MeshEvidenceRequest) (*meshattestpb.AttestationEvidence, error)) error {
		_, err := client.AttestMeshWorkload(ctx, MeshAttestParams{
			AgentFQDN:         fakeMeshAgentFQDN,
			TrustDomain:       spiffeid.RequireTrustDomainFromString(fakeMeshTrustDomain),
			WorkloadUNSName:   fakeMeshUNSName,
			Anchors:           mesh.anchors(),
			EvidenceProviders: []MeshEvidenceProvider{&testProvider{name: "wrong-user-data", collect: collect}},
		})
		return err
	}

	err = attest(func(_ context.Context, request *MeshEvidenceRequest) (*meshattestpb.AttestationEvidence, error) {
		userData, err := meshReportData(request.Nonce, request.CollectedAt.Add(-time.Hour))
		if err != nil {
			return nil, err
		}
		return &meshattestpb.AttestationEvidence{UserData: userData, VarDataOperation: varDataOperationSha256}, nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wrong-user-data", "the refusal names the provider that produced it")
	assert.Contains(t, err.Error(), "user data")

	err = attest(func(context.Context, *MeshEvidenceRequest) (*meshattestpb.AttestationEvidence, error) {
		return &meshattestpb.AttestationEvidence{VarDataOperation: varDataOperationSha256}, nil
	})
	assert.Error(t, err, "an omitted field is a divergence like any other")

	err = attest(func(context.Context, *MeshEvidenceRequest) (*meshattestpb.AttestationEvidence, error) {
		return nil, nil
	})
	assert.Error(t, err, "no evidence and no error is not a bundle")
}
