// The provider seam for mesh workload evidence. A confidential-computing platform decides how a
// quote is obtained -- Azure's HCL publishes one through a vTPM NV index and a link-local quoting
// service, a bare-metal TDX host reads a TD report from a guest device, another cloud does
// something else again -- and none of that shape is the mesh's business. What the mesh does insist
// on is the CONTENT of the bundle, which is documented on CollectEvidence and is the same for
// every provider.
//
// A provider owns a whole collection rather than a step of one, because the steps themselves are
// what differ between platforms: an interface split by step would only ever fit the platform it
// was carved from.

package workloadapi

import (
	"context"
	"errors"
	"fmt"

	meshattestpb "github.com/spiffe/go-spiffe/v2/proto/hushmesh/workload/v1"
)

// MeshAttestationTypeTDXVTPM is ATTESTATION_TYPE_MESH_TDX_VTPM, and today it is the only
// attestation type the mesh implements: the agent sends it on the challenge leg and
// open_challenge_token re-checks it on the attest leg. A provider returning anything else is
// refused with the same uniform status a bad quote gets, so return this unless the mesh has been
// taught a new type first.
const MeshAttestationTypeTDXVTPM = attestationTypeMeshTdxVtpm

// MeshEvidenceProvider collects attestation evidence from one confidential-computing platform.
// Implement it to attest from a platform this library has never seen; pass the implementation in
// MeshAttestParams.EvidenceProviders.
//
// WHAT THE MESH VERIFIES. The provider chooses how to reach the hardware; it does not choose what
// the bundle contains. verify_workload_quote wants a TEE quote AND a TPM quote, and every field
// below is checked (mesh-process crates/crate-common-attestation/src/lib.rs, verify_quote_data,
// FingerprintCheck::TdxMap arm):
//
//   - Quote: an SGX/TDX quote, version 3, 4 or 5. Its report data must equal SHA-256 of VarData,
//     zero-padded to 64 bytes. Its measurement (MRTD for TDX) must be a fingerprint the mesh has
//     registered for this workload.
//   - UserData: exactly MeshEvidenceRequest.ReportData(). Anything else fails the nonce, the
//     timestamp or the reserved-bytes check.
//   - VarData: JSON carrying "user-data", the lowercase hex of UserData, and "keys", a JWK set
//     containing an RSA key with kid "HCLAkPub" -- the public half of the key that signed TpmQuote.
//   - VarDataOperation: the SHA-256 discriminant. The TdxMap arm refuses every other value.
//   - TpmQuote.Report: a marshalled TPMS_ATTEST quote whose extraData is PCRNonce, whose PCR
//     selection is exactly PCRSelectionBitfield, in one bank, and whose digest is SHA-256 over the
//     concatenated PcrValues.
//   - TpmQuote.Signature: the BARE signature over Report, verifying under the HCLAkPub key from
//     VarData. Not the TPMT_SIGNATURE the TPM returns.
//   - TpmQuote.PcrValues: one digest per selected slot, ascending by slot index.
//
// That "HCLAkPub" name is an Azure HCL concept, and it is load-bearing: the mesh has no other way
// to learn which key to trust for the TPM quote. A platform whose firmware does not publish an
// HCL-shaped VarData cannot satisfy today's verifier however good its hardware evidence is, so do
// not ship such a provider until the mesh has been taught to verify the shape it can produce. A
// bundle the mesh cannot verify is refused with one uniform PermissionDenied that names nothing.
type MeshEvidenceProvider interface {
	// Name identifies the provider in selection failures and logs. Short and stable, e.g.
	// "azure-tdx-vtpm".
	Name() string

	// AttestationType is the attestation_type sent on the challenge leg and re-checked on the
	// attest leg. Return MeshAttestationTypeTDXVTPM unless the mesh implements another.
	AttestationType() string

	// Available reports whether this host can produce evidence through this provider, and is what
	// auto-detection selects on. It runs BEFORE the mesh is asked for a challenge, because a
	// challenge is single-use state on the mesh side and must not be spent discovering that this
	// host cannot answer it. It must be cheap, read-only, and must not consume anything.
	Available() error

	// CollectEvidence produces the bundle documented above. It must call
	// MeshEvidenceRequest.CheckAnswerable first, and must not send an incomplete bundle in place of
	// an error: a partially filled bundle is spent state on the mesh side and an opaque refusal
	// here.
	CollectEvidence(ctx context.Context, request *MeshEvidenceRequest) (*meshattestpb.AttestationEvidence, error)
}

// BuiltinMeshEvidenceProviders returns the providers auto-detection tries, in preference order.
// Callers that want their own provider considered ahead of these can prepend to this slice and
// pass the result as MeshAttestParams.EvidenceProviders. The stub is deliberately absent: it
// verifies nowhere, so it is reachable only through the explicit MeshAttestParams.StubEvidence
// opt-in and never by detection.
func BuiltinMeshEvidenceProviders() []MeshEvidenceProvider {
	return []MeshEvidenceProvider{newAzureTDXVTPMProvider()}
}

// resolveMeshEvidenceProvider picks the provider and confirms this host can use it, both before a
// challenge is requested.
func resolveMeshEvidenceProvider(params MeshAttestParams) (MeshEvidenceProvider, error) {
	if params.StubEvidence {
		if len(params.EvidenceProviders) > 0 {
			return nil, errors.New("StubEvidence and EvidenceProviders both ask for a different bundle; set one")
		}
		return stubEvidenceProvider{}, nil
	}

	candidates := params.EvidenceProviders
	if len(candidates) == 0 {
		candidates = BuiltinMeshEvidenceProviders()
	}

	var unavailable []error
	for _, candidate := range candidates {
		if candidate == nil {
			return nil, errors.New("EvidenceProviders contains a nil provider")
		}
		err := candidate.Available()
		if err == nil {
			return candidate, nil
		}
		unavailable = append(unavailable, fmt.Errorf("%s: %w", candidate.Name(), err))
	}
	return nil, fmt.Errorf("no evidence provider can attest on this host: %w; set StubEvidence to exercise the path without a quote", errors.Join(unavailable...))
}

// stubEvidenceProvider exercises the envelope and the wire assembly off a confidential host. It
// cannot verify anywhere, and it says so on the wire: varDataOperationAbsent with an empty
// var_data is the honest encoding of "no quote here", where claiming Sha256 over nothing would
// assert a var_data digest that was never computed.
type stubEvidenceProvider struct{}

func (stubEvidenceProvider) Name() string { return "stub" }

func (stubEvidenceProvider) AttestationType() string { return MeshAttestationTypeTDXVTPM }

func (stubEvidenceProvider) Available() error { return nil }

func (stubEvidenceProvider) CollectEvidence(_ context.Context, request *MeshEvidenceRequest) (*meshattestpb.AttestationEvidence, error) {
	if err := request.CheckAnswerable(); err != nil {
		return nil, err
	}
	userData, err := request.ReportData()
	if err != nil {
		return nil, err
	}
	return &meshattestpb.AttestationEvidence{
		Quote:            nil,
		UserData:         userData,
		VarData:          nil,
		VarDataOperation: varDataOperationAbsent,
		TpmQuote:         nil,
	}, nil
}
