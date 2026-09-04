// The Azure confidential-VM provider: an Intel TDX guest whose Hyper-V Host Compatibility Layer
// publishes a report through a vTPM NV index and turns it into a quote through the Instance
// Metadata Service. Everything platform-specific lives in this file and the meshattest_azure_*.go
// beside it -- the HCL envelope layout, the NV indices, the attestation key handle, the IMDS
// endpoint -- so that a second platform is a new file rather than a branch inside this one.

package workloadapi

import (
	"context"
	"errors"
	"fmt"
	"math/bits"

	meshattestpb "github.com/spiffe/go-spiffe/v2/proto/hushmesh/workload/v1"
)

// azureTDXVTPMProvider is stateless; the sources it collects through are a field only so the
// assembly can be tested where the hardware cannot run.
type azureTDXVTPMProvider struct {
	sources evidenceSources
}

func newAzureTDXVTPMProvider() MeshEvidenceProvider {
	return azureTDXVTPMProvider{sources: liveEvidenceSources}
}

func (azureTDXVTPMProvider) Name() string { return "azure-tdx-vtpm" }

func (azureTDXVTPMProvider) AttestationType() string { return MeshAttestationTypeTDXVTPM }

// Available reports whether a vTPM is reachable. It is deliberately not a proof that this is an
// Azure confidential VM -- reading the HCL index's public area would be that, and would be the
// discriminator to reach for the day a second provider makes detection an actual choice. Today it
// is the same check the path used before there was a provider seam.
func (azureTDXVTPMProvider) Available() error {
	return checkVTPMReachable()
}

// CollectEvidence produces the real bundle: a TDX quote whose report data commits to the ADR-0041
// nonce, the HCL variable data that commitment is the digest of, and a vTPM quote over exactly the
// PCR slots this challenge selected.
func (p azureTDXVTPMProvider) CollectEvidence(ctx context.Context, request *MeshEvidenceRequest) (*meshattestpb.AttestationEvidence, error) {
	if err := request.CheckAnswerable(); err != nil {
		return nil, err
	}
	if err := checkQuotableSelection(request.PCRSelectionBitfield); err != nil {
		return nil, err
	}
	userData, err := request.ReportData()
	if err != nil {
		return nil, err
	}

	// These 64 bytes are both what the vTPM is told to commit to and what travels as UserData. The
	// mesh recomputes the fold and compares byte-exactly, so the two have to be the same value and
	// not two constructions of it.
	raw, err := p.sources.hclReport(userData)
	if err != nil {
		return nil, err
	}
	report, err := parseHCLReport(raw)
	if err != nil {
		return nil, err
	}
	tdReport, err := report.tdReport()
	if err != nil {
		return nil, err
	}

	// var_data carries both halves the mesh re-derives: the HCLAkPub the vTPM quote is verified
	// against, and the user-data hex it compares to UserData. Declaring Sha256 over nothing would
	// assert a digest the TD report cannot be carrying.
	varData := report.varData()
	if len(varData) == 0 {
		return nil, errors.New("the hcl report carries no variable data, so it commits to no report data")
	}

	quote, err := p.sources.tdQuote(ctx, tdReport)
	if err != nil {
		return nil, err
	}
	tpmQuote, err := p.sources.tpmQuote(request.PCRNonce, pcrSlotsFromBitfield(request.PCRSelectionBitfield))
	if err != nil {
		return nil, err
	}

	return &meshattestpb.AttestationEvidence{
		Quote:            quote,
		UserData:         userData,
		VarData:          varData,
		VarDataOperation: varDataOperationSha256,
		TpmQuote: &meshattestpb.TpmQuoteEvidence{
			Report:    tpmQuote.report,
			Signature: tpmQuote.signature,
			PcrValues: tpmQuote.pcrValues,
		},
	}, nil
}

// checkQuotableSelection is this provider's own answerability gate, alongside the mesh-wide one:
// go-tpm encodes a three-octet TPML_PCR_SELECTION, which is what Azure's vTPM accepts and all it
// accepts, so a challenge naming a higher slot is one no quote from here can answer. Refusing
// before the first TPM command keeps it in the same class as the other unanswerable challenges.
func checkQuotableSelection(bitfield uint32) error {
	if width := 32 - bits.LeadingZeros32(bitfield); width > vtpmPCRSlotLimit {
		return fmt.Errorf("challenge selects pcr slot %d, past slot %d, which a three-octet TPML_PCR_SELECTION cannot express", width-1, vtpmPCRSlotLimit-1)
	}
	return nil
}

// evidenceSources are the three I/O leaves of this provider: the vTPM's HCL report, the IMDS quote
// over the TD report that report nests, and the vTPM's own PCR quote. They are reached through
// this indirection so the assembly above them -- which is where the mesh's byte-exact bindings are
// either satisfied or silently broken -- can be tested on a machine where the leaves themselves
// cannot run at all. It is a test seam within one provider, not the provider seam; that one is
// MeshEvidenceProvider.
type evidenceSources struct {
	hclReport func(reportData []byte) ([]byte, error)
	tdQuote   func(ctx context.Context, tdReport []byte) ([]byte, error)
	tpmQuote  func(nonce []byte, slots []int) (*tpmQuoteResult, error)
}

var liveEvidenceSources = evidenceSources{
	hclReport: collectHCLReport,
	tdQuote:   fetchTDQuote,
	tpmQuote:  collectVTPMQuote,
}
