package workloadapi

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"time"

	meshattestpb "github.com/spiffe/go-spiffe/v2/proto/hushmesh/workload/v1"
)

// reportDataLen is the width of the SGX/TDX REPORTDATA field the mesh's ReportData occupies:
// nonce (32) || unix_timestamp (8) || reserved1 (24).
const reportDataLen = 64

// evidenceRequest holds the values a workload may not choose for itself. Nonce is the ADR-0041
// fold output; PCRNonce and PCRSelectionBitfield come out of the sealed challenge because they are
// the verifier's own choices and it compares the vTPM quote against them (ADR-0042 Decision 2).
// ChallengeExpiresAt rides along so the freshness gate sits with the other gates.
type evidenceRequest struct {
	Nonce                []byte
	PCRNonce             []byte
	PCRSelectionBitfield uint32
	ChallengeExpiresAt   int64
}

// checkAnswerable rejects every reason this challenge cannot produce an acceptable quote, before a
// quote is spent on it. A TDX quote plus a vTPM quote is seconds of work and an IMDS round trip,
// and the answer to all of these is the same uniform refusal a genuine binding mismatch gives --
// so failing here is the only place the reason is legible.
func (r *evidenceRequest) checkAnswerable(now time.Time) error {
	if r.PCRSelectionBitfield == 0 {
		return fmt.Errorf("challenge selects no pcr slots")
	}
	if len(r.PCRNonce) != meshIDLen {
		return fmt.Errorf("challenge pcr nonce is %d bytes, not %d", len(r.PCRNonce), meshIDLen)
	}
	if bytes.Equal(r.PCRNonce, make([]byte, meshIDLen)) {
		return fmt.Errorf("challenge carries an all-zero pcr nonce")
	}
	if highest := 32 - bits.LeadingZeros32(r.PCRSelectionBitfield); highest > vtpmPCRSlotLimit {
		return fmt.Errorf("challenge selects pcr slot %d, past slot %d, which a three-octet TPML_PCR_SELECTION cannot express", highest-1, vtpmPCRSlotLimit-1)
	}
	if r.ChallengeExpiresAt <= now.Unix() {
		return fmt.Errorf("challenge expired at %d, before evidence could be produced at %d", r.ChallengeExpiresAt, now.Unix())
	}
	return nil
}

// meshReportData is ReportData in crates/crate-common-types/src/attestation.rs: a #[repr(C,
// packed)] struct of nonce, a native-endian i64 wall-clock second, and 24 reserved zero bytes that
// verify_quote_data rejects if non-zero. Generating it early and sending it late fails on
// freshness rather than on the binding, so it is built at the moment the evidence is.
func meshReportData(nonce []byte, now time.Time) ([]byte, error) {
	if len(nonce) != meshIDLen {
		return nil, fmt.Errorf("report data nonce is %d bytes, not %d", len(nonce), meshIDLen)
	}
	data := make([]byte, reportDataLen)
	copy(data, nonce)
	binary.LittleEndian.PutUint64(data[meshIDLen:meshIDLen+8], uint64(now.Unix()))
	return data, nil
}

// evidenceSources are the three I/O leaves of evidence collection: the vTPM's HCL report, the
// Azure IMDS quote over the TD report that report nests, and the vTPM's own PCR quote. They are
// reached through this indirection so the assembly above them -- which is where the mesh's
// byte-exact bindings are either satisfied or silently broken -- can be tested on a machine where
// the leaves themselves cannot run at all.
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

// collectEvidence produces the real bundle: a TDX quote whose report data commits to the ADR-0041
// nonce, the HCL variable data that commitment is the digest of, and a vTPM quote over exactly the
// PCR slots this challenge selected.
func collectEvidence(request *evidenceRequest, now time.Time) (*meshattestpb.AttestationEvidence, error) {
	return collectEvidenceFrom(context.Background(), liveEvidenceSources, request, now)
}

func collectEvidenceFrom(ctx context.Context, sources evidenceSources, request *evidenceRequest, now time.Time) (*meshattestpb.AttestationEvidence, error) {
	if err := request.checkAnswerable(now); err != nil {
		return nil, err
	}
	userData, err := meshReportData(request.Nonce, now)
	if err != nil {
		return nil, err
	}

	// These 64 bytes are both what the vTPM is told to commit to and what travels as UserData. The
	// mesh recomputes the fold and compares byte-exactly, so the two have to be the same value and
	// not two constructions of it.
	raw, err := sources.hclReport(userData)
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

	quote, err := sources.tdQuote(ctx, tdReport)
	if err != nil {
		return nil, err
	}
	tpmQuote, err := sources.tpmQuote(request.PCRNonce, pcrSlotsFromBitfield(request.PCRSelectionBitfield))
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

// stubEvidence exercises the envelope and the wire assembly off a TDX host. It cannot verify
// anywhere, and it says so on the wire: varDataOperationAbsent with an empty var_data is the
// honest encoding of "no quote here", where claiming Sha256 over nothing would assert a var_data
// digest that was never computed.
func stubEvidence(request *evidenceRequest, now time.Time) (*meshattestpb.AttestationEvidence, error) {
	if err := request.checkAnswerable(now); err != nil {
		return nil, err
	}
	userData, err := meshReportData(request.Nonce, now)
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
