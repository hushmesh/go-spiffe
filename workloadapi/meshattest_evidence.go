package workloadapi

import (
	"bytes"
	"encoding/binary"
	"fmt"
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

// stubEvidence exercises the envelope and the wire assembly off a TDX host. It cannot verify
// anywhere, and it says so on the wire: varDataOperationAbsent with an empty var_data is the
// honest encoding of "no quote here", where claiming Sha256 over nothing would assert a var_data
// digest that was never computed.
//
// TODO: collect real evidence. It needs a TDX quote carrying this report data (Azure IMDS, or
// /dev/tdx_guest) and a vTPM quote over PCRNonce for the slots PCRSelectionBitfield selects
// (github.com/google/go-tpm), filling quote, var_data, var_data_operation and tpm_quote the way
// evidence::collect does in mesh-process apps/app-workload-attester-demo/src/evidence.rs.
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
