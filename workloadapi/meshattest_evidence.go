// The values every mesh workload evidence bundle is built from, independent of the platform that
// produces it: the challenge-derived request a provider is handed, and the 64 bytes of report data
// the hardware quote has to commit to.

package workloadapi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

// reportDataLen is the width of the SGX/TDX REPORTDATA field the mesh's ReportData occupies:
// nonce (32) || unix_timestamp (8) || reserved1 (24).
const reportDataLen = 64

// MeshEvidenceRequest holds the values a workload may not choose for itself. Nonce is the ADR-0041
// fold output; PCRNonce and PCRSelectionBitfield come out of the sealed challenge because they are
// the verifier's own choices and it compares the vTPM quote against them (ADR-0042 Decision 2).
// ChallengeExpiresAt and CollectedAt ride along so the freshness gates sit with the other gates.
type MeshEvidenceRequest struct {
	// Nonce is the 32 bytes the quote's report data must commit to.
	Nonce []byte

	// PCRNonce is the qualifying data the vTPM quote must carry, and PCRSelectionBitfield names
	// the PCR slots it must cover -- exactly those, since the mesh compares the quoted selection
	// against the bitfield it sealed into the challenge.
	PCRNonce             []byte
	PCRSelectionBitfield uint32

	// ChallengeExpiresAt is the unix second past which the mesh will not accept this challenge.
	ChallengeExpiresAt int64

	// CollectedAt is the wall clock the report data commits to. It is set once, when the challenge
	// is answered, so that a bundle built early and sent late fails on freshness rather than on the
	// binding; the mesh accepts a report timestamp within TIMESTAMP_EXPIRATION_SECONDS (120) of its
	// own clock.
	CollectedAt time.Time
}

// CheckAnswerable rejects every reason this challenge cannot produce an acceptable quote, before a
// quote is spent on it. A hardware quote is seconds of work and a round trip, and the answer to
// all of these is the same uniform refusal a genuine binding mismatch gives -- so failing here is
// the only place the reason is legible. A provider calls it first; the client calls it too, so
// that a provider which forgets cannot reach the wire with a bundle that was never answerable.
func (r *MeshEvidenceRequest) CheckAnswerable() error {
	if len(r.Nonce) != meshIDLen {
		return fmt.Errorf("challenge nonce is %d bytes, not %d", len(r.Nonce), meshIDLen)
	}
	if r.PCRSelectionBitfield == 0 {
		return fmt.Errorf("challenge selects no pcr slots")
	}
	if len(r.PCRNonce) != meshIDLen {
		return fmt.Errorf("challenge pcr nonce is %d bytes, not %d", len(r.PCRNonce), meshIDLen)
	}
	if bytes.Equal(r.PCRNonce, make([]byte, meshIDLen)) {
		return fmt.Errorf("challenge carries an all-zero pcr nonce")
	}
	if r.ChallengeExpiresAt <= r.CollectedAt.Unix() {
		return fmt.Errorf("challenge expired at %d, before evidence could be produced at %d", r.ChallengeExpiresAt, r.CollectedAt.Unix())
	}
	return nil
}

// ReportData is the 64 bytes the hardware quote must commit to: ReportData in mesh-process
// crates/crate-common-types/src/attestation.rs, a #[repr(C, packed)] struct of the nonce, a
// native-endian i64 wall-clock second, and 24 reserved zero bytes that verify_quote_data rejects
// if non-zero.
//
// A provider must put THESE bytes in the quote and send THESE bytes as AttestationEvidence.UserData
// -- the same value, not two constructions of it. The mesh recomputes the fold and compares
// byte-exactly, and a mismatch is indistinguishable on the wire from a forged quote.
func (r *MeshEvidenceRequest) ReportData() ([]byte, error) {
	return meshReportData(r.Nonce, r.CollectedAt)
}

func meshReportData(nonce []byte, now time.Time) ([]byte, error) {
	if len(nonce) != meshIDLen {
		return nil, fmt.Errorf("report data nonce is %d bytes, not %d", len(nonce), meshIDLen)
	}
	data := make([]byte, reportDataLen)
	copy(data, nonce)
	binary.LittleEndian.PutUint64(data[meshIDLen:meshIDLen+8], uint64(now.Unix()))
	return data, nil
}
