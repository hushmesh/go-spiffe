// The vTPM half of mesh workload evidence, ported from mesh-process
// crates/crate-app-azure-vtpm-tdx/src/vtpm.rs (Microsoft-authored, MIT) and the composition in
// src/quote.rs. Two separate things come out of the same device and must not be confused:
//
//   - the HCL report at NV index 0x01400001, which nests the TD report the Azure IMDS turns into a
//     TDX quote, and which commits to whatever 64 bytes were last written to NV index 0x01400002;
//   - a TPM quote signed by the HCL's attestation key over the PCR slots the mesh's challenge
//     selects, which is what proves the boot measurements alongside the TDX quote.
//
// None of it is gated behind a build tag. The Rust equivalent is, because tss-esapi-sys is a C FFI
// crate that will not compile for aarch64-darwin at all; go-tpm is pure Go, so gating would buy
// nothing and would cost compile and vet coverage of the one path that can only ever be exercised
// on hardware this repository is not built on. Absence of a vTPM is a runtime condition here,
// refused before a challenge is spent. The single exception is opening the device, which go-tpm
// spells differently on Windows, and which is therefore the only thing in meshattest_vtpm_*.go.

package workloadapi

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	// VTPM_HCL_REPORT_NV_INDEX and the report-data index beside it. Writing the second is what
	// makes the first commit to a caller-chosen 64 bytes, which is the whole of the mesh's
	// binding: without that write the report attests to a nonce nobody asked for.
	vtpmHCLReportNVIndex  = tpmutil.Handle(0x01400001)
	vtpmReportDataNVIndex = tpmutil.Handle(0x01400002)

	// VTPM_AK_HANDLE. This is the HCL's own attestation key, whose public half the firmware
	// publishes in the HCL report's variable data as the HCLAkPub JWK. The mesh verifies the quote
	// against that JWK, so a quote signed by any other key -- including a freshly created
	// attestation key at a library's default handle -- verifies nowhere.
	vtpmAKHandle = tpmutil.Handle(0x81000003)
)

const (
	// GENERATE_REPORT_SLEEP. The HCL regenerates the report asynchronously after the report-data
	// write; reading sooner returns the previous report, which commits to the previous nonce and
	// is refused for a binding mismatch rather than for the race that caused it.
	vtpmGenerateReportDelay = 3 * time.Second

	// MAX_QUOTE_RETRIES. The PCR read and the quote are two commands, so a measurement extended
	// between them yields a signed digest over values this quote does not carry.
	vtpmMaxQuoteRetries = 3

	// TPM2_PCR_Read answers with at most eight digests per call however many the selection names,
	// so a selection wider than that has to be walked.
	vtpmPCRReadBatch = 8

	vtpmPCRDigestLen = sha256.Size

	// go-tpm encodes a three-octet TPML_PCR_SELECTION, which is what Azure's vTPM accepts and all
	// it accepts. Slots past 23 do not fit in three octets and do not work on Azure regardless.
	vtpmPCRSlotLimit = 8 * 3
)

// checkVTPMReachable is the pre-flight for the real evidence path: it answers whether this host
// has a vTPM this process may talk to, without issuing a command and without spending anything.
// The mesh's challenge is single-use state, so "this build cannot answer" has to be discovered
// before one is asked for.
func checkVTPMReachable() error {
	device, err := openVTPM()
	if err != nil {
		return err
	}
	return device.Close()
}

// collectHCLReport writes the report data the quote must commit to, waits out the regeneration
// window, and reads back the HCL report that now attests to it.
func collectHCLReport(reportData []byte) ([]byte, error) {
	device, err := openVTPM()
	if err != nil {
		return nil, err
	}
	defer device.Close()

	if err := writeVTPMNVIndex(device, vtpmReportDataNVIndex, reportData); err != nil {
		return nil, err
	}
	time.Sleep(vtpmGenerateReportDelay)

	report, err := tpm2.NVReadEx(device, vtpmHCLReportNVIndex, tpm2.HandleOwner, "", 0)
	if err != nil {
		return nil, fmt.Errorf("reading the HCL report from nv index %#x failed: %w", uint32(vtpmHCLReportNVIndex), err)
	}
	return report, nil
}

func writeVTPMNVIndex(device io.ReadWriter, index tpmutil.Handle, data []byte) error {
	if len(data) > math.MaxUint16 {
		return fmt.Errorf("nv index %#x cannot hold %d bytes", uint32(index), len(data))
	}

	public, readErr := tpm2.NVReadPublic(device, index)
	switch {
	case readErr != nil:
		// TPM2_NV_ReadPublic on an index nobody has defined is an error, and so is a transport that
		// has stopped answering; the define below distinguishes them by either succeeding or
		// failing for the same underlying reason.
		if err := defineVTPMNVIndex(device, index, len(data)); err != nil {
			return fmt.Errorf("%w (nv index %#x did not read back: %w)", err, uint32(index), readErr)
		}
	case int(public.DataSize) != len(data):
		// An index of the wrong width cannot be written through and is ours to recycle: 0x01400002
		// is the HCL's report-data slot, defined by whoever last used it, not a TPM-owned index.
		if err := tpm2.NVUndefineSpace(device, "", tpm2.HandleOwner, index); err != nil {
			return fmt.Errorf("releasing the %d-byte nv index %#x failed: %w", public.DataSize, uint32(index), err)
		}
		if err := defineVTPMNVIndex(device, index, len(data)); err != nil {
			return err
		}
	}

	if err := tpm2.NVWrite(device, tpm2.HandleOwner, index, "", data, 0); err != nil {
		return fmt.Errorf("writing %d bytes of report data to nv index %#x failed: %w", len(data), uint32(index), err)
	}
	return nil
}

func defineVTPMNVIndex(device io.ReadWriter, index tpmutil.Handle, size int) error {
	// Not tpm2.NVDefineSpace, which hardcodes SHA-1 as the index name algorithm. The reference
	// defines this index with SHA-256, and the name algorithm is part of the index's identity.
	public := tpm2.NVPublic{
		NVIndex:    index,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.AttrOwnerWrite | tpm2.AttrOwnerRead,
		DataSize:   uint16(size),
	}
	owner := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}
	if err := tpm2.NVDefineSpaceEx(device, tpm2.HandleOwner, "", public, owner); err != nil {
		return fmt.Errorf("defining nv index %#x for %d bytes failed: %w", uint32(index), size, err)
	}
	return nil
}

// tpmQuoteResult is what the mesh's TdxMap verification arm consumes: the marshalled TPMS_ATTEST it
// parses as a PcrAttest, the bare signature it checks against HCLAkPub, and the PCR digests it
// re-hashes into the signed digest.
type tpmQuoteResult struct {
	report    []byte
	signature []byte
	pcrValues [][]byte
}

func collectVTPMQuote(nonce []byte, slots []int) (*tpmQuoteResult, error) {
	device, err := openVTPM()
	if err != nil {
		return nil, err
	}
	defer device.Close()
	return vtpmQuote(device, nonce, slots)
}

func vtpmQuote(device io.ReadWriter, nonce []byte, slots []int) (*tpmQuoteResult, error) {
	if len(slots) == 0 {
		return nil, errors.New("a vtpm quote must cover at least one pcr slot")
	}
	if highest := slots[len(slots)-1]; highest >= vtpmPCRSlotLimit {
		return nil, fmt.Errorf("the challenge selects pcr slot %d, past slot %d, which a three-octet TPML_PCR_SELECTION cannot express", highest, vtpmPCRSlotLimit-1)
	}
	selection := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: slots}

	var raced error
	for attempt := 1; attempt <= vtpmMaxQuoteRetries; attempt++ {
		pcrValues, err := readVTPMPCRs(device, selection)
		if err != nil {
			return nil, err
		}

		// tpm2.AlgNull selects the signing key's own scheme, and go-tpm's encoder has no room for
		// an explicit TPMT_SIG_SCHEME here. The HCL's key is RSASSA over SHA-256, which is what
		// the check below insists the returned signature actually is.
		attestation, rawSignature, err := tpm2.QuoteRaw(device, vtpmAKHandle, "", "", nonce, selection, tpm2.AlgNull)
		if err != nil {
			return nil, fmt.Errorf("TPM2_Quote with the HCL attestation key at %#x failed: %w", uint32(vtpmAKHandle), err)
		}

		signature, err := rsaSSASignatureBytes(rawSignature)
		if err != nil {
			return nil, err
		}
		quotedDigest, err := quotedPCRDigest(attestation, nonce, selection)
		if err != nil {
			return nil, err
		}

		observed := sha256.Sum256(bytes.Join(pcrValues, nil))
		if !bytes.Equal(observed[:], quotedDigest) {
			raced = fmt.Errorf("the pcr values read do not hash to the digest the quote signed, after %d attempts", attempt)
			continue
		}
		return &tpmQuoteResult{report: attestation, signature: signature, pcrValues: pcrValues}, nil
	}
	if raced == nil {
		raced = errors.New("no vtpm quote was attempted")
	}
	return nil, raced
}

// readVTPMPCRs returns the selected SHA-256 digests in ascending slot order, which is the order
// the TPM hashes them into the quoted digest and the order the mesh concatenates them back in.
func readVTPMPCRs(device io.ReadWriter, selection tpm2.PCRSelection) ([][]byte, error) {
	values := make([][]byte, 0, len(selection.PCRs))
	for start := 0; start < len(selection.PCRs); start += vtpmPCRReadBatch {
		batch := tpm2.PCRSelection{
			Hash: selection.Hash,
			PCRs: selection.PCRs[start:min(start+vtpmPCRReadBatch, len(selection.PCRs))],
		}
		read, err := tpm2.ReadPCRs(device, batch)
		if err != nil {
			return nil, fmt.Errorf("reading pcr slots %v failed: %w", batch.PCRs, err)
		}
		for _, slot := range batch.PCRs {
			value, ok := read[slot]
			if !ok {
				return nil, fmt.Errorf("the vtpm returned no sha-256 value for pcr slot %d", slot)
			}
			values = append(values, value)
		}
	}
	return values, nil
}

// rsaSSASignatureBytes strips the TPMT_SIGNATURE wrapper the TPM returns. The mesh verifies the
// bare RSA signature against the DER it builds from HCLAkPub, so sending the wrapper would be a
// signature that verifies nowhere and reads as a measurement mismatch.
func rsaSSASignatureBytes(raw []byte) ([]byte, error) {
	signature, err := tpm2.DecodeSignature(bytes.NewBuffer(raw))
	if err != nil {
		return nil, fmt.Errorf("the vtpm signature will not decode: %w", err)
	}
	if signature.Alg != tpm2.AlgRSASSA || signature.RSA == nil {
		return nil, fmt.Errorf("the vtpm signed with scheme %#x, not RSASSA", uint16(signature.Alg))
	}
	if signature.RSA.HashAlg != tpm2.AlgSHA256 {
		return nil, fmt.Errorf("the vtpm signed over hash %#x, not SHA-256", uint16(signature.RSA.HashAlg))
	}
	return signature.RSA.Signature, nil
}

// quotedPCRDigest reads back what the TPM actually signed. Every one of these is something the
// mesh checks too, and checking them here is the difference between a legible local failure and
// the one uniform refusal the mesh answers with.
func quotedPCRDigest(attestation, nonce []byte, selection tpm2.PCRSelection) ([]byte, error) {
	data, err := tpm2.DecodeAttestationData(attestation)
	if err != nil {
		return nil, fmt.Errorf("the quoted TPMS_ATTEST will not decode: %w", err)
	}
	if data.Type != tpm2.TagAttestQuote || data.AttestedQuoteInfo == nil {
		return nil, fmt.Errorf("the vtpm attested structure %#x, which is not a quote", uint16(data.Type))
	}
	if !bytes.Equal(data.ExtraData, nonce) {
		return nil, errors.New("the quote does not carry the challenge's pcr nonce")
	}
	quoted := data.AttestedQuoteInfo.PCRSelection
	if quoted.Hash != selection.Hash || !slices.Equal(quoted.PCRs, selection.PCRs) {
		return nil, fmt.Errorf("the quote covers pcr slots %v in bank %#x, not slots %v in bank %#x", quoted.PCRs, uint16(quoted.Hash), selection.PCRs, uint16(selection.Hash))
	}
	if len(data.AttestedQuoteInfo.PCRDigest) != vtpmPCRDigestLen {
		return nil, fmt.Errorf("the quote carries a %d-byte pcr digest, not %d", len(data.AttestedQuoteInfo.PCRDigest), vtpmPCRDigestLen)
	}
	return data.AttestedQuoteInfo.PCRDigest, nil
}

// pcrSlotsFromBitfield is make_pcr_selection_list: the challenge's bitfield widened to the slot
// indices it names, ascending, which is the order everything downstream assumes.
func pcrSlotsFromBitfield(bitfield uint32) []int {
	slots := make([]int, 0, 32)
	for slot := 0; slot < 32; slot++ {
		if bitfield&(1<<uint(slot)) != 0 {
			slots = append(slots, slot)
		}
	}
	return slots
}
