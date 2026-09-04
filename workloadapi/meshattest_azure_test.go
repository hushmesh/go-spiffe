package workloadapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The offsets are derived in meshattest_hcl.go as the sums the Rust adds up. That derivation and
// this table can only agree if both read the same struct definitions, which is the point: an
// offset wrong in the derivation alone is caught here, and the whole parse is silent about being
// wrong otherwise -- a report read at the wrong offset is still 1024 plausible bytes.
func TestHCLReportLayoutMatchesTheRustStructs(t *testing.T) {
	assert.Equal(t, 32, hclAttestationHeaderSize, "AttestationHeader is eight u32 fields")
	assert.Equal(t, 1184, hclSNPReportSize, "SNP_REPORT_SIZE")
	assert.Equal(t, 1024, hclTDReportSize, "size_of::<TdReport>()")
	assert.Equal(t, 1184, hclMaxReportSize, "MAX_REPORT_SIZE is max(SNP, TD)")
	assert.Equal(t, 32, hclHWReportOffset, "offset_of!(AttestationReport, hw_report)")
	assert.Equal(t, 1216, hclDataOffset, "offset_of!(AttestationReport, hcl_data)")
	assert.Equal(t, 1224, hclDataReportTypeOffset)
	assert.Equal(t, 1232, hclDataVariableDataSizeOffset)
	assert.Equal(t, 1236, hclAttestationReportSize, "size_of::<AttestationReport>()")
	assert.Equal(t, hclAttestationReportSize, hclDataOffset+hclIGVMRequestDataSize,
		"var_data starts at offset_of!(hcl_data)+offset_of!(variable_data), which is the struct size only if nothing is padded")
	assert.Equal(t, 1056, hclHWReportOffset+hclTDReportSize, "TD_REPORT_RANGE end")
}

// hclReportFixture is a synthetic HCL report shaped the way Azure's firmware writes one, including
// the binding the mesh re-derives: the TD report's report_data is SHA-256 of the variable data,
// zero-padded to 64, and the variable data names the 64 bytes the caller asked to be committed to.
type hclReportFixture struct {
	raw        []byte
	varData    []byte
	tdReport   []byte
	reportData []byte
}

func newHCLReportFixture(t *testing.T, userData []byte, reportType uint32) *hclReportFixture {
	t.Helper()

	varData, err := json.Marshal(map[string]any{
		"keys": []map[string]string{{
			"kid": "HCLAkPub",
			"kty": "RSA",
			"e":   "AQAB",
			"n":   base64.RawURLEncoding.EncodeToString([]byte("a modulus this test never verifies against")),
		}},
		"user-data": hex.EncodeToString(userData),
	})
	require.NoError(t, err)

	raw := make([]byte, hclAttestationReportSize+len(varData))
	copy(raw, []byte("HCLA"))
	for i := hclHWReportOffset; i < hclDataOffset; i++ {
		raw[i] = byte(i % 251)
	}

	// ReportMac places report_data after reporttype(4), reserved(12), cpusvn(16) and the two
	// 48-byte hashes.
	const reportDataOffsetInTDReport = 4 + 12 + 16 + 48 + 48
	committed := sha256.Sum256(varData)
	reportData := make([]byte, reportDataLen)
	copy(reportData, committed[:])
	copy(raw[hclHWReportOffset+reportDataOffsetInTDReport:], reportData)

	binary.LittleEndian.PutUint32(raw[hclDataReportTypeOffset:], reportType)
	binary.LittleEndian.PutUint32(raw[hclDataVariableDataSizeOffset:], uint32(len(varData)))
	copy(raw[hclAttestationReportSize:], varData)

	return &hclReportFixture{
		raw:        raw,
		varData:    varData,
		tdReport:   raw[hclHWReportOffset : hclHWReportOffset+hclTDReportSize],
		reportData: reportData,
	}
}

func TestParseHCLReportExtractsTheTDReportAndVariableData(t *testing.T) {
	userData, err := meshReportData(bytes.Repeat([]byte{1}, meshIDLen), time.Now())
	require.NoError(t, err)
	fixture := newHCLReportFixture(t, userData, hclTDXReportType)

	report, err := parseHCLReport(fixture.raw)
	require.NoError(t, err)

	tdReport, err := report.tdReport()
	require.NoError(t, err)
	assert.Len(t, tdReport, hclTDReportSize)
	assert.Equal(t, fixture.tdReport, tdReport, "IMDS signs the bytes as given, so this must be a subslice and not a re-encoding")
	assert.Equal(t, fixture.varData, report.varData())

	// The mesh's ReportDataOp::Sha256 arm computes exactly this and refuses the quote if it does
	// not match the observed report data, so a fixture that did not satisfy it would prove nothing.
	digest := sha256.Sum256(report.varData())
	expected := make([]byte, reportDataLen)
	copy(expected, digest[:])
	assert.Equal(t, expected, fixture.reportData)
}

func TestParseHCLReportRefusesWhatItCannotAccountFor(t *testing.T) {
	fixture := newHCLReportFixture(t, make([]byte, reportDataLen), hclTDXReportType)

	_, err := parseHCLReport(fixture.raw[:hclAttestationReportSize-1])
	assert.Error(t, err, "a report shorter than the fixed section has no report type to read")

	truncated := append([]byte(nil), fixture.raw...)
	_, err = parseHCLReport(truncated[:len(truncated)-1])
	assert.Error(t, err, "a declared variable data size longer than the buffer would slice past the end")

	unknown := append([]byte(nil), fixture.raw...)
	binary.LittleEndian.PutUint32(unknown[hclDataReportTypeOffset:], 7)
	_, err = parseHCLReport(unknown)
	assert.Error(t, err)

	snp := newHCLReportFixture(t, make([]byte, reportDataLen), hclSNPReportType)
	report, err := parseHCLReport(snp.raw)
	require.NoError(t, err, "an SNP report parses; it is only the TDX extraction that must refuse it")
	_, err = report.tdReport()
	assert.Error(t, err)
}

func TestCollectedEvidenceCarriesTheBindingsTheMeshRecomputes(t *testing.T) {
	now := time.Now()
	request := &MeshEvidenceRequest{
		Nonce:                bytes.Repeat([]byte{1}, meshIDLen),
		PCRNonce:             bytes.Repeat([]byte{2}, meshIDLen),
		PCRSelectionBitfield: 0x1_ffff,
		ChallengeExpiresAt:   now.Unix() + 120,
		CollectedAt:          now,
	}
	expectedUserData, err := meshReportData(request.Nonce, now)
	require.NoError(t, err)

	fixture := newHCLReportFixture(t, expectedUserData, hclTDXReportType)
	quoteBytes := []byte("a tdx quote over the td report")
	var committedTo, quotedNonce []byte
	var quotedSlots []int

	sources := evidenceSources{
		hclReport: func(reportData []byte) ([]byte, error) {
			committedTo = reportData
			return fixture.raw, nil
		},
		tdQuote: func(_ context.Context, tdReport []byte) ([]byte, error) {
			assert.Equal(t, fixture.tdReport, tdReport, "IMDS must be handed the nested TD report, not the HCL envelope")
			return quoteBytes, nil
		},
		tpmQuote: func(nonce []byte, slots []int) (*tpmQuoteResult, error) {
			quotedNonce, quotedSlots = nonce, slots
			values := make([][]byte, len(slots))
			for i := range values {
				values[i] = bytes.Repeat([]byte{byte(i)}, sha256.Size)
			}
			return &tpmQuoteResult{report: []byte("attest"), signature: []byte("sig"), pcrValues: values}, nil
		},
	}

	evidence, err := azureTDXVTPMProvider{sources: sources}.CollectEvidence(context.Background(), request)
	require.NoError(t, err)

	assert.Equal(t, expectedUserData, committedTo, "the vTPM must be told to commit to the same bytes that travel as UserData")
	assert.Equal(t, expectedUserData, evidence.GetUserData())
	assert.Equal(t, quoteBytes, evidence.GetQuote())
	assert.Equal(t, fixture.varData, evidence.GetVarData())
	assert.EqualValues(t, varDataOperationSha256, evidence.GetVarDataOperation(),
		"a real HCL report has var_data, and the mesh's TdxMap arm refuses any other operation")

	assert.Equal(t, request.PCRNonce, quotedNonce)
	assert.Equal(t, pcrSlotsFromBitfield(request.PCRSelectionBitfield), quotedSlots)
	require.NotNil(t, evidence.GetTpmQuote())
	assert.Equal(t, []byte("attest"), evidence.GetTpmQuote().GetReport())
	assert.Equal(t, []byte("sig"), evidence.GetTpmQuote().GetSignature())
	assert.Len(t, evidence.GetTpmQuote().GetPcrValues(), 17,
		"verify_quote_data refuses unless there is one value per selected slot")
}

func TestCollectedEvidenceRefusesAnUnanswerableChallengeBeforeSpendingAQuote(t *testing.T) {
	now := time.Now()
	refuseToRun := evidenceSources{
		hclReport: func([]byte) ([]byte, error) {
			t.Fatal("the vTPM was touched for a challenge that cannot be answered")
			return nil, nil
		},
		tdQuote: func(context.Context, []byte) ([]byte, error) {
			t.Fatal("IMDS was called for a challenge that cannot be answered")
			return nil, nil
		},
		tpmQuote: func([]byte, []int) (*tpmQuoteResult, error) {
			t.Fatal("a vTPM quote was taken for a challenge that cannot be answered")
			return nil, nil
		},
	}
	expired := &MeshEvidenceRequest{
		Nonce:                bytes.Repeat([]byte{1}, meshIDLen),
		PCRNonce:             bytes.Repeat([]byte{2}, meshIDLen),
		PCRSelectionBitfield: 0x1_ffff,
		ChallengeExpiresAt:   now.Unix() - 1,
		CollectedAt:          now,
	}
	_, err := azureTDXVTPMProvider{sources: refuseToRun}.CollectEvidence(context.Background(), expired)
	assert.Error(t, err)

	noSlots := *expired
	noSlots.ChallengeExpiresAt = now.Unix() + 120
	noSlots.PCRSelectionBitfield = 0
	_, err = azureTDXVTPMProvider{sources: refuseToRun}.CollectEvidence(context.Background(), &noSlots)
	assert.Error(t, err)

	unencodable := *expired
	unencodable.ChallengeExpiresAt = now.Unix() + 120
	unencodable.PCRSelectionBitfield = 1 << 24
	_, err = azureTDXVTPMProvider{sources: refuseToRun}.CollectEvidence(context.Background(), &unencodable)
	assert.Error(t, err)
}

// go-tpm encodes a three-octet TPML_PCR_SELECTION, so a challenge naming a slot past 23 is one no
// quote from this build can answer. That belongs with the other pre-flight refusals: the challenge
// is single-use mesh state, and spending one to learn this would make the reason unreadable.
func TestASelectionThisBuildCannotEncodeIsUnanswerable(t *testing.T) {
	now := time.Now()
	request := &MeshEvidenceRequest{
		Nonce:                bytes.Repeat([]byte{1}, meshIDLen),
		PCRNonce:             bytes.Repeat([]byte{2}, meshIDLen),
		PCRSelectionBitfield: 1 << 23,
		ChallengeExpiresAt:   now.Unix() + 120,
		CollectedAt:          now,
	}
	require.NoError(t, request.CheckAnswerable())
	require.NoError(t, checkQuotableSelection(request.PCRSelectionBitfield), "slot 23 is the last one three octets hold")

	assert.Error(t, checkQuotableSelection(1<<24))
	assert.Error(t, checkQuotableSelection(0x1_ffff|(1<<31)), "one out-of-range slot makes the whole selection unquotable")
}

func TestCollectedEvidenceRefusesAReportWithNoVariableData(t *testing.T) {
	now := time.Now()
	empty := make([]byte, hclAttestationReportSize)
	binary.LittleEndian.PutUint32(empty[hclDataReportTypeOffset:], hclTDXReportType)

	sources := evidenceSources{
		hclReport: func([]byte) ([]byte, error) { return empty, nil },
		tdQuote: func(context.Context, []byte) ([]byte, error) {
			t.Fatal("a quote was requested over a report that commits to nothing")
			return nil, nil
		},
		tpmQuote: func([]byte, []int) (*tpmQuoteResult, error) { return nil, nil },
	}
	_, err := azureTDXVTPMProvider{sources: sources}.CollectEvidence(context.Background(), &MeshEvidenceRequest{
		Nonce:                bytes.Repeat([]byte{1}, meshIDLen),
		PCRNonce:             bytes.Repeat([]byte{2}, meshIDLen),
		PCRSelectionBitfield: 0x1_ffff,
		ChallengeExpiresAt:   now.Unix() + 120,
		CollectedAt:          now,
	})
	assert.Error(t, err, "declaring Sha256 over an absent var_data would assert a digest nothing computed")
}

func TestPCRSlotsFromBitfieldMirrorsTheRustSelection(t *testing.T) {
	all := pcrSlotsFromBitfield(^uint32(0))
	require.Len(t, all, 32)
	for i, slot := range all {
		assert.Equal(t, i, slot)
	}

	assert.Equal(t,
		[]int{3, 7, 11, 13, 23},
		pcrSlotsFromBitfield((1<<3)|(1<<7)|(1<<11)|(1<<13)|(1<<23)))
	assert.Empty(t, pcrSlotsFromBitfield(0))

	// The mesh seals PcrSelection::Range { pcr_max_inclusive: 16 } and widens it to this bitfield.
	assert.Len(t, pcrSlotsFromBitfield(0x1_ffff), 17)
}

func TestIMDSQuoteExchangeIsUnpaddedBase64URL(t *testing.T) {
	tdReport := bytes.Repeat([]byte{0xab}, hclTDReportSize)
	quote := []byte("quote bytes that are not a multiple of three")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var posted imdsReportBody
		require.NoError(t, json.Unmarshal(body, &posted))
		decoded, err := base64.RawURLEncoding.DecodeString(posted.Report)
		require.NoError(t, err, "the Rust decodes with the unpadded url-safe alphabet and rejects anything else")
		assert.Equal(t, tdReport, decoded)

		require.NoError(t, json.NewEncoder(w).Encode(imdsQuoteResponse{
			Quote: base64.RawURLEncoding.EncodeToString(quote),
		}))
	}))
	defer server.Close()

	restore := imdsTDQuoteEndpoint
	imdsTDQuoteEndpoint = server.URL
	defer func() { imdsTDQuoteEndpoint = restore }()

	got, err := fetchTDQuote(context.Background(), tdReport)
	require.NoError(t, err)
	assert.Equal(t, quote, got)
}

func TestIMDSQuoteFailuresAreLegibleLocally(t *testing.T) {
	restore := imdsTDQuoteEndpoint
	defer func() { imdsTDQuoteEndpoint = restore }()

	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "the report is stale", http.StatusBadRequest)
	}))
	defer refusing.Close()
	imdsTDQuoteEndpoint = refusing.URL
	_, err := fetchTDQuote(context.Background(), []byte("report"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "400", "a refused report must name its status, not surface as a decode failure")

	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"quote":""}`)
	}))
	defer empty.Close()
	imdsTDQuoteEndpoint = empty.URL
	_, err = fetchTDQuote(context.Background(), []byte("report"))
	assert.Error(t, err)
}

func TestQuotedPCRDigestChecksTheTPMAnsweredWhatWasAsked(t *testing.T) {
	nonce := bytes.Repeat([]byte{2}, meshIDLen)
	selection := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrSlotsFromBitfield(0x1_ffff)}
	digest := bytes.Repeat([]byte{9}, sha256.Size)

	encode := func(extraData []byte, quoted tpm2.PCRSelection, pcrDigest []byte) []byte {
		attestation := tpm2.AttestationData{
			Magic:             0xff544347,
			Type:              tpm2.TagAttestQuote,
			ExtraData:         extraData,
			AttestedQuoteInfo: &tpm2.QuoteInfo{PCRSelection: quoted, PCRDigest: pcrDigest},
		}
		encoded, err := attestation.Encode()
		require.NoError(t, err)
		return encoded
	}

	got, err := quotedPCRDigest(encode(nonce, selection, digest), nonce, selection)
	require.NoError(t, err)
	assert.Equal(t, digest, got)

	_, err = quotedPCRDigest(encode(bytes.Repeat([]byte{3}, meshIDLen), selection, digest), nonce, selection)
	assert.Error(t, err, "a quote over another nonce is a replayable quote")

	narrower := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrSlotsFromBitfield(0xffff)}
	_, err = quotedPCRDigest(encode(nonce, narrower, digest), nonce, selection)
	assert.Error(t, err, "the mesh compares the quoted selection against the bitfield it sealed")

	_, err = quotedPCRDigest(encode(nonce, selection, bytes.Repeat([]byte{9}, 20)), nonce, selection)
	assert.Error(t, err)

	_, err = quotedPCRDigest([]byte("not a TPMS_ATTEST"), nonce, selection)
	assert.Error(t, err)
}

func TestVTPMSignatureIsStrippedToWhatTheMeshVerifies(t *testing.T) {
	raw := bytes.Repeat([]byte{0x5a}, 256)
	encoded, err := tpm2.Signature{
		Alg: tpm2.AlgRSASSA,
		RSA: &tpm2.SignatureRSA{HashAlg: tpm2.AlgSHA256, Signature: raw},
	}.Encode()
	require.NoError(t, err)
	assert.Greater(t, len(encoded), len(raw), "the TPM wraps the signature in a TPMT_SIGNATURE the mesh does not verify over")

	stripped, err := rsaSSASignatureBytes(encoded)
	require.NoError(t, err)
	assert.Equal(t, raw, stripped)

	wrongHash, err := tpm2.Signature{
		Alg: tpm2.AlgRSASSA,
		RSA: &tpm2.SignatureRSA{HashAlg: tpm2.AlgSHA384, Signature: raw},
	}.Encode()
	require.NoError(t, err)
	_, err = rsaSSASignatureBytes(wrongHash)
	assert.Error(t, err)

	_, err = rsaSSASignatureBytes([]byte{0x00})
	assert.Error(t, err)
}

// go-tpm encodes a three-octet TPML_PCR_SELECTION, so a challenge naming a slot past 23 is one
// this build cannot quote. Refusing before the first command keeps that in the same class as the
// other unanswerable challenges rather than surfacing as a TPM error mid-collection.
func TestVTPMQuoteRefusesASelectionItCannotEncode(t *testing.T) {
	_, err := vtpmQuote(nil, bytes.Repeat([]byte{2}, meshIDLen), pcrSlotsFromBitfield(1<<24))
	assert.Error(t, err)

	_, err = vtpmQuote(nil, bytes.Repeat([]byte{2}, meshIDLen), nil)
	assert.Error(t, err)
}

// The stale-report race: the firmware regenerates asynchronously and the report-data index is
// shared, so a read can return a valid report carrying somebody else's nonce. Only this check
// separates that from a forged quote, and it is the mesh's own comparison.
func TestHCLReportCommitmentIsCheckedTheWayTheMeshChecksIt(t *testing.T) {
	mine, err := meshReportData(bytes.Repeat([]byte{1}, meshIDLen), time.Now())
	require.NoError(t, err)
	theirs, err := meshReportData(bytes.Repeat([]byte{9}, meshIDLen), time.Now())
	require.NoError(t, err)

	report, err := parseHCLReport(newHCLReportFixture(t, mine, hclTDXReportType).raw)
	require.NoError(t, err)
	assert.NoError(t, report.commitsTo(mine))
	assert.Error(t, report.commitsTo(theirs), "a report committing to another attestation's nonce is the race this catches")

	upper := newHCLReportFixture(t, mine, hclTDXReportType)
	upper.raw = bytes.ReplaceAll(upper.raw, []byte(hex.EncodeToString(mine)), []byte(strings.ToUpper(hex.EncodeToString(mine))))
	report, err = parseHCLReport(upper.raw)
	require.NoError(t, err)
	assert.NoError(t, report.commitsTo(mine), "verify_quote_data compares case-insensitively, so hex case is not a race")

	noVarData := make([]byte, hclAttestationReportSize)
	binary.LittleEndian.PutUint32(noVarData[hclDataReportTypeOffset:], hclTDXReportType)
	report, err = parseHCLReport(noVarData)
	require.NoError(t, err)
	assert.Error(t, report.commitsTo(mine))

	garbage := make([]byte, hclAttestationReportSize+4)
	binary.LittleEndian.PutUint32(garbage[hclDataReportTypeOffset:], hclTDXReportType)
	binary.LittleEndian.PutUint32(garbage[hclDataVariableDataSizeOffset:], 4)
	copy(garbage[hclAttestationReportSize:], "{{{{")
	report, err = parseHCLReport(garbage)
	require.NoError(t, err)
	assert.Error(t, report.commitsTo(mine))
}
