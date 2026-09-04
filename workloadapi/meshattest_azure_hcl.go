package workloadapi

import (
	"encoding/binary"
	"fmt"
)

// The Azure HCL report layout, ported field for field from HclReport and TdReport in mesh-process
// crates/crate-app-azure-vtpm-tdx/src/hcl.rs and src/tdx.rs (Microsoft-authored, MIT). Those are
// #[repr(C)] structs read through zerocopy on x86-64, so every multi-byte field is little-endian
// and the offsets below are the same offset_of! values the Rust computes.
//
// They are written as the sums the Rust adds up rather than as literals, so a reader can check
// each against the struct definition it comes from; the absolute values are pinned separately in
// TestHCLReportLayoutMatchesTheRustStructs, because an offset that is wrong in both places at once
// is exactly the failure this parsing cannot otherwise show.
const (
	// AttestationHeader: signature, version, report_size, request_type, status, reserved[3].
	hclAttestationHeaderSize = 8 * 4

	// SNP_REPORT_SIZE, the AMD SNP AttestationReport size fixed by the SNP firmware ABI. It
	// exceeds a TD report, so it is what MAX_REPORT_SIZE resolves to: hw_report is that wide even
	// when the nested report is a TDX one, and hcl_data therefore sits at the same offset either
	// way.
	hclSNPReportSize = 1184

	// size_of::<TdReport>(): ReportMac (reporttype 4, reserved 12, cpusvn 16, tee_tcb_info_hash
	// 48, tee_info_hash 48, reportdata 64, reserved 32, mac 32), then tee_tcb_info, a reserved
	// gap, and TdInfo (attributes 8, xfam 8, four 48-byte measurements, rtmr[4] of 48, reserved
	// 112).
	hclTDReportSize = 256 + 239 + 17 + 512

	hclMaxReportSize = hclSNPReportSize

	// offset_of!(AttestationReport, hw_report) and offset_of!(AttestationReport, hcl_data).
	hclHWReportOffset = hclAttestationHeaderSize
	hclDataOffset     = hclHWReportOffset + hclMaxReportSize

	// IgvmRequestData: data_size, version, report_type, report_data_hash_type, variable_data_size,
	// then a zero-length variable_data marker whose offset is where the variable data starts.
	hclDataReportTypeOffset       = hclDataOffset + 2*4
	hclDataVariableDataSizeOffset = hclDataOffset + 4*4
	hclIGVMRequestDataSize        = 5 * 4

	// size_of::<AttestationReport>(). Every field is four-byte aligned at a multiple of four, so
	// the struct carries no interior or trailing padding and the variable data begins exactly at
	// its end -- which is what makes offset_of!(hcl_data) + offset_of!(variable_data) and this
	// size the same number in the Rust.
	hclAttestationReportSize = hclDataOffset + hclIGVMRequestDataSize
)

// TDX_REPORT_TYPE and SNP_REPORT_TYPE. The mesh only verifies the TDX shape, but both are
// recognised here so a report from SNP hardware is refused for what it is rather than as a
// corrupt report.
const (
	hclSNPReportType = 2
	hclTDXReportType = 4
)

// hclReport is a parsed HCL envelope. It holds the original bytes because both things taken out of
// it -- the nested TD report and the variable data -- must reach the mesh byte-exact: the TD
// report is what IMDS signs into a quote, and the variable data is what the mesh hashes and
// compares against that quote's report data.
type hclReport struct {
	raw              []byte
	reportType       uint32
	variableDataSize int
}

func parseHCLReport(raw []byte) (*hclReport, error) {
	if len(raw) < hclAttestationReportSize {
		return nil, fmt.Errorf("hcl report is %d bytes, shorter than its %d-byte fixed section", len(raw), hclAttestationReportSize)
	}

	declared := binary.LittleEndian.Uint32(raw[hclDataVariableDataSizeOffset : hclDataVariableDataSizeOffset+4])
	if uint64(len(raw)) < uint64(hclAttestationReportSize)+uint64(declared) {
		return nil, fmt.Errorf("hcl report declares %d bytes of variable data but carries %d", declared, len(raw)-hclAttestationReportSize)
	}

	reportType := binary.LittleEndian.Uint32(raw[hclDataReportTypeOffset : hclDataReportTypeOffset+4])
	if reportType != hclTDXReportType && reportType != hclSNPReportType {
		return nil, fmt.Errorf("hcl report nests hardware report type %d, which is neither TDX (%d) nor SNP (%d)", reportType, hclTDXReportType, hclSNPReportType)
	}

	return &hclReport{raw: raw, reportType: reportType, variableDataSize: int(declared)}, nil
}

// varData is the HCL's variable data section: the JSON the firmware writes alongside the hardware
// report, carrying the HCLAkPub JWK the vTPM quote is verified against and the user-data hex that
// the TD report's report_data is the SHA-256 of.
func (r *hclReport) varData() []byte {
	return r.raw[hclAttestationReportSize : hclAttestationReportSize+r.variableDataSize]
}

// tdReport is the nested TD report, which is what Azure IMDS turns into a quote. It is returned as
// a subslice of the report the vTPM produced rather than a re-encoding, since IMDS signs the bytes
// as given and any re-serialization would change the MAC.
func (r *hclReport) tdReport() ([]byte, error) {
	if r.reportType != hclTDXReportType {
		return nil, fmt.Errorf("hcl report nests a report of type %d; mesh attestation needs a TDX report", r.reportType)
	}
	return r.raw[hclHWReportOffset : hclHWReportOffset+hclTDReportSize], nil
}
