//go:build windows

package workloadapi

import (
	"errors"
	"io"
)

// Mesh TDX evidence comes from the HCL's vTPM in a confidential Linux guest, reached through a
// device file; Windows reaches its TPM through TBS, which go-tpm opens with a different signature
// and which nothing here has ever been run against. Refusing keeps that fact in the pre-flight,
// where it is legible, rather than in a TPM error partway through a challenge.
func openVTPM() (io.ReadWriteCloser, error) {
	return nil, errors.New("mesh TDX/vTPM evidence is collected from a confidential Linux guest's vTPM device, which this platform does not present")
}
