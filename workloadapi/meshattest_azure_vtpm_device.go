//go:build !windows

package workloadapi

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/google/go-tpm/tpmutil"
)

// vtpmDeviceEnv overrides the device path. It is the only way to point this at a software TPM,
// which is the only way any of this is exercised off a confidential VM.
const vtpmDeviceEnv = "MESH_VTPM_DEVICE"

// The reference opens tss-esapi's default device, /dev/tpm0, which is exclusive: one holder at a
// time. A workload attester is never the only TPM user on a confidential node -- the broker's own
// report server wants the same device -- so the resource manager, which multiplexes and offers
// identical semantics for the commands used here, is tried first.
func vtpmDevicePaths() []string {
	if override := os.Getenv(vtpmDeviceEnv); override != "" {
		return []string{override}
	}
	return []string{"/dev/tpmrm0", "/dev/tpm0"}
}

func openVTPM() (io.ReadWriteCloser, error) {
	var failures []error
	for _, path := range vtpmDevicePaths() {
		device, err := tpmutil.OpenTPM(path)
		if err == nil {
			return device, nil
		}
		failures = append(failures, fmt.Errorf("%s: %w", path, err))
	}
	return nil, fmt.Errorf("no usable vTPM device: %w", errors.Join(failures...))
}
