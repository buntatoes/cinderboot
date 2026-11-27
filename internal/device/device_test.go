// SPDX-License-Identifier: GPL-3.0-only
package device

import (
	"errors"
	"testing"
)

func TestValidateTargetSafety(t *testing.T) {
	usb := Drive{
		ID:         "sdb",
		DevicePath: "/dev/sdb",
		Model:      "Ultra Fit",
		Vendor:     "SanDisk",
		SizeBytes:  32 * 1024 * 1024 * 1024,
		SectorSize: 512,
		BusType:    "USB",
		Removable:  true,
		IsUSB:      true,
	}
	if err := ValidateTarget(usb, false); err != nil {
		t.Fatalf("expected valid removable USB drive to pass, got: %v", err)
	}

	// Internal NVMe must always be rejected
	nvme := usb
	nvme.DevicePath = "/dev/nvme0n1"
	nvme.BusType = "NVMe"
	nvme.IsUSB = false
	nvme.Removable = false
	if err := ValidateTarget(nvme, true); !errors.Is(err, ErrNotRemovable) {
		t.Fatalf("expected ErrNotRemovable for internal NVMe, got: %v", err)
	}

	// OS root mount must always be rejected even if USB
	usbRoot := usb
	usbRoot.MountPoints = []string{"/"}
	if err := ValidateTarget(usbRoot, true); !errors.Is(err, ErrSystemDisk) {
		t.Fatalf("expected ErrSystemDisk for root mount, got: %v", err)
	}

	// Windows C: must always be rejected
	winSys := usb
	winSys.DevicePath = `\\.\PhysicalDrive0`
	winSys.MountPoints = []string{"C:"}
	if err := ValidateTarget(winSys, true); !errors.Is(err, ErrSystemDisk) {
		t.Fatalf("expected ErrSystemDisk for C:, got: %v", err)
	}

	// Fixed USB HDD rejected by default, allowed with override
	fixedUSB := usb
	fixedUSB.Removable = false
	if err := ValidateTarget(fixedUSB, false); !errors.Is(err, ErrNotRemovable) {
		t.Fatalf("expected ErrNotRemovable for fixed USB without override, got: %v", err)
	}
	if err := ValidateTarget(fixedUSB, true); err != nil {
		t.Fatalf("expected fixed USB to pass with override, got: %v", err)
	}
}

func TestFormatBytes(t *testing.T) {
	cases := []struct {
		in   uint64
		want string
	}{
		{512, "512 B"},
		{2048, "2.0 KiB"},
		{10 * 1024 * 1024, "10.0 MiB"},
		{32 * 1024 * 1024 * 1024, "32.00 GiB"},
	}
	for _, tc := range cases {
		if got := FormatBytes(tc.in); got != tc.want {
			t.Errorf("FormatBytes(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
