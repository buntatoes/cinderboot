// SPDX-License-Identifier: GPL-3.0-only
package device

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrSystemDisk    = errors.New("refusing to write to a system or OS-mounted disk")
	ErrNotRemovable  = errors.New("refusing to write to a non-removable or non-USB disk")
	ErrEmptyDevice   = errors.New("target device path is empty")
	ErrZeroCapacity  = errors.New("target device reports zero capacity")
	ErrDriveNotFound = errors.New("target removable drive not found")
)

// Drive describes a physical storage device detected on the host OS.
type Drive struct {
	ID           string   `json:"id"`
	DevicePath   string   `json:"device_path"`
	Model        string   `json:"model"`
	Vendor       string   `json:"vendor"`
	Serial       string   `json:"serial,omitempty"`
	SizeBytes    uint64   `json:"size_bytes"`
	SectorSize   uint32   `json:"sector_size"`
	BusType      string   `json:"bus_type"`
	Removable    bool     `json:"removable"`
	IsUSB        bool     `json:"is_usb"`
	IsSystemDisk bool     `json:"is_system_disk"`
	MountPoints  []string `json:"mount_points,omitempty"`
	DriveLetters []string `json:"drive_letters,omitempty"`
	DiskNumber   uint32   `json:"disk_number,omitempty"`
}

// DisplayLabel returns a clear human-readable label for UI dropdowns and confirmation prompts.
func (d Drive) DisplayLabel() string {
	name := strings.TrimSpace(strings.TrimSpace(d.Vendor + " " + d.Model))
	if name == "" {
		name = "USB Storage Device"
	}
	suffix := d.DevicePath
	if len(d.DriveLetters) > 0 {
		suffix = strings.Join(d.DriveLetters, ", ") + " — " + d.DevicePath
	}
	return fmt.Sprintf("%s (%s) [%s]", name, FormatBytes(d.SizeBytes), suffix)
}

// ValidateTarget enforces Cinderboot's hardware safety checks before any destructive write.
func ValidateTarget(d Drive, allowNonRemovableUSB bool) error {
	if strings.TrimSpace(d.DevicePath) == "" {
		return ErrEmptyDevice
	}
	if d.SizeBytes == 0 {
		return ErrZeroCapacity
	}
	if d.IsSystemDisk {
		return fmt.Errorf("%w: %s", ErrSystemDisk, d.DevicePath)
	}
	for _, mp := range d.MountPoints {
		if IsProtectedMount(mp) {
			return fmt.Errorf("%w: %s hosts protected mount %q", ErrSystemDisk, d.DevicePath, mp)
		}
	}
	if !d.IsUSB {
		return fmt.Errorf("%w: %s (bus=%s)", ErrNotRemovable, d.DevicePath, d.BusType)
	}
	if !d.Removable && !allowNonRemovableUSB {
		return fmt.Errorf("%w: %s is a fixed USB disk (enable USB HDD override to target)", ErrNotRemovable, d.DevicePath)
	}
	return nil
}

// IsProtectedMount returns true for OS-critical Linux or Windows mount paths.
func IsProtectedMount(mountPoint string) bool {
	mp := strings.TrimSpace(mountPoint)
	if mp == "" {
		return false
	}
	switch mp {
	case "/", "/boot", "/boot/efi", "/efi", "/home", "/usr", "/var", "/etc", "/opt", "/nix", "/root":
		return true
	}
	upper := strings.ToUpper(strings.TrimRight(mp, "\\/"))
	if upper == "C:" {
		return true
	}
	return false
}

// FormatBytes formats a byte count into a clean binary-prefixed size string (e.g., "29.3 GiB").
func FormatBytes(b uint64) string {
	const (
		kib = 1024
		mib = 1024 * kib
		gib = 1024 * mib
		tib = 1024 * gib
	)
	switch {
	case b >= tib:
		return fmt.Sprintf("%.2f TiB", float64(b)/float64(tib))
	case b >= gib:
		return fmt.Sprintf("%.2f GiB", float64(b)/float64(gib))
	case b >= mib:
		return fmt.Sprintf("%.1f MiB", float64(b)/float64(mib))
	case b >= kib:
		return fmt.Sprintf("%.1f KiB", float64(b)/float64(kib))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// ListOptions controls how drives are filtered during enumeration.
type ListOptions struct {
	IncludeFixedUSB bool
}
