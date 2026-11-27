// SPDX-License-Identifier: GPL-3.0-only
package flash

import (
	"context"
	"fmt"
	"time"

	"github.com/buntatoes/cinderboot/internal/device"
	"github.com/buntatoes/cinderboot/internal/image"
	"github.com/buntatoes/cinderboot/internal/unattend"
)

// Mode controls how Cinderboot writes an OS image to the target USB drive.
type Mode string

const (
	ModeAuto         Mode = "auto"
	ModeRaw          Mode = "raw"
	ModeWindowsFAT32 Mode = "windows-fat32"
	ModeISOFAT32     Mode = "iso-fat32"
	ModeMultiboot    Mode = "multiboot"
)

// JobSpec defines all parameters for a single flash operation (serializable for privileged worker IPC).
type JobSpec struct {
	ImagePath       string           `json:"image_path"`
	ImagePaths      []string         `json:"image_paths,omitempty"`
	Mode            Mode             `json:"mode"`
	DevicePath      string           `json:"device_path"`
	VolumeLabel     string           `json:"volume_label,omitempty"`
	Verify          bool             `json:"verify"`
	IncludeFixedUSB bool             `json:"include_fixed_usb"`
	Unattend        unattend.Options `json:"unattend"`
}

// ProgressEvent is streamed from the flash engine (or elevated worker) to GUI/CLI listeners.
type ProgressEvent struct {
	Phase        string  `json:"phase"`
	BytesDone    uint64  `json:"bytes_done"`
	BytesTotal   uint64  `json:"bytes_total"`
	SpeedBPS     float64 `json:"speed_bps"`
	Percent      float64 `json:"percent"`
	Message      string  `json:"message"`
	SHA256       string  `json:"sha256,omitempty"`
	Done         bool    `json:"done,omitempty"`
	Error        string  `json:"error,omitempty"`
}

// ProgressSink receives structured progress updates during flashing.
type ProgressSink func(ProgressEvent)

// EffectiveImages returns the normalized list of image paths for a JobSpec.
func (s JobSpec) EffectiveImages() []string {
	var out []string
	for _, p := range s.ImagePaths {
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 && s.ImagePath != "" {
		out = append(out, s.ImagePath)
	}
	return out
}

// Execute validates the target drive & image(s), selects the effective mode, and flashes the USB drive.
func Execute(ctx context.Context, spec JobSpec, sink ProgressSink) error {
	emit := func(ev ProgressEvent) {
		if sink != nil {
			sink(ev)
		}
	}

	images := spec.EffectiveImages()
	if len(images) == 0 {
		return fmt.Errorf("no boot image specified")
	}

	drv, err := device.FindByPath(spec.DevicePath, device.ListOptions{
		IncludeFixedUSB: spec.IncludeFixedUSB,
	})
	if err != nil {
		return err
	}
	if err := device.ValidateTarget(drv, spec.IncludeFixedUSB); err != nil {
		return err
	}

	// Multi-distro Linux USB mode when 2+ images are provided or multiboot mode is explicitly selected.
	if spec.Mode == ModeMultiboot || len(images) > 1 {
		spec.ImagePaths = images
		emit(ProgressEvent{
			Phase:   "prepare",
			Message: fmt.Sprintf("Unmounting and preparing %s (%s) for %d-distro multiboot...", drv.DevicePath, drv.DisplayLabel(), len(images)),
		})
		if err := device.PrepareForWrite(drv); err != nil {
			return fmt.Errorf("prepare target drive: %w", err)
		}
		return flashMultibootToDrive(ctx, spec, drv, emit)
	}

	spec.ImagePath = images[0]
	info, err := image.Inspect(spec.ImagePath)
	if err != nil {
		return fmt.Errorf("inspect image: %w", err)
	}

	effectiveMode := spec.Mode
	if effectiveMode == "" || effectiveMode == ModeAuto {
		switch info.RecommendedMode {
		case "windows-fat32":
			effectiveMode = ModeWindowsFAT32
		case "iso-fat32":
			effectiveMode = ModeISOFAT32
		default:
			effectiveMode = ModeRaw
		}
	}

	emit(ProgressEvent{
		Phase:   "prepare",
		Message: fmt.Sprintf("Unmounting and preparing %s (%s)...", drv.DevicePath, drv.DisplayLabel()),
	})
	if err := device.PrepareForWrite(drv); err != nil {
		return fmt.Errorf("prepare target drive: %w", err)
	}

	switch effectiveMode {
	case ModeRaw:
		return flashRawToDrive(ctx, spec, info, drv, emit)
	case ModeWindowsFAT32, ModeISOFAT32:
		return flashISOFAT32ToDrive(ctx, spec, info, drv, emit)
	default:
		return fmt.Errorf("unknown flash mode: %q", effectiveMode)
	}
}

type speedTracker struct {
	start      time.Time
	lastEmit   time.Time
	totalBytes uint64
}

func newSpeedTracker(totalBytes uint64) *speedTracker {
	now := time.Now()
	return &speedTracker{start: now, lastEmit: now, totalBytes: totalBytes}
}

func (s *speedTracker) shouldEmit(force bool) bool {
	if force || time.Since(s.lastEmit) >= 150*time.Millisecond {
		s.lastEmit = time.Now()
		return true
	}
	return false
}

func (s *speedTracker) speed(done uint64) float64 {
	sec := time.Since(s.start).Seconds()
	if sec <= 0.001 {
		return 0
	}
	return float64(done) / sec
}

func (s *speedTracker) percent(done uint64) float64 {
	if s.totalBytes == 0 {
		return 0
	}
	p := float64(done) * 100.0 / float64(s.totalBytes)
	if p > 100 {
		p = 100
	}
	return p
}
