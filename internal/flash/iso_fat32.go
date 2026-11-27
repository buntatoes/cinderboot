// SPDX-License-Identifier: GPL-3.0-only
package flash

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/buntatoes/cinderboot/internal/device"
	"github.com/buntatoes/cinderboot/internal/fs"
	"github.com/buntatoes/cinderboot/internal/image"
	"github.com/buntatoes/cinderboot/internal/unattend"
	"github.com/buntatoes/cinderboot/internal/wim"
)

const fat32FileLimit uint64 = (1 << 32) - 1

func flashISOFAT32ToDrive(ctx context.Context, spec JobSpec, info image.Info, drv device.Drive, emit ProgressSink) error {
	f, err := device.OpenRawWrite(drv)
	if err != nil {
		return err
	}
	if err := WriteISOFAT32(ctx, spec, info, f, drv.SizeBytes, drv.SectorSize, emit); err != nil {
		_ = f.Close()
		return err
	}
	emit(ProgressEvent{
		Phase:   "sync",
		Percent: 100,
		Message: "Flushing FAT32 metadata and device caches...",
	})
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync target device: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close target device: %w", err)
	}
	_ = device.RereadPartitionTablePath(drv.DevicePath)
	emit(ProgressEvent{
		Phase:   "complete",
		Percent: 100,
		Done:    true,
		Message: "Bootable GPT + FAT32 USB created successfully (Secure Boot compatible)",
	})
	return nil
}

// WriteISOFAT32 writes a clean GPT + FAT32 filesystem directly onto dst using 100% pure Go,
// streaming every file from the ISO (UDF 1.02 or ISO9660), automatically splitting >4 GiB
// Microsoft .wim files into .swm parts, and optionally injecting autounattend.xml.
func WriteISOFAT32(
	ctx context.Context,
	spec JobSpec,
	info image.Info,
	dst io.ReadWriteSeeker,
	diskSize uint64,
	sectorSize uint32,
	emit ProgressSink,
) error {
	isoFile, err := os.Open(spec.ImagePath)
	if err != nil {
		return fmt.Errorf("open ISO: %w", err)
	}
	defer isoFile.Close()

	isoFS, err := image.OpenImageFS(isoFile)
	if err != nil {
		return err
	}

	var entries []image.Entry
	var totalBytes uint64
	if err := isoFS.Walk(func(e image.Entry) error {
		entries = append(entries, e)
		if !e.IsDir {
			totalBytes += e.Size
		}
		return nil
	}); err != nil {
		return fmt.Errorf("enumerate ISO contents: %w", err)
	}

	if totalBytes+64*1024*1024 > diskSize {
		return fmt.Errorf("ISO contents (%s) exceed target drive capacity (%s)",
			device.FormatBytes(totalBytes), device.FormatBytes(diskSize))
	}

	label := spec.VolumeLabel
	if strings.TrimSpace(label) == "" {
		label = info.VolumeLabel
	}
	if strings.TrimSpace(label) == "" {
		label = "CINDERBOOT"
	}

	emit(ProgressEvent{
		Phase:   "partition",
		Message: "Writing GPT partition table and formatting FAT32...",
	})
	partOff, partSize, err := fs.WriteSinglePartitionGPT(dst, diskSize, sectorSize, fs.GPTTypeBasicData, label)
	if err != nil {
		return fmt.Errorf("write GPT: %w", err)
	}

	fw, err := fs.FormatFAT32(dst, int64(partOff), partSize, sectorSize, label)
	if err != nil {
		return fmt.Errorf("format FAT32: %w", err)
	}

	tracker := newSpeedTracker(totalBytes)
	var copied uint64
	reportBytes := func(n int, currentFile string) {
		copied += uint64(n)
		if tracker.shouldEmit(false) && emit != nil {
			spd := tracker.speed(copied)
			emit(ProgressEvent{
				Phase:      "copying",
				BytesDone:  copied,
				BytesTotal: totalBytes,
				SpeedBPS:   spd,
				Percent:    tracker.percent(copied),
				Message:    fmt.Sprintf("Writing %s (%s/s)", currentFile, device.FormatBytes(uint64(spd))),
			})
		}
	}

	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if e.IsDir {
			if err := fw.MkdirAll(e.Path); err != nil {
				return fmt.Errorf("mkdir %q: %w", e.Path, err)
			}
			continue
		}

		// Automatically split any Microsoft .wim file exceeding FAT32's 4 GiB limit into .swm parts.
		if e.Size > fat32FileLimit && strings.HasSuffix(strings.ToLower(e.Path), ".wim") {
			emit(ProgressEvent{
				Phase:      "splitting-wim",
				BytesDone:  copied,
				BytesTotal: totalBytes,
				Percent:    tracker.percent(copied),
				Message:    fmt.Sprintf("Splitting %s (%s) into Secure Boot FAT32 .swm parts...", e.Path, device.FormatBytes(e.Size)),
			})

			ra, _, err := isoFS.OpenReaderAt(e.Path)
			if err != nil {
				return fmt.Errorf("open WIM for splitting: %w", err)
			}

			dirName := path.Dir(e.Path)
			stem := strings.TrimSuffix(path.Base(e.Path), path.Ext(e.Path))

			_, err = wim.Split(ra, wim.DefaultMaxPartSize, nil, func(partNum, totalParts uint16, exactSize uint64, stream func(w io.Writer) error) error {
				partFile := wim.PartFileName(stem, partNum)
				destRel := partFile
				if dirName != "." && dirName != "" {
					destRel = path.Join(dirName, partFile)
				}
				pr, pw := io.Pipe()
				errCh := make(chan error, 1)
				go func() {
					errCh <- pw.CloseWithError(stream(pw))
				}()

				wErr := fw.WriteFileCtx(ctx, destRel, pr, exactSize, func(n int) {
					reportBytes(n, fmt.Sprintf("%s (%d/%d)", destRel, partNum, totalParts))
				})
				_ = pr.Close()
				sErr := <-errCh
				if wErr != nil {
					return wErr
				}
				return sErr
			})
			if err != nil {
				return fmt.Errorf("split %s into .swm parts: %w", e.Path, err)
			}
			continue
		}

		if e.Size > fat32FileLimit {
			return fmt.Errorf("file %q (%s) exceeds FAT32 4 GiB limit and is not a splittable .wim archive",
				e.Path, device.FormatBytes(e.Size))
		}

		rc, sz, err := isoFS.Open(e.Path)
		if err != nil {
			return fmt.Errorf("open ISO entry %q: %w", e.Path, err)
		}
		err = fw.WriteFileCtx(ctx, e.Path, rc, sz, func(n int) {
			reportBytes(n, e.Path)
		})
		_ = rc.Close()
		if err != nil {
			return fmt.Errorf("write %q to FAT32: %w", e.Path, err)
		}
	}

	// Inject optional Windows 10/11 autounattend.xml at USB root.
	if spec.Unattend.Enabled() {
		xmlBytes, err := unattend.Generate(spec.Unattend)
		if err != nil {
			return err
		}
		if len(xmlBytes) > 0 {
			emit(ProgressEvent{
				Phase:      "unattend",
				BytesDone:  copied,
				BytesTotal: totalBytes,
				Percent:    99,
				Message:    "Writing autounattend.xml Windows customizations...",
			})
			if err := fw.WriteBytes("autounattend.xml", xmlBytes); err != nil {
				return fmt.Errorf("write autounattend.xml: %w", err)
			}
		}
	}

	if err := fw.Close(); err != nil {
		return fmt.Errorf("finalize FAT32 filesystem: %w", err)
	}
	return nil
}
