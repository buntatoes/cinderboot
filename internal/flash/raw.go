// SPDX-License-Identifier: GPL-3.0-only
package flash

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"syscall"
	"time"

	"github.com/buntatoes/cinderboot/internal/device"
	"github.com/buntatoes/cinderboot/internal/fs"
	"github.com/buntatoes/cinderboot/internal/image"
)

const (
	rawChunkSize    = 2 * 1024 * 1024  // 2 MiB aligned sequential I/O (fast + responsive cancel)
	rawSyncInterval = 16 * 1024 * 1024 // Flush dirty buffers every 16 MiB to prevent USB writeback stalls
	maxRetryAttempt = 3
)

func isFatalIOError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EROFS) ||
		errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) ||
		errors.Is(err, syscall.ENODEV) {
		return true
	}
	return false
}

func writeWithRecovery(ctx context.Context, dst io.Writer, offset uint64, data []byte, emit ProgressSink) error {
	var lastErr error
	seeker, canSeek := dst.(io.Seeker)
	for attempt := 0; attempt <= maxRetryAttempt; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if attempt > 0 {
			if emit != nil {
				emit(ProgressEvent{
					Phase:   "recovering",
					Message: fmt.Sprintf("Transient write error at %s — recovering (retry %d/%d)...", device.FormatBytes(offset), attempt, maxRetryAttempt),
				})
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 250 * time.Millisecond):
			}
			if !canSeek {
				return lastErr
			}
			if _, sErr := seeker.Seek(int64(offset), io.SeekStart); sErr != nil {
				return fmt.Errorf("seek recovery failed at offset %d: %w", offset, sErr)
			}
		}
		n, err := dst.Write(data)
		if err == nil && n == len(data) {
			return nil
		}
		if err == nil {
			err = io.ErrShortWrite
		}
		lastErr = err
		if isFatalIOError(err) || !canSeek {
			return err
		}
	}
	return lastErr
}

func readWithRecovery(ctx context.Context, src io.Reader, offset uint64, buf []byte, emit ProgressSink) (int, error) {
	var lastErr error
	seeker, canSeek := src.(io.Seeker)
	for attempt := 0; attempt <= maxRetryAttempt; attempt++ {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if attempt > 0 {
			if emit != nil {
				emit(ProgressEvent{
					Phase:   "recovering",
					Message: fmt.Sprintf("Transient read error during verify at %s — recovering (retry %d/%d)...", device.FormatBytes(offset), attempt, maxRetryAttempt),
				})
			}
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case <-time.After(time.Duration(attempt) * 250 * time.Millisecond):
			}
			if !canSeek {
				return 0, lastErr
			}
			if _, sErr := seeker.Seek(int64(offset), io.SeekStart); sErr != nil {
				return 0, fmt.Errorf("verify seek recovery failed at offset %d: %w", offset, sErr)
			}
		}
		n, err := io.ReadFull(src, buf)
		if err == nil {
			return n, nil
		}
		lastErr = err
		if isFatalIOError(err) || errors.Is(err, io.EOF) || !canSeek {
			return n, err
		}
	}
	return 0, lastErr
}

func flashRawToDrive(ctx context.Context, spec JobSpec, info image.Info, drv device.Drive, emit ProgressSink) error {
	f, err := device.OpenRawWrite(drv)
	if err != nil {
		return err
	}

	emit(ProgressEvent{
		Phase:   "prepare",
		Message: "Clearing old partition tables and backup GPT metadata...",
	})
	if err := fs.WipePartitionTables(f, drv.SizeBytes, drv.SectorSize); err != nil {
		_ = f.Close()
		return fmt.Errorf("clear old partition tables: %w", err)
	}

	hashHex, written, err := WriteRawStream(ctx, spec.ImagePath, f, drv.SizeBytes, drv.SectorSize, emit)
	if err != nil {
		_ = f.Close()
		return err
	}
	emit(ProgressEvent{
		Phase:      "sync",
		BytesDone:  written,
		BytesTotal: written,
		Percent:    100,
		Message:    "Flushing device caches...",
	})
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync target device: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close target device: %w", err)
	}

	if spec.Verify {
		rf, err := device.OpenRawRead(drv)
		if err != nil {
			return fmt.Errorf("reopen target device for verification: %w", err)
		}
		_ = device.FlushReadCache(rf)
		vErr := VerifyRawReadBack(ctx, rf, written, hashHex, emit)
		_ = rf.Close()
		if vErr != nil {
			return vErr
		}
	}

	// Relocate Backup GPT & Protective MBR to the physical end of the USB drive when a hybrid
	// GPT ISO (such as Ubuntu 22.04/24.04+) is smaller than the target disk so strict UEFI
	// firmwares validate the GPT table and detect the EFI System Partition.
	gf, err := device.OpenRawWrite(drv)
	if err != nil {
		return fmt.Errorf("reopen target device for GPT check: %w", err)
	}
	relocated, gErr := fs.RelocateBackupGPT(gf, drv.SizeBytes, drv.SectorSize)
	if gErr != nil {
		_ = gf.Close()
		return fmt.Errorf("relocate backup GPT: %w", gErr)
	}
	if relocated {
		emit(ProgressEvent{
			Phase:      "partition",
			BytesDone:  written,
			BytesTotal: written,
			Percent:    100,
			Message:    "Relocated Backup GPT to end of USB drive for UEFI compatibility",
		})
		if err := gf.Sync(); err != nil {
			_ = gf.Close()
			return fmt.Errorf("sync relocated GPT: %w", err)
		}
	}
	if err := gf.Close(); err != nil {
		return fmt.Errorf("close target device after GPT check: %w", err)
	}

	_ = device.RereadPartitionTablePath(drv.DevicePath)

	emit(ProgressEvent{
		Phase:      "complete",
		BytesDone:  written,
		BytesTotal: written,
		Percent:    100,
		SHA256:     hashHex,
		Done:       true,
		Message:    fmt.Sprintf("Flash complete (%s)", device.FormatBytes(written)),
	})
	return nil
}

// WriteRawStream streams a raw or compressed image directly into dst, computing its SHA-256 hash on the fly.
func WriteRawStream(
	ctx context.Context,
	imgPath string,
	dst io.Writer,
	maxCapacity uint64,
	sectorSize uint32,
	emit ProgressSink,
) (sha256Hex string, writtenBytes uint64, err error) {
	if sectorSize == 0 {
		sectorSize = 512
	}
	stream, err := image.OpenRawStream(imgPath)
	if err != nil {
		return "", 0, err
	}
	defer stream.Close()

	var totalExpected uint64
	if stream.ExpectedSize > 0 {
		totalExpected = uint64(stream.ExpectedSize)
		if maxCapacity > 0 && totalExpected > maxCapacity {
			return "", 0, fmt.Errorf("image (%s) is larger than target USB drive (%s)",
				device.FormatBytes(totalExpected), device.FormatBytes(maxCapacity))
		}
	}

	hasher := sha256.New()
	tracker := newSpeedTracker(totalExpected)
	buf := make([]byte, rawChunkSize)
	type syncer interface {
		Sync() error
	}
	dstSync, canSync := dst.(syncer)
	var sinceSync uint64

	for {
		if err := ctx.Err(); err != nil {
			return "", writtenBytes, err
		}
		n, rErr := readFullOrEOF(stream.Reader, buf)
		if n > 0 {
			if maxCapacity > 0 && writtenBytes+uint64(n) > maxCapacity {
				return "", writtenBytes, fmt.Errorf("decompressed image exceeds target drive capacity (%s)", device.FormatBytes(maxCapacity))
			}

			// Hash exact logical image bytes before any trailing sector padding.
			_, _ = hasher.Write(buf[:n])

			writeSlice := buf[:n]
			// Pad final partial block to sector boundary for raw block device alignment.
			if rem := n % int(sectorSize); rem != 0 {
				pad := int(sectorSize) - rem
				if n+pad <= len(buf) {
					clear(buf[n : n+pad])
					writeSlice = buf[:n+pad]
				}
			}

			if wErr := writeWithRecovery(ctx, dst, writtenBytes, writeSlice, emit); wErr != nil {
				return "", writtenBytes, fmt.Errorf("write to target device at offset %d: %w", writtenBytes, wErr)
			}
			writtenBytes += uint64(n)
			sinceSync += uint64(len(writeSlice))
			if canSync && sinceSync >= rawSyncInterval {
				if sErr := dstSync.Sync(); sErr != nil {
					return "", writtenBytes, fmt.Errorf("flush target device at offset %d: %w", writtenBytes, sErr)
				}
				sinceSync = 0
			}

			if tracker.shouldEmit(false) && emit != nil {
				spd := tracker.speed(writtenBytes)
				emit(ProgressEvent{
					Phase:      "flashing",
					BytesDone:  writtenBytes,
					BytesTotal: totalExpected,
					SpeedBPS:   spd,
					Percent:    tracker.percent(writtenBytes),
					Message:    fmt.Sprintf("Flashing %s (%s/s)", device.FormatBytes(writtenBytes), device.FormatBytes(uint64(spd))),
				})
			}
		}
		if rErr != nil {
			if errors.Is(rErr, io.EOF) {
				break
			}
			return "", writtenBytes, fmt.Errorf("read image stream: %w", rErr)
		}
	}

	sum := hex.EncodeToString(hasher.Sum(nil))
	if emit != nil {
		emit(ProgressEvent{
			Phase:      "flashing",
			BytesDone:  writtenBytes,
			BytesTotal: writtenBytes,
			SpeedBPS:   tracker.speed(writtenBytes),
			Percent:    100,
			SHA256:     sum,
			Message:    fmt.Sprintf("Wrote %s", device.FormatBytes(writtenBytes)),
		})
	}
	return sum, writtenBytes, nil
}

// VerifyRawReadBack reads writtenBytes back from src and verifies its SHA-256 matches expectedHex.
func VerifyRawReadBack(ctx context.Context, src io.Reader, writtenBytes uint64, expectedHex string, emit ProgressSink) error {
	hasher := sha256.New()
	tracker := newSpeedTracker(writtenBytes)
	buf := make([]byte, rawChunkSize)
	var verified uint64

	for verified < writtenBytes {
		if err := ctx.Err(); err != nil {
			return err
		}
		want := uint64(len(buf))
		if want > writtenBytes-verified {
			want = writtenBytes - verified
		}
		n, err := readWithRecovery(ctx, src, verified, buf[:want], emit)
		if n > 0 {
			_, _ = hasher.Write(buf[:n])
			verified += uint64(n)
			if tracker.shouldEmit(false) && emit != nil {
				spd := tracker.speed(verified)
				emit(ProgressEvent{
					Phase:      "verifying",
					BytesDone:  verified,
					BytesTotal: writtenBytes,
					SpeedBPS:   spd,
					Percent:    tracker.percent(verified),
					Message:    fmt.Sprintf("Verifying SHA-256 %s / %s (%s/s)", device.FormatBytes(verified), device.FormatBytes(writtenBytes), device.FormatBytes(uint64(spd))),
				})
			}
		}
		if err != nil {
			return fmt.Errorf("read back for verification at %d: %w", verified, err)
		}
	}

	gotHex := hex.EncodeToString(hasher.Sum(nil))
	if gotHex != expectedHex {
		return fmt.Errorf("SHA-256 verification failed: wrote %s, read back %s", expectedHex, gotHex)
	}
	return nil
}

// VerifyImageAgainstDevice streams imgPath to compute its SHA-256 and compares it with the USB device.
func VerifyImageAgainstDevice(ctx context.Context, imgPath, devPath string, includeFixed bool, emit ProgressSink) (string, error) {
	drv, err := device.FindByPath(devPath, device.ListOptions{IncludeFixedUSB: includeFixed})
	if err != nil {
		return "", err
	}
	stream, err := image.OpenRawStream(imgPath)
	if err != nil {
		return "", err
	}
	defer stream.Close()

	h := sha256.New()
	n, err := io.Copy(h, stream.Reader)
	if err != nil {
		return "", fmt.Errorf("hash source image: %w", err)
	}
	expected := hex.EncodeToString(h.Sum(nil))

	rf, err := device.OpenRawRead(drv)
	if err != nil {
		return "", err
	}
	defer rf.Close()
	_ = device.FlushReadCache(rf)

	if err := VerifyRawReadBack(ctx, rf, uint64(n), expected, emit); err != nil {
		return "", err
	}
	return expected, nil
}

func readFullOrEOF(r io.Reader, buf []byte) (int, error) {
	var total int
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			if errors.Is(err, io.EOF) && total > 0 {
				return total, nil
			}
			return total, err
		}
	}
	return total, nil
}
