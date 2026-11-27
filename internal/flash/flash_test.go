// SPDX-License-Identifier: GPL-3.0-only
package flash

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type flakyWriteSeeker struct {
	f          *os.File
	failWrites int
	attempts   int
}

func (w *flakyWriteSeeker) Write(p []byte) (int, error) {
	w.attempts++
	if w.attempts <= w.failWrites {
		return 0, errors.New("simulated transient USB write stall")
	}
	return w.f.Write(p)
}

func (w *flakyWriteSeeker) Seek(offset int64, whence int) (int64, error) {
	return w.f.Seek(offset, whence)
}

func TestWriteRawStreamTransientRecovery(t *testing.T) {
	dir := t.TempDir()
	payload := bytes.Repeat([]byte("RECOVERY-TEST-512B-SECTOR-DATA!!"), 2048) // 64 KiB
	imgPath := filepath.Join(dir, "linux.img")
	if err := os.WriteFile(imgPath, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	usbPath := filepath.Join(dir, "flaky_usb.bin")
	f, err := os.Create(usbPath)
	if err != nil {
		t.Fatal(err)
	}
	flaky := &flakyWriteSeeker{f: f, failWrites: 2}

	var sawRecovering bool
	sum, written, err := WriteRawStream(context.Background(), imgPath, flaky, 1024*1024, 512, func(ev ProgressEvent) {
		if ev.Phase == "recovering" {
			sawRecovering = true
		}
	})
	_ = f.Close()
	if err != nil {
		t.Fatalf("expected transient write error recovery to succeed, got: %v", err)
	}
	if !sawRecovering {
		t.Fatalf("expected recovering progress event during retry")
	}
	if written != uint64(len(payload)) {
		t.Fatalf("expected %d written bytes, got %d", len(payload), written)
	}

	rf, _ := os.Open(usbPath)
	defer rf.Close()
	if err := VerifyRawReadBack(context.Background(), rf, written, sum, nil); err != nil {
		t.Fatalf("read-back verify after recovery failed: %v", err)
	}
}

func TestWriteRawStreamAndVerifyReadBack(t *testing.T) {
	dir := t.TempDir()
	rawPayload := bytes.Repeat([]byte("CINDERBOOT-VERIFY-SECTOR-BLOCK!!"), 2048) // 64 KiB

	gzPath := filepath.Join(dir, "distro.img.gz")
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	_, _ = gw.Write(rawPayload)
	_ = gw.Close()
	if err := os.WriteFile(gzPath, gz.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	usbPath := filepath.Join(dir, "fake_usb.bin")
	usbFile, err := os.Create(usbPath)
	if err != nil {
		t.Fatal(err)
	}

	sum, written, err := WriteRawStream(context.Background(), gzPath, usbFile, 1024*1024, 512, nil)
	if err != nil {
		t.Fatalf("WriteRawStream failed: %v", err)
	}
	if written != uint64(len(rawPayload)) {
		t.Fatalf("expected %d written bytes, got %d", len(rawPayload), written)
	}
	_ = usbFile.Close()

	// Verify read-back succeeds against written image
	rf, err := os.Open(usbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer rf.Close()
	if err := VerifyRawReadBack(context.Background(), rf, written, sum, nil); err != nil {
		t.Fatalf("VerifyRawReadBack failed: %v", err)
	}

	// Corrupt 1 byte and ensure verification catches it
	data, _ := os.ReadFile(usbPath)
	data[1024] ^= 0xFF
	_ = os.WriteFile(usbPath, data, 0o644)
	rf2, _ := os.Open(usbPath)
	defer rf2.Close()
	if err := VerifyRawReadBack(context.Background(), rf2, written, sum, nil); err == nil {
		t.Fatalf("expected SHA-256 verification failure on corrupted disk")
	}
}
