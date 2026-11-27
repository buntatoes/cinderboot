// SPDX-License-Identifier: GPL-3.0-only
package flash

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/buntatoes/cinderboot/internal/fs"
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

func TestWriteRawStreamCancellation(t *testing.T) {
	dir := t.TempDir()
	imgPath := filepath.Join(dir, "big.img")
	payload := bytes.Repeat([]byte("CANCEL-TEST-DATA"), 256*1024) // 4 MiB
	if err := os.WriteFile(imgPath, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	usbPath := filepath.Join(dir, "usb.bin")
	f, err := os.Create(usbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = WriteRawStream(ctx, imgPath, f, 16*1024*1024, 512, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
}

func TestWriteMultibootEndToEnd(t *testing.T) {
	dir := t.TempDir()

	ubuntuISO := filepath.Join(dir, "ubuntu-24.04-desktop-amd64.iso")
	voidISO := filepath.Join(dir, "void-live-x86_64.iso")

	// Build a synthetic Ubuntu ISO9660 with embedded GPT FAT32 EFI System Partition (BOOTX64.EFI + grubx64.efi).
	buildSyntheticLinuxISO(t, ubuntuISO, "UBUNTU 24_04", "2024082716232600", map[string][]byte{
		"casper/vmlinuz":      []byte("UBUNTU-KERNEL"),
		"casper/initrd":       []byte("UBUNTU-INITRD"),
		"boot/grub/grub.cfg":  []byte("menuentry \"Try or Install Ubuntu\" {\n  linux /casper/vmlinuz quiet splash ---\n  initrd /casper/initrd\n}\n"),
	}, true)

	// Build a synthetic Void Linux ISO9660.
	buildSyntheticLinuxISO(t, voidISO, "VOID_LIVE", "2024031412000000", map[string][]byte{
		"boot/vmlinuz": []byte("VOID-KERNEL"),
		"boot/initrd":  []byte("VOID-INITRD"),
	}, false)

	// Create a 192 MiB virtual USB disk (64 MiB ESP + two ~40 MiB+ ISOs).
	const diskSize uint64 = 192 * 1024 * 1024
	usbPath := filepath.Join(dir, "multiboot_usb.img")
	usbFile, err := os.Create(usbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer usbFile.Close()
	if err := usbFile.Truncate(int64(diskSize)); err != nil {
		t.Fatal(err)
	}

	spec := JobSpec{
		ImagePaths: []string{ubuntuISO, voidISO},
		Mode:       ModeMultiboot,
	}
	if err := WriteMultiboot(context.Background(), spec, usbFile, diskSize, 512, nil); err != nil {
		t.Fatalf("WriteMultiboot failed: %v", err)
	}

	// Verify GPT contains 3 partitions: ESP + Ubuntu + Void.
	parts, err := fs.ParseGPTPartitions(usbFile, int64(diskSize), 512)
	if err != nil {
		t.Fatalf("ParseGPTPartitions failed: %v", err)
	}
	if len(parts) != 3 {
		t.Fatalf("expected 3 GPT partitions (ESP + 2 ISOs), got %d", len(parts))
	}
	if parts[0].TypeGUID != fs.GPTTypeEFI {
		t.Fatalf("partition 1 must have GPTTypeEFI")
	}

	// Read back Partition 1 (FAT32 ESP) using our pure-Go FATReader.
	espOff := int64(parts[0].FirstLBA * 512)
	espLen := int64((parts[0].LastLBA - parts[0].FirstLBA + 1) * 512)
	fr, err := fs.OpenFATReader(io.NewSectionReader(usbFile, espOff, espLen), espLen)
	if err != nil {
		t.Fatalf("OpenFATReader on multiboot ESP failed: %v", err)
	}
	espFiles, err := fr.ReadAllFiles(16 * 1024 * 1024)
	if err != nil {
		t.Fatalf("ReadAllFiles on ESP failed: %v", err)
	}
	lowerFiles := make(map[string][]byte)
	for k, v := range espFiles {
		lowerFiles[strings.ToLower(k)] = v
	}

	for _, req := range []string{
		"efi/boot/bootx64.efi",
		"efi/boot/grubx64.efi",
		"efi/boot/grub.cfg",
		"efi/ubuntu/grub.cfg",
		"efi/fedora/grub.cfg",
		"boot/grub/grub.cfg",
		".disk/info",
	} {
		if _, ok := lowerFiles[req]; !ok {
			t.Fatalf("missing required multiboot ESP file %q (have: %v)", req, espFiles)
		}
	}

	menu := string(lowerFiles["boot/grub/grub.cfg"])
	ubuntuUUID := fs.FormatGUID(parts[1].UniqueGUID)
	voidUUID := fs.FormatGUID(parts[2].UniqueGUID)
	if !strings.Contains(menu, "2024-08-27-16-23-26-00") || !strings.Contains(menu, "live-media=/dev/disk/by-partuuid/"+ubuntuUUID) {
		t.Fatalf("generated grub.cfg missing Ubuntu PARTUUID entry:\n%s", menu)
	}
	if !strings.Contains(menu, "2024-03-14-12-00-00-00") || !strings.Contains(menu, "root=live:PARTUUID="+voidUUID) {
		t.Fatalf("generated grub.cfg missing Void PARTUUID entry:\n%s", menu)
	}
	if !strings.Contains(menu, "Native UEFI Chainload") {
		t.Fatalf("generated grub.cfg missing UEFI chainload submenu:\n%s", menu)
	}

	// Verify raw ISO bytes written to Partition 2 & 3 match source files.
	wantVoid, _ := os.ReadFile(voidISO)
	gotVoid := make([]byte, len(wantVoid))
	if _, err := usbFile.ReadAt(gotVoid, int64(parts[2].FirstLBA*512)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotVoid, wantVoid) {
		t.Fatalf("Partition 3 raw Void ISO bytes mismatch")
	}
}

// buildSyntheticLinuxISO creates a valid ISO9660 image with optional embedded GPT FAT32 ESP for testing.
func buildSyntheticLinuxISO(t *testing.T, outPath, label, ts16 string, files map[string][]byte, withGPTEFI bool) {
	t.Helper()
	const isoSec = 2048

	// Minimal ISO9660 size; if withGPTEFI, include a 36 MiB FAT32 ESP partition appended inside the ISO.
	isoBytes := uint64(2 * 1024 * 1024)
	if withGPTEFI {
		isoBytes = 40 * 1024 * 1024
	}
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(int64(isoBytes)); err != nil {
		t.Fatal(err)
	}

	// Build flat ISO9660 tree (supports nested directories via simple recursion).
	type dirNode struct {
		dirs  map[string]*dirNode
		files map[string][]byte
		lba   uint32
		size  uint32
	}
	root := &dirNode{dirs: map[string]*dirNode{}, files: map[string][]byte{}}
	for rel, content := range files {
		parts := strings.Split(rel, "/")
		cur := root
		for _, seg := range parts[:len(parts)-1] {
			if cur.dirs[seg] == nil {
				cur.dirs[seg] = &dirNode{dirs: map[string]*dirNode{}, files: map[string][]byte{}}
			}
			cur = cur.dirs[seg]
		}
		cur.files[parts[len(parts)-1]] = content
	}

	nextLBA := uint32(20)
	var writeNode func(n *dirNode)
	writeNode = func(n *dirNode) {
		for _, sub := range n.dirs {
			writeNode(sub)
		}
		var dirBuf bytes.Buffer
		appendRec := func(name string, lba, size uint32, isDir bool) {
			recLen := 33 + len(name)
			if recLen%2 != 0 {
				recLen++
			}
			rec := make([]byte, recLen)
			rec[0] = byte(recLen)
			binary.LittleEndian.PutUint32(rec[2:6], lba)
			binary.LittleEndian.PutUint32(rec[10:14], size)
			if isDir {
				rec[25] = 0x02
			}
			rec[32] = byte(len(name))
			copy(rec[33:], name)
			dirBuf.Write(rec)
		}
		for name, sub := range n.dirs {
			appendRec(name, sub.lba, sub.size, true)
		}
		for name, data := range n.files {
			flba := nextLBA
			secs := uint32((len(data) + isoSec - 1) / isoSec)
			if secs == 0 {
				secs = 1
			}
			nextLBA += secs
			if _, err := f.WriteAt(data, int64(flba)*isoSec); err != nil {
				t.Fatal(err)
			}
			appendRec(name+";1", flba, uint32(len(data)), false)
		}
		n.lba = nextLBA
		raw := dirBuf.Bytes()
		if len(raw) == 0 {
			raw = make([]byte, isoSec)
		}
		secs := uint32((len(raw) + isoSec - 1) / isoSec)
		n.size = secs * isoSec
		nextLBA += secs
		padded := make([]byte, n.size)
		copy(padded, raw)
		if _, err := f.WriteAt(padded, int64(n.lba)*isoSec); err != nil {
			t.Fatal(err)
		}
	}
	writeNode(root)

	// Write ISO9660 Primary Volume Descriptor at sector 16 & Terminator at sector 17.
	pvd := make([]byte, isoSec)
	pvd[0] = 1
	copy(pvd[1:6], "CD001")
	pvd[6] = 1
	copy(pvd[40:72], strings.Repeat(" ", 32))
	copy(pvd[40:72], label)
	binary.LittleEndian.PutUint32(pvd[158:162], root.lba)
	binary.LittleEndian.PutUint32(pvd[166:170], root.size)
	copy(pvd[813:829], ts16)
	if _, err := f.WriteAt(pvd, 16*isoSec); err != nil {
		t.Fatal(err)
	}
	term := make([]byte, isoSec)
	term[0] = 255
	copy(term[1:6], "CD001")
	term[6] = 1
	if _, err := f.WriteAt(term, 17*isoSec); err != nil {
		t.Fatal(err)
	}

	if withGPTEFI {
		// Append a 36 MiB FAT32 ESP starting at 2 MiB inside the synthetic ISO and write a valid GPT header.
		espOff := uint64(2 * 1024 * 1024)
		espSize := uint64(36 * 1024 * 1024)
		gptParts := []fs.GPTPartition{
			{
				TypeGUID:   fs.GPTTypeBasicData,
				UniqueGUID: fs.NewRandomGUID(),
				FirstLBA:   64,
				LastLBA:    (espOff / 512) - 1,
				Name:       "ISO9660",
			},
			{
				TypeGUID:   fs.GPTTypeEFI,
				UniqueGUID: fs.NewRandomGUID(),
				FirstLBA:   espOff / 512,
				LastLBA:    (espOff+espSize)/512 - 1,
				Name:       "Appended2",
			},
		}
		if err := fs.WriteGPT(f, isoBytes, 512, gptParts); err != nil {
			t.Fatal(err)
		}
		fw, err := fs.FormatFAT32(f, int64(espOff), espSize, 512, "UBUNTU_ESP")
		if err != nil {
			t.Fatal(err)
		}
		if err := fw.WriteBytes("EFI/BOOT/BOOTX64.EFI", []byte("MZ-SHIM-SIGNED-EFI")); err != nil {
			t.Fatal(err)
		}
		if err := fw.WriteBytes("EFI/BOOT/grubx64.efi", []byte("MZ-GRUB2-SIGNED-EFI")); err != nil {
			t.Fatal(err)
		}
		if err := fw.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
