// SPDX-License-Identifier: GPL-3.0-only
package fs

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
)

func TestGPTAndFAT32FormatAndWrite(t *testing.T) {
	const diskSize uint64 = 64 * 1024 * 1024 // 64 MiB virtual disk
	imgPath := filepath.Join(t.TempDir(), "virtual_usb.img")
	f, err := os.Create(imgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(int64(diskSize)); err != nil {
		t.Fatal(err)
	}

	// 1. Write GPT
	partOff, partSize, err := WriteSinglePartitionGPT(f, diskSize, 512, GPTTypeBasicData, "CINDERBOOT")
	if err != nil {
		t.Fatalf("WriteSinglePartitionGPT failed: %v", err)
	}
	if partOff != 1024*1024 {
		t.Fatalf("expected 1 MiB aligned partition offset, got %d", partOff)
	}

	// Verify primary GPT header signature & CRC32
	hdr := make([]byte, 512)
	if _, err := f.ReadAt(hdr, 512); err != nil {
		t.Fatal(err)
	}
	if string(hdr[0:8]) != "EFI PART" {
		t.Fatalf("missing EFI PART signature")
	}
	gotCRC := binary.LittleEndian.Uint32(hdr[16:20])
	hdrCopy := append([]byte(nil), hdr[0:92]...)
	binary.LittleEndian.PutUint32(hdrCopy[16:20], 0)
	if wantCRC := crc32.ChecksumIEEE(hdrCopy); gotCRC != wantCRC {
		t.Fatalf("GPT header CRC mismatch: got %#x, want %#x", gotCRC, wantCRC)
	}

	// Verify backup GPT header at last LBA
	backupHdr := make([]byte, 512)
	if _, err := f.ReadAt(backupHdr, int64(diskSize-512)); err != nil {
		t.Fatal(err)
	}
	if string(backupHdr[0:8]) != "EFI PART" {
		t.Fatalf("missing backup EFI PART signature")
	}

	// 2. Format FAT32 and write nested LFN + multi-cluster files
	fw, err := FormatFAT32(f, int64(partOff), partSize, 512, "WIN11_USB")
	if err != nil {
		t.Fatalf("FormatFAT32 failed: %v", err)
	}

	xmlPayload := []byte("<unattend>Cinderboot AutoUnattend Test</unattend>")
	if err := fw.WriteBytes("autounattend.xml", xmlPayload); err != nil {
		t.Fatalf("WriteBytes autounattend.xml failed: %v", err)
	}

	efiPayload := bytes.Repeat([]byte("MZ-EFI-BOOTLOADER-PAYLOAD"), 256)
	if err := fw.WriteBytes("efi/boot/bootx64.efi", efiPayload); err != nil {
		t.Fatalf("WriteBytes efi/boot/bootx64.efi failed: %v", err)
	}

	longPayload := bytes.Repeat([]byte("SPLIT-WIM-CHUNK-DATA"), 1024)
	if err := fw.WriteBytes("sources/install_long_filename_test_archive.swm", longPayload); err != nil {
		t.Fatalf("WriteBytes long LFN file failed: %v", err)
	}

	if err := fw.Close(); err != nil {
		t.Fatalf("FAT32 Close failed: %v", err)
	}

	// Verify FAT32 boot sector, FSInfo, and backup boot sector
	boot := make([]byte, 512)
	if _, err := f.ReadAt(boot, int64(partOff)); err != nil {
		t.Fatal(err)
	}
	if string(boot[82:90]) != "FAT32   " || boot[510] != 0x55 || boot[511] != 0xAA {
		t.Fatalf("invalid FAT32 boot sector signature")
	}
	if string(boot[71:82]) != "WIN11_USB  " {
		t.Fatalf("unexpected volume label: %q", string(boot[71:82]))
	}
	fsInfo := make([]byte, 512)
	if _, err := f.ReadAt(fsInfo, int64(partOff)+512); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(fsInfo[0:4]) != 0x41615252 || binary.LittleEndian.Uint32(fsInfo[484:488]) != 0x61417272 {
		t.Fatalf("invalid FSInfo signatures")
	}
}
