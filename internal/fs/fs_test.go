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

func TestWipeAndRelocateUbuntuStyleGPT(t *testing.T) {
	const (
		sectorSize uint32 = 512
		isoSize    uint64 = 8 * 1024 * 1024  // 8 MiB hybrid ISO
		diskSize   uint64 = 64 * 1024 * 1024 // 64 MiB USB drive
		numEntries uint32 = 248              // Ubuntu xorriso-style 248 GPT entries (62 sectors)
		entrySize  uint32 = 128
	)

	imgPath := filepath.Join(t.TempDir(), "usb_ubuntu_gpt.img")
	f, err := os.Create(imgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(int64(diskSize)); err != nil {
		t.Fatal(err)
	}

	// Pre-populate stale GPT on the 64 MiB disk so we verify WipePartitionTables removes the tail backup.
	if _, _, err := WriteSinglePartitionGPT(f, diskSize, sectorSize, GPTTypeBasicData, "OLD_DISK"); err != nil {
		t.Fatalf("write old GPT: %v", err)
	}
	if err := WipePartitionTables(f, diskSize, sectorSize); err != nil {
		t.Fatalf("WipePartitionTables failed: %v", err)
	}
	tailBefore := make([]byte, sectorSize)
	if _, err := f.ReadAt(tailBefore, int64(diskSize-uint64(sectorSize))); err != nil {
		t.Fatal(err)
	}
	if string(tailBefore[0:8]) == "EFI PART" {
		t.Fatalf("expected WipePartitionTables to clear stale backup GPT at disk tail")
	}

	// Build a synthetic Ubuntu-style 8 MiB hybrid GPT image (248 entries, ISO9660 + ESP partitions).
	sec := uint64(sectorSize)
	isoSectors := isoSize / sec
	entriesBytes := make([]byte, numEntries*entrySize)
	entriesSectors := uint64(len(entriesBytes)) / sec // 62 sectors
	oldAltLBA := isoSectors - 1
	oldBackupEntriesLBA := oldAltLBA - entriesSectors
	oldLastUsable := oldBackupEntriesLBA - 1

	// Partition 1: ISO9660 (LBA 64..14000)
	copy(entriesBytes[0:16], GPTTypeBasicData[:])
	entriesBytes[16] = 0x11
	binary.LittleEndian.PutUint64(entriesBytes[32:40], 64)
	binary.LittleEndian.PutUint64(entriesBytes[40:48], 14000)

	// Partition 2: Appended2 EFI System Partition (LBA 14001..16000)
	eb2 := entriesBytes[entrySize : 2*entrySize]
	copy(eb2[0:16], GPTTypeEFI[:])
	eb2[16] = 0x22
	binary.LittleEndian.PutUint64(eb2[32:40], 14001)
	binary.LittleEndian.PutUint64(eb2[40:48], 16000)

	entriesCRC := crc32.ChecksumIEEE(entriesBytes)
	diskGUID := newRandomGUID()

	buildHdr := func(myLBA, altLBA, partLBA uint64) []byte {
		h := make([]byte, sec)
		copy(h[0:8], "EFI PART")
		binary.LittleEndian.PutUint32(h[8:12], 0x00010000)
		binary.LittleEndian.PutUint32(h[12:16], 92)
		binary.LittleEndian.PutUint64(h[24:32], myLBA)
		binary.LittleEndian.PutUint64(h[32:40], altLBA)
		binary.LittleEndian.PutUint64(h[40:48], 64)
		binary.LittleEndian.PutUint64(h[48:56], oldLastUsable)
		copy(h[56:72], diskGUID[:])
		binary.LittleEndian.PutUint64(h[72:80], partLBA)
		binary.LittleEndian.PutUint32(h[80:84], numEntries)
		binary.LittleEndian.PutUint32(h[84:88], entrySize)
		binary.LittleEndian.PutUint32(h[88:92], entriesCRC)
		binary.LittleEndian.PutUint32(h[16:20], crc32.ChecksumIEEE(h[0:92]))
		return h
	}

	mbr := make([]byte, sec)
	mbr[446+4] = 0xEE
	binary.LittleEndian.PutUint32(mbr[446+8:446+12], 1)
	binary.LittleEndian.PutUint32(mbr[446+12:446+16], uint32(isoSectors-1))
	mbr[510] = 0x55
	mbr[511] = 0xAA

	if _, err := f.WriteAt(mbr, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(buildHdr(1, oldAltLBA, 2), int64(sec)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(entriesBytes, int64(2*sec)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(entriesBytes, int64(oldBackupEntriesLBA*sec)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(buildHdr(oldAltLBA, 1, oldBackupEntriesLBA), int64(oldAltLBA*sec)); err != nil {
		t.Fatal(err)
	}

	// Relocate Backup GPT to end of 64 MiB disk.
	relocated, err := RelocateBackupGPT(f, diskSize, sectorSize)
	if err != nil {
		t.Fatalf("RelocateBackupGPT failed: %v", err)
	}
	if !relocated {
		t.Fatalf("expected RelocateBackupGPT to relocate ISO GPT")
	}

	diskSectors := diskSize / sec
	wantAltLBA := diskSectors - 1
	wantBackupEntriesLBA := wantAltLBA - entriesSectors
	wantLastUsable := wantBackupEntriesLBA - 1

	// Verify updated Protective MBR
	gotMBR := make([]byte, sec)
	if _, err := f.ReadAt(gotMBR, 0); err != nil {
		t.Fatal(err)
	}
	if gotPMBR := binary.LittleEndian.Uint32(gotMBR[446+12 : 446+16]); uint64(gotPMBR) != diskSectors-1 {
		t.Fatalf("PMBR sector count = %d, want %d", gotPMBR, diskSectors-1)
	}

	// Verify updated Primary GPT header
	gotPri := make([]byte, sec)
	if _, err := f.ReadAt(gotPri, int64(sec)); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(gotPri[32:40]); got != wantAltLBA {
		t.Fatalf("Primary AlternateLBA = %d, want %d", got, wantAltLBA)
	}
	if got := binary.LittleEndian.Uint64(gotPri[48:56]); got != wantLastUsable {
		t.Fatalf("Primary LastUsableLBA = %d, want %d", got, wantLastUsable)
	}
	priCheck := append([]byte(nil), gotPri[:92]...)
	binary.LittleEndian.PutUint32(priCheck[16:20], 0)
	if binary.LittleEndian.Uint32(gotPri[16:20]) != crc32.ChecksumIEEE(priCheck) {
		t.Fatalf("Primary GPT header CRC mismatch after relocation")
	}

	// Verify relocated Backup GPT header and entries at end of disk
	gotBak := make([]byte, sec)
	if _, err := f.ReadAt(gotBak, int64(wantAltLBA*sec)); err != nil {
		t.Fatal(err)
	}
	if string(gotBak[0:8]) != "EFI PART" {
		t.Fatalf("missing backup EFI PART signature at end of disk")
	}
	if got := binary.LittleEndian.Uint64(gotBak[24:32]); got != wantAltLBA {
		t.Fatalf("Backup MyLBA = %d, want %d", got, wantAltLBA)
	}
	if got := binary.LittleEndian.Uint64(gotBak[32:40]); got != 1 {
		t.Fatalf("Backup AlternateLBA = %d, want 1", got)
	}
	if got := binary.LittleEndian.Uint64(gotBak[72:80]); got != wantBackupEntriesLBA {
		t.Fatalf("Backup PartitionEntryLBA = %d, want %d", got, wantBackupEntriesLBA)
	}
	bakCheck := append([]byte(nil), gotBak[:92]...)
	binary.LittleEndian.PutUint32(bakCheck[16:20], 0)
	if binary.LittleEndian.Uint32(gotBak[16:20]) != crc32.ChecksumIEEE(bakCheck) {
		t.Fatalf("Backup GPT header CRC mismatch after relocation")
	}
	gotBakEntries := make([]byte, len(entriesBytes))
	if _, err := f.ReadAt(gotBakEntries, int64(wantBackupEntriesLBA*sec)); err != nil {
		t.Fatal(err)
	}
	if crc32.ChecksumIEEE(gotBakEntries) != entriesCRC {
		t.Fatalf("Backup GPT entries CRC mismatch after relocation")
	}

	// Verify old mid-disk backup header was cleared
	oldSec := make([]byte, sec)
	if _, err := f.ReadAt(oldSec, int64(oldAltLBA*sec)); err != nil {
		t.Fatal(err)
	}
	if string(oldSec[0:8]) == "EFI PART" {
		t.Fatalf("expected old mid-disk backup GPT header to be cleared")
	}

	// Running RelocateBackupGPT a second time must be a no-op
	relocated2, err := RelocateBackupGPT(f, diskSize, sectorSize)
	if err != nil {
		t.Fatalf("second RelocateBackupGPT failed: %v", err)
	}
	if relocated2 {
		t.Fatalf("expected second RelocateBackupGPT to be a no-op")
	}
}
