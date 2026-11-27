// SPDX-License-Identifier: GPL-3.0-only
package fs

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"time"
	"unicode/utf16"
)

// Standard UEFI GPT partition type GUIDs (stored in Microsoft mixed-endian on-disk format).
var (
	// GPTTypeBasicData = EBD0A0A2-B9E5-4433-87C0-68B6B72699C7
	GPTTypeBasicData = [16]byte{
		0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
		0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
	}
	// GPTTypeEFI = C12A7328-F81F-11D2-BA4B-00A0C93EC93B
	GPTTypeEFI = [16]byte{
		0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11,
		0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
	}
)

// GPTPartition describes a single GPT partition to write.
type GPTPartition struct {
	TypeGUID   [16]byte
	UniqueGUID [16]byte
	FirstLBA   uint64
	LastLBA    uint64 // inclusive
	Attributes uint64
	Name       string
}

// WriteSinglePartitionGPT writes a Protective MBR + Primary & Backup GPT
// with one 1 MiB-aligned partition spanning the usable disk space.
// Returns the partition's byte offset and exact byte length.
func WriteSinglePartitionGPT(w io.WriteSeeker, diskSize uint64, sectorSize uint32, typeGUID [16]byte, name string) (partOffset, partSize uint64, err error) {
	if sectorSize == 0 {
		sectorSize = 512
	}
	sec := uint64(sectorSize)
	totalSectors := diskSize / sec
	if totalSectors < 4096 {
		return 0, 0, fmt.Errorf("disk too small for GPT (%d sectors)", totalSectors)
	}

	// 1 MiB alignment for FirstLBA, leaving 34 sectors for backup GPT at tail.
	alignSectors := (1024 * 1024) / sec
	if alignSectors < 34 {
		alignSectors = 34
	}
	firstLBA := alignSectors
	lastUsable := totalSectors - 34
	// Align partition end down to 1 MiB boundary when possible.
	lastLBA := lastUsable
	if lastLBA > firstLBA+alignSectors {
		lastLBA = ((lastLBA + 1) / alignSectors * alignSectors) - 1
		if lastLBA > lastUsable {
			lastLBA = lastUsable
		}
	}

	part := GPTPartition{
		TypeGUID:   typeGUID,
		UniqueGUID: newRandomGUID(),
		FirstLBA:   firstLBA,
		LastLBA:    lastLBA,
		Name:       name,
	}
	if err := WriteGPT(w, diskSize, sectorSize, []GPTPartition{part}); err != nil {
		return 0, 0, err
	}
	return firstLBA * sec, (lastLBA - firstLBA + 1) * sec, nil
}

// WriteGPT writes Protective MBR (LBA 0), Primary GPT (LBA 1..33), and Backup GPT (tail 33 sectors).
func WriteGPT(w io.WriteSeeker, diskSize uint64, sectorSize uint32, partitions []GPTPartition) error {
	if sectorSize == 0 {
		sectorSize = 512
	}
	sec := uint64(sectorSize)
	totalSectors := diskSize / sec
	if totalSectors < 128 {
		return fmt.Errorf("disk too small for GPT: %d bytes", diskSize)
	}
	if len(partitions) > 128 {
		return fmt.Errorf("too many GPT partitions: %d", len(partitions))
	}

	// 1. Protective MBR (LBA 0)
	mbr := make([]byte, sec)
	mbr[446+4] = 0xEE // GPT Protective partition type
	mbr[446+1] = 0x00
	mbr[446+2] = 0x02
	mbr[446+3] = 0x00
	mbr[446+5] = 0xFF
	mbr[446+6] = 0xFF
	mbr[446+7] = 0xFF
	binary.LittleEndian.PutUint32(mbr[446+8:446+12], 1)
	mbrSectors := totalSectors - 1
	if mbrSectors > 0xFFFFFFFF {
		mbrSectors = 0xFFFFFFFF
	}
	binary.LittleEndian.PutUint32(mbr[446+12:446+16], uint32(mbrSectors))
	mbr[510] = 0x55
	mbr[511] = 0xAA

	// 2. Partition Entry Array (128 entries * 128 bytes = 16384 bytes)
	const numEntries = 128
	const entrySize = 128
	entriesBytes := make([]byte, numEntries*entrySize)
	for i, p := range partitions {
		if p.UniqueGUID == ([16]byte{}) {
			p.UniqueGUID = newRandomGUID()
		}
		eb := entriesBytes[i*entrySize : (i+1)*entrySize]
		copy(eb[0:16], p.TypeGUID[:])
		copy(eb[16:32], p.UniqueGUID[:])
		binary.LittleEndian.PutUint64(eb[32:40], p.FirstLBA)
		binary.LittleEndian.PutUint64(eb[40:48], p.LastLBA)
		binary.LittleEndian.PutUint64(eb[48:56], p.Attributes)
		u16 := utf16.Encode([]rune(p.Name))
		if len(u16) > 36 {
			u16 = u16[:36]
		}
		for j, c := range u16 {
			binary.LittleEndian.PutUint16(eb[56+j*2:56+j*2+2], c)
		}
	}
	entriesCRC := crc32.ChecksumIEEE(entriesBytes)
	entriesSectors := uint64(len(entriesBytes)) / sec
	if uint64(len(entriesBytes))%sec != 0 {
		entriesSectors++
	}

	diskGUID := newRandomGUID()
	firstUsable := 2 + entriesSectors
	backupEntriesLBA := totalSectors - 1 - entriesSectors
	lastUsable := backupEntriesLBA - 1

	buildHeader := func(myLBA, altLBA, partEntriesLBA uint64) []byte {
		h := make([]byte, sec)
		copy(h[0:8], "EFI PART")
		binary.LittleEndian.PutUint32(h[8:12], 0x00010000) // Revision 1.0
		binary.LittleEndian.PutUint32(h[12:16], 92)        // HeaderSize
		binary.LittleEndian.PutUint64(h[24:32], myLBA)
		binary.LittleEndian.PutUint64(h[32:40], altLBA)
		binary.LittleEndian.PutUint64(h[40:48], firstUsable)
		binary.LittleEndian.PutUint64(h[48:56], lastUsable)
		copy(h[56:72], diskGUID[:])
		binary.LittleEndian.PutUint64(h[72:80], partEntriesLBA)
		binary.LittleEndian.PutUint32(h[80:84], numEntries)
		binary.LittleEndian.PutUint32(h[84:88], entrySize)
		binary.LittleEndian.PutUint32(h[88:92], entriesCRC)
		hdrCRC := crc32.ChecksumIEEE(h[0:92])
		binary.LittleEndian.PutUint32(h[16:20], hdrCRC)
		return h
	}

	primaryHdr := buildHeader(1, totalSectors-1, 2)
	backupHdr := buildHeader(totalSectors-1, 1, backupEntriesLBA)

	// Write LBA 0 + Primary Header + Primary Partition Array
	if err := writeAt(w, 0, mbr); err != nil {
		return err
	}
	if err := writeAt(w, int64(sec), primaryHdr); err != nil {
		return err
	}
	if err := writeAt(w, int64(2*sec), entriesBytes); err != nil {
		return err
	}

	// Write Backup Partition Array + Backup Header
	if err := writeAt(w, int64(backupEntriesLBA*sec), entriesBytes); err != nil {
		return err
	}
	if err := writeAt(w, int64((totalSectors-1)*sec), backupHdr); err != nil {
		return err
	}
	return nil
}

// WipePartitionTables zeroes the leading and trailing regions (up to 1 MiB each)
// of a target disk so stale MBR, Primary GPT, and old Backup GPT structures cannot
// interfere with a freshly flashed image.
func WipePartitionTables(w io.WriteSeeker, diskSize uint64, sectorSize uint32) error {
	if sectorSize == 0 {
		sectorSize = 512
	}
	if diskSize < uint64(sectorSize)*128 {
		return nil
	}
	wipeLen := uint64(1024 * 1024) // 1 MiB covers MBR, GPT up to 2046 sectors, and tail backup GPT
	if wipeLen*2 > diskSize {
		wipeLen = (diskSize / 2 / uint64(sectorSize)) * uint64(sectorSize)
	}
	if wipeLen == 0 {
		return nil
	}
	zeros := make([]byte, wipeLen)
	if err := writeAt(w, 0, zeros); err != nil {
		return fmt.Errorf("wipe leading partition area: %w", err)
	}
	tailOff := int64(diskSize - wipeLen)
	if err := writeAt(w, tailOff, zeros); err != nil {
		return fmt.Errorf("wipe trailing backup GPT area: %w", err)
	}
	if _, err := w.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind after partition wipe: %w", err)
	}
	return nil
}

// RelocateBackupGPT checks whether a raw-flashed disk contains a valid GPT whose
// AlternateLBA does not sit at the physical end of the USB drive (common for hybrid
// Linux ISOs such as Ubuntu 22.04/24.04+). When needed, it relocates the Backup GPT
// header and partition entry array to the end of the disk, updates Primary GPT and
// Protective MBR sizes/CRCs, and clears the stray mid-disk backup header so strict
// UEFI firmwares recognize the EFI System Partition.
func RelocateBackupGPT(rw io.ReadWriteSeeker, diskSize uint64, sectorSize uint32) (bool, error) {
	if sectorSize == 0 {
		sectorSize = 512
	}
	sec := uint64(sectorSize)
	totalSectors := diskSize / sec
	if totalSectors < 128 {
		return false, nil
	}

	mbr := make([]byte, sec)
	if err := readAt(rw, 0, mbr); err != nil {
		return false, fmt.Errorf("read MBR: %w", err)
	}
	hdr := make([]byte, sec)
	if err := readAt(rw, int64(sec), hdr); err != nil {
		return false, fmt.Errorf("read primary GPT header: %w", err)
	}
	if string(hdr[0:8]) != "EFI PART" {
		return false, nil
	}

	hdrSize := binary.LittleEndian.Uint32(hdr[12:16])
	if hdrSize < 92 || uint64(hdrSize) > sec {
		return false, nil
	}

	// Verify primary GPT header CRC32 before modifying anything.
	gotHdrCRC := binary.LittleEndian.Uint32(hdr[16:20])
	hdrCheck := append([]byte(nil), hdr[:hdrSize]...)
	binary.LittleEndian.PutUint32(hdrCheck[16:20], 0)
	if crc32.ChecksumIEEE(hdrCheck) != gotHdrCRC {
		return false, nil
	}

	myLBA := binary.LittleEndian.Uint64(hdr[24:32])
	oldAltLBA := binary.LittleEndian.Uint64(hdr[32:40])
	firstUsable := binary.LittleEndian.Uint64(hdr[40:48])
	oldLastUsable := binary.LittleEndian.Uint64(hdr[48:56])
	partEntriesLBA := binary.LittleEndian.Uint64(hdr[72:80])
	numEntries := binary.LittleEndian.Uint32(hdr[80:84])
	entrySize := binary.LittleEndian.Uint32(hdr[84:88])
	entriesCRC := binary.LittleEndian.Uint32(hdr[88:92])

	if myLBA != 1 || numEntries == 0 || entrySize < 128 {
		return false, nil
	}

	newAltLBA := totalSectors - 1
	if oldAltLBA == newAltLBA {
		return false, nil
	}

	entriesByteLen := uint64(numEntries) * uint64(entrySize)
	if entriesByteLen > 4*1024*1024 {
		return false, nil
	}
	entriesSectors := (entriesByteLen + sec - 1) / sec
	if newAltLBA <= entriesSectors+2 {
		return false, nil
	}
	newBackupEntriesLBA := newAltLBA - entriesSectors
	newLastUsable := newBackupEntriesLBA - 1
	if newLastUsable < oldLastUsable || newBackupEntriesLBA <= firstUsable {
		return false, nil
	}

	// Read and verify the primary partition entry array.
	paddedEntriesLen := entriesSectors * sec
	entriesPadded := make([]byte, paddedEntriesLen)
	if err := readAt(rw, int64(partEntriesLBA*sec), entriesPadded[:entriesByteLen]); err != nil {
		return false, fmt.Errorf("read GPT partition entries: %w", err)
	}
	if crc32.ChecksumIEEE(entriesPadded[:entriesByteLen]) != entriesCRC {
		return false, nil
	}

	var maxPartLastLBA uint64
	for i := uint32(0); i < numEntries; i++ {
		eb := entriesPadded[uint64(i)*uint64(entrySize) : uint64(i+1)*uint64(entrySize)]
		allZero := true
		for _, b := range eb[0:16] {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			continue
		}
		pLast := binary.LittleEndian.Uint64(eb[40:48])
		if pLast > newLastUsable {
			return false, nil
		}
		if pLast > maxPartLastLBA {
			maxPartLastLBA = pLast
		}
	}

	// Build updated Primary GPT header.
	primaryHdr := append([]byte(nil), hdr...)
	binary.LittleEndian.PutUint64(primaryHdr[32:40], newAltLBA)
	binary.LittleEndian.PutUint64(primaryHdr[48:56], newLastUsable)
	binary.LittleEndian.PutUint32(primaryHdr[16:20], 0)
	primaryCRC := crc32.ChecksumIEEE(primaryHdr[:hdrSize])
	binary.LittleEndian.PutUint32(primaryHdr[16:20], primaryCRC)

	// Build Backup GPT header at the physical end of the disk.
	backupHdr := append([]byte(nil), primaryHdr...)
	binary.LittleEndian.PutUint64(backupHdr[24:32], newAltLBA)
	binary.LittleEndian.PutUint64(backupHdr[32:40], 1)
	binary.LittleEndian.PutUint64(backupHdr[72:80], newBackupEntriesLBA)
	binary.LittleEndian.PutUint32(backupHdr[16:20], 0)
	backupCRC := crc32.ChecksumIEEE(backupHdr[:hdrSize])
	binary.LittleEndian.PutUint32(backupHdr[16:20], backupCRC)

	// Update Protective MBR (0xEE starting at LBA 1) sector count if present.
	mbrUpdated := false
	if mbr[510] == 0x55 && mbr[511] == 0xAA {
		pmbrSectors := totalSectors - 1
		if pmbrSectors > 0xFFFFFFFF {
			pmbrSectors = 0xFFFFFFFF
		}
		for p := 0; p < 4; p++ {
			off := 446 + p*16
			partType := mbr[off+4]
			startLBA := binary.LittleEndian.Uint32(mbr[off+8 : off+12])
			if partType == 0xEE && startLBA == 1 {
				binary.LittleEndian.PutUint32(mbr[off+12:off+16], uint32(pmbrSectors))
				mbrUpdated = true
			}
		}
	}

	// Write backup partition entries and backup header at the end of the disk first.
	if err := writeAt(rw, int64(newBackupEntriesLBA*sec), entriesPadded); err != nil {
		return false, fmt.Errorf("write relocated backup GPT entries: %w", err)
	}
	if err := writeAt(rw, int64(newAltLBA*sec), backupHdr); err != nil {
		return false, fmt.Errorf("write relocated backup GPT header: %w", err)
	}
	if err := writeAt(rw, int64(sec), primaryHdr); err != nil {
		return false, fmt.Errorf("write updated primary GPT header: %w", err)
	}
	if mbrUpdated {
		if err := writeAt(rw, 0, mbr); err != nil {
			return false, fmt.Errorf("write updated protective MBR: %w", err)
		}
	}

	// Clear the old mid-disk backup GPT header if it sits safely outside all partitions.
	if oldAltLBA > maxPartLastLBA && oldAltLBA < newBackupEntriesLBA {
		zeroSec := make([]byte, sec)
		_ = writeAt(rw, int64(oldAltLBA*sec), zeroSec)
	}

	return true, nil
}

// NewRandomGUID generates a random RFC 4122 v4 GUID in Microsoft mixed-endian GPT layout.
func NewRandomGUID() [16]byte {
	return newRandomGUID()
}

// FormatGUID formats a mixed-endian GPT GUID as standard lowercase UUID string (for Linux PARTUUID).
func FormatGUID(g [16]byte) string {
	d1 := binary.LittleEndian.Uint32(g[0:4])
	d2 := binary.LittleEndian.Uint16(g[4:6])
	d3 := binary.LittleEndian.Uint16(g[6:8])
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		d1, d2, d3, g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15])
}

// ParseGPTPartitions parses non-empty GPT partition entries from a disk image or hybrid ISO.
func ParseGPTPartitions(r io.ReaderAt, totalSize int64, sectorSize uint32) ([]GPTPartition, error) {
	if sectorSize == 0 {
		sectorSize = 512
	}
	sec := int64(sectorSize)
	if totalSize < sec*4 {
		return nil, fmt.Errorf("image too small for GPT")
	}
	hdr := make([]byte, sec)
	if _, err := r.ReadAt(hdr, sec); err != nil {
		return nil, err
	}
	if string(hdr[0:8]) != "EFI PART" {
		return nil, fmt.Errorf("missing EFI PART signature")
	}
	partEntriesLBA := binary.LittleEndian.Uint64(hdr[72:80])
	numEntries := binary.LittleEndian.Uint32(hdr[80:84])
	entrySize := binary.LittleEndian.Uint32(hdr[84:88])
	if numEntries == 0 || entrySize < 128 || uint64(numEntries)*uint64(entrySize) > 4*1024*1024 {
		return nil, fmt.Errorf("invalid GPT partition array geometry")
	}
	tableOff := int64(partEntriesLBA) * sec
	tableLen := int64(numEntries) * int64(entrySize)
	if tableOff < 0 || tableOff+tableLen > totalSize {
		return nil, fmt.Errorf("GPT partition array exceeds image bounds")
	}
	buf := make([]byte, tableLen)
	if _, err := r.ReadAt(buf, tableOff); err != nil {
		return nil, err
	}
	var out []GPTPartition
	for i := uint32(0); i < numEntries; i++ {
		eb := buf[uint64(i)*uint64(entrySize) : uint64(i+1)*uint64(entrySize)]
		var typeGUID, uniqGUID [16]byte
		copy(typeGUID[:], eb[0:16])
		if typeGUID == ([16]byte{}) {
			continue
		}
		copy(uniqGUID[:], eb[16:32])
		var u16 []uint16
		for j := 0; j < 36; j++ {
			c := binary.LittleEndian.Uint16(eb[56+j*2 : 58+j*2])
			if c == 0 {
				break
			}
			u16 = append(u16, c)
		}
		out = append(out, GPTPartition{
			TypeGUID:   typeGUID,
			UniqueGUID: uniqGUID,
			FirstLBA:   binary.LittleEndian.Uint64(eb[32:40]),
			LastLBA:    binary.LittleEndian.Uint64(eb[40:48]),
			Attributes: binary.LittleEndian.Uint64(eb[48:56]),
			Name:       string(utf16.Decode(u16)),
		})
	}
	return out, nil
}

func readAt(r io.ReadSeeker, offset int64, buf []byte) error {
	if _, err := r.Seek(offset, io.SeekStart); err != nil {
		return err
	}
	_, err := io.ReadFull(r, buf)
	return err
}

func writeAt(w io.WriteSeeker, offset int64, data []byte) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if _, err := w.Seek(offset, io.SeekStart); err != nil {
			lastErr = err
		} else if _, err := w.Write(data); err != nil {
			lastErr = err
		} else {
			return nil
		}
		if attempt < 2 {
			time.Sleep(time.Duration(attempt+1) * 200 * time.Millisecond)
		}
	}
	return lastErr
}

func newRandomGUID() [16]byte {
	var g [16]byte
	_, _ = rand.Read(g[:])
	// Set RFC 4122 version 4 & variant bits (mixed-endian layout).
	g[7] = (g[7] & 0x0F) | 0x40
	g[8] = (g[8] & 0x3F) | 0x80
	return g
}
