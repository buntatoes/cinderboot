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
