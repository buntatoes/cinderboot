// SPDX-License-Identifier: GPL-3.0-only
package fs

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"path"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	fat32EOC       uint32 = 0x0FFFFFFF
	fat32Free      uint32 = 0x00000000
	fat32AttrRO    byte   = 0x01
	fat32AttrVolID byte   = 0x08
	fat32AttrDir   byte   = 0x10
	fat32AttrArch  byte   = 0x20
	fat32AttrLFN   byte   = 0x0F
)

// FAT32Writer is our pure-Go FAT32 filesystem formatter and streaming file writer.
// It formats a partition region directly on any io.ReadWriteSeeker (USB device or disk image)
// and writes nested directories and VFAT long-filename files with zero external tools.
type FAT32Writer struct {
	w               io.ReadWriteSeeker
	partOffset      int64
	partSize        uint64
	sectorSize      uint32
	secPerClus      uint32
	reservedSectors uint32
	numFATs         uint32
	fatSectors      uint32
	totalSectors    uint32
	totalClusters   uint32
	dataStartLBA    uint64
	clusterBytes    uint32
	volumeLabel     string
	volumeSerial    uint32

	fat           []uint32
	nextFreeClus  uint32
	freeClusCount uint32

	dirs map[string]*fatDirState
}

type fatDirState struct {
	clusters    []uint32
	data        []byte
	usedEntries int
	usedSFNs    map[string]bool
	dirty       bool
}

// FormatFAT32 initializes a Microsoft-spec compliant FAT32 filesystem in [partOffset, partOffset+partSize).
func FormatFAT32(w io.ReadWriteSeeker, partOffset int64, partSize uint64, sectorSize uint32, volumeLabel string) (*FAT32Writer, error) {
	if sectorSize == 0 {
		sectorSize = 512
	}
	if sectorSize != 512 {
		return nil, fmt.Errorf("unsupported sector size for FAT32: %d", sectorSize)
	}
	totalSectors64 := partSize / uint64(sectorSize)
	if totalSectors64 < 66600 {
		return nil, fmt.Errorf("partition too small for FAT32 (%d MiB; minimum ~34 MiB)", partSize/(1024*1024))
	}
	if totalSectors64 > 0xFFFFFFFF {
		totalSectors64 = 0xFFFFFFFF
	}

	secPerClus := chooseSectorsPerCluster(partSize)
	const reservedSectors uint32 = 32
	const numFATs uint32 = 2

	// Adjust sectors-per-cluster downward if cluster count would fall below FAT32's 65525 threshold.
	var fatSectors, totalClusters uint32
	for {
		fatSectors, totalClusters = computeFAT32Geometry(uint32(totalSectors64), reservedSectors, numFATs, secPerClus, sectorSize)
		if totalClusters >= 65525 || secPerClus == 1 {
			break
		}
		secPerClus /= 2
	}
	if totalClusters < 65525 {
		return nil, fmt.Errorf("cannot form valid FAT32 cluster count (%d < 65525)", totalClusters)
	}

	var serBytes [4]byte
	_, _ = rand.Read(serBytes[:])

	fw := &FAT32Writer{
		w:               w,
		partOffset:      partOffset,
		partSize:        partSize,
		sectorSize:      sectorSize,
		secPerClus:      secPerClus,
		reservedSectors: reservedSectors,
		numFATs:         numFATs,
		fatSectors:      fatSectors,
		totalSectors:    uint32(totalSectors64),
		totalClusters:   totalClusters,
		dataStartLBA:    uint64(reservedSectors) + uint64(numFATs)*uint64(fatSectors),
		clusterBytes:    secPerClus * sectorSize,
		volumeLabel:     sanitizeVolumeLabel(volumeLabel),
		volumeSerial:    binary.LittleEndian.Uint32(serBytes[:]),
		fat:             make([]uint32, totalClusters+2),
		nextFreeClus:    3,
		freeClusCount:   totalClusters - 1, // cluster 2 allocated for root dir
		dirs:            make(map[string]*fatDirState),
	}

	// Initialize reserved FAT entries 0, 1, and root cluster 2.
	fw.fat[0] = 0x0FFFFFF8
	fw.fat[1] = 0x0FFFFFFF
	fw.fat[2] = fat32EOC

	// Zero the reserved area (32 sectors) so stale signatures are cleared.
	zeroRes := make([]byte, int(reservedSectors)*int(sectorSize))
	if err := writeAt(fw.w, fw.partOffset, zeroRes); err != nil {
		return nil, fmt.Errorf("zero FAT32 reserved region: %w", err)
	}

	// Create in-memory root directory state (cluster 2) with a volume label entry.
	root := &fatDirState{
		clusters: []uint32{2},
		data:     make([]byte, fw.clusterBytes),
		usedSFNs: make(map[string]bool),
		dirty:    true,
	}
	if fw.volumeLabel != "" {
		var volEnt [32]byte
		copy(volEnt[0:11], pad11(fw.volumeLabel))
		volEnt[11] = fat32AttrVolID
		dDate, dTime := dosDateTime(time.Now())
		binary.LittleEndian.PutUint16(volEnt[22:24], dTime)
		binary.LittleEndian.PutUint16(volEnt[24:26], dDate)
		copy(root.data[0:32], volEnt[:])
		root.usedEntries = 1
	}
	fw.dirs[""] = root

	return fw, nil
}

// MkdirAll creates a directory path (e.g., "efi/boot" or "sources") inside the FAT32 volume.
func (f *FAT32Writer) MkdirAll(relPath string) error {
	clean := cleanFATPath(relPath)
	if clean == "" {
		return nil
	}
	if _, ok := f.dirs[clean]; ok {
		return nil
	}

	parts := strings.Split(clean, "/")
	cur := ""
	for _, seg := range parts {
		parent := cur
		if cur == "" {
			cur = seg
		} else {
			cur = cur + "/" + seg
		}
		if _, exists := f.dirs[cur]; exists {
			continue
		}
		parentDir := f.dirs[parent]
		clus, err := f.allocCluster()
		if err != nil {
			return err
		}

		// Initialize "." and ".." entries in new directory cluster.
		dirBuf := make([]byte, f.clusterBytes)
		dDate, dTime := dosDateTime(time.Now())
		parentClus := parentDir.clusters[0]
		if parent == "" {
			parentClus = 0 // FAT32 spec: ".." pointing to root uses cluster 0
		}
		writeDotEntry(dirBuf[0:32], ".", clus, dDate, dTime)
		writeDotEntry(dirBuf[32:64], "..", parentClus, dDate, dTime)

		if err := f.addDirEntry(parentDir, seg, fat32AttrDir, clus, 0); err != nil {
			return err
		}
		f.dirs[cur] = &fatDirState{
			clusters:    []uint32{clus},
			data:        dirBuf,
			usedEntries: 2,
			usedSFNs:    make(map[string]bool),
			dirty:       true,
		}
	}
	return nil
}

// WriteFile streams a file of known size into the FAT32 filesystem at relPath.
// Parent directories are created automatically.
func (f *FAT32Writer) WriteFile(relPath string, r io.Reader, size uint64, onChunk func(int)) error {
	if size > 0xFFFFFFFF {
		return fmt.Errorf("file %q exceeds FAT32 4 GiB limit (%d bytes)", relPath, size)
	}
	clean := cleanFATPath(relPath)
	if clean == "" {
		return fmt.Errorf("empty file path")
	}

	parentPath := ""
	fileName := clean
	if idx := strings.LastIndexByte(clean, '/'); idx >= 0 {
		parentPath = clean[:idx]
		fileName = clean[idx+1:]
	}
	if parentPath != "" {
		if err := f.MkdirAll(parentPath); err != nil {
			return err
		}
	}
	parentDir := f.dirs[parentPath]

	var firstClus uint32
	if size > 0 {
		numClus := uint32((size + uint64(f.clusterBytes) - 1) / uint64(f.clusterBytes))
		chain, err := f.allocChain(numClus)
		if err != nil {
			return fmt.Errorf("allocate %d clusters for %q: %w", numClus, clean, err)
		}
		firstClus = chain[0]

		// Write contiguous cluster runs in ~1 MiB chunks for fast sequential USB I/O.
		bufClus := uint32(1024*1024) / f.clusterBytes
		if bufClus == 0 {
			bufClus = 1
		}
		buf := make([]byte, bufClus*f.clusterBytes)

		remaining := size
		idx := 0
		for idx < len(chain) {
			// Measure contiguous run starting at chain[idx]
			runLen := 1
			for idx+runLen < len(chain) &&
				uint32(runLen) < bufClus &&
				chain[idx+runLen] == chain[idx+runLen-1]+1 {
				runLen++
			}
			runBytes := uint64(runLen) * uint64(f.clusterBytes)
			toRead := runBytes
			if toRead > remaining {
				toRead = remaining
			}

			slice := buf[:runBytes]
			if toRead > 0 {
				if _, err := io.ReadFull(r, slice[:toRead]); err != nil {
					return fmt.Errorf("read source data for %q: %w", clean, err)
				}
			}
			if toRead < runBytes {
				clear(slice[toRead:])
			}
			if err := writeAt(f.w, f.clusterOffset(chain[idx]), slice); err != nil {
				return fmt.Errorf("write clusters for %q: %w", clean, err)
			}
			if onChunk != nil && toRead > 0 {
				onChunk(int(toRead))
			}
			remaining -= toRead
			idx += runLen
		}
	}

	return f.addDirEntry(parentDir, fileName, fat32AttrArch, firstClus, uint32(size))
}

// WriteBytes writes a small in-memory byte slice to relPath.
func (f *FAT32Writer) WriteBytes(relPath string, data []byte) error {
	return f.WriteFile(relPath, strings.NewReader(string(data)), uint64(len(data)), nil)
}

// Close flushes all directory clusters, FAT1, FAT2, FSInfo, Boot Sector, and Backup Boot Sector.
func (f *FAT32Writer) Close() error {
	// 1. Flush every modified directory's cluster chain.
	for _, d := range f.dirs {
		if !d.dirty {
			continue
		}
		for i, clus := range d.clusters {
			start := i * int(f.clusterBytes)
			end := start + int(f.clusterBytes)
			if err := writeAt(f.w, f.clusterOffset(clus), d.data[start:end]); err != nil {
				return fmt.Errorf("flush FAT32 directory cluster %d: %w", clus, err)
			}
		}
		d.dirty = false
	}

	// 2. Write FAT1 and FAT2 in 1 MiB buffered chunks.
	fatByteLen := int(f.fatSectors) * int(f.sectorSize)
	fatBuf := make([]byte, fatByteLen)
	for i, val := range f.fat {
		if i*4+4 > len(fatBuf) {
			break
		}
		binary.LittleEndian.PutUint32(fatBuf[i*4:i*4+4], val)
	}
	for fatIdx := uint32(0); fatIdx < f.numFATs; fatIdx++ {
		off := f.partOffset + int64(f.reservedSectors+fatIdx*f.fatSectors)*int64(f.sectorSize)
		if err := writeAt(f.w, off, fatBuf); err != nil {
			return fmt.Errorf("write FAT%d: %w", fatIdx+1, err)
		}
	}

	// 3. Write Boot Sector (sector 0 + backup sector 6) and FSInfo (sector 1 + backup sector 7).
	boot := f.buildBootSector()
	fsInfo := f.buildFSInfoSector()
	if err := writeAt(f.w, f.partOffset, boot); err != nil {
		return err
	}
	if err := writeAt(f.w, f.partOffset+int64(f.sectorSize), fsInfo); err != nil {
		return err
	}
	if err := writeAt(f.w, f.partOffset+6*int64(f.sectorSize), boot); err != nil {
		return err
	}
	if err := writeAt(f.w, f.partOffset+7*int64(f.sectorSize), fsInfo); err != nil {
		return err
	}
	return nil
}

func (f *FAT32Writer) clusterOffset(clus uint32) int64 {
	lba := f.dataStartLBA + uint64(clus-2)*uint64(f.secPerClus)
	return f.partOffset + int64(lba)*int64(f.sectorSize)
}

func (f *FAT32Writer) allocCluster() (uint32, error) {
	if f.freeClusCount == 0 || f.nextFreeClus >= uint32(len(f.fat)) {
		return 0, fmt.Errorf("FAT32 volume out of free space")
	}
	c := f.nextFreeClus
	f.fat[c] = fat32EOC
	f.nextFreeClus++
	f.freeClusCount--
	return c, nil
}

func (f *FAT32Writer) allocChain(count uint32) ([]uint32, error) {
	if count == 0 {
		return nil, nil
	}
	if count > f.freeClusCount {
		return nil, fmt.Errorf("FAT32 volume out of space (need %d clusters, have %d)", count, f.freeClusCount)
	}
	chain := make([]uint32, count)
	for i := uint32(0); i < count; i++ {
		c := f.nextFreeClus
		f.nextFreeClus++
		chain[i] = c
	}
	for i := uint32(0); i+1 < count; i++ {
		f.fat[chain[i]] = chain[i+1]
	}
	f.fat[chain[count-1]] = fat32EOC
	f.freeClusCount -= count
	return chain, nil
}

func (f *FAT32Writer) addDirEntry(dir *fatDirState, name string, attr byte, firstClus, fileSize uint32) error {
	sfn, needsLFN := makeUniqueSFN(name, dir.usedSFNs)
	dir.usedSFNs[string(sfn[:])] = true

	var records [][32]byte
	if needsLFN {
		lfnRecs := buildLFNEntries(name, sfnChecksum(sfn))
		records = append(records, lfnRecs...)
	}

	var shortRec [32]byte
	copy(shortRec[0:11], sfn[:])
	shortRec[11] = attr
	dDate, dTime := dosDateTime(time.Now())
	binary.LittleEndian.PutUint16(shortRec[14:16], dTime)
	binary.LittleEndian.PutUint16(shortRec[16:18], dDate)
	binary.LittleEndian.PutUint16(shortRec[18:20], dDate)
	binary.LittleEndian.PutUint16(shortRec[20:22], uint16(firstClus>>16))
	binary.LittleEndian.PutUint16(shortRec[22:24], dTime)
	binary.LittleEndian.PutUint16(shortRec[24:26], dDate)
	binary.LittleEndian.PutUint16(shortRec[26:28], uint16(firstClus&0xFFFF))
	binary.LittleEndian.PutUint32(shortRec[28:32], fileSize)
	records = append(records, shortRec)

	// Grow directory cluster chain if needed.
	entriesPerClus := int(f.clusterBytes) / 32
	for dir.usedEntries+len(records) > len(dir.clusters)*entriesPerClus {
		newClus, err := f.allocCluster()
		if err != nil {
			return err
		}
		last := dir.clusters[len(dir.clusters)-1]
		f.fat[last] = newClus
		dir.clusters = append(dir.clusters, newClus)
		dir.data = append(dir.data, make([]byte, f.clusterBytes)...)
	}

	for _, rec := range records {
		off := dir.usedEntries * 32
		copy(dir.data[off:off+32], rec[:])
		dir.usedEntries++
	}
	dir.dirty = true
	return nil
}

func (f *FAT32Writer) buildBootSector() []byte {
	b := make([]byte, f.sectorSize)
	b[0] = 0xEB
	b[1] = 0x58
	b[2] = 0x90
	copy(b[3:11], "MSWIN4.1")
	binary.LittleEndian.PutUint16(b[11:13], uint16(f.sectorSize))
	b[13] = byte(f.secPerClus)
	binary.LittleEndian.PutUint16(b[14:16], uint16(f.reservedSectors))
	b[16] = byte(f.numFATs)
	b[21] = 0xF8 // Fixed / hard media descriptor
	binary.LittleEndian.PutUint16(b[24:26], 63)
	binary.LittleEndian.PutUint16(b[26:28], 255)
	binary.LittleEndian.PutUint32(b[28:32], uint32(f.partOffset/int64(f.sectorSize)))
	binary.LittleEndian.PutUint32(b[32:36], f.totalSectors)
	binary.LittleEndian.PutUint32(b[36:40], f.fatSectors)
	binary.LittleEndian.PutUint32(b[44:48], 2) // Root cluster = 2
	binary.LittleEndian.PutUint16(b[48:50], 1) // FSInfo sector = 1
	binary.LittleEndian.PutUint16(b[50:52], 6) // Backup boot sector = 6
	b[64] = 0x80
	b[66] = 0x29
	binary.LittleEndian.PutUint32(b[67:71], f.volumeSerial)
	copy(b[71:82], pad11(f.volumeLabel))
	copy(b[82:90], "FAT32   ")
	b[510] = 0x55
	b[511] = 0xAA
	return b
}

func (f *FAT32Writer) buildFSInfoSector() []byte {
	b := make([]byte, f.sectorSize)
	binary.LittleEndian.PutUint32(b[0:4], 0x41615252)
	binary.LittleEndian.PutUint32(b[484:488], 0x61417272)
	binary.LittleEndian.PutUint32(b[488:492], f.freeClusCount)
	binary.LittleEndian.PutUint32(b[492:496], f.nextFreeClus)
	binary.LittleEndian.PutUint32(b[508:512], 0xAA550000)
	return b
}

func chooseSectorsPerCluster(partSize uint64) uint32 {
	const gib = uint64(1024 * 1024 * 1024)
	switch {
	case partSize <= 260*1024*1024:
		return 1
	case partSize <= 8*gib:
		return 8 // 4 KiB
	case partSize <= 16*gib:
		return 16 // 8 KiB
	case partSize <= 32*gib:
		return 32 // 16 KiB
	default:
		return 64 // 32 KiB
	}
}

func computeFAT32Geometry(totalSectors, reserved, numFATs, secPerClus, sectorSize uint32) (fatSectors, totalClusters uint32) {
	// Microsoft FAT32 formula
	tmpVal1 := uint64(totalSectors - reserved)
	tmpVal2 := uint64(256*secPerClus+numFATs) / 2
	fatSectors = uint32((tmpVal1 + tmpVal2 - 1) / tmpVal2)
	for iter := 0; iter < 4; iter++ {
		dataSectors := uint64(totalSectors) - uint64(reserved) - uint64(numFATs)*uint64(fatSectors)
		totalClusters = uint32(dataSectors / uint64(secPerClus))
		neededBytes := uint64(totalClusters+2) * 4
		neededSectors := uint32((neededBytes + uint64(sectorSize) - 1) / uint64(sectorSize))
		if neededSectors == fatSectors {
			break
		}
		fatSectors = neededSectors
	}
	dataSectors := uint64(totalSectors) - uint64(reserved) - uint64(numFATs)*uint64(fatSectors)
	totalClusters = uint32(dataSectors / uint64(secPerClus))
	return fatSectors, totalClusters
}

func writeDotEntry(dst []byte, name string, clus uint32, dDate, dTime uint16) {
	copy(dst[0:11], pad11(name))
	dst[11] = fat32AttrDir
	binary.LittleEndian.PutUint16(dst[14:16], dTime)
	binary.LittleEndian.PutUint16(dst[16:18], dDate)
	binary.LittleEndian.PutUint16(dst[18:20], dDate)
	binary.LittleEndian.PutUint16(dst[20:22], uint16(clus>>16))
	binary.LittleEndian.PutUint16(dst[22:24], dTime)
	binary.LittleEndian.PutUint16(dst[24:26], dDate)
	binary.LittleEndian.PutUint16(dst[26:28], uint16(clus&0xFFFF))
}

func makeUniqueSFN(name string, used map[string]bool) ([11]byte, bool) {
	var out [11]byte
	for i := range out {
		out[i] = ' '
	}

	upper := strings.ToUpper(name)
	// Fast check for pure 8.3 uppercase ASCII name that needs no LFN
	if isPure83(name) {
		base, ext := splitBaseExt(upper)
		copy(out[0:8], base)
		copy(out[8:11], ext)
		if !used[string(out[:])] {
			return out, false
		}
	}

	// Build sanitized 8.3 basis with ~N numeric tail and emit LFN entries.
	baseRaw, extRaw := splitBaseExt(upper)
	base := filterSFNChars(baseRaw)
	ext := filterSFNChars(extRaw)
	if len(ext) > 3 {
		ext = ext[:3]
	}
	if base == "" {
		base = "FILE"
	}

	for n := 1; n < 999999; n++ {
		tail := fmt.Sprintf("~%d", n)
		maxBase := 8 - len(tail)
		b := base
		if len(b) > maxBase {
			b = b[:maxBase]
		}
		for i := range out {
			out[i] = ' '
		}
		copy(out[0:8], b+tail)
		copy(out[8:11], ext)
		if !used[string(out[:])] {
			return out, true
		}
	}
	return out, true
}

func isPure83(name string) bool {
	if name == "" || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
		return false
	}
	if strings.Count(name, ".") > 1 {
		return false
	}
	base, ext := splitBaseExt(name)
	if len(base) == 0 || len(base) > 8 || len(ext) > 3 {
		return false
	}
	for _, r := range name {
		if r == '.' {
			continue
		}
		if r > 127 || (r >= 'a' && r <= 'z') || !isValidSFNChar(byte(r)) {
			return false
		}
	}
	return true
}

func splitBaseExt(name string) (string, string) {
	trimmed := strings.TrimLeft(name, ".")
	if idx := strings.LastIndexByte(trimmed, '.'); idx >= 0 {
		return trimmed[:idx], trimmed[idx+1:]
	}
	return trimmed, ""
}

func filterSFNChars(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isValidSFNChar(c) {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func isValidSFNChar(c byte) bool {
	if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
		return true
	}
	switch c {
	case '$', '%', '\'', '-', '_', '@', '~', '`', '!', '(', ')', '{', '}', '^', '#', '&':
		return true
	}
	return false
}

func sfnChecksum(sfn [11]byte) byte {
	var sum byte
	for _, c := range sfn {
		sum = ((sum & 1) << 7) + (sum >> 1) + c
	}
	return sum
}

func buildLFNEntries(name string, checksum byte) [][32]byte {
	u16 := utf16.Encode([]rune(name))
	numEntries := (len(u16) + 12) / 13
	if numEntries == 0 {
		numEntries = 1
	}
	out := make([][32]byte, numEntries)

	for seq := 1; seq <= numEntries; seq++ {
		var rec [32]byte
		ord := byte(seq)
		if seq == numEntries {
			ord |= 0x40
		}
		rec[0] = ord
		rec[11] = fat32AttrLFN
		rec[13] = checksum

		start := (seq - 1) * 13
		var chars [13]uint16
		for j := 0; j < 13; j++ {
			idx := start + j
			switch {
			case idx < len(u16):
				chars[j] = u16[idx]
			case idx == len(u16):
				chars[j] = 0x0000
			default:
				chars[j] = 0xFFFF
			}
		}

		// LFN character slot offsets: [1..10] (5 chars), [14..25] (6 chars), [28..31] (2 chars)
		for j := 0; j < 5; j++ {
			binary.LittleEndian.PutUint16(rec[1+j*2:3+j*2], chars[j])
		}
		for j := 0; j < 6; j++ {
			binary.LittleEndian.PutUint16(rec[14+j*2:16+j*2], chars[5+j])
		}
		for j := 0; j < 2; j++ {
			binary.LittleEndian.PutUint16(rec[28+j*2:30+j*2], chars[11+j])
		}

		// LFN entries are stored on disk in reverse order (last chunk first).
		out[numEntries-seq] = rec
	}
	return out
}

func sanitizeVolumeLabel(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < 11; i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == ' ' {
			b.WriteByte(c)
		}
	}
	res := strings.TrimSpace(b.String())
	if res == "" {
		return "CINDERBOOT"
	}
	return res
}

func pad11(s string) []byte {
	out := []byte("           ")
	copy(out, s)
	return out
}

func cleanFATPath(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	p = strings.TrimPrefix(p, "/")
	p = path.Clean(p)
	if p == "." || p == "/" {
		return ""
	}
	return p
}

func dosDateTime(t time.Time) (uint16, uint16) {
	y := t.Year()
	if y < 1980 {
		y = 1980
	}
	if y > 2107 {
		y = 2107
	}
	dDate := uint16((y-1980)<<9) | uint16(t.Month()<<5) | uint16(t.Day())
	dTime := uint16(t.Hour()<<11) | uint16(t.Minute()<<5) | uint16(t.Second()/2)
	return dDate, dTime
}
