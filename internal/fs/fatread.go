// SPDX-License-Identifier: GPL-3.0-only
package fs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"unicode/utf16"
)

type fatType int

const (
	fatType12 fatType = 12
	fatType16 fatType = 16
	fatType32 fatType = 32
)

// FATReader is a pure-Go read-only FAT12/FAT16/FAT32 reader for extracting UEFI
// bootloaders from ISO EFI System Partitions and El Torito EFI boot images.
type FATReader struct {
	r               io.ReaderAt
	size            int64
	kind            fatType
	bytesPerSec     uint32
	secPerClus      uint32
	reservedSecs    uint32
	numFATs         uint32
	rootEntCnt      uint32
	fatSecs         uint32
	rootClus        uint32
	rootDirStartSec uint64
	rootDirSecs     uint64
	dataStartSec    uint64
	clusterBytes    uint32
	totalClusters   uint32
	fatBytes        []byte
}

// FATFileEntry describes a file discovered inside a FAT12/16/32 filesystem.
type FATFileEntry struct {
	Path       string
	Size       uint32
	FirstClus  uint32
	IsDir      bool
}

var ErrNotFAT = errors.New("not a valid FAT12/FAT16/FAT32 filesystem")

// OpenFATReader parses a FAT12, FAT16, or FAT32 image from r.
func OpenFATReader(r io.ReaderAt, size int64) (*FATReader, error) {
	if size < 512 {
		return nil, ErrNotFAT
	}
	bpb := make([]byte, 512)
	if _, err := r.ReadAt(bpb, 0); err != nil {
		return nil, err
	}
	if bpb[510] != 0x55 || bpb[511] != 0xAA {
		return nil, ErrNotFAT
	}

	bytesPerSec := uint32(binary.LittleEndian.Uint16(bpb[11:13]))
	secPerClus := uint32(bpb[13])
	reservedSecs := uint32(binary.LittleEndian.Uint16(bpb[14:16]))
	numFATs := uint32(bpb[16])
	rootEntCnt := uint32(binary.LittleEndian.Uint16(bpb[17:19]))
	totSec16 := uint32(binary.LittleEndian.Uint16(bpb[19:21]))
	fatSz16 := uint32(binary.LittleEndian.Uint16(bpb[22:24]))
	totSec32 := binary.LittleEndian.Uint32(bpb[32:36])
	fatSz32 := binary.LittleEndian.Uint32(bpb[36:40])
	rootClus := binary.LittleEndian.Uint32(bpb[44:48])

	if bytesPerSec != 512 && bytesPerSec != 1024 && bytesPerSec != 2048 && bytesPerSec != 4096 {
		return nil, ErrNotFAT
	}
	if secPerClus == 0 || (secPerClus&(secPerClus-1)) != 0 || reservedSecs == 0 || numFATs == 0 {
		return nil, ErrNotFAT
	}

	totSec := totSec16
	if totSec == 0 {
		totSec = totSec32
	}
	fatSecs := fatSz16
	if fatSecs == 0 {
		fatSecs = fatSz32
	}
	if totSec == 0 || fatSecs == 0 {
		return nil, ErrNotFAT
	}

	rootDirSecs := ((uint64(rootEntCnt) * 32) + uint64(bytesPerSec) - 1) / uint64(bytesPerSec)
	rootDirStartSec := uint64(reservedSecs) + uint64(numFATs)*uint64(fatSecs)
	dataStartSec := rootDirStartSec + rootDirSecs
	if uint64(totSec) <= dataStartSec {
		return nil, ErrNotFAT
	}
	dataSecs := uint64(totSec) - dataStartSec
	totalClusters := uint32(dataSecs / uint64(secPerClus))

	var kind fatType
	switch {
	case totalClusters < 4085:
		kind = fatType12
	case totalClusters < 65525:
		kind = fatType16
	default:
		kind = fatType32
	}

	fatByteLen := int64(fatSecs) * int64(bytesPerSec)
	fatOff := int64(reservedSecs) * int64(bytesPerSec)
	if fatByteLen <= 0 || fatByteLen > 32*1024*1024 || fatOff+fatByteLen > size {
		return nil, ErrNotFAT
	}
	fatBytes := make([]byte, fatByteLen)
	if _, err := r.ReadAt(fatBytes, fatOff); err != nil {
		return nil, err
	}

	return &FATReader{
		r:               r,
		size:            size,
		kind:            kind,
		bytesPerSec:     bytesPerSec,
		secPerClus:      secPerClus,
		reservedSecs:    reservedSecs,
		numFATs:         numFATs,
		rootEntCnt:      rootEntCnt,
		fatSecs:         fatSecs,
		rootClus:        rootClus,
		rootDirStartSec: rootDirStartSec,
		rootDirSecs:     rootDirSecs,
		dataStartSec:    dataStartSec,
		clusterBytes:    bytesPerSec * secPerClus,
		totalClusters:   totalClusters,
		fatBytes:        fatBytes,
	}, nil
}

// ReadAllFiles walks the entire FAT filesystem and returns a map of relative paths to file contents.
// Files exceeding maxFileBytes are skipped to keep memory bounded.
func (f *FATReader) ReadAllFiles(maxFileBytes uint32) (map[string][]byte, error) {
	out := make(map[string][]byte)
	var rootData []byte
	var err error
	if f.kind == fatType32 {
		rootData, err = f.readClusterChain(f.rootClus, 0)
	} else {
		rootLen := f.rootDirSecs * uint64(f.bytesPerSec)
		rootData = make([]byte, rootLen)
		_, err = f.r.ReadAt(rootData, int64(f.rootDirStartSec*uint64(f.bytesPerSec)))
	}
	if err != nil {
		return nil, err
	}
	if err := f.walkDirData(rootData, "", 0, maxFileBytes, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (f *FATReader) walkDirData(dirData []byte, prefix string, depth int, maxFileBytes uint32, out map[string][]byte) error {
	if depth > 32 {
		return nil
	}
	var lfnParts []string
	for off := 0; off+32 <= len(dirData); off += 32 {
		rec := dirData[off : off+32]
		first := rec[0]
		if first == 0x00 {
			break
		}
		if first == 0xE5 {
			lfnParts = nil
			continue
		}
		attr := rec[11]
		if (attr & 0x3F) == 0x0F { // VFAT Long File Name entry
			lfnParts = append(lfnParts, decodeLFNChunk(rec))
			continue
		}
		if (attr & 0x08) != 0 { // Volume label
			lfnParts = nil
			continue
		}

		var name string
		if len(lfnParts) > 0 {
			// LFN entries appear in reverse order before the short 8.3 entry.
			var b strings.Builder
			for i := len(lfnParts) - 1; i >= 0; i-- {
				b.WriteString(lfnParts[i])
			}
			name = strings.TrimRight(b.String(), "\x00")
			lfnParts = nil
		} else {
			name = decodeShortName(rec[0:11])
		}
		if name == "" || name == "." || name == ".." {
			continue
		}

		rel := name
		if prefix != "" {
			rel = path.Join(prefix, name)
		}

		clusHi := uint32(binary.LittleEndian.Uint16(rec[20:22]))
		clusLo := uint32(binary.LittleEndian.Uint16(rec[26:28]))
		firstClus := clusLo
		if f.kind == fatType32 {
			firstClus |= clusHi << 16
		}
		fileSize := binary.LittleEndian.Uint32(rec[28:32])

		if (attr & 0x10) != 0 {
			if firstClus >= 2 {
				subData, err := f.readClusterChain(firstClus, 0)
				if err == nil {
					_ = f.walkDirData(subData, rel, depth+1, maxFileBytes, out)
				}
			}
			continue
		}

		if maxFileBytes > 0 && fileSize > maxFileBytes {
			continue
		}
		if fileSize == 0 {
			out[rel] = []byte{}
			continue
		}
		data, err := f.readClusterChain(firstClus, fileSize)
		if err != nil {
			continue
		}
		out[rel] = data
	}
	return nil
}

func (f *FATReader) nextCluster(c uint32) (uint32, bool) {
	switch f.kind {
	case fatType12:
		off := c + (c / 2)
		if int(off+1) >= len(f.fatBytes) {
			return 0, false
		}
		val := uint32(binary.LittleEndian.Uint16(f.fatBytes[off : off+2]))
		if (c & 1) == 1 {
			val >>= 4
		} else {
			val &= 0x0FFF
		}
		if val < 2 || val >= 0x0FF8 {
			return 0, false
		}
		return val, true
	case fatType16:
		off := c * 2
		if int(off+2) > len(f.fatBytes) {
			return 0, false
		}
		val := uint32(binary.LittleEndian.Uint16(f.fatBytes[off : off+2]))
		if val < 2 || val >= 0xFFF8 {
			return 0, false
		}
		return val, true
	default: // fatType32
		off := c * 4
		if int(off+4) > len(f.fatBytes) {
			return 0, false
		}
		val := binary.LittleEndian.Uint32(f.fatBytes[off:off+4]) & 0x0FFFFFFF
		if val < 2 || val >= 0x0FFFFFF8 {
			return 0, false
		}
		return val, true
	}
}

func (f *FATReader) readClusterChain(start uint32, exactSize uint32) ([]byte, error) {
	if start < 2 {
		return nil, fmt.Errorf("invalid FAT start cluster %d", start)
	}
	var out []byte
	if exactSize > 0 {
		out = make([]byte, 0, exactSize)
	}
	buf := make([]byte, f.clusterBytes)
	seen := make(map[uint32]bool)
	c := start
	for steps := 0; steps < 65536; steps++ {
		if c < 2 || seen[c] {
			break
		}
		seen[c] = true
		lba := f.dataStartSec + uint64(c-2)*uint64(f.secPerClus)
		off := int64(lba) * int64(f.bytesPerSec)
		if off < 0 || off+int64(len(buf)) > f.size {
			break
		}
		if _, err := f.r.ReadAt(buf, off); err != nil {
			return nil, err
		}
		out = append(out, buf...)
		if exactSize > 0 && uint32(len(out)) >= exactSize {
			return out[:exactSize], nil
		}
		next, ok := f.nextCluster(c)
		if !ok {
			break
		}
		c = next
	}
	if exactSize > 0 && uint32(len(out)) > exactSize {
		out = out[:exactSize]
	}
	return out, nil
}

func decodeShortName(raw []byte) string {
	base := strings.TrimRight(string(raw[0:8]), " ")
	ext := strings.TrimRight(string(raw[8:11]), " ")
	if ext != "" {
		return base + "." + ext
	}
	return base
}

func decodeLFNChunk(rec []byte) string {
	var u16 []uint16
	readSlots := func(start, count int) {
		for i := 0; i < count; i++ {
			v := binary.LittleEndian.Uint16(rec[start+i*2 : start+i*2+2])
			if v == 0x0000 || v == 0xFFFF {
				return
			}
			u16 = append(u16, v)
		}
	}
	readSlots(1, 5)
	readSlots(14, 6)
	readSlots(28, 2)
	return string(utf16.Decode(u16))
}
