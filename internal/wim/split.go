// SPDX-License-Identifier: GPL-3.0-only
package wim

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	wimHeaderSize   = 208
	wimResEntrySize = 50

	// DefaultMaxPartSize is 3800 MiB — comfortably below FAT32's 4 GiB - 1 byte limit.
	DefaultMaxPartSize uint64 = 3800 * 1024 * 1024

	flagHeaderSpanned uint32 = 0x00000008

	resFlagMetadata byte = 0x02

	wimVersionSolid uint32 = 0x00000E00
)

var (
	wimMagic      = []byte{'M', 'S', 'W', 'I', 'M', 0, 0, 0}
	ErrInvalidWIM = errors.New("not a valid Microsoft WIM archive")
	ErrSolidESD   = errors.New("solid ESD archive exceeds 4 GiB and cannot be losslessly split without recompression")
)

type resHdrShort struct {
	size         uint64 // 56-bit
	flags        byte
	offset       uint64
	originalSize uint64
}

type lookupEntry struct {
	res        resHdrShort
	partNumber uint16
	refCount   uint32
	hash       [20]byte
}

type wimHeader struct {
	raw             [wimHeaderSize]byte
	version         uint32
	flags           uint32
	compressionSize uint32
	guid            [16]byte
	partNumber      uint16
	totalParts      uint16
	imageCount      uint32
	offsetTable     resHdrShort
	xmlData         resHdrShort
	bootMetadata    resHdrShort
	bootIndex       uint32
	integrity       resHdrShort
}

func parseResHdrShort(b []byte) resHdrShort {
	var sz uint64
	for i := 0; i < 7; i++ {
		sz |= uint64(b[i]) << (8 * uint(i))
	}
	return resHdrShort{
		size:         sz,
		flags:        b[7],
		offset:       binary.LittleEndian.Uint64(b[8:16]),
		originalSize: binary.LittleEndian.Uint64(b[16:24]),
	}
}

func encodeResHdrShort(b []byte, r resHdrShort) {
	for i := 0; i < 7; i++ {
		b[i] = byte(r.size >> (8 * uint(i)))
	}
	b[7] = r.flags
	binary.LittleEndian.PutUint64(b[8:16], r.offset)
	binary.LittleEndian.PutUint64(b[16:24], r.originalSize)
}

func parseHeader(r io.ReaderAt) (wimHeader, error) {
	var h wimHeader
	if _, err := r.ReadAt(h.raw[:], 0); err != nil {
		return h, fmt.Errorf("%w: %v", ErrInvalidWIM, err)
	}
	if !bytes.Equal(h.raw[0:8], wimMagic) {
		return h, ErrInvalidWIM
	}
	cbSize := binary.LittleEndian.Uint32(h.raw[8:12])
	if cbSize < wimHeaderSize {
		return h, fmt.Errorf("%w: header size %d", ErrInvalidWIM, cbSize)
	}
	h.version = binary.LittleEndian.Uint32(h.raw[12:16])
	h.flags = binary.LittleEndian.Uint32(h.raw[16:20])
	h.compressionSize = binary.LittleEndian.Uint32(h.raw[20:24])
	copy(h.guid[:], h.raw[24:40])
	h.partNumber = binary.LittleEndian.Uint16(h.raw[40:42])
	h.totalParts = binary.LittleEndian.Uint16(h.raw[42:44])
	h.imageCount = binary.LittleEndian.Uint32(h.raw[44:48])
	h.offsetTable = parseResHdrShort(h.raw[48:72])
	h.xmlData = parseResHdrShort(h.raw[72:96])
	h.bootMetadata = parseResHdrShort(h.raw[96:120])
	h.bootIndex = binary.LittleEndian.Uint32(h.raw[120:124])
	h.integrity = parseResHdrShort(h.raw[124:148])
	return h, nil
}

func (h *wimHeader) encodePartHeader(
	partNum, totalParts uint16,
	tableRes, xmlRes, bootMetaRes resHdrShort,
	bootIndex uint32,
) [wimHeaderSize]byte {
	out := h.raw
	binary.LittleEndian.PutUint32(out[16:20], h.flags|flagHeaderSpanned)
	binary.LittleEndian.PutUint16(out[40:42], partNum)
	binary.LittleEndian.PutUint16(out[42:44], totalParts)
	encodeResHdrShort(out[48:72], tableRes)
	encodeResHdrShort(out[72:96], xmlRes)
	encodeResHdrShort(out[96:120], bootMetaRes)
	binary.LittleEndian.PutUint32(out[120:124], bootIndex)
	// Clear integrity table on split SWM parts.
	encodeResHdrShort(out[124:148], resHdrShort{})
	return out
}

// PartSpec describes one planned .swm output part before streaming any data.
type PartSpec struct {
	PartNumber uint16
	TotalParts uint16
	TotalSize  uint64
	entries    []plannedEntry
	bootMeta   resHdrShort
	bootIndex  uint32
	tableRes   resHdrShort
	xmlRes     resHdrShort
}

type plannedEntry struct {
	srcOffset uint64
	newEntry  lookupEntry
}

// PartConsumer receives each generated .swm part with its exact byte length up front
// so callers can stream directly into a FAT32 file on USB with zero temp disk usage.
type PartConsumer func(partNum, totalParts uint16, exactSize uint64, stream func(w io.Writer) error) error

// ProgressFunc reports copied bytes during WIM splitting.
type ProgressFunc func(bytesCopied uint64)

// Split streams a Microsoft WIM file into spanned .swm parts (each <= maxPartBytes)
// without decompressing or recompressing any LZX/XPRESS payloads.
func Split(src io.ReaderAt, maxPartBytes uint64, progress ProgressFunc, consume PartConsumer) (uint16, error) {
	if maxPartBytes == 0 {
		maxPartBytes = DefaultMaxPartSize
	}
	if maxPartBytes < 64*1024 {
		return 0, fmt.Errorf("maxPartBytes too small: %d", maxPartBytes)
	}

	hdr, err := parseHeader(src)
	if err != nil {
		return 0, err
	}
	if hdr.version == wimVersionSolid {
		return 0, ErrSolidESD
	}
	if hdr.offsetTable.size == 0 || hdr.offsetTable.size%wimResEntrySize != 0 {
		return 0, fmt.Errorf("%w: invalid lookup table size %d", ErrInvalidWIM, hdr.offsetTable.size)
	}

	// Read entire lookup table and XML metadata into memory (typically a few MiB).
	tableRaw := make([]byte, hdr.offsetTable.size)
	if _, err := src.ReadAt(tableRaw, int64(hdr.offsetTable.offset)); err != nil {
		return 0, fmt.Errorf("read WIM lookup table: %w", err)
	}
	xmlRaw := make([]byte, hdr.xmlData.size)
	if hdr.xmlData.size > 0 {
		if _, err := src.ReadAt(xmlRaw, int64(hdr.xmlData.offset)); err != nil {
			return 0, fmt.Errorf("read WIM XML metadata: %w", err)
		}
	}

	numEntries := int(hdr.offsetTable.size / wimResEntrySize)
	var metaEntries []lookupEntry
	var dataEntries []lookupEntry

	for i := 0; i < numEntries; i++ {
		eb := tableRaw[i*wimResEntrySize : (i+1)*wimResEntrySize]
		ent := lookupEntry{
			res:        parseResHdrShort(eb[0:24]),
			partNumber: binary.LittleEndian.Uint16(eb[24:26]),
			refCount:   binary.LittleEndian.Uint32(eb[26:30]),
		}
		copy(ent.hash[:], eb[30:50])

		if (ent.res.flags & resFlagMetadata) != 0 {
			metaEntries = append(metaEntries, ent)
		} else {
			dataEntries = append(dataEntries, ent)
		}
	}

	// Plan parts: Part 1 holds all metadata resources + as many data resources as fit.
	var parts []PartSpec
	newPart := func(num uint16) PartSpec {
		return PartSpec{PartNumber: num}
	}

	cur := newPart(1)
	curDataOff := uint64(wimHeaderSize)
	xmlLen := uint64(len(xmlRaw))

	addEntryToPart := func(p *PartSpec, off *uint64, ent lookupEntry) {
		srcOff := ent.res.offset
		ne := ent
		ne.partNumber = p.PartNumber
		ne.res.offset = *off
		p.entries = append(p.entries, plannedEntry{
			srcOffset: srcOff,
			newEntry:  ne,
		})
		if p.PartNumber == 1 && hdr.bootMetadata.size > 0 && srcOff == hdr.bootMetadata.offset {
			p.bootMeta = ne.res
			p.bootIndex = hdr.bootIndex
		}
		*off += ent.res.size
	}

	// Place all metadata entries in Part 1 first (required by Windows Setup).
	for _, me := range metaEntries {
		addEntryToPart(&cur, &curDataOff, me)
	}

	// Distribute data resources across Part 1..N under maxPartBytes.
	for _, de := range dataEntries {
		projectedTable := uint64(len(cur.entries)+1) * wimResEntrySize
		projectedTotal := curDataOff + de.res.size + projectedTable + xmlLen
		if projectedTotal > maxPartBytes && len(cur.entries) > 0 {
			finalizePartSpec(&cur, curDataOff, xmlLen, hdr.xmlData)
			parts = append(parts, cur)

			cur = newPart(uint16(len(parts) + 1))
			curDataOff = uint64(wimHeaderSize)
		}
		addEntryToPart(&cur, &curDataOff, de)
	}
	finalizePartSpec(&cur, curDataOff, xmlLen, hdr.xmlData)
	parts = append(parts, cur)

	totalParts := uint16(len(parts))
	for i := range parts {
		parts[i].TotalParts = totalParts
	}

	// Stream each planned part directly to the consumer.
	copyBuf := make([]byte, 1024*1024)
	for i := range parts {
		p := parts[i]
		err := consume(p.PartNumber, totalParts, p.TotalSize, func(w io.Writer) error {
			partHdr := hdr.encodePartHeader(
				p.PartNumber,
				totalParts,
				p.tableRes,
				p.xmlRes,
				p.bootMeta,
				p.bootIndex,
			)
			if _, err := w.Write(partHdr[:]); err != nil {
				return err
			}

			// Stream every resource payload assigned to this part.
			for _, pe := range p.entries {
				remaining := pe.newEntry.res.size
				srcPos := int64(pe.srcOffset)
				for remaining > 0 {
					chunk := uint64(len(copyBuf))
					if chunk > remaining {
						chunk = remaining
					}
					n, err := src.ReadAt(copyBuf[:chunk], srcPos)
					if err != nil && !errors.Is(err, io.EOF) {
						return fmt.Errorf("read WIM resource at offset %d: %w", srcPos, err)
					}
					if n == 0 {
						return io.ErrUnexpectedEOF
					}
					if _, err := w.Write(copyBuf[:n]); err != nil {
						return err
					}
					srcPos += int64(n)
					remaining -= uint64(n)
					if progress != nil {
						progress(uint64(n))
					}
				}
			}

			// Write this part's lookup table.
			partTable := make([]byte, len(p.entries)*wimResEntrySize)
			for idx, pe := range p.entries {
				eb := partTable[idx*wimResEntrySize : (idx+1)*wimResEntrySize]
				encodeResHdrShort(eb[0:24], pe.newEntry.res)
				binary.LittleEndian.PutUint16(eb[24:26], pe.newEntry.partNumber)
				binary.LittleEndian.PutUint32(eb[26:30], pe.newEntry.refCount)
				copy(eb[30:50], pe.newEntry.hash[:])
			}
			if len(partTable) > 0 {
				if _, err := w.Write(partTable); err != nil {
					return err
				}
			}

			// Write XML metadata at the end of the part.
			if len(xmlRaw) > 0 {
				if _, err := w.Write(xmlRaw); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return 0, err
		}
	}

	return totalParts, nil
}

func finalizePartSpec(p *PartSpec, dataEnd, xmlLen uint64, srcXML resHdrShort) {
	tableBytes := uint64(len(p.entries)) * wimResEntrySize
	p.tableRes = resHdrShort{
		size:         tableBytes,
		offset:       dataEnd,
		originalSize: tableBytes,
	}
	xmlOff := dataEnd + tableBytes
	if xmlLen > 0 {
		p.xmlRes = resHdrShort{
			size:         xmlLen,
			flags:        srcXML.flags,
			offset:       xmlOff,
			originalSize: srcXML.originalSize,
		}
	}
	p.TotalSize = xmlOff + xmlLen
}

// PartFileName returns Microsoft Windows Setup's exact naming convention:
// part 1 -> "install.swm", part 2 -> "install2.swm", part 3 -> "install3.swm", etc.
func PartFileName(baseStem string, partNum uint16) string {
	if partNum <= 1 {
		return baseStem + ".swm"
	}
	return fmt.Sprintf("%s%d.swm", baseStem, partNum)
}
