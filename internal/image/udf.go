// SPDX-License-Identifier: GPL-3.0-only
package image

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"unicode/utf16"
)

const udfSectorSize = 2048

// Entry represents a file or directory inside an ISO9660 or UDF image.
type Entry struct {
	Path  string
	Size  uint64
	IsDir bool
}

// ImageFS is a read-only filesystem view over an ISO9660 or UDF 1.02 image.
type ImageFS interface {
	Format() string
	VolumeLabel() string
	Walk(fn func(Entry) error) error
	Open(relPath string) (io.ReadCloser, uint64, error)
	OpenReaderAt(relPath string) (io.ReaderAt, uint64, error)
}

// UDFReader is our pure-Go read-only OSTA UDF 1.02 (ECMA-167) parser
// supporting standard Microsoft Windows 10/11 ISOs created by oscdimg.
type UDFReader struct {
	r           io.ReaderAt
	size        int64
	blockSize   uint32
	partStart   uint64 // partition starting sector (in blockSize units)
	partLength  uint64
	rootICB     udfLongAD
	volumeLabel string
	index       map[string]udfFileNode
	ordered     []Entry
}

type udfExtent struct {
	offset int64
	length int64
}

type udfFileNode struct {
	entry   Entry
	inline  []byte
	extents []udfExtent
}

type udfLongAD struct {
	length uint32
	lbn    uint32
	part   uint16
}

var ErrNotUDF = errors.New("not a valid UDF 1.02 image")

// OpenUDF opens a UDF 1.02 image from r and indexes its directory tree.
func OpenUDF(r io.ReaderAt, totalSize int64) (*UDFReader, error) {
	if totalSize < 257*udfSectorSize {
		return nil, ErrNotUDF
	}

	// Read Anchor Volume Descriptor Pointer (AVDP) at sector 256.
	avdp := make([]byte, udfSectorSize)
	if _, err := r.ReadAt(avdp, 256*udfSectorSize); err != nil {
		return nil, ErrNotUDF
	}
	if binary.LittleEndian.Uint16(avdp[0:2]) != 2 {
		return nil, ErrNotUDF
	}

	mvdsLen := binary.LittleEndian.Uint32(avdp[16:20])
	mvdsLoc := binary.LittleEndian.Uint32(avdp[20:24])
	if mvdsLen < udfSectorSize || mvdsLoc == 0 {
		return nil, ErrNotUDF
	}

	ur := &UDFReader{
		r:         r,
		size:      totalSize,
		blockSize: udfSectorSize,
		index:     make(map[string]udfFileNode),
	}

	var fsdAD udfLongAD
	var havePart, haveLVD bool

	secCount := mvdsLen / udfSectorSize
	if secCount > 128 {
		secCount = 128
	}
	buf := make([]byte, udfSectorSize)
	for i := uint32(0); i < secCount; i++ {
		off := int64(mvdsLoc+i) * udfSectorSize
		if off+udfSectorSize > totalSize {
			break
		}
		if _, err := r.ReadAt(buf, off); err != nil {
			break
		}
		tagID := binary.LittleEndian.Uint16(buf[0:2])
		if tagID == 8 { // Terminating Descriptor
			break
		}
		switch tagID {
		case 5: // Partition Descriptor
			ur.partStart = uint64(binary.LittleEndian.Uint32(buf[188:192]))
			ur.partLength = uint64(binary.LittleEndian.Uint32(buf[192:196]))
			havePart = true
		case 6: // Logical Volume Descriptor
			ur.volumeLabel = decodeOSTADString(buf[84:212])
			bs := binary.LittleEndian.Uint32(buf[212:216])
			if bs >= 512 && bs <= 8192 {
				ur.blockSize = bs
			}
			// Logical Volume Contents Use (16 bytes at offset 248) is a LongAD pointing to FSD.
			fsdAD = parseLongAD(buf[248:264])
			haveLVD = true
		}
	}

	if !havePart || !haveLVD || fsdAD.length == 0 {
		return nil, ErrNotUDF
	}

	// Read File Set Descriptor (Tag 256).
	fsdOff := ur.partByteOffset(fsdAD.lbn)
	fsdBuf := make([]byte, ur.blockSize)
	if _, err := r.ReadAt(fsdBuf, fsdOff); err != nil {
		return nil, fmt.Errorf("read UDF FSD: %w", err)
	}
	if binary.LittleEndian.Uint16(fsdBuf[0:2]) != 256 {
		return nil, ErrNotUDF
	}
	// Root Directory ICB is a LongAD at offset 400.
	ur.rootICB = parseLongAD(fsdBuf[400:416])

	if err := ur.walkDir(ur.rootICB, "", 0); err != nil {
		return nil, err
	}
	return ur, nil
}

func (u *UDFReader) Format() string      { return "UDF 1.02" }
func (u *UDFReader) VolumeLabel() string { return u.volumeLabel }

func (u *UDFReader) Walk(fn func(Entry) error) error {
	for _, e := range u.ordered {
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

func (u *UDFReader) Open(relPath string) (io.ReadCloser, uint64, error) {
	key := normalizeRelPath(relPath)
	node, ok := u.index[key]
	if !ok {
		// Case-insensitive fallback for Windows ISO paths
		for k, v := range u.index {
			if strings.EqualFold(k, key) {
				node = v
				ok = true
				break
			}
		}
	}
	if !ok || node.entry.IsDir {
		return nil, 0, fmt.Errorf("UDF file not found: %s", relPath)
	}
	if node.inline != nil {
		return io.NopCloser(strings.NewReader(string(node.inline))), node.entry.Size, nil
	}
	return &extentReader{
		r:         u.r,
		extents:   node.extents,
		remaining: int64(node.entry.Size),
	}, node.entry.Size, nil
}

func (u *UDFReader) OpenReaderAt(relPath string) (io.ReaderAt, uint64, error) {
	key := normalizeRelPath(relPath)
	node, ok := u.index[key]
	if !ok {
		for k, v := range u.index {
			if strings.EqualFold(k, key) {
				node = v
				ok = true
				break
			}
		}
	}
	if !ok || node.entry.IsDir {
		return nil, 0, fmt.Errorf("UDF file not found: %s", relPath)
	}
	if node.inline != nil {
		return strings.NewReader(string(node.inline)), node.entry.Size, nil
	}
	return &extentReaderAt{
		r:       u.r,
		extents: node.extents,
		size:    int64(node.entry.Size),
	}, node.entry.Size, nil
}

func (u *UDFReader) partByteOffset(lbn uint32) int64 {
	return int64(u.partStart+uint64(lbn)) * int64(u.blockSize)
}

func (u *UDFReader) readFileEntry(icb udfLongAD) (isDir bool, infoLen uint64, inline []byte, extents []udfExtent, err error) {
	buf := make([]byte, u.blockSize)
	if _, err := u.r.ReadAt(buf, u.partByteOffset(icb.lbn)); err != nil {
		return false, 0, nil, nil, err
	}
	tagID := binary.LittleEndian.Uint16(buf[0:2])
	var fileType byte
	var icbFlags uint16
	var eaLen, adLen uint32
	var adOff uint32

	switch tagID {
	case 261: // File Entry
		fileType = buf[27]
		icbFlags = binary.LittleEndian.Uint16(buf[34:36])
		infoLen = binary.LittleEndian.Uint64(buf[56:64])
		eaLen = binary.LittleEndian.Uint32(buf[168:172])
		adLen = binary.LittleEndian.Uint32(buf[172:176])
		adOff = 176 + eaLen
	case 266: // Extended File Entry
		fileType = buf[27]
		icbFlags = binary.LittleEndian.Uint16(buf[34:36])
		infoLen = binary.LittleEndian.Uint64(buf[56:64])
		eaLen = binary.LittleEndian.Uint32(buf[208:212])
		adLen = binary.LittleEndian.Uint32(buf[212:216])
		adOff = 216 + eaLen
	default:
		return false, 0, nil, nil, fmt.Errorf("unexpected UDF file entry tag %d", tagID)
	}

	isDir = (fileType == 4)
	if uint64(adOff)+uint64(adLen) > uint64(len(buf)) {
		return false, 0, nil, nil, fmt.Errorf("UDF allocation descriptors exceed block size")
	}
	adData := buf[adOff : adOff+adLen]
	adType := icbFlags & 0x0007

	switch adType {
	case 3: // Inline data stored directly inside allocation descriptor area
		cp := make([]byte, len(adData))
		copy(cp, adData)
		if uint64(len(cp)) > infoLen {
			cp = cp[:infoLen]
		}
		return isDir, infoLen, cp, nil, nil
	case 0: // Short Allocation Descriptors (8 bytes each)
		extents, err = u.parseShortADs(adData, 0)
		return isDir, infoLen, nil, extents, err
	case 1: // Long Allocation Descriptors (16 bytes each)
		extents, err = u.parseLongADs(adData, 0)
		return isDir, infoLen, nil, extents, err
	default:
		return false, 0, nil, nil, fmt.Errorf("unsupported UDF AD type %d", adType)
	}
}

func (u *UDFReader) parseShortADs(adData []byte, depth int) ([]udfExtent, error) {
	if depth > 64 {
		return nil, errors.New("UDF allocation extent recursion limit exceeded")
	}
	var out []udfExtent
	for pos := 0; pos+8 <= len(adData); pos += 8 {
		rawLen := binary.LittleEndian.Uint32(adData[pos : pos+4])
		lbn := binary.LittleEndian.Uint32(adData[pos+4 : pos+8])
		extLen := rawLen & 0x3FFFFFFF
		extType := rawLen >> 30
		if extLen == 0 {
			break
		}
		switch extType {
		case 0: // Recorded and allocated
			out = append(out, udfExtent{
				offset: u.partByteOffset(lbn),
				length: int64(extLen),
			})
		case 3: // Next extent of allocation descriptors (Tag 258)
			nextBuf := make([]byte, extLen)
			if _, err := u.r.ReadAt(nextBuf, u.partByteOffset(lbn)); err != nil {
				return nil, err
			}
			if len(nextBuf) >= 24 && binary.LittleEndian.Uint16(nextBuf[0:2]) == 258 {
				nextLen := binary.LittleEndian.Uint32(nextBuf[20:24])
				if int(24+nextLen) <= len(nextBuf) {
					more, err := u.parseShortADs(nextBuf[24:24+nextLen], depth+1)
					if err != nil {
						return nil, err
					}
					out = append(out, more...)
				}
			}
		}
	}
	return out, nil
}

func (u *UDFReader) parseLongADs(adData []byte, depth int) ([]udfExtent, error) {
	if depth > 64 {
		return nil, errors.New("UDF long allocation extent recursion limit exceeded")
	}
	var out []udfExtent
	for pos := 0; pos+16 <= len(adData); pos += 16 {
		rawLen := binary.LittleEndian.Uint32(adData[pos : pos+4])
		lbn := binary.LittleEndian.Uint32(adData[pos+4 : pos+8])
		extLen := rawLen & 0x3FFFFFFF
		extType := rawLen >> 30
		if extLen == 0 {
			break
		}
		switch extType {
		case 0:
			out = append(out, udfExtent{
				offset: u.partByteOffset(lbn),
				length: int64(extLen),
			})
		case 3:
			nextBuf := make([]byte, extLen)
			if _, err := u.r.ReadAt(nextBuf, u.partByteOffset(lbn)); err != nil {
				return nil, err
			}
			if len(nextBuf) >= 24 && binary.LittleEndian.Uint16(nextBuf[0:2]) == 258 {
				nextLen := binary.LittleEndian.Uint32(nextBuf[20:24])
				if int(24+nextLen) <= len(nextBuf) {
					more, err := u.parseLongADs(nextBuf[24:24+nextLen], depth+1)
					if err != nil {
						return nil, err
					}
					out = append(out, more...)
				}
			}
		}
	}
	return out, nil
}

func (u *UDFReader) walkDir(icb udfLongAD, prefix string, depth int) error {
	if depth > 64 {
		return errors.New("UDF directory depth limit exceeded")
	}
	isDir, infoLen, inline, extents, err := u.readFileEntry(icb)
	if err != nil {
		return err
	}
	if !isDir {
		return nil
	}

	var dirBytes []byte
	if inline != nil {
		dirBytes = inline
	} else {
		dirBytes = make([]byte, infoLen)
		er := &extentReader{r: u.r, extents: extents, remaining: int64(infoLen)}
		if _, err := io.ReadFull(er, dirBytes); err != nil {
			return fmt.Errorf("read UDF directory %q: %w", prefix, err)
		}
	}

	pos := 0
	for pos+38 <= len(dirBytes) {
		tagID := binary.LittleEndian.Uint16(dirBytes[pos : pos+2])
		if tagID != 257 { // File Identifier Descriptor
			break
		}
		chars := dirBytes[pos+18]
		nameLen := int(dirBytes[pos+19])
		childICB := parseLongAD(dirBytes[pos+20 : pos+36])
		impUseLen := int(binary.LittleEndian.Uint16(dirBytes[pos+36 : pos+38]))

		nameStart := pos + 38 + impUseLen
		nameEnd := nameStart + nameLen
		if nameEnd > len(dirBytes) {
			break
		}
		recLen := 38 + impUseLen + nameLen
		if rem := recLen % 4; rem != 0 {
			recLen += 4 - rem
		}
		pos += recLen

		// Bit 2 = deleted, Bit 3 = parent directory entry ("..")
		if (chars&0x04) != 0 || (chars&0x08) != 0 || nameLen == 0 {
			continue
		}

		name := decodeOSTACompression(dirBytes[nameStart:nameEnd])
		if name == "" || name == "." || name == ".." {
			continue
		}

		rel := name
		if prefix != "" {
			rel = path.Join(prefix, name)
		}

		cIsDir, cLen, cInline, cExtents, err := u.readFileEntry(childICB)
		if err != nil {
			return fmt.Errorf("read UDF entry %q: %w", rel, err)
		}

		ent := Entry{Path: rel, Size: cLen, IsDir: cIsDir}
		u.ordered = append(u.ordered, ent)
		u.index[rel] = udfFileNode{
			entry:   ent,
			inline:  cInline,
			extents: cExtents,
		}

		if cIsDir {
			if err := u.walkDir(childICB, rel, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func parseLongAD(b []byte) udfLongAD {
	return udfLongAD{
		length: binary.LittleEndian.Uint32(b[0:4]) & 0x3FFFFFFF,
		lbn:    binary.LittleEndian.Uint32(b[4:8]),
		part:   binary.LittleEndian.Uint16(b[8:10]),
	}
}

// decodeOSTADString decodes a fixed-length OSTA CS0 dstring where the final byte stores the length.
func decodeOSTADString(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	n := int(b[len(b)-1])
	if n == 0 || n >= len(b) {
		return ""
	}
	return strings.TrimSpace(decodeOSTACompression(b[:n]))
}

// decodeOSTACompression decodes an OSTA CS0 compressed Unicode string (tag 8 = Latin-1, tag 16 = UTF-16BE).
func decodeOSTACompression(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	switch b[0] {
	case 8:
		runes := make([]rune, len(b)-1)
		for i, c := range b[1:] {
			runes[i] = rune(c)
		}
		return string(runes)
	case 16:
		data := b[1:]
		n := len(data) / 2
		u16 := make([]uint16, n)
		for i := 0; i < n; i++ {
			u16[i] = binary.BigEndian.Uint16(data[i*2 : i*2+2])
		}
		return string(utf16.Decode(u16))
	default:
		return strings.TrimRight(string(b), "\x00")
	}
}

type extentReader struct {
	r         io.ReaderAt
	extents   []udfExtent
	idx       int
	extOff    int64
	remaining int64
}

func (e *extentReader) Read(p []byte) (int, error) {
	if e.remaining <= 0 {
		return 0, io.EOF
	}
	for e.idx < len(e.extents) {
		ext := e.extents[e.idx]
		avail := ext.length - e.extOff
		if avail <= 0 {
			e.idx++
			e.extOff = 0
			continue
		}
		toRead := int64(len(p))
		if toRead > avail {
			toRead = avail
		}
		if toRead > e.remaining {
			toRead = e.remaining
		}
		n, err := e.r.ReadAt(p[:toRead], ext.offset+e.extOff)
		e.extOff += int64(n)
		e.remaining -= int64(n)
		if n > 0 && errors.Is(err, io.EOF) {
			return n, nil
		}
		return n, err
	}
	return 0, io.EOF
}

func (e *extentReader) Close() error { return nil }

type extentReaderAt struct {
	r       io.ReaderAt
	extents []udfExtent
	size    int64
}

func (e *extentReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	if off >= e.size {
		return 0, io.EOF
	}
	maxRead := int64(len(p))
	hitEOF := false
	if off+maxRead > e.size {
		maxRead = e.size - off
		hitEOF = true
	}

	var total int
	curOff := off
	var logicalPos int64
	for _, ext := range e.extents {
		if total >= int(maxRead) {
			break
		}
		extEnd := logicalPos + ext.length
		if curOff < extEnd {
			inExt := curOff - logicalPos
			avail := ext.length - inExt
			want := maxRead - int64(total)
			if want > avail {
				want = avail
			}
			n, err := e.r.ReadAt(p[total:total+int(want)], ext.offset+inExt)
			total += n
			curOff += int64(n)
			if err != nil && !errors.Is(err, io.EOF) {
				return total, err
			}
			if int64(n) < want {
				return total, io.ErrUnexpectedEOF
			}
		}
		logicalPos = extEnd
	}
	if hitEOF {
		return total, io.EOF
	}
	return total, nil
}

func normalizeRelPath(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	p = strings.TrimPrefix(p, "/")
	return path.Clean(p)
}
