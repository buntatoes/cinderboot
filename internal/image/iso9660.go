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

const isoSectorSize = 2048

var ErrNotISO9660 = errors.New("not a valid ISO9660 image")

// ISO9660Reader is our pure-Go read-only ISO9660 + Rock Ridge + Joliet parser.
type ISO9660Reader struct {
	r                  io.ReaderAt
	size               int64
	volumeLabel        string
	fsUUID             string // GRUB2-compatible ISO9660 timestamp UUID (YYYY-MM-DD-HH-MM-SS-CC)
	joliet             bool
	rockRidge          bool
	hasElTorito        bool
	elToritoCatalogLBA uint32
	index              map[string]isoFileNode
	ordered            []Entry
}

type isoFileNode struct {
	entry   Entry
	extents []udfExtent
}

// OpenISO9660 opens an ISO9660 (preferring Joliet SVD when present) image and indexes its tree.
func OpenISO9660(r io.ReaderAt, totalSize int64) (*ISO9660Reader, error) {
	if totalSize < 17*isoSectorSize {
		return nil, ErrNotISO9660
	}

	var pvdRootLBA, pvdRootSize uint32
	var svdRootLBA, svdRootSize uint32
	var elToritoCatLBA uint32
	var label, fsUUID string
	var havePVD, haveJoliet, hasElTorito bool

	sec := make([]byte, isoSectorSize)
	for lba := int64(16); lba < 64; lba++ {
		if (lba+1)*isoSectorSize > totalSize {
			break
		}
		if _, err := r.ReadAt(sec, lba*isoSectorSize); err != nil {
			break
		}
		if string(sec[1:6]) != "CD001" {
			break
		}
		vdType := sec[0]
		if vdType == 255 { // Volume Descriptor Set Terminator
			break
		}
		switch vdType {
		case 0: // Boot Record
			if strings.HasPrefix(string(sec[7:39]), "EL TORITO SPECIFICATION") {
				hasElTorito = true
				elToritoCatLBA = binary.LittleEndian.Uint32(sec[71:75])
			}
		case 1: // Primary Volume Descriptor
			label = strings.TrimSpace(string(sec[40:72]))
			pvdRootLBA = binary.LittleEndian.Uint32(sec[158:162])
			pvdRootSize = binary.LittleEndian.Uint32(sec[166:170])
			fsUUID = parseISO9660UUID(sec[813:829], sec[830:846])
			havePVD = true
		case 2: // Supplementary Volume Descriptor (check Joliet escape sequences)
			esc := sec[88:91]
			if (esc[0] == '%' && esc[1] == '/') && (esc[2] == '@' || esc[2] == 'C' || esc[2] == 'E') {
				svdRootLBA = binary.LittleEndian.Uint32(sec[158:162])
				svdRootSize = binary.LittleEndian.Uint32(sec[166:170])
				if jl := decodeUTF16BEString(sec[40:72]); jl != "" {
					label = jl
				}
				haveJoliet = true
			}
		}
	}

	if !havePVD {
		return nil, ErrNotISO9660
	}

	haveRockRidge := detectRockRidge(r, pvdRootLBA, pvdRootSize)

	ir := &ISO9660Reader{
		r:                  r,
		size:               totalSize,
		volumeLabel:        label,
		fsUUID:             fsUUID,
		joliet:             haveJoliet && !haveRockRidge,
		rockRidge:          haveRockRidge,
		hasElTorito:        hasElTorito,
		elToritoCatalogLBA: elToritoCatLBA,
		index:              make(map[string]isoFileNode),
	}

	rootLBA, rootSize := pvdRootLBA, pvdRootSize
	// Prefer Primary Volume Descriptor with Rock Ridge (matches GRUB2 & Linux kernel POSIX names);
	// otherwise fall back to Joliet SVD when present.
	if ir.joliet && svdRootLBA != 0 && svdRootSize != 0 {
		rootLBA, rootSize = svdRootLBA, svdRootSize
	}
	if err := ir.walkDir(rootLBA, rootSize, "", 0); err != nil {
		return nil, err
	}
	return ir, nil
}

func (i *ISO9660Reader) Format() string {
	if i.rockRidge {
		return "ISO9660 (Rock Ridge)"
	}
	if i.joliet {
		return "ISO9660 (Joliet)"
	}
	return "ISO9660"
}

func (i *ISO9660Reader) VolumeLabel() string        { return i.volumeLabel }
func (i *ISO9660Reader) FSUUID() string             { return i.fsUUID }
func (i *ISO9660Reader) HasElTorito() bool          { return i.hasElTorito }
func (i *ISO9660Reader) ElToritoCatalogLBA() uint32 { return i.elToritoCatalogLBA }

func parseISO9660UUID(creation, modification []byte) string {
	formatTS := func(b []byte) string {
		if len(b) < 16 {
			return ""
		}
		allZero := true
		for _, c := range b[:16] {
			if c < '0' || c > '9' {
				return ""
			}
			if c != '0' {
				allZero = false
			}
		}
		if allZero {
			return ""
		}
		s := string(b[:16])
		return fmt.Sprintf("%s-%s-%s-%s-%s-%s-%s", s[0:4], s[4:6], s[6:8], s[8:10], s[10:12], s[12:14], s[14:16])
	}
	// Match GRUB2 (grub_iso9660_uuid) and blkid: prefer modification timestamp, fall back to creation.
	if u := formatTS(modification); u != "" {
		return u
	}
	return formatTS(creation)
}

func (i *ISO9660Reader) Walk(fn func(Entry) error) error {
	for _, e := range i.ordered {
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

func (i *ISO9660Reader) Open(relPath string) (io.ReadCloser, uint64, error) {
	key := normalizeRelPath(relPath)
	node, ok := i.index[key]
	if !ok {
		for k, v := range i.index {
			if strings.EqualFold(k, key) {
				node = v
				ok = true
				break
			}
		}
	}
	if !ok || node.entry.IsDir {
		return nil, 0, fmt.Errorf("ISO9660 file not found: %s", relPath)
	}
	return &extentReader{
		r:         i.r,
		extents:   node.extents,
		remaining: int64(node.entry.Size),
	}, node.entry.Size, nil
}

func (i *ISO9660Reader) OpenReaderAt(relPath string) (io.ReaderAt, uint64, error) {
	key := normalizeRelPath(relPath)
	node, ok := i.index[key]
	if !ok {
		for k, v := range i.index {
			if strings.EqualFold(k, key) {
				node = v
				ok = true
				break
			}
		}
	}
	if !ok || node.entry.IsDir {
		return nil, 0, fmt.Errorf("ISO9660 file not found: %s", relPath)
	}
	return &extentReaderAt{
		r:       i.r,
		extents: node.extents,
		size:    int64(node.entry.Size),
	}, node.entry.Size, nil
}

func (i *ISO9660Reader) walkDir(lba, size uint32, prefix string, depth int) error {
	if depth > 64 || size == 0 {
		return nil
	}
	data := make([]byte, size)
	if _, err := i.r.ReadAt(data, int64(lba)*isoSectorSize); err != nil {
		return err
	}

	pos := 0
	for pos < len(data) {
		recLen := int(data[pos])
		if recLen == 0 {
			// Skip zero padding to the next 2048-byte sector boundary.
			nextSec := ((pos / isoSectorSize) + 1) * isoSectorSize
			if nextSec <= pos || nextSec >= len(data) {
				break
			}
			pos = nextSec
			continue
		}
		if pos+recLen > len(data) || recLen < 34 {
			break
		}
		rec := data[pos : pos+recLen]
		pos += recLen

		extLBA := binary.LittleEndian.Uint32(rec[2:6])
		extLen := binary.LittleEndian.Uint32(rec[10:14])
		flags := rec[25]
		nameLen := int(rec[32])
		if 33+nameLen > len(rec) || nameLen == 0 {
			continue
		}
		rawName := rec[33 : 33+nameLen]
		// Skip "." (0x00) and ".." (0x01)
		if nameLen == 1 && (rawName[0] == 0x00 || rawName[0] == 0x01) {
			continue
		}

		var name string
		if i.rockRidge {
			suStart := 33 + nameLen
			if suStart%2 != 0 {
				suStart++
			}
			if suStart < len(rec) {
				name = i.parseRockRidgeName(rec[suStart:], 0)
			}
		}
		if name == "" {
			if i.joliet {
				name = decodeUTF16BEString(rawName)
			} else {
				name = string(rawName)
			}
			if semi := strings.IndexByte(name, ';'); semi >= 0 {
				name = name[:semi]
			}
			name = strings.TrimSuffix(name, ".")
		}
		if name == "" {
			continue
		}

		rel := name
		if prefix != "" {
			rel = path.Join(prefix, name)
		}

		isDir := (flags & 0x02) != 0
		isMultiExtent := (flags & 0x80) != 0

		if isDir {
			ent := Entry{Path: rel, Size: uint64(extLen), IsDir: true}
			i.ordered = append(i.ordered, ent)
			i.index[rel] = isoFileNode{entry: ent}
			if err := i.walkDir(extLBA, extLen, rel, depth+1); err != nil {
				return err
			}
			continue
		}

		// Handle ISO9660 multi-extent files (>4 GiB files split into consecutive directory records)
		if existing, exists := i.index[rel]; exists {
			existing.entry.Size += uint64(extLen)
			existing.extents = append(existing.extents, udfExtent{
				offset: int64(extLBA) * isoSectorSize,
				length: int64(extLen),
			})
			i.index[rel] = existing
			for idx := range i.ordered {
				if i.ordered[idx].Path == rel {
					i.ordered[idx].Size = existing.entry.Size
					break
				}
			}
			_ = isMultiExtent
			continue
		}

		ent := Entry{Path: rel, Size: uint64(extLen), IsDir: false}
		i.ordered = append(i.ordered, ent)
		i.index[rel] = isoFileNode{
			entry: ent,
			extents: []udfExtent{{
				offset: int64(extLBA) * isoSectorSize,
				length: int64(extLen),
			}},
		}
	}
	return nil
}

func decodeUTF16BEString(b []byte) string {
	n := len(b) / 2
	if n == 0 {
		return ""
	}
	u16 := make([]uint16, n)
	for i := 0; i < n; i++ {
		u16[i] = binary.BigEndian.Uint16(b[i*2 : i*2+2])
	}
	return strings.TrimSpace(strings.TrimRight(string(utf16.Decode(u16)), "\x00"))
}

// detectRockRidge inspects the Primary Volume Descriptor root directory records
// for SUSP / RRIP System Use entries (SP, RR, NM, PX, ER).
func detectRockRidge(r io.ReaderAt, rootLBA, rootSize uint32) bool {
	if rootLBA == 0 || rootSize == 0 {
		return false
	}
	readLen := rootSize
	if readLen > 8*isoSectorSize {
		readLen = 8 * isoSectorSize
	}
	buf := make([]byte, readLen)
	if _, err := r.ReadAt(buf, int64(rootLBA)*isoSectorSize); err != nil {
		return false
	}
	pos := 0
	for pos < len(buf) {
		recLen := int(buf[pos])
		if recLen == 0 {
			nextSec := ((pos / isoSectorSize) + 1) * isoSectorSize
			if nextSec <= pos || nextSec >= len(buf) {
				break
			}
			pos = nextSec
			continue
		}
		if pos+recLen > len(buf) || recLen < 34 {
			break
		}
		rec := buf[pos : pos+recLen]
		pos += recLen
		nameLen := int(rec[32])
		suStart := 33 + nameLen
		if suStart%2 != 0 {
			suStart++
		}
		for off := suStart; off+4 <= len(rec); {
			eLen := int(rec[off+2])
			if eLen < 4 || off+eLen > len(rec) {
				break
			}
			sig0, sig1 := rec[off], rec[off+1]
			if sig0 == 'S' && sig1 == 'P' && eLen >= 7 && rec[off+4] == 0xBE && rec[off+5] == 0xEF {
				return true
			}
			if (sig0 == 'N' && sig1 == 'M') || (sig0 == 'R' && sig1 == 'R') || (sig0 == 'P' && sig1 == 'X') {
				return true
			}
			if sig0 == 'S' && sig1 == 'T' {
				break
			}
			off += eLen
		}
	}
	return false
}

// parseRockRidgeName extracts the POSIX filename from Rock Ridge NM (and CE continuation) entries.
func (i *ISO9660Reader) parseRockRidgeName(su []byte, depth int) string {
	if depth > 4 || len(su) < 4 {
		return ""
	}
	var b strings.Builder
	var ceLBA, ceOff, ceLen uint32
	done := false

	for off := 0; off+4 <= len(su); {
		eLen := int(su[off+2])
		if eLen < 4 || off+eLen > len(su) {
			break
		}
		sig0, sig1 := su[off], su[off+1]
		if sig0 == 'S' && sig1 == 'T' {
			break
		}
		if sig0 == 'N' && sig1 == 'M' && eLen >= 5 {
			flags := su[off+4]
			// Ignore CURRENT (0x02) and PARENT (0x04) directory references.
			if (flags & (0x02 | 0x04)) == 0 {
				b.Write(su[off+5 : off+eLen])
				if (flags & 0x01) == 0 {
					done = true
				}
			}
		} else if sig0 == 'C' && sig1 == 'E' && eLen >= 28 {
			ceLBA = binary.LittleEndian.Uint32(su[off+4 : off+8])
			ceOff = binary.LittleEndian.Uint32(su[off+12 : off+16])
			ceLen = binary.LittleEndian.Uint32(su[off+20 : off+24])
		}
		off += eLen
	}

	if !done && ceLen > 0 && ceLen <= 64*1024 {
		absOff := int64(ceLBA)*isoSectorSize + int64(ceOff)
		if absOff >= 0 && absOff+int64(ceLen) <= i.size {
			cont := make([]byte, ceLen)
			if _, err := i.r.ReadAt(cont, absOff); err == nil {
				b.WriteString(i.parseRockRidgeName(cont, depth+1))
			}
		}
	}
	return b.String()
}
