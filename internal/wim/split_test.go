// SPDX-License-Identifier: GPL-3.0-only
package wim

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"testing"
)

func buildSyntheticWIM(t *testing.T) ([]byte, [][]byte, []byte) {
	t.Helper()

	meta := bytes.Repeat([]byte("META"), 1024)
	res1 := bytes.Repeat([]byte("AAA1"), 16*1024) // 64 KiB
	res2 := bytes.Repeat([]byte("BBB2"), 16*1024) // 64 KiB
	res3 := bytes.Repeat([]byte("CCC3"), 16*1024) // 64 KiB
	xmlData := []byte("<WIM><TOTALBYTES>200704</TOTALBYTES><IMAGE INDEX=\"1\"><NAME>Test</NAME></IMAGE></WIM>")

	payloads := [][]byte{meta, res1, res2, res3}
	var buf bytes.Buffer
	var hdr [wimHeaderSize]byte
	copy(hdr[0:8], wimMagic)
	binary.LittleEndian.PutUint32(hdr[8:12], wimHeaderSize)
	binary.LittleEndian.PutUint32(hdr[12:16], 0x00010D00)
	binary.LittleEndian.PutUint32(hdr[20:24], 32768)
	copy(hdr[24:40], []byte("0123456789ABCDEF"))
	binary.LittleEndian.PutUint16(hdr[40:42], 1)
	binary.LittleEndian.PutUint16(hdr[42:44], 1)
	binary.LittleEndian.PutUint32(hdr[44:48], 1)
	buf.Write(hdr[:])

	var entries []lookupEntry
	for idx, p := range payloads {
		off := uint64(buf.Len())
		buf.Write(p)
		flags := byte(0)
		if idx == 0 {
			flags = resFlagMetadata
		}
		entries = append(entries, lookupEntry{
			res: resHdrShort{
				size:         uint64(len(p)),
				flags:        flags,
				offset:       off,
				originalSize: uint64(len(p)),
			},
			partNumber: 1,
			refCount:   1,
			hash:       sha1.Sum(p),
		})
	}

	tableOff := uint64(buf.Len())
	tableBuf := make([]byte, len(entries)*wimResEntrySize)
	for i, e := range entries {
		eb := tableBuf[i*wimResEntrySize : (i+1)*wimResEntrySize]
		encodeResHdrShort(eb[0:24], e.res)
		binary.LittleEndian.PutUint16(eb[24:26], e.partNumber)
		binary.LittleEndian.PutUint32(eb[26:30], e.refCount)
		copy(eb[30:50], e.hash[:])
	}
	buf.Write(tableBuf)

	xmlOff := uint64(buf.Len())
	buf.Write(xmlData)

	raw := buf.Bytes()
	encodeResHdrShort(raw[48:72], resHdrShort{size: uint64(len(tableBuf)), offset: tableOff, originalSize: uint64(len(tableBuf))})
	encodeResHdrShort(raw[72:96], resHdrShort{size: uint64(len(xmlData)), offset: xmlOff, originalSize: uint64(len(xmlData))})
	encodeResHdrShort(raw[96:120], entries[0].res)
	binary.LittleEndian.PutUint32(raw[120:124], 1)

	return raw, payloads, xmlData
}

func TestSplitWIMRoundTrip(t *testing.T) {
	wimBytes, payloads, xmlData := buildSyntheticWIM(t)
	reader := bytes.NewReader(wimBytes)

	var parts [][]byte
	total, err := Split(reader, 100*1024, nil, func(partNum, totalParts uint16, exactSize uint64, stream func(w io.Writer) error) error {
		var out bytes.Buffer
		if err := stream(&out); err != nil {
			return err
		}
		if uint64(out.Len()) != exactSize {
			t.Fatalf("part %d size mismatch: streamed %d, promised %d", partNum, out.Len(), exactSize)
		}
		parts = append(parts, out.Bytes())
		return nil
	})
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}
	if total != 3 || len(parts) != 3 {
		t.Fatalf("expected 3 SWM parts, got total=%d len=%d", total, len(parts))
	}

	recovered := make(map[[20]byte][]byte)
	for idx, pBytes := range parts {
		ph, err := parseHeader(bytes.NewReader(pBytes))
		if err != nil {
			t.Fatalf("part %d invalid header: %v", idx+1, err)
		}
		if ph.partNumber != uint16(idx+1) || ph.totalParts != 3 {
			t.Fatalf("part %d header part/total mismatch: %d/%d", idx+1, ph.partNumber, ph.totalParts)
		}
		if (ph.flags & flagHeaderSpanned) == 0 {
			t.Fatalf("part %d missing FLAG_HEADER_SPANNED", idx+1)
		}
		gotXML := pBytes[ph.xmlData.offset : ph.xmlData.offset+ph.xmlData.size]
		if !bytes.Equal(gotXML, xmlData) {
			t.Fatalf("part %d XML mismatch", idx+1)
		}

		// Read every lookup table entry in this part and verify payload hash + exact offset
		tbl := pBytes[ph.offsetTable.offset : ph.offsetTable.offset+ph.offsetTable.size]
		count := len(tbl) / wimResEntrySize
		for i := 0; i < count; i++ {
			eb := tbl[i*wimResEntrySize : (i+1)*wimResEntrySize]
			rh := parseResHdrShort(eb[0:24])
			pn := binary.LittleEndian.Uint16(eb[24:26])
			if pn != uint16(idx+1) {
				t.Fatalf("part %d entry has wrong partNumber %d", idx+1, pn)
			}
			var hash [20]byte
			copy(hash[:], eb[30:50])
			blob := pBytes[rh.offset : rh.offset+rh.size]
			if sha1.Sum(blob) != hash {
				t.Fatalf("part %d entry %d SHA-1 mismatch", idx+1, i)
			}
			recovered[hash] = blob
		}
	}

	for i, orig := range payloads {
		h := sha1.Sum(orig)
		got, ok := recovered[h]
		if !ok || !bytes.Equal(got, orig) {
			t.Fatalf("payload %d missing or corrupted across split SWM parts", i)
		}
	}

	if PartFileName("install", 1) != "install.swm" || PartFileName("install", 2) != "install2.swm" {
		t.Fatalf("unexpected PartFileName formatting")
	}
}
