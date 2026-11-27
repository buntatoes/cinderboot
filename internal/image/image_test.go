// SPDX-License-Identifier: GPL-3.0-only
package image

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRawStreamCompressed(t *testing.T) {
	payload := bytes.Repeat([]byte("CINDERBOOT-RAW-STREAM-TEST-DATA!"), 4096)
	dir := t.TempDir()

	// 1. Gzip
	gzPath := filepath.Join(dir, "test.img.gz")
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	_, _ = gw.Write(payload)
	_ = gw.Close()
	if err := os.WriteFile(gzPath, gzBuf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := OpenRawStream(gzPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(s.Reader)
	_ = s.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("gzip stream mismatch: got %d bytes, want %d", len(got), len(payload))
	}

	// 2. Zip
	zipPath := filepath.Join(dir, "test.zip")
	zf, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	w, err := zw.Create("distro.img")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write(payload)
	_ = zw.Close()
	_ = zf.Close()

	s2, err := OpenRawStream(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	got2, err := io.ReadAll(s2.Reader)
	_ = s2.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got2, payload) {
		t.Fatalf("zip stream mismatch: got %d bytes, want %d", len(got2), len(payload))
	}
}

func TestSyntheticUDFWindowsISOInspect(t *testing.T) {
	const totalSectors = 300
	img := make([]byte, totalSectors*udfSectorSize)

	writeTag := func(sec []byte, id uint16) {
		binary.LittleEndian.PutUint16(sec[0:2], id)
	}

	// Sector 256: AVDP pointing MVDS at sector 32 (length 16 sectors)
	avdp := img[256*udfSectorSize : 257*udfSectorSize]
	writeTag(avdp, 2)
	binary.LittleEndian.PutUint32(avdp[16:20], 16*udfSectorSize)
	binary.LittleEndian.PutUint32(avdp[20:24], 32)

	// Sector 32: Partition Descriptor (tag 5) starting at sector 64
	pd := img[32*udfSectorSize : 33*udfSectorSize]
	writeTag(pd, 5)
	binary.LittleEndian.PutUint32(pd[188:192], 64)
	binary.LittleEndian.PutUint32(pd[192:196], 180)

	// Sector 33: Logical Volume Descriptor (tag 6) with FSD at partition LBN 0
	lvd := img[33*udfSectorSize : 34*udfSectorSize]
	writeTag(lvd, 6)
	volName := append([]byte{8}, []byte("WIN11_TEST")...)
	copy(lvd[84:212], volName)
	lvd[211] = byte(len(volName))
	binary.LittleEndian.PutUint32(lvd[212:216], udfSectorSize)
	binary.LittleEndian.PutUint32(lvd[248:252], udfSectorSize)
	binary.LittleEndian.PutUint32(lvd[252:256], 0)

	// Sector 34: Terminating Descriptor (tag 8)
	writeTag(img[34*udfSectorSize:35*udfSectorSize], 8)

	partSec := func(lbn int) []byte {
		off := (64 + lbn) * udfSectorSize
		return img[off : off+udfSectorSize]
	}

	// Partition LBN 0: File Set Descriptor (tag 256), root ICB at LBN 1
	fsd := partSec(0)
	writeTag(fsd, 256)
	binary.LittleEndian.PutUint32(fsd[400:404], udfSectorSize)
	binary.LittleEndian.PutUint32(fsd[404:408], 1)

	makeFID := func(name string, isDir bool, childLBN uint32) []byte {
		encName := append([]byte{8}, []byte(name)...)
		recLen := 38 + len(encName)
		if rem := recLen % 4; rem != 0 {
			recLen += 4 - rem
		}
		b := make([]byte, recLen)
		writeTag(b, 257)
		if isDir {
			b[18] = 0x02
		}
		b[19] = byte(len(encName))
		binary.LittleEndian.PutUint32(b[20:24], udfSectorSize)
		binary.LittleEndian.PutUint32(b[24:28], childLBN)
		copy(b[38:], encName)
		return b
	}

	// Partition LBN 1: Root Directory File Entry
	rootFE := partSec(1)
	rootFIDs := makeFID("sources", true, 2)
	writeTag(rootFE, 261)
	rootFE[27] = 4
	binary.LittleEndian.PutUint16(rootFE[34:36], 3)
	binary.LittleEndian.PutUint64(rootFE[56:64], uint64(len(rootFIDs)))
	binary.LittleEndian.PutUint32(rootFE[172:176], uint32(len(rootFIDs)))
	copy(rootFE[176:], rootFIDs)

	// Partition LBN 2: "sources" Directory File Entry
	srcFE := partSec(2)
	srcFIDs := append(makeFID("boot.wim", false, 3), makeFID("install.wim", false, 4)...)
	writeTag(srcFE, 261)
	srcFE[27] = 4
	binary.LittleEndian.PutUint16(srcFE[34:36], 3)
	binary.LittleEndian.PutUint64(srcFE[56:64], uint64(len(srcFIDs)))
	binary.LittleEndian.PutUint32(srcFE[172:176], uint32(len(srcFIDs)))
	copy(srcFE[176:], srcFIDs)

	// Partition LBN 3: boot.wim
	bootFE := partSec(3)
	bootData := []byte("MSWIM-BOOT-DATA")
	writeTag(bootFE, 261)
	bootFE[27] = 5
	binary.LittleEndian.PutUint16(bootFE[34:36], 3)
	binary.LittleEndian.PutUint64(bootFE[56:64], uint64(len(bootData)))
	binary.LittleEndian.PutUint32(bootFE[172:176], uint32(len(bootData)))
	copy(bootFE[176:], bootData)

	// Partition LBN 4: install.wim (short AD at LBN 5)
	instFE := partSec(4)
	instData := []byte("MSWIM-INSTALL-PAYLOAD")
	writeTag(instFE, 261)
	instFE[27] = 5
	binary.LittleEndian.PutUint16(instFE[34:36], 0)
	binary.LittleEndian.PutUint64(instFE[56:64], uint64(len(instData)))
	binary.LittleEndian.PutUint32(instFE[172:176], 8)
	binary.LittleEndian.PutUint32(instFE[176:180], uint32(len(instData)))
	binary.LittleEndian.PutUint32(instFE[180:184], 5)
	copy(partSec(5), instData)

	isoPath := filepath.Join(t.TempDir(), "win11_synthetic.iso")
	if err := os.WriteFile(isoPath, img, 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := Inspect(isoPath)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if info.Kind != KindWindowsISO {
		t.Fatalf("expected KindWindowsISO, got %q", info.Kind)
	}
	if info.VolumeLabel != "WIN11_TEST" {
		t.Fatalf("expected VolumeLabel WIN11_TEST, got %q", info.VolumeLabel)
	}

	f, _ := os.Open(isoPath)
	defer f.Close()
	udf, err := OpenUDF(f, int64(len(img)))
	if err != nil {
		t.Fatal(err)
	}
	rc, sz, err := udf.Open("sources/install.wim")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	_ = rc.Close()
	if sz != uint64(len(instData)) || !bytes.Equal(got, instData) {
		t.Fatalf("install.wim read mismatch: got %q (sz=%d)", got, sz)
	}

	// Verify OpenReaderAt works directly on UDF file extents
	ra, raSize, err := udf.OpenReaderAt("sources/install.wim")
	if err != nil {
		t.Fatal(err)
	}
	part := make([]byte, 7)
	if _, err := ra.ReadAt(part, 6); err != nil {
		t.Fatal(err)
	}
	if raSize != uint64(len(instData)) || string(part) != "INSTALL" {
		t.Fatalf("OpenReaderAt mismatch: got %q", string(part))
	}
}
