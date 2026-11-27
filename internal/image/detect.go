// SPDX-License-Identifier: GPL-3.0-only
package image

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Kind describes the automatically detected boot image category.
type Kind string

const (
	KindWindowsISO     Kind = "windows-iso"
	KindHybridLinuxISO Kind = "hybrid-linux-iso"
	KindStandardISO    Kind = "standard-iso"
	KindRawImage       Kind = "raw-image"
	KindCompressedRaw  Kind = "compressed-raw"
)

// Info summarizes an inspected OS image for UI display and automatic flash mode selection.
type Info struct {
	Path              string `json:"path"`
	FileName          string `json:"file_name"`
	SizeBytes         int64  `json:"size_bytes"`
	Kind              Kind   `json:"kind"`
	ISOFormat         string `json:"iso_format,omitempty"`
	VolumeLabel       string `json:"volume_label,omitempty"`
	HasEFI            bool   `json:"has_efi"`
	HasHybridMBR      bool   `json:"has_hybrid_mbr"`
	HasGPT            bool   `json:"has_gpt"`
	InstallWimPath    string `json:"install_wim_path,omitempty"`
	InstallWimBytes   uint64 `json:"install_wim_bytes,omitempty"`
	RequiresWimSplit  bool   `json:"requires_wim_split"`
	RecommendedMode   string `json:"recommended_mode"`
	Summary           string `json:"summary"`
}

const fat32MaxFileSize = (1 << 32) - 1 // 4,294,967,295 bytes

// Inspect analyzes an image file without extracting or mounting it.
func Inspect(imgPath string) (Info, error) {
	st, err := os.Stat(imgPath)
	if err != nil {
		return Info{}, err
	}
	if st.IsDir() {
		return Info{}, fmt.Errorf("image path is a directory: %s", imgPath)
	}

	info := Info{
		Path:            imgPath,
		FileName:        filepath.Base(imgPath),
		SizeBytes:       st.Size(),
		Kind:            KindRawImage,
		RecommendedMode: "raw",
	}

	lower := strings.ToLower(imgPath)
	if strings.HasSuffix(lower, ".gz") || strings.HasSuffix(lower, ".bz2") || strings.HasSuffix(lower, ".zip") {
		info.Kind = KindCompressedRaw
		info.RecommendedMode = "raw"
		info.Summary = fmt.Sprintf("Compressed Disk Image (%s) • Raw Stream Mode", strings.ToUpper(strings.TrimPrefix(filepath.Ext(lower), ".")))
		return info, nil
	}

	f, err := os.Open(imgPath)
	if err != nil {
		return Info{}, err
	}
	defer f.Close()

	// Check sector 0 MBR boot signature and sector 1 GPT signature.
	hdr := make([]byte, 1024)
	if n, _ := f.ReadAt(hdr, 0); n >= 512 {
		if hdr[510] == 0x55 && hdr[511] == 0xAA {
			// Check whether at least one MBR partition entry is non-empty.
			for p := 0; p < 4; p++ {
				partType := hdr[446+p*16+4]
				partSectors := binary.LittleEndian.Uint32(hdr[446+p*16+12 : 446+p*16+16])
				if partType != 0 && partSectors > 0 {
					info.HasHybridMBR = true
					break
				}
			}
		}
		if n >= 520 && string(hdr[512:520]) == "EFI PART" {
			info.HasGPT = true
		}
	}

	// Try UDF 1.02 first (Microsoft Windows 10/11 ISOs put full filenames & >4 GiB install.wim in UDF),
	// then fall back to ISO9660/Joliet.
	var fs ImageFS
	if udf, err := OpenUDF(f, st.Size()); err == nil {
		fs = udf
	} else if iso, err := OpenISO9660(f, st.Size()); err == nil {
		fs = iso
	}

	if fs != nil {
		info.ISOFormat = fs.Format()
		info.VolumeLabel = fs.VolumeLabel()

		var hasBootWim bool
		var wimPath string
		var wimSize uint64

		_ = fs.Walk(func(e Entry) error {
			lp := strings.ToLower(e.Path)
			if strings.HasPrefix(lp, "efi/boot/boot") && strings.HasSuffix(lp, ".efi") {
				info.HasEFI = true
			}
			if lp == "sources/boot.wim" {
				hasBootWim = true
			}
			if lp == "sources/install.wim" || lp == "sources/install.esd" {
				wimPath = e.Path
				wimSize = e.Size
			}
			return nil
		})

		if hasBootWim && wimPath != "" {
			info.Kind = KindWindowsISO
			info.InstallWimPath = wimPath
			info.InstallWimBytes = wimSize
			info.RequiresWimSplit = wimSize > fat32MaxFileSize
			info.RecommendedMode = "windows-fat32"
			if info.RequiresWimSplit {
				info.Summary = fmt.Sprintf("Windows Installer ISO (%s) • Auto-Split WIM (%.2f GiB) -> Secure Boot FAT32",
					info.ISOFormat, float64(wimSize)/(1024*1024*1024))
			} else {
				info.Summary = fmt.Sprintf("Windows Installer ISO (%s) • GPT FAT32 UEFI Mode", info.ISOFormat)
			}
			return info, nil
		}

		if info.HasHybridMBR || info.HasGPT {
			info.Kind = KindHybridLinuxISO
			info.RecommendedMode = "raw"
			info.Summary = fmt.Sprintf("Hybrid Bootable ISO (%s) • Direct Raw Flash Mode", info.ISOFormat)
			return info, nil
		}

		info.Kind = KindStandardISO
		info.RecommendedMode = "iso-fat32"
		info.Summary = fmt.Sprintf("Standard ISO (%s) • GPT FAT32 Extract Mode", info.ISOFormat)
		return info, nil
	}

	info.Kind = KindRawImage
	info.RecommendedMode = "raw"
	info.Summary = "Raw Disk Image • Direct Bit-for-Bit Flash Mode"
	return info, nil
}

// OpenImageFS opens an ISO image using UDF 1.02 (preferred) or ISO9660/Joliet.
func OpenImageFS(f *os.File) (ImageFS, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if udf, err := OpenUDF(f, st.Size()); err == nil {
		return udf, nil
	}
	if iso, err := OpenISO9660(f, st.Size()); err == nil {
		return iso, nil
	}
	return nil, fmt.Errorf("file is neither a valid UDF 1.02 nor ISO9660 image")
}
