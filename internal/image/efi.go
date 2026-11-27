// SPDX-License-Identifier: GPL-3.0-only
package image

import (
	"encoding/binary"
	"io"
	"strings"

	"github.com/buntatoes/cinderboot/internal/fs"
)

// EFIBundle holds UEFI boot binaries extracted directly from a Linux ISO
// (appended GPT ESP, MBR 0xEF partition, El Torito EFI image, or ISO9660 /EFI tree).
type EFIBundle struct {
	Files       map[string][]byte // relative paths like "EFI/BOOT/BOOTX64.EFI"
	HasGRUB     bool
	HasShim     bool
	SourceLabel string
}

// ExtractISOEFIBundle extracts UEFI bootloaders (BOOTX64.EFI, grubx64.efi, mmx64.efi, etc.)
// from a Linux ISO image using 100% pure Go.
func ExtractISOEFIBundle(r io.ReaderAt, totalSize int64, isoFS ImageFS) EFIBundle {
	bundle := EFIBundle{
		Files: make(map[string][]byte),
	}
	const maxEFIFile = 16 * 1024 * 1024 // 16 MiB safety cap per EFI binary

	addFATRegion := func(off, length int64, src string) bool {
		if off < 0 || length < 512 || off+length > totalSize {
			return false
		}
		sr := io.NewSectionReader(r, off, length)
		fr, err := fs.OpenFATReader(sr, length)
		if err != nil {
			return false
		}
		files, err := fr.ReadAllFiles(maxEFIFile)
		if err != nil || len(files) == 0 {
			return false
		}
		added := false
		for p, data := range files {
			lp := strings.ToLower(p)
			if strings.HasPrefix(lp, "efi/") || strings.HasPrefix(lp, "boot/grub/") || strings.HasPrefix(lp, "loader/") {
				bundle.Files[p] = data
				added = true
			}
		}
		if added && bundle.SourceLabel == "" {
			bundle.SourceLabel = src
		}
		return added
	}

	// 1. Check GPT EFI System Partition (modern Ubuntu 20.10+, Fedora, Debian 12+, Mint, openSUSE, EndeavourOS).
	if parts, err := fs.ParseGPTPartitions(r, totalSize, 512); err == nil {
		for _, p := range parts {
			if p.TypeGUID == fs.GPTTypeEFI && p.LastLBA >= p.FirstLBA {
				off := int64(p.FirstLBA) * 512
				length := int64(p.LastLBA-p.FirstLBA+1) * 512
				if addFATRegion(off, length, "GPT EFI System Partition") {
					break
				}
			}
		}
	}

	// 2. Check MBR 0xEF EFI partition (Arch, Manjaro, older hybrid ISOs).
	if len(bundle.Files) == 0 && totalSize >= 512 {
		mbr := make([]byte, 512)
		if _, err := r.ReadAt(mbr, 0); err == nil && mbr[510] == 0x55 && mbr[511] == 0xAA {
			for p := 0; p < 4; p++ {
				off := 446 + p*16
				if mbr[off+4] == 0xEF {
					startLBA := uint64(binary.LittleEndian.Uint32(mbr[off+8 : off+12]))
					numSecs := uint64(binary.LittleEndian.Uint32(mbr[off+12 : off+16]))
					if startLBA > 0 && numSecs > 0 {
						if addFATRegion(int64(startLBA*512), int64(numSecs*512), "MBR 0xEF Partition") {
							break
						}
					}
				}
			}
		}
	}

	// 3. Check El Torito EFI Boot Catalog entry.
	if len(bundle.Files) == 0 {
		if iso, ok := isoFS.(*ISO9660Reader); ok && iso.HasElTorito() && iso.ElToritoCatalogLBA() > 0 {
			catOff := int64(iso.ElToritoCatalogLBA()) * isoSectorSize
			if catOff+isoSectorSize <= totalSize {
				cat := make([]byte, isoSectorSize)
				if _, err := r.ReadAt(cat, catOff); err == nil {
					for pos := 32; pos+64 <= len(cat); pos += 32 {
						hdrID := cat[pos]
						platID := cat[pos+1]
						if (hdrID == 0x90 || hdrID == 0x91) && platID == 0xEF {
							entry := cat[pos+32 : pos+64]
							if entry[0] == 0x88 { // Bootable
								secCnt := uint64(binary.LittleEndian.Uint16(entry[6:8]))
								loadRBA := uint64(binary.LittleEndian.Uint32(entry[8:12]))
								if loadRBA > 0 {
									imgOff := int64(loadRBA) * isoSectorSize
									imgLen := int64(secCnt) * 512
									if imgLen == 0 || imgOff+imgLen > totalSize {
										imgLen = totalSize - imgOff
										if imgLen > 64*1024*1024 {
											imgLen = 64 * 1024 * 1024
										}
									}
									if addFATRegion(imgOff, imgLen, "El Torito EFI Image") {
										break
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// 4. Fallback: check ISO9660 tree directly for /EFI/BOOT/* or embedded efiboot.img.
	if len(bundle.Files) == 0 && isoFS != nil {
		_ = isoFS.Walk(func(e Entry) error {
			if e.IsDir || e.Size == 0 || e.Size > maxEFIFile {
				return nil
			}
			lp := strings.ToLower(e.Path)
			if strings.HasPrefix(lp, "efi/boot/") || strings.HasSuffix(lp, ".efi") {
				rc, _, err := isoFS.Open(e.Path)
				if err == nil {
					data, rErr := io.ReadAll(rc)
					_ = rc.Close()
					if rErr == nil {
						bundle.Files[e.Path] = data
						if bundle.SourceLabel == "" {
							bundle.SourceLabel = "ISO9660 /EFI"
						}
					}
				}
			}
			return nil
		})
	}

	for p := range bundle.Files {
		lp := strings.ToLower(p)
		if strings.Contains(lp, "grubx64.efi") || strings.Contains(lp, "grub") && strings.HasSuffix(lp, ".efi") {
			bundle.HasGRUB = true
		}
		if strings.Contains(lp, "bootx64.efi") || strings.Contains(lp, "shimx64.efi") {
			bundle.HasShim = true
		}
	}
	return bundle
}
