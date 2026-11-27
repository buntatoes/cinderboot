// SPDX-License-Identifier: GPL-3.0-only
package flash

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/buntatoes/cinderboot/internal/device"
	"github.com/buntatoes/cinderboot/internal/fs"
	"github.com/buntatoes/cinderboot/internal/image"
)

const multibootESPSizeBytes uint64 = 64 * 1024 * 1024 // 64 MiB FAT32 EFI System Partition

type multibootDistro struct {
	path      string
	fileName  string
	sizeBytes uint64
	profile   image.LinuxBootProfile
	efiBundle image.EFIBundle
	part      fs.GPTPartition
	partUUID  string
	chainEFI  string // path inside ESP to native chainload EFI binary (if available)
}

func flashMultibootToDrive(ctx context.Context, spec JobSpec, drv device.Drive, emit ProgressSink) error {
	f, err := device.OpenRawWrite(drv)
	if err != nil {
		return err
	}
	if err := WriteMultiboot(ctx, spec, f, drv.SizeBytes, drv.SectorSize, emit); err != nil {
		_ = f.Close()
		return err
	}
	emit(ProgressEvent{
		Phase:   "sync",
		Percent: 100,
		Message: "Flushing multiboot metadata and device caches...",
	})
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync target device: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close target device: %w", err)
	}
	_ = device.RereadPartitionTablePath(drv.DevicePath)

	emit(ProgressEvent{
		Phase:   "complete",
		Percent: 100,
		Done:    true,
		Message: fmt.Sprintf("Multi-distro UEFI bootable USB created (%d distros)", len(spec.EffectiveImages())),
	})
	return nil
}

// WriteMultiboot creates a GPT multi-partition UEFI multiboot USB drive in 100% pure Go:
//   - Partition 1: 64 MiB FAT32 EFI System Partition (CINDERBOOT) holding a signed GRUB2
//     bootloader extracted from one of the selected Linux ISOs plus a generated boot menu.
//   - Partitions 2..N+1: One 1 MiB-aligned dedicated GPT partition per Linux ISO written raw
//     (no 4 GiB FAT32 limit; each distro keeps its native ISO9660 volume and unique PARTUUID).
func WriteMultiboot(
	ctx context.Context,
	spec JobSpec,
	dst io.ReadWriteSeeker,
	diskSize uint64,
	sectorSize uint32,
	emit ProgressSink,
) error {
	if sectorSize == 0 {
		sectorSize = 512
	}
	sec := uint64(sectorSize)
	alignSecs := (1024 * 1024) / sec
	if alignSecs < 34 {
		alignSecs = 34
	}

	paths := spec.EffectiveImages()
	if len(paths) == 0 {
		return fmt.Errorf("multiboot requires at least one Linux ISO")
	}

	if emit != nil {
		emit(ProgressEvent{
			Phase:   "prepare",
			Message: fmt.Sprintf("Inspecting %d Linux ISO(s) and extracting UEFI bootloaders...", len(paths)),
		})
	}

	distros := make([]multibootDistro, 0, len(paths))
	var totalISOBytes uint64
	hostIdx := -1

	for idx, p := range paths {
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := image.Inspect(p)
		if err != nil {
			return fmt.Errorf("inspect ISO %q: %w", filepath.Base(p), err)
		}
		if info.Kind == image.KindWindowsISO {
			return fmt.Errorf("Windows ISO %q cannot be combined in Linux Multiboot mode; flash Windows ISOs individually", info.FileName)
		}
		if info.Kind == image.KindCompressedRaw {
			return fmt.Errorf("compressed image %q is not supported in Linux Multiboot mode (provide uncompressed .iso files)", info.FileName)
		}

		f, err := os.Open(p)
		if err != nil {
			return fmt.Errorf("open ISO %q: %w", filepath.Base(p), err)
		}
		isoReader, isoErr := image.OpenISO9660(f, info.SizeBytes)
		if isoErr != nil {
			_ = f.Close()
			return fmt.Errorf("%q is not a valid ISO9660 Linux image: %w", info.FileName, isoErr)
		}
		efiBundle := image.ExtractISOEFIBundle(f, info.SizeBytes, isoReader)
		profile := image.DetectLinuxBoot(isoReader, info.FileName, isoReader.VolumeLabel(), isoReader.FSUUID())
		_ = f.Close()

		d := multibootDistro{
			path:      p,
			fileName:  info.FileName,
			sizeBytes: uint64(info.SizeBytes),
			profile:   profile,
			efiBundle: efiBundle,
		}
		distros = append(distros, d)
		totalISOBytes += uint64(info.SizeBytes)

		// Prefer an ISO with both Shim and GRUB2 (Ubuntu/Fedora/Debian/Mint/openSUSE), then any GRUB2 ISO.
		if efiBundle.HasGRUB && efiBundle.HasShim && hostIdx == -1 {
			hostIdx = idx
		}
	}
	if hostIdx == -1 {
		for idx, d := range distros {
			if d.efiBundle.HasGRUB {
				hostIdx = idx
				break
			}
		}
	}
	if hostIdx == -1 {
		return fmt.Errorf("none of the selected Linux ISOs contain a UEFI GRUB2 bootloader (include at least one GRUB2-based ISO such as Ubuntu, Fedora, Debian, Mint, Manjaro, Void, or openSUSE)")
	}

	// Plan 1 MiB-aligned GPT partitions: Partition 1 = FAT32 ESP, Partitions 2..N+1 = raw ISOs.
	totalSectors := diskSize / sec
	if totalSectors < 4096 {
		return fmt.Errorf("target drive too small for multiboot GPT")
	}
	lastUsable := totalSectors - 34

	espSectors := multibootESPSizeBytes / sec
	espFirstLBA := alignSecs
	espLastLBA := espFirstLBA + espSectors - 1

	espLabel := strings.TrimSpace(spec.VolumeLabel)
	if espLabel == "" {
		espLabel = "CINDERBOOT"
	}

	gptParts := make([]fs.GPTPartition, 0, len(distros)+1)
	gptParts = append(gptParts, fs.GPTPartition{
		TypeGUID:   fs.GPTTypeEFI,
		UniqueGUID: fs.NewRandomGUID(),
		FirstLBA:   espFirstLBA,
		LastLBA:    espLastLBA,
		Name:       "CINDERBOOT_ESP",
	})

	nextLBA := ((espLastLBA + 1 + alignSecs - 1) / alignSecs) * alignSecs
	for i := range distros {
		isoSecs := (distros[i].sizeBytes + sec - 1) / sec
		alignedSecs := ((isoSecs + alignSecs - 1) / alignSecs) * alignSecs
		first := nextLBA
		last := first + alignedSecs - 1
		if last > lastUsable {
			return fmt.Errorf("selected Linux ISOs (%s + 64 MiB boot menu) exceed target USB drive capacity (%s)",
				device.FormatBytes(totalISOBytes), device.FormatBytes(diskSize))
		}
		guid := fs.NewRandomGUID()
		partName := distros[i].profile.DisplayName
		if len(partName) > 32 {
			partName = partName[:32]
		}
		p := fs.GPTPartition{
			TypeGUID:   fs.GPTTypeBasicData,
			UniqueGUID: guid,
			FirstLBA:   first,
			LastLBA:    last,
			Name:       partName,
		}
		distros[i].part = p
		distros[i].partUUID = fs.FormatGUID(guid)
		gptParts = append(gptParts, p)
		nextLBA = last + 1
	}

	if emit != nil {
		emit(ProgressEvent{
			Phase:   "partition",
			Message: fmt.Sprintf("Writing GPT table (%d partitions) and creating UEFI multiboot menu...", len(gptParts)),
		})
	}
	if err := fs.WipePartitionTables(dst, diskSize, sectorSize); err != nil {
		return fmt.Errorf("wipe old partition tables: %w", err)
	}
	if err := fs.WriteGPT(dst, diskSize, sectorSize, gptParts); err != nil {
		return fmt.Errorf("write multiboot GPT: %w", err)
	}

	// Format Partition 1 (ESP) as FAT32 and install the extracted GRUB2 bootloader + multiboot menu.
	fw, err := fs.FormatFAT32(dst, int64(espFirstLBA*sec), espSectors*sec, sectorSize, espLabel)
	if err != nil {
		return fmt.Errorf("format multiboot ESP FAT32: %w", err)
	}
	espUUID := fw.VolumeSerialString()

	if err := installHostEFI(ctx, fw, distros[hostIdx].efiBundle); err != nil {
		return fmt.Errorf("install host UEFI bootloader: %w", err)
	}

	// Copy each distro's own EFI binaries under /EFI/cinderboot/d<N>/ for optional native UEFI chainloading.
	for i := range distros {
		if err := ctx.Err(); err != nil {
			return err
		}
		chainRel, err := installDistroChainloadEFI(ctx, fw, i+1, distros[i].efiBundle)
		if err != nil {
			return fmt.Errorf("install chainload EFI for %s: %w", distros[i].fileName, err)
		}
		distros[i].chainEFI = chainRel
	}

	// Marker file so Ubuntu's signed grubx64.efi matches Partition 1 first instead of jumping to Partition 2.
	if err := fw.WriteBytes(".disk/info", []byte("Cinderboot Multiboot USB\n")); err != nil {
		return fmt.Errorf("write .disk/info marker: %w", err)
	}

	menuCfg := generateMultibootGrubCfg(distros, espUUID)
	if err := fw.WriteBytes("boot/grub/grub.cfg", []byte(menuCfg)); err != nil {
		return fmt.Errorf("write /boot/grub/grub.cfg: %w", err)
	}

	// Write stub configs in vendor-specific GRUB search paths so whichever distro provided
	// grubx64.efi (Ubuntu, Fedora, Debian, Manjaro, openSUSE) always loads Cinderboot's menu.
	stubCfg := fmt.Sprintf("search --no-floppy --fs-uuid --set=root %s\nset prefix=($root)/boot/grub\nconfigfile ($root)/boot/grub/grub.cfg\n", espUUID)
	for _, stubPath := range []string{
		"EFI/BOOT/grub.cfg",
		"EFI/ubuntu/grub.cfg",
		"EFI/fedora/grub.cfg",
		"EFI/debian/grub.cfg",
	} {
		if err := fw.WriteBytes(stubPath, []byte(stubCfg)); err != nil {
			return fmt.Errorf("write %s: %w", stubPath, err)
		}
	}

	if err := fw.Close(); err != nil {
		return fmt.Errorf("finalize multiboot ESP FAT32: %w", err)
	}

	// Stream each Linux ISO raw into its dedicated GPT partition with periodic sync & cancel checks.
	tracker := newSpeedTracker(totalISOBytes)
	buf := make([]byte, rawChunkSize)
	type syncer interface {
		Sync() error
	}
	dstSync, canSync := dst.(syncer)

	var totalWritten uint64
	var sinceSync uint64

	for i, d := range distros {
		if err := ctx.Err(); err != nil {
			return err
		}
		partStartByte := d.part.FirstLBA * sec
		if _, err := dst.Seek(int64(partStartByte), io.SeekStart); err != nil {
			return fmt.Errorf("seek to partition %d (%s): %w", i+2, d.fileName, err)
		}

		srcFile, err := os.Open(d.path)
		if err != nil {
			return fmt.Errorf("open ISO %q: %w", d.fileName, err)
		}

		var partOffset uint64
		for {
			if err := ctx.Err(); err != nil {
				_ = srcFile.Close()
				return err
			}
			n, rErr := readFullOrEOF(srcFile, buf)
			if n > 0 {
				writeSlice := buf[:n]
				if rem := n % int(sectorSize); rem != 0 {
					pad := int(sectorSize) - rem
					if n+pad <= len(buf) {
						clear(buf[n : n+pad])
						writeSlice = buf[:n+pad]
					}
				}
				if wErr := writeWithRecovery(ctx, dst, partStartByte+partOffset, writeSlice, emit); wErr != nil {
					_ = srcFile.Close()
					return fmt.Errorf("write %s at offset %d: %w", d.fileName, partOffset, wErr)
				}
				partOffset += uint64(n)
				totalWritten += uint64(n)
				sinceSync += uint64(len(writeSlice))
				if canSync && sinceSync >= rawSyncInterval {
					if sErr := dstSync.Sync(); sErr != nil {
						_ = srcFile.Close()
						return fmt.Errorf("flush while writing %s: %w", d.fileName, sErr)
					}
					sinceSync = 0
				}
				if tracker.shouldEmit(false) && emit != nil {
					spd := tracker.speed(totalWritten)
					emit(ProgressEvent{
						Phase:      "flashing",
						BytesDone:  totalWritten,
						BytesTotal: totalISOBytes,
						SpeedBPS:   spd,
						Percent:    tracker.percent(totalWritten),
						Message:    fmt.Sprintf("Flashing [%d/%d] %s (%s/s)", i+1, len(distros), d.profile.DisplayName, device.FormatBytes(uint64(spd))),
					})
				}
			}
			if rErr != nil {
				if errors.Is(rErr, io.EOF) {
					break
				}
				_ = srcFile.Close()
				return fmt.Errorf("read ISO %q: %w", d.fileName, rErr)
			}
		}
		_ = srcFile.Close()
	}

	if emit != nil {
		emit(ProgressEvent{
			Phase:      "flashing",
			BytesDone:  totalWritten,
			BytesTotal: totalISOBytes,
			SpeedBPS:   tracker.speed(totalWritten),
			Percent:    100,
			Message:    fmt.Sprintf("Wrote %d Linux ISOs (%s)", len(distros), device.FormatBytes(totalWritten)),
		})
	}
	return nil
}

func installHostEFI(ctx context.Context, fw *fs.FAT32Writer, bundle image.EFIBundle) error {
	keys := make([]string, 0, len(bundle.Files))
	for k := range bundle.Files {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var wroteBootX64 bool
	var grubBytes []byte
	for _, k := range keys {
		if err := ctx.Err(); err != nil {
			return err
		}
		lp := strings.ToLower(k)
		if !strings.HasPrefix(lp, "efi/boot/") || !strings.HasSuffix(lp, ".efi") {
			continue
		}
		base := path.Base(k)
		baseLower := strings.ToLower(base)
		destName := base
		if baseLower == "bootx64.efi" {
			destName = "BOOTX64.EFI"
			wroteBootX64 = true
		} else if baseLower == "grubx64.efi" {
			grubBytes = bundle.Files[k]
		}
		if err := fw.WriteFileCtx(ctx, "EFI/BOOT/"+destName, strings.NewReader(string(bundle.Files[k])), uint64(len(bundle.Files[k])), nil); err != nil {
			return err
		}
	}
	// If the ISO had grubx64.efi without BOOTX64.EFI, install grubx64.efi directly as BOOTX64.EFI.
	if !wroteBootX64 && len(grubBytes) > 0 {
		if err := fw.WriteBytes("EFI/BOOT/BOOTX64.EFI", grubBytes); err != nil {
			return err
		}
		wroteBootX64 = true
	}
	if !wroteBootX64 {
		return fmt.Errorf("host ISO EFI bundle did not contain BOOTX64.EFI or grubx64.efi")
	}
	return nil
}

func installDistroChainloadEFI(ctx context.Context, fw *fs.FAT32Writer, idx int, bundle image.EFIBundle) (string, error) {
	if len(bundle.Files) == 0 {
		return "", nil
	}
	dir := fmt.Sprintf("EFI/cinderboot/d%d", idx)
	keys := make([]string, 0, len(bundle.Files))
	for k := range bundle.Files {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var chainPath string
	for _, k := range keys {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		lp := strings.ToLower(k)
		if !strings.HasPrefix(lp, "efi/boot/") || !strings.HasSuffix(lp, ".efi") {
			continue
		}
		base := path.Base(k)
		dest := dir + "/" + base
		if err := fw.WriteBytes(dest, bundle.Files[k]); err != nil {
			return "", err
		}
		bl := strings.ToLower(base)
		if bl == "bootx64.efi" || bl == "shimx64.efi" {
			chainPath = "/" + dest
		} else if chainPath == "" && strings.HasSuffix(bl, ".efi") {
			chainPath = "/" + dest
		}
	}
	return chainPath, nil
}

func generateMultibootGrubCfg(distros []multibootDistro, espUUID string) string {
	var b strings.Builder
	b.WriteString("# Generated by Cinderboot Multi-Distro UEFI Boot Manager\n")
	b.WriteString("set timeout=30\n")
	b.WriteString("set default=0\n")
	b.WriteString("insmod all_video\n")
	b.WriteString("insmod part_gpt\n")
	b.WriteString("insmod fat\n")
	b.WriteString("insmod iso9660\n")
	b.WriteString("insmod search_fs_uuid\n")
	b.WriteString("insmod search_label\n")
	b.WriteString("insmod chain\n\n")

	for i, d := range distros {
		partNum := i + 2
		title := sanitizeGrubTitle(d.profile.DisplayName)
		if d.profile.Family != image.DistroGeneric {
			title = fmt.Sprintf("%s (%s)", title, strings.ToUpper(string(d.profile.Family)))
		}
		fmt.Fprintf(&b, "menuentry \"%s\" {\n", title)
		writePartitionSearch(&b, d.profile.FSUUID, d.profile.VolumeLabel, partNum)

		if d.profile.KernelPath != "" {
			args := d.profile.BuildKernelArgs(d.partUUID)
			fmt.Fprintf(&b, "    linux %s %s\n", d.profile.KernelPath, args)
			if len(d.profile.InitrdPaths) > 0 {
				fmt.Fprintf(&b, "    initrd %s\n", strings.Join(d.profile.InitrdPaths, " "))
			}
		} else if d.profile.ISOGrubCfg != "" {
			fmt.Fprintf(&b, "    configfile %s\n", d.profile.ISOGrubCfg)
		} else if d.chainEFI != "" {
			fmt.Fprintf(&b, "    search --no-floppy --fs-uuid --set=root %s\n", espUUID)
			fmt.Fprintf(&b, "    chainloader %s\n", d.chainEFI)
		}
		b.WriteString("}\n\n")
	}

	// Provide native UEFI chainloader submenu for mixed-vendor Secure Boot compatibility.
	hasAnyChain := false
	for _, d := range distros {
		if d.chainEFI != "" {
			hasAnyChain = true
			break
		}
	}
	if hasAnyChain {
		b.WriteString("submenu \"Native UEFI Chainload (Secure Boot / Fallback)\" {\n")
		for _, d := range distros {
			if d.chainEFI == "" {
				continue
			}
			title := sanitizeGrubTitle(d.profile.DisplayName)
			fmt.Fprintf(&b, "    menuentry \"Chainload %s\" {\n", title)
			fmt.Fprintf(&b, "        search --no-floppy --fs-uuid --set=root %s\n", espUUID)
			fmt.Fprintf(&b, "        chainloader %s\n", d.chainEFI)
			b.WriteString("    }\n")
		}
		b.WriteString("}\n\n")
	}

	b.WriteString("menuentry \"UEFI Firmware Settings\" {\n    fwsetup\n}\n\n")
	b.WriteString("menuentry \"Reboot\" {\n    reboot\n}\n")
	return b.String()
}

func writePartitionSearch(b *strings.Builder, fsUUID, label string, gptPartNum int) {
	if fsUUID != "" {
		fmt.Fprintf(b, "    search --no-floppy --fs-uuid --set=root %s\n", fsUUID)
	} else if label != "" {
		fmt.Fprintf(b, "    search --no-floppy --label --set=root \"%s\"\n", sanitizeGrubTitle(label))
	} else {
		fmt.Fprintf(b, "    set root=(hd0,gpt%d)\n", gptPartNum)
	}
}

func sanitizeGrubTitle(s string) string {
	s = strings.ReplaceAll(s, `"`, "'")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return strings.TrimSpace(s)
}
