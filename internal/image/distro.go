// SPDX-License-Identifier: GPL-3.0-only
package image

import (
	"io"
	"path"
	"strings"
)

// DistroFamily categorizes how a Linux live ISO's initramfs locates its root partition.
type DistroFamily string

const (
	DistroUbuntu   DistroFamily = "ubuntu"   // Ubuntu, Mint, Pop!_OS, Zorin, Elementary (casper)
	DistroFedora   DistroFamily = "fedora"   // Fedora, Rocky, Alma, Nobara, Bazzite (dracut)
	DistroVoid     DistroFamily = "void"     // Void Linux (dracut void-live)
	DistroArch     DistroFamily = "arch"     // Arch, EndeavourOS, CachyOS, Garuda (archiso)
	DistroManjaro  DistroFamily = "manjaro"  // Manjaro (miso)
	DistroDebian   DistroFamily = "debian"   // Debian, Kali, Parrot, Tails, MX (live-boot)
	DistroOpenSUSE DistroFamily = "opensuse" // openSUSE (kiwi / dracut)
	DistroGeneric  DistroFamily = "generic"
)

// LinuxBootProfile describes how to boot a Linux ISO from a dedicated GPT partition in GRUB2.
type LinuxBootProfile struct {
	Family      DistroFamily
	DisplayName string
	KernelPath  string   // e.g. "/casper/vmlinuz"
	InitrdPaths []string // e.g. ["/boot/intel_ucode.img", "/casper/initrd"]
	KernelArgs  string   // base args parsed from ISO grub.cfg / loader conf (without PARTUUID yet)
	ISOGrubCfg  string   // path to ISO's own grub.cfg if present (for configfile fallback)
	VolumeLabel string
	FSUUID      string // GRUB2 ISO9660 timestamp UUID
}

// DetectLinuxBoot inspects an ISO9660 filesystem to determine its distro family,
// kernel/initrd paths, and base kernel parameters for multi-partition GRUB2 multiboot.
func DetectLinuxBoot(isoFS ImageFS, fileName, volumeLabel, fsUUID string) LinuxBootProfile {
	prof := LinuxBootProfile{
		Family:      DistroGeneric,
		DisplayName: cleanDistroDisplayName(volumeLabel, fileName),
		VolumeLabel: volumeLabel,
		FSUUID:      fsUUID,
	}
	if isoFS == nil {
		return prof
	}

	filesLower := make(map[string]string) // lowercase path -> exact ISO path
	var allFiles []string
	_ = isoFS.Walk(func(e Entry) error {
		if !e.IsDir {
			lp := strings.ToLower(e.Path)
			filesLower[lp] = "/" + strings.TrimPrefix(e.Path, "/")
			allFiles = append(allFiles, lp)
		}
		return nil
	})

	hasFile := func(lp string) (string, bool) {
		p, ok := filesLower[lp]
		return p, ok
	}
	findFirst := func(prefixes []string, contains string) string {
		for _, lp := range allFiles {
			for _, pref := range prefixes {
				if strings.HasPrefix(lp, pref) && (contains == "" || strings.Contains(lp, contains)) {
					return filesLower[lp]
				}
			}
		}
		return ""
	}

	// Locate ISO's own grub.cfg (if any) to parse authentic kernel/initrd/cmdline flags.
	grubCandidates := []string{
		"boot/grub/grub.cfg",
		"boot/grub2/grub.cfg",
		"efi/boot/grub.cfg",
		"boot/grub/loopback.cfg",
	}
	for _, cand := range grubCandidates {
		if exact, ok := hasFile(cand); ok {
			if prof.ISOGrubCfg == "" {
				prof.ISOGrubCfg = exact
			}
			if k, inits, args := parseFirstGrubEntry(readISOFileText(isoFS, strings.TrimPrefix(exact, "/"))); k != "" {
				prof.KernelPath = k
				prof.InitrdPaths = inits
				prof.KernelArgs = args
				break
			}
		}
	}

	// Check systemd-boot loader entries (Arch, Pop!_OS, EndeavourOS, CachyOS).
	if prof.KernelPath == "" {
		for _, lp := range allFiles {
			if strings.HasPrefix(lp, "loader/entries/") && strings.HasSuffix(lp, ".conf") {
				if k, inits, args := parseSystemdBootEntry(readISOFileText(isoFS, strings.TrimPrefix(filesLower[lp], "/"))); k != "" {
					prof.KernelPath = k
					prof.InitrdPaths = inits
					prof.KernelArgs = args
					break
				}
			}
		}
	}

	// Detect distro family from characteristic files & volume label.
	lblUpper := strings.ToUpper(volumeLabel + " " + fileName)
	switch {
	case strings.Contains(lblUpper, "VOID") || findFirst([]string{"liveos/"}, "squashfs") != "" && strings.Contains(lblUpper, "VOID"):
		prof.Family = DistroVoid
	case findFirst([]string{"casper/"}, "vmlinuz") != "" || findFirst([]string{"casper/"}, "squashfs") != "":
		prof.Family = DistroUbuntu
	case findFirst([]string{"manjaro/"}, "") != "" || strings.Contains(lblUpper, "MANJARO"):
		prof.Family = DistroManjaro
	case findFirst([]string{"arch/boot/"}, "vmlinuz") != "" || strings.Contains(lblUpper, "ARCH") || strings.Contains(lblUpper, "ENDEAVOUR") || strings.Contains(lblUpper, "CACHY"):
		prof.Family = DistroArch
	case findFirst([]string{"images/pxeboot/"}, "vmlinuz") != "" || strings.Contains(lblUpper, "FEDORA") || strings.Contains(lblUpper, "NOBARA") || strings.Contains(lblUpper, "BAZZITE"):
		prof.Family = DistroFedora
	case findFirst([]string{"live/"}, "vmlinuz") != "" || findFirst([]string{"live/"}, "squashfs") != "":
		prof.Family = DistroDebian
	case findFirst([]string{"boot/x86_64/loader/"}, "linux") != "" || strings.Contains(lblUpper, "OPENSUSE"):
		prof.Family = DistroOpenSUSE
	}

	// Fill in fallback kernel/initrd paths if not already parsed from grub.cfg / loader.conf.
	if prof.KernelPath == "" {
		switch prof.Family {
		case DistroUbuntu:
			prof.KernelPath = firstNonEmpty(
				findFirst([]string{"casper/"}, "vmlinuz"),
			)
			if initrd := findFirst([]string{"casper/"}, "initrd"); initrd != "" {
				prof.InitrdPaths = []string{initrd}
			}
		case DistroFedora:
			prof.KernelPath = findFirst([]string{"images/pxeboot/"}, "vmlinuz")
			if initrd := findFirst([]string{"images/pxeboot/"}, "initrd"); initrd != "" {
				prof.InitrdPaths = []string{initrd}
			}
		case DistroVoid:
			prof.KernelPath = findFirst([]string{"boot/"}, "vmlinuz")
			if initrd := findFirst([]string{"boot/"}, "initrd"); initrd != "" {
				prof.InitrdPaths = []string{initrd}
			}
		case DistroArch:
			prof.KernelPath = findFirst([]string{"arch/boot/x86_64/", "boot/x86_64/"}, "vmlinuz")
			for _, u := range []string{"intel-ucode.img", "amd-ucode.img"} {
				if p := findFirst([]string{"arch/boot/", "boot/"}, u); p != "" {
					prof.InitrdPaths = append(prof.InitrdPaths, p)
				}
			}
			if initrd := findFirst([]string{"arch/boot/x86_64/", "boot/x86_64/"}, "initramfs"); initrd != "" {
				prof.InitrdPaths = append(prof.InitrdPaths, initrd)
			}
		case DistroManjaro:
			prof.KernelPath = findFirst([]string{"boot/"}, "vmlinuz")
			for _, u := range []string{"intel_ucode.img", "amd_ucode.img"} {
				if p := findFirst([]string{"boot/"}, u); p != "" {
					prof.InitrdPaths = append(prof.InitrdPaths, p)
				}
			}
			if initrd := findFirst([]string{"boot/"}, "initramfs"); initrd != "" {
				prof.InitrdPaths = append(prof.InitrdPaths, initrd)
			}
		case DistroDebian:
			prof.KernelPath = findFirst([]string{"live/"}, "vmlinuz")
			if initrd := findFirst([]string{"live/"}, "initrd"); initrd != "" {
				prof.InitrdPaths = []string{initrd}
			}
		case DistroOpenSUSE:
			prof.KernelPath = findFirst([]string{"boot/x86_64/loader/"}, "linux")
			if initrd := findFirst([]string{"boot/x86_64/loader/"}, "initrd"); initrd != "" {
				prof.InitrdPaths = []string{initrd}
			}
		}
	}

	return prof
}

// BuildKernelArgs returns the final Linux kernel command line pinned to partUUID so multiple
// distros on the same USB drive never collide when mounting their live squashfs.
func (p LinuxBootProfile) BuildKernelArgs(partUUID string) string {
	args := strings.TrimSpace(p.KernelArgs)

	switch p.Family {
	case DistroUbuntu:
		if args == "" {
			args = "boot=casper quiet splash"
		}
		if !strings.Contains(args, "boot=casper") {
			args = "boot=casper " + args
		}
		args = stripArgPrefix(args, "live-media=")
		args = stripArgPrefix(args, "iso-scan/filename=")
		return insertBeforeDashDash(args, "live-media=/dev/disk/by-partuuid/"+partUUID)

	case DistroFedora:
		if args == "" {
			args = "rd.live.image quiet"
		}
		args = replaceOrAddRootLive(args, "root=live:PARTUUID="+partUUID)
		return args

	case DistroVoid:
		if args == "" {
			args = "ro init=/sbin/init rd.luks=0 rd.md=0 rd.dm=0 loglevel=4 gpt add_efi_memmap"
		}
		args = replaceOrAddRootLive(args, "root=live:PARTUUID="+partUUID)
		return args

	case DistroArch:
		if args == "" {
			args = "archisobasedir=arch"
		}
		args = stripArgPrefix(args, "archisolabel=")
		args = stripArgPrefix(args, "archisosearchuuid=")
		args = stripArgPrefix(args, "archisodevice=")
		return strings.TrimSpace(args + " archisodevice=/dev/disk/by-partuuid/" + partUUID)

	case DistroManjaro:
		if args == "" {
			args = "misobasedir=manjaro driver=free"
		}
		args = stripArgPrefix(args, "misolabel=")
		if p.VolumeLabel != "" {
			args = strings.TrimSpace(args + " misolabel=" + p.VolumeLabel)
		}
		return args

	case DistroDebian:
		if args == "" {
			args = "boot=live components quiet splash"
		}
		if !strings.Contains(args, "boot=live") {
			args = "boot=live " + args
		}
		args = stripArgPrefix(args, "live-media=")
		return insertBeforeDashDash(args, "live-media=/dev/disk/by-partuuid/"+partUUID)

	case DistroOpenSUSE:
		if args == "" {
			args = "splash=silent quiet"
		}
		args = replaceOrAddRootLive(args, "root=live:PARTUUID="+partUUID)
		return args

	default:
		if strings.Contains(args, "root=live:CDLABEL=") || strings.Contains(args, "root=live:LABEL=") {
			return replaceOrAddRootLive(args, "root=live:PARTUUID="+partUUID)
		}
		return args
	}
}

func readISOFileText(isoFS ImageFS, relPath string) string {
	rc, sz, err := isoFS.Open(relPath)
	if err != nil || sz > 512*1024 {
		if rc != nil {
			_ = rc.Close()
		}
		return ""
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		return ""
	}
	return string(b)
}

func parseFirstGrubEntry(cfg string) (kernel string, initrds []string, args string) {
	if cfg == "" {
		return "", nil, ""
	}
	lines := strings.Split(cfg, "\n")
	inEntry := false
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "menuentry ") {
			if kernel != "" {
				break
			}
			inEntry = true
			continue
		}
		if !inEntry {
			continue
		}
		if line == "}" && kernel != "" {
			break
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		cmd := fields[0]
		if (cmd == "linux" || cmd == "linuxefi") && kernel == "" {
			k := fields[1]
			if !strings.HasPrefix(k, "$") {
				kernel = k
				if len(fields) > 2 {
					args = cleanGrubVars(strings.Join(fields[2:], " "))
				}
			}
		} else if cmd == "initrd" || cmd == "initrdefi" {
			for _, f := range fields[1:] {
				if !strings.HasPrefix(f, "$") {
					initrds = append(initrds, f)
				}
			}
		}
	}
	return kernel, initrds, args
}

func parseSystemdBootEntry(cfg string) (kernel string, initrds []string, args string) {
	for _, raw := range strings.Split(cfg, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "linux":
			kernel = fields[1]
		case "initrd":
			initrds = append(initrds, fields[1])
		case "options":
			args = strings.Join(fields[1:], " ")
		}
	}
	return kernel, initrds, args
}

func cleanGrubVars(args string) string {
	var kept []string
	for _, tok := range strings.Fields(args) {
		if strings.Contains(tok, "$") {
			continue
		}
		kept = append(kept, tok)
	}
	return strings.Join(kept, " ")
}

func stripArgPrefix(args, prefix string) string {
	var out []string
	for _, tok := range strings.Fields(args) {
		if strings.HasPrefix(tok, prefix) {
			continue
		}
		out = append(out, tok)
	}
	return strings.Join(out, " ")
}

func replaceOrAddRootLive(args, replacement string) string {
	var out []string
	replaced := false
	for _, tok := range strings.Fields(args) {
		if strings.HasPrefix(tok, "root=live:") {
			out = append(out, replacement)
			replaced = true
			continue
		}
		out = append(out, tok)
	}
	if !replaced {
		out = append([]string{replacement}, out...)
	}
	return strings.Join(out, " ")
}

func insertBeforeDashDash(args, extra string) string {
	toks := strings.Fields(args)
	for i, t := range toks {
		if t == "---" || t == "--" {
			res := append([]string{}, toks[:i]...)
			res = append(res, extra)
			res = append(res, toks[i:]...)
			return strings.Join(res, " ")
		}
	}
	return strings.TrimSpace(args + " " + extra)
}

func cleanDistroDisplayName(label, fileName string) string {
	if strings.TrimSpace(label) != "" {
		return strings.TrimSpace(label)
	}
	base := path.Base(fileName)
	return strings.TrimSuffix(base, path.Ext(base))
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
