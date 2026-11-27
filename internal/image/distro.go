// SPDX-License-Identifier: GPL-3.0-only
package image

import (
	"io"
	"path"
	"sort"
	"strings"
)

// DistroFamily categorizes how a Linux live ISO's initramfs locates its root partition.
type DistroFamily string

const (
	DistroPopOS    DistroFamily = "pop-os"   // Pop!_OS (casper with custom casper_* dir & systemd-boot/isolinux)
	DistroUbuntu   DistroFamily = "ubuntu"   // Ubuntu, Mint, Zorin, Elementary (casper)
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
	KernelPath  string   // e.g. "/casper/vmlinuz" or "/casper_pop-os_.../vmlinuz.efi"
	InitrdPaths []string // e.g. ["/boot/intel_ucode.img", "/casper/initrd"]
	KernelArgs  string   // base args parsed from ISO grub.cfg / loader conf / isolinux.cfg (without PARTUUID yet)
	ISOGrubCfg  string   // path to ISO's own grub.cfg if present (for configfile fallback)
	CasperDir   string   // casper live directory inside ISO (e.g. "/casper_pop-os_22.04_amd64_intel_42")
	VolumeLabel string
	FSUUID      string // GRUB2 ISO9660 timestamp UUID
}

// DetectLinuxBoot inspects an ISO9660 filesystem to determine its distro family,
// kernel/initrd paths, and base kernel parameters for multi-partition GRUB2 multiboot.
func DetectLinuxBoot(isoFS ImageFS, fileName, volumeLabel, fsUUID string) LinuxBootProfile {
	return DetectLinuxBootWithEFI(isoFS, nil, fileName, volumeLabel, fsUUID)
}

// DetectLinuxBootWithEFI inspects an ISO9660 filesystem together with any files extracted
// from its appended EFI System Partition (such as Pop!_OS systemd-boot loader/entries/*.conf)
// to determine its distro family, exact ISO9660 kernel/initrd paths, and base kernel arguments.
func DetectLinuxBootWithEFI(isoFS ImageFS, efiFiles map[string][]byte, fileName, volumeLabel, fsUUID string) LinuxBootProfile {
	prof := LinuxBootProfile{
		Family:      DistroGeneric,
		DisplayName: cleanDistroDisplayName(volumeLabel, fileName),
		VolumeLabel: volumeLabel,
		FSUUID:      fsUUID,
	}
	if isoFS == nil {
		return prof
	}

	filesLower := make(map[string]string) // lowercase path -> exact ISO path with leading "/"
	var allFiles []string
	_ = isoFS.Walk(func(e Entry) error {
		if !e.IsDir {
			lp := strings.ToLower(strings.TrimPrefix(e.Path, "/"))
			filesLower[lp] = "/" + strings.TrimPrefix(e.Path, "/")
			allFiles = append(allFiles, lp)
		}
		return nil
	})
	sort.Strings(allFiles)

	efiLower := make(map[string][]byte, len(efiFiles))
	efiKeys := make([]string, 0, len(efiFiles))
	for k, v := range efiFiles {
		lp := strings.ToLower(strings.TrimPrefix(strings.ReplaceAll(k, `\`, "/"), "/"))
		efiLower[lp] = v
		efiKeys = append(efiKeys, lp)
	}
	sort.Strings(efiKeys)

	hasFile := func(lp string) (string, bool) {
		p, ok := filesLower[lp]
		return p, ok
	}
	resolveISOPath := func(p string) (string, bool) {
		norm := strings.ToLower(strings.TrimPrefix(strings.ReplaceAll(strings.TrimSpace(p), `\`, "/"), "/"))
		if norm == "" {
			return "", false
		}
		exact, ok := filesLower[norm]
		return exact, ok
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
	findInCasperDir := func(contains string) string {
		for _, lp := range allFiles {
			slash := strings.IndexByte(lp, '/')
			if slash <= 0 {
				continue
			}
			topDir := lp[:slash]
			if topDir != "casper" && !strings.HasPrefix(topDir, "casper_") && !strings.HasPrefix(topDir, "casper-") {
				continue
			}
			base := lp[slash+1:]
			if strings.Contains(base, "/") || isMetadataSidecar(base) {
				continue
			}
			if contains == "" || strings.Contains(base, contains) {
				return filesLower[lp]
			}
		}
		return ""
	}

	// 1. Locate ISO's own grub.cfg (if any) to parse authentic kernel/initrd/cmdline flags.
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
	if prof.KernelPath == "" {
		for _, cand := range grubCandidates {
			if raw, ok := efiLower[cand]; ok {
				if k, inits, args := parseFirstGrubEntry(string(raw)); k != "" {
					prof.KernelPath = k
					prof.InitrdPaths = inits
					prof.KernelArgs = args
					break
				}
			}
		}
	}

	// 2. Check systemd-boot loader entries in both ISO9660 and the appended FAT ESP
	// (Pop!_OS, Arch, EndeavourOS, CachyOS).
	if prof.KernelPath == "" {
		type loaderCandidate struct {
			name string
			text string
		}
		var loaders []loaderCandidate
		for _, lp := range allFiles {
			if strings.HasPrefix(lp, "loader/entries/") && strings.HasSuffix(lp, ".conf") {
				loaders = append(loaders, loaderCandidate{
					name: path.Base(lp),
					text: readISOFileText(isoFS, strings.TrimPrefix(filesLower[lp], "/")),
				})
			}
		}
		for _, lp := range efiKeys {
			if strings.HasPrefix(lp, "loader/entries/") && strings.HasSuffix(lp, ".conf") {
				loaders = append(loaders, loaderCandidate{
					name: path.Base(lp),
					text: string(efiLower[lp]),
				})
			}
		}
		// Prioritize primary live entries ahead of recovery/fallback/memtest entries.
		sort.SliceStable(loaders, func(i, j int) bool {
			return loaderEntryPriority(loaders[i].name) < loaderEntryPriority(loaders[j].name)
		})
		for _, cand := range loaders {
			if k, inits, args := parseSystemdBootEntry(cand.text); k != "" {
				prof.KernelPath = k
				prof.InitrdPaths = inits
				prof.KernelArgs = args
				break
			}
		}
	}

	// 3. Check ISOLINUX / SYSLINUX configs (Pop!_OS, Debian/Ubuntu derivatives without grub.cfg).
	if prof.KernelPath == "" {
		isoLinuxCandidates := []string{
			"isolinux/isolinux.cfg",
			"isolinux/live.cfg",
			"isolinux/txt.cfg",
			"syslinux/syslinux.cfg",
			"boot/syslinux/syslinux.cfg",
		}
		visited := make(map[string]bool)
		for _, cand := range isoLinuxCandidates {
			if k, inits, args := parseIsolinuxConfig(isoFS, filesLower, cand, visited, 0); k != "" {
				prof.KernelPath = k
				prof.InitrdPaths = inits
				prof.KernelArgs = args
				break
			}
		}
	}

	// Validate parsed kernel & initrd paths against the ISO9660 filesystem so ESP-relative
	// paths (from efi.img loader/entries/*.conf) are safely resolved to actual ISO9660 paths
	// while preserving authentic KernelArgs (e.g. modules_load=nvidia, live-media-path=...).
	if prof.KernelPath != "" {
		if exact, ok := resolveISOPath(prof.KernelPath); ok {
			prof.KernelPath = exact
		} else {
			prof.KernelPath = ""
			prof.InitrdPaths = nil
		}
	}
	if len(prof.InitrdPaths) > 0 {
		resolved := make([]string, 0, len(prof.InitrdPaths))
		allOK := true
		for _, initrd := range prof.InitrdPaths {
			if exact, ok := resolveISOPath(initrd); ok {
				resolved = append(resolved, exact)
			} else {
				allOK = false
				break
			}
		}
		if allOK {
			prof.InitrdPaths = resolved
		} else {
			prof.InitrdPaths = nil
		}
	}

	// Detect casper directory (handles both standard /casper and Pop!_OS /casper_pop-os_.../).
	casperKernel := findInCasperDir("vmlinuz")
	casperSquash := findInCasperDir("squashfs")
	if casperSquash != "" {
		prof.CasperDir = path.Dir(casperSquash)
	} else if casperKernel != "" {
		prof.CasperDir = path.Dir(casperKernel)
	}

	// Detect distro family from characteristic files, volume label, and parsed kernel args.
	lblUpper := strings.ToUpper(volumeLabel + " " + fileName)
	isPopOS := strings.Contains(lblUpper, "POP_OS") ||
		strings.Contains(lblUpper, "POP-OS") ||
		strings.Contains(lblUpper, "POP!_OS") ||
		strings.Contains(strings.ToLower(prof.CasperDir), "pop-os") ||
		strings.Contains(strings.ToLower(prof.KernelArgs), "hostname=pop-os")

	switch {
	case strings.Contains(lblUpper, "VOID") || (findFirst([]string{"liveos/"}, "squashfs") != "" && strings.Contains(lblUpper, "VOID")):
		prof.Family = DistroVoid
	case isPopOS:
		prof.Family = DistroPopOS
	case casperKernel != "" || casperSquash != "":
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

	// Fill in fallback kernel/initrd paths if not already resolved from ISO boot configs.
	if prof.KernelPath == "" {
		switch prof.Family {
		case DistroPopOS, DistroUbuntu:
			prof.KernelPath = casperKernel
			if initrd := findInCasperDir("initrd"); initrd != "" {
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
	} else if len(prof.InitrdPaths) == 0 && (prof.Family == DistroPopOS || prof.Family == DistroUbuntu) {
		if initrd := findInCasperDir("initrd"); initrd != "" {
			prof.InitrdPaths = []string{initrd}
		}
	}

	if prof.CasperDir == "" && prof.KernelPath != "" && (prof.Family == DistroPopOS || prof.Family == DistroUbuntu) {
		prof.CasperDir = path.Dir(prof.KernelPath)
	}

	return prof
}

// BuildKernelArgs returns the final Linux kernel command line pinned to partUUID so multiple
// distros on the same USB drive never collide when mounting their live squashfs.
func (p LinuxBootProfile) BuildKernelArgs(partUUID string) string {
	args := strings.TrimSpace(p.KernelArgs)

	switch p.Family {
	case DistroPopOS:
		if args == "" {
			args = "boot=casper hostname=pop-os username=pop-os noprompt"
			metaLower := strings.ToLower(p.CasperDir + " " + p.DisplayName + " " + p.VolumeLabel)
			if strings.Contains(metaLower, "nvidia") {
				args += " modules_load=nvidia nvidia-drm.modeset=1"
			}
		}
		if !strings.Contains(args, "boot=casper") {
			args = "boot=casper " + args
		}
		args = stripArgPrefix(args, "live-media=")
		args = stripArgPrefix(args, "iso-scan/filename=")
		if p.CasperDir != "" && p.CasperDir != "/" && p.CasperDir != "/casper" && !hasArgPrefix(args, "live-media-path=") {
			args = insertBeforeDashDash(args, "live-media-path="+p.CasperDir)
		}
		return insertBeforeDashDash(args, "live-media=/dev/disk/by-partuuid/"+partUUID)

	case DistroUbuntu:
		if args == "" {
			args = "boot=casper quiet splash"
		}
		if !strings.Contains(args, "boot=casper") {
			args = "boot=casper " + args
		}
		args = stripArgPrefix(args, "live-media=")
		args = stripArgPrefix(args, "iso-scan/filename=")
		if p.CasperDir != "" && p.CasperDir != "/" && p.CasperDir != "/casper" && !hasArgPrefix(args, "live-media-path=") {
			args = insertBeforeDashDash(args, "live-media-path="+p.CasperDir)
		}
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
				kernel = normalizeBootPath(k)
				if len(fields) > 2 {
					args = cleanGrubVars(strings.Join(fields[2:], " "))
				}
			}
		} else if cmd == "initrd" || cmd == "initrdefi" {
			for _, f := range fields[1:] {
				if !strings.HasPrefix(f, "$") {
					initrds = append(initrds, normalizeBootPath(f))
				}
			}
		}
	}
	return kernel, initrds, args
}

func parseSystemdBootEntry(cfg string) (kernel string, initrds []string, args string) {
	var optParts []string
	for _, raw := range strings.Split(cfg, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "linux":
			kernel = normalizeBootPath(fields[1])
		case "initrd":
			initrds = append(initrds, normalizeBootPath(fields[1]))
		case "options":
			optParts = append(optParts, strings.Join(fields[1:], " "))
		}
	}
	return kernel, initrds, strings.Join(optParts, " ")
}

func parseIsolinuxConfig(isoFS ImageFS, filesLower map[string]string, cfgPath string, visited map[string]bool, depth int) (kernel string, initrds []string, args string) {
	if depth > 4 {
		return "", nil, ""
	}
	lp := strings.ToLower(strings.TrimPrefix(cfgPath, "/"))
	if visited[lp] {
		return "", nil, ""
	}
	visited[lp] = true

	exact, ok := filesLower[lp]
	if !ok {
		return "", nil, ""
	}
	cfg := readISOFileText(isoFS, strings.TrimPrefix(exact, "/"))
	if cfg == "" {
		return "", nil, ""
	}

	cfgDir := path.Dir(lp)
	var includes []string
	var argTokens []string

	for _, raw := range strings.Split(cfg, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		cmd := strings.ToLower(fields[0])
		switch cmd {
		case "include":
			inc := strings.TrimPrefix(strings.ReplaceAll(fields[1], `\`, "/"), "/")
			if !strings.Contains(inc, "/") && cfgDir != "." && cfgDir != "" {
				inc = path.Join(cfgDir, inc)
			}
			includes = append(includes, inc)
		case "label":
			if kernel != "" {
				return kernel, initrds, strings.Join(argTokens, " ")
			}
		case "kernel", "linux":
			cand := strings.TrimSpace(fields[1])
			candLower := strings.ToLower(cand)
			if strings.HasSuffix(candLower, ".c32") || strings.HasPrefix(candLower, "localboot") {
				continue
			}
			if kernel == "" {
				kernel = normalizeBootPath(cand)
			}
		case "initrd":
			if kernel != "" {
				for _, part := range strings.Split(fields[1], ",") {
					if p := normalizeBootPath(part); p != "" {
						initrds = append(initrds, p)
					}
				}
			}
		case "append":
			if kernel == "" {
				continue
			}
			for _, tok := range fields[1:] {
				if strings.HasPrefix(strings.ToLower(tok), "initrd=") {
					val := tok[len("initrd="):]
					for _, part := range strings.Split(val, ",") {
						if p := normalizeBootPath(part); p != "" {
							initrds = append(initrds, p)
						}
					}
					continue
				}
				if strings.Contains(tok, "$") {
					continue
				}
				argTokens = append(argTokens, tok)
			}
		}
	}

	if kernel != "" {
		return kernel, initrds, strings.Join(argTokens, " ")
	}
	for _, inc := range includes {
		if k, inits, a := parseIsolinuxConfig(isoFS, filesLower, inc, visited, depth+1); k != "" {
			return k, inits, a
		}
	}
	return "", nil, ""
}

func loaderEntryPriority(name string) int {
	nl := strings.ToLower(name)
	switch {
	case strings.Contains(nl, "memtest") || strings.Contains(nl, "uefi") || strings.Contains(nl, "firmware"):
		return 3
	case strings.Contains(nl, "recovery") || strings.Contains(nl, "fallback") || strings.Contains(nl, "safe") || strings.Contains(nl, "nomodeset"):
		return 2
	case strings.Contains(nl, "pop") || strings.Contains(nl, "live") || strings.Contains(nl, "current"):
		return 0
	default:
		return 1
	}
}

func isMetadataSidecar(base string) bool {
	for _, suf := range []string{".sig", ".asc", ".gpg", ".sha256", ".sha512", ".md5", ".manifest", ".size", ".txt"} {
		if strings.HasSuffix(base, suf) {
			return true
		}
	}
	return false
}

func normalizeBootPath(p string) string {
	p = strings.TrimSpace(strings.ReplaceAll(p, `\`, "/"))
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
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

func hasArgPrefix(args, prefix string) bool {
	for _, tok := range strings.Fields(args) {
		if strings.HasPrefix(tok, prefix) {
			return true
		}
	}
	return false
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
