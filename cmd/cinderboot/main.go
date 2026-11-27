// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/buntatoes/cinderboot/internal/device"
	"github.com/buntatoes/cinderboot/internal/elevate"
	"github.com/buntatoes/cinderboot/internal/flash"
	"github.com/buntatoes/cinderboot/internal/image"
	"github.com/buntatoes/cinderboot/internal/ui"
	"github.com/buntatoes/cinderboot/internal/unattend"
	"github.com/buntatoes/cinderboot/internal/version"
)

//go:embed icon.svg
var embeddedIconSVG []byte

//go:embed icon.png
var embeddedIconPNG []byte

func main() {
	if len(os.Args) < 2 {
		if err := ui.RunDesktop(ui.RunOptions{Icon: embeddedIconSVG}); err != nil {
			fatalf("UI error: %v", err)
		}
		return
	}

	switch os.Args[1] {
	case "-v", "--version", "version":
		fmt.Printf("cinderboot v%s (%s/%s, GPL-3.0)\n", version.Version, runtime.GOOS, runtime.GOARCH)
	case "-h", "--help", "help":
		printHelp()
	case "ui":
		runUI(os.Args[2:])
	case "list":
		runList(os.Args[2:])
	case "inspect":
		runInspect(os.Args[2:])
	case "flash":
		runFlashCLI(os.Args[2:])
	case "verify":
		runVerifyCLI(os.Args[2:])
	case "worker":
		runWorker(os.Args[2:])
	case "--install":
		runInstallLinux()
	case "--uninstall":
		runUninstallLinux()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printHelp()
		os.Exit(2)
	}
}

func printHelp() {
	fmt.Printf(`Cinderboot v%s — Cross-Platform Bootable USB Creator (Zero Dependencies, GPL-3.0)

Usage:
  cinderboot                      Launch the desktop UI
  cinderboot ui [flags]           Launch the desktop UI with options
  cinderboot list [flags]         List detected removable USB drives
  cinderboot inspect <image>      Inspect a Linux/Windows ISO or disk image
  cinderboot flash [flags]        Write an image to a removable USB drive
  cinderboot verify [flags]       Verify a flashed USB drive via SHA-256 read-back
  cinderboot --install            Install binary & desktop entry to ~/.local (Linux)
  cinderboot --uninstall          Remove installed files from ~/.local (Linux)
  cinderboot -v, --version        Show version
  cinderboot -h, --help           Show help
`, version.Version)
}

func runUI(args []string) {
	fs := flag.NewFlagSet("ui", flag.ExitOnError)
	port := fs.Int("port", 0, "Local loopback port (0 = automatic)")
	noOpen := fs.Bool("no-open", false, "Do not automatically open the app window")
	_ = fs.Parse(args)

	if err := ui.RunDesktop(ui.RunOptions{Port: *port, NoOpen: *noOpen, Icon: embeddedIconSVG}); err != nil {
		fatalf("UI error: %v", err)
	}
}

func runList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "Output JSON")
	includeFixed := fs.Bool("include-fixed", false, "Include non-removable USB HDDs/SSDs")
	_ = fs.Parse(args)

	drives, err := device.ListRemovable(device.ListOptions{IncludeFixedUSB: *includeFixed})
	if err != nil {
		fatalf("list drives: %v", err)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(drives)
		return
	}
	if len(drives) == 0 {
		fmt.Println("No removable USB drives detected.")
		return
	}
	for _, d := range drives {
		fmt.Println(d.DisplayLabel())
	}
}

func runInspect(args []string) {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "Output JSON")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fatalf("usage: cinderboot inspect [--json] <image-path>")
	}
	info, err := image.Inspect(fs.Arg(0))
	if err != nil {
		fatalf("inspect: %v", err)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(info)
		return
	}
	fmt.Printf("File:        %s (%s)\n", info.FileName, device.FormatBytes(uint64(info.SizeBytes)))
	fmt.Printf("Detected:    %s\n", info.Summary)
	fmt.Printf("Mode:        %s\n", info.RecommendedMode)
	if info.VolumeLabel != "" {
		fmt.Printf("Label:       %s\n", info.VolumeLabel)
	}
	if info.InstallWimPath != "" {
		fmt.Printf("Windows WIM: %s (%s, auto-split=%v)\n",
			info.InstallWimPath, device.FormatBytes(info.InstallWimBytes), info.RequiresWimSplit)
	}
}

type multiStringFlag []string

func (m *multiStringFlag) String() string { return strings.Join(*m, ", ") }
func (m *multiStringFlag) Set(val string) error {
	if strings.TrimSpace(val) != "" {
		*m = append(*m, strings.TrimSpace(val))
	}
	return nil
}

func runFlashCLI(args []string) {
	fs := flag.NewFlagSet("flash", flag.ExitOnError)
	var imgPaths multiStringFlag
	fs.Var(&imgPaths, "image", "Path to ISO or disk image (repeatable for multi-distro Linux USB)")
	devPath := fs.String("device", "", "Target USB device path or Windows drive letter (required)")
	mode := fs.String("mode", "auto", "Flash mode: auto, raw, windows-fat32, iso-fat32, multiboot")
	label := fs.String("label", "", "FAT32 volume label (optional)")
	verify := fs.Bool("verify", true, "Verify written bytes via SHA-256 read-back (raw mode)")
	includeFixed := fs.Bool("include-fixed", false, "Allow targeting fixed USB HDDs/SSDs")
	yes := fs.Bool("yes", false, "Skip interactive erase confirmation prompt")
	bypassReq := fs.Bool("win-bypass-req", false, "Windows 11: bypass TPM 2.0, Secure Boot, and RAM checks")
	bypassMSA := fs.Bool("win-bypass-msa", false, "Windows 11: remove Microsoft Account requirement")
	noBitLocker := fs.Bool("win-no-bitlocker", false, "Windows 11: disable automatic BitLocker encryption")
	skipPrivacy := fs.Bool("win-skip-privacy", false, "Windows 11: skip OOBE privacy prompts")
	winUser := fs.String("win-user", "", "Windows 11: optional local admin username")
	_ = fs.Parse(args)

	if len(imgPaths) == 0 || *devPath == "" {
		fatalf("usage: cinderboot flash --image <path> [--image <path2> ...] --device <dev> [options]")
	}

	drv, err := device.FindByPath(*devPath, device.ListOptions{IncludeFixedUSB: *includeFixed})
	if err != nil {
		fatalf("%v", err)
	}

	var inspected []image.Info
	for _, p := range imgPaths {
		info, err := image.Inspect(p)
		if err != nil {
			fatalf("inspect image %q: %v", p, err)
		}
		inspected = append(inspected, info)
	}

	if !*yes {
		fmt.Printf("\nWARNING: ALL DATA ON THIS USB DRIVE WILL BE ERASED!\n")
		fmt.Printf("  Target: %s\n", drv.DisplayLabel())
		if len(inspected) == 1 {
			fmt.Printf("  Image:  %s (%s)\n", inspected[0].FileName, inspected[0].Summary)
		} else {
			fmt.Printf("  Mode:   Multi-Distro Linux UEFI USB (%d ISOs)\n", len(inspected))
			for i, info := range inspected {
				fmt.Printf("    %d. %s (%s)\n", i+1, info.FileName, device.FormatBytes(uint64(info.SizeBytes)))
			}
		}
		fmt.Printf("Type ERASE to continue: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(line) != "ERASE" {
			fmt.Println("Aborted.")
			return
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	spec := flash.JobSpec{
		ImagePath:       imgPaths[0],
		ImagePaths:      []string(imgPaths),
		DevicePath:      drv.DevicePath,
		Mode:            flash.Mode(*mode),
		VolumeLabel:     *label,
		Verify:          *verify,
		IncludeFixedUSB: *includeFixed,
		Unattend: unattend.Options{
			BypassRequirements: *bypassReq,
			BypassMSA:          *bypassMSA,
			DisableBitLocker:   *noBitLocker,
			SkipPrivacy:        *skipPrivacy,
			LocalUsername:      *winUser,
		},
	}

	err = elevate.RunFlash(ctx, spec, func(ev flash.ProgressEvent) {
		if ev.Percent > 0 {
			fmt.Printf("\r[%s] %5.1f%% — %-60s", ev.Phase, ev.Percent, ev.Message)
		} else if ev.Message != "" {
			fmt.Printf("\n[%s] %s\n", ev.Phase, ev.Message)
		}
		if ev.Done {
			fmt.Println()
			if ev.SHA256 != "" {
				fmt.Printf("SHA-256: %s\n", ev.SHA256)
			}
		}
	})
	if err != nil {
		fatalf("\nFlash failed: %v", err)
	}
}

func runVerifyCLI(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	imgPath := fs.String("image", "", "Path to source image")
	devPath := fs.String("device", "", "Target USB device path")
	includeFixed := fs.Bool("include-fixed", false, "Allow fixed USB HDDs")
	_ = fs.Parse(args)
	if *imgPath == "" || *devPath == "" {
		fatalf("usage: cinderboot verify --image <path> --device <dev>")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sum, err := flash.VerifyImageAgainstDevice(ctx, *imgPath, *devPath, *includeFixed, func(ev flash.ProgressEvent) {
		fmt.Printf("\r[verify] %5.1f%% — %s", ev.Percent, ev.Message)
	})
	if err != nil {
		fatalf("\nVerify failed: %v", err)
	}
	fmt.Printf("\nVerified OK! SHA-256: %s\n", sum)
}

func runWorker(args []string) {
	fs := flag.NewFlagSet("worker", flag.ExitOnError)
	specPath := fs.String("spec", "", "Path to JSON job spec")
	eventsPath := fs.String("events", "", "Optional JSONL output file (defaults to stdout)")
	cancelPath := fs.String("cancel", "", "Optional cancel sentinel file watched for user cancellation")
	_ = fs.Parse(args)

	if *specPath == "" {
		os.Exit(2)
	}

	var out io.Writer = os.Stdout
	var evFile *os.File
	if *eventsPath != "" {
		f, err := os.OpenFile(*eventsPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err == nil {
			evFile = f
			out = f
			defer evFile.Close()
		}
	}

	emit := func(ev flash.ProgressEvent) {
		b, err := json.Marshal(ev)
		if err != nil {
			return
		}
		_, _ = out.Write(append(b, '\n'))
		if evFile != nil {
			_ = evFile.Sync()
		}
	}

	raw, err := os.ReadFile(*specPath)
	if err != nil {
		emit(flash.ProgressEvent{Phase: "error", Error: err.Error(), Done: true})
		os.Exit(1)
	}
	var spec flash.JobSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		emit(flash.ProgressEvent{Phase: "error", Error: err.Error(), Done: true})
		os.Exit(1)
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(sigCtx)
	defer cancel()

	// Watch the user-owned cancel sentinel file so unprivileged UI parents can reliably cancel root/Admin workers.
	if *cancelPath != "" {
		go func() {
			ticker := time.NewTicker(50 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if _, err := os.Stat(*cancelPath); err == nil {
						cancel()
						return
					}
				}
			}
		}()
	}

	// Also watch stdin EOF when launched over a pipe (Linux pkexec/sudo).
	if st, err := os.Stdin.Stat(); err == nil && (st.Mode()&os.ModeCharDevice) == 0 {
		go func() {
			var b [1]byte
			_, _ = os.Stdin.Read(b[:])
			cancel()
		}()
	}

	if err := flash.Execute(ctx, spec, emit); err != nil {
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			emit(flash.ProgressEvent{
				Phase:   "cancelled",
				Message: "Flash cancelled by user",
				Error:   "Flash cancelled by user",
				Done:    true,
			})
			os.Exit(130)
		}
		emit(flash.ProgressEvent{Phase: "error", Error: err.Error(), Done: true})
		os.Exit(1)
	}
}

func runInstallLinux() {
	if runtime.GOOS != "linux" {
		fmt.Println("On Windows, Cinderboot runs as a standalone portable executable — no install required.")
		return
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fatalf("resolve HOME: %v", err)
	}
	prefix := os.Getenv("PREFIX")
	if prefix == "" {
		prefix = filepath.Join(home, ".local")
	}

	selfExe, err := os.Executable()
	if err != nil {
		fatalf("resolve executable: %v", err)
	}

	appDir := filepath.Join(prefix, "share", "cinderboot")
	binDir := filepath.Join(prefix, "bin")
	desktopDir := filepath.Join(prefix, "share", "applications")
	iconScalableDir := filepath.Join(prefix, "share", "icons", "hicolor", "scalable", "apps")
	icon256Dir := filepath.Join(prefix, "share", "icons", "hicolor", "256x256", "apps")

	for _, d := range []string{appDir, binDir, desktopDir, iconScalableDir, icon256Dir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			fatalf("mkdir %s: %v", d, err)
		}
	}

	srcBytes, err := os.ReadFile(selfExe)
	if err != nil {
		fatalf("read self binary: %v", err)
	}
	dstBin := filepath.Join(appDir, "cinderboot")
	tmpBin := dstBin + ".new"
	if err := os.WriteFile(tmpBin, srcBytes, 0o755); err != nil {
		fatalf("write binary: %v", err)
	}
	if err := os.Rename(tmpBin, dstBin); err != nil {
		_ = os.Remove(tmpBin)
		fatalf("install binary: %v", err)
	}

	linkPath := filepath.Join(binDir, "cinderboot")
	if target, err := os.Readlink(linkPath); err != nil || target != dstBin {
		_ = os.Remove(linkPath)
		if err := os.Symlink(dstBin, linkPath); err != nil {
			fatalf("symlink %s: %v", linkPath, err)
		}
	}

	appIconPNG := filepath.Join(appDir, "icon.png")
	_ = os.WriteFile(appIconPNG, embeddedIconPNG, 0o644)
	_ = os.WriteFile(filepath.Join(iconScalableDir, "cinderboot.svg"), embeddedIconSVG, 0o644)
	_ = os.WriteFile(filepath.Join(icon256Dir, "cinderboot.png"), embeddedIconPNG, 0o644)

	desktop := fmt.Sprintf(`[Desktop Entry]
Version=1.0
Type=Application
Name=Cinderboot
GenericName=Bootable USB Creator
Comment=Create bootable USB drives from Linux and Windows ISOs or disk images
Exec=%s
Icon=%s
Terminal=false
Categories=System;Utility;
Keywords=usb;iso;bootable;flash;windows;linux;
StartupNotify=true
`, linkPath, appIconPNG)
	_ = os.WriteFile(filepath.Join(desktopDir, "cinderboot.desktop"), []byte(desktop), 0o644)

	// Refresh desktop launcher & icon caches if available.
	if p, err := exec.LookPath("gtk-update-icon-cache"); err == nil {
		_ = exec.Command(p, "-f", "-t", filepath.Join(prefix, "share", "icons", "hicolor")).Run()
	}
	if p, err := exec.LookPath("update-desktop-database"); err == nil {
		_ = exec.Command(p, desktopDir).Run()
	}

	fmt.Printf("Installed Cinderboot v%s to %s\nRun with: %s\n", version.Version, appDir, linkPath)
}

func runUninstallLinux() {
	if runtime.GOOS != "linux" {
		fmt.Println("On Windows, simply delete the portable Cinderboot executable.")
		return
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	prefix := os.Getenv("PREFIX")
	if prefix == "" {
		prefix = filepath.Join(home, ".local")
	}
	_ = os.Remove(filepath.Join(prefix, "bin", "cinderboot"))
	_ = os.Remove(filepath.Join(prefix, "share", "applications", "cinderboot.desktop"))
	_ = os.Remove(filepath.Join(prefix, "share", "icons", "hicolor", "scalable", "apps", "cinderboot.svg"))
	_ = os.Remove(filepath.Join(prefix, "share", "icons", "hicolor", "256x256", "apps", "cinderboot.png"))
	_ = os.Remove(filepath.Join(prefix, "share", "cinderboot", "icon.png"))
	_ = os.Remove(filepath.Join(prefix, "share", "cinderboot", "cinderboot"))
	_ = os.Remove(filepath.Join(prefix, "share", "cinderboot"))
	fmt.Println("Uninstalled Cinderboot.")
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
