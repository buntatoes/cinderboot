// SPDX-License-Identifier: GPL-3.0-only
//go:build linux

package ui

import (
	"fmt"
	"os/exec"
	"strings"
)

func openAppWindow(url string) {
	// Prefer Chromium/Chrome/Brave/Edge in standalone frameless --app mode so it behaves like a native window.
	appBrowsers := []string{"chromium", "google-chrome", "google-chrome-stable", "brave", "microsoft-edge", "vivaldi"}
	for _, b := range appBrowsers {
		if path, err := exec.LookPath(b); err == nil {
			cmd := exec.Command(path, "--app="+url, "--window-size=780,860")
			if err := cmd.Start(); err == nil {
				return
			}
		}
	}
	if xdg, err := exec.LookPath("xdg-open"); err == nil {
		_ = exec.Command(xdg, url).Start()
	}
}

func pickImageDialog() (string, error) {
	if p, err := exec.LookPath("kdialog"); err == nil {
		out, err := exec.Command(p, "--getopenfilename", ".", "Boot Images (*.iso *.img *.raw *.gz *.bz2 *.zip);;All Files (*)").Output()
		if err == nil {
			return strings.TrimSpace(string(out)), nil
		}
		return "", nil
	}
	if p, err := exec.LookPath("zenity"); err == nil {
		out, err := exec.Command(p, "--file-selection", "--title=Select Boot Image", "--file-filter=Boot Images | *.iso *.img *.raw *.gz *.bz2 *.zip", "--file-filter=All Files | *").Output()
		if err == nil {
			return strings.TrimSpace(string(out)), nil
		}
		return "", nil
	}
	return "", fmt.Errorf("no native file dialog (kdialog/zenity) found")
}
