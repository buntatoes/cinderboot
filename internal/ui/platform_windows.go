// SPDX-License-Identifier: GPL-3.0-only
//go:build windows

package ui

import (
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	comdlg32DLL         = syscall.NewLazyDLL("comdlg32.dll")
	procGetOpenFileName = comdlg32DLL.NewProc("GetOpenFileNameW")
)

type openFileNameW struct {
	lStructSize       uint32
	hwndOwner         uintptr
	hInstance         uintptr
	lpstrFilter       *uint16
	lpstrCustomFilter *uint16
	nMaxCustFilter    uint32
	nFilterIndex      uint32
	lpstrFile         *uint16
	nMaxFile          uint32
	lpstrFileTitle    *uint16
	nMaxFileTitle     uint32
	lpstrInitialDir   *uint16
	lpstrTitle        *uint16
	flags             uint32
	nFileOffset       uint16
	nFileExtension    uint16
	lpstrDefExt       *uint16
	lCustData         uintptr
	lpfnHook          uintptr
	lpTemplateName    *uint16
	pvReserved        uintptr
	dwReserved        uint32
	flagsEx           uint32
}

const (
	ofnFileMustExist = 0x00001000
	ofnPathMustExist = 0x00000800
	ofnNoChangeDir   = 0x00000008
)

func openAppWindow(url string) {
	// Prefer Microsoft Edge / Chrome standalone --app mode on Windows for a clean native-like window.
	edgePaths := []string{
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
	}
	for _, p := range edgePaths {
		if _, err := exec.LookPath(p); err == nil {
			if err := exec.Command(p, "--app="+url, "--window-size=780,860").Start(); err == nil {
				return
			}
		}
	}
	_ = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url).Start()
}

func pickImageDialog() (string, error) {
	buf := make([]uint16, 4096)
	filter := syscall.StringToUTF16("Boot Images (*.iso;*.img;*.raw;*.gz;*.bz2;*.zip)\x00*.iso;*.img;*.raw;*.gz;*.bz2;*.zip\x00All Files (*.*)\x00*.*\x00\x00")
	title, _ := syscall.UTF16PtrFromString("Select Boot Image — Cinderboot")

	ofn := openFileNameW{
		lStructSize: uint32(unsafe.Sizeof(openFileNameW{})),
		lpstrFilter: &filter[0],
		lpstrFile:   &buf[0],
		nMaxFile:    uint32(len(buf)),
		lpstrTitle:  title,
		flags:       ofnFileMustExist | ofnPathMustExist | ofnNoChangeDir,
	}
	r1, _, _ := procGetOpenFileName.Call(uintptr(unsafe.Pointer(&ofn)))
	if r1 == 0 {
		return "", nil
	}
	return filepath.Clean(syscall.UTF16ToString(buf)), nil
}
