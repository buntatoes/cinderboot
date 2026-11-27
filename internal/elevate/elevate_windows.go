// SPDX-License-Identifier: GPL-3.0-only
//go:build windows

package elevate

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"github.com/buntatoes/cinderboot/internal/flash"
)

var (
	shell32DLL            = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteExW   = shell32DLL.NewProc("ShellExecuteExW")
	procIsUserAnAdmin     = shell32DLL.NewProc("IsUserAnAdmin")
	kernel32ElevDLL       = syscall.NewLazyDLL("kernel32.dll")
	procTerminateProcess  = kernel32ElevDLL.NewProc("TerminateProcess")
	procGetExitCodeProc   = kernel32ElevDLL.NewProc("GetExitCodeProcess")
)

type shellExecuteInfo struct {
	cbSize         uint32
	fMask          uint32
	hwnd           uintptr
	lpVerb         *uint16
	lpFile         *uint16
	lpParameters   *uint16
	lpDirectory    *uint16
	nShow          int32
	hInstApp       uintptr
	lpIDList       uintptr
	lpClass        *uint16
	hkeyClass      uintptr
	dwHotKey       uint32
	hIconOrMonitor uintptr
	hProcess       syscall.Handle
}

const (
	seeMaskNoCloseProcess = 0x00000040
	swHide                = 0
)

// IsElevated reports whether the current Windows process holds Administrator privileges.
func IsElevated() bool {
	r1, _, _ := procIsUserAnAdmin.Call()
	return r1 != 0
}

// RunFlash runs directly if Administrator, or spawns this executable elevated via UAC ShellExecuteExW("runas")
// and tails structured JSON-line progress events from a temp status file.
func RunFlash(ctx context.Context, spec flash.JobSpec, sink flash.ProgressSink) error {
	if IsElevated() {
		return flash.Execute(ctx, spec, sink)
	}

	selfExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	specPath, err := writeTempSpec(spec)
	if err != nil {
		return err
	}
	defer os.Remove(specPath)

	eventsFile, err := os.CreateTemp("", "cinderboot-events-*.jsonl")
	if err != nil {
		return err
	}
	eventsPath := eventsFile.Name()
	_ = eventsFile.Close()
	defer os.Remove(eventsPath)

	verbPtr, _ := syscall.UTF16PtrFromString("runas")
	filePtr, _ := syscall.UTF16PtrFromString(selfExe)
	params := fmt.Sprintf(`worker --spec "%s" --events "%s"`, specPath, eventsPath)
	paramsPtr, _ := syscall.UTF16PtrFromString(params)
	dirPtr, _ := syscall.UTF16PtrFromString(filepath.Dir(selfExe))

	sei := shellExecuteInfo{
		cbSize:       uint32(unsafe.Sizeof(shellExecuteInfo{})),
		fMask:        seeMaskNoCloseProcess,
		lpVerb:       verbPtr,
		lpFile:       filePtr,
		lpParameters: paramsPtr,
		lpDirectory:  dirPtr,
		nShow:        swHide,
	}

	r1, _, callErr := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&sei)))
	if r1 == 0 {
		return fmt.Errorf("UAC elevation cancelled or failed: %v", callErr)
	}
	defer syscall.CloseHandle(sei.hProcess)

	var offset int64
	var workerErr string
	readNewEvents := func() {
		f, err := os.Open(eventsPath)
		if err != nil {
			return
		}
		defer f.Close()
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return
		}
		r := bufio.NewReader(f)
		for {
			line, err := r.ReadBytes('\n')
			if len(line) > 0 && line[len(line)-1] == '\n' {
				offset += int64(len(line))
				var ev flash.ProgressEvent
				if json.Unmarshal(line, &ev) == nil {
					if ev.Error != "" {
						workerErr = ev.Error
					}
					if sink != nil {
						sink(ev)
					}
				}
			}
			if err != nil {
				break
			}
		}
	}

	ticker := time.NewTicker(150 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			_, _, _ = procTerminateProcess.Call(uintptr(sei.hProcess), 1)
			return ctx.Err()
		case <-ticker.C:
			readNewEvents()
			res, _ := syscall.WaitForSingleObject(sei.hProcess, 0)
			if res == syscall.WAIT_OBJECT_0 {
				readNewEvents()
				var exitCode uint32
				_, _, _ = procGetExitCodeProc.Call(uintptr(sei.hProcess), uintptr(unsafe.Pointer(&exitCode)))
				if workerErr != "" {
					return fmt.Errorf("%s", workerErr)
				}
				if exitCode != 0 {
					return fmt.Errorf("elevated flash worker exited with code %d", exitCode)
				}
				return nil
			}
		}
	}
}
