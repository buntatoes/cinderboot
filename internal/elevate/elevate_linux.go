// SPDX-License-Identifier: GPL-3.0-only
//go:build linux

package elevate

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/buntatoes/cinderboot/internal/flash"
)

// IsElevated reports whether the current Linux process is running as root.
func IsElevated() bool {
	return os.Geteuid() == 0
}

// RunFlash executes the flash job directly if already root, or launches this same binary
// in privileged `worker` mode via pkexec (graphical Polkit prompt) or sudo.
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
		return fmt.Errorf("write job spec: %w", err)
	}
	defer os.Remove(specPath)

	var cmd *exec.Cmd
	if pkexec, err := exec.LookPath("pkexec"); err == nil {
		cmd = exec.CommandContext(ctx, pkexec, selfExe, "worker", "--spec", specPath)
	} else if sudo, err := exec.LookPath("sudo"); err == nil {
		cmd = exec.CommandContext(ctx, sudo, selfExe, "worker", "--spec", specPath)
	} else {
		return fmt.Errorf("neither pkexec nor sudo was found; run cinderboot with root privileges")
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start elevated worker: %w", err)
	}

	var workerErrMsg string
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var ev flash.ProgressEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			continue
		}
		if ev.Error != "" {
			workerErrMsg = ev.Error
		}
		if sink != nil {
			sink(ev)
		}
	}

	var stderrText string
	errSc := bufio.NewScanner(stderr)
	for errSc.Scan() {
		if stderrText != "" {
			stderrText += "\n"
		}
		stderrText += errSc.Text()
	}

	waitErr := cmd.Wait()
	if workerErrMsg != "" {
		return fmt.Errorf("%s", workerErrMsg)
	}
	if waitErr != nil {
		if stderrText != "" {
			return fmt.Errorf("elevated flash failed: %s", stderrText)
		}
		return fmt.Errorf("elevated flash cancelled or failed: %w", waitErr)
	}
	return nil
}
