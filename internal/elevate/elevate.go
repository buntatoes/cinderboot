// SPDX-License-Identifier: GPL-3.0-only
package elevate

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/buntatoes/cinderboot/internal/flash"
)

type jobTempFiles struct {
	dir        string
	specPath   string
	cancelPath string
}

func (j jobTempFiles) cleanup() {
	if j.dir != "" {
		_ = os.RemoveAll(j.dir)
	}
}

func (j jobTempFiles) triggerCancel() {
	if j.cancelPath != "" {
		_ = os.WriteFile(j.cancelPath, []byte("cancel\n"), 0o600)
	}
}

func prepareJobTempFiles(spec flash.JobSpec) (jobTempFiles, error) {
	dir, err := os.MkdirTemp("", "cinderboot-job-*")
	if err != nil {
		return jobTempFiles{}, err
	}
	specPath := filepath.Join(dir, "spec.json")
	f, err := os.OpenFile(specPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		_ = os.RemoveAll(dir)
		return jobTempFiles{}, err
	}
	if err := json.NewEncoder(f).Encode(spec); err != nil {
		_ = f.Close()
		_ = os.RemoveAll(dir)
		return jobTempFiles{}, err
	}
	if err := f.Close(); err != nil {
		_ = os.RemoveAll(dir)
		return jobTempFiles{}, err
	}
	return jobTempFiles{
		dir:        dir,
		specPath:   specPath,
		cancelPath: filepath.Join(dir, "cancel"),
	}, nil
}
