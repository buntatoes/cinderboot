// SPDX-License-Identifier: GPL-3.0-only
package elevate

import (
	"encoding/json"
	"os"

	"github.com/buntatoes/cinderboot/internal/flash"
)

func writeTempSpec(spec flash.JobSpec) (string, error) {
	f, err := os.CreateTemp("", "cinderboot-job-*.json")
	if err != nil {
		return "", err
	}
	path := f.Name()
	enc := json.NewEncoder(f)
	if err := enc.Encode(spec); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}
