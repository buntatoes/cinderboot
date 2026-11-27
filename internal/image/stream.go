// SPDX-License-Identifier: GPL-3.0-only
package image

import (
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Stream represents a raw or transparently decompressed image byte stream (100% Go stdlib).
type Stream struct {
	Reader       io.Reader
	ExpectedSize int64 // >0 when known in advance, -1 when streaming unknown-length compressed data
	Compressed   bool
	closers      []io.Closer
}

func (s *Stream) Close() error {
	var firstErr error
	for i := len(s.closers) - 1; i >= 0; i-- {
		if err := s.closers[i].Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// OpenRawStream opens an .iso, .img, .raw, .gz, .bz2, or single-image .zip as a sequential byte stream.
func OpenRawStream(imgPath string) (*Stream, error) {
	lower := strings.ToLower(imgPath)

	if strings.HasSuffix(lower, ".zip") {
		zr, err := zip.OpenReader(imgPath)
		if err != nil {
			return nil, fmt.Errorf("open zip image: %w", err)
		}
		var chosen *zip.File
		for _, f := range zr.File {
			if f.FileInfo().IsDir() {
				continue
			}
			fl := strings.ToLower(f.Name)
			if strings.HasSuffix(fl, ".iso") || strings.HasSuffix(fl, ".img") || strings.HasSuffix(fl, ".raw") {
				chosen = f
				break
			}
			if chosen == nil || f.UncompressedSize64 > chosen.UncompressedSize64 {
				chosen = f
			}
		}
		if chosen == nil {
			_ = zr.Close()
			return nil, fmt.Errorf("zip archive contains no image file: %s", filepath.Base(imgPath))
		}
		rc, err := chosen.Open()
		if err != nil {
			_ = zr.Close()
			return nil, err
		}
		return &Stream{
			Reader:       rc,
			ExpectedSize: int64(chosen.UncompressedSize64),
			Compressed:   true,
			closers:      []io.Closer{zr, rc},
		}, nil
	}

	f, err := os.Open(imgPath)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}

	switch {
	case strings.HasSuffix(lower, ".gz"):
		gr, err := gzip.NewReader(f)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("open gzip stream: %w", err)
		}
		return &Stream{
			Reader:       gr,
			ExpectedSize: -1,
			Compressed:   true,
			closers:      []io.Closer{f, gr},
		}, nil

	case strings.HasSuffix(lower, ".bz2"):
		return &Stream{
			Reader:       bzip2.NewReader(f),
			ExpectedSize: -1,
			Compressed:   true,
			closers:      []io.Closer{f},
		}, nil

	default:
		return &Stream{
			Reader:       f,
			ExpectedSize: st.Size(),
			Compressed:   false,
			closers:      []io.Closer{f},
		}, nil
	}
}
