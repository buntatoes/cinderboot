// SPDX-License-Identifier: GPL-3.0-only
package ui

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/buntatoes/cinderboot/internal/device"
	"github.com/buntatoes/cinderboot/internal/elevate"
	"github.com/buntatoes/cinderboot/internal/flash"
	"github.com/buntatoes/cinderboot/internal/image"
	"github.com/buntatoes/cinderboot/internal/version"
)

//go:embed web/index.html
var webFS embed.FS

// RunOptions configures the local loopback desktop UI server.
type RunOptions struct {
	Port   int
	NoOpen bool
	Icon   []byte
}

type driveDTO struct {
	device.Drive
	DisplayLabel string `json:"display_label"`
}

type inspectDTO struct {
	image.Info
	SizeHuman string `json:"size_human"`
}

type serverState struct {
	token    string
	host     string
	iconSVG  []byte
	indexRaw string

	mu          sync.Mutex
	active      bool
	cancelFlash context.CancelFunc
	subs        map[chan flash.ProgressEvent]struct{}
	shutdownCh  chan struct{}
	onceQuit    sync.Once
}

// RunDesktop starts the local loopback HTTP UI server (127.0.0.1) and opens it in app-window mode.
func RunDesktop(opts RunOptions) error {
	tokBytes := make([]byte, 24)
	if _, err := rand.Read(tokBytes); err != nil {
		return err
	}
	token := hex.EncodeToString(tokBytes)

	htmlBytes, err := webFS.ReadFile("web/index.html")
	if err != nil {
		return err
	}
	rendered := strings.ReplaceAll(string(htmlBytes), "{{TOKEN}}", token)
	rendered = strings.ReplaceAll(rendered, "{{VERSION}}", version.Version)

	addr := fmt.Sprintf("127.0.0.1:%d", opts.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("bind local UI server on %s: %w", addr, err)
	}
	actualAddr := ln.Addr().String()
	url := "http://" + actualAddr + "/"

	st := &serverState{
		token:      token,
		host:       actualAddr,
		iconSVG:    opts.Icon,
		indexRaw:   rendered,
		subs:       make(map[chan flash.ProgressEvent]struct{}),
		shutdownCh: make(chan struct{}),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", st.handleIndex)
	mux.HandleFunc("/icon.svg", st.handleIcon)
	mux.HandleFunc("/api/drives", st.requireAuth(st.handleDrives))
	mux.HandleFunc("/api/pick-image", st.requireAuth(st.handlePickImage))
	mux.HandleFunc("/api/inspect", st.requireAuth(st.handleInspect))
	mux.HandleFunc("/api/flash", st.requireAuth(st.handleFlash))
	mux.HandleFunc("/api/cancel", st.requireAuth(st.handleCancel))
	mux.HandleFunc("/api/quit", st.requireAuth(st.handleQuit))
	mux.HandleFunc("/api/events", st.handleEvents)

	srv := &http.Server{
		Handler:           st.securityHeaders(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	fmt.Printf("Cinderboot v%s UI running at %s\n", version.Version, url)
	if !opts.NoOpen {
		openAppWindow(url)
	}

	select {
	case err := <-errCh:
		return err
	case <-st.shutdownCh:
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		return nil
	}
}

func (s *serverState) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != s.host {
			http.Error(w, "invalid host", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline' data:")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *serverState) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Cinderboot-Token") != s.token {
			writeJSONError(w, http.StatusUnauthorized, "missing or invalid session token")
			return
		}
		next(w, r)
	}
}

func (s *serverState) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(s.indexRaw))
}

func (s *serverState) handleIcon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	_, _ = w.Write(s.iconSVG)
}

func (s *serverState) handleDrives(w http.ResponseWriter, r *http.Request) {
	inc := r.URL.Query().Get("include_fixed") == "1"
	drives, err := device.ListRemovable(device.ListOptions{IncludeFixedUSB: inc})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]driveDTO, 0, len(drives))
	for _, d := range drives {
		out = append(out, driveDTO{Drive: d, DisplayLabel: d.DisplayLabel()})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *serverState) handlePickImage(w http.ResponseWriter, r *http.Request) {
	p, err := pickImageDialog()
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"path": p})
}

func (s *serverState) handleInspect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	info, err := image.Inspect(strings.TrimSpace(req.Path))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, inspectDTO{
		Info:      info,
		SizeHuman: device.FormatBytes(uint64(info.SizeBytes)),
	})
}

func (s *serverState) handleFlash(w http.ResponseWriter, r *http.Request) {
	var spec flash.JobSpec
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid flash specification")
		return
	}

	s.mu.Lock()
	if s.active {
		s.mu.Unlock()
		writeJSONError(w, http.StatusConflict, "a flash job is already running")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.active = true
	s.cancelFlash = cancel
	s.mu.Unlock()

	go func() {
		defer func() {
			cancel()
			s.mu.Lock()
			s.active = false
			s.cancelFlash = nil
			s.mu.Unlock()
		}()
		var sawTerminal bool
		err := elevate.RunFlash(ctx, spec, func(ev flash.ProgressEvent) {
			if ev.Done {
				sawTerminal = true
			}
			s.broadcast(ev)
		})
		if err != nil && !sawTerminal {
			if errors.Is(err, context.Canceled) {
				s.broadcast(flash.ProgressEvent{
					Phase:   "cancelled",
					Message: "Flash cancelled by user",
					Error:   "Flash cancelled by user",
					Done:    true,
				})
			} else {
				s.broadcast(flash.ProgressEvent{
					Phase: "error",
					Error: err.Error(),
					Done:  true,
				})
			}
		}
	}()

	writeJSON(w, http.StatusAccepted, map[string]string{"status": "started"})
}

func (s *serverState) handleCancel(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.cancelFlash != nil {
		s.cancelFlash()
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelling"})
}

func (s *serverState) handleQuit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "bye"})
	s.onceQuit.Do(func() {
		go func() {
			time.Sleep(100 * time.Millisecond)
			close(s.shutdownCh)
		}()
	})
}

func (s *serverState) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("token") != s.token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan flash.ProgressEvent, 64)
	s.mu.Lock()
	s.subs[ch] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.subs, ch)
		s.mu.Unlock()
	}()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.shutdownCh:
			return
		case ev := <-ch:
			b, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		}
	}
}

func (s *serverState) broadcast(ev flash.ProgressEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
