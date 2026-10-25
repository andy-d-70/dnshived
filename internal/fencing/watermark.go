// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package fencing

import (
	"dnshived/internal/loglevel"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Watermark is each node's monotonic memory of the highest fencing Token
// it has observed backed by INDEPENDENTLY-VERIFIED quorum.
type Watermark struct {
	mu      sync.RWMutex
	current Token
	path    string // persistence path; "" disables persistence
}

// NewWatermark creates a watermark, loading any persisted value from
// <dir>/fencing.
func NewWatermark(dir string) (*Watermark, error) {
	w := &Watermark{}
	if dir != "" {
		w.path = filepath.Join(dir, "fencing")
		if err := w.load(); err != nil {
			return nil, err
		}
	}
	return w, nil
}

func (w *Watermark) load() error {
	data, err := os.ReadFile(w.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // legitimate first run → start at (0,0)
		}
		return fmt.Errorf("read watermark %s: %w", w.path, err)
	}
	var t Token
	if err := json.Unmarshal(data, &t); err != nil {
		return fmt.Errorf("corrupt watermark %s: %w", w.path, err)
	}
	w.current = t
	return nil
}

// persist writes the watermark to disk using atomic tmp+rename with full
// fsync.
func (w *Watermark) persist() {
	if w.path == "" {
		return
	}
	data, err := json.Marshal(w.current)
	if err != nil {
		loglevel.Warnf("[FENCING:CRITICAL]: cannot marshal watermark: %v", err)
		return
	}
	if err := atomicWriteSync(w.path, data); err != nil {
		loglevel.Warnf("[FENCING:CRITICAL]: watermark persistence failed: %v", err)
		// The watermark advanced in memory but NOT on disk.
	}
}

// atomicWriteSync writes data to path via tmp+rename with full fsync on
// both the file and the parent directory.
func atomicWriteSync(path string, data []byte) error {
	tmp := path + ".tmp"

	// 1. Write to temporary file.
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write tmp: %w", err)
	}

	// 2. Fsync the file — data reaches physical media.
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("fsync data: %w", err)
	}

	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close tmp: %w", err)
	}

	// 3. Atomic rename.
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}

	// 4. Fsync the parent directory — the rename itself is persisted.
	dir, err := os.Open(filepath.Dir(path))
	if err == nil {
		_ = dir.Sync()
		dir.Close()
	}

	return nil
}

// Current returns the current watermark token.
func (w *Watermark) Current() Token {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.current
}

// Advance moves the watermark forward to candidate IF it is strictly
// higher.
func (w *Watermark) Advance(candidate Token) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if candidate.Compare(w.current) > 0 {
		w.current = candidate
		w.persist()
		return true
	}
	return false
}

// Fenced reports whether a claim carrying token `claim` is fenced out —
// i.e. strictly below the current watermark and therefore must be refused.
func (w *Watermark) Fenced(claim Token) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return claim.Less(w.current)
}
