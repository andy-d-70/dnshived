// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package state manages persistent node-local runtime state under
// /var/lib/dnshived.
package state

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DefaultDir is where dnshived stores persistent runtime state.
const DefaultDir = "/var/lib/dnshived"

// NextIncarnation reads the persisted incarnation counter, increments it,
// writes it back, and returns the new value.
func NextIncarnation(dir string) (uint64, error) {
	if dir == "" {
		dir = DefaultDir
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return 0, fmt.Errorf("create state dir: %w", err)
	}
	path := filepath.Join(dir, "incarnation")

	var current uint64
	data, err := os.ReadFile(path)
	if err == nil {
		s := strings.TrimSpace(string(data))
		if v, perr := strconv.ParseUint(s, 10, 64); perr == nil {
			current = v
		}
		// A corrupt/unparseable file resets to 0 → next becomes 1.
		// Safe: we only ever move forward from whatever we can read.
	} else if !os.IsNotExist(err) {
		return 0, fmt.Errorf("read incarnation: %w", err)
	}

	next := current + 1

	// Atomic write: temp file + fsync + rename + directory fsync.
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return 0, fmt.Errorf("create incarnation tmp file: %w", err)
	}
	if _, err := f.WriteString(strconv.FormatUint(next, 10) + "\n"); err != nil {
		f.Close()
		return 0, fmt.Errorf("write incarnation: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return 0, fmt.Errorf("sync incarnation: %w", err)
	}
	if err := f.Close(); err != nil {
		return 0, fmt.Errorf("close incarnation: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return 0, fmt.Errorf("commit incarnation: %w", err)
	}
	// Best-effort: fsync the directory entry so the rename itself survives a
	// crash, not just the file's content.
	if dirF, derr := os.Open(dir); derr == nil {
		dirF.Sync()
		dirF.Close()
	}

	return next, nil
}
