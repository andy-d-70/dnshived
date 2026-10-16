// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package auditlog provides a persisted, append-only record of write
// actions taken through the web UI (cmd/dnshived-web): who changed what,
// when.
package auditlog

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// DefaultMaxBytes is the size threshold past which Append rotates the log
// file before writing.
const DefaultMaxBytes = 10 * 1024 * 1024 // 10MB

// Entry is a single audit record — field names match internal/eventlog's
// Event style (ts, node_id) for consistency across the two logs.
type Entry struct {
	Timestamp time.Time `json:"ts"`
	Actor     string    `json:"actor"`   // the web-UI credential name that performed the action
	NodeID    string    `json:"node_id"` // which node's dnshived recorded this entry
	Action    string    `json:"action"`  // e.g. "config.scopes.save"
	Summary   string    `json:"summary"`
}

// Logger appends Entry records to a single append-only file, rotating it
// once it exceeds MaxBytes.
type Logger struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
}

// New creates a Logger writing to path, using DefaultMaxBytes as the
// rotation threshold.
func New(path string) *Logger {
	return &Logger{path: path, maxBytes: DefaultMaxBytes}
}

// Append records one audit entry, rotating the file first if it's grown
// past the threshold.
func (l *Logger) Append(actor, nodeID, action, summary string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.rotateIfNeeded(); err != nil {
		return err
	}

	entry := Entry{
		Timestamp: time.Now().UTC(),
		Actor:     actor,
		NodeID:    nodeID,
		Action:    action,
		Summary:   summary,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

// rotateIfNeeded renames the current file to path+".1" (dropping any prior
// ".1", best-effort) once it's at or past maxBytes.
func (l *Logger) rotateIfNeeded() error {
	info, err := os.Stat(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // nothing written yet
		}
		return err
	}
	if info.Size() < l.maxBytes {
		return nil
	}
	backup := l.path + ".1"
	os.Remove(backup)
	return os.Rename(l.path, backup)
}

// ReadAll returns the raw newline-delimited-JSON bytes of the full
// retained history, for export (GET /api/v1/audit) — nil, nil if nothing
// has been written yet.
func (l *Logger) ReadAll() ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var out []byte
	backup, err := os.ReadFile(l.path + ".1")
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	out = append(out, backup...)

	data, err := os.ReadFile(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			if len(out) == 0 {
				return nil, nil
			}
			return out, nil
		}
		return nil, err
	}
	out = append(out, data...)
	return out, nil
}
