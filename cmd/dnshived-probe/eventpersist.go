// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// probeFailureLogMaxBytes mirrors internal/auditlog.DefaultMaxBytes —
// same simple, stdlib-only rotation bound, no full log-rotation subsystem.
const probeFailureLogMaxBytes = 10 * 1024 * 1024 // 10MB

// probeFailureLogEntry is one persisted line.
type probeFailureLogEntry struct {
	Timestamp time.Time `json:"ts"`
	Level     string    `json:"level"`
	Prefix    string    `json:"prefix"`
	Message   string    `json:"message"`
}

type probeFailureLog struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
}

// newProbeFailureLog returns nil when path is empty.
func newProbeFailureLog(path string) *probeFailureLog {
	if path == "" {
		return nil
	}
	return &probeFailureLog{path: path, maxBytes: probeFailureLogMaxBytes}
}

// append writes one entry, rotating first if needed.
func (l *probeFailureLog) append(level, prefix, message string) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.rotateIfNeeded(); err != nil {
		return err
	}

	entry := probeFailureLogEntry{
		Timestamp: time.Now().UTC(),
		Level:     level,
		Prefix:    prefix,
		Message:   message,
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
func (l *probeFailureLog) rotateIfNeeded() error {
	info, err := os.Stat(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
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
