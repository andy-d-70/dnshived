// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package auditlog provides a persisted, append-only record of write
// actions taken through the web UI (cmd/dnshived-web): who changed what,
// when.
package auditlog

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ErrFileCopy marks an entry that is stored but whose line in the local audit.log (kept for a downgrade) failed.
var ErrFileCopy = errors.New("auditlog: entry stored, local file copy failed")

// DefaultMaxBytes is the size threshold past which Append rotates the log
// file before writing.
const DefaultMaxBytes = 10 * 1024 * 1024 // 10MB

// Entry is a single audit record — field names match internal/eventlog's
// Event style (ts, node_id) for consistency across the two logs.
type Entry struct {
	ID        string    `json:"id,omitempty"`
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
	store    *Store
	onAppend func(StoredEntry)
}

// Attach makes the store the place entries are kept; the file stays as a copy for a downgrade. onAppend, if set, is
// called with every new entry after it is stored and must not block.
func (l *Logger) Attach(s *Store, onAppend func(StoredEntry)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.store, l.onAppend = s, onAppend
}

// Store returns the attached store or nil.
func (l *Logger) Store() *Store {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.store
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

	entry := Entry{
		Timestamp: time.Now().UTC(),
		Actor:     actor,
		NodeID:    nodeID,
		Action:    action,
		Summary:   summary,
	}
	var id ID
	if l.store != nil {
		if _, err := rand.Read(id[:]); err != nil {
			return fmt.Errorf("auditlog: entry id: %w", err)
		}
		entry.ID = hex.EncodeToString(id[:])
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if l.store == nil {
		return l.appendFile(data)
	}
	if _, err := l.store.Append([]StoredEntry{{ID: id, Body: data}}); err != nil {
		return err
	}
	if l.onAppend != nil {
		l.onAppend(StoredEntry{ID: id, Body: data})
	}
	if err := l.appendFile(data); err != nil {
		return fmt.Errorf("%w: %w", ErrFileCopy, err)
	}
	return nil
}

func (l *Logger) appendFile(line []byte) error {
	if err := l.rotateIfNeeded(); err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// rotateIfNeeded moves the current file to path+".1" once it is at or past maxBytes. A previous ".1" is archived as
// path+".archive-<UTC time>", never deleted; an older version that reads only ".1" and the current file still works.
func (l *Logger) rotateIfNeeded() error {
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
	if _, err := os.Stat(backup); err == nil {
		archive := l.path + ".archive-" + time.Now().UTC().Format("20060102T150405.000000000Z")
		if _, err := os.Stat(archive); err == nil {
			return fmt.Errorf("auditlog: archive %s already exists", archive)
		}
		if err := os.Rename(backup, archive); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(l.path, backup); err != nil {
		return err
	}
	return syncDir(filepath.Dir(l.path))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Files lists the audit files oldest first: archives, then ".1", then the current file (only those that exist).
func (l *Logger) Files() ([]string, error) {
	archives, err := filepath.Glob(l.path + ".archive-*")
	if err != nil {
		return nil, err
	}
	sort.Strings(archives)
	out := archives
	for _, p := range []string{l.path + ".1", l.path} {
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	return out, nil
}

// ReadAll returns the raw newline-delimited JSON of every audit file this node holds, oldest first (archives, ".1",
// current) — nil, nil if nothing has been written yet.
func (l *Logger) ReadAll() ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	files, err := l.Files()
	if err != nil {
		return nil, err
	}
	var out []byte
	for _, p := range files {
		data, err := os.ReadFile(p)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		out = append(out, data...)
	}
	return out, nil
}
