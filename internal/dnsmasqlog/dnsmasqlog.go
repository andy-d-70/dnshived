// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsmasqlog

import (
	"io"
	"os"
	"strings"
	"sync"
)

// Finding is one noteworthy dnsmasq log line, classified and ready to
// forward into a caller's own event log.
type Finding struct {
	Level string // "WARNING" or "ERROR" — matches internal/eventlog's own level strings
	Line  string // the raw dnsmasq line, unmodified
}

// TailLines returns the last n lines of a scope's dnsmasq log file, in
// original (oldest-first) order.
func TailLines(path string, n int) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	all := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(all) == 1 && all[0] == "" {
		return nil, nil
	}
	if len(all) <= n {
		return all, nil
	}
	return all[len(all)-n:], nil
}

// Classify reports whether line is noteworthy enough to surface, and at
// what level.
func Classify(line string) (level string, ok bool) {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(line, "DHCPNAK"):
		return "WARNING", true
	case strings.Contains(lower, "not using configured address"):
		return "WARNING", true
	case strings.Contains(lower, "possible dns-rebind attack"):
		return "WARNING", true
	case strings.Contains(lower, "failed to"),
		strings.Contains(lower, "cannot "),
		strings.Contains(lower, "unable to"),
		strings.Contains(lower, "bad address at line"),
		strings.Contains(lower, "bad name at line"):
		return "ERROR", true
	default:
		return "", false
	}
}

// Tailer tracks, per scope, the last byte offset read from that scope's
// own dnsmasq log file.
type Tailer struct {
	mu      sync.Mutex
	offsets map[string]int64
}

// New returns a ready-to-use Tailer.
func New() *Tailer {
	return &Tailer{offsets: make(map[string]int64)}
}

// CheckScope reads any new lines appended to path (that scope's own
// dnsmasq log file) since the last call for this scope, and returns the
// noteworthy ones.
func (t *Tailer) CheckScope(path, scope string) []Finding {
	t.mu.Lock()
	defer t.mu.Unlock()

	fi, err := os.Stat(path)
	if err != nil {
		return nil
	}

	lastOffset, known := t.offsets[scope]
	if !known {
		t.offsets[scope] = fi.Size()
		return nil
	}
	if fi.Size() < lastOffset {
		lastOffset = 0
	}
	if fi.Size() == lastOffset {
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	if _, err := f.Seek(lastOffset, io.SeekStart); err != nil {
		return nil
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil
	}
	t.offsets[scope] = lastOffset + int64(len(data))

	var findings []Finding
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		if level, ok := Classify(line); ok {
			findings = append(findings, Finding{Level: level, Line: line})
		}
	}
	return findings
}
