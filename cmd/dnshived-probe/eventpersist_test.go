// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dnshived/internal/eventlog"
)

func TestNewProbeFailureLog_EmptyPathReturnsNil(t *testing.T) {
	if l := newProbeFailureLog(""); l != nil {
		t.Errorf("newProbeFailureLog(\"\") = %v, want nil (persistence disabled)", l)
	}
}

// TestProbeFailureLog_NilAppendIsNoOp confirms a nil *probeFailureLog
// (persistence disabled) is safe to call append on directly.
func TestProbeFailureLog_NilAppendIsNoOp(t *testing.T) {
	var l *probeFailureLog
	if err := l.append("WARNING", "PROBE:DHCP_FAIL", "rw-100: no answer"); err != nil {
		t.Errorf("nil.append() = %v, want nil error", err)
	}
}

func TestProbeFailureLog_AppendAndReadBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	l := newProbeFailureLog(path)

	if err := l.append("WARNING", "PROBE:DHCP_FAIL", "rw-100: no answer"); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := l.append("INFO", "PROBE:DHCP_OK", "rw-100: DHCP recovered"); err != nil {
		t.Fatalf("append: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2: %q", len(lines), data)
	}
	var e probeFailureLogEntry
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatalf("unmarshal first entry: %v", err)
	}
	if e.Level != "WARNING" || e.Prefix != "PROBE:DHCP_FAIL" || e.Message != "rw-100: no answer" {
		t.Errorf("first entry = %+v, want level=WARNING prefix=PROBE:DHCP_FAIL message=%q", e, "rw-100: no answer")
	}
}

func TestProbeFailureLog_RotatesAtThreshold(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	l := newProbeFailureLog(path)
	l.maxBytes = 100

	for i := 0; i < 10; i++ {
		if err := l.append("WARNING", "PROBE:DHCP_FAIL", "padding entry to grow the file past the threshold"); err != nil {
			t.Fatalf("append #%d: %v", i, err)
		}
	}

	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("expected a rotated backup file at %s.1, got: %v", path, err)
	}
}

func TestProbeLogTracker_PersistsToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	tracker := newProbeLogTracker(newProbeFailureLog(path))
	events := eventlog.New(100, "probe")

	healthy := ScopeProbeResult{Scope: "rw-100", Enabled: true}
	healthy.DHCP.Verdict = "ok"
	healthy.DHCP.Valid = true

	failing := healthy
	failing.DHCP.Verdict = "no_answer"
	failing.DHCP.Reason = "no answer"

	tracker.check(events, "rw-100", healthy)
	tracker.check(events, "rw-100", failing)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted log: %v", err)
	}
	if !strings.Contains(string(data), "rw-100: no answer") {
		t.Errorf("persisted log = %q, want it to contain the DHCP failure message", data)
	}
}
