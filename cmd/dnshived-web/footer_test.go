// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"strings"
	"testing"
	"time"
)

func footerRow(name, state string, up bool) statusRow {
	r := statusRow{Node: NodeConfig{Name: name}, Nickname: name, FetchedAt: time.Unix(1000, 0)}
	if !up {
		r.FetchError = "timeout"
		return r
	}
	rev := int64(41)
	r.Status = nodeStatus{Role: "core-1", State: state, ConfigRevision: &rev}
	r.HasSystem = true
	r.System = systemInfo{UptimeSec: 3 * 3600, LoadAvg1: 0.4}
	return r
}

func TestBuildFooter_Level(t *testing.T) {
	now := time.Unix(1005, 0)
	fresh := &footerAttn{At: now.Add(-10 * time.Second)}
	tests := []struct {
		name      string
		rows      []statusRow
		att       *footerAttn
		wantLevel string
		wantState string
	}{
		{"all stable", []statusRow{footerRow("a", "STABLE", true), footerRow("b", "STABLE", true), footerRow("c", "STABLE", true)}, nil, "ok", "STABLE"},
		{"one node settling", []statusRow{footerRow("a", "STABLE", true), footerRow("b", "STABLE", true), footerRow("c", "SETTLING", true)}, nil, "warn", "DEGRADED"},
		{"one node down", []statusRow{footerRow("a", "STABLE", true), footerRow("b", "STABLE", true), footerRow("c", "", false)}, nil, "warn", "DEGRADED"},
		{"majority down", []statusRow{footerRow("a", "STABLE", true), footerRow("b", "", false), footerRow("c", "", false)}, nil, "crit", "DEGRADED"},
		{"no rows", nil, nil, "crit", "NO NODES"},
		{"all unreachable", []statusRow{footerRow("a", "", false)}, nil, "crit", "NO NODES"},
		{"fresh warnings lift ok to warn", []statusRow{footerRow("a", "STABLE", true)}, &footerAttn{Warnings: 2, At: fresh.At}, "warn", "STABLE"},
		{"fresh alerts make it crit", []statusRow{footerRow("a", "STABLE", true)}, &footerAttn{Alerts: 1, At: fresh.At}, "crit", "STABLE"},
		{"old counts are ignored", []statusRow{footerRow("a", "STABLE", true)}, &footerAttn{Alerts: 3, At: now.Add(-2 * footerAttnMaxAge)}, "ok", "STABLE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildFooter(tt.rows, tt.att, now)
			if got.Level != tt.wantLevel || got.State != tt.wantState {
				t.Errorf("level/state = %s/%s, want %s/%s", got.Level, got.State, tt.wantLevel, tt.wantState)
			}
		})
	}
}

func TestBuildFooter_NodesRevisionAndAge(t *testing.T) {
	rows := []statusRow{footerRow("b", "STABLE", true), footerRow("a", "STABLE", true), footerRow("z", "", false)}
	got := buildFooter(rows, nil, time.Unix(1007, 0))
	if len(got.Nodes) != 3 || got.Nodes[0].Name != "a" || got.Nodes[2].Name != "z" {
		t.Fatalf("nodes must be sorted by name: %+v", got.Nodes)
	}
	if got.Nodes[0].Uptime != "3h 0m" || got.Nodes[0].Load != "0.40" || !got.Nodes[0].Up {
		t.Errorf("node a = %+v", got.Nodes[0])
	}
	if got.Nodes[2].Up {
		t.Error("an unreachable node must not be marked up")
	}
	if got.Revision != 41 {
		t.Errorf("revision = %d, want 41", got.Revision)
	}
	if got.AgeSec != 7 {
		t.Errorf("age = %d, want 7", got.AgeSec)
	}
}

func TestFooterEvent(t *testing.T) {
	if got := footerEvent(nil); got != "" {
		t.Errorf("no events must give an empty string, got %q", got)
	}
	got := footerEvent([]logRow{{Time: "11-17 10:53:29", Prefix: "PROBE:DHCP_OK", Message: "scope-002 recovered"}})
	if got != "10:53 PROBE:DHCP_OK scope-002 recovered" {
		t.Errorf("got %q", got)
	}
	long := footerEvent([]logRow{{Time: "11-17 10:53:29", Message: strings.Repeat("x", 500)}})
	if len(long) > 130 {
		t.Errorf("a long event must be cut, got %d bytes", len(long))
	}
}

func TestFooterHTML_StaticAndEscapedByConstruction(t *testing.T) {
	for _, want := range []string{`id="appfoot"`, `data-cs="stale"`, `textContent`, `/api/footer`} {
		if !strings.Contains(footerHTML, want) {
			t.Errorf("footer markup lacks %q", want)
		}
	}
	if strings.Contains(footerHTML, "innerHTML") {
		t.Error("the footer script must set text only, never innerHTML")
	}
}

func TestFooterInvalidate(t *testing.T) {
	footerCache.mu.Lock()
	footerCache.body, footerCache.at = []byte("x"), time.Now()
	footerCache.mu.Unlock()
	footerInvalidate()
	footerCache.mu.Lock()
	defer footerCache.mu.Unlock()
	if footerCache.body != nil {
		t.Error("the cached answer must be gone")
	}
}
