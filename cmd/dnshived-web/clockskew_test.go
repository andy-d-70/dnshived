// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

func TestClockSkewOutside(t *testing.T) {
	end := time.Date(2026, 11, 10, 12, 0, 10, 0, time.UTC)
	start := end.Add(-4 * time.Second)
	tests := []struct {
		name    string
		serverT time.Time
		start   time.Time
		want    time.Duration
	}{
		{"inside the window", start.Add(2 * time.Second), start, 0},
		{"at the start, second resolution", start.Add(-time.Second + time.Nanosecond), start, 0},
		{"older than the window", start.Add(-9 * time.Second), start, 8 * time.Second},
		{"newer than the window", end.Add(7 * time.Second), start, 7 * time.Second},
		{"no start uses the end", end.Add(-3 * time.Second), time.Time{}, 2 * time.Second},
		{"start after end is ignored", end.Add(-3 * time.Second), end.Add(time.Hour), 2 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clockSkewOutside(tt.serverT, tt.start, end); got != tt.want {
				t.Errorf("clockSkewOutside() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSkewTracker_Debounce(t *testing.T) {
	var tr skewTracker
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	base := time.Now()
	at := func(i int) time.Time { return base.Add(time.Duration(i) * time.Second) }

	if tr.observe("n1", at(1), 6*time.Second, "core-2") {
		t.Fatal("one reading must not raise")
	}
	if tr.observe("n1", at(1), 6*time.Second, "core-2") {
		t.Fatal("the same snapshot seen again must not count twice")
	}
	if !tr.observe("n1", at(2), 6*time.Second, "core-2") {
		t.Fatal("two fresh readings in a row must raise")
	}
	if !tr.observe("n1", at(3), 7*time.Second, "core-2") {
		t.Fatal("must stay raised while over the limit")
	}
	if tr.observe("n1", at(4), time.Second, "core-2") {
		t.Fatal("a clean reading must clear")
	}
	if tr.observe("n1", at(5), 6*time.Second, "core-2") {
		t.Fatal("after a clear one bad reading must not raise again")
	}
	out := buf.String()
	if strings.Count(out, "skew raised") != 1 || strings.Count(out, "skew cleared") != 1 {
		t.Errorf("want one raised and one cleared line, got %q", out)
	}
	if !strings.Contains(out, "core-2") {
		t.Errorf("log lines must name the observer, got %q", out)
	}
}

func TestSkewTracker_AlternatingReadingsNeverRaise(t *testing.T) {
	var tr skewTracker
	base := time.Now()
	for i := 0; i < 10; i++ {
		skew := time.Second
		if i%2 == 0 {
			skew = 9 * time.Second
		}
		if tr.observe("n1", base.Add(time.Duration(i)*time.Second), skew, "x") {
			t.Fatalf("reading %d: a bad reading between clean ones must not raise", i)
		}
	}
}

func TestSkewTracker_NodesAreIndependentAndBounded(t *testing.T) {
	var tr skewTracker
	base := time.Now()
	tr.observe("a", base, 9*time.Second, "x")
	tr.observe("b", base, time.Second, "x")
	if !tr.observe("a", base.Add(time.Second), 9*time.Second, "x") {
		t.Error("node a must raise on its own two readings")
	}
	if tr.observe("b", base.Add(time.Second), 9*time.Second, "x") {
		t.Error("node b has only one bad reading")
	}
	for i := 0; i < 3*clockSkewMaxTracked; i++ {
		tr.observe("n"+time.Duration(i).String(), base, time.Second, "x")
	}
	tr.mu.Lock()
	n := len(tr.nodes)
	tr.mu.Unlock()
	if n > clockSkewMaxTracked {
		t.Errorf("tracked %d nodes, limit %d", n, clockSkewMaxTracked)
	}
}

// A cached snapshot older than the longest age the web UI serves must not
// make its nodes look skewed: rows carry the snapshot's own fetch window.
func TestStatusRowsFromSnapshot_RowsCarryTheFetchWindow(t *testing.T) {
	clockSkewTracker.reset()
	end := time.Now().Add(-snapshotMaxServeAge)
	start := end.Add(-300 * time.Millisecond)
	node := NodeConfig{Name: "core-1", Addr: "192.0.2.1:9443"}
	st := `{"node_id":"n1","role":"core-1","server_time":"` + start.UTC().Format(time.RFC3339) + `"}`
	byAddr := map[string]clusterSnapshotNode{node.Addr: {Status: []byte(st)}}
	snap := clusterSnapshotResponse{FetchStart: start, FetchEnd: end}

	rows := statusRowsFromSnapshot([]NodeConfig{node}, byAddr, snap)
	if len(rows) != 1 {
		t.Fatalf("rows = %d", len(rows))
	}
	if !rows[0].FetchedAt.Equal(end) || !rows[0].FetchStart.Equal(start) {
		t.Errorf("row window = [%v, %v], want the snapshot's [%v, %v]", rows[0].FetchStart, rows[0].FetchedAt, start, end)
	}
	for i := 0; i < clockSkewReadings+1; i++ {
		if w := skewWarnings(checkCoherence(rows, map[string]tokenInfo{})); len(w) != 0 {
			t.Errorf("a snapshot %v old must not warn, got %v", snapshotMaxServeAge, w)
		}
		rows[0].FetchedAt = rows[0].FetchedAt.Add(time.Millisecond)
		rows[0].FetchStart = rows[0].FetchStart.Add(time.Millisecond)
	}
}
