// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package access

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReporter_CountsAndEvicts(t *testing.T) {
	r := NewReporter(3)
	now := time.Unix(1000, 0)
	for i := 0; i < 5; i++ {
		r.Add(DNS, addr("203.0.113.1"), now)
	}
	r.Add(Web, addr("203.0.113.2"), now)
	r.Add(DNS, addr("203.0.113.3"), now.Add(time.Second))
	r.Add(DNS, addr("203.0.113.4"), now.Add(2*time.Second))
	rep := r.Snapshot(false, now)
	if len(rep.Items) != 3 {
		t.Fatalf("items = %d, want the cap of 3", len(rep.Items))
	}
	if rep.Items[0].Src != "203.0.113.1" || rep.Items[0].Count != 5 {
		t.Errorf("the most counted source must come first and stay: %+v", rep.Items[0])
	}
	if rep.Dropped != 8 {
		t.Errorf("dropped = %d, want 8 (every packet counts, evicted or not)", rep.Dropped)
	}
	for _, it := range rep.Items {
		if it.Src == "203.0.113.2" {
			t.Error("the least counted, oldest source should have been evicted")
		}
	}
}

func TestReporter_NilIsSafe(t *testing.T) {
	var r *Reporter
	r.Add(DNS, addr("1.2.3.4"), time.Now())
	if rep := r.Snapshot(true, time.Now()); len(rep.Items) != 0 || !rep.Enforcing {
		t.Errorf("nil reporter snapshot = %+v", rep)
	}
}

func TestReport_WriteRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "r.json")
	if rep, err := ReadReport(path); err != nil || len(rep.Items) != 0 {
		t.Fatalf("a missing report must read as empty, got %+v, %v", rep, err)
	}
	r := NewReporter(0)
	r.Add(DHCP, addr("198.18.0.9"), time.Unix(5, 0))
	if err := WriteReport(path, r.Snapshot(true, time.Unix(6, 0))); err != nil {
		t.Fatal(err)
	}
	got, err := ReadReport(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enforcing || len(got.Items) != 1 || got.Items[0].Svc != "dhcp" || got.Items[0].Src != "198.18.0.9" {
		t.Errorf("round trip = %+v", got)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxReportFile+2)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadReport(path); err == nil {
		t.Error("an oversized report must be refused")
	}
	if err := os.WriteFile(path, []byte("{nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadReport(path); err == nil {
		t.Error("a malformed report must be refused")
	}
}

func TestReporter_RunWritesAndStops(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.json")
	r := NewReporter(0)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.Run(ctx, path, 10*time.Millisecond, func() bool { return false }, nil)
		close(done)
	}()
	r.Add(DNS, addr("203.0.113.7"), time.Now())
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if rep, err := ReadReport(path); err == nil && len(rep.Items) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after the context ended")
	}
	if rep, err := ReadReport(path); err != nil || len(rep.Items) != 1 {
		t.Errorf("final report = %+v, %v", rep, err)
	}
}
