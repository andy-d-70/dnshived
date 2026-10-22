// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"

	"dnshived/internal/fsm"
)

func TestTrackUnserved_WarnsOnceRepeatsAndReportsRecovery(t *testing.T) {
	var buf bytes.Buffer
	w, f := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(w); log.SetFlags(f) })

	a := &Agent{role: "core-3", unserved: make(map[string]*unservedState), unservedKnown: map[string]bool{"office": true}}
	in := ReconcileInputs{State: fsm.StateStable, DesiredOwners: map[string]string{"office": "core-1"}}
	start := time.Unix(1_800_000_000, 0)
	count := func() int { return strings.Count(buf.String(), "WARNING scope office") }

	a.trackUnserved("office", false, "not owned in authoritative map", in, start)
	a.trackUnserved("office", false, "not owned in authoritative map", in, start.Add(29*time.Second))
	if count() != 0 {
		t.Fatalf("warned before %s: %q", unservedWarnAfter, buf.String())
	}
	a.trackUnserved("office", false, "not owned in authoritative map", in, start.Add(31*time.Second))
	if count() != 1 {
		t.Fatalf("want one warning after %s, got %q", unservedWarnAfter, buf.String())
	}
	for _, want := range []string{"core-3", "not owned in authoritative map", "desired owner here: core-1", "for 31s"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("warning lacks %q: %q", want, buf.String())
		}
	}
	a.trackUnserved("office", false, "x", in, start.Add(4*time.Minute))
	if count() != 1 {
		t.Fatalf("repeated before %s", unservedRepeat)
	}
	a.trackUnserved("office", false, "x", in, start.Add(31*time.Second+unservedRepeat))
	if count() != 2 {
		t.Fatalf("want a repeat after %s, got %d warnings", unservedRepeat, count())
	}

	in.ServedBy = map[string]string{"office": "core-1"}
	a.trackUnserved("office", false, "", in, start.Add(10*time.Minute))
	if !strings.Contains(buf.String(), "scope office served again by core-1 after 10m0s") {
		t.Fatalf("no recovery line: %q", buf.String())
	}
	if _, still := a.unserved["office"]; still {
		t.Fatal("state kept after recovery")
	}
}

func TestTrackUnserved_ShortGapIsSilent(t *testing.T) {
	var buf bytes.Buffer
	w := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(w) })

	a := &Agent{role: "core-1", unserved: make(map[string]*unservedState), unservedKnown: map[string]bool{"office": true}}
	start := time.Unix(1_800_000_000, 0)
	a.trackUnserved("office", false, "settling", ReconcileInputs{}, start)
	a.trackUnserved("office", true, "", ReconcileInputs{}, start.Add(4*time.Second))
	if buf.Len() != 0 {
		t.Fatalf("a gap shorter than %s must not log: %q", unservedGapLog, buf.String())
	}
}

func TestTrackUnserved_HandoverGapIsLoggedWhenItEnds(t *testing.T) {
	var buf bytes.Buffer
	w, f := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(w); log.SetFlags(f) })

	a := &Agent{role: "core-1", unserved: make(map[string]*unservedState), unservedKnown: map[string]bool{"office": true}}
	start := time.Unix(1_800_000_000, 0)
	a.trackUnserved("office", false, "not owned in authoritative map", ReconcileInputs{}, start)
	a.trackUnserved("office", true, "", ReconcileInputs{}, start.Add(27*time.Second))
	if !strings.Contains(buf.String(), "scope office was served by no node for 27s, now served by core-1") {
		t.Fatalf("no gap line: %q", buf.String())
	}
	if strings.Contains(buf.String(), "WARNING") {
		t.Fatalf("a 27 s gap must not warn: %q", buf.String())
	}
}

func TestTrackUnserved_GapFromThisNodesStartIsNotAHandover(t *testing.T) {
	var buf bytes.Buffer
	w := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(w) })

	a := &Agent{role: "core-1", unserved: make(map[string]*unservedState), unservedKnown: make(map[string]bool)}
	start := time.Unix(1_800_000_000, 0)
	a.trackUnserved("office", false, "settling", ReconcileInputs{}, start)
	a.trackUnserved("office", true, "", ReconcileInputs{}, start.Add(20*time.Second))
	if buf.Len() != 0 {
		t.Fatalf("a gap that began before this node looked must not be logged as a handover: %q", buf.String())
	}
}
