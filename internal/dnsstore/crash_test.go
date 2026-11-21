// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsstore

import (
	"errors"
	"math/rand"
	"testing"

	"dnshived/internal/dnsstore/vfs/faultfs"
)

func scenarioOptions(fs *faultfs.FS, create bool) Options {
	return Options{FS: fs, Keys: testKeys(), Create: create, SegmentSize: 700, SnapshotBytes: 1 << 40}
}

// runScenario commits, snapshots and rotates until done or until the injected crash; states[i] is the model at revision i,
// inflight is the state if the operation that failed had in fact become durable.
func runScenario(fs *faultfs.FS) (states []model, inflight model) {
	states = []model{{}}
	s, err := Open(testDir, scenarioOptions(fs, true))
	if err != nil {
		return states, nil
	}
	r := rand.New(rand.NewSource(99))
	cur := model{}
	for i := 0; i < 40; i++ {
		b := randBatch(r, 12)
		next := cur.clone()
		next.apply(b)
		if _, err := s.Commit(b); err != nil {
			return states, next
		}
		cur = next
		states = append(states, cur.clone())
		if i%9 == 8 {
			if err := s.Snapshot(); err != nil {
				return states, nil
			}
		}
		if i == 20 {
			if _, err := s.Rotate(2); err != nil {
				return states, cur.clone()
			}
			states = append(states, cur.clone())
		}
	}
	_ = s.Close()
	return states, nil
}

func checkRecovered(t *testing.T, fs *faultfs.FS, states []model, inflight model, label string) {
	t.Helper()
	s, err := Open(testDir, scenarioOptions(fs, false))
	if errors.Is(err, ErrNoStore) {
		if len(states) > 1 {
			t.Fatalf("%s: store vanished after %d acknowledged commits", label, len(states)-1)
		}
		return
	}
	if err != nil {
		t.Fatalf("%s: reopen: %v", label, err)
	}
	acked := len(states) - 1
	head := int(s.View().Rev())
	var want model
	switch {
	case head >= 0 && head <= acked && head == acked:
		want = states[head]
	case head == acked+1 && inflight != nil:
		want = inflight
	default:
		t.Fatalf("%s: head %d with %d acknowledged commits", label, head, acked)
	}
	checkModel(t, s.View(), want)
	if err := s.Verify(); err != nil {
		t.Fatalf("%s: verify: %v", label, err)
	}
	b := putBatch(500, "after-crash")
	if _, err := s.Commit(b); err != nil {
		t.Fatalf("%s: commit after recovery: %v", label, err)
	}
	want = want.clone()
	want.apply(b)
	_ = s.Close()
	s, err = Open(testDir, scenarioOptions(fs, false))
	if err != nil {
		t.Fatalf("%s: second reopen: %v", label, err)
	}
	checkModel(t, s.View(), want)
	_ = s.Close()
}

func TestCrash_EveryOperationBoundary(t *testing.T) {
	probe := faultfs.New(0)
	runScenario(probe)
	total := probe.Ops()
	if total < 100 {
		t.Fatalf("scenario made only %d operations", total)
	}
	for n := 1; n <= total; n++ {
		for _, torn := range []bool{false, true} {
			fs := faultfs.New(int64(n))
			fs.SetCrashAt(n, torn)
			states, inflight := runScenario(fs)
			if !fs.Crashed() {
				continue
			}
			fs.Crash()
			checkRecovered(t, fs, states, inflight, "crash at "+itoa(n)+tornLabel(torn))
		}
	}
}

func TestCrash_DuringRecovery(t *testing.T) {
	probe := faultfs.New(0)
	runScenario(probe)
	total := probe.Ops()
	for n := 5; n <= total; n += 7 {
		fs := faultfs.New(int64(n))
		fs.SetCrashAt(n, true)
		states, inflight := runScenario(fs)
		if !fs.Crashed() {
			continue
		}
		fs.Crash()
		for k := 1; k <= 6; k++ {
			fs.SetCrashAt(k, true)
			if s, err := Open(testDir, scenarioOptions(fs, false)); err == nil {
				_ = s.Close()
			}
			fs.Crash()
		}
		checkRecovered(t, fs, states, inflight, "recovery crash after "+itoa(n))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func tornLabel(torn bool) string {
	if torn {
		return " torn"
	}
	return ""
}
