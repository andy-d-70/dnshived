// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func strictProbeInstance(t *testing.T, idx *fakeIndex, name string, hosts []NodeConfig) (*probeHostsDoc, *configRef, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "web.json")
	cfg := &WebConfig{ProbeHosts: append([]NodeConfig(nil), hosts...), ProbeHostsVersion: 1, ProbeHostsUpdatedAt: "2026-11-27T10:00:00Z", ProbeHostsOrigin: "seed"}
	cfg.ProbeHostsHash = probeHostsHash(cfg.ProbeHosts)
	if err := saveWebConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	ref := newConfigRef(cfg)
	d := newProbeHostsDoc(ref, path, func() string { return name })
	d.strict = &usersStrict{latched: true, refresh: func() {}, getIndex: idx.get, post: idx.post, now: time.Now}
	return d, ref, path
}

func useProbeDoc(t *testing.T, d *probeHostsDoc) {
	t.Helper()
	prev := probeHostsShared
	probeHostsShared = d
	t.Cleanup(func() { probeHostsShared = prev })
}

func renamed(cfg *WebConfig, addr, name string) *WebConfig {
	next := *cfg
	next.ProbeHosts = append([]NodeConfig(nil), cfg.ProbeHosts...)
	for i := range next.ProbeHosts {
		if next.ProbeHosts[i].Addr == addr {
			next.ProbeHosts[i].DisplayName = name
		}
	}
	return &next
}

func displayOf(ref *configRef, addr string) string {
	for _, h := range ref.Load().ProbeHosts {
		if h.Addr == addr {
			return h.DisplayName
		}
	}
	return "<absent>"
}

var seedProbes = []NodeConfig{{Name: "probe", Addr: "10.0.0.9:9443", AdminToken: "t1"}, {Name: "probe", Addr: "10.0.0.10:9443", AdminToken: "t2"}}

func TestProbeHostsStrict_TheSecondChangeOfTheSameHostIsRefused(t *testing.T) {
	idx := newFakeIndex()
	a, refA, pathA := strictProbeInstance(t, idx, "core1", seedProbes)
	b, refB, pathB := strictProbeInstance(t, idx, "core2", seedProbes)
	useProbeDoc(t, a)
	if err := saveProbeHostsChange(pathA, refA, refA.Load(), renamed(refA.Load(), "10.0.0.9:9443", "lab A")); err != nil {
		t.Fatal(err)
	}
	if refA.Load().ProbeHostsVersion != 2 {
		t.Fatal("an ordered change stamps a new revision so it spreads")
	}
	useProbeDoc(t, b)
	err := saveProbeHostsChange(pathB, refB, refB.Load(), renamed(refB.Load(), "10.0.0.9:9443", "lab B"))
	if err == nil || !strings.Contains(err.Error(), "was changed on core1") || displayOf(refB, "10.0.0.9:9443") != "" {
		t.Fatalf("refused, nothing saved: %v, %q", err, displayOf(refB, "10.0.0.9:9443"))
	}
	if err := saveProbeHostsChange(pathB, refB, refB.Load(), renamed(refB.Load(), "10.0.0.10:9443", "lab C")); err != nil {
		t.Fatalf("another probe host is not refused: %v", err)
	}
}

func TestProbeHostsStrict_AStaleListNeverReplacesTheOrderedHost(t *testing.T) {
	idx := newFakeIndex()
	a, refA, pathA := strictProbeInstance(t, idx, "core1", seedProbes)
	stale, refS, _ := strictProbeInstance(t, idx, "core3", seedProbes)
	useProbeDoc(t, a)
	if err := saveProbeHostsChange(pathA, refA, refA.Load(), renamed(refA.Load(), "10.0.0.9:9443", "ordered")); err != nil {
		t.Fatal(err)
	}
	old := renamed(refS.Load(), "10.0.0.9:9443", "stale")
	old.ProbeHostsVersion = 9
	refS.Store(old)
	raw, _ := stale.Marshal()
	_, spread, err := a.Adopt(raw, "core3")
	if err != nil {
		t.Fatal(err)
	}
	if displayOf(refA, "10.0.0.9:9443") != "ordered" || !spread {
		t.Fatalf("the ordered version stays and spreads: %q %v", displayOf(refA, "10.0.0.9:9443"), spread)
	}
}

func TestProbeHostsStrict_AnAddWithoutMajorityIsKeptAndListedOnceAccepted(t *testing.T) {
	idx := newFakeIndex()
	a, refA, pathA := strictProbeInstance(t, idx, "core1", seedProbes)
	useProbeDoc(t, a)
	next := *refA.Load()
	next.ProbeHosts = append(append([]NodeConfig(nil), refA.Load().ProbeHosts...), NodeConfig{Name: "probe", Addr: "10.0.0.11:9443", AdminToken: "fresh"})
	idx.fail = true
	if err := saveProbeHostsChange(pathA, refA, refA.Load(), &next); !errors.Is(err, errNotConfirmed) {
		t.Fatalf("not confirmed: %v", err)
	}
	if displayOf(refA, "10.0.0.11:9443") != "<absent>" {
		t.Fatal("not listed before the cores accept it")
	}
	if _, err := os.Stat(a.pendingPath()); err != nil {
		t.Fatal("the new probe host (with its token) is kept on disk")
	}
	idx.fail = false
	a.settle()
	if displayOf(refA, "10.0.0.11:9443") != "" {
		t.Fatal("listed once the cores accept it")
	}
	if _, err := os.Stat(a.pendingPath()); !os.IsNotExist(err) {
		t.Fatal("pending cleared")
	}
}

func TestProbeHostsStrict_ASiblingsDirectChangeIsPulledNotApplied(t *testing.T) {
	idx := newFakeIndex()
	a, _, _ := strictProbeInstance(t, idx, "core1", seedProbes)
	useProbeDoc(t, a)
	pulled := make(chan struct{}, 1)
	a.sync = func() { pulled <- struct{}{} }
	if !a.pullFromSiblings() {
		t.Fatal("strict mode answers a direct change with a pull")
	}
	select {
	case <-pulled:
	case <-time.After(2 * time.Second):
		t.Fatal("the ordered comparison runs")
	}
	a.strict.latched = false
	if a.pullFromSiblings() {
		t.Fatal("without strict mode the direct change is applied as before")
	}
}
