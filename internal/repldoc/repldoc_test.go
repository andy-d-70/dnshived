// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package repldoc

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDoc is a document whose body is a string.
type fakeDoc struct {
	mu       sync.Mutex
	meta     Meta
	body     string
	adoptErr error
	started  int
	drifted  bool
}

func (d *fakeDoc) Meta() Meta {
	d.mu.Lock()
	defer d.mu.Unlock()
	m := d.meta
	m.Hash = BodyHash([]byte(d.body))
	return m
}

func (d *fakeDoc) Marshal() ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return json.Marshal(struct {
		Meta
		Body string `json:"body"`
	}{d.meta, d.body})
}

func (d *fakeDoc) Adopt(raw []byte, from string) (bool, bool, error) {
	if d.adoptErr != nil {
		return false, false, d.adoptErr
	}
	var in struct {
		Meta
		Body string `json:"body"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return false, false, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !Newer(in.Meta, d.meta) {
		return false, false, nil
	}
	d.meta, d.body = in.Meta, in.Body
	return true, false, nil
}

func (d *fakeDoc) StartFirst(self string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.started++
	d.meta = Meta{Version: 1, UpdatedAt: "t1", Origin: self}
	return nil
}

func (d *fakeDoc) Drift(self string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.drifted {
		d.meta = Meta{Version: d.meta.Version + 1, UpdatedAt: "t9", Origin: self}
		d.drifted = false
		return true, nil
	}
	return false, nil
}

// fakeNet routes Do calls to other fakeDocs by peer name.
type fakeNet struct {
	mu    sync.Mutex
	docs  map[string]*fakeDoc
	down  map[string]bool
	calls []string
}

func (n *fakeNet) do(p Peer, method, path string, body []byte) ([]byte, error) {
	n.mu.Lock()
	n.calls = append(n.calls, method+" "+p.Name+" "+path)
	down := n.down[p.Name]
	d := n.docs[p.Name]
	n.mu.Unlock()
	if down {
		return nil, errors.New("unreachable")
	}
	switch {
	case method == "GET" && path == "/doc/meta":
		return json.Marshal(d.Meta())
	case method == "GET" && path == "/doc":
		return d.Marshal()
	case method == "POST" && path == "/doc":
		_, _, err := d.Adopt(body, "peer")
		return []byte("{}"), err
	}
	return nil, errors.New("bad request")
}

func newSyncer(self string, doc *fakeDoc, net *fakeNet, peers ...string) (*Syncer, *[]string) {
	var conflicts []string
	var mu sync.Mutex
	s := &Syncer{
		Name: "TEST", Path: "/doc", Doc: doc,
		Self: func() string { return self },
		Peers: func() []Peer {
			var out []Peer
			for _, p := range peers {
				out = append(out, Peer{Name: p})
			}
			return out
		},
		Do: net.do,
		DecodeMeta: func(raw []byte) (Meta, error) {
			var m Meta
			return m, json.Unmarshal(raw, &m)
		},
		OnConflict: func(l, r Meta, peer string) {
			mu.Lock()
			conflicts = append(conflicts, peer)
			mu.Unlock()
		},
		Logf: func(string, ...any) {},
	}
	return s, &conflicts
}

func TestNewerAndConflict(t *testing.T) {
	tests := []struct {
		name         string
		a, b         Meta
		newer, confl bool
	}{
		{"higher version", Meta{Version: 2}, Meta{Version: 1}, true, false},
		{"lower version", Meta{Version: 1}, Meta{Version: 2}, false, false},
		{"same version later time", Meta{Version: 2, UpdatedAt: "b"}, Meta{Version: 2, UpdatedAt: "a"}, true, false},
		{"same version same time higher origin", Meta{Version: 2, UpdatedAt: "a", Origin: "core-2"}, Meta{Version: 2, UpdatedAt: "a", Origin: "core-1"}, true, false},
		{"identical", Meta{Version: 2, UpdatedAt: "a", Origin: "x"}, Meta{Version: 2, UpdatedAt: "a", Origin: "x"}, false, false},
		{"same version different hash", Meta{Version: 3, Hash: "h1"}, Meta{Version: 3, Hash: "h2"}, false, true},
		{"same version same hash", Meta{Version: 3, Hash: "h1"}, Meta{Version: 3, Hash: "h1"}, false, false},
		{"old peer without hash", Meta{Version: 3, Hash: "h1"}, Meta{Version: 3}, false, false},
		{"different version different hash", Meta{Version: 3, Hash: "h1"}, Meta{Version: 4, Hash: "h2"}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Newer(tt.a, tt.b); got != tt.newer {
				t.Errorf("Newer = %v, want %v", got, tt.newer)
			}
			if got := Conflict(tt.a, tt.b); got != tt.confl {
				t.Errorf("Conflict = %v, want %v", got, tt.confl)
			}
		})
	}
}

func TestStartsFirstRevision(t *testing.T) {
	if !StartsFirstRevision("core-1", []string{"core-2", "core-3"}) {
		t.Error("lowest name must start")
	}
	if StartsFirstRevision("core-2", []string{"core-1"}) {
		t.Error("a higher name must not start")
	}
	if !StartsFirstRevision("core-3", nil) {
		t.Error("a lone instance starts")
	}
}

func TestSyncOnce_PullsNewerAndPushesToBehind(t *testing.T) {
	local := &fakeDoc{meta: Meta{Version: 3, UpdatedAt: "t3", Origin: "core-1"}, body: "local"}
	ahead := &fakeDoc{meta: Meta{Version: 5, UpdatedAt: "t5", Origin: "core-2"}, body: "ahead"}
	behind := &fakeDoc{meta: Meta{Version: 1, UpdatedAt: "t1", Origin: "core-3"}, body: "behind"}
	net := &fakeNet{docs: map[string]*fakeDoc{"core-2": ahead, "core-3": behind}}
	s, _ := newSyncer("core-1", local, net, "core-2", "core-3")
	s.SyncOnce()
	if local.body != "ahead" || local.meta.Version != 5 {
		t.Errorf("local did not take the newer document: %+v %q", local.meta, local.body)
	}
	if behind.body != "ahead" || behind.meta.Version != 5 {
		t.Errorf("the lagging peer did not receive the newer document: %+v %q", behind.meta, behind.body)
	}
}

func TestSyncOnce_UnreachablePeerDoesNotStopTheRest(t *testing.T) {
	local := &fakeDoc{meta: Meta{Version: 1, UpdatedAt: "t1", Origin: "core-1"}, body: "local"}
	ahead := &fakeDoc{meta: Meta{Version: 4, UpdatedAt: "t4", Origin: "core-3"}, body: "ahead"}
	net := &fakeNet{docs: map[string]*fakeDoc{"core-2": {}, "core-3": ahead}, down: map[string]bool{"core-2": true}}
	s, _ := newSyncer("core-1", local, net, "core-2", "core-3")
	s.SyncOnce()
	if local.body != "ahead" {
		t.Error("an unreachable peer blocked catching up from the reachable one")
	}
}

func TestSyncOnce_FlagsSameVersionConflict(t *testing.T) {
	local := &fakeDoc{meta: Meta{Version: 4, UpdatedAt: "t4a", Origin: "core-1"}, body: "mine"}
	other := &fakeDoc{meta: Meta{Version: 4, UpdatedAt: "t4b", Origin: "core-2"}, body: "theirs"}
	net := &fakeNet{docs: map[string]*fakeDoc{"core-2": other}}
	s, conflicts := newSyncer("core-1", local, net, "core-2")
	s.SyncOnce()
	if len(*conflicts) != 1 || (*conflicts)[0] != "core-2" {
		t.Errorf("conflicts = %v", *conflicts)
	}
	if local.body != "theirs" {
		t.Errorf("deterministic order must still pick the later document, local = %q", local.body)
	}
}

func TestSyncOnce_SameVersionSameContentIsNotAConflict(t *testing.T) {
	local := &fakeDoc{meta: Meta{Version: 4, UpdatedAt: "t4a", Origin: "core-1"}, body: "same"}
	other := &fakeDoc{meta: Meta{Version: 4, UpdatedAt: "t4b", Origin: "core-2"}, body: "same"}
	net := &fakeNet{docs: map[string]*fakeDoc{"core-2": other}}
	s, conflicts := newSyncer("core-1", local, net, "core-2")
	s.SyncOnce()
	if len(*conflicts) != 0 {
		t.Errorf("flagged equal content: %v", *conflicts)
	}
}

func TestSyncOnce_FirstRevisionStartedByLowestName(t *testing.T) {
	tests := []struct {
		name    string
		self    string
		peer    string
		started int
	}{
		{"lowest starts", "core-1", "core-2", 1},
		{"higher waits", "core-2", "core-1", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			local := &fakeDoc{body: "x"}
			peerDoc := &fakeDoc{body: "y"}
			net := &fakeNet{docs: map[string]*fakeDoc{tt.peer: peerDoc}}
			s, _ := newSyncer(tt.self, local, net, tt.peer)
			s.SyncOnce()
			if local.started != tt.started {
				t.Errorf("StartFirst called %d times, want %d", local.started, tt.started)
			}
		})
	}
}

func TestSyncOnce_NoFirstRevisionWhenANewerDocumentExists(t *testing.T) {
	local := &fakeDoc{body: "x"}
	peerDoc := &fakeDoc{meta: Meta{Version: 2, UpdatedAt: "t2", Origin: "core-2"}, body: "y"}
	net := &fakeNet{docs: map[string]*fakeDoc{"core-2": peerDoc}}
	s, _ := newSyncer("core-1", local, net, "core-2")
	s.SyncOnce()
	if local.started != 0 || local.body != "y" {
		t.Errorf("started=%d body=%q", local.started, local.body)
	}
}

func TestSyncOnce_DriftIsStampedAndPushed(t *testing.T) {
	local := &fakeDoc{meta: Meta{Version: 2, UpdatedAt: "t2", Origin: "core-1"}, body: "changed", drifted: true}
	other := &fakeDoc{meta: Meta{Version: 2, UpdatedAt: "t2", Origin: "core-1"}, body: "old"}
	net := &fakeNet{docs: map[string]*fakeDoc{"core-2": other}}
	s, _ := newSyncer("core-1", local, net, "core-2")
	s.SyncOnce()
	if local.meta.Version != 3 {
		t.Fatalf("drift not stamped: %+v", local.meta)
	}
	deadline := time.Now().Add(2 * time.Second)
	for other.Meta().Version != 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if other.Meta().Version != 3 || other.body != "changed" {
		t.Errorf("the stamped drift did not reach the peer: %+v %q", other.meta, other.body)
	}
}

func TestSyncOnce_AdoptErrorIsLoggedNotFatal(t *testing.T) {
	local := &fakeDoc{meta: Meta{Version: 1}, adoptErr: errors.New("refused"), body: "x"}
	ahead := &fakeDoc{meta: Meta{Version: 5, UpdatedAt: "t5", Origin: "core-2"}, body: "y"}
	net := &fakeNet{docs: map[string]*fakeDoc{"core-2": ahead}}
	var logged []string
	s, _ := newSyncer("core-1", local, net, "core-2")
	s.Logf = func(f string, a ...any) { logged = append(logged, f) }
	s.SyncOnce()
	if len(logged) == 0 {
		t.Error("an adopt error was not logged")
	}
	if local.body != "x" {
		t.Error("a refused document was installed")
	}
}

func TestRun_ComparesRepeatedlyAndStopsOnCancel(t *testing.T) {
	local := &fakeDoc{meta: Meta{Version: 1, UpdatedAt: "t1", Origin: "core-1"}, body: "x"}
	net := &fakeNet{docs: map[string]*fakeDoc{}}
	s, _ := newSyncer("core-1", local, net)
	var runs atomic.Int64
	s.Self = func() string { runs.Add(1); return "core-1" }
	ctx, cancel := context.WithCancel(context.Background())
	s.Run(ctx, time.Millisecond, time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	for runs.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if runs.Load() < 3 {
		t.Fatalf("only %d comparisons ran", runs.Load())
	}
	cancel()
	time.Sleep(50 * time.Millisecond)
	stopped := runs.Load()
	time.Sleep(50 * time.Millisecond)
	if runs.Load() != stopped {
		t.Errorf("comparisons continued after cancel: %d -> %d", stopped, runs.Load())
	}
}

func TestValidMeta(t *testing.T) {
	long := string(make([]byte, maxStampLen+1))
	tests := []struct {
		name string
		m    Meta
		ok   bool
	}{
		{"normal", Meta{Version: 7, UpdatedAt: "2026-11-07T10:00:00Z", Origin: "core-1", Hash: "abc"}, true},
		{"zero", Meta{}, true},
		{"negative version", Meta{Version: -1}, false},
		{"huge version", Meta{Version: maxVersion + 1}, false},
		{"max version", Meta{Version: maxVersion}, true},
		{"long stamp", Meta{UpdatedAt: long}, false},
		{"long origin", Meta{Origin: long}, false},
		{"long hash", Meta{Hash: long}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidMeta(tt.m); (err == nil) != tt.ok {
				t.Errorf("ValidMeta = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}
