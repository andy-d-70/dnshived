// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsrepl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"dnshived/internal/dnsstore"
	"dnshived/internal/dnsstore/vfs"
)

const liveToken = "live-test-token"

type live struct {
	t     *testing.T
	ids   []string
	dirs  map[string]string
	mu    sync.Mutex
	addr  map[string]string
	nodes map[string]*liveNode
}

type liveNode struct {
	st  *dnsstore.Store
	n   *Node
	drv *Driver
	srv *httptest.Server
}

func newLive(t *testing.T, ids ...string) *live {
	l := &live{t: t, ids: ids, dirs: map[string]string{}, addr: map[string]string{}, nodes: map[string]*liveNode{}}
	for _, id := range ids {
		l.dirs[id] = filepath.Join(t.TempDir(), "store")
	}
	t.Cleanup(func() {
		for id := range l.nodes {
			l.stop(id)
		}
	})
	return l
}

func (l *live) start(id string) {
	l.t.Helper()
	st, err := dnsstore.Open(l.dirs[id], dnsstore.Options{Keys: simKeys(), Create: true, StoreID: testID, SegmentSize: 4096, SnapshotBytes: 1 << 40})
	if err != nil {
		l.t.Fatal(err)
	}
	var peers []string
	for _, o := range l.ids {
		if o != id {
			peers = append(peers, o)
		}
	}
	n, err := New(Config{ID: id, Peers: peers, Membership: 1, BatchEntries: 16}, st, vfs.OS{}, l.dirs[id])
	if err != nil {
		l.t.Fatal(err)
	}
	tr := &HTTPTransport{Client: &http.Client{Timeout: 3 * time.Second}, Scheme: "http", Token: liveToken, Addr: func(p string) (string, bool) {
		l.mu.Lock()
		defer l.mu.Unlock()
		a, ok := l.addr[p]
		return a, ok
	}}
	drv := NewDriver(n, tr, DriverConfig{Tick: 10 * time.Millisecond, Heartbeat: 30 * time.Millisecond, ElectionMin: 200 * time.Millisecond, ElectionMax: 500 * time.Millisecond, RPCTimeout: time.Second, Seed: int64(len(id))})
	mux := http.NewServeMux()
	drv.Routes(mux, liveToken, nil)
	srv := httptest.NewServer(mux)
	l.mu.Lock()
	l.addr[id] = srv.Listener.Addr().String()
	l.nodes[id] = &liveNode{st: st, n: n, drv: drv, srv: srv}
	l.mu.Unlock()
	drv.Start()
}

func (l *live) stop(id string) {
	l.mu.Lock()
	ln := l.nodes[id]
	delete(l.nodes, id)
	l.mu.Unlock()
	if ln == nil {
		return
	}
	ln.drv.Stop()
	ln.srv.Close()
	_ = ln.st.Close()
}

func (l *live) get(id string) *liveNode {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.nodes[id]
}

func (l *live) leader() (string, *liveNode) {
	for _, id := range l.ids {
		if ln := l.get(id); ln != nil && ln.n.Role() == Leader {
			return id, ln
		}
	}
	return "", nil
}

func (l *live) waitLeader(except string) (string, *liveNode) {
	l.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if id, ln := l.leader(); ln != nil && id != except {
			return id, ln
		}
		time.Sleep(10 * time.Millisecond)
	}
	l.t.Fatal("no leader elected")
	return "", nil
}

func (l *live) propose(ln *liveNode, row int) uint64 {
	l.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rev, err := ln.drv.Propose(ctx, dnsstore.Batch{Origin: 3, Author: "live", Ops: []dnsstore.Op{{Kind: dnsstore.OpPut, Type: 1, ID: rowID(row), Body: []byte(fmt.Sprintf("v%d", row))}}})
	if err != nil {
		l.t.Fatalf("propose %d: %v", row, err)
	}
	return rev
}

func (l *live) waitCommit(rev uint64, ids ...string) {
	l.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ok := true
		for _, id := range ids {
			if ln := l.get(id); ln == nil || ln.st.CommitIndex() < rev {
				ok = false
			}
		}
		if ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, id := range ids {
		if ln := l.get(id); ln != nil {
			h, _, _ := ln.st.Head()
			l.t.Logf("%s: %s head %d commit %d", id, ln.n.Role(), h, ln.st.CommitIndex())
		}
	}
	l.t.Fatalf("revision %d was not committed on %v", rev, ids)
}

func (l *live) sameState(ids ...string) {
	l.t.Helper()
	first := l.get(ids[0])
	for _, id := range ids[1:] {
		o := l.get(id)
		if o.st.View().Manifest() != first.st.View().Manifest() || o.st.View().Rev() != first.st.View().Rev() {
			l.t.Fatalf("%s and %s hold different state", ids[0], id)
		}
	}
}

func TestLive_ElectsReplicatesAndFailsOver(t *testing.T) {
	l := newLive(t, "core1", "core2", "core3")
	for _, id := range l.ids {
		l.start(id)
	}
	lid, ln := l.waitLeader("")
	var last uint64
	for i := 1; i <= 20; i++ {
		last = l.propose(ln, i)
	}
	l.waitCommit(last, "core1", "core2", "core3")
	l.sameState("core1", "core2", "core3")

	l.stop(lid)
	var rest []string
	for _, id := range l.ids {
		if id != lid {
			rest = append(rest, id)
		}
	}
	nid, nln := l.waitLeader(lid)
	if nid == lid {
		t.Fatal("the stopped node cannot lead")
	}
	for i := 21; i <= 30; i++ {
		last = l.propose(nln, i)
	}
	l.waitCommit(last, rest...)

	l.start(lid)
	l.waitCommit(last, "core1", "core2", "core3")
	l.sameState("core1", "core2", "core3")
	for row := 1; row <= 30; row++ {
		body, _, ok := l.get(lid).st.View().Get(1, rowID(row))
		if !ok || string(body) != fmt.Sprintf("v%d", row) {
			t.Fatalf("the restarted node misses row %d", row)
		}
	}
}

func TestLive_FollowerRefusesProposalsAndNamesTheLeader(t *testing.T) {
	l := newLive(t, "core1", "core2", "core3")
	for _, id := range l.ids {
		l.start(id)
	}
	lid, _ := l.waitLeader("")
	time.Sleep(300 * time.Millisecond)
	for _, id := range l.ids {
		if id == lid {
			continue
		}
		_, err := l.get(id).drv.Propose(context.Background(), dnsstore.Batch{Ops: []dnsstore.Op{{Kind: dnsstore.OpPut, Type: 1, ID: rowID(1), Body: []byte("x")}}})
		var nl *NotLeaderError
		if !errors.As(err, &nl) || nl.Leader != lid {
			t.Fatalf("%s: want a NotLeaderError naming %s, got %v", id, lid, err)
		}
	}
}

func TestLive_PeerEndpointsNeedTheToken(t *testing.T) {
	l := newLive(t, "core1", "core2", "core3")
	for _, id := range l.ids {
		l.start(id)
	}
	addr := l.addr["core1"]
	for name, token := range map[string]string{"none": "", "wrong": "nope"} {
		req, _ := http.NewRequest("POST", "http://"+addr+pathVote, bytes.NewReader([]byte(`{"Term":99,"Candidate":"core2","Membership":1}`)))
		req.Header.Set(TokenHeader, token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s token: status %d", name, resp.StatusCode)
		}
	}
	if l.get("core1").n.Term() >= 99 {
		t.Fatal("an unauthenticated vote request must not move the term")
	}
	req, _ := http.NewRequest("POST", "http://"+addr+pathAppend, bytes.NewReader([]byte(`{"Term":1,"Bogus":1}`)))
	req.Header.Set(TokenHeader, liveToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("unknown fields must be refused")
	}
}

func TestLive_SingleNodeIsItsOwnLeader(t *testing.T) {
	l := newLive(t, "solo")
	l.start("solo")
	_, ln := l.waitLeader("")
	rev := l.propose(ln, 1)
	l.waitCommit(rev, "solo")
}
