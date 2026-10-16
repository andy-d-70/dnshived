// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDecodeSnapshotNode_HappyPath confirms a real bundle decodes into
// exactly the nodeData shape collectAll's own legacy per-node fetch
// already produces.
func TestDecodeSnapshotNode_HappyPath(t *testing.T) {
	sn := snapshotNode{
		Status:  []byte(`{"role":"core-1","state":"STABLE"}`),
		System:  []byte(`{"load_avg_1":0.4}`),
		Events:  []byte(`[{"message":"hello"}]`),
		Daemons: []byte(`{"node_id":"core-1","daemons":[{"unit":"dnshived.service"}]}`),
	}
	nd := decodeSnapshotNode("192.168.0.23:9443", sn)

	if nd.Addr != "192.168.0.23:9443" {
		t.Errorf("Addr = %q, want the given address", nd.Addr)
	}
	if !nd.Reachable || nd.Error != "" {
		t.Errorf("Reachable/Error = %v/%q, want true/empty", nd.Reachable, nd.Error)
	}
	if nd.Status == nil || nd.Status.Role != "core-1" || nd.Status.State != "STABLE" {
		t.Errorf("Status = %+v, want role=worker-a state=STABLE", nd.Status)
	}
	if nd.System == nil || nd.System.LoadAvg1 != 0.4 {
		t.Errorf("System = %+v, want LoadAvg1=0.4", nd.System)
	}
	if len(nd.Events) != 1 || nd.Events[0].Message != "hello" {
		t.Errorf("Events = %+v, want one event with message=hello", nd.Events)
	}
	if len(nd.Daemons) != 1 || nd.Daemons[0].Unit != "dnshived.service" {
		t.Errorf("Daemons = %+v, want one daemon unit=dnshived.service", nd.Daemons)
	}
}

func TestDecodeSnapshotNode_ErrorFieldShortCircuits(t *testing.T) {
	nd := decodeSnapshotNode("192.168.0.43:9443", snapshotNode{Error: "connection refused"})
	if nd.Reachable {
		t.Error("Reachable = true, want false when the server itself reported an error")
	}
	if nd.Error != "connection refused" {
		t.Errorf("Error = %q, want the server's own error passed through", nd.Error)
	}
	if nd.Status != nil {
		t.Errorf("Status = %+v, want nil", nd.Status)
	}
}

// TestDecodeSnapshotNode_BadStatusJSONIsAnError confirms a malformed
// Status payload is treated as a real failure, not silently ignored.
func TestDecodeSnapshotNode_BadStatusJSONIsAnError(t *testing.T) {
	nd := decodeSnapshotNode("addr", snapshotNode{Status: []byte("not json")})
	if nd.Reachable {
		t.Error("Reachable = true, want false on malformed Status JSON")
	}
	if nd.Error == "" {
		t.Error("Error is empty, want the decode failure captured")
	}
}

func TestCollectFromSnapshot_RealEndToEnd(t *testing.T) {
	origScheme := scheme
	t.Cleanup(func() { scheme = origScheme })
	scheme = "http"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/cluster/snapshot" {
			t.Errorf("path = %q, want /api/v1/cluster/snapshot", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"self": {"status": {"role":"core-1","state":"STABLE"}},
			"peers": {
				"192.168.0.22:9443": {"status": {"role":"core-2","state":"STABLE"}},
				"192.168.0.43:9443": {"error": "connection refused"}
			},
			"tokens": {}
		}`))
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	nodes, tokens, _, ok := collectFromSnapshot(addr)
	if !ok {
		t.Fatal("collectFromSnapshot ok = false, want true against a real, well-formed response")
	}
	if tokens == nil {
		t.Error("tokens = nil, want a real (even if empty) map")
	}
	if len(nodes) != 3 {
		t.Fatalf("len(nodes) = %d, want 3 (self + 2 peers)", len(nodes))
	}
	byAddr := make(map[string]nodeData, len(nodes))
	for _, n := range nodes {
		byAddr[n.Addr] = n
	}
	self, ok := byAddr[addr]
	if !ok || self.role() != "core-1" || !self.Reachable {
		t.Errorf("self entry (addr=%q) = %+v, want reachable role=worker-a", addr, self)
	}
	peer, ok := byAddr["192.168.0.22:9443"]
	if !ok || peer.role() != "core-2" || !peer.Reachable {
		t.Errorf("healthy peer entry = %+v, want reachable role=worker-b", peer)
	}
	dead, ok := byAddr["192.168.0.43:9443"]
	if !ok || dead.Reachable || dead.Error == "" {
		t.Errorf("dead peer entry = %+v, want unreachable with its own captured error — an unreachable node's role can never be known, so it correctly can't be identified as \"arbiter\" here", dead)
	}
}

// TestCollectFromSnapshot_FailsGracefullyOnUnreachableEntry confirms
// ok=false (never a partial result) when the entry address itself can't
// even be reached.
func TestCollectFromSnapshot_FailsGracefullyOnUnreachableEntry(t *testing.T) {
	origScheme := scheme
	t.Cleanup(func() { scheme = origScheme })
	scheme = "http"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	addr := strings.TrimPrefix(srv.URL, "http://")
	srv.Close() // closed before any real request can land

	nodes, tokens, warnings, ok := collectFromSnapshot(addr)
	if ok {
		t.Fatal("ok = true, want false against a genuinely unreachable address")
	}
	if nodes != nil || tokens != nil || warnings != nil {
		t.Errorf("expected all-nil results on failure, got nodes=%v tokens=%v warnings=%v", nodes, tokens, warnings)
	}
}

func TestCollectFromSnapshot_FailsGracefullyOn404(t *testing.T) {
	origScheme := scheme
	t.Cleanup(func() { scheme = origScheme })
	scheme = "http"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	_, _, _, ok := collectFromSnapshot(addr)
	if ok {
		t.Fatal("ok = true, want false against a 404 (simulating an older daemon build)")
	}
}

// A peer the daemon fetched over its fallback address (mgmt path down)
// must decode as REACHABLE with the via-fallback marker — never as an
// error/DOWN.
func TestDecodeSnapshotNode_ViaFallbackIsReachableAndMarked(t *testing.T) {
	nd := decodeSnapshotNode("10.0.0.2:9443", snapshotNode{
		Status: []byte(`{"role":"core-2","state":"STABLE"}`), Via: "fallback", ViaAddr: "172.16.5.23:9443",
	})
	if !nd.Reachable || !nd.ViaFallback || nd.role() != "core-2" {
		t.Errorf("nd = %+v, want reachable core-2 marked ViaFallback", nd)
	}
}

// -top pointed at one address must not show every node offline when that
// node lost its mgmt interface.
func TestCollectAll_DeadEntryFallsBackToKnownNode(t *testing.T) {
	origScheme := scheme
	t.Cleanup(func() { scheme = origScheme })
	scheme = "http"

	alive := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/cluster/snapshot" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{
			"self": {"status": {"role":"core-1","state":"STABLE"}},
			"peers": {"10.255.255.1:9443": {"status": {"role":"core-2","state":"STABLE"}, "via": "fallback", "via_addr": "172.16.5.23:9443"}},
			"tokens": {}
		}`))
	}))
	defer alive.Close()
	aliveAddr := strings.TrimPrefix(alive.URL, "http://")

	// Entry address that never answers (the node that lost mgmt).
	const deadEntry = "127.0.0.1:1"

	knownNodesMu.Lock()
	saved := knownNodes
	knownNodes = map[string]bool{aliveAddr: true}
	knownNodesMu.Unlock()
	t.Cleanup(func() { knownNodesMu.Lock(); knownNodes = saved; knownNodesMu.Unlock() })

	nodes, _, _ := collectAll([]string{deadEntry})
	if len(nodes) != 2 {
		t.Fatalf("len(nodes) = %d, want 2 — a dead entry address must not blank the whole cluster; nodes=%+v", len(nodes), nodes)
	}
	var via, plain int
	for _, n := range nodes {
		if !n.Reachable {
			t.Errorf("node %s offline, want both reachable", n.Addr)
		}
		if n.ViaFallback {
			via++
		} else {
			plain++
		}
	}
	if via != 1 || plain != 1 {
		t.Errorf("via-fallback=%d plain=%d, want 1 and 1", via, plain)
	}
}

// Path-aware PARTITION in -top: a node reaching its peer over the fallback
// path is not a partition; a genuine both-ways loss is ONE folded line.
func TestCheckCoherence_Partition_PathAwareAndFolded(t *testing.T) {
	mk := func(addr, id string, unreach []string, fb map[string]string) nodeData {
		return nodeData{Addr: addr, Reachable: true, Status: &nodeStatus{Role: "core-1", NodeID: id, PeersUnreachable: unreach, FallbackPeers: fb}}
	}
	count := func(ws []string) (n int, line string) {
		for _, w := range ws {
			if strings.HasPrefix(w, "PARTITION:") {
				n++
				line = w
			}
		}
		return
	}
	viaFB := []nodeData{
		mk("a:1", "n1", []string{"b:1"}, map[string]string{"b:1": "fb-b:1"}),
		mk("b:1", "n2", []string{"a:1"}, map[string]string{"a:1": "fb-a:1"}),
	}
	if n, _ := count(checkCoherence(viaFB, map[string]tokenInfo{})); n != 0 {
		t.Errorf("fallback-reachable pair produced %d PARTITION line(s), want 0", n)
	}
	real := []nodeData{mk("a:1", "n1", []string{"b:1"}, nil), mk("b:1", "n2", []string{"a:1"}, nil)}
	n, line := count(checkCoherence(real, map[string]tokenInfo{}))
	if n != 1 || !strings.Contains(line, "n1 and n2 cannot see each other") {
		t.Errorf("real partition: %d line(s) %q, want exactly one folded line", n, line)
	}
}
