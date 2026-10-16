// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"dnshived/internal/cluster"
	"dnshived/internal/identity"
)

// statusServer answers every path with a tiny JSON body and counts hits.
func statusServer(t *testing.T, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"state":"STABLE"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func observerWithPeer(primary, role string, reachable bool, fallbackAddr string, fallbackUp bool) *cluster.Observer {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := cluster.NewObserver(self, "self-addr", nil, "")
	o.SetPeerForTest(primary, &cluster.PeerState{Addr: primary, Reachable: reachable, Identity: &identity.Identity{Role: role}})
	if fallbackAddr != "" {
		o.SetFallbackStatusForTest(role, "ens19", cluster.FallbackStatus{Role: role, Addr: fallbackAddr, Reachable: fallbackUp})
	}
	return o
}

// The core of the tunnel: a peer down over mgmt but confirmed alive on its
// fallback address is fetched THERE, tagged Via=fallback, with its real
// data.
func TestFetchPeerSnapshot_TunnelsOverFallbackWhenMgmtDown(t *testing.T) {
	var fbHits atomic.Int32
	fb := statusServer(t, &fbHits)
	o := observerWithPeer("192.0.2.50:9443", "core-2", false, fb.Listener.Addr().String(), true)

	snap := fetchPeerSnapshot("http", "192.0.2.50:9443", "", o)
	if snap.Error != "" {
		t.Fatalf("snapshot error %q — a peer with a confirmed fallback must be fetched over it", snap.Error)
	}
	if snap.Via != "fallback" || snap.ViaAddr != fb.Listener.Addr().String() {
		t.Errorf("Via=%q ViaAddr=%q, want fallback via %s", snap.Via, snap.ViaAddr, fb.Listener.Addr())
	}
	if len(snap.Status) == 0 || fbHits.Load() == 0 {
		t.Error("no real status came back from the fallback address")
	}
}

func TestFetchPeerSnapshot_DownWithoutFallbackIsNotRedialed(t *testing.T) {
	o := observerWithPeer("192.0.2.51:9443", "core-2", false, "", false)
	snap := fetchPeerSnapshot("http", "192.0.2.51:9443", "", o)
	if snap.Error == "" || snap.Via != "" {
		t.Errorf("snapshot = %+v, want the immediate un-dialed 'believed unreachable' error", snap)
	}
}

// The window before the Observer's own debounce catches up: the peer is
// still BELIEVED reachable, but the mgmt dial actually fails.
func TestFetchPeerSnapshot_MgmtDialFailsRetriesViaConfirmedFallback(t *testing.T) {
	var fbHits atomic.Int32
	fb := statusServer(t, &fbHits)
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadAddr := dead.Listener.Addr().String()
	dead.Close() // connection refused
	o := observerWithPeer(deadAddr, "core-2", true /* still believed reachable */, fb.Listener.Addr().String(), true)

	snap := fetchPeerSnapshot("http", deadAddr, "", o)
	if snap.Error != "" || snap.Via != "fallback" {
		t.Fatalf("snapshot = %+v, want a successful retry via the confirmed fallback", snap)
	}
	if fbHits.Load() == 0 {
		t.Error("fallback server never hit")
	}
}

func TestFetchPeerSnapshot_MgmtDialFailsWithNoFallbackKeepsTheError(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadAddr := dead.Listener.Addr().String()
	dead.Close()
	o := observerWithPeer(deadAddr, "core-2", true, "", false)
	if snap := fetchPeerSnapshot("http", deadAddr, "", o); snap.Error == "" {
		t.Errorf("snapshot = %+v, want the mgmt dial error when no fallback is known", snap)
	}
}

func TestFetchPeerSnapshot_NilObserverIsPlainMgmtDial(t *testing.T) {
	var hits atomic.Int32
	srv := statusServer(t, &hits)
	snap := fetchPeerSnapshot("http", srv.Listener.Addr().String(), "", nil)
	if snap.Error != "" || snap.Via != "" || len(snap.Status) == 0 {
		t.Errorf("snapshot = %+v, want a plain successful mgmt fetch", snap)
	}
}
