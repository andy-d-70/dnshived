// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"dnshived/internal/cluster"
	"dnshived/internal/config"
	"dnshived/internal/identity"
)

func TestAnyAPIToken_PrefersAdminRole(t *testing.T) {
	tokens := []config.APIToken{
		{Name: "ro", Token: "readonly-tok", Role: "readonly"},
		{Name: "adm", Token: "admin-tok", Role: "admin"},
	}
	if got := anyAPIToken(tokens); got != "admin-tok" {
		t.Errorf("anyAPIToken() = %q, want the admin-role token", got)
	}
}

func TestAnyAPIToken_FallsBackToFirstWhenNoAdmin(t *testing.T) {
	tokens := []config.APIToken{
		{Name: "ro", Token: "readonly-tok", Role: "readonly"},
	}
	if got := anyAPIToken(tokens); got != "readonly-tok" {
		t.Errorf("anyAPIToken() = %q, want the only available token", got)
	}
}

func TestAnyAPIToken_EmptyWhenNoTokens(t *testing.T) {
	if got := anyAPIToken(nil); got != "" {
		t.Errorf("anyAPIToken(nil) = %q, want empty", got)
	}
}

func TestFetchPeerStatus_SuccessDecodesRealJSON(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/api/v1/status" {
			t.Errorf("path = %q, want /api/v1/status", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"role":"core-1","state":"STABLE"}`))
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	entry := fetchPeerStatus("http", addr, "shared-tok")
	if entry.Error != "" {
		t.Fatalf("entry.Error = %q, want empty", entry.Error)
	}
	if entry.Status["role"] != "core-1" || entry.Status["state"] != "STABLE" {
		t.Errorf("entry.Status = %+v, want role/state from the real response", entry.Status)
	}
	if gotAuth != "Bearer shared-tok" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer shared-tok")
	}
}

func TestFetchPeerStatus_NoTokenOmitsAuthHeader(t *testing.T) {
	var gotAuth string
	sawAuth := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		sawAuth = gotAuth != ""
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	fetchPeerStatus("http", addr, "")
	if sawAuth {
		t.Errorf("Authorization header = %q, want none sent when no token is configured", gotAuth)
	}
}

func TestFetchPeerStatus_NonOKStatusCapturedAsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	entry := fetchPeerStatus("http", addr, "wrong-tok")
	if entry.Error == "" {
		t.Fatal("entry.Error is empty, want the non-200 status captured")
	}
	if entry.Status != nil {
		t.Errorf("entry.Status = %+v, want nil on a failed fetch", entry.Status)
	}
}

func TestFetchPeerStatus_BadJSONCapturedAsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	entry := fetchPeerStatus("http", addr, "")
	if entry.Error == "" {
		t.Fatal("entry.Error is empty, want the decode failure captured")
	}
}

func TestFetchPeerStatus_UnreachablePeerCapturedAsError(t *testing.T) {
	// A closed listener on loopback -- connection refused, no real
	// network dependency, no flaky timing.
	ln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	addr := strings.TrimPrefix(ln.URL, "http://")
	ln.Close() // close immediately, before any real request lands

	entry := fetchPeerStatus("http", addr, "")
	if entry.Error == "" {
		t.Fatal("entry.Error is empty, want the connection failure captured")
	}
}

func TestClusterStatusHandler_AggregatesSelfAndPeers(t *testing.T) {
	origCfg := currentConfig.Load()
	t.Cleanup(func() { currentConfig.Store(origCfg) })

	healthyPeer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer cluster-admin-tok" {
			t.Errorf("peer saw Authorization = %q, want the admin token", got)
		}
		w.Write([]byte(`{"role":"core-2","state":"STABLE"}`))
	}))
	defer healthyPeer.Close()
	healthyAddr := strings.TrimPrefix(healthyPeer.URL, "http://")

	deadPeer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadAddr := strings.TrimPrefix(deadPeer.URL, "http://")
	deadPeer.Close()

	currentConfig.Store(&config.Cluster{
		Peers: []string{healthyAddr, deadAddr},
		APITokens: []config.APIToken{
			{Name: "ro", Token: "readonly-tok", Role: "readonly"},
			{Name: "adm", Token: "cluster-admin-tok", Role: "admin"},
		},
	})

	buildStatus := func() map[string]interface{} {
		return map[string]interface{}{"role": "core-1", "state": "STABLE"}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/cluster/status", nil)
	rec := httptest.NewRecorder()
	clusterStatusHandler(buildStatus, nil)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var body struct {
		Self  map[string]interface{}     `json:"self"`
		Peers map[string]peerStatusEntry `json:"peers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if body.Self["role"] != "core-1" {
		t.Errorf("self.role = %v, want worker-a (buildStatus's own output, reused verbatim)", body.Self["role"])
	}
	if len(body.Peers) != 2 {
		t.Fatalf("len(peers) = %d, want 2 (one healthy, one dead)", len(body.Peers))
	}
	healthy, ok := body.Peers[healthyAddr]
	if !ok || healthy.Error != "" || healthy.Status["role"] != "core-2" {
		t.Errorf("peers[%q] = %+v, want a real, error-free worker-b status", healthyAddr, healthy)
	}
	dead, ok := body.Peers[deadAddr]
	if !ok || dead.Error == "" {
		t.Errorf("peers[%q] = %+v, want a captured error — the dead peer must never fail the whole aggregate", deadAddr, dead)
	}
}

func TestClusterStatusHandler_NoPeersConfiguredStillReturnsSelf(t *testing.T) {
	origCfg := currentConfig.Load()
	t.Cleanup(func() { currentConfig.Store(origCfg) })
	currentConfig.Store(&config.Cluster{})

	buildStatus := func() map[string]interface{} {
		return map[string]interface{}{"role": "core-3"}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/cluster/status", nil)
	rec := httptest.NewRecorder()
	clusterStatusHandler(buildStatus, nil)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Self  map[string]interface{}     `json:"self"`
		Peers map[string]peerStatusEntry `json:"peers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Self["role"] != "core-3" {
		t.Errorf("self.role = %v, want arbiter", body.Self["role"])
	}
	if len(body.Peers) != 0 {
		t.Errorf("peers = %+v, want empty", body.Peers)
	}
}

func TestClusterStatusHandler_SkipsDialingAPeerTheObserverAlreadyKnowsIsDead(t *testing.T) {
	origCfg := currentConfig.Load()
	t.Cleanup(func() { currentConfig.Store(origCfg) })

	peerHits := 0
	peerMux := http.NewServeMux()
	peerMux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		peerHits++
		w.Write([]byte(`{"role":"core-2"}`))
	})
	peerSrv := httptest.NewServer(peerMux)
	defer peerSrv.Close()
	peerAddr := strings.TrimPrefix(peerSrv.URL, "http://")

	currentConfig.Store(&config.Cluster{Peers: []string{peerAddr}})

	buildStatus := func() map[string]interface{} {
		return map[string]interface{}{"role": "core-1"}
	}

	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	observer := cluster.NewObserver(self, "self-addr", nil, "")
	observer.SetPeerForTest(peerAddr, &cluster.PeerState{Addr: peerAddr, Reachable: false, Failures: 3})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/cluster/status", nil)
	rec := httptest.NewRecorder()
	clusterStatusHandler(buildStatus, observer)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if peerHits != 0 {
		t.Errorf("peer received %d real request(s), want 0 — a peer already known unreachable must never be dialed", peerHits)
	}
	var body struct {
		Peers map[string]peerStatusEntry `json:"peers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	peer, ok := body.Peers[peerAddr]
	if !ok || peer.Error == "" {
		t.Errorf("peers[%q] = %+v, want a real Error entry for the known-dead peer", peerAddr, peer)
	}
}
