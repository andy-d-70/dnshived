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

func TestSelfLoopbackAddr_ExtractsPortFromVariousListenAddrShapes(t *testing.T) {
	cases := []struct {
		listenAddr string
		want       string
	}{
		{":9443", "127.0.0.1:9443"},
		{"0.0.0.0:9443", "127.0.0.1:9443"},
		{"192.168.0.23:9443", "127.0.0.1:9443"},
	}
	for _, c := range cases {
		if got := selfLoopbackAddr(c.listenAddr); got != c.want {
			t.Errorf("selfLoopbackAddr(%q) = %q, want %q", c.listenAddr, got, c.want)
		}
	}
}

func TestFetchJSONFrom_SuccessReturnsRawBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/system" {
			t.Errorf("path = %q, want /api/v1/system", r.URL.Path)
		}
		w.Write([]byte(`{"load_avg_1":0.5}`))
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	raw, err := fetchJSONFrom("http", addr, "/api/v1/system", "")
	if err != nil {
		t.Fatalf("fetchJSONFrom: %v", err)
	}
	var decoded map[string]float64
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode raw: %v", err)
	}
	if decoded["load_avg_1"] != 0.5 {
		t.Errorf("load_avg_1 = %v, want 0.5", decoded["load_avg_1"])
	}
}

func TestFetchJSONFrom_NonOKIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	_, err := fetchJSONFrom("http", addr, "/api/v1/system", "")
	if err == nil {
		t.Fatal("expected an error on a non-200 response")
	}
}

func TestFetchNodeSnapshot_AllFourEndpointsBundled(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"role":"core-1"}`))
	})
	mux.HandleFunc("/api/v1/system", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"load_avg_1":1.2}`))
	})
	mux.HandleFunc("/api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"message":"hello"}]`))
	})
	mux.HandleFunc("/api/v1/daemons", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"node_id":"core-1","daemons":[]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	snap := fetchNodeSnapshot("http", addr, "")
	if snap.Error != "" {
		t.Fatalf("snap.Error = %q, want empty", snap.Error)
	}
	if len(snap.Status) == 0 || len(snap.System) == 0 || len(snap.Events) == 0 || len(snap.Daemons) == 0 {
		t.Fatalf("snap = %+v, want all four fields populated", snap)
	}
}

func TestFetchNodeSnapshot_StatusFailureIsFatalButOthersAreBestEffort(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	snap := fetchNodeSnapshot("http", addr, "")
	if snap.Error == "" {
		t.Fatal("expected Error to be set when Status itself fails")
	}
	if snap.System != nil || snap.Events != nil || snap.Daemons != nil {
		t.Errorf("snap = %+v, want System/Events/Daemons never attempted once Status fails", snap)
	}
}

func TestFetchNodeSnapshot_SystemFailureDoesNotBlockTheRest(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"role":"core-1"}`))
	})
	mux.HandleFunc("/api/v1/system", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // simulates an older daemon build lacking this route
	})
	mux.HandleFunc("/api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	})
	mux.HandleFunc("/api/v1/daemons", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	snap := fetchNodeSnapshot("http", addr, "")
	if snap.Error != "" {
		t.Errorf("snap.Error = %q, want empty — Status itself succeeded", snap.Error)
	}
	if snap.System != nil {
		t.Errorf("snap.System = %s, want nil (the endpoint failed)", snap.System)
	}
	if snap.Events == nil || snap.Daemons == nil {
		t.Errorf("snap = %+v, want Events/Daemons still populated despite System failing", snap)
	}
}

func TestClusterSnapshotHandler_RealEndToEnd(t *testing.T) {
	origCfg := currentConfig.Load()
	t.Cleanup(func() { currentConfig.Store(origCfg) })

	selfMux := http.NewServeMux()
	selfMux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"role":"core-1"}`))
	})
	selfMux.HandleFunc("/api/v1/system", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"load_avg_1":0.1}`))
	})
	selfMux.HandleFunc("/api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	})
	selfMux.HandleFunc("/api/v1/daemons", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	})
	selfMux.HandleFunc("/api/v1/token/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"debugwalk-1":{"owner":"core-1"}}`))
	})
	selfSrv := httptest.NewServer(selfMux)
	defer selfSrv.Close()
	_, selfPort := parseHostPort(t, selfSrv.URL)

	peerMux := http.NewServeMux()
	peerMux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"role":"core-2"}`))
	})
	peerSrv := httptest.NewServer(peerMux)
	defer peerSrv.Close()
	peerAddr := strings.TrimPrefix(peerSrv.URL, "http://")

	currentConfig.Store(&config.Cluster{
		BindAddr: ":" + selfPort,
		Peers:    []string{peerAddr},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/cluster/snapshot", nil)
	rec := httptest.NewRecorder()
	clusterSnapshotHandler(nil)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var body struct {
		Self   nodeSnapshot            `json:"self"`
		Peers  map[string]nodeSnapshot `json:"peers"`
		Tokens json.RawMessage         `json:"tokens"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if body.Self.Error != "" {
		t.Errorf("self.Error = %q, want empty", body.Self.Error)
	}
	if len(body.Self.Status) == 0 || len(body.Self.System) == 0 {
		t.Errorf("self = %+v, want Status/System populated via the real loopback fetch", body.Self)
	}
	if len(body.Tokens) == 0 {
		t.Error("tokens is empty, want the real token/status payload fetched via loopback")
	}
	peer, ok := body.Peers[peerAddr]
	if !ok || peer.Error != "" || len(peer.Status) == 0 {
		t.Errorf("peers[%q] = %+v, want a real, error-free status", peerAddr, peer)
	}
}

func TestClusterSnapshotHandler_SkipsDialingAPeerTheObserverAlreadyKnowsIsDead(t *testing.T) {
	selfMux := http.NewServeMux()
	selfMux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"role":"core-1"}`))
	})
	selfSrv := httptest.NewServer(selfMux)
	defer selfSrv.Close()
	_, selfPort := parseHostPort(t, selfSrv.URL)

	peerHits := 0
	peerMux := http.NewServeMux()
	peerMux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		peerHits++
		w.Write([]byte(`{"role":"core-2"}`))
	})
	peerSrv := httptest.NewServer(peerMux)
	defer peerSrv.Close()
	peerAddr := strings.TrimPrefix(peerSrv.URL, "http://")

	currentConfig.Store(&config.Cluster{
		BindAddr: ":" + selfPort,
		Peers:    []string{peerAddr},
	})

	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	observer := cluster.NewObserver(self, "self-addr", nil, "")
	observer.SetPeerForTest(peerAddr, &cluster.PeerState{Addr: peerAddr, Reachable: false, Failures: 3})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/cluster/snapshot", nil)
	rec := httptest.NewRecorder()
	clusterSnapshotHandler(observer)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if peerHits != 0 {
		t.Errorf("peer received %d real request(s), want 0 — a peer already known unreachable must never be dialed", peerHits)
	}

	var body struct {
		Peers map[string]nodeSnapshot `json:"peers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	peer, ok := body.Peers[peerAddr]
	if !ok || peer.Error == "" {
		t.Errorf("peers[%q] = %+v, want a real Error entry for the known-dead peer", peerAddr, peer)
	}
}

// parseHostPort is a tiny test helper.
func parseHostPort(t *testing.T, url string) (host, port string) {
	t.Helper()
	hp := strings.TrimPrefix(url, "http://")
	i := strings.LastIndex(hp, ":")
	if i < 0 {
		t.Fatalf("no port in %q", url)
	}
	return hp[:i], hp[i+1:]
}
