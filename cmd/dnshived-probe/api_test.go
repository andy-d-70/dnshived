// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"dnshived/internal/auth"
	"dnshived/internal/eventlog"
	"dnshived/internal/probehelper"
)

func TestStartAPIServer_BindFailureReturnsErrorNotPanic(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve a port for the test: %v", err)
	}
	defer occupied.Close()

	cfg := &ProbeConfig{ListenAddr: occupied.Addr().String()}
	store := newResultStore()
	tracker := newProbeLogTracker(nil)
	events := eventlog.New(10, "probe")
	authMw := auth.New(nil)

	err = startAPIServer(cfg, "/nonexistent/probe.json", store, tracker, events, newOwnershipDebounce(), time.Now(), authMw)
	if err == nil {
		t.Fatal("startAPIServer() = nil, want an error for an already-bound address")
	}
}

// fakeConfigHelper is a minimal Unix-socket stand-in for
// dnshived-probe-helper's write-config/restart-self verbs.
type fakeConfigHelper struct {
	socketPath string
	mu         sync.Mutex
	written    []byte
	restarted  bool
}

func newFakeConfigHelper(t *testing.T) *fakeConfigHelper {
	t.Helper()
	f := &fakeConfigHelper{socketPath: filepath.Join(t.TempDir(), "probe-helper.sock")}
	ln, err := net.Listen("unix", f.socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.handle(conn)
		}
	}()
	return f
}

func (f *fakeConfigHelper) handle(conn net.Conn) {
	defer conn.Close()
	var req probehelper.Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return
	}
	var resp probehelper.Response
	switch req.Command {
	case "write-config":
		f.mu.Lock()
		f.written = req.Content
		f.mu.Unlock()
		resp = probehelper.Response{OK: true}
	case "restart-self":
		f.mu.Lock()
		f.restarted = true
		f.mu.Unlock()
		resp = probehelper.Response{OK: true}
	default:
		resp = probehelper.Response{OK: false, Error: "unknown command"}
	}
	json.NewEncoder(conn).Encode(resp)
}

func TestPostConfig_TogglesParallelProbingLiveWithoutRestart(t *testing.T) {
	helper := newFakeConfigHelper(t)
	cfgPath := filepath.Join(t.TempDir(), "probe.json")
	if err := os.WriteFile(cfgPath, []byte(`{
		"listen_addr": ":0",
		"trunk_parent": "ens19",
		"cluster_token": "tok",
		"cluster_nodes": [{"name": "core-1", "addr": "127.0.0.1:1"}],
		"probe_helper_socket": "`+helper.socketPath+`"
	}`), 0o644); err != nil {
		t.Fatalf("write test config: %v", err)
	}

	cfg := &ProbeConfig{ProbeHelperSocket: helper.socketPath}
	authMw := auth.New(nil)

	mux := http.NewServeMux()
	registerConfigEndpoint(mux, cfg, cfgPath, authMw)

	srv := httptest.NewServer(authMw.Wrap(mux))
	defer srv.Close()

	if cfg.Parallel() {
		t.Fatal("precondition: parallel must start off")
	}
	post := func(on bool) {
		t.Helper()
		body, _ := json.Marshal(map[string]bool{"parallel_probing": on})
		resp, err := http.Post(srv.URL+"/api/v1/config", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("POST /api/v1/config: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d (applied live, no restart)", resp.StatusCode, http.StatusOK)
		}
		var out struct {
			Restarting bool `json:"restarting"`
		}
		json.NewDecoder(resp.Body).Decode(&out)
		if out.Restarting {
			t.Error("response says restarting=true, want false")
		}
	}

	post(true)
	if !cfg.Parallel() {
		t.Error("cfg.Parallel() = false right after enabling, want true immediately (live apply)")
	}
	post(false)
	if cfg.Parallel() {
		t.Error("cfg.Parallel() = true right after disabling, want false immediately (live apply)")
	}
	post(true)

	// Give any (wrongly) async restart goroutine (300ms delay) time to fire.
	time.Sleep(600 * time.Millisecond)

	helper.mu.Lock()
	defer helper.mu.Unlock()
	if helper.written == nil {
		t.Fatal("helper never received a write-config call — the change wasn't persisted for the next start")
	}
	var written ProbeConfig
	if err := json.Unmarshal(helper.written, &written); err != nil {
		t.Fatalf("unmarshal what was written: %v", err)
	}
	if !written.ParallelProbing {
		t.Error("written config has ParallelProbing = false, want true")
	}
	if written.TrunkParent != "ens19" {
		t.Errorf("written config lost an existing field: trunk_parent = %q, want ens19 (whole-document write must preserve untouched fields)", written.TrunkParent)
	}
	if helper.restarted {
		t.Error("helper received a restart-self call — a parallel_probing-only change must not restart the probe (it wipes every stored result)")
	}
}

func TestProbeConfig_ParallelFallsBackToLoadedValueUntilSetLive(t *testing.T) {
	c := &ProbeConfig{ParallelProbing: true}
	if !c.Parallel() {
		t.Error("Parallel() = false, want true (loaded value, no live override yet)")
	}
	c.SetParallel(false)
	if c.Parallel() {
		t.Error("Parallel() = true after SetParallel(false), want false (live override must beat the loaded true)")
	}
	c.SetParallel(true)
	if !c.Parallel() {
		t.Error("Parallel() = false after SetParallel(true), want true")
	}
}

func TestPostConfig_UpdatesClusterNodesWithoutTouchingParallelProbing(t *testing.T) {
	helper := newFakeConfigHelper(t)
	cfgPath := filepath.Join(t.TempDir(), "probe.json")
	if err := os.WriteFile(cfgPath, []byte(`{
		"listen_addr": ":0",
		"trunk_parent": "ens19",
		"cluster_token": "tok",
		"parallel_probing": true,
		"cluster_nodes": [{"name": "core-1", "addr": "192.0.2.23:9443", "tls": true}],
		"probe_helper_socket": "`+helper.socketPath+`"
	}`), 0o644); err != nil {
		t.Fatalf("write test config: %v", err)
	}

	cfg := &ProbeConfig{ProbeHelperSocket: helper.socketPath}
	authMw := auth.New(nil)

	mux := http.NewServeMux()
	registerConfigEndpoint(mux, cfg, cfgPath, authMw)

	srv := httptest.NewServer(authMw.Wrap(mux))
	defer srv.Close()

	newNodes := []ClusterNode{
		{Name: "core-1", Addr: "192.0.2.26:9443", TLS: true},
		{Name: "core-3", Addr: "192.0.2.27:9443", TLS: true},
		{Name: "core-2", Addr: "192.0.2.28:9443", TLS: true},
	}
	body, _ := json.Marshal(map[string]interface{}{"cluster_nodes": newNodes})
	resp, err := http.Post(srv.URL+"/api/v1/config", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/v1/config: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		helper.mu.Lock()
		done := helper.written != nil && helper.restarted
		helper.mu.Unlock()
		if done {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	helper.mu.Lock()
	defer helper.mu.Unlock()
	if helper.written == nil {
		t.Fatal("helper never received a write-config call")
	}
	var written ProbeConfig
	if err := json.Unmarshal(helper.written, &written); err != nil {
		t.Fatalf("unmarshal what was written: %v", err)
	}
	if !written.ParallelProbing {
		t.Error("cluster_nodes-only patch clobbered ParallelProbing back to false — the exact partial-patch wipe bug this test guards against")
	}
	if len(written.ClusterNodes) != 3 || written.ClusterNodes[0].Addr != "192.0.2.26:9443" {
		t.Errorf("written ClusterNodes = %+v, want the 3 new nodes", written.ClusterNodes)
	}
}

func TestPostConfig_EmptyPatchIsRejected(t *testing.T) {
	helper := newFakeConfigHelper(t)
	cfgPath := filepath.Join(t.TempDir(), "probe.json")
	if err := os.WriteFile(cfgPath, []byte(`{"listen_addr": ":0", "probe_helper_socket": "`+helper.socketPath+`"}`), 0o644); err != nil {
		t.Fatalf("write test config: %v", err)
	}
	cfg := &ProbeConfig{ProbeHelperSocket: helper.socketPath}
	authMw := auth.New(nil)
	mux := http.NewServeMux()
	registerConfigEndpoint(mux, cfg, cfgPath, authMw)
	srv := httptest.NewServer(authMw.Wrap(mux))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/v1/config", "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatalf("POST /api/v1/config: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	helper.mu.Lock()
	defer helper.mu.Unlock()
	if helper.written != nil {
		t.Error("an empty patch reached the helper's write-config call — should have been rejected before any write")
	}
}

func TestAllowedProbeJournalUnits_MatchesTheProbeHelperSFixedSet(t *testing.T) {
	want := []string{"dnshived-probe.service", "dnshived-probe-helper.service"}
	if len(allowedProbeJournalUnits) != len(want) {
		t.Errorf("allowedProbeJournalUnits has %d entries, want exactly %d", len(allowedProbeJournalUnits), len(want))
	}
	for _, u := range want {
		if !allowedProbeJournalUnits[u] {
			t.Errorf("expected %s in allowedProbeJournalUnits", u)
		}
	}
}
