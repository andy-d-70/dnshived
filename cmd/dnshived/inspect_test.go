// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dnshived/internal/config"
	"dnshived/internal/discovery"
)

// fakeCandidateMux builds a real httptest.Server standing in for a
// not-yet-adopted candidate.
func fakeCandidateMux(t *testing.T, ifaces []string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/bootstrap/status", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(bootstrapStatusResponse{
			Hostname: "fake-candidate", Version: "test", OS: "Fake OS 1.0",
			Interfaces: ifaces,
		})
	})
	mux.HandleFunc("POST /api/v1/bootstrap/probe-interface", func(w http.ResponseWriter, r *http.Request) {
		var req bootstrapProbeInterfaceRequest
		json.NewDecoder(r.Body).Decode(&req)
		found := false
		for _, i := range ifaces {
			if i == req.Interface {
				found = true
			}
		}
		if !found {
			http.Error(w, "not a recognized interface", http.StatusBadRequest)
			return
		}
		dur := time.Duration(req.DurationMS) * time.Millisecond
		ctx, cancel := context.WithTimeout(r.Context(), dur)
		defer cancel()
		discovery.BroadcastOnInterface(ctx, req.Interface, "fake-candidate")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})
	return httptest.NewServer(mux)
}

// candidateAt points the core bootstrap port at srv and returns srv's
// address.
func candidateAt(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	addr := strings.TrimPrefix(srv.URL, "http://")
	_, port, _ := net.SplitHostPort(addr)
	orig := coreBootstrapPort
	coreBootstrapPort = port
	t.Cleanup(func() { coreBootstrapPort = orig })
	return addr
}

func TestInspectNodeHandler_DetectsRealMatchOnLoopback(t *testing.T) {
	srv := fakeCandidateMux(t, []string{"lo"})
	defer srv.Close()
	candAddr := candidateAt(t, srv)

	orig := currentConfig.Load()
	t.Cleanup(func() { currentConfig.Store(orig) })
	currentConfig.Store(&config.Cluster{
		Role:     "core-1",
		Platform: &config.Platform{Workers: []string{"lo"}},
	})

	burstOverride := inspectBurstDurationForTest(1500 * time.Millisecond)
	defer burstOverride()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/inspect", strings.NewReader(`{"addr":"`+candAddr+`"}`))
	rec := httptest.NewRecorder()
	inspectNodeHandler()(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp inspectCandidateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v, body = %s", err, rec.Body.String())
	}
	if !resp.OK {
		t.Fatalf("resp.OK = false, error = %q", resp.Error)
	}
	if resp.OS != "Fake OS 1.0" {
		t.Errorf("resp.OS = %q, want %q", resp.OS, "Fake OS 1.0")
	}
	if resp.Mapping["lo"] != "lo" {
		t.Errorf(`resp.Mapping["lo"] = %q, want "lo" (a real, detected match)`, resp.Mapping["lo"])
	}
}

func TestInspectNodeHandler_FlagsVersionMismatch(t *testing.T) {
	srv := fakeCandidateMux(t, []string{"lo"})
	defer srv.Close()
	candAddr := candidateAt(t, srv)

	orig := currentConfig.Load()
	t.Cleanup(func() { currentConfig.Store(orig) })
	currentConfig.Store(&config.Cluster{Role: "core-1", Platform: &config.Platform{Workers: []string{"lo"}}})

	burstOverride := inspectBurstDurationForTest(200 * time.Millisecond)
	defer burstOverride()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/inspect", strings.NewReader(`{"addr":"`+candAddr+`"}`))
	rec := httptest.NewRecorder()
	inspectNodeHandler()(rec, req)

	var resp inspectCandidateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v, body = %s", err, rec.Body.String())
	}
	if resp.CandidateVersion != "test" {
		t.Errorf("CandidateVersion = %q, want %q (the fake candidate's own stubbed version)", resp.CandidateVersion, "test")
	}
	if resp.ThisVersion != version {
		t.Errorf("ThisVersion = %q, want this node's own real version %q", resp.ThisVersion, version)
	}
	if !resp.VersionMismatch {
		t.Error("VersionMismatch = false, want true (\"test\" can never equal this node's own real version)")
	}
}

// TestInspectNodeHandler_SameVersionIsNoMismatch confirms the other
// direction: a candidate reporting THIS node's own exact version string is
// never flagged.
func TestInspectNodeHandler_SameVersionIsNoMismatch(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/bootstrap/status", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(bootstrapStatusResponse{
			Hostname: "fake-candidate", Version: version, OS: "Fake OS 1.0", Interfaces: nil,
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	candAddr := candidateAt(t, srv)

	orig := currentConfig.Load()
	t.Cleanup(func() { currentConfig.Store(orig) })
	currentConfig.Store(&config.Cluster{Role: "core-1", Platform: &config.Platform{Workers: []string{"lo"}}})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/inspect", strings.NewReader(`{"addr":"`+candAddr+`"}`))
	rec := httptest.NewRecorder()
	inspectNodeHandler()(rec, req)

	var resp inspectCandidateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v, body = %s", err, rec.Body.String())
	}
	if resp.VersionMismatch {
		t.Errorf("VersionMismatch = true for a candidate reporting the identical version %q, want false", version)
	}
}

func TestInspectNodeHandler_UndetectedTrunkStaysEmpty(t *testing.T) {
	// Candidate reports zero interfaces at all — nothing can ever be
	// detected for any of this node's own trunks.
	srv := fakeCandidateMux(t, nil)
	defer srv.Close()
	candAddr := candidateAt(t, srv)

	orig := currentConfig.Load()
	t.Cleanup(func() { currentConfig.Store(orig) })
	currentConfig.Store(&config.Cluster{
		Role:     "core-1",
		Platform: &config.Platform{Workers: []string{"lo"}},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/inspect", strings.NewReader(`{"addr":"`+candAddr+`"}`))
	rec := httptest.NewRecorder()
	inspectNodeHandler()(rec, req)

	var resp inspectCandidateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got, ok := resp.Mapping["lo"]; !ok || got != "" {
		t.Errorf(`resp.Mapping["lo"] = %q (present=%v), want "" (undetected)`, got, ok)
	}
}

// TestInspectNodeHandler_RequiresAddr covers basic request validation.
func TestInspectNodeHandler_RequiresAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/inspect", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	inspectNodeHandler()(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestSortedTrunkNames(t *testing.T) {
	got := sortedTrunkNames(map[string]string{"ens20": "", "ens19": "eth1"})
	if len(got) != 2 || got[0] != "ens19" || got[1] != "ens20" {
		t.Errorf("sortedTrunkNames = %v, want [ens19 ens20]", got)
	}
}

// TestInspectNodeHandler_ProbePortStillReachesCoreDaemon is the NC5
// regression: a discovered address carrying the probe daemon's port must
// still be checked against the core daemon.
func TestInspectNodeHandler_ProbePortStillReachesCoreDaemon(t *testing.T) {
	srv := fakeCandidateMux(t, []string{"lo"})
	defer srv.Close()
	host, _, _ := net.SplitHostPort(candidateAt(t, srv))

	orig := currentConfig.Load()
	t.Cleanup(func() { currentConfig.Store(orig) })
	currentConfig.Store(&config.Cluster{Role: "core-1", Platform: &config.Platform{Workers: []string{"lo"}}})
	burstOverride := inspectBurstDurationForTest(1500 * time.Millisecond)
	defer burstOverride()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/inspect", strings.NewReader(`{"addr":"`+host+`:9444"}`))
	rec := httptest.NewRecorder()
	inspectNodeHandler()(rec, req)

	var resp inspectCandidateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v, body = %s", err, rec.Body.String())
	}
	if !resp.OK || resp.Mapping["lo"] != "lo" {
		t.Errorf("probe-port address not redirected to the core daemon: %+v", resp)
	}
}
