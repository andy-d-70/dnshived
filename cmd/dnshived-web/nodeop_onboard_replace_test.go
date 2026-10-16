// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"dnshived/internal/webauth"
)

func TestPendingNodeOp_DescribeDistinguishesOnboardVsReplace(t *testing.T) {
	cases := []struct {
		name string
		op   pendingNodeOp
		want string
	}{
		{"core role missing", pendingNodeOp{Kind: nodeOpReplace, Role: "core-2", Addr: "192.168.0.23:9443", Onboarding: true}, "Onboard 192.168.0.23:9443 as core-2"},
		{"core role occupied", pendingNodeOp{Kind: nodeOpReplace, Role: "core-2", Addr: "192.168.0.23:9443", Onboarding: false}, "Replace core-2 with 192.168.0.23:9443"},
		{"probe missing", pendingNodeOp{Kind: nodeOpReplace, Role: probeRoleName, Addr: "192.168.0.43:9444", Onboarding: true}, "Onboard 192.168.0.43:9444 as the probe host"},
		{"probe occupied", pendingNodeOp{Kind: nodeOpReplace, Role: probeRoleName, Addr: "192.168.0.43:9444", Onboarding: false}, "Replace the probe host with 192.168.0.43:9444"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.op.Describe(); got != c.want {
				t.Errorf("Describe() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestPendingNodeOp_Steps_ProbeReplaceIncludesRemovalStepOnlyWhenOccupied(t *testing.T) {
	onboard := pendingNodeOp{Kind: nodeOpReplace, Role: probeRoleName, Onboarding: true}
	replace := pendingNodeOp{Kind: nodeOpReplace, Role: probeRoleName, Onboarding: false}

	for _, s := range onboard.Steps() {
		if strings.Contains(s, "removing") {
			t.Errorf("onboarding steps must not mention removal, got: %v", onboard.Steps())
		}
	}
	found := false
	for _, s := range replace.Steps() {
		if strings.Contains(s, "removing") {
			found = true
		}
	}
	if !found {
		t.Errorf("replace steps must mention removing the existing probe, got: %v", replace.Steps())
	}
}

// TestRoleIsMissing covers both core roles (checked against cfg.Nodes) and
// the probe sentinel (checked against cfg.ProbeHosts).
func TestRoleIsMissing(t *testing.T) {
	cfg := &WebConfig{
		Nodes:      []NodeConfig{{Name: "core-1"}},
		ProbeHosts: nil,
	}
	if !roleIsMissing(cfg, "core-2") {
		t.Error("core-2 should be missing")
	}
	if roleIsMissing(cfg, "core-1") {
		t.Error("core-1 should NOT be missing")
	}
	if !roleIsMissing(cfg, probeRoleName) {
		t.Error("probe should be missing with zero ProbeHosts")
	}
	cfg.ProbeHosts = []NodeConfig{{Name: "probe", Addr: "192.168.0.43:9444"}}
	if roleIsMissing(cfg, probeRoleName) {
		t.Error("probe should NOT be missing once one is adopted")
	}
}

func TestOnboardAndReplaceTargets_SplitsCorrectly(t *testing.T) {
	nodes := []NodeConfig{{Name: "core-3"}, {Name: "core-1"}} // core-2 missing
	var probeHosts []NodeConfig                               // probe missing too

	onboard, replace := onboardAndReplaceTargets(nodes, probeHosts)
	if !reflect.DeepEqual(onboard, []string{"core-2", probeRoleName}) {
		t.Errorf("onboard = %v, want [core-2 probe]", onboard)
	}
	if !reflect.DeepEqual(replace, []string{"core-1", "core-3"}) {
		t.Errorf("replace = %v, want [core-1 core-3] (numeric order, core-2 excluded)", replace)
	}

	// Fully onboarded cluster + an adopted probe: onboard empty, every
	// role in replace.
	nodes = []NodeConfig{{Name: "core-3"}, {Name: "core-1"}, {Name: "core-2"}}
	probeHosts = []NodeConfig{{Name: "probe", Addr: "x"}}
	onboard, replace = onboardAndReplaceTargets(nodes, probeHosts)
	if len(onboard) != 0 {
		t.Errorf("onboard = %v, want empty", onboard)
	}
	if !reflect.DeepEqual(replace, []string{"core-1", "core-2", "core-3", probeRoleName}) {
		t.Errorf("replace = %v, want all 4 roles in numeric order", replace)
	}
}

// TestExecuteReplaceProbe_RemovesExistingProbeFirst checks only one probe
// host can exist.
func TestExecuteReplaceProbe_RemovesExistingProbeFirst(t *testing.T) {
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true,"probe_admin_token":"tok"}`))
	}))
	defer core.Close()

	cfg := &WebConfig{
		Nodes:      []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(core.URL, "http://"), AdminToken: "admin-tok"}},
		ProbeHosts: []NodeConfig{{Name: "probe", Addr: "192.168.0.43:9444"}}, // the OLD probe
	}
	ref := newConfigRef(cfg)
	cfgPath := t.TempDir() + "/web.json"

	op := pendingNodeOp{Kind: nodeOpReplace, Role: probeRoleName, Addr: "192.168.0.99:9444", JoinCode: "X", Onboarding: false}
	if _, err := executeReplaceProbe(cfgPath, ref, "tester", op); err != nil {
		t.Fatalf("executeReplaceProbe: %v", err)
	}

	hosts := ref.Load().ProbeHosts
	if len(hosts) != 1 {
		t.Fatalf("ProbeHosts = %v, want exactly 1 entry (the new one, old one removed)", hosts)
	}
	if hosts[0].Addr != "192.168.0.99:9444" {
		t.Errorf("ProbeHosts[0].Addr = %q, want the new address", hosts[0].Addr)
	}
}

func TestExecuteReplaceProbe_NoExistingProbeAddsCleanly(t *testing.T) {
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true,"probe_admin_token":"tok"}`))
	}))
	defer core.Close()

	cfg := &WebConfig{
		Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(core.URL, "http://"), AdminToken: "admin-tok"}},
	}
	ref := newConfigRef(cfg)
	cfgPath := t.TempDir() + "/web.json"

	op := pendingNodeOp{Kind: nodeOpReplace, Role: probeRoleName, Addr: "192.168.0.43:9444", JoinCode: "X", Onboarding: true}
	if _, err := executeReplaceProbe(cfgPath, ref, "tester", op); err != nil {
		t.Fatalf("executeReplaceProbe: %v", err)
	}
	hosts := ref.Load().ProbeHosts
	if len(hosts) != 1 || hosts[0].Addr != "192.168.0.43:9444" {
		t.Fatalf("ProbeHosts = %v, want exactly the new entry", hosts)
	}
}

func TestExecuteReplaceProbe_ResolvesRealPortNotTheDiscoveredBootstrapPort(t *testing.T) {
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true,"probe_admin_token":"tok"}`))
	}))
	defer core.Close()

	cfg := &WebConfig{
		Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(core.URL, "http://"), AdminToken: "admin-tok"}},
	}
	ref := newConfigRef(cfg)
	cfgPath := t.TempDir() + "/web.json"

	op := pendingNodeOp{Kind: nodeOpReplace, Role: probeRoleName, Addr: "192.168.0.42:80", JoinCode: "X", Onboarding: true}
	if _, err := executeReplaceProbe(cfgPath, ref, "tester", op); err != nil {
		t.Fatalf("executeReplaceProbe: %v", err)
	}
	hosts := ref.Load().ProbeHosts
	if len(hosts) != 1 || hosts[0].Addr != "192.168.0.42:9444" {
		t.Fatalf("ProbeHosts = %v, want exactly one entry at 192.168.0.42:9444 (the probe's own real port, not the discovered :80)", hosts)
	}
}

func TestExecuteReplaceProbe_FallsBackToSelfWhenNodesIsEmpty(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:9443")
	if err != nil {
		t.Skipf("port 9443 unavailable in this environment: %v", err)
	}
	var srv *httptest.Server
	srv = &httptest.Server{Listener: ln, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/config":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"role":"core-1","control_addr":%q}`, srv.Listener.Addr().String())
		case "/api/v1/nodes/probe":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"ok":true,"probe_admin_token":"tok"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})}}
	srv.StartTLS()
	defer srv.Close()

	cfg := &WebConfig{}
	ref := newConfigRef(cfg)
	cfgPath := t.TempDir() + "/web.json"

	op := pendingNodeOp{Kind: nodeOpReplace, Role: probeRoleName, Addr: "192.168.0.43:9444", JoinCode: "X", Onboarding: true}
	if _, err := executeReplaceProbe(cfgPath, ref, "tester", op); err != nil {
		t.Fatalf("executeReplaceProbe: %v", err)
	}

	hosts := ref.Load().ProbeHosts
	if len(hosts) != 1 || hosts[0].Addr != "192.168.0.43:9444" {
		t.Fatalf("ProbeHosts = %v, want exactly the new entry", hosts)
	}
}

func TestReplaceNodeFormHandler_SetsOnboardingFlagFromLiveState(t *testing.T) {
	t.Cleanup(clearNodeOp)
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1"}}} // core-2 missing
	ref := newConfigRef(cfg)
	cfgPath := t.TempDir() + "/web.json"

	form := "role=core-2&addr=192.168.0.23%3A9443&otp=X"
	req := httptest.NewRequest(http.MethodPost, "/nodes/replace", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), userContextKey{}, webauth.User{Name: "tester"}))
	rec := httptest.NewRecorder()
	replaceNodeFormHandler(cfgPath, ref)(rec, req)

	op := currentNodeOp()
	if op == nil || !op.Onboarding {
		t.Fatalf("currentNodeOp() = %+v, want Onboarding=true for a missing role", op)
	}
	if !strings.Contains(rec.Body.String(), "Onboard 192.168.0.23:9443 as core-2") {
		t.Errorf("expected the onboard wording in the staged response, got: %s", rec.Body.String())
	}
}
