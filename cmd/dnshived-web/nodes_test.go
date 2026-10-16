// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"dnshived/internal/webauth"
)

// TestApplyRename_SetsDisplayNameOnMatchingCoreNode confirms a match
// against cfg.Nodes sets DisplayName there and never touches ProbeHosts.
func TestApplyRename_SetsDisplayNameOnMatchingCoreNode(t *testing.T) {
	cfg := &WebConfig{
		Nodes: []NodeConfig{
			{Name: "core-1", Addr: "192.168.0.22:9443"},
			{Name: "core-2", Addr: "192.168.0.23:9443"},
		},
	}
	if !applyRename(cfg, "192.168.0.23:9443", "Office Worker") {
		t.Fatal("applyRename = false, want true — worker-b's address matches")
	}
	if cfg.Nodes[0].DisplayName != "" {
		t.Errorf("worker-a's DisplayName changed unexpectedly: %q", cfg.Nodes[0].DisplayName)
	}
	if cfg.Nodes[1].DisplayName != "Office Worker" {
		t.Errorf("worker-b's DisplayName = %q, want %q", cfg.Nodes[1].DisplayName, "Office Worker")
	}
	if cfg.Nodes[1].Name != "core-2" {
		t.Error("applyRename must never touch the real Name, only DisplayName")
	}
}

// TestApplyRename_SetsDisplayNameOnMatchingProbeHost confirms the second
// search list (ProbeHosts) is checked too, and correctly independent of
// cfg.Nodes.
func TestApplyRename_SetsDisplayNameOnMatchingProbeHost(t *testing.T) {
	cfg := &WebConfig{
		ProbeHosts: []NodeConfig{{Name: "probe", Addr: "192.168.0.42:9444"}},
	}
	if !applyRename(cfg, "192.168.0.42:9444", "Lab Probe") {
		t.Fatal("applyRename = false, want true")
	}
	if cfg.ProbeHosts[0].DisplayName != "Lab Probe" {
		t.Errorf("DisplayName = %q, want %q", cfg.ProbeHosts[0].DisplayName, "Lab Probe")
	}
}

// TestApplyRename_NoMatchReturnsFalseAndLeavesConfigUntouched confirms a
// non-matching address changes nothing, in either list.
func TestApplyRename_NoMatchReturnsFalseAndLeavesConfigUntouched(t *testing.T) {
	cfg := &WebConfig{
		Nodes:      []NodeConfig{{Name: "core-1", Addr: "192.168.0.22:9443"}},
		ProbeHosts: []NodeConfig{{Name: "probe", Addr: "192.168.0.42:9444"}},
	}
	if applyRename(cfg, "192.168.0.99:9443", "Nope") {
		t.Fatal("applyRename = true, want false — no address matches")
	}
	if cfg.Nodes[0].DisplayName != "" || cfg.ProbeHosts[0].DisplayName != "" {
		t.Error("no entry should have been touched")
	}
}

func TestApplyRename_DoesNotMutateCallersOriginalSliceOnFailurePath(t *testing.T) {
	original := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: "192.168.0.22:9443"}}}
	newCfg := *original // the exact shallow-copy idiom both real call sites use
	applyRename(&newCfg, "192.168.0.22:9443", "Renamed")

	if original.Nodes[0].DisplayName != "" {
		t.Errorf("original cfg's own Nodes slice was mutated through the shared backing array: DisplayName = %q, want empty", original.Nodes[0].DisplayName)
	}
	if newCfg.Nodes[0].DisplayName != "Renamed" {
		t.Errorf("the copy itself should show the rename: got %q", newCfg.Nodes[0].DisplayName)
	}
}

// TestProbeHostDisplayNames_BuildsAddrKeyedLookup pins the small
// template-side helper directly.
func TestProbeHostDisplayNames_BuildsAddrKeyedLookup(t *testing.T) {
	hosts := []NodeConfig{
		{Name: "probe", Addr: "192.168.0.42:9444", DisplayName: "Lab Probe"},
		{Name: "probe2", Addr: "192.168.0.43:9444"},
	}
	got := probeHostDisplayNames(hosts)
	if got["192.168.0.42:9444"] != "Lab Probe" {
		t.Errorf("got[42] = %q, want %q", got["192.168.0.42:9444"], "Lab Probe")
	}
	if got["192.168.0.43:9444"] != "" {
		t.Errorf("got[43] = %q, want empty (no DisplayName set)", got["192.168.0.43:9444"])
	}
}

func TestProbeHostDisplayNamesList_UsesDisplayNameFallback(t *testing.T) {
	hosts := []NodeConfig{
		{Name: "probe", DisplayName: "Lab Probe"},
		{Name: "probe2"},
	}
	got := probeHostDisplayNamesList(hosts)
	want := []string{"Lab Probe", "probe2"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("probeHostDisplayNamesList(...) = %v, want %v", got, want)
	}
}

// TestNodeConfig_DisplayName_FallsBackToName pins the one place every page
// listing a node should go through for this fallback.
func TestNodeConfig_DisplayName_FallsBackToName(t *testing.T) {
	n := NodeConfig{Name: "core-1"}
	if got := n.displayName(); got != "core-1" {
		t.Errorf("displayName() = %q, want %q (fallback to Name)", got, "core-1")
	}
	n.DisplayName = "Office Worker"
	if got := n.displayName(); got != "Office Worker" {
		t.Errorf("displayName() = %q, want %q", got, "Office Worker")
	}
}

func TestSiblingNodes_ExcludesSelfByAddressNotPosition(t *testing.T) {
	cfg := &WebConfig{Nodes: []NodeConfig{
		{Name: "core-1", Addr: "10.99.99.99:9443"}, // never local in this test
		{Name: "core-2", Addr: "127.0.0.1:9443"},   // "this instance"
		{Name: "core-3", Addr: "10.99.99.98:9443"}, // never local in this test
	}}

	got := siblingNodes(cfg)
	if len(got) != 2 {
		t.Fatalf("siblingNodes = %v, want exactly 2 (everyone except worker-b)", got)
	}
	for _, n := range got {
		if n.Name == "core-2" {
			t.Error("siblingNodes included self (worker-b) — must exclude by address match, not list position")
		}
	}
}

func TestIsLocalAddr_MatchesRealLoopback(t *testing.T) {
	if !isLocalAddr("127.0.0.1:9443") {
		t.Error("isLocalAddr(127.0.0.1:9443) = false, want true — loopback is always a real local address")
	}
	if isLocalAddr("203.0.113.1:9443") {
		t.Error("isLocalAddr(203.0.113.1:9443) = true, want false — that's a TEST-NET-3 address, never real on this machine")
	}
}

func TestSiblingWebURL_UsesOwnSchemeAndPortNotCoreAPIs(t *testing.T) {
	cfg := &WebConfig{
		ListenAddr: "0.0.0.0:8443",
		TLSCert:    "/etc/dnshived/webui-tls-cert.pem",
		TLSKey:     "/etc/dnshived/webui-tls-key.pem",
	}
	n := NodeConfig{Name: "core-1", Addr: "192.168.0.22:9443"}

	got := siblingWebURL(n, cfg)
	want := "https://192.168.0.22:8443"
	if got != want {
		t.Errorf("siblingWebURL = %q, want %q", got, want)
	}
}

func TestSiblingWebURL_PlainHTTPWhenTLSNotConfigured(t *testing.T) {
	cfg := &WebConfig{ListenAddr: "0.0.0.0:8080"}
	n := NodeConfig{Name: "core-1", Addr: "192.168.0.22:9443"}

	got := siblingWebURL(n, cfg)
	want := "http://192.168.0.22:8080"
	if got != want {
		t.Errorf("siblingWebURL = %q, want %q", got, want)
	}
}

func TestRenameNodeFormHandler_PublishesLiveWithoutRestart(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "web.json")
	original := &WebConfig{
		ListenAddr: "127.0.0.1:0",
		Nodes: []NodeConfig{
			{Name: "core-1", Addr: "127.0.0.1:1"}, // unreachable; no siblings to fan out to
		},
	}
	ref := newConfigRef(original)

	form := url.Values{"addr": {"127.0.0.1:1"}, "display_name": {"renamed-a"}}
	req := httptest.NewRequest(http.MethodPost, "/nodes/rename", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), userContextKey{}, webauth.User{Name: "tester"}))
	rec := httptest.NewRecorder()

	renameNodeFormHandler(cfgPath, ref)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	live := ref.Load()
	if live.Nodes[0].DisplayName != "renamed-a" {
		t.Fatalf("ref.Load() after the handler returned has DisplayName %q, want %q — "+
			"the rename was never published live, a caller would still need a process restart to see it",
			live.Nodes[0].DisplayName, "renamed-a")
	}

	if original.Nodes[0].DisplayName != "" {
		t.Fatalf("original *WebConfig mutated in place: DisplayName = %q, want empty", original.Nodes[0].DisplayName)
	}
}

func TestRenameNodeFormHandler_SelfTargetSetsSelfDisplayName(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "web.json")
	original := &WebConfig{
		ListenAddr: "127.0.0.1:0",
		Nodes: []NodeConfig{
			{Name: "core-2", Addr: "127.0.0.1:1"},
		},
	}
	ref := newConfigRef(original)

	form := url.Values{"addr": {"127.0.0.1:9443"}, "display_name": {"this-box"}}
	req := httptest.NewRequest(http.MethodPost, "/nodes/rename", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), userContextKey{}, webauth.User{Name: "tester"}))
	rec := httptest.NewRecorder()

	renameNodeFormHandler(cfgPath, ref)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s — self-targeted rename must succeed, not \"no node recorded\"", rec.Code, rec.Body.String())
	}
	live := ref.Load()
	if live.SelfDisplayName != "this-box" {
		t.Errorf("SelfDisplayName = %q, want %q", live.SelfDisplayName, "this-box")
	}
	// The real sibling entry must be completely untouched by a
	// self-targeted rename.
	if live.Nodes[0].DisplayName != "" {
		t.Errorf("sibling worker-b's own DisplayName = %q, want untouched (empty)", live.Nodes[0].DisplayName)
	}
}

func TestOffboardNodeFormHandler_StagesWithoutTouchingLocalNodeList(t *testing.T) {
	t.Cleanup(clearNodeOp)
	called := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer target.Close()
	targetAddr := strings.TrimPrefix(target.URL, "http://")

	cfgPath := filepath.Join(t.TempDir(), "web.json")
	original := &WebConfig{
		ListenAddr: "127.0.0.1:0",
		Nodes: []NodeConfig{
			{Name: "core-1", Addr: "192.168.0.22:9443"},
			{Name: "core-2", Addr: "192.168.0.23:9443"},
			{Name: "core-3", Addr: targetAddr},
		},
	}
	ref := newConfigRef(original)

	form := url.Values{"role": {"core-3"}}
	req := httptest.NewRequest(http.MethodPost, "/nodes/offboard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), userContextKey{}, webauth.User{Name: "tester"}))
	rec := httptest.NewRecorder()

	offboardNodeFormHandler(ref, cfgPath)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if called {
		t.Fatal("staging an offboard must never call the target node — that's executeOffboardNode's job, at commit time")
	}
	live := ref.Load()
	if len(live.Nodes) != 3 {
		t.Fatalf("cfg.Nodes changed at stage time: %v", live.Nodes)
	}
	op := currentNodeOp()
	if op == nil || op.Kind != nodeOpOffboard || op.Role != "core-3" {
		t.Fatalf("currentNodeOp() = %+v, want a staged offboard for core-3", op)
	}
}

func TestExecuteOffboardNode_RemovesTargetFromLocalNodeList(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer target.Close()
	targetAddr := strings.TrimPrefix(target.URL, "http://")

	cfgPath := filepath.Join(t.TempDir(), "web.json")
	original := &WebConfig{
		ListenAddr: "127.0.0.1:0",
		Nodes: []NodeConfig{
			{Name: "core-1", Addr: "192.168.0.22:9443"},
			{Name: "core-2", Addr: "192.168.0.23:9443"},
			{Name: "core-3", Addr: targetAddr},
		},
	}
	ref := newConfigRef(original)

	_, err := executeOffboardNode(ref, cfgPath, "tester", pendingNodeOp{Kind: nodeOpOffboard, Role: "core-3"}, false, false)
	if err != nil {
		t.Fatalf("executeOffboardNode: %v", err)
	}

	live := ref.Load()
	for _, n := range live.Nodes {
		if n.Name == "core-3" {
			t.Fatalf("core-3 is still in cfg.Nodes after a successful offboard — the exact stale-list bug this test guards against")
		}
	}
	if len(live.Nodes) != 2 {
		t.Fatalf("live.Nodes = %v, want the 2 remaining core roles", live.Nodes)
	}

	// The original *WebConfig must be left untouched, same invariant
	// every other handler in this file already upholds.
	if len(original.Nodes) != 3 {
		t.Fatalf("original *WebConfig mutated in place: Nodes = %v", original.Nodes)
	}
}

func TestExecuteOffboardNode_RefreshesClusterNodesOnEveryProbeHost(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer target.Close()
	targetAddr := strings.TrimPrefix(target.URL, "http://")

	var gotProbeBody map[string][]probeClusterNodePatch
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotProbeBody); err != nil {
			t.Errorf("decode probe request body: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"ok":true,"restarting":true}`))
	}))
	defer probe.Close()
	probeAddr := strings.TrimPrefix(probe.URL, "http://")

	cfgPath := filepath.Join(t.TempDir(), "web.json")
	original := &WebConfig{
		ListenAddr: "127.0.0.1:0",
		Nodes: []NodeConfig{
			{Name: "core-1", Addr: "192.168.0.22:9443"},
			{Name: "core-2", Addr: "192.168.0.23:9443"},
			{Name: "core-3", Addr: targetAddr},
		},
		ProbeHosts: []NodeConfig{
			{Name: "probe", Addr: probeAddr, AdminToken: "probe-tok"},
		},
	}
	ref := newConfigRef(original)

	_, err := executeOffboardNode(ref, cfgPath, "tester", pendingNodeOp{Kind: nodeOpOffboard, Role: "core-3"}, false, false)
	if err != nil {
		t.Fatalf("executeOffboardNode: %v", err)
	}

	pushed := gotProbeBody["cluster_nodes"]
	if len(pushed) != 2 {
		t.Fatalf("probe host received %d cluster_nodes, want 2 (the remaining core-1/core-2, core-3 dropped): %+v", len(pushed), pushed)
	}
	for _, n := range pushed {
		if n.Name == "core-3" {
			t.Errorf("probe host was pushed the just-offboarded core-3 (%q) — stale by construction", n.Addr)
		}
	}
}

// TestWouldBreakQuorumFloor covers wouldBreakQuorumFloor's own pure logic
// directly.
func TestWouldBreakQuorumFloor(t *testing.T) {
	allThree := []NodeConfig{{Name: "core-1"}, {Name: "core-2"}, {Name: "core-3"}}
	core1AndCore2 := []NodeConfig{{Name: "core-1"}, {Name: "core-2"}}
	core1AndCore3 := []NodeConfig{{Name: "core-1"}, {Name: "core-3"}}
	core1Only := []NodeConfig{{Name: "core-1"}}

	cases := []struct {
		name  string
		role  string
		nodes []NodeConfig
		want  bool
	}{
		{"all 3 present, offboarding core-1 leaves 2 — fine", "core-1", allThree, false},
		{"all 3 present, offboarding core-2 leaves 2 — fine", "core-2", allThree, false},
		{"all 3 present, offboarding core-3 leaves 2 — fine, core-3 is no longer exempt", "core-3", allThree, false},
		{"only 2 present, offboarding core-1 leaves 1 — breaks the floor", "core-1", core1AndCore2, true},
		{"only 2 present (core-3 already down), offboarding core-1 leaves 1 — breaks the floor", "core-1", core1AndCore3, true},
		{"only 2 present (core-2 already down), offboarding core-3 leaves 1 — breaks the floor, the direct regression case for core-3's old exemption", "core-3", core1AndCore3, true},
		{"only 1 present, offboarding it leaves 0 — breaks the floor", "core-1", core1Only, true},
		{"probe host role is exempt entirely (not a core role)", "probe", allThree, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := wouldBreakQuorumFloor(c.role, c.nodes); got != c.want {
				t.Errorf("wouldBreakQuorumFloor(%q, %v) = %v, want %v", c.role, c.nodes, got, c.want)
			}
		})
	}
}

func TestWouldLeaveZeroCoreNodes(t *testing.T) {
	allThree := []NodeConfig{{Name: "core-1"}, {Name: "core-2"}, {Name: "core-3"}}
	core1AndCore2 := []NodeConfig{{Name: "core-1"}, {Name: "core-2"}}
	core1Only := []NodeConfig{{Name: "core-1"}}

	cases := []struct {
		name  string
		role  string
		nodes []NodeConfig
		want  bool
	}{
		{"all 3 present, offboarding core-1 leaves 2 — not zero", "core-1", allThree, false},
		{"only 2 present, offboarding core-1 leaves 1 — not zero, this is the safe standalone case", "core-1", core1AndCore2, false},
		{"only 1 present, offboarding it leaves 0 — the real wipe case", "core-1", core1Only, true},
		{"probe host role is exempt entirely (not a core role)", "probe", core1Only, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := wouldLeaveZeroCoreNodes(c.role, c.nodes); got != c.want {
				t.Errorf("wouldLeaveZeroCoreNodes(%q, %v) = %v, want %v", c.role, c.nodes, got, c.want)
			}
		})
	}
}

func TestOffboardNodeFormHandler_WarnsButStagesLastRemainingWorker(t *testing.T) {
	t.Cleanup(clearNodeOp)
	local := newLocalConfigServer(t, "core-3", "192.168.0.24:9443")
	port := localPort(t, local)

	cfgPath := filepath.Join(t.TempDir(), "web.json")
	original := &WebConfig{
		ListenAddr: "127.0.0.1:0",
		Nodes: []NodeConfig{
			{Name: "core-1", Addr: "192.168.9.9:" + port},
		},
	}
	ref := newConfigRef(original)

	form := url.Values{"role": {"core-1"}}
	req := httptest.NewRequest(http.MethodPost, "/nodes/offboard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), userContextKey{}, webauth.User{Name: "tester"}))
	rec := httptest.NewRecorder()

	offboardNodeFormHandler(ref, cfgPath)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — offboarding down to 1 remaining core node warns now, it no longer refuses", rec.Code)
	}
	op := currentNodeOp()
	if op == nil {
		t.Fatal("currentNodeOp() = nil, want a staged offboard op")
	}
	if !op.BreaksQuorumFloor {
		t.Error("op.BreaksQuorumFloor = false, want true — offboarding core-1 leaves only core-3")
	}
	if !strings.Contains(rec.Body.String(), "fewer than 2 remaining core nodes") {
		t.Errorf("staged-confirmation response missing the quorum-floor warning: %s", rec.Body.String())
	}
}

func TestExecuteOffboardNode_RefusesLastRemainingNodeWithoutConfirmation(t *testing.T) {
	var offboardCalled bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offboardCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer target.Close()
	targetAddr := strings.TrimPrefix(target.URL, "http://")

	cfgPath := filepath.Join(t.TempDir(), "web.json")
	original := &WebConfig{
		ListenAddr: "127.0.0.1:0",
		Nodes: []NodeConfig{
			{Name: "core-1", Addr: targetAddr},
		},
	}
	ref := newConfigRef(original)

	_, err := executeOffboardNode(ref, cfgPath, "tester", pendingNodeOp{Kind: nodeOpOffboard, Role: "core-1"}, false, false)
	if err == nil {
		t.Fatal("executeOffboardNode = nil error, want a refusal — this is the last remaining core node and confirmedWipe was false")
	}
	if offboardCalled {
		t.Error("the target's own /api/v1/nodes/offboard was called despite missing confirmation — nothing destructive must run before the gate")
	}
	live := ref.Load()
	if len(live.Nodes) != 1 {
		t.Fatalf("cfg.Nodes = %v, want core-1 left untouched — the refusal must happen before any mutation", live.Nodes)
	}
}

// TestExecuteOffboardNode_ProceedsForLastRemainingNodeWhenConfirmed is the
// other half.
func TestExecuteOffboardNode_ProceedsForLastRemainingNodeWhenConfirmed(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer target.Close()
	targetAddr := strings.TrimPrefix(target.URL, "http://")

	cfgPath := filepath.Join(t.TempDir(), "web.json")
	original := &WebConfig{
		ListenAddr: "127.0.0.1:0",
		Nodes: []NodeConfig{
			{Name: "core-1", Addr: targetAddr},
		},
	}
	ref := newConfigRef(original)

	msg, err := executeOffboardNode(ref, cfgPath, "tester", pendingNodeOp{Kind: nodeOpOffboard, Role: "core-1"}, true, false)
	if err != nil {
		t.Fatalf("executeOffboardNode: %v, want it to proceed once confirmed", err)
	}
	if !strings.Contains(msg, "fewer than 2 remaining core nodes") {
		t.Errorf("result message missing the quorum-floor warning: %q", msg)
	}
	live := ref.Load()
	if len(live.Nodes) != 0 {
		t.Fatalf("cfg.Nodes = %v, want core-1 actually removed — the offboard must still run for real once confirmed", live.Nodes)
	}
}

func TestReplaceNodeFormHandler_StagesWithoutTouchingLocalNodeList(t *testing.T) {
	t.Cleanup(clearNodeOp)
	called := false
	survivor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer survivor.Close()
	survivorAddr := strings.TrimPrefix(survivor.URL, "http://")

	cfgPath := filepath.Join(t.TempDir(), "web.json")
	original := &WebConfig{
		ListenAddr: "127.0.0.1:0",
		Nodes: []NodeConfig{
			{Name: "core-1", Addr: survivorAddr, AdminToken: "shared-tok"},
		},
	}
	ref := newConfigRef(original)

	form := url.Values{"role": {"core-2"}, "addr": {"192.168.0.23:9443"}, "otp": {"JOIN-CODE"}}
	req := httptest.NewRequest(http.MethodPost, "/nodes/replace", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), userContextKey{}, webauth.User{Name: "tester"}))
	rec := httptest.NewRecorder()

	replaceNodeFormHandler(cfgPath, ref)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if called {
		t.Fatal("staging a replace must never call the survivor node — that's executeReplaceNode's job, at commit time")
	}
	if len(ref.Load().Nodes) != 1 {
		t.Fatalf("cfg.Nodes changed at stage time: %v", ref.Load().Nodes)
	}
	op := currentNodeOp()
	if op == nil || op.Kind != nodeOpReplace || op.Role != "core-2" || op.Addr != "192.168.0.23:9443" {
		t.Fatalf("currentNodeOp() = %+v, want a staged replace of worker-b with 192.168.0.23:9443", op)
	}
}

func TestExecuteReplaceNode_AddsMissingRoleToLocalNodeList(t *testing.T) {
	survivor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer survivor.Close()
	survivorAddr := strings.TrimPrefix(survivor.URL, "http://")
	_, survivorPort, err := net.SplitHostPort(survivorAddr)
	if err != nil {
		t.Fatalf("unexpected error splitting httptest server addr: %v", err)
	}

	cfgPath := filepath.Join(t.TempDir(), "web.json")
	original := &WebConfig{
		ListenAddr: "127.0.0.1:0",
		Nodes: []NodeConfig{
			{Name: "core-1", Addr: survivorAddr, AdminToken: "shared-tok"},
		},
	}
	ref := newConfigRef(original)

	_, err = executeReplaceNode(cfgPath, ref, "tester", pendingNodeOp{Kind: nodeOpReplace, Role: "core-2", Addr: "192.168.0.23:80", JoinCode: "JOIN-CODE"}, false)
	if err != nil {
		t.Fatalf("executeReplaceNode: %v", err)
	}

	live := ref.Load()
	var found *NodeConfig
	for i := range live.Nodes {
		if live.Nodes[i].Name == "core-2" {
			found = &live.Nodes[i]
		}
	}
	if found == nil {
		t.Fatalf("worker-b was never added to cfg.Nodes after a successful replace — the exact invisible-on-Overview/false-UNSERVED bug this test guards against; live.Nodes = %v", live.Nodes)
	}
	wantAddr := net.JoinHostPort("192.168.0.23", survivorPort)
	if found.Addr != wantAddr {
		t.Errorf("worker-b.Addr = %q, want %q (submitted addr's own host, survivor's own port convention)", found.Addr, wantAddr)
	}

	// The original *WebConfig must be left untouched.
	if len(original.Nodes) != 1 {
		t.Fatalf("original *WebConfig mutated in place: Nodes = %v", original.Nodes)
	}
}

func TestExecuteReplaceNode_ForwardsOldAddrFromExistingNodeEntry(t *testing.T) {
	var gotBody map[string]interface{}
	survivor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer survivor.Close()
	survivorAddr := strings.TrimPrefix(survivor.URL, "http://")

	cfgPath := filepath.Join(t.TempDir(), "web.json")
	original := &WebConfig{
		ListenAddr: "127.0.0.1:0",
		Nodes: []NodeConfig{
			{Name: "core-1", Addr: survivorAddr, AdminToken: "shared-tok"},
			{Name: "core-2", Addr: "192.168.0.22-OLD:9443", AdminToken: "shared-tok"},
		},
	}
	ref := newConfigRef(original)

	_, err := executeReplaceNode(cfgPath, ref, "tester", pendingNodeOp{Kind: nodeOpReplace, Role: "core-2", Addr: "192.168.0.22-NEW:9443", JoinCode: "JOIN-CODE"}, false)
	if err != nil {
		t.Fatalf("executeReplaceNode: %v", err)
	}

	if gotBody["old_addr"] != "192.168.0.22-OLD:9443" {
		t.Errorf("old_addr sent to cmd/dnshived = %v, want the existing worker-b entry's own address %q", gotBody["old_addr"], "192.168.0.22-OLD:9443")
	}
	if gotBody["role"] != "core-2" || gotBody["addr"] != "192.168.0.22-NEW:9443" {
		t.Errorf("unexpected role/addr in forwarded body: %+v", gotBody)
	}
}

func TestExecuteReplaceNode_RefreshesClusterNodesOnEveryProbeHost(t *testing.T) {
	survivor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer survivor.Close()
	survivorAddr := strings.TrimPrefix(survivor.URL, "http://")
	_, survivorPort, err := net.SplitHostPort(survivorAddr)
	if err != nil {
		t.Fatalf("unexpected error splitting httptest server addr: %v", err)
	}

	var gotProbeBody map[string][]probeClusterNodePatch
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotProbeBody); err != nil {
			t.Errorf("decode probe request body: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"ok":true,"restarting":true}`))
	}))
	defer probe.Close()
	probeAddr := strings.TrimPrefix(probe.URL, "http://")

	cfgPath := filepath.Join(t.TempDir(), "web.json")
	original := &WebConfig{
		ListenAddr: "127.0.0.1:0",
		Nodes: []NodeConfig{
			{Name: "core-1", Addr: survivorAddr, AdminToken: "shared-tok"},
			{Name: "core-2", Addr: "192.168.0.22-OLD:9443", AdminToken: "shared-tok"},
		},
		ProbeHosts: []NodeConfig{
			{Name: "probe", Addr: probeAddr, AdminToken: "probe-tok"},
		},
	}
	ref := newConfigRef(original)

	_, err = executeReplaceNode(cfgPath, ref, "tester", pendingNodeOp{Kind: nodeOpReplace, Role: "core-2", Addr: "192.168.0.22-NEW:9443", JoinCode: "JOIN-CODE"}, false)
	if err != nil {
		t.Fatalf("executeReplaceNode: %v", err)
	}

	wantNewAddr := net.JoinHostPort("192.168.0.22-NEW", survivorPort)
	pushed := gotProbeBody["cluster_nodes"]
	if len(pushed) != 2 {
		t.Fatalf("probe host received %d cluster_nodes, want 2 (worker-a + the newly-replaced worker-b): %+v", len(pushed), pushed)
	}
	var sawNewWorkerB bool
	for _, n := range pushed {
		if n.Name == "core-2" && n.Addr == wantNewAddr {
			sawNewWorkerB = true
		}
		if n.Addr == "192.168.0.22-OLD:9443" {
			t.Errorf("probe host was pushed the OLD, just-replaced address %q — stale by construction", n.Addr)
		}
	}
	if !sawNewWorkerB {
		t.Errorf("probe host's pushed cluster_nodes never included the just-adopted worker-b at its new address %q: %+v", wantNewAddr, pushed)
	}
}

func TestExecuteReplaceNode_PushedClusterNodesIncludesSelf(t *testing.T) {
	var gotProbeBody map[string][]probeClusterNodePatch
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/config", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"role":"core-3","control_addr":"192.168.0.43:9443"}`)
	})
	mux.HandleFunc("/api/v1/nodes/replace", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	})
	survivor := httptest.NewTLSServer(mux)
	defer survivor.Close()
	survivorAddr := strings.TrimPrefix(survivor.URL, "https://")

	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotProbeBody); err != nil {
			t.Errorf("decode probe request body: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"ok":true,"restarting":true}`))
	}))
	defer probe.Close()
	probeAddr := strings.TrimPrefix(probe.URL, "http://")

	cfgPath := filepath.Join(t.TempDir(), "web.json")
	original := &WebConfig{
		ListenAddr: "127.0.0.1:0",
		Nodes: []NodeConfig{
			{Name: "core-1", Addr: survivorAddr, TLS: true, AdminToken: "shared-tok"},
			{Name: "core-2", Addr: "192.168.0.22-OLD:9443", AdminToken: "shared-tok"},
		},
		ProbeHosts: []NodeConfig{
			{Name: "probe", Addr: probeAddr, AdminToken: "probe-tok"},
		},
	}
	ref := newConfigRef(original)

	_, err := executeReplaceNode(cfgPath, ref, "tester", pendingNodeOp{Kind: nodeOpReplace, Role: "core-2", Addr: "192.168.0.22-NEW:9443", JoinCode: "JOIN-CODE"}, false)
	if err != nil {
		t.Fatalf("executeReplaceNode: %v", err)
	}

	pushed := gotProbeBody["cluster_nodes"]
	var sawSelf bool
	for _, n := range pushed {
		if n.Name == "core-3" && n.Addr == "192.168.0.43:9443" {
			sawSelf = true
		}
	}
	if !sawSelf {
		t.Errorf("pushed cluster_nodes never included the executing instance's OWN role (arbiter) — the exact bug found live; pushed = %+v", pushed)
	}
	if len(pushed) != 3 {
		t.Errorf("pushed cluster_nodes has %d entries, want 3 (worker-a, the new worker-b, and self/arbiter): %+v", len(pushed), pushed)
	}
}

func TestExecuteReplaceNode_FallsBackToSelfWhenNodesIsEmpty(t *testing.T) {
	var replaceCalled bool
	var selfAddr string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/config", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"role":"core-1","control_addr":%q}`, selfAddr)
	})
	mux.HandleFunc("/api/v1/nodes/replace", func(w http.ResponseWriter, r *http.Request) {
		replaceCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/internal/nodes/replace", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	selfAddr = u.Host
	_, selfPort, err := net.SplitHostPort(selfAddr)
	if err != nil {
		t.Fatalf("unexpected error splitting httptest server addr: %v", err)
	}

	cfgPath := filepath.Join(t.TempDir(), "web.json")
	original := &WebConfig{
		ListenAddr: "127.0.0.1:0",
		Nodes:      []NodeConfig{{Name: "core-2", Addr: "192.168.0.23-STALE:" + localPort(t, srv)}},
	}
	ref := newConfigRef(original)

	_, err = executeReplaceNode(cfgPath, ref, "tester", pendingNodeOp{Kind: nodeOpReplace, Role: "core-2", Addr: "192.168.0.23:9443", JoinCode: "JOIN-CODE"}, false)
	if err != nil {
		t.Fatalf("executeReplaceNode: %v", err)
	}
	if !replaceCalled {
		t.Fatal("executeReplaceNode never called self's own /api/v1/nodes/replace — self-fallback failed silently")
	}

	wantAddr := net.JoinHostPort("192.168.0.23", selfPort)
	live := ref.Load()
	found := false
	for _, n := range live.Nodes {
		if n.Name == "core-2" && n.Addr == wantAddr {
			found = true
		}
	}
	if !found {
		t.Errorf("worker-b was never added to cfg.Nodes after the self-served replace; want addr %q, live.Nodes = %v", wantAddr, live.Nodes)
	}
}

func TestExecuteReplaceNode_UpdatesStaleAddrForExistingRole(t *testing.T) {
	survivor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer survivor.Close()
	survivorAddr := strings.TrimPrefix(survivor.URL, "http://")
	_, survivorPort, err := net.SplitHostPort(survivorAddr)
	if err != nil {
		t.Fatalf("unexpected error splitting httptest server addr: %v", err)
	}

	cfgPath := filepath.Join(t.TempDir(), "web.json")
	original := &WebConfig{
		ListenAddr: "127.0.0.1:0",
		Nodes: []NodeConfig{
			{Name: "core-1", Addr: survivorAddr, AdminToken: "shared-tok"},
			{Name: "core-2", Addr: "192.168.0.99:9443"}, // stale, dead address
		},
	}
	ref := newConfigRef(original)

	_, err = executeReplaceNode(cfgPath, ref, "tester", pendingNodeOp{Kind: nodeOpReplace, Role: "core-2", Addr: "192.168.0.23:9443", JoinCode: "JOIN-CODE"}, false)
	if err != nil {
		t.Fatalf("executeReplaceNode: %v", err)
	}

	wantAddr := net.JoinHostPort("192.168.0.23", survivorPort)
	live := ref.Load()
	if len(live.Nodes) != 2 {
		t.Fatalf("live.Nodes has %d entries, want exactly 2 (updated in place, not duplicated): %v", len(live.Nodes), live.Nodes)
	}
	for _, n := range live.Nodes {
		if n.Name == "core-2" && n.Addr != wantAddr {
			t.Errorf("worker-b.Addr = %q, want the new address %q, not the stale one", n.Addr, wantAddr)
		}
	}
}

func TestOffboardNodeFormHandler_AllowsSelfsOwnRole(t *testing.T) {
	t.Cleanup(clearNodeOp)
	local := newLocalConfigServer(t, "core-3", "192.168.0.22:9443")
	port := localPort(t, local)

	cfgPath := filepath.Join(t.TempDir(), "web.json")
	original := &WebConfig{
		ListenAddr: "127.0.0.1:0",
		Nodes: []NodeConfig{
			{Name: "core-1", Addr: "192.168.9.9:" + port},
			{Name: "core-2", Addr: "192.168.9.10:" + port},
		},
	}
	ref := newConfigRef(original)

	form := url.Values{"role": {"core-3"}}
	req := httptest.NewRequest(http.MethodPost, "/nodes/offboard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), userContextKey{}, webauth.User{Name: "tester"}))
	rec := httptest.NewRecorder()

	offboardNodeFormHandler(ref, cfgPath)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s — want the offboard to stage successfully for self's own role", rec.Code, rec.Body.String())
	}
	op := currentNodeOp()
	if op == nil || op.Kind != nodeOpOffboard || op.Role != "core-3" {
		t.Fatalf("currentNodeOp() = %+v, want a staged offboard for arbiter (self)", op)
	}
}

// TestExecuteOffboardNode_TargetsSelfWhenRoleIsNotInNodes is the
// commit-time counterpart of the staging test above.
func TestExecuteOffboardNode_TargetsSelfWhenRoleIsNotInNodes(t *testing.T) {
	var offboardCalled bool
	var selfAddr string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/config", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"role":"core-3","control_addr":%q}`, selfAddr)
	})
	mux.HandleFunc("/api/v1/nodes/offboard", func(w http.ResponseWriter, r *http.Request) {
		offboardCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/api/v1/audit", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	selfAddr = u.Host

	cfgPath := filepath.Join(t.TempDir(), "web.json")
	original := &WebConfig{
		ListenAddr: "127.0.0.1:0",
		Nodes: []NodeConfig{
			{Name: "core-1", Addr: u.Host},
			{Name: "core-2", Addr: u.Host},
		},
	}
	ref := newConfigRef(original)

	msg, err := executeOffboardNode(ref, cfgPath, "tester", pendingNodeOp{Kind: nodeOpOffboard, Role: "core-3"}, false, false)
	if err != nil {
		t.Fatalf("executeOffboardNode: %v", err)
	}
	if !offboardCalled {
		t.Fatal("executeOffboardNode never actually called the target's /api/v1/nodes/offboard — self-resolution failed silently")
	}
	if !strings.Contains(msg, "core-3") {
		t.Errorf("result message = %q, want it to mention the offboarded role", msg)
	}
	live := ref.Load()
	if len(live.Nodes) != 2 {
		t.Errorf("live.Nodes = %v, want the 2 original entries left untouched", live.Nodes)
	}
}

func newLocalConfigServer(t *testing.T, role, controlAddr string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/config" {
			t.Errorf("unexpected path %q, want /api/v1/config", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"role":%q,"control_addr":%q}`, role, controlAddr)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// localPort extracts the port a TLS test server bound to.
func localPort(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split test server host:port: %v", err)
	}
	return port
}

func TestSelfNodeConfig_QueriesTheLocalCoreDaemonOverLoopback(t *testing.T) {
	local := newLocalConfigServer(t, "core-3", "192.168.0.22:9443")
	port := localPort(t, local)

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: "192.168.9.9:" + port, AdminToken: "shared-tok"}}}

	self, ok := selfNodeConfig(cfg)
	if !ok {
		t.Fatal("selfNodeConfig ok = false, want true")
	}
	if self.Name != "core-3" {
		t.Errorf("self.Name = %q, want %q", self.Name, "core-3")
	}
	if self.Addr != "192.168.0.22:9443" {
		t.Errorf("self.Addr = %q, want the real control_addr, not loopback", self.Addr)
	}
}

func TestNodesSharedToken_FallsBackToCoordinatorWhenNodesEmpty(t *testing.T) {
	cfg := &WebConfig{
		CoordinatorNode: &NodeConfig{Name: "coordinator", Addr: "192.168.0.230:9443", AdminToken: "shared-tok"},
	}
	if got := nodesSharedToken(cfg); got != "shared-tok" {
		t.Errorf("nodesSharedToken = %q, want the CoordinatorNode's own token %q", got, "shared-tok")
	}
}

// TestNodesSharedToken_PrefersNodesOverCoordinator confirms the fallback
// only kicks in when cfg.Nodes has nothing.
func TestNodesSharedToken_PrefersNodesOverCoordinator(t *testing.T) {
	cfg := &WebConfig{
		Nodes:           []NodeConfig{{Name: "core-2", AdminToken: "nodes-tok"}},
		CoordinatorNode: &NodeConfig{Name: "coordinator", AdminToken: "coordinator-tok"},
	}
	if got := nodesSharedToken(cfg); got != "nodes-tok" {
		t.Errorf("nodesSharedToken = %q, want the cfg.Nodes entry's own token %q (unchanged precedence)", got, "nodes-tok")
	}
}

func TestNodesSharedToken_EmptyEverywhereReturnsEmpty(t *testing.T) {
	if got := nodesSharedToken(&WebConfig{}); got != "" {
		t.Errorf("nodesSharedToken = %q, want empty", got)
	}
}

func TestNodesSharedToken_SelfAdminTokenWinsEvenWithZeroPeers(t *testing.T) {
	cfg := &WebConfig{SelfAdminToken: "durable-self-tok"}
	if got := nodesSharedToken(cfg); got != "durable-self-tok" {
		t.Errorf("nodesSharedToken = %q, want the durable SelfAdminToken %q with zero peers and no CoordinatorNode", got, "durable-self-tok")
	}
}

// TestNodesSharedToken_SelfAdminTokenTakesPrecedence confirms the new
// field is checked FIRST, ahead of both existing fallbacks.
func TestNodesSharedToken_SelfAdminTokenTakesPrecedence(t *testing.T) {
	cfg := &WebConfig{
		SelfAdminToken:  "self-tok",
		Nodes:           []NodeConfig{{Name: "core-2", AdminToken: "nodes-tok"}},
		CoordinatorNode: &NodeConfig{Name: "coordinator", AdminToken: "coordinator-tok"},
	}
	if got := nodesSharedToken(cfg); got != "self-tok" {
		t.Errorf("nodesSharedToken = %q, want SelfAdminToken %q to win over both fallbacks", got, "self-tok")
	}
}

// TestNodesSharedToken_EmptySelfAdminTokenFallsBackToNodes checks a
// web.json without the self admin token still works.
func TestNodesSharedToken_EmptySelfAdminTokenFallsBackToNodes(t *testing.T) {
	cfg := &WebConfig{
		Nodes: []NodeConfig{{Name: "core-2", AdminToken: "nodes-tok"}},
	}
	if got := nodesSharedToken(cfg); got != "nodes-tok" {
		t.Errorf("nodesSharedToken = %q, want the cfg.Nodes entry's own token %q (pre-fix web.json, SelfAdminToken empty)", got, "nodes-tok")
	}
}

func TestSelfNodeConfig_CarriesSelfDisplayName(t *testing.T) {
	local := newLocalConfigServer(t, "core-3", "192.168.0.22:9443")
	port := localPort(t, local)

	cfg := &WebConfig{
		Nodes:           []NodeConfig{{Name: "core-1", Addr: "192.168.9.9:" + port}},
		SelfDisplayName: "lab-arbiter",
	}

	self, ok := selfNodeConfig(cfg)
	if !ok {
		t.Fatal("selfNodeConfig ok = false, want true")
	}
	if self.DisplayName != "lab-arbiter" {
		t.Errorf("self.DisplayName = %q, want the persisted SelfDisplayName %q", self.DisplayName, "lab-arbiter")
	}
}

// TestSelfNodeConfig_UnreachableReturnsNotOK confirms the best-effort
// fallback.
func TestSelfNodeConfig_UnreachableReturnsNotOK(t *testing.T) {
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: "192.168.9.9:1"}}}
	if _, ok := selfNodeConfig(cfg); ok {
		t.Error("selfNodeConfig ok = true, want false on an unreachable local daemon")
	}
}

func TestSelfNodeConfig_FailedSelfProbeNeverPoisonsRealPeerAtSameAddress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"role":"core-2","control_addr":"192.168.0.23:9443"}`)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: addr}}}

	selfNodeConfig(cfg)

	c, err := fetchConfig(NodeConfig{Addr: addr})
	if err != nil {
		t.Fatalf("fetchConfig to a real, live peer failed after an unrelated self-probe at the same address: %v", err)
	}
	if c.Role != "core-2" {
		t.Errorf("fetchConfig returned Role %q, want worker-b (the real peer's own response)", c.Role)
	}
}

func TestMissingCoreRolesExcludingSelf_RemovesOwnRoleFromTheResult(t *testing.T) {
	local := newLocalConfigServer(t, "core-3", "192.168.0.22:9443")
	port := localPort(t, local)

	cfg := &WebConfig{Nodes: []NodeConfig{
		{Name: "core-1", Addr: "192.168.9.9:" + port},
		{Name: "core-2", Addr: "192.168.9.10:" + port},
	}}

	got := missingCoreRolesExcludingSelf(cfg)
	if len(got) != 0 {
		t.Errorf("missingCoreRolesExcludingSelf = %v, want empty (arbiter is self, worker-a/worker-b are both present)", got)
	}
}

func TestMissingCoreRolesExcludingSelf_StillReportsAGenuinelyMissingRole(t *testing.T) {
	local := newLocalConfigServer(t, "core-3", "192.168.0.22:9443")
	port := localPort(t, local)

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: "192.168.9.9:" + port}}}

	got := missingCoreRolesExcludingSelf(cfg)
	want := []string{"core-2"}
	if len(got) != 1 || got[0] != want[0] {
		t.Errorf("missingCoreRolesExcludingSelf = %v, want %v", got, want)
	}
}

func TestNodesIncludingSelf_AddsOwnRowInCanonicalOrder(t *testing.T) {
	local := newLocalConfigServer(t, "core-3", "192.168.0.22:9443")
	port := localPort(t, local)

	cfg := &WebConfig{Nodes: []NodeConfig{
		{Name: "core-2", Addr: "192.168.9.10:" + port},
		{Name: "core-1", Addr: "192.168.9.9:" + port},
	}}

	got := nodesIncludingSelf(cfg)
	if len(got) != 3 {
		t.Fatalf("nodesIncludingSelf returned %d nodes, want 3 (core-1, core-2, core-3/self): %+v", len(got), got)
	}
	want := []string{"core-1", "core-2", "core-3"}
	for i, n := range got {
		if n.Name != want[i] {
			t.Errorf("got[%d].Name = %q, want %q (canonical order)", i, n.Name, want[i])
		}
	}
	if got[2].Addr != "192.168.0.22:9443" {
		t.Errorf("self (core-3) entry's Addr = %q, want its real control_addr, not loopback", got[2].Addr)
	}
}

func TestNodesIncludingSelf_FallsBackWhenSelfUnresolvable(t *testing.T) {
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: "192.168.9.9:1"}}}
	got := nodesIncludingSelf(cfg)
	if len(got) != 1 || got[0].Name != "core-1" {
		t.Errorf("nodesIncludingSelf = %+v, want just the original worker-a entry unchanged", got)
	}
}

func TestNodesIncludingSelf_DropsStaleSameNamedEntryFromCfgNodes(t *testing.T) {
	local := newLocalConfigServer(t, "core-3", "192.168.0.27:9443")
	port := localPort(t, local)

	cfg := &WebConfig{Nodes: []NodeConfig{
		{Name: "core-1", Addr: "192.168.9.9:" + port},
		{Name: "core-2", Addr: "192.168.9.10:" + port},
		{Name: "core-3", Addr: "192.168.0.24:9443"},
	}}

	got := nodesIncludingSelf(cfg)
	if len(got) != 3 {
		t.Fatalf("nodesIncludingSelf returned %d nodes, want exactly 3 (core-1, core-2, core-3 — no duplicate): %+v", len(got), got)
	}
	var core3Count int
	for _, n := range got {
		if n.Name == "core-3" {
			core3Count++
			if n.Addr != "192.168.0.27:9443" {
				t.Errorf("core-3 entry's Addr = %q, want self's real, live-resolved address (192.168.0.27:9443), not the stale cfg.Nodes leftover", n.Addr)
			}
		}
	}
	if core3Count != 1 {
		t.Errorf("core-3 appears %d times in nodesIncludingSelf, want exactly 1 (self must replace, not duplicate, the stale cfg.Nodes entry)", core3Count)
	}
}

func TestRoleIsMissing_FalseForSelfsOwnRoleEvenWhenAbsentFromNodes(t *testing.T) {
	local := newLocalConfigServer(t, "core-3", "192.168.0.22:9443")
	port := localPort(t, local)

	// cfg.Nodes lists only the two workers — exactly the real shape
	// when this handler runs FROM the arbiter's own -web instance.
	cfg := &WebConfig{Nodes: []NodeConfig{
		{Name: "core-1", Addr: "192.168.9.9:" + port},
		{Name: "core-2", Addr: "192.168.9.10:" + port},
	}}

	if roleIsMissing(cfg, "core-3") {
		t.Error("roleIsMissing(arbiter) = true, want false — arbiter is this instance's own role, genuinely occupied")
	}
	if !roleIsMissing(cfg, "worker-c-does-not-exist") {
		t.Error("roleIsMissing(a genuinely absent role) = false, want true")
	}
}

// TestPushProbeSelfDecommission_SuccessReturnsNoNote confirms a probe host
// that accepts the self-wipe (202/200) produces no operator-facing note.
func TestPushProbeSelfDecommission_SuccessReturnsNoNote(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	note := pushProbeSelfDecommission(NodeConfig{Name: "probe", Addr: u.Host, AdminToken: "tok-123"})
	if note != "" {
		t.Errorf("expected no note on a successful self-wipe, got %q", note)
	}
	if gotPath != "/api/v1/self-decommission" {
		t.Errorf("probe hit path %q, want /api/v1/self-decommission", gotPath)
	}
	if gotAuth != "Bearer tok-123" {
		t.Errorf("probe admin token not forwarded, got auth header %q", gotAuth)
	}
}

// TestPushProbeSelfDecommission_RejectionAndUnreachableReturnNotes
// confirms the two failure shapes both surface an actionable note rather
// than being swallowed.
func TestPushProbeSelfDecommission_RejectionAndUnreachableReturnNotes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"boom"}`)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	if note := pushProbeSelfDecommission(NodeConfig{Addr: u.Host}); !strings.Contains(note, "rejected") {
		t.Errorf("500 response should yield a 'rejected' note, got %q", note)
	}
	// An address nothing is listening on — connection refused.
	if note := pushProbeSelfDecommission(NodeConfig{Addr: "127.0.0.1:1"}); !strings.Contains(note, "did not confirm") {
		t.Errorf("unreachable probe should yield a 'did not confirm' note, got %q", note)
	}
}

func TestResolveProbeAddr_AlwaysForcesTheRealProbePort(t *testing.T) {
	cases := map[string]string{
		"192.168.0.42:80":   "192.168.0.42:9444",
		"192.168.0.42:9443": "192.168.0.42:9444",
		"192.168.0.42:9444": "192.168.0.42:9444",
	}
	for in, want := range cases {
		if got := resolveProbeAddr(in); got != want {
			t.Errorf("resolveProbeAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveAddrs_BareHostGetsConventionPort(t *testing.T) {
	if got := resolveProbeAddr("192.168.0.54"); got != "192.168.0.54:9444" {
		t.Errorf("resolveProbeAddr(bare host) = %q, want 192.168.0.54:9444", got)
	}
	if got := resolveReplacementControlAddr("192.168.0.52", "192.168.0.51:9443"); got != "192.168.0.52:9443" {
		t.Errorf("resolveReplacementControlAddr(bare host) = %q, want 192.168.0.52:9443", got)
	}
	if got := resolveReplacementControlAddr("192.168.0.52:80", "192.168.0.51:9443"); got != "192.168.0.52:9443" {
		t.Errorf("resolveReplacementControlAddr(bootstrap port) = %q, want 192.168.0.52:9443", got)
	}
	malformed := "fe80::1:80"
	if got := resolveProbeAddr(malformed); got != malformed {
		t.Errorf("resolveProbeAddr(malformed) = %q, want it unchanged", got)
	}
	if got := resolveReplacementControlAddr(malformed, "192.168.0.51:9443"); got != malformed {
		t.Errorf("resolveReplacementControlAddr(malformed) = %q, want it unchanged", got)
	}
}
