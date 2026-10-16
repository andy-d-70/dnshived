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
	"reflect"
	"strings"
	"testing"
	"time"

	"dnshived/internal/config"
)

// TestBuilderState_AddNodeRejectsSelfAddress guards against an operator
// accidentally re-adding this node's own address as if it were a different
// one.
func TestBuilderState_AddNodeRejectsSelfAddress(t *testing.T) {
	b := &builderState{}
	if err := b.setSelfAddr("192.168.0.22:9443"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := b.addNode("192.168.0.22:9443", config.RoleCore2, "CODE", ""); err == nil {
		t.Error("addNode with this node's own address returned nil error, want a rejection")
	}
}

// TestBuilderState_AddNodeRejectsDuplicateAddress covers a real mistake an
// operator could make.
func TestBuilderState_AddNodeRejectsDuplicateAddress(t *testing.T) {
	b := &builderState{}
	if err := b.addNode("192.168.0.23:9443", config.RoleCore2, "CODE1", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := b.addNode("192.168.0.23:9443", config.RoleCore3, "CODE2", ""); err == nil {
		t.Error("addNode with a duplicate address returned nil error, want a rejection")
	}
	if got := len(b.getNodes()); got != 1 {
		t.Errorf("getNodes() has %d entries, want 1 — the rejected duplicate must not have been added", got)
	}
}

// TestBuilderState_AddNodeRejectsDuplicateRole covers the other real
// mistake.
func TestBuilderState_AddNodeRejectsDuplicateRole(t *testing.T) {
	b := &builderState{}
	if err := b.addNode("192.168.0.23:9443", config.RoleCore2, "CODE1", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := b.addNode("192.168.0.24:9443", config.RoleCore2, "CODE2", ""); err == nil {
		t.Error("addNode with an already-claimed role returned nil error, want a rejection")
	}
}

func TestBuilderState_AddNodeRejectsSelfRole(t *testing.T) {
	b := &builderState{}
	if err := b.setRole(config.RoleCore1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := b.addNode("192.168.0.23:9443", config.RoleCore1, "CODE", ""); err == nil {
		t.Error("addNode claiming this node's own already-chosen role returned nil error, want a rejection")
	}
}

func TestAllNodes_IncludesSelfFirst(t *testing.T) {
	b := &builderState{}
	if err := b.setRole(config.RoleCore1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := b.setSelfAddr("192.168.0.22:9443"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := b.addNode("192.168.0.23:9443", config.RoleCore2, "CODE", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	nodes := b.allNodes()
	if len(nodes) != 2 {
		t.Fatalf("allNodes() has %d entries, want 2", len(nodes))
	}
	if !nodes[0].Self || nodes[0].Addr != "192.168.0.22:9443" {
		t.Errorf("nodes[0] = %+v, want self at 192.168.0.22:9443", nodes[0])
	}
}

// TestCoreRolesComplete_RequiresExactlyAllThree covers every incomplete
// combination, not just the empty case.
func TestCoreRolesComplete_RequiresExactlyAllThree(t *testing.T) {
	cases := []struct {
		name  string
		roles []string
		want  bool
	}{
		{"none", nil, false},
		{"one", []string{config.RoleCore1}, false},
		{"two", []string{config.RoleCore1, config.RoleCore2}, false},
		{"all three", []string{config.RoleCore1, config.RoleCore2, config.RoleCore3}, true},
		{"all three plus probe", []string{config.RoleCore1, config.RoleCore2, config.RoleCore3, "probe"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var nodes []clusterNode
			for _, r := range tc.roles {
				nodes = append(nodes, clusterNode{Role: r})
			}
			if got := coreRolesComplete(nodes); got != tc.want {
				t.Errorf("coreRolesComplete(%v) = %v, want %v", tc.roles, got, tc.want)
			}
		})
	}
}

// TestBuildClusterConfig_PassesRealValidation is the real correctness
// check for everything this wizard generates.
func TestBuildClusterConfig_PassesRealValidation(t *testing.T) {
	secrets, err := generateClusterSecrets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	nodes := []clusterNode{
		{Addr: "192.168.0.22:9443", Role: config.RoleCore1, Self: true},
		{Addr: "192.168.0.23:9443", Role: config.RoleCore2},
		{Addr: "192.168.0.24:9443", Role: config.RoleCore3},
	}

	cc, err := buildClusterConfig(secrets, nodes[0], nodes, mgmtSetup{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := cc.ValidateExtended()
	if !result.OK() {
		t.Errorf("generated config failed validation: %v", result.Errors)
	}
}

func TestBuildClusterConfig_ProbeAdminTokenHasDistinctRole(t *testing.T) {
	secrets, err := generateClusterSecrets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	nodes := []clusterNode{
		{Addr: "192.168.0.22:9443", Role: config.RoleCore1, Self: true},
		{Addr: "192.168.0.23:9443", Role: config.RoleCore2},
		{Addr: "192.168.0.24:9443", Role: config.RoleCore3},
	}

	cc, err := buildClusterConfig(secrets, nodes[0], nodes, mgmtSetup{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	byRole := map[string]string{}
	for _, tok := range cc.APITokens {
		if _, dup := byRole[tok.Role]; dup {
			t.Errorf("role %q appears more than once in APITokens", tok.Role)
		}
		byRole[tok.Role] = tok.Token
	}
	if byRole["admin"] != secrets.AdminToken {
		t.Errorf("admin-role token = %q, want %q", byRole["admin"], secrets.AdminToken)
	}
	probeAdmin, ok := byRole["probe-admin"]
	if !ok {
		t.Fatal("no probe-admin-role token in generated cluster.json")
	}
	if probeAdmin != secrets.ProbeAdminToken {
		t.Errorf("probe-admin-role token = %q, want %q", probeAdmin, secrets.ProbeAdminToken)
	}
	if probeAdmin == secrets.AdminToken {
		t.Error("probe-admin-role token equals the real admin token — must be a distinct value")
	}
}

// TestBuildClusterConfig_PeersExcludesSelf pins the actual peer-list
// derivation.
func TestBuildClusterConfig_PeersExcludesSelf(t *testing.T) {
	secrets, err := generateClusterSecrets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	nodes := []clusterNode{
		{Addr: "192.168.0.22:9443", Role: config.RoleCore1, Self: true},
		{Addr: "192.168.0.23:9443", Role: config.RoleCore2},
		{Addr: "192.168.0.24:9443", Role: config.RoleCore3},
	}

	cc, err := buildClusterConfig(secrets, nodes[0], nodes, mgmtSetup{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cc.Peers) != 2 {
		t.Fatalf("Peers = %v, want exactly 2 entries", cc.Peers)
	}
	for _, p := range cc.Peers {
		if p == "192.168.0.22:9443" {
			t.Error("Peers includes this node's own address — must never happen")
		}
	}
}

func TestBuildClusterConfig_PopulatesNodeIPSuffixesForEveryCoreNode(t *testing.T) {
	secrets, err := generateClusterSecrets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	nodes := []clusterNode{
		{Addr: "192.168.0.22:9443", Role: config.RoleCore1, Self: true},
		{Addr: "192.168.0.23:9443", Role: config.RoleCore2},
		{Addr: "192.168.0.24:9443", Role: config.RoleCore3},
		{Addr: "192.168.0.42:9443", Role: "probe"},
	}

	cc, err := buildClusterConfig(secrets, nodes[0], nodes, mgmtSetup{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cc.ScopeDefaults == nil {
		t.Fatal("ScopeDefaults is nil, want NodeIPSuffixes populated for every core node")
	}
	want := map[string]string{"core-1": "22", "core-2": "23", "core-3": "24"}
	if len(cc.ScopeDefaults.NodeIPSuffixes) != len(want) {
		t.Fatalf("NodeIPSuffixes = %v, want exactly %v (probe excluded — it never serves scopes)", cc.ScopeDefaults.NodeIPSuffixes, want)
	}
	for role, suffix := range want {
		if cc.ScopeDefaults.NodeIPSuffixes[role] != suffix {
			t.Errorf("NodeIPSuffixes[%q] = %q, want %q", role, cc.ScopeDefaults.NodeIPSuffixes[role], suffix)
		}
	}
	if result := cc.ValidateExtended(); !result.OK() {
		t.Errorf("auto-derived NodeIPSuffixes failed validation (should never collide — real, distinct addresses): %v", result.Errors)
	}
}

func TestBuildClusterConfig_SingleNodeStillPopulatesOwnSuffix(t *testing.T) {
	secrets, err := generateClusterSecrets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	self := clusterNode{Addr: "192.168.0.22:9443", Role: config.RoleCore1, Self: true}
	nodes := []clusterNode{self}

	cc, err := buildClusterConfig(secrets, self, nodes, mgmtSetup{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cc.ScopeDefaults == nil || cc.ScopeDefaults.NodeIPSuffixes["core-1"] != "22" {
		t.Fatalf("ScopeDefaults = %+v, want NodeIPSuffixes[core-1] = 22", cc.ScopeDefaults)
	}
}

func TestBuildClusterConfig_TrustedHostsIncludesAllThreeIncludingSelf(t *testing.T) {
	secrets, err := generateClusterSecrets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	nodes := []clusterNode{
		{Addr: "192.168.0.22:9443", Role: config.RoleCore1, Self: true},
		{Addr: "192.168.0.23:9443", Role: config.RoleCore2},
		{Addr: "192.168.0.24:9443", Role: config.RoleCore3},
	}

	cc, err := buildClusterConfig(secrets, nodes[0], nodes, mgmtSetup{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := map[string]bool{"192.168.0.22": true, "192.168.0.23": true, "192.168.0.24": true}
	if len(cc.TrustedHosts) != 3 {
		t.Fatalf("TrustedHosts = %v, want exactly 3 entries", cc.TrustedHosts)
	}
	for _, h := range cc.TrustedHosts {
		if !want[h] {
			t.Errorf("unexpected TrustedHosts entry %q", h)
		}
		delete(want, h)
	}
	if len(want) != 0 {
		t.Errorf("TrustedHosts missing entries: %v", want)
	}

	nodesWithProbe := append(append([]clusterNode{}, nodes...),
		clusterNode{Addr: "192.168.0.42:9443", Role: "probe"})
	ccWithProbe, err := buildClusterConfig(secrets, nodesWithProbe[0], nodesWithProbe, mgmtSetup{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, h := range ccWithProbe.TrustedHosts {
		if h == "192.168.0.42" {
			t.Error("TrustedHosts must not include a probe-role node's address")
		}
	}
}

func TestBuildClusterConfig_SharedSecretsIdenticalAcrossNodes(t *testing.T) {
	secrets, err := generateClusterSecrets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	nodes := []clusterNode{
		{Addr: "192.168.0.22:9443", Role: config.RoleCore1, Self: true},
		{Addr: "192.168.0.23:9443", Role: config.RoleCore2},
	}

	a, err := buildClusterConfig(secrets, nodes[0], nodes, mgmtSetup{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	b, err := buildClusterConfig(secrets, nodes[1], nodes, mgmtSetup{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if a.PSK != b.PSK {
		t.Errorf("PSK differs between nodes: %q vs %q", a.PSK, b.PSK)
	}
	if a.ClusterID != b.ClusterID {
		t.Errorf("ClusterID differs between nodes: %q vs %q", a.ClusterID, b.ClusterID)
	}
	if a.NodeID == b.NodeID {
		t.Error("NodeID is identical between two different nodes — must be unique per node")
	}
}

func TestBuildClusterConfig_ServesAndSeedsUpstream(t *testing.T) {
	secrets, err := generateClusterSecrets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	nodes := []clusterNode{{Addr: "192.168.0.22:9443", Role: config.RoleCore1, Self: true}}

	cc, err := buildClusterConfig(secrets, nodes[0], nodes, mgmtSetup{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cc.ScopeDefaults == nil || !reflect.DeepEqual(cc.ScopeDefaults.Upstream, []string{"1.1.1.1", "8.8.8.8"}) {
		t.Errorf("ScopeDefaults.Upstream = %+v, want [1.1.1.1 8.8.8.8]", cc.ScopeDefaults)
	}
	sd := cc.ScopeDefaults
	if sd.VIPSuffix != "254" || sd.GatewaySuffix != "1" || sd.DHCPStartSuffix != "200" || sd.DHCPEndSuffix != "250" {
		t.Errorf("scope address defaults = vip %q gw %q dhcp %q-%q, want 254 / 1 / 200-250", sd.VIPSuffix, sd.GatewaySuffix, sd.DHCPStartSuffix, sd.DHCPEndSuffix)
	}
	path := filepath.Join(t.TempDir(), "cluster.json")
	if err := config.Save(path, cc); err != nil {
		t.Fatalf("founded config does not validate: %v", err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "dry_run") {
		t.Error("founded config still writes dry_run")
	}
}

func TestGenerateClusterSecrets_PSKMeetsRecommendedLength(t *testing.T) {
	secrets, err := generateClusterSecrets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(secrets.PSK) < 64 {
		t.Errorf("PSK is %d characters, want at least 64", len(secrets.PSK))
	}
}

func TestBootstrapAdoptHandler_WrongCodeRejectedBeforeTouchingConfig(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "cluster.json")
	handler := bootstrapAdoptHandler("REAL-CODE", cfgPath)

	body, _ := json.Marshal(bootstrapAdoptRequest{Code: "WRONG-CODE", ClusterJSON: json.RawMessage(`{"role":"core-1"}`)})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/bootstrap/adopt", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if _, err := os.Stat(cfgPath); err == nil {
		t.Error("cluster.json was written despite a wrong code — must never happen")
	}
}

func TestBootstrapAdoptHandler_InvalidConfigRejectedNotWritten(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "cluster.json")
	handler := bootstrapAdoptHandler("REAL-CODE", cfgPath)

	// Missing cluster_id/node_id/control_addr -- real.validate() must reject this.
	body, _ := json.Marshal(bootstrapAdoptRequest{Code: "REAL-CODE", ClusterJSON: json.RawMessage(`{"role":"core-1"}`)})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/bootstrap/adopt", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if _, err := os.Stat(cfgPath); err == nil {
		t.Error("cluster.json was written despite failing validation — must never happen")
	}
}

func TestBootstrapAdoptHandler_ValidConfigWrittenExactly(t *testing.T) {
	origReExec := reExecFunc
	reExecCalled := make(chan struct{}, 1)
	reExecFunc = func() { reExecCalled <- struct{}{} }
	defer func() { reExecFunc = origReExec }()

	cfgPath := filepath.Join(t.TempDir(), "cluster.json")
	handler := bootstrapAdoptHandler("REAL-CODE", cfgPath)

	secrets, err := generateClusterSecrets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	nodes := []clusterNode{
		{Addr: "192.168.0.22:9443", Role: config.RoleCore1, Self: true},
		{Addr: "192.168.0.23:9443", Role: config.RoleCore2},
		{Addr: "192.168.0.24:9443", Role: config.RoleCore3},
	}
	cc, err := buildClusterConfig(secrets, nodes[1], nodes, mgmtSetup{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	raw, err := json.Marshal(cc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	body, _ := json.Marshal(bootstrapAdoptRequest{Code: "REAL-CODE", ClusterJSON: raw})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/bootstrap/adopt", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	onDisk, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("expected cluster.json to exist: %v", err)
	}
	if !bytes.Equal(onDisk, raw) {
		t.Errorf("on-disk content does not match the pushed payload exactly")
	}

	select {
	case <-reExecCalled:
	case <-time.After(time.Second):
		t.Error("reExecFunc was never called within 1s of a successful adopt — the scheduled restart is missing")
	}
}

// TestPushAdoptConfig_SendsCodeAndReceivesSuccess exercises the actual
// HTTP client against a real httptest.Server standing in for a remote
// node's adopt endpoint.
func TestPushAdoptConfig_SendsCodeAndReceivesSuccess(t *testing.T) {
	var gotCode string
	var gotBody []byte
	ln, err := net.Listen("tcp", "127.0.0.1:80")
	if err != nil {
		t.Skipf("port 80 unavailable in this test environment: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req bootstrapAdoptRequest
		json.NewDecoder(r.Body).Decode(&req)
		gotCode = req.Code
		gotBody = req.ClusterJSON
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	defer srv.Close()

	addr := "127.0.0.1:9443"
	payload := []byte(`{"role":"core-2"}`)
	if err := pushAdoptConfig(addr, "MY-CODE", adoptPayload{ClusterJSON: payload}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotCode != "MY-CODE" {
		t.Errorf("server received code %q, want MY-CODE", gotCode)
	}
	if !bytes.Equal(gotBody, payload) {
		t.Errorf("server received payload %s, want %s", gotBody, payload)
	}
}

func TestCoreBootstrapContactAddr_AlwaysForcesPort80(t *testing.T) {
	cases := map[string]string{
		"192.168.0.26:9443": "192.168.0.26:80",
		"192.168.0.26:80":   "192.168.0.26:80",
		"192.168.0.26":      "192.168.0.26:80",
	}
	for in, want := range cases {
		if got := coreBootstrapContactAddr(in); got != want {
			t.Errorf("coreBootstrapContactAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProbeAdoptTarget_AlwaysForcesTheProbeBootstrapPort(t *testing.T) {
	cases := map[string]string{
		"192.168.0.42:80":   "192.168.0.42:9444",
		"192.168.0.42:9443": "192.168.0.42:9444",
		"192.168.0.42:9444": "192.168.0.42:9444",
	}
	for in, want := range cases {
		got, err := probeAdoptTarget(in)
		if err != nil {
			t.Fatalf("probeAdoptTarget(%q) unexpected error: %v", in, err)
		}
		if got != want {
			t.Errorf("probeAdoptTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPushAdoptConfig_NonOKStatusReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "wrong join code", http.StatusUnauthorized)
	}))
	defer srv.Close()

	addr := srv.Listener.Addr().String()
	err := pushAdoptConfig(addr, "WRONG-CODE", adoptPayload{ClusterJSON: []byte(`{}`)})
	if err == nil {
		t.Fatal("expected an error for a 401 response, got nil")
	}
}

// TestBootstrapCommitHandler_RejectsZeroCoreNodes is the actual
// server-side enforcement of hasAtLeastOneCoreNode.
func TestBootstrapCommitHandler_RejectsZeroCoreNodes(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "cluster.json")
	state := &builderState{}
	if err := state.setRole("probe"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := state.setSelfAddr("192.168.0.22:9443"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No core-1/core-2/core-3 recorded at all.

	handler := bootstrapCommitHandler(cfgPath, state)
	req := httptest.NewRequest(http.MethodPost, "/setup/commit", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if _, err := os.Stat(cfgPath); err == nil {
		t.Error("cluster.json was written despite zero core nodes — must never happen")
	}
}

func TestBootstrapCommitHandler_SingleCoreNodeSucceeds(t *testing.T) {
	origReExec := reExecFunc
	reExecCalled := make(chan struct{}, 1)
	reExecFunc = func() { reExecCalled <- struct{}{} }
	defer func() { reExecFunc = origReExec }()

	cfgPath := filepath.Join(t.TempDir(), "cluster.json")
	state := &builderState{}
	if err := state.setRole(config.RoleCore1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := state.setSelfAddr("192.168.0.22:9443"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No other nodes recorded at all — the single-node-from-scratch case.

	handler := bootstrapCommitHandler(cfgPath, state)
	req := httptest.NewRequest(http.MethodPost, "/setup/commit", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "All nodes accepted") {
		t.Errorf("result page does not report full success: %s", body)
	}
	if !strings.Contains(body, "fewer than the usual 3 core nodes") {
		t.Errorf("result page missing the standalone note: %s", body)
	}

	onDisk, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("expected this node's own cluster.json to be written: %v", err)
	}
	var selfCC config.Cluster
	if err := json.Unmarshal(onDisk, &selfCC); err != nil {
		t.Fatalf("on-disk config is not valid JSON: %v", err)
	}
	if selfCC.Role != config.RoleCore1 {
		t.Errorf("self config role = %q, want core-1", selfCC.Role)
	}
	if len(selfCC.Peers) != 0 {
		t.Errorf("Peers = %v, want empty — no other nodes were recorded", selfCC.Peers)
	}
	if len(selfCC.TrustedHosts) != 1 || selfCC.TrustedHosts[0] != "192.168.0.22" {
		t.Errorf("TrustedHosts = %v, want exactly this node's own address", selfCC.TrustedHosts)
	}

	select {
	case <-reExecCalled:
	case <-time.After(time.Second):
		t.Error("reExecFunc was never called for self after a successful single-node commit")
	}
}

func TestBootstrapCommitHandler_FullSuccessWritesLocalAndPushesRemote(t *testing.T) {
	origReExec := reExecFunc
	reExecCalled := make(chan struct{}, 1)
	reExecFunc = func() { reExecCalled <- struct{}{} }
	defer func() { reExecFunc = origReExec }()

	var workerBGotCode string
	var workerBGotRole string
	workerBLn, err := net.Listen("tcp", "127.0.0.2:80")
	if err != nil {
		t.Skipf("port 80 unavailable in this test environment: %v", err)
	}
	workerB := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req bootstrapAdoptRequest
		json.NewDecoder(r.Body).Decode(&req)
		workerBGotCode = req.Code
		var cc config.Cluster
		json.Unmarshal(req.ClusterJSON, &cc)
		workerBGotRole = cc.Role
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	workerB.Listener.Close()
	workerB.Listener = workerBLn
	workerB.Start()
	defer workerB.Close()

	var arbiterGotCode string
	arbiterLn, err := net.Listen("tcp", "127.0.0.3:80")
	if err != nil {
		t.Skipf("port 80 unavailable in this test environment: %v", err)
	}
	arbiter := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req bootstrapAdoptRequest
		json.NewDecoder(r.Body).Decode(&req)
		arbiterGotCode = req.Code
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	arbiter.Listener.Close()
	arbiter.Listener = arbiterLn
	arbiter.Start()
	defer arbiter.Close()

	cfgPath := filepath.Join(t.TempDir(), "cluster.json")
	state := &builderState{}
	selfAddr := "192.168.0.22:9443"
	if err := state.setRole(config.RoleCore1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := state.setSelfAddr(selfAddr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := state.addNode("127.0.0.2:9443", config.RoleCore2, "WORKER-B-CODE", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := state.addNode("127.0.0.3:9443", config.RoleCore3, "ARBITER-CODE", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	handler := bootstrapCommitHandler(cfgPath, state)
	req := httptest.NewRequest(http.MethodPost, "/setup/commit", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "All nodes accepted") {
		t.Errorf("result page does not report full success: %s", body)
	}

	onDisk, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("expected this node's own cluster.json to be written: %v", err)
	}
	var selfCC config.Cluster
	if err := json.Unmarshal(onDisk, &selfCC); err != nil {
		t.Fatalf("on-disk config is not valid JSON: %v", err)
	}
	if selfCC.Role != config.RoleCore1 || selfCC.ControlAddr != selfAddr {
		t.Errorf("self config = role %q addr %q, want worker-a at %s", selfCC.Role, selfCC.ControlAddr, selfAddr)
	}

	if workerBGotCode != "WORKER-B-CODE" {
		t.Errorf("worker-b received code %q, want WORKER-B-CODE", workerBGotCode)
	}
	if workerBGotRole != config.RoleCore2 {
		t.Errorf("worker-b's pushed config has role %q, want worker-b", workerBGotRole)
	}
	if arbiterGotCode != "ARBITER-CODE" {
		t.Errorf("arbiter received code %q, want ARBITER-CODE", arbiterGotCode)
	}

	select {
	case <-reExecCalled:
	case <-time.After(time.Second):
		t.Error("reExecFunc was never called for self after a fully successful commit")
	}
}

func TestBootstrapCommitHandler_RemoteFailureReportedNotHidden(t *testing.T) {
	origReExec := reExecFunc
	reExecCalled := make(chan struct{}, 1)
	reExecFunc = func() { reExecCalled <- struct{}{} }
	defer func() { reExecFunc = origReExec }()

	workerB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "wrong join code", http.StatusUnauthorized)
	}))
	defer workerB.Close()

	arbiter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	defer arbiter.Close()

	cfgPath := filepath.Join(t.TempDir(), "cluster.json")
	state := &builderState{}
	if err := state.setRole(config.RoleCore1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := state.setSelfAddr("192.168.0.22:9443"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := state.addNode(workerB.Listener.Addr().String(), config.RoleCore2, "WRONG-CODE-ON-PURPOSE", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := state.addNode(arbiter.Listener.Addr().String(), config.RoleCore3, "ARBITER-CODE", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	handler := bootstrapCommitHandler(cfgPath, state)
	req := httptest.NewRequest(http.MethodPost, "/setup/commit", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "FAILED") {
		t.Errorf("result page does not report the worker-b failure: %s", body)
	}
	if strings.Contains(body, "All nodes accepted") {
		t.Errorf("result page falsely claims full success despite a real failure: %s", body)
	}
	if _, err := os.Stat(cfgPath); err != nil {
		t.Error("self's own config was not written despite self succeeding — one remote failure must not roll back an unrelated node's own success")
	}

	select {
	case <-reExecCalled:
	case <-time.After(time.Second):
		t.Error("reExecFunc was never called for self, even though self's own push succeeded independently of worker-b's failure")
	}
}

func TestBuildClusterConfig_MgmtOverridesOnlyForDifferingNames(t *testing.T) {
	secrets, err := generateClusterSecrets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	nodes := []clusterNode{
		{Addr: "192.168.0.51:9443", Role: config.RoleCore1, Self: true},
		{Addr: "192.168.0.52:9443", Role: config.RoleCore2, Mgmt: "ens18"},
		{Addr: "192.168.0.26:9443", Role: config.RoleCore3, Mgmt: "eth0"},
		{Addr: "192.168.0.54:9444", Role: "probe", Mgmt: "enp1s0"},
	}
	mgmt := mgmtSetup{PlatformMgmt: "ens18", PlatformWorkers: []string{"ens19"}}

	for _, self := range nodes[:3] {
		cc, err := buildClusterConfig(secrets, self, nodes, mgmt)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", self.Role, err)
		}
		want := map[string]string{config.RoleCore3: "eth0"}
		if !reflect.DeepEqual(cc.Platform.MgmtOverrides, want) {
			t.Errorf("%s: MgmtOverrides = %v, want %v", self.Role, cc.Platform.MgmtOverrides, want)
		}
		if got := cc.Platform.ResolveMgmt(config.RoleCore3); got != "eth0" {
			t.Errorf("%s: ResolveMgmt(core-3) = %q, want eth0", self.Role, got)
		}
		if !cc.ValidateExtended().OK() {
			t.Errorf("%s: generated config failed validation: %v", self.Role, cc.ValidateExtended().Errors)
		}
	}

	cc, err := buildClusterConfig(secrets, nodes[0], nodes[:2], mgmt)
	if err != nil {
		t.Fatal(err)
	}
	if cc.Platform.MgmtOverrides != nil {
		t.Errorf("MgmtOverrides = %v, want nil when every name matches", cc.Platform.MgmtOverrides)
	}
}
