// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"dnshived/internal/cluster"
	"dnshived/internal/config"
	"dnshived/internal/identity"
)

func TestFindTokenByRole_ReturnsMatchingTokenOrError(t *testing.T) {
	cfg := &config.Cluster{APITokens: []config.APIToken{
		{Name: "a", Token: "admin-tok", Role: "admin"},
		{Name: "b", Token: "ro-tok", Role: "readonly"},
	}}
	tok, err := findTokenByRole(cfg, "admin")
	if err != nil || tok != "admin-tok" {
		t.Errorf("findTokenByRole(admin) = (%q, %v), want (admin-tok, nil)", tok, err)
	}
	if _, err := findTokenByRole(cfg, "probe"); err == nil {
		t.Error("expected an error for a role with no configured token, got nil")
	}
}

func TestLiveCoreNodes_IncludesSelfAndReachablePeersOnly(t *testing.T) {
	cfg := &config.Cluster{Role: "core-1", ControlAddr: "192.168.0.22:9443"}
	snapshot := []cluster.PeerState{
		{Addr: "192.168.0.23:9443", Reachable: true, Identity: &identity.Identity{Role: "core-2"}},
		{Addr: "192.168.0.24:9443", Reachable: false, Identity: &identity.Identity{Role: "core-3"}}, // unreachable — must be omitted
		{Addr: "192.168.0.99:9443", Reachable: true, Identity: nil},                                 // no identity handshake yet — must be omitted
	}

	got := liveCoreNodes(cfg, snapshot)
	if len(got) != 2 {
		t.Fatalf("liveCoreNodes = %v, want exactly 2 entries (self + the one reachable-with-identity peer)", got)
	}
	if got[0].Name != "core-1" || got[0].Addr != "192.168.0.22:9443" {
		t.Errorf("got[0] = %+v, want self (worker-a, 192.168.0.22:9443)", got[0])
	}
	if got[1].Name != "core-2" || got[1].Addr != "192.168.0.23:9443" {
		t.Errorf("got[1] = %+v, want worker-b, 192.168.0.23:9443", got[1])
	}
}

func TestAddProbeHandler_PushesRealProbeConfigWithBothTokens(t *testing.T) {
	origCfg := currentConfig.Load()
	t.Cleanup(func() { currentConfig.Store(origCfg) })
	currentConfig.Store(&config.Cluster{
		Role:        "core-1",
		ControlAddr: "192.168.0.22:9443",
		Platform:    &config.Platform{Workers: []string{"ens19", "ens20"}},
		APITokens: []config.APIToken{
			{Name: "bootstrap-admin", Token: "admin-tok", Role: "admin"},
			{Name: "bootstrap-probe", Token: "probe-tok", Role: "probe"},
			{Name: "bootstrap-probe-admin", Token: "probe-admin-tok", Role: "probe-admin"},
			{Name: "monitoring", Token: "ro-tok", Role: "readonly"},
		},
	})

	var gotCode string
	var gotConfig generatedProbeConfig
	ln, err := net.Listen("tcp", "127.0.0.1:9444")
	if err != nil {
		t.Skipf("port 9444 unavailable in this test environment: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Code   string          `json:"code"`
			Config json.RawMessage `json:"config"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		gotCode = req.Code
		json.Unmarshal(req.Config, &gotConfig)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	defer srv.Close()

	self := identity.Identity{Role: "core-1"}
	observer := cluster.NewObserver(self, "192.168.0.22:9443", nil, "")
	handler := addProbeHandler(observer)

	body, _ := json.Marshal(addProbeRequest{Addr: "127.0.0.1:80", OTP: "JOIN-CODE"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/probe", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if gotCode != "JOIN-CODE" {
		t.Errorf("pushed join code = %q, want JOIN-CODE", gotCode)
	}
	if gotConfig.TrunkParent != "ens19" {
		t.Errorf("TrunkParent = %q, want ens19 (Platform.Workers[0])", gotConfig.TrunkParent)
	}
	if len(gotConfig.TrunkParents) != 2 || gotConfig.TrunkParents[0] != "ens19" || gotConfig.TrunkParents[1] != "ens20" {
		t.Errorf("TrunkParents = %v, want [ens19 ens20] (the cluster's real Platform.Workers)", gotConfig.TrunkParents)
	}
	if gotConfig.ClusterToken != "probe-tok" {
		t.Errorf("ClusterToken = %q, want probe-tok", gotConfig.ClusterToken)
	}
	if len(gotConfig.ClusterNodes) != 1 || gotConfig.ClusterNodes[0].Name != "core-1" {
		t.Errorf("ClusterNodes = %v, want exactly self (worker-a) — no peers were configured in this test", gotConfig.ClusterNodes)
	}
	byRole := map[string]string{}
	for _, tok := range gotConfig.APITokens {
		byRole[tok.Role] = tok.Token
	}
	if byRole["admin"] != "probe-admin-tok" {
		t.Errorf("pushed admin-role token = %q, want the dedicated probe-admin-tok, NOT the real cluster admin token", byRole["admin"])
	}
	if byRole["admin"] == "admin-tok" {
		t.Error("pushed admin-role token equals the REAL cluster admin token — a compromised probe would yield full RequireAdmin power over every core node")
	}
	if byRole["readonly"] != "ro-tok" {
		t.Errorf("pushed readonly token = %q, want ro-tok — a live-adopted probe must get the same least-privilege token a wizard-adopted one does", byRole["readonly"])
	}
}

func TestAddProbeHandler_PopulatesVLANConstructionFields(t *testing.T) {
	origCfg := currentConfig.Load()
	t.Cleanup(func() { currentConfig.Store(origCfg) })
	currentConfig.Store(&config.Cluster{
		Role:        "core-1",
		ControlAddr: "192.168.0.22:9443",
		Platform:    &config.Platform{Workers: []string{"ens19"}},
		APITokens: []config.APIToken{
			{Name: "bootstrap-probe", Token: "probe-tok", Role: "probe"},
		},
	})

	var gotConfig generatedProbeConfig
	ln, err := net.Listen("tcp", "127.0.0.1:9444")
	if err != nil {
		t.Skipf("port 9444 unavailable in this test environment: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Config json.RawMessage `json:"config"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		json.Unmarshal(req.Config, &gotConfig)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	defer srv.Close()

	self := identity.Identity{Role: "core-1"}
	observer := cluster.NewObserver(self, "192.168.0.22:9443", nil, "")
	handler := addProbeHandler(observer)

	body, _ := json.Marshal(addProbeRequest{Addr: "127.0.0.1:80", OTP: "JOIN-CODE"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/probe", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if gotConfig.LocalOctet != 1 {
		t.Errorf("LocalOctet = %d, want 1 (derived from the test server's own loopback address 127.0.0.1)", gotConfig.LocalOctet)
	}
	if gotConfig.ProbeHelperSocket == "" {
		t.Error("ProbeHelperSocket is empty — without it, the adopted probe can't reach its own privileged helper to build VLAN interfaces at all")
	}
	if gotConfig.KnownVLANsPath == "" {
		t.Error("KnownVLANsPath is empty — required by the probe's own loadProbeConfig whenever LocalOctet is nonzero")
	}
}

// TestAddProbeHandler_RejectsMissingFields covers the request-validation
// path — a malformed/incomplete form submission must never even attempt
// a network push.
func TestAddProbeHandler_RejectsMissingFields(t *testing.T) {
	self := identity.Identity{Role: "core-1"}
	observer := cluster.NewObserver(self, "192.168.0.22:9443", nil, "")
	handler := addProbeHandler(observer)

	for _, req := range []addProbeRequest{
		{OTP: "x"},
		{Addr: "1.2.3.4:9444"},
	} {
		body, _ := json.Marshal(req)
		httpReq := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/probe", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		handler(rec, httpReq)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("req %+v: status = %d, want 400", req, rec.Code)
		}
	}
}

func TestAddProbeHandler_RejectsWhenNoWorkerTrunksConfigured(t *testing.T) {
	origCfg := currentConfig.Load()
	t.Cleanup(func() { currentConfig.Store(origCfg) })
	currentConfig.Store(&config.Cluster{Role: "core-1", ControlAddr: "192.168.0.22:9443"})

	self := identity.Identity{Role: "core-1"}
	observer := cluster.NewObserver(self, "192.168.0.22:9443", nil, "")
	handler := addProbeHandler(observer)

	body, _ := json.Marshal(addProbeRequest{Addr: "1.2.3.4:9444", OTP: "x"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/probe", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (no worker trunks configured to derive coverage from), body=%s", rec.Code, rec.Body.String())
	}
}

func TestThirdCoreRole_ReturnsTheRemainingRole(t *testing.T) {
	cases := []struct{ a, b, want string }{
		{config.RoleCore1, config.RoleCore2, config.RoleCore3},
		{config.RoleCore1, config.RoleCore3, config.RoleCore2},
		{config.RoleCore2, config.RoleCore3, config.RoleCore1},
		{config.RoleCore3, config.RoleCore1, config.RoleCore2},
	}
	for _, c := range cases {
		if got := thirdCoreRole(c.a, c.b); got != c.want {
			t.Errorf("thirdCoreRole(%q, %q) = %q, want %q", c.a, c.b, got, c.want)
		}
	}
}

func TestCorrectedWebConfigJSON_RebuildsNodesFromScratch(t *testing.T) {
	raw := []byte(`{
		"listen_addr": "0.0.0.0:8443",
		"users_file": "/etc/dnshived/webui-users.json",
		"templates_file": "/etc/dnshived/web-templates.json",
		"vip_host": "192.168.0.230",
		"nodes": [{"name": "core-1", "addr": "192.168.0.25:9443", "tls": true, "admin_token": "shared-tok"}],
		"coordinator": {"name": "coordinator", "addr": "192.168.0.230:9443", "tls": true, "admin_token": "shared-tok"}
	}`)

	out := correctedWebConfigJSON(raw, "core-2", "192.168.0.23:9443", "core-3", "192.168.0.22:9443", "fallback-tok-unused", true)

	var doc map[string]interface{}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}

	nodesRaw, _ := json.Marshal(doc["nodes"])
	var nodes []webConfigNode
	if err := json.Unmarshal(nodesRaw, &nodes); err != nil {
		t.Fatalf("nodes field is not a valid node list: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes = %+v, want exactly 2 entries", nodes)
	}
	byName := map[string]webConfigNode{}
	for _, n := range nodes {
		byName[n.Name] = n
	}
	if n, ok := byName["core-2"]; !ok || n.Addr != "192.168.0.23:9443" {
		t.Errorf("missing/wrong worker-b entry (the requesting survivor's own identity — this is the exact real bug): %+v", byName)
	}
	if n, ok := byName["core-3"]; !ok || n.Addr != "192.168.0.22:9443" {
		t.Errorf("missing/wrong arbiter entry (the third node): %+v", byName)
	}
	for _, n := range nodes {
		if n.AdminToken != "shared-tok" {
			t.Errorf("entry %q admin_token = %q, want the reused shared-tok", n.Name, n.AdminToken)
		}
		if !n.TLS {
			t.Errorf("entry %q TLS = false, want true", n.Name)
		}
	}
	if _, ok := byName["core-1"]; ok {
		t.Errorf("stale worker-a entry (the old, being-replaced role) survived into the corrected output: %+v", byName)
	}

	// Every other field must pass through untouched.
	if doc["vip_host"] != "192.168.0.230" {
		t.Errorf("vip_host = %v, want passed through unchanged", doc["vip_host"])
	}
	if doc["templates_file"] != "/etc/dnshived/web-templates.json" {
		t.Errorf("templates_file = %v, want passed through unchanged", doc["templates_file"])
	}
	coord, _ := doc["coordinator"].(map[string]interface{})
	if coord["addr"] != "192.168.0.230:9443" {
		t.Errorf("coordinator field was not passed through unchanged: %v", doc["coordinator"])
	}
}

func TestCorrectedWebConfigJSON_HonorsTLSEnabledFalse(t *testing.T) {
	raw := []byte(`{"nodes": [{"name": "core-1", "addr": "192.168.0.25:9443", "tls": true, "admin_token": "shared-tok"}]}`)

	out := correctedWebConfigJSON(raw, "core-2", "192.168.0.23:9443", "core-3", "192.168.0.22:9443", "fallback-tok-unused", false)

	var doc map[string]interface{}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	nodesRaw, _ := json.Marshal(doc["nodes"])
	var nodes []webConfigNode
	if err := json.Unmarshal(nodesRaw, &nodes); err != nil {
		t.Fatalf("nodes field is not a valid node list: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes = %+v, want exactly 2 entries", nodes)
	}
	for _, n := range nodes {
		if n.TLS {
			t.Errorf("entry %q TLS = true, want false (tlsEnabled=false was passed in) — the exact bug this test guards against", n.Name)
		}
	}
}

func TestCorrectedWebConfigJSON_EmptyThirdAddrOmitsThirdEntry(t *testing.T) {
	raw := []byte(`{"nodes": [], "vip_host": "192.168.0.230"}`)

	out := correctedWebConfigJSON(raw, "core-2", "192.168.0.23:9443", "core-3", "", "real-admin-tok", true)

	var doc map[string]interface{}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	nodesRaw, _ := json.Marshal(doc["nodes"])
	var nodes []webConfigNode
	if err := json.Unmarshal(nodesRaw, &nodes); err != nil {
		t.Fatalf("nodes field is not a valid node list: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("nodes = %+v, want exactly 1 entry (no bogus empty-Addr third entry)", nodes)
	}
	if nodes[0].Name != "core-2" || nodes[0].Addr != "192.168.0.23:9443" {
		t.Errorf("nodes[0] = %+v, want the requesting survivor's own identity", nodes[0])
	}
	if nodes[0].AdminToken != "real-admin-tok" {
		t.Errorf("nodes[0].AdminToken = %q, want the fallbackToken — this is the exact real bug: an empty raw nodes list has nothing to scan, so the authoritative fallback must be used instead of settling for empty", nodes[0].AdminToken)
	}
}

func TestCorrectedWebConfigJSON_FallbackTokenUsedWhenExistingNodesHaveNone(t *testing.T) {
	raw := []byte(`{"nodes": [{"name": "core-1", "addr": "192.168.0.23:9443", "tls": true, "admin_token": ""}]}`)

	out := correctedWebConfigJSON(raw, "core-2", "192.168.0.22:9443", "core-3", "192.168.0.43:9443", "real-admin-tok", true)

	var doc map[string]interface{}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	nodesRaw, _ := json.Marshal(doc["nodes"])
	var nodes []webConfigNode
	if err := json.Unmarshal(nodesRaw, &nodes); err != nil {
		t.Fatalf("nodes field is not a valid node list: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes = %+v, want exactly 2 entries", nodes)
	}
	for _, n := range nodes {
		if n.AdminToken != "real-admin-tok" {
			t.Errorf("entry %q AdminToken = %q, want the fallback %q — the exact bug confirmed live: a survivor whose own existing entries are all empty-token propagated that emptiness forward instead of using its real admin token", n.Name, n.AdminToken, "real-admin-tok")
		}
	}
}

func TestCorrectedWebConfigJSON_SetsSelfAdminTokenFromOlderFormatInput(t *testing.T) {
	raw := []byte(`{"nodes": [{"name": "core-1", "addr": "192.168.0.23:9443", "tls": true, "admin_token": "sniffed-tok"}]}`)

	out := correctedWebConfigJSON(raw, "core-2", "192.168.0.22:9443", "core-3", "192.168.0.43:9443", "fallback-tok", true)

	var doc map[string]interface{}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if got, _ := doc["self_admin_token"].(string); got != "sniffed-tok" {
		t.Errorf("self_admin_token = %q, want the same sniffed token %q the Nodes[] entries already got, set even though the input had no self_admin_token field at all", got, "sniffed-tok")
	}
}

func TestCorrectedWebConfigJSON_PreservesSelfAdminTokenAlreadyCorrect(t *testing.T) {
	raw := []byte(`{"self_admin_token": "real-tok", "nodes": [{"name": "core-1", "addr": "192.168.0.23:9443", "tls": true, "admin_token": "real-tok"}]}`)

	out := correctedWebConfigJSON(raw, "core-2", "192.168.0.22:9443", "core-3", "192.168.0.43:9443", "fallback-tok", true)

	var doc map[string]interface{}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if got, _ := doc["self_admin_token"].(string); got != "real-tok" {
		t.Errorf("self_admin_token = %q, want %q preserved", got, "real-tok")
	}
}

// TestCorrectedWebConfigJSON_EmptyOrUnparsableInputReturnsUnchanged covers
// the best-effort fallback paths.
func TestCorrectedWebConfigJSON_EmptyOrUnparsableInputReturnsUnchanged(t *testing.T) {
	if out := correctedWebConfigJSON(nil, "core-2", "a", "core-3", "b", "fallback", true); out != nil {
		t.Errorf("nil input: got %v, want nil unchanged", out)
	}
	bad := []byte("not json")
	if out := correctedWebConfigJSON(bad, "core-2", "a", "core-3", "b", "fallback", true); string(out) != string(bad) {
		t.Errorf("unparsable input: got %s, want unchanged %s", out, bad)
	}
	valid := []byte(`{"nodes":[]}`)
	if out := correctedWebConfigJSON(valid, "", "a", "core-3", "b", "fallback", true); string(out) != string(valid) {
		t.Errorf("empty survivorRole: got %s, want unchanged (nothing to correct with)", out)
	}
}
