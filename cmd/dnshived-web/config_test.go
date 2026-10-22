// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"dnshived/internal/config"
)

func fakeConfigServer(t *testing.T, c config.Cluster) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(c)
	}))
}

func TestParseClusterConfigForm_CoreAddressesRoundTrip(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(
		"core_dns_address=127.0.0.99&core_dhcp_address=127.0.0.98"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := r.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}

	payload, err := parseClusterConfigForm(r, nil)
	if err != nil {
		t.Fatalf("parseClusterConfigForm: %v", err)
	}
	if payload.CoreDNSAddress != "127.0.0.99" {
		t.Errorf("CoreDNSAddress = %q, want 127.0.0.99", payload.CoreDNSAddress)
	}
	if payload.CoreDHCPAddress != "127.0.0.98" {
		t.Errorf("CoreDHCPAddress = %q, want 127.0.0.98", payload.CoreDHCPAddress)
	}
}

func TestParseClusterConfigForm_MgmtVIPBlankVRRPIDDefaultsTo60(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(
		"mgmt_vip_vip=192.0.2.230%2F24&mgmt_vip_vrrp_id="))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := r.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}

	payload, err := parseClusterConfigForm(r, nil)
	if err != nil {
		t.Fatalf("parseClusterConfigForm: %v", err)
	}
	if payload.MgmtVIP == nil {
		t.Fatal("MgmtVIP is nil, want a real config with the default VRRPID")
	}
	if payload.MgmtVIP.VRRPID != 60 {
		t.Errorf("VRRPID = %d, want 60 (the same default bootstrapSetMgmtVIPHandler already uses)", payload.MgmtVIP.VRRPID)
	}
}

func TestParseClusterConfigForm_MgmtVIPExplicitVRRPIDIsPreserved(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(
		"mgmt_vip_vip=192.0.2.230%2F24&mgmt_vip_vrrp_id=77"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := r.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}

	payload, err := parseClusterConfigForm(r, nil)
	if err != nil {
		t.Fatalf("parseClusterConfigForm: %v", err)
	}
	if payload.MgmtVIP == nil || payload.MgmtVIP.VRRPID != 77 {
		t.Errorf("MgmtVIP = %+v, want VRRPID 77 preserved", payload.MgmtVIP)
	}
}

func TestParseClusterConfigForm_CoreDNSQueryLogging(t *testing.T) {
	on := httptest.NewRequest(http.MethodPost, "/config", strings.NewReader("core_dns_query_logging=1"))
	on.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := on.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}
	payload, err := parseClusterConfigForm(on, nil)
	if err != nil {
		t.Fatalf("parseClusterConfigForm: %v", err)
	}
	if !payload.CoreDNSQueryLogging {
		t.Error("expected CoreDNSQueryLogging=true when the checkbox is present")
	}

	off := httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(""))
	off.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := off.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}
	payload2, err := parseClusterConfigForm(off, nil)
	if err != nil {
		t.Fatalf("parseClusterConfigForm: %v", err)
	}
	if payload2.CoreDNSQueryLogging {
		t.Error("expected CoreDNSQueryLogging=false when the checkbox is absent")
	}
}

// TestParseClusterConfigForm_SanityCheckDisabled checks the sanity-check
// toggle uses the same checkbox convention as CoreDNSQueryLogging.
func TestParseClusterConfigForm_SanityCheckDisabled(t *testing.T) {
	on := httptest.NewRequest(http.MethodPost, "/config", strings.NewReader("sanity_check_disabled=1"))
	on.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := on.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}
	payload, err := parseClusterConfigForm(on, nil)
	if err != nil {
		t.Fatalf("parseClusterConfigForm: %v", err)
	}
	if !payload.SanityCheckDisabled {
		t.Error("expected SanityCheckDisabled=true when the checkbox is present")
	}

	off := httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(""))
	off.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := off.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}
	payload2, err := parseClusterConfigForm(off, nil)
	if err != nil {
		t.Fatalf("parseClusterConfigForm: %v", err)
	}
	if payload2.SanityCheckDisabled {
		t.Error("expected SanityCheckDisabled=false when the checkbox is absent")
	}
}

func TestParseClusterConfigForm_DNSRelayCacheRoundTrips(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(
		"dnsrelay_cache_size=12000&dnsrelay_cache_max_bytes=8388608"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := r.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}
	payload, err := parseClusterConfigForm(r, nil)
	if err != nil {
		t.Fatalf("parseClusterConfigForm: %v", err)
	}
	if payload.DNSRelayCacheSize != 12000 {
		t.Errorf("DNSRelayCacheSize = %d, want 12000", payload.DNSRelayCacheSize)
	}
	if payload.DNSRelayCacheMaxBytes != 8388608 {
		t.Errorf("DNSRelayCacheMaxBytes = %d, want 8388608", payload.DNSRelayCacheMaxBytes)
	}

	blank := httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(""))
	blank.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := blank.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}
	payload2, err := parseClusterConfigForm(blank, nil)
	if err != nil {
		t.Fatalf("parseClusterConfigForm: %v", err)
	}
	if payload2.DNSRelayCacheSize != 0 || payload2.DNSRelayCacheMaxBytes != 0 {
		t.Errorf("DNSRelayCacheSize/DNSRelayCacheMaxBytes = %d/%d, want 0/0 for a blank form (the \"don't manage\" sentinel)",
			payload2.DNSRelayCacheSize, payload2.DNSRelayCacheMaxBytes)
	}
}

func TestParseInterfaceLabels_ParsesValidPairsAndSkipsJunk(t *testing.T) {
	got := parseInterfaceLabels("ens19=Interface Office\nens20=Interface Dante Vlans\n\nnotapair\n=noiface\nens21=\n")
	want := map[string]string{"ens19": "Interface Office", "ens20": "Interface Dante Vlans"}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("got[%q] = %q, want %q", k, got[k], v)
		}
	}
}

func TestParseInterfaceLabels_EmptyInputReturnsNil(t *testing.T) {
	if got := parseInterfaceLabels(""); got != nil {
		t.Errorf("parseInterfaceLabels(\"\") = %+v, want nil", got)
	}
}

func TestHandleConfigExport_AllModeIncludesEverything(t *testing.T) {
	c := config.Cluster{
		ClusterID: "lab01",
		PSK:       "supersecretpsk",
		APITokens: []config.APIToken{{Name: "web-ui", Token: "tok123", Role: "admin"}},
		Scopes:    map[string]config.ScopeConfig{"office": {VLANID: 100, NodeIP: "172.16.100.22/24"}},
	}
	srv := fakeConfigServer(t, c)
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest("GET", "/config/export?mode=all", nil)
	rec := httptest.NewRecorder()
	handleConfigExport(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "supersecretpsk") {
		t.Error("expected all-mode export to include the PSK")
	}
	if !strings.Contains(body, "tok123") {
		t.Error("expected all-mode export to include api_tokens")
	}
	if !strings.Contains(body, "office") {
		t.Error("expected all-mode export to include scopes")
	}
}

func TestHandleConfigExport_ClusterModeExcludesScopes(t *testing.T) {
	c := config.Cluster{
		ClusterID: "lab01",
		PSK:       "supersecretpsk",
		Scopes:    map[string]config.ScopeConfig{"office": {VLANID: 100}},
	}
	srv := fakeConfigServer(t, c)
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest("GET", "/config/export?mode=cluster", nil)
	rec := httptest.NewRecorder()
	handleConfigExport(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "supersecretpsk") {
		t.Error("expected cluster-mode export to still include the PSK (identity/secrets stay)")
	}
	if strings.Contains(body, "\"scopes\"") {
		t.Errorf("expected cluster-mode export to omit scopes entirely, got: %s", body)
	}
}

func TestHandleConfigExport_ScopesModeExcludesSecrets(t *testing.T) {
	c := config.Cluster{
		ClusterID: "lab01",
		PSK:       "supersecretpsk",
		APITokens: []config.APIToken{{Name: "web-ui", Token: "tok123", Role: "admin"}},
		Peers:     []string{"192.0.2.23:9443"},
		Scopes:    map[string]config.ScopeConfig{"office": {VLANID: 100, NodeIP: "172.16.100.22/24"}},
	}
	srv := fakeConfigServer(t, c)
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest("GET", "/config/export?mode=scopes", nil)
	rec := httptest.NewRecorder()
	handleConfigExport(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "supersecretpsk") {
		t.Errorf("scopes-mode export leaked the PSK: %s", body)
	}
	if strings.Contains(body, "tok123") {
		t.Errorf("scopes-mode export leaked an api_token: %s", body)
	}
	if strings.Contains(body, "192.0.2.23:9443") {
		t.Errorf("scopes-mode export leaked peers: %s", body)
	}
	if !strings.Contains(body, "office") || !strings.Contains(body, "172.16.100.22/24") {
		t.Error("expected scopes-mode export to still include the actual scope definitions")
	}
	if !strings.Contains(body, "\"source_node\"") || !strings.Contains(body, "core-1") {
		t.Error("expected scopes-mode export to note which node's node_ip values it reflects")
	}
}

// TestHandleConfigExport_SetsDownloadHeaders confirms the response is
// actually offered as a file download, not rendered inline.
func TestHandleConfigExport_SetsDownloadHeaders(t *testing.T) {
	srv := fakeConfigServer(t, config.Cluster{ClusterID: "lab01"})
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest("GET", "/config/export?mode=all", nil)
	rec := httptest.NewRecorder()
	handleConfigExport(newConfigRef(cfg))(rec, req)

	cd := rec.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "attachment") || !strings.Contains(cd, "lab01") || !strings.Contains(cd, "all") {
		t.Errorf("Content-Disposition = %q, want an attachment filename mentioning lab01 and all", cd)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestHandleConfigExport_UnknownModeRejected(t *testing.T) {
	srv := fakeConfigServer(t, config.Cluster{ClusterID: "lab01"})
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest("GET", "/config/export?mode=bogus", nil)
	rec := httptest.NewRecorder()
	handleConfigExport(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for an unknown mode", rec.Code)
	}
}

func TestHandleConfigExport_DefaultModeIsAll(t *testing.T) {
	c := config.Cluster{ClusterID: "lab01", PSK: "supersecretpsk"}
	srv := fakeConfigServer(t, c)
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest("GET", "/config/export", nil)
	rec := httptest.NewRecorder()
	handleConfigExport(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "supersecretpsk") {
		t.Errorf("expected default mode to behave like mode=all, got status %d body %s", rec.Code, rec.Body.String())
	}
}

func TestAllProbeHostsParallel_AllEnabledIsTrue(t *testing.T) {
	rows := []probeParallelRow{
		{Reachable: true, Enabled: true},
		{Reachable: true, Enabled: true},
	}
	if !allProbeHostsParallel(rows) {
		t.Error("want true — every reachable host has it enabled")
	}
}

func TestAllProbeHostsParallel_MixedIsFalse(t *testing.T) {
	rows := []probeParallelRow{
		{Reachable: true, Enabled: true},
		{Reachable: true, Enabled: false},
	}
	if allProbeHostsParallel(rows) {
		t.Error("want false — one reachable host doesn't have it enabled")
	}
}

func TestAllProbeHostsParallel_UnreachableHostIgnored(t *testing.T) {
	rows := []probeParallelRow{
		{Reachable: true, Enabled: true},
		{Reachable: false},
	}
	if !allProbeHostsParallel(rows) {
		t.Error("want true — the unreachable host must not count against the reachable ones")
	}
}

func TestAllProbeHostsParallel_NothingReachableIsFalse(t *testing.T) {
	rows := []probeParallelRow{{Reachable: false}}
	if allProbeHostsParallel(rows) {
		t.Error("want false — no evidence any host has it enabled")
	}
}

func TestAllProbeHostsParallel_EmptyIsFalse(t *testing.T) {
	if allProbeHostsParallel(nil) {
		t.Error("want false for no probe hosts at all")
	}
}

func TestPushProbeHostParallelProbing_SendsCorrectRequest(t *testing.T) {
	var gotBody map[string]bool
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	defer srv.Close()

	node := NodeConfig{Name: "probe-42", Addr: strings.TrimPrefix(srv.URL, "http://"), AdminToken: "sekret"}
	if err := pushProbeHostParallelProbing(node, true); err != nil {
		t.Fatalf("pushProbeHostParallelProbing: %v", err)
	}
	if gotAuth != "Bearer sekret" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer sekret")
	}
	if gotBody == nil || !gotBody["parallel_probing"] {
		t.Errorf("request body = %v, want parallel_probing:true", gotBody)
	}
}

func TestPushProbeHostParallelProbing_NonOKStatusIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "no probe_helper_socket configured"})
	}))
	defer srv.Close()

	node := NodeConfig{Name: "probe-42", Addr: strings.TrimPrefix(srv.URL, "http://")}
	if err := pushProbeHostParallelProbing(node, true); err == nil {
		t.Error("want an error on a 500 response, got nil")
	}
}

func TestHandleProbeParallelPost_BroadcastsToEveryProbeHost(t *testing.T) {
	var gotBodies []map[string]bool
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]bool
		json.NewDecoder(r.Body).Decode(&b)
		mu.Lock()
		gotBodies = append(gotBodies, b)
		mu.Unlock()
		if r.URL.Path == "/api/v1/config" {
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")
	cfg := &WebConfig{ProbeHosts: []NodeConfig{
		{Name: "probe-a", Addr: addr},
		{Name: "probe-b", Addr: addr},
	}}

	form := strings.NewReader("probe_parallel_enabled=on")
	req := httptest.NewRequest("POST", "/config/probe-parallel", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleProbeParallelPost(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d (redirect)", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); loc != "/probes#settings" {
		t.Errorf("redirect target = %q, want /probes#settings (real regression, found live: this form moved to /probes but the redirect still pointed at the old page, making a successful save look like it silently did nothing)", loc)
	}

	mu.Lock()
	defer mu.Unlock()
	configCalls := 0
	for _, b := range gotBodies {
		if b != nil && b["parallel_probing"] {
			configCalls++
		}
	}
	if configCalls != 2 {
		t.Errorf("got %d config-write calls with parallel_probing:true, want 2 (one per probe host)", configCalls)
	}
}

func TestHandleProbeParallelPost_UncheckedDisablesEverywhere(t *testing.T) {
	var gotEnabled *bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/config" {
			var b map[string]bool
			json.NewDecoder(r.Body).Decode(&b)
			v := b["parallel_probing"]
			gotEnabled = &v
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cfg := &WebConfig{ProbeHosts: []NodeConfig{{Name: "probe-a", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest("POST", "/config/probe-parallel", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleProbeParallelPost(newConfigRef(cfg))(rec, req)

	if gotEnabled == nil {
		t.Fatal("probe host never received a config write")
	}
	if *gotEnabled {
		t.Error("parallel_probing = true, want false when the checkbox is unchecked (absent from form)")
	}
}

// TestProbesTmpl_ProbeParallelSectionRendersScopeCounts pins the Probe
// hosts table's own scope-count column, plain.
func TestProbesTmpl_ProbeParallelSectionRendersScopeCounts(t *testing.T) {
	data := probesPageData{
		ProbeHostNames: []string{"probe-big", "probe-small"},
		probeManagementData: probeManagementData{
			NodeProbeHosts: []NodeConfig{
				{Name: "probe-big", Addr: "192.0.2.42:9444"},
				{Name: "probe-small", Addr: "192.0.2.43:9444"},
			},
			ProbeParallelRows: []probeParallelRow{
				{Name: "probe-big", Addr: "192.0.2.42:9444", Reachable: true, Enabled: false, ScopeCount: 40},
				{Name: "probe-small", Addr: "192.0.2.43:9444", Reachable: true, Enabled: true, ScopeCount: 5},
			},
			ProbeHostDisplayNames: map[string]string{},
		},
	}
	var buf strings.Builder
	if err := probesTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "probe-big") || !strings.Contains(out, ">40<") {
		t.Errorf("expected probe-big's scope count (40) to render:\n%s", out)
	}
	if strings.Contains(out, "recommended") {
		t.Errorf("recommendation hint should be gone entirely:\n%s", out)
	}
}

func TestProbesTmpl_ProbeParallelWordingSingularForOneHost(t *testing.T) {
	one := probesPageData{
		ProbeHostNames: []string{"probe-42"},
		probeManagementData: probeManagementData{
			NodeProbeHosts:        []NodeConfig{{Name: "probe-42", Addr: "192.0.2.42:9444"}},
			ProbeParallelRows:     []probeParallelRow{{Name: "probe-42", Addr: "192.0.2.42:9444", Reachable: true, ScopeCount: 40}},
			ProbeHostDisplayNames: map[string]string{},
		},
	}
	var buf strings.Builder
	if err := probesTmpl.Execute(&buf, one); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `value="Apply"`) {
		t.Errorf("expected the singular \"Apply\" button with exactly one probe host, got:\n%s", out)
	}
	if strings.Contains(out, "Apply to all probe hosts") {
		t.Errorf("expected the plural \"Apply to all probe hosts\" wording to be gone with only one host, got:\n%s", out)
	}
	if !strings.Contains(out, "Enable parallel probing on this probe host") {
		t.Errorf("expected the singular checkbox label, got:\n%s", out)
	}

	two := probesPageData{
		ProbeHostNames: []string{"probe-a", "probe-b"},
		probeManagementData: probeManagementData{
			NodeProbeHosts: []NodeConfig{
				{Name: "probe-a", Addr: "192.0.2.42:9444"}, {Name: "probe-b", Addr: "192.0.2.43:9444"},
			},
			ProbeParallelRows: []probeParallelRow{
				{Name: "probe-a", Addr: "192.0.2.42:9444", Reachable: true, ScopeCount: 40},
				{Name: "probe-b", Addr: "192.0.2.43:9444", Reachable: true, ScopeCount: 5},
			},
			ProbeHostDisplayNames: map[string]string{},
		},
	}
	var buf2 strings.Builder
	if err := probesTmpl.Execute(&buf2, two); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out2 := buf2.String()
	if !strings.Contains(out2, "Apply to all probe hosts") {
		t.Errorf("expected the plural wording to stay with genuinely multiple probe hosts, got:\n%s", out2)
	}
}

func TestDeriveNodeIP_UsesThisNodesOwnLastOctet(t *testing.T) {
	got := deriveNodeIP("192.0.2.22:9443", "172.16.66.254/24")
	if got != "172.16.66.22/24" {
		t.Errorf("deriveNodeIP = %q, want 172.16.66.22/24", got)
	}
	got = deriveNodeIP("192.0.2.23:9443", "172.16.66.254/24")
	if got != "172.16.66.23/24" {
		t.Errorf("deriveNodeIP = %q, want 172.16.66.23/24", got)
	}
}

func TestDeriveNodeIP_InvalidInputsReturnEmpty(t *testing.T) {
	if got := deriveNodeIP("not-an-addr", "172.16.66.254/24"); got != "" {
		t.Errorf("deriveNodeIP with bad node addr = %q, want empty", got)
	}
	if got := deriveNodeIP("192.0.2.22:9443", "not-a-cidr"); got != "" {
		t.Errorf("deriveNodeIP with bad VIP = %q, want empty", got)
	}
}

func TestPayloadForNode_AlwaysDerivesAddressFallback(t *testing.T) {
	p := configPushPayload{Scopes: map[string]config.ScopeConfig{
		"new-scope":      {VIP: "172.16.66.254/24"},
		"existing-scope": {VIP: "172.16.67.254/24", NodeIP: "172.16.67.99/24"},
	}}
	out := payloadForNode(p, NodeConfig{Name: "core-1", Addr: "192.0.2.22:9443"})

	if got := out.Scopes["new-scope"].NodeIP; got != "172.16.66.22/24" {
		t.Errorf("new-scope NodeIP = %q, want derived 172.16.66.22/24", got)
	}
	if got := out.Scopes["existing-scope"].NodeIP; got != "172.16.67.22/24" {
		t.Errorf("existing-scope NodeIP = %q, want re-derived 172.16.67.22/24 (the stale 172.16.67.99/24 snapshot must not survive)", got)
	}
}

func TestPayloadForNode_ExplicitSuffixAlwaysWinsEvenOverExistingNodeIP(t *testing.T) {
	p := configPushPayload{
		Scopes: map[string]config.ScopeConfig{
			"test2": {VIP: "192.168.10.254/23", NodeIP: "192.168.10.22/23"}, // stale shared value from before suffixes existed
		},
		ScopeDefaults: &config.ScopeDefaults{NodeIPSuffixes: map[string]string{"core-1": "22", "core-2": "23"}},
	}
	a := payloadForNode(p, NodeConfig{Name: "core-1", Addr: "192.0.2.22:9443"})
	b := payloadForNode(p, NodeConfig{Name: "core-2", Addr: "192.0.2.23:9443"})
	if got := a.Scopes["test2"].NodeIP; got != "192.168.10.22/23" {
		t.Errorf("worker-a NodeIP = %q, want 192.168.10.22/23", got)
	}
	if got := b.Scopes["test2"].NodeIP; got != "192.168.10.23/23" {
		t.Errorf("worker-b NodeIP = %q, want the suffix-derived 192.168.10.23/23, NOT the stale shared 192.168.10.22/23", got)
	}
}

func TestPayloadForNode_ArbiterGetsDerivedNodeIPToo(t *testing.T) {
	p := configPushPayload{Scopes: map[string]config.ScopeConfig{
		"new-scope": {VIP: "172.16.66.254/24"},
	}}
	out := payloadForNode(p, NodeConfig{Name: "core-3", Addr: "192.0.2.24:9443"})
	if got := out.Scopes["new-scope"].NodeIP; got != "172.16.66.24/24" {
		t.Errorf("arbiter's derived NodeIP = %q, want 172.16.66.24/24 (address-derived fallback)", got)
	}
}

func TestPayloadForNode_DifferentNodesGetDifferentValues(t *testing.T) {
	p := configPushPayload{Scopes: map[string]config.ScopeConfig{
		"new-scope": {VIP: "172.16.66.254/24"},
	}}
	a := payloadForNode(p, NodeConfig{Name: "core-1", Addr: "192.0.2.22:9443"})
	b := payloadForNode(p, NodeConfig{Name: "core-2", Addr: "192.0.2.23:9443"})
	arb := payloadForNode(p, NodeConfig{Name: "core-3", Addr: "192.0.2.24:9443"})
	if a.Scopes["new-scope"].NodeIP == b.Scopes["new-scope"].NodeIP {
		t.Errorf("worker-a and worker-b got the SAME node_ip (%q) — duplicate-IP risk", a.Scopes["new-scope"].NodeIP)
	}
	if a.Scopes["new-scope"].NodeIP == arb.Scopes["new-scope"].NodeIP {
		t.Errorf("worker-a and arbiter got the SAME node_ip (%q) — this is the exact 2026-09-15 dual-VRRP-MASTER incident", a.Scopes["new-scope"].NodeIP)
	}
	if b.Scopes["new-scope"].NodeIP == arb.Scopes["new-scope"].NodeIP {
		t.Errorf("worker-b and arbiter got the SAME node_ip (%q) — duplicate-IP risk", b.Scopes["new-scope"].NodeIP)
	}
}

func TestPayloadForNode_ExplicitSuffixWinsOverDerived(t *testing.T) {
	p := configPushPayload{
		Scopes: map[string]config.ScopeConfig{
			"new-scope": {VIP: "172.16.66.254/24"},
		},
		ScopeDefaults: &config.ScopeDefaults{
			NodeIPSuffixes: map[string]string{"core-1": "99"},
		},
	}
	// worker-a's own real address would derive .22, but the explicit
	// suffix (99) must win.
	out := payloadForNode(p, NodeConfig{Name: "core-1", Addr: "192.0.2.22:9443"})
	if got := out.Scopes["new-scope"].NodeIP; got != "172.16.66.99/24" {
		t.Errorf("NodeIP = %q, want explicit suffix 172.16.66.99/24 (not the derived .22)", got)
	}
}

func TestPayloadForNode_FallsBackToDerivedWhenNoExplicitEntry(t *testing.T) {
	p := configPushPayload{
		Scopes:        map[string]config.ScopeConfig{"new-scope": {VIP: "172.16.66.254/24"}},
		ScopeDefaults: &config.ScopeDefaults{NodeIPSuffixes: map[string]string{"core-2": "99"}},
	}
	// worker-a has no entry in the map — must fall back to its own
	// address-derived value (.22), not go blank.
	out := payloadForNode(p, NodeConfig{Name: "core-1", Addr: "192.0.2.22:9443"})
	if got := out.Scopes["new-scope"].NodeIP; got != "172.16.66.22/24" {
		t.Errorf("NodeIP = %q, want derived fallback 172.16.66.22/24", got)
	}
}

func TestPayloadForNode_OverrideWinsOverExistingValue(t *testing.T) {
	p := configPushPayload{
		Scopes: map[string]config.ScopeConfig{
			"office": {
				VIP: "172.16.67.254/24", NodeIP: "172.16.67.99/24",
				NodeIPOverrides: map[string]string{"core-1": "172.16.67.5/24"},
			},
		},
	}
	out := payloadForNode(p, NodeConfig{Name: "core-1", Addr: "192.0.2.22:9443"})
	if got := out.Scopes["office"].NodeIP; got != "172.16.67.5/24" {
		t.Errorf("NodeIP = %q, want the explicit override 172.16.67.5/24", got)
	}
}

// TestPayloadForNode_OverrideOnlyAppliesToItsOwnWorker confirms an
// override for one worker never leaks onto a different worker's own
// resolution for the same scope.
func TestPayloadForNode_OverrideOnlyAppliesToItsOwnWorker(t *testing.T) {
	p := configPushPayload{
		Scopes: map[string]config.ScopeConfig{
			"office": {
				VIP: "172.16.67.254/24", NodeIP: "172.16.67.99/24",
				NodeIPOverrides: map[string]string{"core-1": "172.16.67.5/24"},
			},
		},
	}
	out := payloadForNode(p, NodeConfig{Name: "core-2", Addr: "192.0.2.23:9443"})
	if got := out.Scopes["office"].NodeIP; got != "172.16.67.23/24" {
		t.Errorf("worker-b NodeIP = %q, want its own derived 172.16.67.23/24 (override was worker-a's only; falling back to the stale 172.16.67.99/24 would risk colliding with a third node)", got)
	}
}

func TestCheckNodeIPCollisions_ExistingSharedValueNoLongerCollides(t *testing.T) {
	nodes := []NodeConfig{
		{Name: "core-1", Addr: "192.0.2.22:9443"},
		{Name: "core-2", Addr: "192.0.2.23:9443"},
		{Name: "core-3", Addr: "192.0.2.24:9443"},
	}
	payload := configPushPayload{
		Scopes: map[string]config.ScopeConfig{
			"office": {VIP: "172.16.67.254/24", NodeIP: "172.16.67.99/24"}, // stale single-node snapshot, no override
		},
	}
	if err := checkNodeIPCollisions(payload, nodes); err != nil {
		t.Errorf("an existing scope's stale shared NodeIP must not collide once every node correctly re-derives its own value, got: %v", err)
	}
}

func TestCheckNodeIPCollisions_CatchesSameExplicitSuffixOnTwoNodes(t *testing.T) {
	nodes := []NodeConfig{
		{Name: "core-1", Addr: "192.0.2.22:9443"},
		{Name: "core-2", Addr: "192.0.2.23:9443"},
	}
	payload := configPushPayload{
		Scopes: map[string]config.ScopeConfig{
			"office": {VIP: "172.16.67.254/24"},
		},
		ScopeDefaults: &config.ScopeDefaults{NodeIPSuffixes: map[string]string{"core-1": "50", "core-2": "50"}},
	}
	err := checkNodeIPCollisions(payload, nodes)
	if err == nil {
		t.Fatal("expected a collision error — both nodes explicitly mapped to the same suffix")
	}
	if !strings.Contains(err.Error(), "office") || !strings.Contains(err.Error(), "172.16.67.50/24") {
		t.Errorf("error %q missing expected scope/address detail", err.Error())
	}
}

// TestCheckNodeIPCollisions_AllowsDistinctPerWorkerOverrides confirms the
// legitimate, intended case (explicit distinct per-worker overrides) is
// never blocked.
func TestCheckNodeIPCollisions_AllowsDistinctPerWorkerOverrides(t *testing.T) {
	nodes := []NodeConfig{
		{Name: "core-1", Addr: "192.0.2.22:9443"},
		{Name: "core-2", Addr: "192.0.2.23:9443"},
	}
	payload := configPushPayload{
		Scopes: map[string]config.ScopeConfig{
			"office": {
				VIP: "172.16.67.254/24", NodeIP: "172.16.67.99/24",
				NodeIPOverrides: map[string]string{"core-1": "172.16.67.22/24", "core-2": "172.16.67.23/24"},
			},
		},
	}
	if err := checkNodeIPCollisions(payload, nodes); err != nil {
		t.Errorf("distinct per-worker overrides must not be refused, got: %v", err)
	}
}

func TestCheckNodeIPCollisions_AllowsExistingScopeWithClusterWideSuffixes(t *testing.T) {
	nodes := []NodeConfig{
		{Name: "core-1", Addr: "192.0.2.22:9443"},
		{Name: "core-2", Addr: "192.0.2.23:9443"},
	}
	payload := configPushPayload{
		Scopes: map[string]config.ScopeConfig{
			"test2": {VIP: "192.168.10.254/23", NodeIP: "192.168.10.22/23"},
		},
		ScopeDefaults: &config.ScopeDefaults{NodeIPSuffixes: map[string]string{"core-1": "22", "core-2": "23"}},
	}
	if err := checkNodeIPCollisions(payload, nodes); err != nil {
		t.Errorf("an old scope's stale shared NodeIP must not be refused once cluster-wide suffixes correctly differentiate it, got: %v", err)
	}
}

func TestCheckNodeIPCollisions_CatchesArbiterCollidingWithWorker(t *testing.T) {
	nodes := []NodeConfig{
		{Name: "core-1", Addr: "192.0.2.22:9443"},
		{Name: "core-2", Addr: "192.0.2.23:9443"},
		{Name: "core-3", Addr: "192.0.2.24:9443"},
	}
	payload := configPushPayload{
		Scopes: map[string]config.ScopeConfig{
			"test-66": {
				VIP: "172.17.66.254/24",
				NodeIPOverrides: map[string]string{
					"core-1": "172.17.66.22/24",
					"core-2": "172.17.66.23/24",
					"core-3": "172.17.66.22/24", // collides with worker-a's own override
				},
			},
		},
	}
	err := checkNodeIPCollisions(payload, nodes)
	if err == nil {
		t.Fatal("expected a collision error — arbiter's override collides with worker-a's own resolved value")
	}
	if !strings.Contains(err.Error(), "test-66") || !strings.Contains(err.Error(), "172.17.66.22/24") {
		t.Errorf("error %q missing expected scope/address detail", err.Error())
	}
}

func TestNodeIPFromVIPAndOctet_InvalidInputsReturnEmpty(t *testing.T) {
	if got := nodeIPFromVIPAndOctet("172.16.66.254/24", "not-a-number"); got != "" {
		t.Errorf("nodeIPFromVIPAndOctet with bad octet = %q, want empty", got)
	}
	if got := nodeIPFromVIPAndOctet("172.16.66.254/24", "256"); got != "" {
		t.Errorf("nodeIPFromVIPAndOctet with out-of-range octet = %q, want empty", got)
	}
	if got := nodeIPFromVIPAndOctet("not-a-vip", "22"); got != "" {
		t.Errorf("nodeIPFromVIPAndOctet with bad VIP = %q, want empty", got)
	}
}

func TestSecurityFormTmpl_TokenRoleSelectOffersAllFourRoles(t *testing.T) {
	data := clusterFormData{
		Tokens: []tokenFormRow{
			{Index: 0, APIToken: config.APIToken{Name: "probe-host-42", Role: "probe"}},
			{Index: 1, APIToken: config.APIToken{Name: "probe-admin-test", Role: "probe-admin"}},
		},
		TokenRowCount: 2,
	}
	var buf strings.Builder
	if err := securityFormTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	for _, want := range []string{`value="probe"`, `value="probe-admin"`} {
		if !strings.Contains(out, want) {
			t.Errorf("expected the role select to offer %s, got:\n%s", want, out)
		}
	}
	if !strings.Contains(out, `value="probe" selected`) {
		t.Errorf("expected probe-host-42's role select to show \"probe\" as selected, got:\n%s", out)
	}
	if !strings.Contains(out, `value="probe-admin" selected`) {
		t.Errorf("expected probe-admin-test's role select to show \"probe-admin\" as selected, got:\n%s", out)
	}
}

func TestBuildClusterFormData_NodeIPSuffixesSuggestFromMgmtAddress(t *testing.T) {
	c := config.Cluster{
		ScopeDefaults: &config.ScopeDefaults{
			NodeIPSuffixes: map[string]string{"core-2": "99"},
		},
	}
	nodes := []NodeConfig{
		{Name: "core-1", Addr: "192.0.2.22:9443"},
		{Name: "core-2", Addr: "192.0.2.23:9443"},
		{Name: "core-3", Addr: "192.0.2.24:9443"},
	}
	data := buildClusterFormData(c, NodeConfig{Name: "core-1"}, nodes)

	byName := map[string]string{}
	for _, row := range data.ScopeDefaultsNodeIPSuffixes {
		byName[row.Name] = row.Suffix
	}
	if byName["core-1"] != "22" {
		t.Errorf("worker-a suffix = %q, want suggested \"22\" (from its own mgmt address, no explicit entry set)", byName["core-1"])
	}
	if byName["core-2"] != "99" {
		t.Errorf("worker-b suffix = %q, want explicit \"99\" (must win over the derivable \"23\" suggestion)", byName["core-2"])
	}
	if byName["core-3"] != "24" {
		t.Errorf("arbiter suffix = %q, want suggested \"24\" (from its own mgmt address, no explicit entry set) — the arbiter must now get a row like any other node", byName["core-3"])
	}
}
