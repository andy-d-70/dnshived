// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Test cases ported from cmd/dnshived-top/main_test.go — same logic,
// ANSI colors replaced with CSS classes.

func TestDaemonClass_ActiveIsOK(t *testing.T) {
	text, class := daemonClass(daemonStatus{LoadState: "loaded", ActiveState: "active", SubState: "running"})
	if class != "ok" {
		t.Errorf("class = %q, want ok for an active/running unit", class)
	}
	if text != "active/running" {
		t.Errorf("text = %q, want %q", text, "active/running")
	}
}

func TestDaemonClass_FailedIsCrit(t *testing.T) {
	_, class := daemonClass(daemonStatus{LoadState: "loaded", ActiveState: "failed", SubState: "failed"})
	if class != "crit" {
		t.Errorf("class = %q, want crit for a failed unit", class)
	}
}

func TestDaemonClass_LoadedButInactiveIsCrit(t *testing.T) {
	_, class := daemonClass(daemonStatus{LoadState: "loaded", ActiveState: "inactive", SubState: "dead"})
	if class != "crit" {
		t.Errorf("class = %q, want crit for a loaded-but-inactive unit", class)
	}
}

func TestDaemonClass_DnsmasqAggregateAllActiveIsOK(t *testing.T) {
	text, class := daemonClass(daemonStatus{Unit: "dnsmasq", ActiveCount: 20, TotalCount: 20})
	if text != "20/20 active" {
		t.Errorf("text = %q, want %q", text, "20/20 active")
	}
	if class != "ok" {
		t.Errorf("class = %q, want ok when every scope's dnsmasq unit is active", class)
	}
}

func TestDaemonClass_DnsmasqAggregatePartialIsCrit(t *testing.T) {
	text, class := daemonClass(daemonStatus{Unit: "dnsmasq", ActiveCount: 18, TotalCount: 20})
	if text != "18/20 active" {
		t.Errorf("text = %q, want %q", text, "18/20 active")
	}
	if class != "crit" {
		t.Errorf("class = %q, want crit when fewer than all scopes' dnsmasq units are active", class)
	}
}

func TestDaemonClass_NotFoundIsDimNotCrit(t *testing.T) {
	text, class := daemonClass(daemonStatus{LoadState: "not-found", ActiveState: "inactive", SubState: "dead"})
	if class != "dim" {
		t.Errorf("class = %q, want dim for a not-installed unit, not crit", class)
	}
	if text != "not installed" {
		t.Errorf("text = %q, want %q", text, "not installed")
	}
}

func TestDaemonClass_TransportErrorIsDim(t *testing.T) {
	_, class := daemonClass(daemonStatus{Error: "systemctl show: exit status 1"})
	if class != "dim" {
		t.Errorf("class = %q, want dim for a query error, not a confirmed state", class)
	}
}

func TestDaemonClass_ActivatingIsWarn(t *testing.T) {
	_, class := daemonClass(daemonStatus{LoadState: "loaded", ActiveState: "activating", SubState: "start"})
	if class != "warn" {
		t.Errorf("class = %q, want warn for a mid-transition unit", class)
	}
}

func TestDaemonClass_DhcpRelayAggregateAllActiveIsOK(t *testing.T) {
	text, class := daemonClass(daemonStatus{Unit: "dhcp-relay", ActiveCount: 3, TotalCount: 3})
	if text != "3/3 active" {
		t.Errorf("text = %q, want %q", text, "3/3 active")
	}
	if class != "ok" {
		t.Errorf("class = %q, want ok when every relayed VLAN is active", class)
	}
}

func TestDaemonClass_DhcpRelayZeroEligibleIsDimNotCrit(t *testing.T) {
	text, class := daemonClass(daemonStatus{Unit: "dhcp-relay", LoadState: "loaded", ActiveState: "inactive", TotalCount: 0})
	if class != "dim" {
		t.Errorf("class = %q, want dim when zero scopes are relay-eligible, not crit", class)
	}
	if text != "no scope eligible yet" {
		t.Errorf("text = %q, want %q", text, "no scope eligible yet")
	}
}

func TestDaemonClass_RealRelayUnitZeroEligibleIsDimNotCrit(t *testing.T) {
	text, class := daemonClass(daemonStatus{Unit: "dnshived-relay.service", LoadState: "loaded", ActiveState: "inactive", TotalCount: 0})
	if class != "dim" {
		t.Errorf("class = %q, want dim when zero scopes are relay-eligible, not crit", class)
	}
	if text != "no scope eligible yet" {
		t.Errorf("text = %q, want %q", text, "no scope eligible yet")
	}
}

func TestDaemonClass_RealRelayUnitActiveStaysOKEvenWithZeroEligible(t *testing.T) {
	text, class := daemonClass(daemonStatus{Unit: "dnshived-relay.service", LoadState: "loaded", ActiveState: "active", TotalCount: 0})
	if class != "ok" {
		t.Errorf("class = %q, want ok for a genuinely active unit regardless of TotalCount", class)
	}
	if text != "active" {
		t.Errorf("text = %q, want %q", text, "active")
	}
}

func TestDaemonClass_RealRelayUnitActiveWithNonzeroEligibleStaysOK(t *testing.T) {
	text, class := daemonClass(daemonStatus{Unit: "dnshived-relay.service", LoadState: "loaded", ActiveState: "active", TotalCount: 1})
	if class != "ok" {
		t.Errorf("class = %q, want ok — a real unit's TotalCount is an eligibility signal, never an N/M display driver", class)
	}
	if text != "active" {
		t.Errorf("text = %q, want %q", text, "active")
	}
}

func TestIsRelayClientEntry(t *testing.T) {
	cases := map[string]bool{
		"dhcp-relay: central-test-1 (ens19.200)": true,
		"dhcp-relay: ens19.201":                  true,
		"dhcp-relay":                             false, // the aggregate row
		"dnshived-relay.service":                 false, // the real unit
	}
	for unit, want := range cases {
		if got := isRelayClientEntry(unit); got != want {
			t.Errorf("isRelayClientEntry(%q) = %v, want %v", unit, got, want)
		}
	}
}

func TestRunningAsText_InactiveIsDash(t *testing.T) {
	if got := runningAsText(0, ""); got != "—" {
		t.Errorf("runningAsText(0, \"\") = %q, want \"—\"", got)
	}
}

func TestRunningAsText_ResolvedUser(t *testing.T) {
	if got := runningAsText(1234, "dnshived"); got != "dnshived" {
		t.Errorf("runningAsText(1234, \"dnshived\") = %q, want \"dnshived\"", got)
	}
}

func TestRunningAsText_UnresolvedIsUnknown(t *testing.T) {
	if got := runningAsText(1234, ""); got != "unknown" {
		t.Errorf("runningAsText(1234, \"\") = %q, want \"unknown\" (live PID, unresolvable user)", got)
	}
}

func TestDaemonsTmpl_RendersPIDAndRunningAs(t *testing.T) {
	data := daemonsPageData{
		Total: 2,
		Rows: []daemonRow{
			{Node: "core-1", Unit: "dnshived-dnsmasq@office.service", Text: "active", Class: "ok",
				PID: 12345, RunningAs: "dnshived"},
			{Node: "core-1", Unit: "dnshived-helper.service", Text: "active", Class: "ok",
				PID: 999, RunningAs: "root"},
		},
	}
	var buf strings.Builder
	if err := daemonsTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "12345") {
		t.Errorf("expected PID 12345 rendered, got: %s", out)
	}
	if !strings.Contains(out, ">dnshived<") {
		t.Errorf("expected running-as \"dnshived\" rendered, got: %s", out)
	}
	if !strings.Contains(out, `class="warn">root`) {
		t.Errorf("expected root-running unit flagged warn, got: %s", out)
	}
}

func TestDaemonsTmpl_LinksBackToClusterConfig(t *testing.T) {
	var buf strings.Builder
	if err := daemonsTmpl.Execute(&buf, daemonsPageData{}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(buf.String(), `href="/config"`) {
		t.Error("expected a link back to /config (the new Cluster Config parent tab)")
	}
}

func TestHandleDaemons_GroupsPerScopeDnsmasqUnderAggregate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"node_id":"n1","daemons":[
			{"unit":"dnshived.service","load_state":"loaded","active_state":"active","pid":100,"user":"root"},
			{"unit":"dnsmasq","load_state":"loaded","active_state":"active","active_count":2,"total_count":2},
			{"unit":"dnshived-dnsmasq@office.service","load_state":"loaded","active_state":"active","pid":201,"user":"dnshived"},
			{"unit":"dnshived-dnsmasq@rw-100.service","load_state":"loaded","active_state":"active","pid":202,"user":"dnshived"}
		]}`))
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest("GET", "/daemons", nil)
	rec := httptest.NewRecorder()

	handleDaemons(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Count(body, "<td>dnshived-dnsmasq@office.service</td>") != 1 {
		t.Errorf("expected dnshived-dnsmasq@office.service to appear as exactly one table cell (inside the expandable detail, not also as its own top-level row), got body: %s", body)
	}
	if !strings.Contains(body, "2 scope(s)") {
		t.Errorf("expected the expandable summary to say \"2 scope(s)\", got: %s", body)
	}
	if !strings.Contains(body, "201") || !strings.Contains(body, "202") {
		t.Errorf("expected both scopes' real PIDs (201, 202) in the expandable detail, got: %s", body)
	}
}

func TestFormatUptime_Seconds(t *testing.T) {
	if got := formatUptime(45); got != "45s" {
		t.Errorf("formatUptime(45) = %q, want %q", got, "45s")
	}
}

func TestFormatUptime_Minutes(t *testing.T) {
	if got := formatUptime(150); got != "2m" {
		t.Errorf("formatUptime(150) = %q, want %q", got, "2m")
	}
}

func TestFormatUptime_HoursAndMinutes(t *testing.T) {
	if got := formatUptime(2*3600 + 5*60); got != "2h 5m" {
		t.Errorf("formatUptime = %q, want %q", got, "2h 5m")
	}
}

func TestFormatUptime_DaysAndHours(t *testing.T) {
	if got := formatUptime(3*86400 + 4*3600); got != "3d 4h" {
		t.Errorf("formatUptime = %q, want %q", got, "3d 4h")
	}
}

func TestFormatUptime_ZeroOrNegativeIsDash(t *testing.T) {
	if got := formatUptime(0); got != "-" {
		t.Errorf("formatUptime(0) = %q, want %q", got, "-")
	}
	if got := formatUptime(-5); got != "-" {
		t.Errorf("formatUptime(-5) = %q, want %q", got, "-")
	}
}

func TestFormatCacheStats_UnavailableIsEmptyString(t *testing.T) {
	if got := formatCacheStats(dnsRelayStatsResult{Available: false}); got != "" {
		t.Errorf("formatCacheStats(unavailable) = %q, want empty string, not a fabricated 0%% line", got)
	}
}

func TestFormatCacheStats_NoCeilingConfigured(t *testing.T) {
	got := formatCacheStats(dnsRelayStatsResult{
		Available: true, Entries: 900, CacheSize: 5000, BytesUsed: 2202009, HitRatePct: 87.3,
	})
	want := "87.3% hit rate — 900/5000 entries, 2.1 MiB"
	if got != want {
		t.Errorf("formatCacheStats = %q, want %q", got, want)
	}
}

func TestFormatCacheStats_WithByteCeilingShowsBoth(t *testing.T) {
	got := formatCacheStats(dnsRelayStatsResult{
		Available: true, Entries: 900, CacheSize: 5000, CacheMaxBytes: 8388608, BytesUsed: 2202009, HitRatePct: 87.3,
	})
	want := "87.3% hit rate — 900/5000 entries, 2.1 MiB/8.0 MiB"
	if got != want {
		t.Errorf("formatCacheStats = %q, want %q", got, want)
	}
}

func TestFormatBytesIEC(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0 B"}, {512, "512 B"}, {1024, "1.0 KiB"},
		{1536, "1.5 KiB"}, {1048576, "1.0 MiB"}, {1073741824, "1.0 GiB"},
	}
	for _, c := range cases {
		if got := formatBytesIEC(c.in); got != c.want {
			t.Errorf("formatBytesIEC(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRestartLabel(t *testing.T) {
	cases := []struct {
		unit        string
		notFound    bool
		isProbeHost bool
		want        string
	}{
		{"dnshived.service", false, false, "Restart"},
		{"dnshived-keepalived.service", false, false, "Reload"},
		{"dnshived-keepalived-mgmt.service", false, false, "Restart"},
		{"dnshived-helper.service", false, false, "Restart"},
		{"dnshived-web.service", false, false, "Restart"},
		{"dnshived-relay.service", false, false, "Restart"},
		{"dnshived-dnsrelay.service", false, false, "Restart"},
		{"dnshived-relay.service", true, false, ""},    // not-found — e.g. never constructed yet
		{"dnshived-relay.service", false, true, ""},    // wrong kind of unit for a probe host
		{"dnshived-dnsrelay.service", false, true, ""}, // wrong kind of unit for a probe host
		{"dnshived-helper.service", false, true, ""},   // wrong kind of unit for a probe host
		{"dnsmasq", false, false, ""},                  // the aggregate row itself — no @, never restartable via this endpoint
		{"dnshived-dnsmasq@office.service", false, false, "Restart"},
		{"dnshived-dnsmasq@office.service", false, true, ""},  // probe hosts never run scope dnsmasq units
		{"dnshived-keepalived-mgmt.service", true, false, ""}, // not-found — e.g. arbiter, unit never even shipped there
		{"dnshived-probe.service", false, true, "Restart"},
		{"dnshived.service", false, true, ""}, // wrong kind of unit for a probe host
	}
	for _, tc := range cases {
		if got := restartLabel(tc.unit, tc.notFound, tc.isProbeHost); got != tc.want {
			t.Errorf("restartLabel(%q, notFound=%v, isProbeHost=%v) = %q, want %q",
				tc.unit, tc.notFound, tc.isProbeHost, got, tc.want)
		}
	}
}

func TestIsDnsmasqScopeUnit(t *testing.T) {
	cases := map[string]bool{
		"dnshived-dnsmasq@office.service":    true,
		"dnshived-dnsmasq@rw-100.service":    true,
		"dnsmasq":                            false, // the aggregate row
		"dnshived-dnsmasq@office":            false, // missing .service suffix
		"dnshived-keepalived.service":        false,
		"dnshived-dnsmasq@core-dns.service":  false,
		"dnshived-dnsmasq@core-dhcp.service": false, // same
	}
	for unit, want := range cases {
		if got := isDnsmasqScopeUnit(unit); got != want {
			t.Errorf("isDnsmasqScopeUnit(%q) = %v, want %v", unit, got, want)
		}
	}
}

// TestHandleDaemonRestartConfirm_RendersWarningForRestartableUnit confirms
// the GET confirm page.
func TestHandleDaemonRestartConfirm_RendersWarningForRestartableUnit(t *testing.T) {
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: "192.168.0.22:9443"}}}
	req := httptest.NewRequest("GET", "/daemons/core-1/dnshived.service/restart/confirm", nil)
	req.SetPathValue("node", "core-1")
	req.SetPathValue("unit", "dnshived.service")
	rec := httptest.NewRecorder()

	handleDaemonRestartConfirm(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "dnshived.service") || !strings.Contains(body, "core-1") {
		t.Error("expected the unit and node name in the confirmation page")
	}
	if !strings.Contains(body, `action="/daemons/core-1/dnshived.service/restart"`) {
		t.Error("expected the confirmation form to POST to the actual restart action path")
	}
}

func TestHandleDaemonRestartConfirm_NonRestartableUnitRejected(t *testing.T) {
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1"}}}
	req := httptest.NewRequest("GET", "/daemons/core-1/dnsmasq/restart/confirm", nil)
	req.SetPathValue("node", "core-1")
	req.SetPathValue("unit", "dnsmasq")
	rec := httptest.NewRecorder()

	handleDaemonRestartConfirm(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for a non-restartable unit", rec.Code)
	}
}

func TestHandleDaemonRestartConfirm_UnknownNode404s(t *testing.T) {
	cfg := &WebConfig{}
	req := httptest.NewRequest("GET", "/daemons/nonexistent/dnshived.service/restart/confirm", nil)
	req.SetPathValue("node", "nonexistent")
	req.SetPathValue("unit", "dnshived.service")
	rec := httptest.NewRecorder()

	handleDaemonRestartConfirm(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for an unknown node", rec.Code)
	}
}

func TestHandleDaemonRestart_TriggersRealCallAndRedirects(t *testing.T) {
	var gotMethod string
	var gotPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.Path)
		if r.URL.Path == "/api/v1/daemons/dnshived-keepalived.service/restart" {
			gotMethod = r.Method
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true,"throttled":false}`))
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest("POST", "/daemons/core-1/dnshived-keepalived.service/restart", nil)
	req.SetPathValue("node", "core-1")
	req.SetPathValue("unit", "dnshived-keepalived.service")
	rec := httptest.NewRecorder()

	handleDaemonRestart(newConfigRef(cfg))(rec, req)

	if gotMethod != http.MethodPost {
		t.Errorf("downstream received method %q for the restart path, want POST", gotMethod)
	}
	found := false
	for _, p := range gotPaths {
		if p == "/api/v1/daemons/dnshived-keepalived.service/restart" {
			found = true
		}
	}
	if !found {
		t.Errorf("downstream never received the restart path, got: %v", gotPaths)
	}
	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303 (redirect back to /daemons)", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/daemons" {
		t.Errorf("Location = %q, want /daemons", loc)
	}
}

func TestHandleDaemonRestart_ProbeHostUsesItsOwnEndpoint(t *testing.T) {
	var gotPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.Path)
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	cfg := &WebConfig{ProbeHosts: []NodeConfig{{Name: "probe-a", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest("POST", "/daemons/probe-a/dnshived-probe.service/restart", nil)
	req.SetPathValue("node", "probe-a")
	req.SetPathValue("unit", "dnshived-probe.service")
	rec := httptest.NewRecorder()

	handleDaemonRestart(newConfigRef(cfg))(rec, req)

	found := false
	for _, p := range gotPaths {
		if p == "/api/v1/restart" {
			found = true
		}
	}
	if !found {
		t.Errorf("downstream never received /api/v1/restart, got: %v", gotPaths)
	}
	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", rec.Code)
	}
}

func TestFindNode_FallsBackToSelfWhenNameMatchesNeitherList(t *testing.T) {
	local := newLocalConfigServer(t, "core-3", "192.168.0.22:9443")
	port := localPort(t, local)
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: "192.168.9.9:" + port}}}

	node, isProbeHost, ok := findNode(cfg, "core-3")
	if !ok {
		t.Fatal("findNode(\"arbiter\") ok = false, want true (self-fallback)")
	}
	if isProbeHost {
		t.Error("expected self-resolved arbiter to never be treated as a probe host")
	}
	if node.Name != "core-3" || node.Addr != "192.168.0.22:9443" {
		t.Errorf("node = %+v, want the real self-probed arbiter identity", node)
	}
}

// TestFindNode_UnknownNameStillFails confirms the self-fallback doesn't
// turn every lookup into a match.
func TestFindNode_UnknownNameStillFails(t *testing.T) {
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: "127.0.0.1:1"}}}
	_, _, ok := findNode(cfg, "totally-unknown")
	if ok {
		t.Error("expected findNode to fail for a name matching nothing, including self")
	}
}

func TestDaemonClass_DNSRelayZeroScopes(t *testing.T) {
	if _, class := daemonClass(daemonStatus{Unit: "dnshived-dnsrelay.service", LoadState: "loaded", ActiveState: "inactive", TotalCount: 0}); class != "dim" {
		t.Errorf("idle dnsrelay with zero scopes: class = %q, want dim", class)
	}
	if _, class := daemonClass(daemonStatus{Unit: "dnshived-dnsrelay.service", LoadState: "loaded", ActiveState: "inactive", TotalCount: 2}); class != "crit" {
		t.Errorf("dead dnsrelay with scopes: class = %q, want crit", class)
	}
}
