// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"dnshived/internal/config"
	"dnshived/internal/webauth"
)

func TestScopesTmpl_LinkUsesBareNameNotIoTTag(t *testing.T) {
	data := scopesPageData{
		Total: 1, Page: 1, TotalPages: 1,
		Rows: []scopeRow{
			{Name: "rw-129", Display: "rw-129 [IoT]", Worker: "core-1", Token: "dnshived1022", Status: "active", Class: "ok"},
		},
	}
	var buf bytes.Buffer
	if err := scopesTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("scopesTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `href="/scopes/rw-129"`) {
		t.Errorf("expected the link href to use the bare name, got: %s", out)
	}
	if !strings.Contains(out, ">rw-129 [IoT]</a>") {
		t.Errorf("expected the visible cell text to carry the [IoT] tag, got: %s", out)
	}
}

// TestScopesTmpl_TableWrappedForHorizontalScroll.
func TestScopesTmpl_TableWrappedForHorizontalScroll(t *testing.T) {
	data := scopesPageData{
		Total: 1, Page: 1, TotalPages: 1,
		Rows: []scopeRow{{Name: "rw-1", Display: "rw-1", Worker: "core-1", Token: "n1", Status: "active", Class: "ok"}},
	}
	var buf bytes.Buffer
	if err := scopesTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("scopesTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `<div class="table-wrap">`) {
		t.Errorf("expected the scopes table wrapped in .table-wrap, got: %s", out)
	}
}

func TestScopesTmpl_LinksToTopologyView(t *testing.T) {
	var buf bytes.Buffer
	if err := scopesTmpl.Execute(&buf, scopesPageData{}); err != nil {
		t.Fatalf("scopesTmpl.Execute failed: %v", err)
	}
	if !strings.Contains(buf.String(), `href="/topology"`) {
		t.Error("expected a link to /topology (the new Topology view tab)")
	}
}

func TestScopeDetailTmpl_RendersDnsmasqLogLines(t *testing.T) {
	data := scopeDetailData{
		Scope:      "rw-100",
		TargetNode: "core-1",
		Check:      authorityCheck{Decision: "SERVE"},
		DnsmasqLog: []string{"line one", "line two", "line three"},
	}
	var buf bytes.Buffer
	if err := scopeDetailTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("scopeDetailTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"line one", "line two", "line three"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in rendered output, got: %s", want, out)
		}
	}
	if strings.Index(out, "line one") > strings.Index(out, "line three") {
		t.Error("expected lines to render in their original (oldest-first) order")
	}
}

func TestScopeDetailTmpl_EmptyDnsmasqLogShowsExplanationNotBlankSection(t *testing.T) {
	data := scopeDetailData{
		Scope:      "rw-100",
		TargetNode: "core-2",
		Check:      authorityCheck{Decision: "STANDBY"},
	}
	var buf bytes.Buffer
	if err := scopeDetailTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("scopeDetailTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "no per-scope log") {
		t.Errorf("expected an explanatory message for an empty log, got: %s", out)
	}
	if strings.Contains(out, "<pre>") {
		t.Error("expected no <pre> block rendered when there are no log lines")
	}
}

func TestScopeDetailTmpl_ProbeEnabledCheckbox_GatedOnHasProbeHost(t *testing.T) {
	base := scopeDetailData{
		Scope: "rw-100", TargetNode: "core-1", Check: authorityCheck{Decision: "SERVE"},
		ConfigOK: true, EditScope: config.ScopeConfig{ProbeDisabled: true},
	}

	without := base
	without.HasProbeHost = false
	var buf bytes.Buffer
	if err := scopeDetailTmpl.Execute(&buf, without); err != nil {
		t.Fatalf("scopeDetailTmpl.Execute failed: %v", err)
	}
	if strings.Contains(buf.String(), `name="probe_enabled"`) {
		t.Error("expected no probe_enabled checkbox when HasProbeHost is false")
	}

	disabled := base
	disabled.HasProbeHost = true
	buf.Reset()
	if err := scopeDetailTmpl.Execute(&buf, disabled); err != nil {
		t.Fatalf("scopeDetailTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `name="probe_enabled"`) {
		t.Error("expected a probe_enabled checkbox when HasProbeHost is true")
	}
	if strings.Contains(out, `name="probe_enabled" checked`) {
		t.Errorf("expected the checkbox UNCHECKED for an opted-out (ProbeDisabled=true) scope, got: %s", out)
	}

	enabled := base
	enabled.HasProbeHost = true
	enabled.EditScope.ProbeDisabled = false
	buf.Reset()
	if err := scopeDetailTmpl.Execute(&buf, enabled); err != nil {
		t.Fatalf("scopeDetailTmpl.Execute failed: %v", err)
	}
	if !strings.Contains(buf.String(), `name="probe_enabled" checked`) {
		t.Errorf("expected the checkbox CHECKED for a currently-probed (ProbeDisabled=false) scope, got: %s", buf.String())
	}
}

// TestScopeSubnetCIDR pins the Scopes overview's Subnet column — the
// network address/prefix, not the VIP address itself.
func TestScopeSubnetCIDR(t *testing.T) {
	cases := map[string]string{
		"192.168.100.1/24":  "192.168.100.0/24",
		"172.16.100.130/25": "172.16.100.128/25",
		"":                  "",
		"not-an-ip":         "not-an-ip",
	}
	for in, want := range cases {
		if got := scopeSubnetCIDR(in); got != want {
			t.Errorf("scopeSubnetCIDR(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveDisplayedNodeIP_SuffixWinsOverStaleOnDiskValue(t *testing.T) {
	sc := config.ScopeConfig{VIP: "192.168.10.254/23", NodeIP: "192.168.10.22/23"}
	suffixes := map[string]string{"core-1": "22", "core-2": "23"}
	if got := resolveDisplayedNodeIP(sc, "core-1", "192.0.2.22:9443", suffixes, "192.168.10.22/23"); got != "192.168.10.22/23" {
		t.Errorf("worker-a = %q, want 192.168.10.22/23", got)
	}
	if got := resolveDisplayedNodeIP(sc, "core-2", "192.0.2.23:9443", suffixes, "192.168.10.22/23"); got != "192.168.10.23/23" {
		t.Errorf("worker-b = %q, want the suffix-derived 192.168.10.23/23, NOT the stale shared on-disk value", got)
	}
}

func TestResolveDisplayedNodeIP_PerScopeOverrideWinsOverSuffix(t *testing.T) {
	sc := config.ScopeConfig{
		VIP:             "192.168.10.254/23",
		NodeIPOverrides: map[string]string{"core-1": "192.168.10.5/23"},
	}
	suffixes := map[string]string{"core-1": "22"}
	if got := resolveDisplayedNodeIP(sc, "core-1", "192.0.2.22:9443", suffixes, ""); got != "192.168.10.5/23" {
		t.Errorf("got = %q, want the per-scope override 192.168.10.5/23", got)
	}
}

// TestResolveDisplayedNodeIP_FallsBackToOnDiskThenDerived covers a node
// with no configured suffix at all.
func TestResolveDisplayedNodeIP_FallsBackToOnDiskThenDerived(t *testing.T) {
	sc := config.ScopeConfig{VIP: "192.168.10.254/23"}
	if got := resolveDisplayedNodeIP(sc, "core-1", "192.0.2.22:9443", nil, "192.168.10.77/23"); got != "192.168.10.77/23" {
		t.Errorf("got = %q, want the preserved custom on-disk value 192.168.10.77/23", got)
	}
	if got := resolveDisplayedNodeIP(sc, "core-1", "192.0.2.22:9443", nil, ""); got != "192.168.10.22/23" {
		t.Errorf("got = %q, want the address-derived fallback 192.168.10.22/23", got)
	}
}

func TestPerNodeScopeNodeIPs_IncludesArbiter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				Scopes: map[string]config.ScopeConfig{
					"test-66": {VIP: "172.17.66.254/24", NodeIP: "172.17.66.43/24"},
				},
			})
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")
	nodes := []NodeConfig{
		{Name: "core-1", Addr: addr},
		{Name: "core-2", Addr: addr},
		{Name: "core-3", Addr: addr},
	}
	out := perNodeScopeNodeIPs(nodes, "test-66")
	if _, ok := out["core-3"]; !ok {
		t.Errorf("expected an \"arbiter\" entry, got %+v", out)
	}
	if out["core-3"] != "172.17.66.43/24" {
		t.Errorf("arbiter NodeIP = %q, want 172.17.66.43/24", out["core-3"])
	}
}

func TestBuildScopeRows_ShowsUnservedScopeWithHint(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", Serving: []string{"office"}}},
		{Node: NodeConfig{Name: "core-2"}, Status: nodeStatus{Role: "core-2"}},
	}
	configScopes := map[string]config.ScopeConfig{
		"office": {VIP: "192.168.100.1/24"},
		"test2":  {VIP: "192.168.10.254/23"}, // not in anyone's Serving list
	}
	got := buildScopeRows(rows, configScopes, nil, nil, nil, nil)
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2 (both configured scopes)", len(got))
	}
	var test2Row scopeRow
	for _, r := range got {
		if r.Name == "test2" {
			test2Row = r
		}
	}
	if test2Row.Name == "" {
		t.Fatal("test2 missing from rows entirely — an unserved scope must still be shown")
	}
	if test2Row.Status != "not served" || test2Row.Class != "dim" {
		t.Errorf("test2 Status/Class = %q/%q, want \"not served\"/\"dim\"", test2Row.Status, test2Row.Class)
	}
}

func TestBuildScopeRows_FlagsPendingDelete(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", Serving: []string{"office", "test2"}}},
	}
	configScopes := map[string]config.ScopeConfig{
		"office": {VIP: "192.168.100.1/24"},
		"test2":  {VIP: "192.168.10.254/24"},
	}
	got := buildScopeRows(rows, configScopes, nil, nil, nil, map[string]bool{"test2": true})
	var office, test2 scopeRow
	for _, r := range got {
		switch r.Name {
		case "office":
			office = r
		case "test2":
			test2 = r
		}
	}
	if test2.PendingDelete != true {
		t.Error("test2.PendingDelete = false, want true (it's in pendingDeletes)")
	}
	if test2.Status != "active" {
		t.Errorf("test2.Status = %q, want it to still show as normally served, not replaced", test2.Status)
	}
	if office.PendingDelete {
		t.Error("office.PendingDelete = true, want false (not in pendingDeletes)")
	}
}

// TestScopesTmpl_RendersPendingDeleteBadge confirms the actual rendered
// HTML carries the badge for a flagged row and not for a normal one.
func TestScopesTmpl_RendersPendingDeleteBadge(t *testing.T) {
	data := scopesPageData{
		Rows: []scopeRow{
			{Name: "gone-soon", Display: "gone-soon", PendingDelete: true, Class: "dim", Status: "active"},
			{Name: "staying", Display: "staying", Class: "dim", Status: "active"},
		},
		Total: 2, Page: 1, TotalPages: 1,
	}
	var buf bytes.Buffer
	if err := scopesTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	html := buf.String()
	if !strings.Contains(html, "marked for deletion") {
		t.Error("rendered page missing \"marked for deletion\" badge for the flagged scope")
	}
	// Confirm it's scoped to the right row, not printed unconditionally.
	stayingIdx := strings.Index(html, ">staying<")
	badgeIdx := strings.Index(html, "marked for deletion")
	if stayingIdx == -1 || badgeIdx == -1 || stayingIdx < badgeIdx {
		t.Errorf("badge doesn't appear to be scoped to gone-soon's own row (staying at %d, badge at %d)", stayingIdx, badgeIdx)
	}
}

func TestScopesTmpl_RendersInterfaceVLANSubnet(t *testing.T) {
	data := scopesPageData{
		Total: 1, Page: 1, TotalPages: 1,
		Rows: []scopeRow{
			{Name: "rw-100", Display: "rw-100", Worker: "core-1", Token: "dnshived1022", Status: "active", Class: "ok",
				Interface: "ens19.100", ParentInterface: "ens19", VLANID: 100, Subnet: "172.16.100.0/24"},
		},
	}
	var buf bytes.Buffer
	if err := scopesTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("scopesTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"ens19.100", "172.16.100.0/24"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in rendered output, got: %s", want, out)
		}
	}
	if !strings.Contains(out, "<td>100</td>") {
		t.Errorf("expected VLAN 100 rendered as its own cell, got: %s", out)
	}
	if !strings.Contains(out, `core-1's trunk NIC (ens19), VLAN-tagged for this scope`) {
		t.Errorf("expected the Interface cell's tooltip to describe the worker's trunk NIC, got: %s", out)
	}
	if !strings.Contains(out, "VLAN sub-interface this scope is actually constructed") {
		t.Errorf("expected an explanatory caption below the table, got: %s", out)
	}
}

func TestScopesTmpl_ProbeColumn_GatedOnHasProbeHosts(t *testing.T) {
	row := scopeRow{
		Name: "rw-100", Display: "rw-100", Worker: "core-1", Status: "active", Class: "ok",
		ProbeCells: []probeCellData{{Scope: "rw-100", Worker: "probe-42", DNSText: "DNS✔", DNSClass: "ok", DHCPText: "DHCP✔", DHCPClass: "ok"}},
	}

	without := scopesPageData{Total: 1, Page: 1, TotalPages: 1, Rows: []scopeRow{row}, HasProbeHosts: false}
	var buf bytes.Buffer
	if err := scopesTmpl.Execute(&buf, without); err != nil {
		t.Fatalf("scopesTmpl.Execute failed: %v", err)
	}
	if strings.Contains(buf.String(), "<th>Probe</th>") || strings.Contains(buf.String(), "DHCP✔") {
		t.Error("expected no Probe column at all when HasProbeHosts is false")
	}

	with := scopesPageData{Total: 1, Page: 1, TotalPages: 1, Rows: []scopeRow{row}, HasProbeHosts: true}
	buf.Reset()
	if err := scopesTmpl.Execute(&buf, with); err != nil {
		t.Fatalf("scopesTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "<th>Probe</th>") {
		t.Error("expected a Probe column header when HasProbeHosts is true")
	}
	if !strings.Contains(out, "DHCP✔") {
		t.Errorf("expected the probe cell's short DHCP status rendered, got: %s", out)
	}
}

func TestFetchDnsmasqLog_ParsesLinesFromRealServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/api/v1/dnsmasq-log/rw-100") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Write([]byte(`{"lines":["a","b","c"]}`))
	}))
	defer srv.Close()

	node := NodeConfig{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}
	lines, err := fetchDnsmasqLog(node, "rw-100", 20)
	if err != nil {
		t.Fatalf("fetchDnsmasqLog: %v", err)
	}
	if len(lines) != 3 || lines[0] != "a" || lines[2] != "c" {
		t.Errorf("lines = %v, want [a b c]", lines)
	}
}

func TestScopeDetailTmpl_RendersConfigAndPoolUsage(t *testing.T) {
	data := scopeDetailData{
		Scope: "rw-100", TargetNode: "core-1", Check: authorityCheck{Decision: "SERVE"},
		ConfigOK: true, VIP: "172.16.100.1/24", Gateway: "172.16.100.1",
		DHCPStart: "172.16.100.100", DHCPEnd: "172.16.100.200",
		PoolSize: 101, PoolUsed: 10, PoolUsagePct: 9,
	}
	var buf bytes.Buffer
	if err := scopeDetailTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("scopeDetailTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"172.16.100.1/24", "172.16.100.1", "172.16.100.100", "172.16.100.200", "10 / 101", "9%"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in rendered output, got: %s", want, out)
		}
	}
}

func TestScopeDetailTmpl_RendersColorPickerWithPresetsAndCurrentValue(t *testing.T) {
	data := scopeDetailData{
		Scope: "rw-100", TargetNode: "core-1", Check: authorityCheck{Decision: "SERVE"},
		ConfigOK: true, EditScope: config.ScopeConfig{Color: "#f58231"},
		ColorPalette: []string{"#f58231", "#911eb4"},
	}
	var buf bytes.Buffer
	if err := scopeDetailTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("scopeDetailTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `name="color" id="color_rw-100" value="#f58231"`) {
		t.Errorf("color picker should pre-fill the scope's existing color, got: %s", out)
	}
	if !strings.Contains(out, `background:#911eb4`) {
		t.Errorf("expected a preset swatch for #911eb4, got: %s", out)
	}
}

func TestScopeDetailTmpl_RendersDNSRecordsAndDHCPOptions(t *testing.T) {
	data := scopeDetailData{
		Scope: "rw-100", TargetNode: "core-1", Check: authorityCheck{Decision: "SERVE"},
		ConfigOK: true, DNSRecordsText: "A|printer.lan|172.16.100.60",
		DHCPOptionsText: "option:ntp-server,10.0.0.1",
	}
	var buf bytes.Buffer
	if err := scopeDetailTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("scopeDetailTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `name="dns_records"`) || !strings.Contains(out, "A|printer.lan|172.16.100.60") {
		t.Errorf("expected a pre-filled dns_records textarea, got: %s", out)
	}
	if !strings.Contains(out, `name="dhcp_options"`) || !strings.Contains(out, "option:ntp-server,10.0.0.1") {
		t.Errorf("expected a pre-filled dhcp_options textarea, got: %s", out)
	}
}

// TestScopeDetailTmpl_ConfigErrorShowsExplanation confirms a config fetch
// failure surfaces its reason rather than blank/zero fields.
func TestScopeDetailTmpl_ConfigErrorShowsExplanation(t *testing.T) {
	data := scopeDetailData{
		Scope: "rw-100", TargetNode: "core-1", Check: authorityCheck{Decision: "SERVE"},
		ConfigOK: false, ConfigError: "no node reachable, last error: dial tcp: connection refused",
	}
	var buf bytes.Buffer
	if err := scopeDetailTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("scopeDetailTmpl.Execute failed: %v", err)
	}
	if !strings.Contains(buf.String(), "connection refused") {
		t.Errorf("expected the config error reason in rendered output, got: %s", buf.String())
	}
}

func TestScopeDetailTmpl_RendersLeasesWithStaticStyling(t *testing.T) {
	data := scopeDetailData{
		Scope: "rw-100", TargetNode: "core-1", Check: authorityCheck{Decision: "SERVE"},
		Leases: []leaseRow{
			{MAC: "aa:bb:cc:dd:ee:ff", IP: "172.16.100.150", Hostname: "myhost", Expiry: "2026-08-10 12:00:00"},
			{MAC: "11:22:33:44:55:66", IP: "172.16.100.151", Hostname: "—", Expiry: "static", Static: true},
		},
	}
	var buf bytes.Buffer
	if err := scopeDetailTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("scopeDetailTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "aa:bb:cc:dd:ee:ff") || !strings.Contains(out, "myhost") {
		t.Errorf("expected the timed lease's details in rendered output, got: %s", out)
	}
	if !strings.Contains(out, `class="dim">static`) {
		t.Errorf("expected the static lease's expiry cell styled dim, got: %s", out)
	}
}

func TestScopeDetailTmpl_NoLeasesShowsExplanation(t *testing.T) {
	data := scopeDetailData{Scope: "rw-100", TargetNode: "core-1", Check: authorityCheck{Decision: "SERVE"}}
	var buf bytes.Buffer
	if err := scopeDetailTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("scopeDetailTmpl.Execute failed: %v", err)
	}
	if !strings.Contains(buf.String(), "no active leases") {
		t.Errorf("expected an explanation for zero leases, got: %s", buf.String())
	}
}

func TestFetchDnsmasqLeases_ParsesLeasesFromRealServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/api/v1/leases/rw-100") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Write([]byte(`{"leases":[{"mac":"aa:bb:cc:dd:ee:ff","ip":"172.16.100.150","hostname":"myhost","expiry":"2026-08-10T12:00:00Z"}]}`))
	}))
	defer srv.Close()

	node := NodeConfig{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}
	leases, err := fetchDnsmasqLeases(node, "rw-100")
	if err != nil {
		t.Fatalf("fetchDnsmasqLeases: %v", err)
	}
	if len(leases) != 1 || leases[0].MAC != "aa:bb:cc:dd:ee:ff" || leases[0].Hostname != "myhost" {
		t.Errorf("leases = %+v, want one lease for aa:bb:cc:dd:ee:ff/myhost", leases)
	}
}

// TestPromoteLeaseFormHandler_MissingFieldsRedirectsWithoutCalling
// confirms a form submission missing mac/ip never reaches the daemon at
// all.
func TestPromoteLeaseFormHandler_MissingFieldsRedirectsWithoutCalling(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	form := url.Values{"mac": {""}, "ip": {"172.16.100.150"}}
	req := httptest.NewRequest(http.MethodPost, "/scopes/rw-100/reservations", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("name", "rw-100")
	rec := httptest.NewRecorder()

	promoteLeaseFormHandler(newConfigRef(cfg))(rec, req)

	if called {
		t.Error("expected no call to the daemon when mac is missing")
	}
	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303 (redirect back to the scope page)", rec.Code)
	}
}

func TestPromoteLeaseFormHandler_SuccessStagesReservationInScopeConfig(t *testing.T) {
	var pushedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				Scopes: map[string]config.ScopeConfig{
					"rw-100": {VIP: "172.16.100.1/24", Gateway: "172.16.100.1", DHCPRange: [2]string{"172.16.100.100", "172.16.100.200"}},
					"rw-101": {VIP: "172.16.101.1/24", Gateway: "172.16.101.1", DHCPRange: [2]string{"172.16.101.100", "172.16.101.200"}},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/candidate":
			body, _ := io.ReadAll(r.Body)
			pushedBody = string(body)
			w.Write([]byte(`{"ok":true}`))
		case r.URL.Path == "/api/v1/audit":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://"), AdminToken: "tok"}}}
	form := url.Values{"mac": {"aa:bb:cc:dd:ee:ff"}, "ip": {"172.16.100.150"}, "hostname": {"myhost"}}
	req := httptest.NewRequest(http.MethodPost, "/scopes/rw-100/reservations", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("name", "rw-100")
	req = withAuthedUser(req, webauth.User{Name: "admin", Role: "admin"})
	rec := httptest.NewRecorder()

	promoteLeaseFormHandler(newConfigRef(cfg))(rec, req)

	var pushed configPushPayload
	if err := json.Unmarshal([]byte(pushedBody), &pushed); err != nil {
		t.Fatalf("unmarshal pushed payload: %v, body=%s", err, pushedBody)
	}
	rw100 := pushed.Scopes["rw-100"]
	if len(rw100.Reservations) != 1 || rw100.Reservations[0].MAC != "aa:bb:cc:dd:ee:ff" || rw100.Reservations[0].IP != "172.16.100.150" {
		t.Errorf("rw-100 reservations = %+v, want exactly the submitted one", rw100.Reservations)
	}
	if len(pushed.Scopes["rw-101"].Reservations) != 0 {
		t.Errorf("rw-101 was disturbed by an rw-100 reservation: %+v", pushed.Scopes["rw-101"])
	}
}

func TestPromoteLeaseFormHandler_UpdatesExistingReservationByMAC(t *testing.T) {
	var pushedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				Scopes: map[string]config.ScopeConfig{
					"rw-100": {
						VIP: "172.16.100.1/24", Gateway: "172.16.100.1", DHCPRange: [2]string{"172.16.100.100", "172.16.100.200"},
						Reservations: []config.Reservation{{MAC: "aa:bb:cc:dd:ee:ff", IP: "172.16.100.99", Hostname: "old"}},
					},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/candidate":
			body, _ := io.ReadAll(r.Body)
			pushedBody = string(body)
			w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	form := url.Values{"mac": {"aa:bb:cc:dd:ee:ff"}, "ip": {"172.16.100.150"}, "hostname": {"new"}}
	req := httptest.NewRequest(http.MethodPost, "/scopes/rw-100/reservations", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("name", "rw-100")
	rec := httptest.NewRecorder()

	promoteLeaseFormHandler(newConfigRef(cfg))(rec, req)

	var pushed configPushPayload
	if err := json.Unmarshal([]byte(pushedBody), &pushed); err != nil {
		t.Fatalf("unmarshal pushed payload: %v, body=%s", err, pushedBody)
	}
	res := pushed.Scopes["rw-100"].Reservations
	if len(res) != 1 {
		t.Fatalf("reservations = %+v, want exactly 1 (updated in place, not appended)", res)
	}
	if res[0].IP != "172.16.100.150" || res[0].Hostname != "new" {
		t.Errorf("res[0] = %+v, want the updated IP/hostname", res[0])
	}
}

// TestReleaseLeaseFormHandler_PostsToTheCurrentlyServingNode checks a
// lease release goes to the serving node.
func TestReleaseLeaseFormHandler_PostsToTheCurrentlyServingNode(t *testing.T) {
	var releaseCalled bool
	var gotMAC, gotIP string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v1/status"):
			w.Write([]byte(`{"role":"core-1","serving":["rw-100"]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/leases/rw-100/release":
			releaseCalled = true
			r.ParseForm()
			gotMAC = r.FormValue("mac")
			gotIP = r.FormValue("ip")
			w.Write([]byte(`{"released":true}`))
		default:
			w.Write([]byte("{}"))
		}
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	form := url.Values{"mac": {"aa:bb:cc:dd:ee:ff"}, "ip": {"172.16.100.150"}}
	req := httptest.NewRequest(http.MethodPost, "/scopes/rw-100/leases/release", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("name", "rw-100")
	rec := httptest.NewRecorder()

	releaseLeaseFormHandler(newConfigRef(cfg))(rec, req)

	if !releaseCalled {
		t.Fatal("expected a POST to /api/v1/leases/rw-100/release, got none")
	}
	if gotMAC != "aa:bb:cc:dd:ee:ff" || gotIP != "172.16.100.150" {
		t.Errorf("mac/ip = %q/%q, want aa:bb:cc:dd:ee:ff/172.16.100.150", gotMAC, gotIP)
	}
	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303 (redirect back to the scope page)", rec.Code)
	}
}

func TestReleaseLeaseFormHandler_MissingFieldsRedirectsWithoutCalling(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	form := url.Values{"mac": {""}, "ip": {"172.16.100.150"}}
	req := httptest.NewRequest(http.MethodPost, "/scopes/rw-100/leases/release", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("name", "rw-100")
	rec := httptest.NewRecorder()

	releaseLeaseFormHandler(newConfigRef(cfg))(rec, req)

	if called {
		t.Error("expected no call to the daemon when mac/ip is missing")
	}
	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303 (redirect back to the scope page)", rec.Code)
	}
}

func TestDeleteReservationFormHandler_RemovesOnlyMatchingMAC(t *testing.T) {
	var pushedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				Scopes: map[string]config.ScopeConfig{
					"rw-100": {
						VIP: "172.16.100.1/24", Gateway: "172.16.100.1", DHCPRange: [2]string{"172.16.100.100", "172.16.100.200"},
						Reservations: []config.Reservation{
							{MAC: "aa:bb:cc:dd:ee:ff", IP: "172.16.100.99"},
							{MAC: "11:22:33:44:55:66", IP: "172.16.100.98"},
						},
					},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/candidate":
			body, _ := io.ReadAll(r.Body)
			pushedBody = string(body)
			w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	form := url.Values{"mac": {"aa:bb:cc:dd:ee:ff"}}
	req := httptest.NewRequest(http.MethodPost, "/scopes/rw-100/reservations/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("name", "rw-100")
	rec := httptest.NewRecorder()

	deleteReservationFormHandler(newConfigRef(cfg))(rec, req)

	var pushed configPushPayload
	if err := json.Unmarshal([]byte(pushedBody), &pushed); err != nil {
		t.Fatalf("unmarshal pushed payload: %v, body=%s", err, pushedBody)
	}
	res := pushed.Scopes["rw-100"].Reservations
	if len(res) != 1 || res[0].MAC != "11:22:33:44:55:66" {
		t.Errorf("reservations after delete = %+v, want exactly the untouched other entry", res)
	}
}

func TestParseScopeEditForm_ParsesAllFields(t *testing.T) {
	form := url.Values{
		"parent": {"ens19"}, "vlan_id": {"100"}, "vip": {"172.16.100.1/24"},
		"node_ip": {"172.16.100.22/24"}, "dhcp_start": {"172.16.100.100"}, "dhcp_end": {"172.16.100.200"},
		"gateway": {"172.16.100.1"}, "vrrp_id": {"51"},
		"preferred_worker": {"core-2"}, "advert_int_ms": {"500"}, "vrrp_version": {"3"},
		"color": {"#f58231"}, "dns_records": {"A|printer.lan|172.16.100.60"},
		"dhcp_options": {"option:ntp-server,10.0.0.1"},
	}
	req := httptest.NewRequest(http.MethodPost, "/scopes/rw-100/config", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()

	sc, err := parseScopeEditForm(req)
	if err != nil {
		t.Fatalf("parseScopeEditForm: %v", err)
	}
	if sc.Parent != "ens19" || sc.VLANID != 100 || sc.VIP != "172.16.100.1/24" {
		t.Errorf("Parent/VLANID/VIP = %q/%d/%q", sc.Parent, sc.VLANID, sc.VIP)
	}
	if sc.DHCPRange[0] != "172.16.100.100" || sc.DHCPRange[1] != "172.16.100.200" {
		t.Errorf("DHCPRange = %v", sc.DHCPRange)
	}
	if sc.VRRPID != 51 || sc.PreferredWorker != "core-2" || sc.AdvertIntMS != 500 || sc.VRRPVersion != 3 {
		t.Errorf("VRRPID/PreferredWorker/AdvertIntMS/VRRPVersion = %d/%q/%d/%d", sc.VRRPID, sc.PreferredWorker, sc.AdvertIntMS, sc.VRRPVersion)
	}
	if sc.Color != "#f58231" {
		t.Errorf("Color = %q, want #f58231 (0.9.7: color selector moved to this edit page)", sc.Color)
	}
	if len(sc.DNSRecords) != 1 || sc.DNSRecords[0].Name != "printer.lan" {
		t.Errorf("DNSRecords = %+v, want one printer.lan record (0.9.7: dns_records finally editable here)", sc.DNSRecords)
	}
	if len(sc.DHCPOptions) != 1 || sc.DHCPOptions[0] != "option:ntp-server,10.0.0.1" {
		t.Errorf("DHCPOptions = %+v", sc.DHCPOptions)
	}
	if !sc.ProbeDisabled {
		t.Error("ProbeDisabled = false, want true (0.9.7: probing opt-out checkbox)")
	}
}

func TestParseScopeEditForm_ProbeEnabledOmittedMeansDisabled(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/scopes/rw-100/config", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()

	sc, err := parseScopeEditForm(req)
	if err != nil {
		t.Fatalf("parseScopeEditForm: %v", err)
	}
	if !sc.ProbeDisabled {
		t.Error("ProbeDisabled = false, want true when the probe_enabled checkbox field is absent")
	}
}

// TestParseScopeEditForm_ProbeEnabledChecked_MeansNotDisabled is the other
// half — a checked "enabled" box must produce ProbeDisabled=false.
func TestParseScopeEditForm_ProbeEnabledChecked_MeansNotDisabled(t *testing.T) {
	form := url.Values{"probe_enabled": {"on"}}
	req := httptest.NewRequest(http.MethodPost, "/scopes/rw-100/config", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()

	sc, err := parseScopeEditForm(req)
	if err != nil {
		t.Fatalf("parseScopeEditForm: %v", err)
	}
	if sc.ProbeDisabled {
		t.Error("ProbeDisabled = true, want false when probe_enabled=on")
	}
}

// TestParseScopeEditForm_MalformedDNSRecordsReturnsError pins the new
// error path.
func TestParseScopeEditForm_MalformedDNSRecordsReturnsError(t *testing.T) {
	form := url.Values{"dns_records": {"BOGUS|x|y"}}
	req := httptest.NewRequest(http.MethodPost, "/scopes/rw-100/config", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()

	if _, err := parseScopeEditForm(req); err == nil {
		t.Fatal("expected an error for a malformed dns_records line")
	}
}

func TestParseScopeEditForm_UnsetSentinelMeansNoColor(t *testing.T) {
	form := url.Values{"color": {scopeColorUnset}}
	req := httptest.NewRequest(http.MethodPost, "/scopes/rw-100/config", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()

	sc, err := parseScopeEditForm(req)
	if err != nil {
		t.Fatalf("parseScopeEditForm: %v", err)
	}
	if sc.Color != "" {
		t.Errorf("Color = %q, want empty for the untouched %s default", sc.Color, scopeColorUnset)
	}
}

func TestParseScopeEditForm_WhiteIsARealColorChoice(t *testing.T) {
	form := url.Values{"color": {"#ffffff"}}
	req := httptest.NewRequest(http.MethodPost, "/scopes/rw-100/config", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()

	sc, err := parseScopeEditForm(req)
	if err != nil {
		t.Fatalf("parseScopeEditForm: %v", err)
	}
	if sc.Color != "#ffffff" {
		t.Errorf("Color = %q, want #ffffff preserved as a real choice", sc.Color)
	}
}

func TestHandleScopeConfigPost_PreservesEverythingElse(t *testing.T) {
	var pushedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				PSK:      "secret-psk",
				LogLevel: "info",
				Scopes: map[string]config.ScopeConfig{
					"rw-100": {VIP: "172.16.100.1/24", Gateway: "172.16.100.1", DHCPRange: [2]string{"172.16.100.100", "172.16.100.200"}},
					"rw-101": {VIP: "172.16.101.1/24", Gateway: "172.16.101.1", DHCPRange: [2]string{"172.16.101.100", "172.16.101.200"}},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/candidate":
			body, _ := io.ReadAll(r.Body)
			pushedBody = string(body)
			w.Write([]byte(`{"ok":true}`))
		case r.URL.Path == "/api/v1/audit":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	form := url.Values{
		"parent": {""}, "vlan_id": {"100"}, "vip": {"172.16.100.1/24"}, "node_ip": {""},
		"dhcp_start": {"172.16.100.150"}, "dhcp_end": {"172.16.100.250"}, "gateway": {"172.16.100.1"},
		"vrrp_id": {"0"}, "preferred_worker": {"core-1"}, "advert_int_ms": {""}, "vrrp_version": {""},
	}
	req := httptest.NewRequest(http.MethodPost, "/scopes/rw-100/config", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("name", "rw-100")
	rec := httptest.NewRecorder()

	handleScopeConfigPost(newConfigRef(cfg))(rec, req)

	var pushed configPushPayload
	if err := json.Unmarshal([]byte(pushedBody), &pushed); err != nil {
		t.Fatalf("unmarshal pushed payload: %v, body=%s", err, pushedBody)
	}
	if pushed.PSK != "secret-psk" || pushed.LogLevel != "info" {
		t.Errorf("expected PSK/LogLevel preserved untouched, got PSK=%q LogLevel=%q", pushed.PSK, pushed.LogLevel)
	}
	if len(pushed.Scopes) != 2 {
		t.Fatalf("expected both scopes still present, got %d", len(pushed.Scopes))
	}
	if pushed.Scopes["rw-101"].VIP != "172.16.101.1/24" {
		t.Errorf("rw-101 was disturbed by an rw-100 edit: %+v", pushed.Scopes["rw-101"])
	}
	if pushed.Scopes["rw-100"].DHCPRange[0] != "172.16.100.150" {
		t.Errorf("expected rw-100's edit to actually apply, got %+v", pushed.Scopes["rw-100"])
	}
}

func TestHandleScopeConfigPost_AcceptsCore3NodeIPOverride(t *testing.T) {
	var (
		mu         sync.Mutex
		pushedBody string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				Scopes: map[string]config.ScopeConfig{
					"test-66": {VIP: "172.17.66.254/24", Gateway: "172.17.66.1", DHCPRange: [2]string{"172.17.66.200", "172.17.66.250"}},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/candidate":
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			pushedBody = string(body)
			mu.Unlock()
			w.Write([]byte(`{"ok":true}`))
		case r.URL.Path == "/api/v1/audit":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")
	cfg := &WebConfig{Nodes: []NodeConfig{
		{Name: "core-1", Addr: addr},
		{Name: "core-2", Addr: addr},
		{Name: "core-3", Addr: addr},
	}}
	form := url.Values{
		"parent": {""}, "vlan_id": {"2"}, "vip": {"172.17.66.254/24"}, "node_ip": {""},
		"dhcp_start": {"172.17.66.200"}, "dhcp_end": {"172.17.66.250"}, "gateway": {"172.17.66.1"},
		"vrrp_id": {"0"}, "preferred_worker": {"core-1"}, "advert_int_ms": {""}, "vrrp_version": {""},
		"node_ip_core-1": {"172.17.66.22/24"},
		"node_ip_core-2": {"172.17.66.23/24"},
		"node_ip_core-3": {"172.17.66.43/24"},
	}
	req := httptest.NewRequest(http.MethodPost, "/scopes/test-66/config", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("name", "test-66")
	rec := httptest.NewRecorder()

	handleScopeConfigPost(newConfigRef(cfg))(rec, req)

	mu.Lock()
	body := pushedBody
	mu.Unlock()
	var pushed configPushPayload
	if err := json.Unmarshal([]byte(body), &pushed); err != nil {
		t.Fatalf("unmarshal pushed payload: %v, body=%s", err, body)
	}
	overrides := pushed.Scopes["test-66"].NodeIPOverrides
	if overrides["core-3"] != "172.17.66.43/24" {
		t.Errorf("expected NodeIPOverrides[\"core-3\"] = 172.17.66.43/24, got %+v", overrides)
	}
	if overrides["core-1"] != "172.17.66.22/24" || overrides["core-2"] != "172.17.66.23/24" {
		t.Errorf("expected both workers' overrides preserved too, got %+v", overrides)
	}
}

func TestHandleScopeConfigPost_ResubmittedDNSRecordsRoundTripAndClusterWideFieldsPreserved(t *testing.T) {
	var pushedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				DefaultDNSChecks: []config.DNSCheck{{Name: "example.com.", Type: "A"}},
				GlobalDNSRecords: []config.DNSRecord{{Name: "fileserver.lan", Type: "A", Value: "10.0.0.50"}},
				ScopeDefaults:    &config.ScopeDefaults{GatewaySuffix: "1"},
				Scopes: map[string]config.ScopeConfig{
					"rw-100": {
						VIP: "172.16.100.1/24", Gateway: "172.16.100.1",
						DHCPRange:  [2]string{"172.16.100.100", "172.16.100.200"},
						DNSRecords: []config.DNSRecord{{Name: "printer.lan", Type: "A", Value: "172.16.100.60"}},
					},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/candidate":
			body, _ := io.ReadAll(r.Body)
			pushedBody = string(body)
			w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	form := url.Values{
		"parent": {""}, "vlan_id": {"100"}, "vip": {"172.16.100.1/24"}, "node_ip": {""},
		"dhcp_start": {"172.16.100.150"}, "dhcp_end": {"172.16.100.250"}, "gateway": {"172.16.100.1"},
		"vrrp_id": {"0"}, "preferred_worker": {"core-1"}, "advert_int_ms": {""}, "vrrp_version": {""},
		// A real browser resubmits the textarea's pre-filled current value.
		"dns_records": {"A|printer.lan|172.16.100.60"},
	}
	req := httptest.NewRequest(http.MethodPost, "/scopes/rw-100/config", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("name", "rw-100")
	rec := httptest.NewRecorder()

	handleScopeConfigPost(newConfigRef(cfg))(rec, req)

	var pushed configPushPayload
	if err := json.Unmarshal([]byte(pushedBody), &pushed); err != nil {
		t.Fatalf("unmarshal pushed payload: %v, body=%s", err, pushedBody)
	}
	if len(pushed.Scopes["rw-100"].DNSRecords) != 1 || pushed.Scopes["rw-100"].DNSRecords[0].Name != "printer.lan" {
		t.Errorf("rw-100's dns_records didn't round-trip: %+v", pushed.Scopes["rw-100"].DNSRecords)
	}
	if len(pushed.DefaultDNSChecks) != 1 || pushed.DefaultDNSChecks[0].Name != "example.com." {
		t.Errorf("DefaultDNSChecks not preserved: %+v", pushed.DefaultDNSChecks)
	}
	if len(pushed.GlobalDNSRecords) != 1 || pushed.GlobalDNSRecords[0].Name != "fileserver.lan" {
		t.Errorf("GlobalDNSRecords not preserved: %+v", pushed.GlobalDNSRecords)
	}
	if pushed.ScopeDefaults == nil || pushed.ScopeDefaults.GatewaySuffix != "1" {
		t.Errorf("ScopeDefaults not preserved: %+v", pushed.ScopeDefaults)
	}
}

// TestHandleScopeConfigPost_RenameSucceeds.
func TestHandleScopeConfigPost_RenameSucceeds(t *testing.T) {
	var pushedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				Scopes: map[string]config.ScopeConfig{
					"rw-100": {VIP: "172.16.100.1/24", Gateway: "172.16.100.1", DHCPRange: [2]string{"172.16.100.100", "172.16.100.200"}},
					"rw-101": {VIP: "172.16.101.1/24", Gateway: "172.16.101.1", DHCPRange: [2]string{"172.16.101.100", "172.16.101.200"}},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/candidate":
			body, _ := io.ReadAll(r.Body)
			pushedBody = string(body)
			w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	form := url.Values{
		"new_name": {"office"},
		"parent":   {""}, "vlan_id": {"100"}, "vip": {"172.16.100.1/24"}, "node_ip": {""},
		"dhcp_start": {"172.16.100.150"}, "dhcp_end": {"172.16.100.250"}, "gateway": {"172.16.100.1"},
		"vrrp_id": {"0"}, "preferred_worker": {"core-1"}, "advert_int_ms": {""}, "vrrp_version": {""},
	}
	req := httptest.NewRequest(http.MethodPost, "/scopes/rw-100/config", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("name", "rw-100")
	rec := httptest.NewRecorder()

	handleScopeConfigPost(newConfigRef(cfg))(rec, req)

	var pushed configPushPayload
	if err := json.Unmarshal([]byte(pushedBody), &pushed); err != nil {
		t.Fatalf("unmarshal pushed payload: %v, body=%s", err, pushedBody)
	}
	if _, stillThere := pushed.Scopes["rw-100"]; stillThere {
		t.Errorf("old key rw-100 should be gone after rename, got: %+v", pushed.Scopes)
	}
	if _, ok := pushed.Scopes["office"]; !ok {
		t.Fatalf("new key office missing after rename, got: %+v", pushed.Scopes)
	}
	if pushed.Scopes["office"].DHCPRange[0] != "172.16.100.150" {
		t.Errorf("renamed scope should carry the edited fields, got %+v", pushed.Scopes["office"])
	}
	if _, ok := pushed.Scopes["rw-101"]; !ok {
		t.Errorf("unrelated scope rw-101 should be untouched by the rename, got: %+v", pushed.Scopes)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "/scopes/office") {
		t.Errorf("expected the result page to link back to the NEW scope name, body=%s", rec.Body.String())
	}
}

// TestHandleScopeConfigPost_RenameRejectsDuplicateName confirms renaming
// onto an already-in-use scope name is refused before anything is pushed.
func TestHandleScopeConfigPost_RenameRejectsDuplicateName(t *testing.T) {
	var pushed bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				Scopes: map[string]config.ScopeConfig{
					"rw-100": {VIP: "172.16.100.1/24"},
					"rw-101": {VIP: "172.16.101.1/24"},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/candidate":
			pushed = true
			w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	form := url.Values{
		"new_name": {"rw-101"},
		"parent":   {""}, "vlan_id": {"100"}, "vip": {"172.16.100.1/24"}, "node_ip": {""},
		"dhcp_start": {"172.16.100.150"}, "dhcp_end": {"172.16.100.250"}, "gateway": {"172.16.100.1"},
		"vrrp_id": {"0"}, "preferred_worker": {"core-1"}, "advert_int_ms": {""}, "vrrp_version": {""},
	}
	req := httptest.NewRequest(http.MethodPost, "/scopes/rw-100/config", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("name", "rw-100")
	rec := httptest.NewRecorder()

	handleScopeConfigPost(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for a duplicate rename target, got %d", rec.Code)
	}
	if pushed {
		t.Error("must not push a candidate when the rename target already exists")
	}
}

func TestHandleScopeConfigPost_RenameRejectsInvalidCharacters(t *testing.T) {
	var pushed bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				Scopes: map[string]config.ScopeConfig{"rw-100": {VIP: "172.16.100.1/24"}},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/candidate":
			pushed = true
			w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	form := url.Values{
		"new_name": {"office suite"},
		"parent":   {""}, "vlan_id": {"100"}, "vip": {"172.16.100.1/24"}, "node_ip": {""},
		"dhcp_start": {"172.16.100.150"}, "dhcp_end": {"172.16.100.250"}, "gateway": {"172.16.100.1"},
		"vrrp_id": {"0"}, "preferred_worker": {"core-1"}, "advert_int_ms": {""}, "vrrp_version": {""},
	}
	req := httptest.NewRequest(http.MethodPost, "/scopes/rw-100/config", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("name", "rw-100")
	rec := httptest.NewRecorder()

	handleScopeConfigPost(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for an invalid rename target, got %d", rec.Code)
	}
	if pushed {
		t.Error("must not push a candidate when the rename target is invalid")
	}
}

func TestHandleScopeConfigPost_SameNameIsNotARename(t *testing.T) {
	var pushedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				Scopes: map[string]config.ScopeConfig{"rw-100": {VIP: "172.16.100.1/24"}},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/candidate":
			body, _ := io.ReadAll(r.Body)
			pushedBody = string(body)
			w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	form := url.Values{
		"new_name": {"rw-100"},
		"parent":   {""}, "vlan_id": {"100"}, "vip": {"172.16.100.1/24"}, "node_ip": {""},
		"dhcp_start": {"172.16.100.150"}, "dhcp_end": {"172.16.100.250"}, "gateway": {"172.16.100.1"},
		"vrrp_id": {"0"}, "preferred_worker": {"core-1"}, "advert_int_ms": {""}, "vrrp_version": {""},
	}
	req := httptest.NewRequest(http.MethodPost, "/scopes/rw-100/config", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("name", "rw-100")
	rec := httptest.NewRecorder()

	handleScopeConfigPost(newConfigRef(cfg))(rec, req)

	var pushed configPushPayload
	if err := json.Unmarshal([]byte(pushedBody), &pushed); err != nil {
		t.Fatalf("unmarshal pushed payload: %v, body=%s", err, pushedBody)
	}
	if _, ok := pushed.Scopes["rw-100"]; !ok {
		t.Errorf("expected rw-100 to still be present, got: %+v", pushed.Scopes)
	}
	if len(pushed.Scopes) != 1 {
		t.Errorf("expected exactly one scope, got: %+v", pushed.Scopes)
	}
}

func TestHandleScopeConfigPost_UnknownScopeReturns404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{Scopes: map[string]config.ScopeConfig{"rw-100": {}}})
		}
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest(http.MethodPost, "/scopes/rw-999/config", strings.NewReader("vip=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("name", "rw-999")
	rec := httptest.NewRecorder()

	handleScopeConfigPost(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for a scope not in the cluster config", rec.Code)
	}
}

func TestHandleScopeDelete_RemovesOnlyTheNamedScope(t *testing.T) {
	var pushedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				PSK:      "secret-psk",
				LogLevel: "info",
				Scopes: map[string]config.ScopeConfig{
					"rw-100": {VIP: "172.16.100.1/24"},
					"rw-101": {VIP: "172.16.101.1/24"},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/candidate":
			body, _ := io.ReadAll(r.Body)
			pushedBody = string(body)
			w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest(http.MethodPost, "/scopes/rw-100/delete", nil)
	req.SetPathValue("name", "rw-100")
	rec := httptest.NewRecorder()

	handleScopeDelete(newConfigRef(cfg))(rec, req)

	var pushed configPushPayload
	if err := json.Unmarshal([]byte(pushedBody), &pushed); err != nil {
		t.Fatalf("unmarshal pushed payload: %v, body=%s", err, pushedBody)
	}
	if pushed.PSK != "secret-psk" || pushed.LogLevel != "info" {
		t.Errorf("expected cluster-wide fields preserved untouched, got PSK=%q LogLevel=%q", pushed.PSK, pushed.LogLevel)
	}
	if _, ok := pushed.Scopes["rw-100"]; ok {
		t.Errorf("expected rw-100 removed from the pushed candidate, got: %v", pushed.Scopes)
	}
	if _, ok := pushed.Scopes["rw-101"]; !ok {
		t.Errorf("expected rw-101 untouched, got: %v", pushed.Scopes)
	}
	if len(pushed.Scopes) != 1 {
		t.Errorf("expected exactly 1 scope left, got %d: %v", len(pushed.Scopes), pushed.Scopes)
	}
}

func TestHandleScopeDelete_UnknownScopeReturns404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{Scopes: map[string]config.ScopeConfig{"rw-100": {}}})
		}
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest(http.MethodPost, "/scopes/rw-999/delete", nil)
	req.SetPathValue("name", "rw-999")
	rec := httptest.NewRecorder()

	handleScopeDelete(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for a scope not in the cluster config", rec.Code)
	}
}

// TestHandleScopeRebalance_StampsOnlyTheNamedScope is the direct
// regression for handleScopeRebalance.
func TestHandleScopeRebalance_StampsOnlyTheNamedScope(t *testing.T) {
	var pushedBody string
	before := time.Now().Unix()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				PSK:      "secret-psk",
				LogLevel: "info",
				Scopes: map[string]config.ScopeConfig{
					"rw-100": {VIP: "172.16.100.1/24", PreferredWorker: "core-2"},
					"rw-101": {VIP: "172.16.101.1/24", PreferredWorker: "core-1"},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/candidate":
			body, _ := io.ReadAll(r.Body)
			pushedBody = string(body)
			w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest(http.MethodPost, "/scopes/rw-100/rebalance", nil)
	req.SetPathValue("name", "rw-100")
	rec := httptest.NewRecorder()

	handleScopeRebalance(newConfigRef(cfg))(rec, req)

	var pushed configPushPayload
	if err := json.Unmarshal([]byte(pushedBody), &pushed); err != nil {
		t.Fatalf("unmarshal pushed payload: %v, body=%s", err, pushedBody)
	}
	if pushed.PSK != "secret-psk" || pushed.LogLevel != "info" {
		t.Errorf("expected cluster-wide fields preserved untouched, got PSK=%q LogLevel=%q", pushed.PSK, pushed.LogLevel)
	}
	after := time.Now().Unix()
	got := pushed.Scopes["rw-100"].RebalanceApprovedAt
	if got < before || got > after {
		t.Errorf("rw-100 RebalanceApprovedAt = %d, want a timestamp between %d and %d", got, before, after)
	}
	if pushed.Scopes["rw-101"].RebalanceApprovedAt != 0 {
		t.Errorf("expected rw-101 untouched, got RebalanceApprovedAt=%d", pushed.Scopes["rw-101"].RebalanceApprovedAt)
	}
}

func TestHandleScopeRebalance_UnknownScopeReturns404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{Scopes: map[string]config.ScopeConfig{"rw-100": {}}})
		}
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest(http.MethodPost, "/scopes/rw-999/rebalance", nil)
	req.SetPathValue("name", "rw-999")
	rec := httptest.NewRecorder()

	handleScopeRebalance(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for a scope not in the cluster config", rec.Code)
	}
}

// TestHandleScopeRebalanceAll_StampsEveryScope is the direct regression
// for the cluster-wide convenience action.
func TestHandleScopeRebalanceAll_StampsEveryScope(t *testing.T) {
	var pushedBody string
	before := time.Now().Unix()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				Scopes: map[string]config.ScopeConfig{
					"rw-100": {VIP: "172.16.100.1/24", PreferredWorker: "core-2"},
					"rw-101": {VIP: "172.16.101.1/24", PreferredWorker: "core-1"},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/candidate":
			body, _ := io.ReadAll(r.Body)
			pushedBody = string(body)
			w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest(http.MethodPost, "/scopes/rebalance-all", nil)
	rec := httptest.NewRecorder()

	handleScopeRebalanceAll(newConfigRef(cfg))(rec, req)

	var pushed configPushPayload
	if err := json.Unmarshal([]byte(pushedBody), &pushed); err != nil {
		t.Fatalf("unmarshal pushed payload: %v, body=%s", err, pushedBody)
	}
	after := time.Now().Unix()
	for name, sc := range pushed.Scopes {
		if sc.RebalanceApprovedAt < before || sc.RebalanceApprovedAt > after {
			t.Errorf("scope %q RebalanceApprovedAt = %d, want a timestamp between %d and %d", name, sc.RebalanceApprovedAt, before, after)
		}
	}
	if len(pushed.Scopes) != 2 {
		t.Errorf("expected both scopes in the pushed candidate, got %d: %v", len(pushed.Scopes), pushed.Scopes)
	}
}

// TestScopesTmpl_DeleteButtonWiredWithConfirm checks the Scopes page asks
// before deleting a scope.
func TestScopesTmpl_DeleteButtonWiredWithConfirm(t *testing.T) {
	data := scopesPageData{
		Rows:  []scopeRow{{Name: "rw-100", Display: "rw-100"}},
		Total: 1, Page: 1, TotalPages: 1,
	}
	var buf strings.Builder
	if err := scopesTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `action="/scopes/rw-100/delete"`) {
		t.Errorf("expected a delete form pointed at /scopes/rw-100/delete, got: %s", out)
	}
	if !strings.Contains(out, "Really delete scope rw-100?") {
		t.Errorf("expected a 'really delete?' confirm dialog, got: %s", out)
	}
}

// TestScopeDetailTmpl_DeleteButtonWiredWithConfirm pins the same on the
// scope detail page.
func TestScopeDetailTmpl_DeleteButtonWiredWithConfirm(t *testing.T) {
	data := scopeDetailData{Scope: "rw-100", ConfigOK: true}
	var buf strings.Builder
	if err := scopeDetailTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `action="/scopes/rw-100/delete"`) {
		t.Errorf("expected a delete form pointed at /scopes/rw-100/delete, got: %s", out)
	}
	if !strings.Contains(out, "Really delete scope rw-100?") {
		t.Errorf("expected a 'really delete?' confirm dialog, got: %s", out)
	}
}

func TestScopesTmpl_DisableButtonColorsMatchState(t *testing.T) {
	data := scopesPageData{
		Rows: []scopeRow{
			{Name: "rw-100", Display: "rw-100", Disabled: false},
			{Name: "rw-101", Display: "rw-101", Disabled: true},
		},
		Total: 2, Page: 1, TotalPages: 1,
	}
	var buf strings.Builder
	if err := scopesTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `action="/scopes/rw-100/toggle-disabled"`) || !strings.Contains(out, `action="/scopes/rw-101/toggle-disabled"`) {
		t.Errorf("expected a toggle-disabled form for every row, got: %s", out)
	}
	if !strings.Contains(out, `class="btn-danger">delete<`) {
		t.Error("expected the list page's delete button to carry btn-danger")
	}
	if !strings.Contains(out, `class="btn-warn">disable<`) {
		t.Errorf("expected the NOT-yet-disabled row's button to read \"disable\" with btn-warn, got: %s", out)
	}
	if !strings.Contains(out, `class="btn-success">enable<`) {
		t.Errorf("expected the already-disabled row's button to read \"enable\" with btn-success, got: %s", out)
	}
}

func TestScopeDetailTmpl_DisableButtonColorsMatchState(t *testing.T) {
	notDisabled := scopeDetailData{Scope: "rw-100", ConfigOK: true, EditScope: config.ScopeConfig{DNSMasqDisabled: false}}
	var buf strings.Builder
	if err := scopeDetailTmpl.Execute(&buf, notDisabled); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `class="btn-warn">Disable this scope`) {
		t.Errorf("expected btn-warn on the Disable button when not yet disabled, got: %s", out)
	}
	if !strings.Contains(out, `class="btn-danger">Delete this scope`) {
		t.Errorf("expected btn-danger on the Delete button, got: %s", out)
	}

	disabled := scopeDetailData{Scope: "rw-100", ConfigOK: true, EditScope: config.ScopeConfig{DNSMasqDisabled: true}}
	buf.Reset()
	if err := scopeDetailTmpl.Execute(&buf, disabled); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out = buf.String()
	if !strings.Contains(out, `class="btn-success">Enable this scope`) {
		t.Errorf("expected btn-success on the Enable button once already disabled, got: %s", out)
	}
}

// TestScopeDetailTmpl_RenameFieldPresent.
func TestScopeDetailTmpl_RenameFieldPresent(t *testing.T) {
	data := scopeDetailData{Scope: "rw-100", ConfigOK: true}
	var buf strings.Builder
	if err := scopeDetailTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `<input name="new_name" value="rw-100">`) {
		t.Errorf("expected a new_name field pre-filled with the current scope name, got: %s", out)
	}
}

// TestScopeDetailTmpl_SubnetAutoFillDataAttributesWired.
func TestScopeDetailTmpl_SubnetAutoFillDataAttributesWired(t *testing.T) {
	data := scopeDetailData{
		Scope: "rw-100", ConfigOK: true,
		VIPSuffix: "254", GatewaySuffix: "1", DHCPStartSuffix: "100", DHCPEndSuffix: "200",
		IPPattern: ipPattern, IPCIDRPattern: ipCIDRPattern,
	}
	var buf strings.Builder
	if err := scopeDetailTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`data-vip-suffix="254"`, `data-gw-suffix="1"`, `data-dhcp-start-suffix="100"`, `data-dhcp-end-suffix="200"`,
		`id="edit_gateway"`, `id="edit_dhcp_start"`, `id="edit_dhcp_end"`,
		"autoScopeVIP(this)", "autoScopeGateway(this)", "autoScopeDHCPRange(this)",
		"function autoScopeGateway(vipInput)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in rendered output, got: %s", want, out)
		}
	}
}

// TestScopeDetailTmpl_TemplatePickersRendered.
func TestScopeDetailTmpl_TemplatePickersRendered(t *testing.T) {
	data := scopeDetailData{
		Scope: "rw-100", ConfigOK: true,
		DNSTemplatePicker:  wizardTemplateButtonsHTML(TemplateKindDNS, "scope_dns_records", buildTemplateRows([]Template{{ID: "ddm", Name: "ddm", Kind: TemplateKindDNS, Body: "A|ddm.fake.lan|203.0.113.10"}})),
		DHCPTemplatePicker: wizardTemplateButtonsHTML(TemplateKindDHCP, "scope_dhcp_options", buildTemplateRows([]Template{{ID: "dante", Name: "dante", Kind: TemplateKindDHCP, Body: "dhcp-option=42,192.168.1.1"}})),
	}
	var buf strings.Builder
	if err := scopeDetailTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `id="scope_dhcp_options"`) {
		t.Errorf("expected the dhcp_options textarea to carry a real id, got: %s", out)
	}
	if !strings.Contains(out, "wizInsert_scope_dns_records") || !strings.Contains(out, "ddm") {
		t.Errorf("expected the DNS template picker (ddm) wired to scope_dns_records, got: %s", out)
	}
	if !strings.Contains(out, "wizInsert_scope_dhcp_options") || !strings.Contains(out, "dante") {
		t.Errorf("expected the DHCP template picker (dante) wired to scope_dhcp_options, got: %s", out)
	}
}

func TestScopeDetailTmpl_ShowsDnsmasqPIDAndRestartLink(t *testing.T) {
	data := scopeDetailData{
		Scope: "rw-100", ConfigOK: true, TargetNode: "core-1",
		DnsmasqPID: 12345, DnsmasqRunningAs: "dnshived", DnsmasqRestartUnit: "dnshived-dnsmasq@rw-100.service",
	}
	var buf strings.Builder
	if err := scopeDetailTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "12345") {
		t.Errorf("expected the dnsmasq PID rendered, got: %s", out)
	}
	if !strings.Contains(out, "dnshived") {
		t.Errorf("expected the running-as user rendered, got: %s", out)
	}
	if !strings.Contains(out, `href="/daemons/core-1/dnshived-dnsmasq@rw-100.service/restart/confirm"`) {
		t.Errorf("expected a restart link pointed at the existing generic restart-confirm route, got: %s", out)
	}
	if strings.Contains(strings.ToLower(out), "reload dnsmasq") {
		t.Errorf("expected no 'reload' option for dnsmasq — it has no live config reload, only restart, got: %s", out)
	}
}

func TestFreeVLANIDsForEdit_ExcludesOnlyOtherScopes(t *testing.T) {
	scopes := map[string]config.ScopeConfig{
		"test2": {VLANID: 42},
		"test6": {VLANID: 7},
	}
	free := freeVLANIDsForEdit(scopes, "test6")
	for _, id := range free {
		if id == "42" {
			t.Errorf("expected vlan_id 42 (used by test2) excluded, got it in %v", free)
		}
	}
	found7 := false
	for _, id := range free {
		if id == "7" {
			found7 = true
		}
	}
	if !found7 {
		t.Errorf("expected test6's own current vlan_id 7 to stay selectable, got %v", free)
	}
}

func TestFreeVLANIDsForEdit_KeepsOwnReservedVLANOneSelectable(t *testing.T) {
	scopes := map[string]config.ScopeConfig{
		"legacy": {Parent: "ens19", VLANID: 1},
	}
	free := freeVLANIDsForEdit(scopes, "legacy")
	if len(free) == 0 || free[0] != "1" {
		t.Fatalf("expected legacy's own current vlan_id 1 to stay selectable (as the first entry), got %v", free)
	}
}

func TestFreeVLANIDsForEdit_AllowsSameVLANIDOnDifferentParent(t *testing.T) {
	scopes := map[string]config.ScopeConfig{
		"test2": {Parent: "ens19", VLANID: 10},
		"test6": {Parent: "ens20", VLANID: 7},
	}
	free := freeVLANIDsForEdit(scopes, "test6")
	found10 := false
	for _, id := range free {
		if id == "10" {
			found10 = true
		}
	}
	if !found10 {
		t.Errorf("expected vlan_id 10 (used by test2 on a different parent, ens19) to stay free for test6 on ens20, got %v", free)
	}
}

func TestScopeDetailTmpl_VLANIDIsAFindAsYouTypeCombobox(t *testing.T) {
	data := scopeDetailData{
		Scope:         "rw-100",
		TargetNode:    "core-1",
		Check:         authorityCheck{Decision: "SERVE"},
		ConfigOK:      true,
		EditScope:     config.ScopeConfig{Parent: "ens19", VLANID: 42, DHCPRange: [2]string{"192.168.10.10", "192.168.10.200"}},
		VLANIDOptions: []string{"41", "42", "43"},
	}
	var buf bytes.Buffer
	if err := scopeDetailTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("scopeDetailTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `<select name="vlan_id" class="js-combo">`) {
		t.Errorf("expected the vlan_id select to carry class=\"js-combo\", got: %s", out)
	}
}

func TestOtherScopeSubnetsAttr_ExcludesSelfAndFormatsCorrectly(t *testing.T) {
	scopes := map[string]config.ScopeConfig{
		"test2": {VIP: "192.168.10.254/23"},
		"test6": {VIP: "192.168.20.1/24"},
		"empty": {},
	}
	got := otherScopeSubnetsAttr(scopes, "test6")
	want := "test2|192.168.10.254/23"
	if got != want {
		t.Errorf("otherScopeSubnetsAttr(scopes, %q) = %q, want %q", "test6", got, want)
	}
	if strings.Contains(got, "test6") {
		t.Errorf("expected self (test6) excluded, got %q", got)
	}
}

func TestRenderScopePreview_BothSections(t *testing.T) {
	sc := config.ScopeConfig{
		Parent: "ens19", VLANID: 42, VIP: "192.168.10.1/24", NodeIP: "192.168.10.22/24",
		Gateway: "192.168.10.1", DHCPRange: [2]string{"192.168.10.100", "192.168.10.200"},
		DNSRecords: []config.DNSRecord{{Name: "nas.office.lan", Type: "A", Value: "192.168.10.50"}},
	}
	got := renderScopePreview("office", sc, nil)
	if !strings.Contains(got, "# DHCP —") || !strings.Contains(got, "dhcp-range=set:office,192.168.10.100,192.168.10.200") {
		t.Errorf("expected a labeled DHCP section with a real tag-scoped dhcp-range line, got %q", got)
	}
	if !strings.Contains(got, "# DNS —") || !strings.Contains(got, "host-record=nas.office.lan,192.168.10.50") {
		t.Errorf("expected a labeled DNS section with a real host-record line, got %q", got)
	}
}

func TestRenderScopePreview_IncompleteScopeOmitsDHCPSection(t *testing.T) {
	sc := config.ScopeConfig{
		Parent: "ens19", VLANID: 42, VIP: "192.168.10.1/24",
		Gateway: "192.168.10.1", DHCPRange: [2]string{"192.168.10.100", "192.168.10.200"},
	}
	got := renderScopePreview("office", sc, nil)
	if strings.Contains(got, "# DHCP —") {
		t.Errorf("expected no DHCP section for a scope missing node_ip, got %q", got)
	}
}

// TestRenderScopePreview_DNSOnlyScope confirms DNS renders independently
// of DHCP completeness — DNS has no node_ip dependency at all.
func TestRenderScopePreview_DNSOnlyScope(t *testing.T) {
	sc := config.ScopeConfig{
		Parent:     "ens19",
		VLANID:     42,
		DNSRecords: []config.DNSRecord{{Name: "nas.office.lan", Type: "A", Value: "192.168.10.50"}},
	}
	got := renderScopePreview("office", sc, nil)
	if strings.Contains(got, "# DHCP —") {
		t.Errorf("expected no DHCP section for a scope with no addressing at all, got %q", got)
	}
	if !strings.Contains(got, "# DNS —") || !strings.Contains(got, "host-record=nas.office.lan,192.168.10.50") {
		t.Errorf("expected a labeled DNS section regardless of DHCP completeness, got %q", got)
	}
}

func TestRenderScopePreview_EmptyScopeYieldsEmptyString(t *testing.T) {
	sc := config.ScopeConfig{Parent: "ens19", VLANID: 42}
	got := renderScopePreview("office", sc, nil)
	if got != "" {
		t.Errorf("expected an empty string for a scope with no addressing and no DNS records, got %q", got)
	}
}

func TestParseScopeEditForm_ClientDNSServerOtherChoiceParses(t *testing.T) {
	form := url.Values{
		"parent": {"ens19"}, "vlan_id": {"100"}, "vip": {"172.16.100.1/24"},
		"dhcp_start": {"172.16.100.100"}, "dhcp_end": {"172.16.100.200"},
		"gateway": {"172.16.100.1"}, "vrrp_id": {"51"}, "preferred_worker": {"core-2"},
		"dns_records":       {""},
		"client_dns_choice": {"other"}, "client_dns_server": {"172.17.42.1,172.17.42.2"},
	}
	req := httptest.NewRequest(http.MethodPost, "/scopes/rw-100/config", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()

	sc, err := parseScopeEditForm(req)
	if err != nil {
		t.Fatalf("parseScopeEditForm: %v", err)
	}
	if sc.ClientDNSServer != "172.17.42.1,172.17.42.2" {
		t.Errorf("ClientDNSServer = %q, want 172.17.42.1,172.17.42.2", sc.ClientDNSServer)
	}
}

// TestParseScopeEditForm_ClientDNSServerDnshivedChoiceWipesOverride
// mirrors the wizard's own test (scope_wizard_test.go) for this exact
// scenario.
func TestParseScopeEditForm_ClientDNSServerDnshivedChoiceWipesOverride(t *testing.T) {
	form := url.Values{
		"parent": {"ens19"}, "vlan_id": {"100"}, "vip": {"172.16.100.1/24"},
		"dhcp_start": {"172.16.100.100"}, "dhcp_end": {"172.16.100.200"},
		"gateway": {"172.16.100.1"}, "vrrp_id": {"51"}, "preferred_worker": {"core-2"},
		"dns_records":       {""},
		"client_dns_choice": {"dnshived"}, "client_dns_server": {"172.17.42.1"},
	}
	req := httptest.NewRequest(http.MethodPost, "/scopes/rw-100/config", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ParseForm()

	sc, err := parseScopeEditForm(req)
	if err != nil {
		t.Fatalf("parseScopeEditForm: %v", err)
	}
	if sc.ClientDNSServer != "" {
		t.Errorf("ClientDNSServer = %q, want empty (dnshived choice must wipe any override)", sc.ClientDNSServer)
	}
}

// A disabled scope reads "disabled" in the Status column even while its
// owner still lists it as serving, never "active".
func TestBuildScopeRows_DisabledScopeShowsDisabled(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", Serving: []string{"office", "test2"}}},
	}
	configScopes := map[string]config.ScopeConfig{
		"office": {VIP: "192.168.100.1/24"},
		"test2":  {VIP: "192.168.2.254/24", DNSMasqDisabled: true, ProbeDisabled: true},
	}
	got := buildScopeRows(rows, configScopes, nil, nil, nil, nil)
	for _, r := range got {
		switch r.Name {
		case "test2":
			if r.Status != "disabled" || r.Class != "warn" || r.StatusTitle == "" {
				t.Errorf("test2 = %q/%q (title %q), want \"disabled\"/\"warn\" with a tooltip", r.Status, r.Class, r.StatusTitle)
			}
		case "office":
			if r.Status != "active" {
				t.Errorf("office.Status = %q, want active", r.Status)
			}
		}
	}
}
