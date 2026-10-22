// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"dnshived/internal/discovery"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"dnshived/internal/config"
	"dnshived/internal/webauth"
)

func TestBuildScopesFormData_SortsByVLANIDNotName(t *testing.T) {
	c := config.Cluster{
		Platform: &config.Platform{Workers: []string{"ens19"}},
		Scopes: map[string]config.ScopeConfig{
			"zzz-late":  {VLANID: 100},
			"aaa-early": {VLANID: 200},
		},
	}
	data := buildScopesFormData(c, NodeConfig{Name: "core-1"})
	if len(data.Scopes) != 2 {
		t.Fatalf("Scopes = %+v, want 2", data.Scopes)
	}
	if data.Scopes[0].Name != "zzz-late" || data.Scopes[1].Name != "aaa-early" {
		t.Errorf("order = [%s, %s], want VLAN-ID order (zzz-late/100 then aaa-early/200), not name order", data.Scopes[0].Name, data.Scopes[1].Name)
	}
}

func TestBuildScopesFormData_ScopeDefaultsPrefillNewScopeRow(t *testing.T) {
	c := config.Cluster{ScopeDefaults: &config.ScopeDefaults{
		GatewaySuffix: "1", VIPSuffix: "50",
		AdvertIntMS: 150, VRRPVersion: 3,
	}}
	data := buildScopesFormData(c, NodeConfig{Name: "core-1"})
	if data.GatewaySuffix != "1" {
		t.Errorf("GatewaySuffix = %q, want 1", data.GatewaySuffix)
	}
	if data.VIPSuffix != "50" {
		t.Errorf("VIPSuffix = %q, want 50", data.VIPSuffix)
	}
	if data.AdvertIntMS != 150 {
		t.Errorf("AdvertIntMS = %d, want 150", data.AdvertIntMS)
	}
	if data.VRRPVersion != 3 {
		t.Errorf("VRRPVersion = %d, want 3", data.VRRPVersion)
	}
}

func TestLessLoadedWorker_EmptyDefaultsToCore1(t *testing.T) {
	if got := lessLoadedWorker(nil); got != "core-1" {
		t.Errorf("got %q, want core-1 for the zero-scopes/tie case", got)
	}
}

func TestLessLoadedWorker_FewerScopesWins(t *testing.T) {
	rows := []scopeFormRow{
		{ScopeConfig: config.ScopeConfig{PreferredWorker: "core-1"}},
		{ScopeConfig: config.ScopeConfig{PreferredWorker: "core-1"}},
		{ScopeConfig: config.ScopeConfig{PreferredWorker: "core-2"}},
		{ScopeConfig: config.ScopeConfig{PreferredWorker: "core-3"}},
	}
	if got := lessLoadedWorker(rows); got != "core-2" {
		t.Errorf("got %q, want core-2 (2 vs 1 vs 1 scopes, core-2 sorts first on the 1-1 tie)", got)
	}
}

func TestLessLoadedWorker_TieGoesToCore1(t *testing.T) {
	rows := []scopeFormRow{
		{ScopeConfig: config.ScopeConfig{PreferredWorker: "core-1"}},
		{ScopeConfig: config.ScopeConfig{PreferredWorker: "core-2"}},
		// core-3 included at the same count — a genuine 3-way tie, not
		// just a 2-way one core-3 would trivially win by omission.
		{ScopeConfig: config.ScopeConfig{PreferredWorker: "core-3"}},
	}
	if got := lessLoadedWorker(rows); got != "core-1" {
		t.Errorf("got %q, want core-1 on a 3-way tie", got)
	}
}

func TestLessLoadedWorker_Core3CanWin(t *testing.T) {
	rows := []scopeFormRow{
		{ScopeConfig: config.ScopeConfig{PreferredWorker: "core-1"}},
		{ScopeConfig: config.ScopeConfig{PreferredWorker: "core-1"}},
		{ScopeConfig: config.ScopeConfig{PreferredWorker: "core-2"}},
		{ScopeConfig: config.ScopeConfig{PreferredWorker: "core-2"}},
	}
	if got := lessLoadedWorker(rows); got != "core-3" {
		t.Errorf("got %q, want core-3 (0 scopes, fewer than either core-1 or core-2)", got)
	}
}

func TestBuildScopesFormData_PreferredWorkerDefaultReflectsLowerCount(t *testing.T) {
	c := config.Cluster{Scopes: map[string]config.ScopeConfig{
		"a": {VLANID: 1, PreferredWorker: "core-1"},
		"b": {VLANID: 2, PreferredWorker: "core-1"},
		"c": {VLANID: 3, PreferredWorker: "core-2"},
		"d": {VLANID: 4, PreferredWorker: "core-3"},
	}}
	data := buildScopesFormData(c, NodeConfig{Name: "core-1"})
	if data.PreferredWorkerDefault != "core-2" {
		t.Errorf("PreferredWorkerDefault = %q, want core-2 (fewer configured scopes)", data.PreferredWorkerDefault)
	}
}

func TestBuildScopesFormData_DNSRecordsTextRoundTrips(t *testing.T) {
	c := config.Cluster{Scopes: map[string]config.ScopeConfig{
		"office": {VLANID: 104, DNSRecords: []config.DNSRecord{{Name: "printer.lan", Type: "A", Value: "10.0.0.60"}}},
	}}
	data := buildScopesFormData(c, NodeConfig{Name: "core-1"})
	if data.Scopes[0].DNSRecordsText != "A|printer.lan|10.0.0.60" {
		t.Errorf("DNSRecordsText = %q, want A|printer.lan|10.0.0.60", data.Scopes[0].DNSRecordsText)
	}
}

func TestUsedVRRPIDsCSV_CollectsScopesAndMgmtVIPAscending(t *testing.T) {
	c := config.Cluster{
		MgmtVIP: &config.MgmtVIPConfig{VRRPID: 5},
		Scopes: map[string]config.ScopeConfig{
			"b": {VRRPID: 20},
			"a": {VRRPID: 3},
		},
	}
	got := usedVRRPIDsCSV(c)
	if got != "3,5,20" {
		t.Errorf("usedVRRPIDsCSV = %q, want 3,5,20", got)
	}
}

func TestBuildScopesFormData_UsedVRRPIDsExcludesNothingAndIsSorted(t *testing.T) {
	c := config.Cluster{Scopes: map[string]config.ScopeConfig{
		"office": {VLANID: 104, VRRPID: 50},
		"av":     {VLANID: 105, VRRPID: 10},
	}}
	data := buildScopesFormData(c, NodeConfig{Name: "core-1"})
	if data.UsedVRRPIDs != "10,50" {
		t.Errorf("UsedVRRPIDs = %q, want 10,50", data.UsedVRRPIDs)
	}
}

func TestScopesConfigFormTmpl_NewScopeSlotVRRPIDCarriesUsedIDsForJSSuggestion(t *testing.T) {
	data := buildScopesFormData(config.Cluster{Scopes: map[string]config.ScopeConfig{
		"office": {VLANID: 104, VRRPID: 7},
	}}, NodeConfig{Name: "core-1"})
	var buf strings.Builder
	if err := scopesConfigFormTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `class="narrow vrrp-suggest"`) {
		t.Errorf("new-scope-slot vrrp_id input missing vrrp-suggest class:\n%s", out)
	}
	if !strings.Contains(out, `data-used-vrrp-ids="7"`) {
		t.Errorf("new-scope-slot vrrp_id input missing data-used-vrrp-ids=\"7\":\n%s", out)
	}
	if !strings.Contains(out, "function autoVRRPID") {
		t.Errorf("page missing autoVRRPID script")
	}
	if strings.Contains(out, `name="scope_vrrp_id_office" value="7" class="vrrp-suggest"`) {
		t.Errorf("existing scope's vrrp_id input must not be marked vrrp-suggest")
	}
}

func TestScopesConfigFormTmpl_VIPSuffixWired(t *testing.T) {
	data := buildScopesFormData(config.Cluster{
		ScopeDefaults: &config.ScopeDefaults{VIPSuffix: "50"},
		Scopes:        map[string]config.ScopeConfig{"office": {VLANID: 104, VIP: "192.168.100.1/24"}},
	}, NodeConfig{Name: "core-1"})
	var buf strings.Builder
	if err := scopesConfigFormTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `data-vip-suffix="50"`) {
		t.Errorf("new-scope-slot vip input missing data-vip-suffix=\"50\":\n%s", out)
	}
	if !strings.Contains(out, "autoVIPFromNetwork(this)") {
		t.Errorf("new-scope-slot vip input not wired to autoVIPFromNetwork:\n%s", out)
	}
	if !strings.Contains(out, "function autoVIPFromNetwork(vipInput)") {
		t.Errorf("page missing autoVIPFromNetwork script")
	}
	if strings.Contains(out, `oninput="autoVIPFromNetwork(this);autoGateway(this);syncNodeIPMask(this,'vip_office'`) {
		t.Errorf("existing scope's vip input must not be wired to autoVIPFromNetwork")
	}
}

func TestScopesConfigFormTmpl_DNSCopySelectsAreFindAsYouTypeCombos(t *testing.T) {
	data := buildScopesFormData(config.Cluster{Scopes: map[string]config.ScopeConfig{
		"office": {VLANID: 104, VIP: "192.168.100.1/24"},
	}}, NodeConfig{Name: "core-1"})
	var buf strings.Builder
	if err := scopesConfigFormTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `<select id="dns-copy-from" class="js-combo">`) {
		t.Errorf("expected dns-copy-from to carry class=\"js-combo\":\n%s", out)
	}
	if !strings.Contains(out, `<select id="dns-copy-to" class="js-combo">`) {
		t.Errorf("expected dns-copy-to to carry class=\"js-combo\":\n%s", out)
	}
}

func TestScopesConfigFormTmpl_NodeIPMaskAutofillWired(t *testing.T) {
	data := buildScopesFormData(config.Cluster{Scopes: map[string]config.ScopeConfig{
		"office": {VLANID: 104, VIP: "192.168.100.1/24", NodeIP: "192.168.100.22/24"},
	}}, NodeConfig{Name: "core-1"})
	var buf strings.Builder
	if err := scopesConfigFormTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "function syncNodeIPMask") {
		t.Fatal("page missing syncNodeIPMask script")
	}
	for _, want := range []string{
		`syncNodeIPMask(this,'vip_office','node_ip_office')`,
		`syncNodeIPMask(this,'vip_new_0','node_ip_new_0')`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	for _, want := range []string{`id="vip_office"`, `id="node_ip_office"`, `id="vip_new_0"`, `id="node_ip_new_0"`} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// TestScopesConfigFormTmpl_LiveValidityScriptWired pins the live field
// validity check in the scope form.
func TestScopesConfigFormTmpl_LiveValidityScriptWired(t *testing.T) {
	data := buildScopesFormData(config.Cluster{}, NodeConfig{Name: "core-1"})
	var buf strings.Builder
	if err := scopesConfigFormTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `#scope-table input[pattern]`) {
		t.Errorf("page missing the generic input[pattern] live-validity wiring:\n%s", out)
	}
	if !strings.Contains(out, "field-invalid") {
		t.Errorf("page missing the field-invalid class toggle:\n%s", out)
	}
}

func TestScopesConfigFormTmpl_NewScopeSlotDefaultsRendered(t *testing.T) {
	c := config.Cluster{
		ScopeDefaults: &config.ScopeDefaults{AdvertIntMS: 150, VRRPVersion: 3},
		Scopes: map[string]config.ScopeConfig{
			"office": {VLANID: 100, PreferredWorker: "core-1"},
		},
	}
	data := buildScopesFormData(c, NodeConfig{Name: "core-1"})
	var buf strings.Builder
	if err := scopesConfigFormTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `<option value="core-2" selected>core-2</option>`) {
		t.Errorf("new-scope-slot preferred_worker must default to core-2 (0 vs 1 scope):\n%s", out)
	}
	if !strings.Contains(out, `name="scope_advert_int_ms_new_0" id="advert_new_0" value="150"`) {
		t.Errorf("new-scope-slot advert_int_ms missing the 150 default:\n%s", out)
	}
	if !strings.Contains(out, `name="scope_vrrp_version_new_0" id="vrrpver_new_0" value="3"`) {
		t.Errorf("new-scope-slot vrrp_version missing the 3 default:\n%s", out)
	}
}

func TestBuildClusterFormData_NewFieldsTextEncoded(t *testing.T) {
	c := config.Cluster{
		ScopeDefaults: &config.ScopeDefaults{GatewaySuffix: "1", Upstream: []string{"1.1.1.1"}},
	}
	data := buildClusterFormData(c, NodeConfig{Name: "core-1"}, nil)
	if data.ScopeDefaultsGatewaySuffix != "1" || data.ScopeDefaultsUpstreamText != "1.1.1.1" {
		t.Errorf("ScopeDefaults fields = %q / %q", data.ScopeDefaultsGatewaySuffix, data.ScopeDefaultsUpstreamText)
	}
}

func TestBuildDNSConfigFormData_FieldsTextEncoded(t *testing.T) {
	c := config.Cluster{
		DefaultDNSChecks: []config.DNSCheck{{Name: "example.com.", Type: "A"}},
		GlobalDNSRecords: []config.DNSRecord{{Name: "fileserver.lan", Type: "A", Value: "10.0.0.50"}},
	}
	data := buildDNSConfigFormData(c, NodeConfig{Name: "core-1"})
	if data.DefaultDNSChecksText != "example.com.|A" {
		t.Errorf("DefaultDNSChecksText = %q", data.DefaultDNSChecksText)
	}
	if data.GlobalDNSRecordsText != "A|fileserver.lan|10.0.0.50" {
		t.Errorf("GlobalDNSRecordsText = %q", data.GlobalDNSRecordsText)
	}
}

func TestBuildDNSConfigFormData_GlobalDNSNamesDedupedAndSorted(t *testing.T) {
	c := config.Cluster{
		GlobalDNSRecords: []config.DNSRecord{
			{Name: "zeta.lan", Type: "A", Value: "10.0.0.2"},
			{Name: "alpha.lan", Type: "A", Value: "10.0.0.1"},
			{Name: "alpha.lan", Type: "A", Value: "10.0.0.1"}, // exact duplicate
		},
	}
	data := buildDNSConfigFormData(c, NodeConfig{Name: "core-1"})
	if len(data.GlobalDNSNames) != 2 {
		t.Fatalf("expected 2 deduped names, got %d: %+v", len(data.GlobalDNSNames), data.GlobalDNSNames)
	}
	if data.GlobalDNSNames[0].Name != "alpha.lan" || data.GlobalDNSNames[1].Name != "zeta.lan" {
		t.Errorf("expected sorted [alpha.lan, zeta.lan], got %+v", data.GlobalDNSNames)
	}
}

func TestBuildDHCPConfigFormData_FieldsTextEncodedAndSortedByVLAN(t *testing.T) {
	c := config.Cluster{
		DefaultDHCPOptions: []string{"option:domain-search,corp.local"},
		Scopes: map[string]config.ScopeConfig{
			"guest":  {VLANID: 100},
			"office": {VLANID: 104, DHCPOptions: []string{"option:ntp-server,10.0.0.1"}},
		},
	}
	data := buildDHCPConfigFormData(c, NodeConfig{Name: "core-1"})
	if data.DefaultDHCPOptionsText != "option:domain-search,corp.local" {
		t.Errorf("DefaultDHCPOptionsText = %q", data.DefaultDHCPOptionsText)
	}
	if len(data.Scopes) != 2 || data.Scopes[0].Name != "guest" || data.Scopes[1].Name != "office" {
		t.Fatalf("Scopes = %+v, want [guest, office] sorted by VLAN", data.Scopes)
	}
	if !data.Scopes[0].UsesDefault {
		t.Error("guest has no own dhcp_options, want UsesDefault=true")
	}
	if data.Scopes[1].UsesDefault || data.Scopes[1].DHCPOptionsText != "option:ntp-server,10.0.0.1" {
		t.Errorf("office = %+v, want its own dhcp_options preserved", data.Scopes[1])
	}
}

func TestParseDNSCheckLines_ParsesAndRejectsMalformed(t *testing.T) {
	checks, err := parseDNSCheckLines("example.com.|A\nfoo.bar.|AAAA\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(checks) != 2 || checks[0].Name != "example.com." || checks[0].Type != "A" {
		t.Errorf("checks = %+v", checks)
	}
	if _, err := parseDNSCheckLines("no-pipe-here"); err == nil {
		t.Fatal("expected an error for a line missing '|'")
	}
}

func TestParseScopeColor_SentinelMeansUnset(t *testing.T) {
	if got := parseScopeColor(scopeColorUnset); got != "" {
		t.Errorf("parseScopeColor(%s) = %q, want empty", scopeColorUnset, got)
	}
	if got := parseScopeColor("#C0C0C0"); got != "" {
		t.Errorf("parseScopeColor(#C0C0C0) = %q, want empty (case-insensitive)", got)
	}
	if got := parseScopeColor(""); got != "" {
		t.Errorf("parseScopeColor(\"\") = %q, want empty", got)
	}
	if got := parseScopeColor("#f58231"); got != "#f58231" {
		t.Errorf("parseScopeColor(#f58231) = %q, want #f58231 preserved", got)
	}
	if got := parseScopeColor("#ffffff"); got != "#ffffff" {
		t.Errorf("parseScopeColor(#ffffff) = %q, want #ffffff preserved — white is a real palette choice now", got)
	}
}

func TestParseScopeSlots_ParsesColor(t *testing.T) {
	f := url.Values{
		"__scope_names__":     {"office"},
		"scope_parent_office": {"ens19"},
		"scope_color_office":  {"#f58231"},
	}
	scopes, err := parseScopeSlots(f)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if scopes["office"].Color != "#f58231" {
		t.Errorf("Color = %q, want #f58231", scopes["office"].Color)
	}
}

// TestParseScopeSlots_CarriesForwardProbeDisabled pins the hidden
// carry-forward field mirroring scope_color_'s own.
func TestParseScopeSlots_CarriesForwardProbeDisabled(t *testing.T) {
	f := url.Values{
		"__scope_names__":             {"office"},
		"scope_parent_office":         {"ens19"},
		"scope_probe_disabled_office": {"on"},
	}
	scopes, err := parseScopeSlots(f)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !scopes["office"].ProbeDisabled {
		t.Error("ProbeDisabled = false, want true carried forward from the hidden field")
	}
}

// TestParseScopeSlots_ProbeDisabledOmittedMeansEnabled confirms a scope
// that never had probing disabled stays enabled through a bulk save.
func TestParseScopeSlots_ProbeDisabledOmittedMeansEnabled(t *testing.T) {
	f := url.Values{
		"__scope_names__":     {"office"},
		"scope_parent_office": {"ens19"},
	}
	scopes, err := parseScopeSlots(f)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if scopes["office"].ProbeDisabled {
		t.Error("ProbeDisabled = true, want false when the hidden field is absent")
	}
}

func TestParseScopeSlots_ParsesDNSRecordsAndRejectsMalformed(t *testing.T) {
	f := url.Values{
		"__scope_names__":          {"office"},
		"scope_parent_office":      {"ens19"},
		"scope_vlan_id_office":     {"104"},
		"scope_dns_records_office": {"A|printer.lan|10.0.0.60"},
	}
	scopes, err := parseScopeSlots(f)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(scopes["office"].DNSRecords) != 1 || scopes["office"].DNSRecords[0].Name != "printer.lan" {
		t.Errorf("office.DNSRecords = %+v", scopes["office"].DNSRecords)
	}

	f["scope_dns_records_office"] = []string{"BOGUS|x|y"}
	if _, err := parseScopeSlots(f); err == nil {
		t.Fatal("expected an error for a malformed dns_records line")
	}
}

func TestPushConfigAndRenderResult_SuccessfulSaveTriggersReload(t *testing.T) {
	var restartCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/config":
			w.Write([]byte(`{"ok":true,"warnings":[],"restart_needed":true}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/daemons/dnshived.service/restart":
			restartCalled = true
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/status":
			w.Write([]byte(`{"state":"STABLE"}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	rec := httptest.NewRecorder()
	pushConfigAndRenderResult(rec, cfg, configPushPayload{}, webauth.User{Name: "admin"}, "/config", "back", nil)

	if !restartCalled {
		t.Error("a successful config check must trigger a reload (restart dnshived.service), but the restart endpoint was never called")
	}
	if !strings.Contains(rec.Body.String(), "reloaded") {
		t.Errorf("result page should report the reload as successful, got:\n%s", rec.Body.String())
	}
}

func TestPushConfigAndRenderResult_RestartNeededFalseSkipsReload(t *testing.T) {
	var restartCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/config":
			w.Write([]byte(`{"ok":true,"warnings":[],"restart_needed":false}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/daemons/dnshived.service/restart":
			restartCalled = true
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	rec := httptest.NewRecorder()
	pushConfigAndRenderResult(rec, cfg, configPushPayload{}, webauth.User{Name: "admin"}, "/config", "back", nil)

	if restartCalled {
		t.Error("a node reporting restart_needed=false must never trigger a reload")
	}
	body := rec.Body.String()
	if !strings.Contains(body, "no restart needed") {
		t.Errorf("result page should say no restart was needed, got:\n%s", body)
	}
	if strings.Contains(body, "Partial or full failure") {
		t.Errorf("skipping an unneeded restart must still report overall success, got:\n%s", body)
	}
}

// TestPushConfigAndRenderResult_StreamsLivePushAndReloadProgress pins the
// live-progress log.
func TestPushConfigAndRenderResult_StreamsLivePushAndReloadProgress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/config":
			w.Write([]byte(`{"ok":true,"warnings":[],"restart_needed":true}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/status":
			w.Write([]byte(`{"state":"STABLE"}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{
		{Name: "core-3", Addr: strings.TrimPrefix(srv.URL, "http://")},
		{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")},
	}}
	rec := httptest.NewRecorder()
	pushConfigAndRenderResult(rec, cfg, configPushPayload{}, webauth.User{Name: "admin"}, "/config", "back", nil)

	body := rec.Body.String()
	for _, want := range []string{
		"pushing to core-3…", "pushing to core-1…",
		"pushing to core-3… <span class=\"ok\">done</span>",
		"pushing to core-1… <span class=\"ok\">done</span>",
		"restarting core-3… <span class=\"ok\">done</span>",
		"restarting core-1… <span class=\"ok\">done</span>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in the live progress log, got:\n%s", want, body)
		}
	}
	lastAnnounce := strings.LastIndex(body, `id="log-`)
	firstDone := strings.Index(body, `<span class="ok">done</span>`)
	if lastAnnounce == -1 || firstDone == -1 || lastAnnounce > firstDone {
		t.Error("both nodes' initial 'pushing to…' announcements should appear before any completion line")
	}
}

func TestPushConfigAndRenderResult_RejectedConfigSkipsReloadAndReportsErrors(t *testing.T) {
	var restartCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/config":
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"errors":["scope \"office\": vrrp_id 51 already used by scope \"guest\""]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/daemons/dnshived.service/restart":
			restartCalled = true
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	rec := httptest.NewRecorder()
	pushConfigAndRenderResult(rec, cfg, configPushPayload{}, webauth.User{Name: "admin"}, "/config", "back", nil)

	if restartCalled {
		t.Error("a REJECTED config check must never trigger a reload")
	}
	body := rec.Body.String()
	if !strings.Contains(body, "vrrp_id 51 already used") {
		t.Errorf("result page must show the real validation error text, got:\n%s", body)
	}
	if !strings.Contains(body, "not attempted") {
		t.Errorf("result page must say the reload was skipped, got:\n%s", body)
	}
}

func TestConfigFormTmpl_LinksToDaemonsView(t *testing.T) {
	var buf strings.Builder
	if err := configFormTmpl.Execute(&buf, clusterFormData{}); err != nil {
		t.Fatalf("configFormTmpl.Execute failed: %v", err)
	}
	if !strings.Contains(buf.String(), `href="/daemons"`) {
		t.Error("expected a link to /daemons (the new Daemons view tab)")
	}
}

// TestConfigFormTmpl_LogLevelCarriesInfoIcon pins the info icon on a field
// whose effect isn't obvious from its label.
func TestConfigFormTmpl_LogLevelCarriesInfoIcon(t *testing.T) {
	var buf strings.Builder
	if err := configFormTmpl.Execute(&buf, clusterFormData{}); err != nil {
		t.Fatalf("configFormTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "dry_run") {
		t.Error("Cluster Settings still renders a dry_run field")
	}
	if !strings.Contains(out, `log_level <span class="info-ico"`) {
		t.Error("expected log_level's label to be followed by an info-ico span")
	}
}

func TestHandleConfigGet_RendersFullClusterWithoutError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(config.Cluster{
			ClusterID: "lab01", NodeID: "worker-a-node", Role: "core-1",
			Platform:         &config.Platform{Mgmt: "eth0", Workers: []string{"ens19", "ens20"}, InterfaceLabels: map[string]string{"ens19": "Interface Office"}},
			MgmtVIP:          &config.MgmtVIPConfig{VIP: "192.0.2.230/24", VRRPID: 60},
			APITokens:        []config.APIToken{{Name: "admin", Token: "x", Role: "admin"}},
			DefaultDNSChecks: []config.DNSCheck{{Name: "example.com.", Type: "A"}},
			GlobalDNSRecords: []config.DNSRecord{{Name: "fileserver.lan", Type: "A", Value: "10.0.0.50"}},
			ScopeDefaults:    &config.ScopeDefaults{GatewaySuffix: "1", Upstream: []string{"1.1.1.1"}},
		})
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	rec := httptest.NewRecorder()

	handleConfigGet(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "192.0.2.230/24") {
		t.Errorf("rendered page missing expected content (mgmt VIP), got:\n%s", body)
	}
	if strings.Contains(body, "<h2>Scopes</h2>") {
		t.Error("cluster page must not render a Scopes section anymore — that moved to /config/scopes")
	}
	if strings.Contains(body, "fileserver.lan") || strings.Contains(body, "example.com.") {
		t.Error("cluster page must not render DNS/DHCP-default content anymore — that moved to /config/dns")
	}
	if strings.Contains(body, `name="token_name_0"`) {
		t.Error("cluster page must not render API tokens anymore — that moved to /security")
	}
	if strings.Contains(body, "1.1.1.1") || strings.Contains(body, `name="scope_defaults_vip_suffix"`) {
		t.Error("cluster page must not render ScopeDefaults content anymore — that moved to /scopes/options")
	}
}

func TestHandleConfigGet_OnboardTargetsNeverOfferSelfsOwnRoleAsMissing(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(config.Cluster{
			ClusterID: "lab01", NodeID: "arbiter-node", Role: "core-3",
			ControlAddr:   "192.0.2.24:9443",
			Platform:      &config.Platform{Mgmt: "eth0", Workers: []string{"ens19"}},
			APITokens:     []config.APIToken{{Name: "admin", Token: "x", Role: "admin"}},
			ScopeDefaults: &config.ScopeDefaults{GatewaySuffix: "1"},
		})
	}))
	defer srv.Close()
	port := strings.TrimPrefix(srv.URL, "https://127.0.0.1:")

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: "192.168.9.9:" + port, AdminToken: "shared-tok"}}}
	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	rec := httptest.NewRecorder()

	handleConfigGet(newConfigRef(cfg))(rec, req)
	body := rec.Body.String()

	if strings.Contains(body, `<option value="core-3">core-3</option>`) {
		t.Errorf("expected core-3 NOT offered under Onboard as (missing) — it's this very instance's own, genuinely-occupied role, got:\n%s", body)
	}
}

func TestHandleDHCPDNSConfigGet_RendersDNSAndDHCPSectionsTogether(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(config.Cluster{
			GlobalDNSRecords:   []config.DNSRecord{{Name: "fileserver.lan", Type: "A", Value: "10.0.0.50"}},
			DefaultDHCPOptions: []string{"option:domain-search,corp.local"},
			Scopes: map[string]config.ScopeConfig{
				"office": {VLANID: 104, DHCPOptions: []string{"option:ntp-server,10.0.0.1"}},
			},
		})
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest(http.MethodGet, "/config/dns", nil)
	rec := httptest.NewRecorder()

	handleDHCPDNSConfigGet(newConfigRef(cfg), &TemplateStore{})(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "fileserver.lan") {
		t.Errorf("DNS section missing expected content, got:\n%s", body)
	}
	if !strings.Contains(body, "corp.local") || !strings.Contains(body, "office") || !strings.Contains(body, "10.0.0.1") {
		t.Errorf("DHCP section missing expected content, got:\n%s", body)
	}
	if strings.Contains(body, `id="dns_check_quick_add"`) {
		t.Error("Default DNS probe checks moved to /probes — this page must no longer render its own quick-add picker")
	}
}

func TestHandleDHCPDNSConfigGet_RendersTemplateLibrary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(config.Cluster{})
	}))
	defer srv.Close()

	store := &TemplateStore{}
	store.Upsert("", "dante", "#123456", TemplateKindDHCP, "6,8.8.8.8")
	store.Upsert("", "ddm", "#654321", TemplateKindDNS, "A|test.local|10.0.0.1")

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest(http.MethodGet, "/config/dns", nil)
	rec := httptest.NewRecorder()

	handleDHCPDNSConfigGet(newConfigRef(cfg), store)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "dante") || !strings.Contains(body, "ddm") {
		t.Errorf("template library section missing expected rows, got:\n%s", body)
	}
	if !strings.Contains(body, "/templates/new") {
		t.Error("expected a link to /templates/new")
	}
}

func TestHandleProbes_QuickAddSelectSizeStaysFixed(t *testing.T) {
	var names []config.DNSRecord
	for i := 0; i < 50; i++ {
		names = append(names, config.DNSRecord{Name: fmt.Sprintf("host%d.lan", i), Type: "A", Value: "10.0.0.1"})
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v1/candidate"):
			json.NewEncoder(w).Encode(map[string]any{"exists": false})
		case strings.HasPrefix(r.URL.Path, "/api/v1/config"):
			json.NewEncoder(w).Encode(config.Cluster{GlobalDNSRecords: names})
		default:
			w.Write([]byte("{}"))
		}
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest(http.MethodGet, "/probes", nil)
	rec := httptest.NewRecorder()

	handleProbes(newConfigRef(cfg))(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, `id="dns_check_quick_add" multiple size="6"`) {
		t.Errorf("expected the quick-add select to stay fixed at size=6 regardless of 50 real option rows, got:\n%s", body)
	}
	if strings.Contains(body, `size="50"`) {
		t.Error("select size must never grow to the full option count — that's the exact doomscrolling regression this test guards")
	}
}

func TestHandleScopesConfigGet_RendersManyScopesWithoutError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(config.Cluster{
			Platform: &config.Platform{Workers: []string{"ens19"}},
			Scopes: map[string]config.ScopeConfig{
				"office": {VLANID: 104, VIP: "10.0.104.1/24", Color: "#f58231", DHCPOptions: []string{"option:ntp-server,10.0.0.1"}, DNSRecords: []config.DNSRecord{{Name: "printer.lan", Type: "A", Value: "10.0.104.60"}}, ProbeDisabled: true},
				"guest":  {VLANID: 100, VIP: "10.0.100.1/24"},
			},
			ScopeDefaults: &config.ScopeDefaults{GatewaySuffix: "1"},
		})
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest(http.MethodGet, "/config/scopes", nil)
	rec := httptest.NewRecorder()

	handleScopesConfigGet(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "printer.lan") {
		t.Errorf("rendered page missing the scope's dns_records, got:\n%s", body)
	}
	// guest (VLAN 100) must render before office (VLAN 104).
	if strings.Index(body, `name="scope_vip_guest"`) > strings.Index(body, `name="scope_vip_office"`) {
		t.Error("scopes not rendered in VLAN-ID order")
	}
	if !strings.Contains(body, `name="scope_color_office" value="#f58231"`) {
		t.Errorf("office's color must still be carried forward via a hidden field, got:\n%s", body)
	}
	if !strings.Contains(body, `name="scope_probe_disabled_office" value="on"`) {
		t.Errorf("office's probe_disabled must still be carried forward via a hidden field, got:\n%s", body)
	}
	if strings.Contains(body, `type="color"`) {
		t.Error("the bulk scope table must not have an editable color picker anymore — that moved to the scope detail page")
	}
	if !strings.Contains(body, "option:ntp-server,10.0.0.1") {
		t.Errorf("rendered page missing the scope's dhcp_options, got:\n%s", body)
	}
}

func TestHandleConfigPost_PreservesLiveScopesUnedited(t *testing.T) {
	var pushedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				Scopes:                 map[string]config.ScopeConfig{"office": {VIP: "10.0.0.1/24"}},
				APITokens:              []config.APIToken{{Name: "admin", Token: "tok", Role: "admin"}},
				ScopeDefaults:          &config.ScopeDefaults{VIPSuffix: "254"},
				ProbeIntervalMS:        7000,
				BackupEnabled:          true,
				BackupIntervalHours:    12,
				BackupRetentionCount:   14,
				BackupPassword:         "secret",
				BackupReplicateToPeers: true,
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
	form := url.Values{"psk": {"newpsk"}, "log_level": {"debug"}}
	req := httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	handleConfigPost(newConfigRef(cfg))(rec, req)

	var pushed configPushPayload
	if err := json.Unmarshal([]byte(pushedBody), &pushed); err != nil {
		t.Fatalf("unmarshal pushed payload: %v, body=%s", err, pushedBody)
	}
	if pushed.PSK != "newpsk" || pushed.LogLevel != "debug" {
		t.Errorf("edited fields not applied: PSK=%q LogLevel=%q", pushed.PSK, pushed.LogLevel)
	}
	if len(pushed.Scopes) != 1 || pushed.Scopes["office"].VIP != "10.0.0.1/24" {
		t.Errorf("live scopes not preserved: %+v", pushed.Scopes)
	}
	if len(pushed.APITokens) != 1 || pushed.APITokens[0].Name != "admin" {
		t.Errorf("live API tokens not preserved: %+v", pushed.APITokens)
	}
	if pushed.ScopeDefaults == nil || pushed.ScopeDefaults.VIPSuffix != "254" {
		t.Errorf("live ScopeDefaults not preserved: %+v", pushed.ScopeDefaults)
	}
	if pushed.ProbeIntervalMS != 7000 {
		t.Errorf("live ProbeIntervalMS not preserved: got %d, want 7000", pushed.ProbeIntervalMS)
	}
	if !pushed.BackupEnabled {
		t.Error("live BackupEnabled=true not preserved — this is the exact reported bug")
	}
	if pushed.BackupIntervalHours != 12 {
		t.Errorf("live BackupIntervalHours not preserved: got %d, want 12", pushed.BackupIntervalHours)
	}
	if pushed.BackupRetentionCount != 14 {
		t.Errorf("live BackupRetentionCount not preserved: got %d, want 14", pushed.BackupRetentionCount)
	}
	if pushed.BackupPassword != "secret" {
		t.Errorf("live BackupPassword not preserved: got %q, want %q", pushed.BackupPassword, "secret")
	}
	if !pushed.BackupReplicateToPeers {
		t.Error("live BackupReplicateToPeers=true not preserved")
	}
}

func TestHandleConfigPost_PreservesWorkerOverrides(t *testing.T) {
	var pushedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				Platform: &config.Platform{
					Mgmt:    "eth0",
					Workers: []string{"ens19", "ens20"},
					WorkerOverrides: map[string]map[string]string{
						"core-2": {"ens19": "eth1", "ens20": "eth2"},
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
		"psk":              {"newpsk"},
		"platform_mgmt":    {"eth0"},
		"platform_workers": {"ens19\nens20"},
	}
	req := httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	handleConfigPost(newConfigRef(cfg))(rec, req)

	var pushed configPushPayload
	if err := json.Unmarshal([]byte(pushedBody), &pushed); err != nil {
		t.Fatalf("unmarshal pushed payload: %v, body=%s", err, pushedBody)
	}
	if pushed.Platform == nil {
		t.Fatal("pushed Platform is nil")
	}
	got := pushed.Platform.WorkerOverrides["core-2"]
	if got["ens19"] != "eth1" || got["ens20"] != "eth2" {
		t.Errorf("live WorkerOverrides not preserved — this is the exact reported bug: got %+v", pushed.Platform.WorkerOverrides)
	}
}

func TestHandleScopeDefaultsPost_BuildsPerNodeNodeIPSuffixes(t *testing.T) {
	var (
		mu         sync.Mutex
		pushedBody string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/candidate":
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			pushedBody = string(body)
			mu.Unlock()
			w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{
		{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")},
		{Name: "core-2", Addr: strings.TrimPrefix(srv.URL, "http://")},
		{Name: "core-3", Addr: strings.TrimPrefix(srv.URL, "http://")},
	}}
	form := url.Values{
		"scope_defaults_node_ip_suffix_core-1": {"22"},
		"scope_defaults_node_ip_suffix_core-2": {"23"},
		"scope_defaults_node_ip_suffix_core-3": {"24"},
	}
	req := httptest.NewRequest(http.MethodPost, "/scopes/options", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	handleScopeDefaultsPost(newConfigRef(cfg))(rec, req)

	mu.Lock()
	body := pushedBody
	mu.Unlock()
	var pushed configPushPayload
	if err := json.Unmarshal([]byte(body), &pushed); err != nil {
		t.Fatalf("unmarshal pushed payload: %v, body=%s", err, body)
	}
	if pushed.ScopeDefaults == nil {
		t.Fatal("expected ScopeDefaults to be set")
	}
	want := map[string]string{"core-1": "22", "core-2": "23", "core-3": "24"}
	if len(pushed.ScopeDefaults.NodeIPSuffixes) != len(want) {
		t.Fatalf("NodeIPSuffixes = %+v, want %+v", pushed.ScopeDefaults.NodeIPSuffixes, want)
	}
	for k, v := range want {
		if pushed.ScopeDefaults.NodeIPSuffixes[k] != v {
			t.Errorf("NodeIPSuffixes[%q] = %q, want %q", k, pushed.ScopeDefaults.NodeIPSuffixes[k], v)
		}
	}
}

func TestHandleScopesConfigPost_PreservesLiveClusterFieldsUnedited(t *testing.T) {
	var pushedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				PSK: "secret-psk", LogLevel: "info",
				Scopes: map[string]config.ScopeConfig{"office": {VIP: "10.0.0.1/24"}},
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
		"__scope_names__":      {"office"},
		"scope_parent_office":  {"ens19"},
		"scope_vlan_id_office": {"999"}, // the actual edit
	}
	req := httptest.NewRequest(http.MethodPost, "/config/scopes", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	handleScopesConfigPost(newConfigRef(cfg))(rec, req)

	var pushed configPushPayload
	if err := json.Unmarshal([]byte(pushedBody), &pushed); err != nil {
		t.Fatalf("unmarshal pushed payload: %v, body=%s", err, pushedBody)
	}
	if pushed.PSK != "secret-psk" || pushed.LogLevel != "info" {
		t.Errorf("live cluster-wide fields not preserved: PSK=%q LogLevel=%q", pushed.PSK, pushed.LogLevel)
	}
	if pushed.Scopes["office"].VLANID != 999 {
		t.Errorf("the actual scope edit didn't apply: %+v", pushed.Scopes["office"])
	}
}

func TestHandleDHCPDNSConfigGet_RendersLocalDomainsSection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(config.Cluster{
			LocalDomains: []config.LocalDomain{{
				Name: "foo.lan",
				TTL:  3600,
				Records: []config.LocalDomainHost{
					{Host: "nas1", Type: "A", Value: "192.168.10.20"},
				},
			}},
		})
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest(http.MethodGet, "/config/dns", nil)
	rec := httptest.NewRecorder()

	handleDHCPDNSConfigGet(newConfigRef(cfg), &TemplateStore{})(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `id="domains"`) {
		t.Error("missing the Local domains section anchor")
	}
	if !strings.Contains(body, "foo.lan") {
		t.Errorf("missing the configured domain name, got:\n%s", body)
	}
	if !strings.Contains(body, "A|nas1|192.168.10.20") {
		t.Errorf("missing the domain's own record in the bulk textarea, got:\n%s", body)
	}
	if !strings.Contains(body, `id="domain_records_foo_lan"`) {
		t.Errorf("missing the domain's own textarea id, got:\n%s", body)
	}
	if !strings.Contains(body, "tpl-builder") {
		t.Error("missing the structured record-add picker")
	}
	if idx1, idx2 := strings.Index(body, `id="domains"`), strings.Index(body, `id="dns"`); idx1 < 0 || idx2 < 0 || idx1 > idx2 {
		t.Errorf("Local domains section must render before DNS defaults, got domains@%d dns@%d", idx1, idx2)
	}
}

func TestWithoutMembersDropsJoinedNodes(t *testing.T) {
	cands := []discovery.Candidate{{Addr: "192.0.2.52"}, {Addr: "192.0.2.60"}, {Addr: "192.0.2.54"}}
	got := withoutMembers(cands,
		[]NodeConfig{{Name: "core-1", Addr: "192.0.2.51:9443"}, {Name: "core-2", Addr: "192.0.2.52:9443"}},
		[]NodeConfig{{Name: "probe", Addr: "192.0.2.54:9444"}})
	if len(got) != 1 || got[0].Addr != "192.0.2.60" {
		t.Errorf("withoutMembers = %+v, want only 192.0.2.60", got)
	}
}
