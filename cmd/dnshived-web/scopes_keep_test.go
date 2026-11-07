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
	"reflect"
	"strings"
	"testing"

	"dnshived/internal/config"
)

func scopeWithUnshownFields() config.ScopeConfig {
	off := false
	return config.ScopeConfig{
		Parent:              "ens19",
		VLANID:              42,
		VIP:                 "10.0.0.1/24",
		DHCPRange:           [2]string{"10.0.0.100", "10.0.0.200"},
		Gateway:             "10.0.0.1",
		VRRPID:              7,
		PreferredWorker:     "core-1",
		NodeIPOverrides:     map[string]string{"core-2": "10.0.0.23/24"},
		ClientDNSServer:     "10.0.0.53",
		Reservations:        []config.Reservation{{MAC: "aa:bb:cc:dd:ee:01", IP: "10.0.0.50", Hostname: "printer"}},
		VRRPUnicast:         &off,
		DHCPNoPing:          true,
		DHCPIoTDefaults:     true,
		DHCPBroadcast:       &off,
		DHCPAuthoritative:   &off,
		DHCPLeaseTime:       "12h",
		DNSMasqDisabled:     true,
		ProbeDisabled:       true,
		RebalanceApprovedAt: 1700000000,
		ContentLinks:        map[string]config.ContentLink{"dhcp": {Kind: "dhcp", SourceID: "iot"}},
	}
}

func assertUnshownFieldsKept(t *testing.T, got, want config.ScopeConfig) {
	t.Helper()
	checks := []struct {
		name     string
		got, exp any
	}{
		{"Reservations", got.Reservations, want.Reservations},
		{"VRRPUnicast", got.VRRPUnicast, want.VRRPUnicast},
		{"DHCPNoPing", got.DHCPNoPing, want.DHCPNoPing},
		{"DHCPIoTDefaults", got.DHCPIoTDefaults, want.DHCPIoTDefaults},
		{"DHCPBroadcast", got.DHCPBroadcast, want.DHCPBroadcast},
		{"DHCPAuthoritative", got.DHCPAuthoritative, want.DHCPAuthoritative},
		{"DHCPLeaseTime", got.DHCPLeaseTime, want.DHCPLeaseTime},
		{"DNSMasqDisabled", got.DNSMasqDisabled, want.DNSMasqDisabled},
		{"RebalanceApprovedAt", got.RebalanceApprovedAt, want.RebalanceApprovedAt},
		{"ContentLinks", got.ContentLinks, want.ContentLinks},
	}
	for _, c := range checks {
		if !reflect.DeepEqual(c.got, c.exp) {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.exp)
		}
	}
}

func TestKeepUnshownScopeFields(t *testing.T) {
	stored := scopeWithUnshownFields()
	edited := config.ScopeConfig{Parent: "ens20", VLANID: 43, VIP: "10.0.1.1/24"}

	got := keepUnshownScopeFields(edited, stored)

	assertUnshownFieldsKept(t, got, stored)
	if got.Parent != "ens20" || got.VLANID != 43 || got.VIP != "10.0.1.1/24" {
		t.Errorf("a field the form owns was overwritten: %+v", got)
	}
}

func TestKeepUnshownScopeFields_ProbingFlag(t *testing.T) {
	tests := []struct {
		name     string
		stored   config.ScopeConfig
		edited   config.ScopeConfig
		wantFlag bool
	}{
		{"enabled scope follows the form, off", config.ScopeConfig{ProbeDisabled: false}, config.ScopeConfig{ProbeDisabled: true}, true},
		{"enabled scope follows the form, on", config.ScopeConfig{ProbeDisabled: true}, config.ScopeConfig{ProbeDisabled: false}, false},
		{"disabled scope keeps its stored flag, off", config.ScopeConfig{DNSMasqDisabled: true, ProbeDisabled: true}, config.ScopeConfig{ProbeDisabled: false}, true},
		{"disabled scope keeps its stored flag, on", config.ScopeConfig{DNSMasqDisabled: true, ProbeDisabled: false}, config.ScopeConfig{ProbeDisabled: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := keepUnshownScopeFields(tt.edited, tt.stored); got.ProbeDisabled != tt.wantFlag {
				t.Errorf("ProbeDisabled = %v, want %v", got.ProbeDisabled, tt.wantFlag)
			}
		})
	}
}

func fakeNodeWithCluster(t *testing.T, live config.Cluster) (*httptest.Server, *string) {
	t.Helper()
	var pushedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(live)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/candidate":
			body, _ := io.ReadAll(r.Body)
			pushedBody = string(body)
			w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &pushedBody
}

func TestHandleScopeConfigPost_KeepsFieldsTheFormDoesNotShow(t *testing.T) {
	stored := scopeWithUnshownFields()
	srv, pushedBody := fakeNodeWithCluster(t, config.Cluster{Scopes: map[string]config.ScopeConfig{"office": stored}})
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	form := url.Values{
		"parent": {"ens19"}, "vlan_id": {"42"}, "vip": {"10.0.0.1/24"}, "node_ip": {""},
		"dhcp_start": {"10.0.0.110"}, "dhcp_end": {"10.0.0.210"}, "gateway": {"10.0.0.1"},
		"vrrp_id": {"7"}, "preferred_worker": {"core-1"}, "client_dns_choice": {"dnshived"},
	}
	req := httptest.NewRequest(http.MethodPost, "/scopes/office/config", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("name", "office")

	handleScopeConfigPost(newConfigRef(cfg))(httptest.NewRecorder(), req)

	var pushed configPushPayload
	if err := json.Unmarshal([]byte(*pushedBody), &pushed); err != nil {
		t.Fatalf("unmarshal pushed payload: %v, body=%s", err, *pushedBody)
	}
	got := pushed.Scopes["office"]
	assertUnshownFieldsKept(t, got, stored)
	if got.DHCPRange[0] != "10.0.0.110" {
		t.Errorf("the edit itself did not apply: %+v", got.DHCPRange)
	}
	if !got.ProbeDisabled {
		t.Error("a disabled scope's probing flag changed although the checkbox was absent")
	}
}

func TestHandleScopesConfigPost_KeepsFieldsTheEditorDoesNotShow(t *testing.T) {
	stored := scopeWithUnshownFields()
	other := config.ScopeConfig{VIP: "10.0.9.1/24"}
	srv, pushedBody := fakeNodeWithCluster(t, config.Cluster{Scopes: map[string]config.ScopeConfig{"office": stored, "gone": other}})
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	form := url.Values{
		"__scope_names__":        {"office,gone"},
		"scope_delete_gone":      {"on"},
		"scope_parent_office":    {"ens19"},
		"scope_vlan_id_office":   {"99"},
		"scope_name_new_0":       {"fresh"},
		"scope_vlan_id_new_0":    {"50"},
		"scope_parent_new_0":     {"ens19"},
		"scope_vip_new_0":        {"10.0.5.1/24"},
		"scope_gateway_new_0":    {"10.0.5.1"},
		"scope_vrrp_id_new_0":    {"9"},
		"scope_dhcp_start_new_0": {"10.0.5.100"},
		"scope_dhcp_end_new_0":   {"10.0.5.200"},
	}
	req := httptest.NewRequest(http.MethodPost, "/config/scopes", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	handleScopesConfigPost(newConfigRef(cfg))(httptest.NewRecorder(), req)

	var pushed configPushPayload
	if err := json.Unmarshal([]byte(*pushedBody), &pushed); err != nil {
		t.Fatalf("unmarshal pushed payload: %v, body=%s", err, *pushedBody)
	}
	got := pushed.Scopes["office"]
	assertUnshownFieldsKept(t, got, stored)
	if !reflect.DeepEqual(got.NodeIPOverrides, stored.NodeIPOverrides) || got.ClientDNSServer != stored.ClientDNSServer {
		t.Errorf("per-node overrides or client DNS server lost: %+v", got)
	}
	if got.VLANID != 99 {
		t.Errorf("the edit itself did not apply: VLANID = %d", got.VLANID)
	}
	if _, ok := pushed.Scopes["gone"]; ok {
		t.Error("a scope marked for deletion was kept")
	}
	fresh, ok := pushed.Scopes["fresh"]
	if !ok {
		t.Fatal("the new scope is missing")
	}
	if fresh.Reservations != nil || fresh.ContentLinks != nil || fresh.DNSMasqDisabled || fresh.DHCPLeaseTime != "" {
		t.Errorf("a new scope inherited fields: %+v", fresh)
	}
}

func TestScopeDetailTmpl_ProbeCheckboxIsReadOnlyOnADisabledScope(t *testing.T) {
	render := func(sc config.ScopeConfig) string {
		var buf bytes.Buffer
		data := scopeDetailData{
			Scope: "rw-100", TargetNode: "core-1", Check: authorityCheck{Decision: "SERVE"},
			ConfigOK: true, HasProbeHost: true, EditScope: sc,
		}
		if err := scopeDetailTmpl.Execute(&buf, data); err != nil {
			t.Fatalf("scopeDetailTmpl.Execute failed: %v", err)
		}
		return buf.String()
	}
	if !strings.Contains(render(config.ScopeConfig{DNSMasqDisabled: true, ProbeDisabled: true}), `disabled title="Probing follows the scope: enable the scope first."`) {
		t.Error("the probing checkbox of a disabled scope is not read-only")
	}
	if strings.Contains(render(config.ScopeConfig{}), `Probing follows the scope`) {
		t.Error("the probing checkbox of an enabled scope is read-only")
	}
}
