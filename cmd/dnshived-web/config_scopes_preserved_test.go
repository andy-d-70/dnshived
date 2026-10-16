// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"dnshived/internal/config"
)

func fakeCandidateNode(t *testing.T, live config.Cluster) (*httptest.Server, *config.Cluster) {
	t.Helper()
	var pushed config.Cluster
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			json.NewEncoder(w).Encode(map[string]any{"exists": false})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(live)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/candidate":
			if err := json.NewDecoder(r.Body).Decode(&pushed); err != nil {
				t.Errorf("decode pushed candidate: %v", err)
			}
			json.NewEncoder(w).Encode(map[string]any{"ok": true})
		default:
			http.NotFound(w, r)
		}
	}))
	return srv, &pushed
}

func nodeConfigFor(t *testing.T, srv *httptest.Server) NodeConfig {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	return NodeConfig{Name: "test-node", Addr: u.Host}
}

func testClusterWithScopes() config.Cluster {
	return config.Cluster{
		Scopes: map[string]config.ScopeConfig{
			"office": {Parent: "ens19", VLANID: 42, NodeIP: "192.168.10.22/24"},
		},
	}
}

func TestHandleDNSConfigPost_PreservesExistingScopes(t *testing.T) {
	live := testClusterWithScopes()
	srv, pushed := fakeCandidateNode(t, live)
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}
	form := strings.NewReader("default_dns_checks=&global_dns_records=A%7Cwww.example.local%7C10.0.0.1")
	r := httptest.NewRequest(http.MethodPost, "/config/dns", form)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handleDNSConfigPost(newConfigRef(cfg))(w, r)

	if w.Code >= 400 {
		t.Fatalf("handler returned HTTP %d: %s", w.Code, w.Body.String())
	}
	if len(pushed.Scopes) != 1 {
		t.Errorf("pushed candidate has %d scope(s), want 1 (existing scopes must survive a DNS-defaults save); got: %+v",
			len(pushed.Scopes), pushed.Scopes)
	}
	if _, ok := pushed.Scopes["office"]; !ok {
		t.Errorf("pushed candidate is missing the real, pre-existing \"office\" scope entirely")
	}
}

// TestHandleDHCPConfigPost_PreservesExistingScopes mirrors the DNS-side
// test — handleDHCPConfigPost had the identical gap.
func TestHandleDHCPConfigPost_PreservesExistingScopes(t *testing.T) {
	live := testClusterWithScopes()
	srv, pushed := fakeCandidateNode(t, live)
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}
	form := strings.NewReader("default_dhcp_options=" + url.QueryEscape("option:dns-server,1.1.1.1"))
	r := httptest.NewRequest(http.MethodPost, "/config/dhcp", form)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handleDHCPConfigPost(newConfigRef(cfg))(w, r)

	if w.Code >= 400 {
		t.Fatalf("handler returned HTTP %d: %s", w.Code, w.Body.String())
	}
	if len(pushed.Scopes) != 1 {
		t.Errorf("pushed candidate has %d scope(s), want 1 (existing scopes must survive a DHCP-defaults save); got: %+v",
			len(pushed.Scopes), pushed.Scopes)
	}
	if _, ok := pushed.Scopes["office"]; !ok {
		t.Errorf("pushed candidate is missing the real, pre-existing \"office\" scope entirely")
	}
}

func TestHandleDNSConfigPost_PreservesLiveDNSRelayCacheSettings(t *testing.T) {
	live := testClusterWithScopes()
	live.DNSRelayCacheSize = 12000
	live.DNSRelayCacheMaxBytes = 8388608
	srv, pushed := fakeCandidateNode(t, live)
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}
	form := strings.NewReader("default_dns_checks=&global_dns_records=A%7Cwww.example.local%7C10.0.0.1")
	r := httptest.NewRequest(http.MethodPost, "/config/dns", form)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handleDNSConfigPost(newConfigRef(cfg))(w, r)

	if w.Code >= 400 {
		t.Fatalf("handler returned HTTP %d: %s", w.Code, w.Body.String())
	}
	if pushed.DNSRelayCacheSize != 12000 {
		t.Errorf("pushed DNSRelayCacheSize = %d, want the preserved live value 12000", pushed.DNSRelayCacheSize)
	}
	if pushed.DNSRelayCacheMaxBytes != 8388608 {
		t.Errorf("pushed DNSRelayCacheMaxBytes = %d, want the preserved live value 8388608", pushed.DNSRelayCacheMaxBytes)
	}
}

func TestHandleDNSConfigPost_PreservesLiveDefaultDNSChecks(t *testing.T) {
	live := testClusterWithScopes()
	live.DefaultDNSChecks = []config.DNSCheck{{Name: "example.com.", Type: "A"}}
	srv, pushed := fakeCandidateNode(t, live)
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}
	form := strings.NewReader("global_dns_records=" + url.QueryEscape("A|www.example.local|10.0.0.1"))
	r := httptest.NewRequest(http.MethodPost, "/config/dns", form)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handleDNSConfigPost(newConfigRef(cfg))(w, r)

	if w.Code >= 400 {
		t.Fatalf("handler returned HTTP %d: %s", w.Code, w.Body.String())
	}
	if len(pushed.DefaultDNSChecks) != 1 || pushed.DefaultDNSChecks[0].Name != "example.com." {
		t.Errorf("live DefaultDNSChecks not preserved by a GlobalDNSRecords-only save: %+v", pushed.DefaultDNSChecks)
	}
}

// TestHandleProbeSettingsPost_PreservesLiveClusterFieldsUnedited pins the
// new /probes/settings handler's own safety property.
func TestHandleProbeSettingsPost_PreservesLiveClusterFieldsUnedited(t *testing.T) {
	live := testClusterWithScopes()
	live.GlobalDNSRecords = []config.DNSRecord{{Name: "fileserver.lan", Type: "A", Value: "10.0.0.50"}}
	live.ProbeIntervalMS = 5000
	srv, pushed := fakeCandidateNode(t, live)
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}
	form := url.Values{
		"default_dns_checks": {"example.com.|A"},
		"probe_interval_ms":  {"9000"},
	}
	r := httptest.NewRequest(http.MethodPost, "/probes/settings", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handleProbeSettingsPost(newConfigRef(cfg))(w, r)

	if w.Code >= 400 {
		t.Fatalf("handler returned HTTP %d: %s", w.Code, w.Body.String())
	}
	if len(pushed.Scopes) != 1 {
		t.Errorf("pushed candidate has %d scope(s), want 1 (existing scopes must survive a probe-settings save); got: %+v",
			len(pushed.Scopes), pushed.Scopes)
	}
	if len(pushed.GlobalDNSRecords) != 1 || pushed.GlobalDNSRecords[0].Name != "fileserver.lan" {
		t.Errorf("live GlobalDNSRecords not preserved: %+v", pushed.GlobalDNSRecords)
	}
	if len(pushed.DefaultDNSChecks) != 1 || pushed.DefaultDNSChecks[0].Name != "example.com." {
		t.Errorf("edited DefaultDNSChecks not applied: %+v", pushed.DefaultDNSChecks)
	}
	if pushed.ProbeIntervalMS != 9000 {
		t.Errorf("edited ProbeIntervalMS not applied: got %d, want 9000", pushed.ProbeIntervalMS)
	}
}
