// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"dnshived/internal/config"
	"dnshived/internal/webauth"
)

func TestDiffScopeFields_NoChangesIsEmpty(t *testing.T) {
	sc := config.ScopeConfig{Parent: "ens19", VLANID: 100, VIP: "10.0.0.1/24"}
	if diffs := diffScopeFields(sc, sc); len(diffs) != 0 {
		t.Errorf("diffScopeFields(x, x) = %v, want empty", diffs)
	}
}

func TestDiffScopeFields_ReportsEachChangedField(t *testing.T) {
	old := config.ScopeConfig{Parent: "ens19", VLANID: 100, VIP: "10.0.100.1/24", Gateway: "10.0.100.1", Color: "#ff0000"}
	updated := config.ScopeConfig{Parent: "ens19", VLANID: 200, VIP: "10.0.200.1/24", Gateway: "10.0.200.1", Color: "#00ff00"}
	diffs := diffScopeFields(old, updated)
	wantSubstrings := []string{"vlan_id: 100 → 200", `vip: "10.0.100.1/24" → "10.0.200.1/24"`, "color:"}
	for _, want := range wantSubstrings {
		found := false
		for _, d := range diffs {
			if strings.Contains(d, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("diffScopeFields missing expected substring %q, got %v", want, diffs)
		}
	}
	// parent/gateway... only gateway changed here besides the above.
	if len(diffs) != 4 {
		t.Errorf("diffScopeFields = %v, want exactly 4 entries (vlan_id, vip, gateway, color)", diffs)
	}
}

func TestDiffScopeFields_RebalanceApprovedAtShowsUp(t *testing.T) {
	old := config.ScopeConfig{Parent: "ens19", RebalanceApprovedAt: 0}
	updated := config.ScopeConfig{Parent: "ens19", RebalanceApprovedAt: 1790786141}
	diffs := diffScopeFields(old, updated)
	if len(diffs) != 1 {
		t.Fatalf("diffScopeFields = %v, want exactly 1 entry (rebalance approved)", diffs)
	}
	if !strings.Contains(diffs[0], "rebalance approved: never →") {
		t.Errorf("diffScopeFields = %v, want a real \"rebalance approved: never → <timestamp>\" line", diffs)
	}
	if strings.Contains(diffs[0], "1790786141") {
		t.Errorf("diffScopeFields = %v, want a formatted timestamp, not the raw Unix int", diffs)
	}
}

func TestDiffScopeFields_DNSMasqDisabledShowsUp(t *testing.T) {
	old := config.ScopeConfig{Parent: "ens19", DNSMasqDisabled: false}
	updated := config.ScopeConfig{Parent: "ens19", DNSMasqDisabled: true}
	diffs := diffScopeFields(old, updated)
	if len(diffs) != 1 || !strings.Contains(diffs[0], "dnsmasq_disabled: false → true") {
		t.Errorf("diffScopeFields = %v, want exactly 1 entry reporting dnsmasq_disabled false → true", diffs)
	}
}

func TestDiffScopeFields_LegacyNodeIPWipeAlongsideOverridesMigration(t *testing.T) {
	old := config.ScopeConfig{
		Color:  "#4477aa",
		NodeIP: "10.130.96.22/24",
	}
	updated := config.ScopeConfig{
		Color: "#e6194b",
		NodeIPOverrides: map[string]string{
			"core-1": "10.130.96.22/24",
			"core-2": "10.130.96.23/24",
		},
	}
	diffs := diffScopeFields(old, updated)

	wantSubstrings := []string{
		`node_ip: "10.130.96.22/24" → ""`,
		`node_ip_overrides.core-1: "" → "10.130.96.22/24"`,
		`node_ip_overrides.core-2: "" → "10.130.96.23/24"`,
		"color:",
	}
	for _, want := range wantSubstrings {
		found := false
		for _, d := range diffs {
			if strings.Contains(d, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("diffScopeFields missing expected substring %q, got %v", want, diffs)
		}
	}
}

func TestDiffNodeIPOverrides_NoChangeIsEmpty(t *testing.T) {
	m := map[string]string{"core-1": "10.0.0.22/24", "core-2": "10.0.0.23/24"}
	if diffs := diffNodeIPOverrides(m, m); len(diffs) != 0 {
		t.Errorf("diffNodeIPOverrides(x, x) = %v, want empty", diffs)
	}
}

func TestDiffNodeIPOverrides_OnlyChangedWorkerReported(t *testing.T) {
	old := map[string]string{"core-1": "10.0.0.22/24", "core-2": "10.0.0.23/24"}
	updated := map[string]string{"core-1": "10.0.0.22/24", "core-2": "10.0.0.99/24"}
	diffs := diffNodeIPOverrides(old, updated)
	if len(diffs) != 1 {
		t.Fatalf("diffNodeIPOverrides = %v, want exactly 1 entry (only core-2 changed)", diffs)
	}
	if !strings.Contains(diffs[0], "core-2") || !strings.Contains(diffs[0], "10.0.0.99/24") {
		t.Errorf("diffNodeIPOverrides = %v, want a core-2 line naming the new value", diffs)
	}
}

func TestDiffScopeFields_DNSAndDHCPOptionsReportLineLevelDetail(t *testing.T) {
	old := config.ScopeConfig{
		DNSRecords:  []config.DNSRecord{{Name: "a.lan.", Type: "A", Value: "1.1.1.1"}},
		DHCPOptions: []string{"option:domain-search,old.local"},
	}
	new := config.ScopeConfig{
		DNSRecords:  []config.DNSRecord{{Name: "bla.foo.bar.", Type: "A", Value: "2.2.2.2"}},
		DHCPOptions: []string{"option:domain-search,new.local"},
	}
	diffs := diffScopeFields(old, new)

	wantSubstrings := []string{
		"dns_records: removed: A|a.lan.|1.1.1.1",
		"dns_records: added: A|bla.foo.bar.|2.2.2.2",
		"dhcp_options: removed: option:domain-search,old.local",
		"dhcp_options: added: option:domain-search,new.local",
	}
	if len(diffs) != len(wantSubstrings) {
		t.Fatalf("diffs = %v, want exactly %d entries", diffs, len(wantSubstrings))
	}
	for _, want := range wantSubstrings {
		found := false
		for _, d := range diffs {
			if d == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("diffScopeFields missing expected entry %q, got %v", want, diffs)
		}
	}
}

// TestDiffScopeFields_DNSRecordUnchangedProducesNoDiff guards against a
// false positive from the new line-level diff.
func TestDiffScopeFields_DNSRecordUnchangedProducesNoDiff(t *testing.T) {
	recs := []config.DNSRecord{
		{Name: "a.lan.", Type: "A", Value: "1.1.1.1"},
		{Name: "b.lan.", Type: "A", Value: "2.2.2.2"},
	}
	old := config.ScopeConfig{DNSRecords: recs}
	new := config.ScopeConfig{DNSRecords: []config.DNSRecord{recs[1], recs[0]}} // same records, reordered
	if diffs := diffScopeFields(old, new); len(diffs) != 0 {
		t.Errorf("reordering identical records should produce no diff, got %v", diffs)
	}
}

func TestDiffScopes_AddedRemovedChanged(t *testing.T) {
	live := map[string]config.ScopeConfig{
		"office": {VLANID: 100},
		"stale":  {VLANID: 200},
	}
	candidate := map[string]config.ScopeConfig{
		"office":  {VLANID: 101}, // changed
		"new-one": {VLANID: 300}, // added
	}
	entries := diffScopes(live, candidate, nil, nil)
	if len(entries) != 3 {
		t.Fatalf("entries = %+v, want 3 (office changed, stale removed, new-one added)", entries)
	}
	byName := map[string]scopeDiffEntry{}
	for _, e := range entries {
		byName[e.Name] = e
	}
	if byName["office"].Kind != "changed" || len(byName["office"].Changes) == 0 {
		t.Errorf("office = %+v, want kind=changed with at least one field diff", byName["office"])
	}
	if byName["stale"].Kind != "removed" {
		t.Errorf("stale = %+v, want kind=removed", byName["stale"])
	}
	if byName["new-one"].Kind != "added" {
		t.Errorf("new-one = %+v, want kind=added", byName["new-one"])
	}
}

func TestDiffScopes_IdenticalIsEmpty(t *testing.T) {
	scopes := map[string]config.ScopeConfig{"office": {VLANID: 100}}
	if entries := diffScopes(scopes, scopes, nil, nil); len(entries) != 0 {
		t.Errorf("diffScopes(x, x) = %+v, want empty", entries)
	}
}

func TestDiffScopes_RenderedPreviewOnAddedAndChanged(t *testing.T) {
	live := map[string]config.ScopeConfig{
		"office": {
			Parent: "ens19", VLANID: 100, VIP: "192.168.100.1/24", NodeIP: "192.168.100.22/24",
			DHCPRange: [2]string{"192.168.100.100", "192.168.100.200"}, Gateway: "192.168.100.1",
		},
		"stale": {Parent: "ens19", VLANID: 200},
	}
	candidate := map[string]config.ScopeConfig{
		"office": {
			Parent: "ens19", VLANID: 101, VIP: "192.168.101.1/24", NodeIP: "192.168.101.22/24",
			DHCPRange: [2]string{"192.168.101.100", "192.168.101.200"}, Gateway: "192.168.101.1",
		},
		"new-one": {
			Parent: "ens19", VLANID: 30, VIP: "192.168.30.1/24", NodeIP: "192.168.30.22/24",
			DHCPRange: [2]string{"192.168.30.100", "192.168.30.200"}, Gateway: "192.168.30.1",
		},
	}
	entries := diffScopes(live, candidate, nil, nil)
	byName := map[string]scopeDiffEntry{}
	for _, e := range entries {
		byName[e.Name] = e
	}

	if !strings.Contains(byName["new-one"].RenderedPreview, "dhcp-range=set:new-one,192.168.30.100,192.168.30.200") {
		t.Errorf("new-one (added) RenderedPreview missing real content: %q", byName["new-one"].RenderedPreview)
	}
	if !strings.Contains(byName["office"].RenderedPreview, "dhcp-range=set:office,192.168.101.100,192.168.101.200") {
		t.Errorf("office (changed) RenderedPreview missing real content: %q", byName["office"].RenderedPreview)
	}
	if byName["stale"].RenderedPreview != "" {
		t.Errorf("stale (removed) should have no RenderedPreview, got %q", byName["stale"].RenderedPreview)
	}
}

func TestDiffClusterFields_DetectsChangesAndRedactsSensitiveFields(t *testing.T) {
	live := config.Cluster{PSK: "old-psk", LogLevel: "info", APITokens: []config.APIToken{{Name: "admin", Token: "abc"}}}
	candidate := config.Cluster{PSK: "new-psk", LogLevel: "debug", APITokens: []config.APIToken{{Name: "admin", Token: "xyz"}}}
	diffs := diffClusterFields(live, candidate)

	byLabel := map[string]clusterDiffEntry{}
	for _, d := range diffs {
		byLabel[d.Label] = d
	}
	if d, ok := byLabel["psk"]; !ok || strings.Contains(d.Detail, "old-psk") || strings.Contains(d.Detail, "new-psk") {
		t.Errorf("psk diff = %+v, want present but with real values redacted", d)
	}
	if d, ok := byLabel["api_tokens"]; !ok || strings.Contains(d.Detail, "abc") || strings.Contains(d.Detail, "xyz") {
		t.Errorf("api_tokens diff = %+v, want present but with real token values redacted", d)
	}
	if d, ok := byLabel["log_level"]; !ok || !strings.Contains(d.Detail, "info") || !strings.Contains(d.Detail, "debug") {
		t.Errorf("log_level diff = %+v, want real before/after values shown (not sensitive)", d)
	}
}

func TestDiffClusterFields_GlobalDNSRecordsReportsLineLevelDetail(t *testing.T) {
	live := config.Cluster{GlobalDNSRecords: []config.DNSRecord{{Name: "old.lan.", Type: "A", Value: "1.1.1.1"}}}
	candidate := config.Cluster{GlobalDNSRecords: []config.DNSRecord{
		{Name: "old.lan.", Type: "A", Value: "1.1.1.1"},
		{Name: "bla.foo.bar.", Type: "A", Value: "2.2.2.2"},
	}}
	diffs := diffClusterFields(live, candidate)

	var found *clusterDiffEntry
	for i := range diffs {
		if diffs[i].Label == "global_dns_records" {
			found = &diffs[i]
			break
		}
	}
	if found == nil {
		t.Fatal("expected a global_dns_records diff entry")
	}
	if found.Detail != "added: A|bla.foo.bar.|2.2.2.2" {
		t.Errorf("global_dns_records diff Detail = %q, want the specific added record only", found.Detail)
	}
	// Adding one record must produce exactly one diff entry, not a
	// bare "changed" covering the whole field.
	count := 0
	for _, d := range diffs {
		if d.Label == "global_dns_records" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 global_dns_records entry (one real addition), got %d", count)
	}
}

func TestDiffClusterFields_NoChangesIsEmpty(t *testing.T) {
	c := config.Cluster{PSK: "x", LogLevel: "info"}
	if diffs := diffClusterFields(c, c); len(diffs) != 0 {
		t.Errorf("diffClusterFields(x, x) = %v, want empty", diffs)
	}
}

func TestDiffClusterFields_CoreDNSFieldsReported(t *testing.T) {
	live := config.Cluster{CoreDNSAddress: "127.0.0.42", CoreDHCPAddress: "127.0.0.21", CoreDNSQueryLogging: false}
	candidate := config.Cluster{CoreDNSAddress: "127.0.0.99", CoreDHCPAddress: "127.0.0.21", CoreDNSQueryLogging: true}
	diffs := diffClusterFields(live, candidate)

	byLabel := map[string]clusterDiffEntry{}
	for _, d := range diffs {
		byLabel[d.Label] = d
	}
	if d, ok := byLabel["core_dns_address"]; !ok || !strings.Contains(d.Detail, "127.0.0.42") || !strings.Contains(d.Detail, "127.0.0.99") {
		t.Errorf("core_dns_address diff = %+v, want a real before/after entry", d)
	}
	if _, ok := byLabel["core_dhcp_address"]; ok {
		t.Error("core_dhcp_address unchanged, must not report a diff entry")
	}
	if d, ok := byLabel["core_dns_query_logging"]; !ok || !strings.Contains(d.Detail, "false") || !strings.Contains(d.Detail, "true") {
		t.Errorf("core_dns_query_logging diff = %+v, want a real before/after entry (this is the exact field that was silently invisible live)", d)
	}
}

// TestDiffClusterFields_SanityCheckDisabledReported.
func TestDiffClusterFields_SanityCheckDisabledReported(t *testing.T) {
	live := config.Cluster{SanityCheckDisabled: false}
	candidate := config.Cluster{SanityCheckDisabled: true}
	diffs := diffClusterFields(live, candidate)

	byLabel := map[string]clusterDiffEntry{}
	for _, d := range diffs {
		byLabel[d.Label] = d
	}
	if d, ok := byLabel["sanity_check_disabled"]; !ok || !strings.Contains(d.Detail, "false") || !strings.Contains(d.Detail, "true") {
		t.Errorf("sanity_check_disabled diff = %+v, want a real before/after entry", d)
	}
}

func TestRestartWarningFieldsFrom_OnlyFlagsTheFourRealRestartFields(t *testing.T) {
	live := config.Cluster{
		PSK: "old", TLSCert: "/old.pem", Platform: &config.Platform{Mgmt: "eth0"},
		LogLevel: "info", HelperSocket: "/old.sock", CoreDNSAddress: "127.0.0.42",
	}
	candidate := config.Cluster{
		PSK: "new", TLSCert: "/new.pem", Platform: &config.Platform{Mgmt: "eth1"},
		LogLevel: "debug", HelperSocket: "/new.sock", CoreDNSAddress: "127.0.0.99",
	}
	diffs := diffClusterFields(live, candidate)
	got := restartWarningFieldsFrom(diffs)

	gotSet := map[string]bool{}
	for _, f := range got {
		gotSet[f] = true
	}
	for _, want := range []string{"psk", "tls_cert / tls_key", "platform"} {
		if !gotSet[want] {
			t.Errorf("restartWarningFieldsFrom() = %v, missing %q", got, want)
		}
	}
	for _, mustNotWarn := range []string{"log_level", "helper_socket", "core_dns_address"} {
		if gotSet[mustNotWarn] {
			t.Errorf("restartWarningFieldsFrom() = %v, must NOT include %q (it's graceful now)", got, mustNotWarn)
		}
	}
}

func TestRestartWarningFieldsFrom_NoneWhenOnlyGracefulFieldsChanged(t *testing.T) {
	live := config.Cluster{LogLevel: "info"}
	candidate := config.Cluster{LogLevel: "debug"}
	diffs := diffClusterFields(live, candidate)
	if got := restartWarningFieldsFrom(diffs); len(got) != 0 {
		t.Errorf("restartWarningFieldsFrom() = %v, want empty for a log_level-only change", got)
	}
}

func candidateTestServer(t *testing.T, live config.Cluster, candidate *config.Cluster) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(live)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			if candidate == nil {
				w.Write([]byte(`{"exists":false}`))
				return
			}
			json.NewEncoder(w).Encode(candidateResponse{Exists: true, Candidate: *candidate})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/candidate":
			var upd config.Cluster
			json.NewDecoder(r.Body).Decode(&upd)
			candidate = &upd
			w.Write([]byte(`{"ok":true}`))
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/candidate"):
			candidate = nil
			w.Write([]byte(`{"status":"discarded"}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
}

func TestCurrentEditableConfig_NoCandidateFallsBackToLive(t *testing.T) {
	live := config.Cluster{LogLevel: "info"}
	srv := candidateTestServer(t, live, nil)
	defer srv.Close()

	nodes := []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}
	c, _, isPending, err := currentEditableConfig(nodes)
	if err != nil {
		t.Fatalf("currentEditableConfig: %v", err)
	}
	if isPending {
		t.Error("isPending = true, want false when no candidate exists")
	}
	if c.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want live value", c.LogLevel)
	}
}

func TestCurrentEditableConfig_PrefersExistingCandidate(t *testing.T) {
	live := config.Cluster{LogLevel: "info"}
	candidate := config.Cluster{LogLevel: "debug"}
	srv := candidateTestServer(t, live, &candidate)
	defer srv.Close()

	nodes := []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}
	c, _, isPending, err := currentEditableConfig(nodes)
	if err != nil {
		t.Fatalf("currentEditableConfig: %v", err)
	}
	if !isPending {
		t.Error("isPending = false, want true when a candidate exists")
	}
	if c.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want the CANDIDATE's value, not live", c.LogLevel)
	}
}

func TestHandlePending_NoCandidateShowsNoPendingChanges(t *testing.T) {
	srv := candidateTestServer(t, config.Cluster{}, nil)
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest(http.MethodGet, "/pending", nil)
	rec := httptest.NewRecorder()
	handlePending(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "No pending changes") {
		t.Errorf("expected 'No pending changes', got:\n%s", rec.Body.String())
	}
}

func TestHandlePending_CandidateIdenticalToLiveShowsNoActions(t *testing.T) {
	live := config.Cluster{Scopes: map[string]config.ScopeConfig{"office": {VLANID: 100}}}
	candidate := config.Cluster{Scopes: map[string]config.ScopeConfig{"office": {VLANID: 100}}} // identical
	srv := candidateTestServer(t, live, &candidate)
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest(http.MethodGet, "/pending", nil)
	rec := httptest.NewRecorder()
	handlePending(newConfigRef(cfg))(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "No pending changes") {
		t.Errorf("expected 'No pending changes' for an identical-to-live candidate, got:\n%s", body)
	}
	if strings.Contains(body, "Commit — apply to the live cluster") {
		t.Errorf("Commit button must be hidden when the candidate has no real changes, got:\n%s", body)
	}
	if strings.Contains(body, "Discard all pending changes") {
		t.Errorf("Discard button must be hidden when the candidate has no real changes, got:\n%s", body)
	}
}

func TestHandlePending_WithCandidateShowsDiffAndActions(t *testing.T) {
	live := config.Cluster{Scopes: map[string]config.ScopeConfig{"office": {VLANID: 100}}}
	candidate := config.Cluster{Scopes: map[string]config.ScopeConfig{"office": {VLANID: 200}}}
	srv := candidateTestServer(t, live, &candidate)
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest(http.MethodGet, "/pending", nil)
	rec := httptest.NewRecorder()
	handlePending(newConfigRef(cfg))(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "vlan_id: 100 → 200") {
		t.Errorf("expected the scope field diff rendered, got:\n%s", body)
	}
	if !strings.Contains(body, "Commit") || !strings.Contains(body, "Discard all pending changes") {
		t.Errorf("expected Commit/Discard actions rendered, got:\n%s", body)
	}
	if !strings.Contains(body, "Discard this change") {
		t.Errorf("expected a per-scope discard action, got:\n%s", body)
	}
	if !strings.Contains(body, `class="btn-success">Commit`) {
		t.Errorf("expected the Commit button to carry class=\"btn-success\", got:\n%s", body)
	}
	if strings.Count(body, `class="btn-danger">Discard`) < 2 {
		t.Errorf("expected both the \"Discard all\" and per-scope \"Discard this change\" buttons to carry class=\"btn-danger\", got:\n%s", body)
	}
}

func TestHandlePending_RestartRequiringFieldChangeShowsWarningBanner(t *testing.T) {
	live := config.Cluster{PSK: "old-psk"}
	candidate := config.Cluster{PSK: "new-psk"}
	srv := candidateTestServer(t, live, &candidate)
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest(http.MethodGet, "/pending", nil)
	rec := httptest.NewRecorder()
	handlePending(newConfigRef(cfg))(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "will restart the daemon") {
		t.Errorf("expected the restart warning banner for a PSK change, got:\n%s", body)
	}
	if !strings.Contains(body, "<code>psk</code>") {
		t.Errorf("expected the banner to name psk specifically, got:\n%s", body)
	}
}

func TestHandlePending_GracefulFieldChangeShowsNoWarningBanner(t *testing.T) {
	live := config.Cluster{LogLevel: "info"}
	candidate := config.Cluster{LogLevel: "debug"}
	srv := candidateTestServer(t, live, &candidate)
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest(http.MethodGet, "/pending", nil)
	rec := httptest.NewRecorder()
	handlePending(newConfigRef(cfg))(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, "will restart the daemon") {
		t.Errorf("expected NO restart warning banner for a log_level-only change, got:\n%s", body)
	}
}

func TestHandlePendingDiscard_ClearsCandidate(t *testing.T) {
	candidate := config.Cluster{LogLevel: "debug"}
	srv := candidateTestServer(t, config.Cluster{}, &candidate)
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest(http.MethodPost, "/pending/discard", nil)
	rec := httptest.NewRecorder()
	req = withAuthedUser(req, webauth.User{Name: "admin", Role: webauth.RoleAdmin})
	handlePendingDiscard(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if _, exists, err := fetchCandidate(cfg.Nodes[0]); err != nil || exists {
		t.Errorf("candidate still exists after discard: exists=%v err=%v", exists, err)
	}
}

func TestHandlePendingCommit_NoCandidateRedirectsWithoutError(t *testing.T) {
	srv := candidateTestServer(t, config.Cluster{}, nil)
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest(http.MethodPost, "/pending/commit", nil)
	rec := httptest.NewRecorder()
	req = withAuthedUser(req, webauth.User{Name: "admin", Role: webauth.RoleAdmin})
	handlePendingCommit(filepath.Join(t.TempDir(), "web.json"), newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d (redirect to /pending, nothing to commit)", rec.Code, http.StatusSeeOther)
	}
}

func TestHandlePendingCommit_SuccessPushesLiveAndClearsCandidate(t *testing.T) {
	var pushedLiveBody []byte
	var candidateCleared bool
	candidate := &config.Cluster{LogLevel: "debug", Scopes: map[string]config.ScopeConfig{"office": {VLANID: 200}}}
	live := config.Cluster{LogLevel: "info", Scopes: map[string]config.ScopeConfig{"office": {VLANID: 100}}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(live)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			if candidate == nil {
				w.Write([]byte(`{"exists":false}`))
				return
			}
			json.NewEncoder(w).Encode(candidateResponse{Exists: true, Candidate: *candidate})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/config":
			body, _ := io.ReadAll(r.Body)
			pushedLiveBody = body
			w.Write([]byte(`{"ok":true,"warnings":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/daemons/dnshived.service/restart":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/candidate":
			candidateCleared = true
			candidate = nil
			w.Write([]byte(`{"status":"discarded"}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest(http.MethodPost, "/pending/commit", nil)
	rec := httptest.NewRecorder()
	req = withAuthedUser(req, webauth.User{Name: "admin", Role: webauth.RoleAdmin})
	handlePendingCommit(filepath.Join(t.TempDir(), "web.json"), newConfigRef(cfg))(rec, req)

	if len(pushedLiveBody) == 0 {
		t.Fatal("candidate's content was never pushed to the live POST /api/v1/config path")
	}
	var pushed configPushPayload
	if err := json.Unmarshal(pushedLiveBody, &pushed); err != nil {
		t.Fatalf("unmarshal pushed live payload: %v", err)
	}
	if pushed.Scopes["office"].VLANID != 200 {
		t.Errorf("pushed live payload = %+v, want the candidate's VLANID 200", pushed.Scopes["office"])
	}
	if !candidateCleared {
		t.Error("candidate was never cleared after a fully successful commit")
	}
}

func TestCheckPendingCoherence_FlagsCandidateOnlyScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				Scopes: map[string]config.ScopeConfig{"test2": {VLANID: 42}},
			})
		case "/api/v1/candidate":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"exists": true,
				"candidate": config.Cluster{
					Scopes: map[string]config.ScopeConfig{
						"test2": {VLANID: 42},
						"test6": {VLANID: 1},
					},
				},
			})
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}

	warnings := checkPendingCoherence(cfg)
	found := false
	for _, w := range warnings {
		if strings.Contains(w, `scope "test6" exists only in the uncommitted candidate`) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a PENDING finding for test6, got: %v", warnings)
	}
}

// TestCheckPendingCoherence_NoCandidateIsQuiet pins the common case — no
// stale candidate exists, so nothing should be flagged.
func TestCheckPendingCoherence_NoCandidateIsQuiet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				Scopes: map[string]config.ScopeConfig{"test2": {VLANID: 42}},
			})
		case "/api/v1/candidate":
			json.NewEncoder(w).Encode(map[string]interface{}{"exists": false})
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}

	if warnings := checkPendingCoherence(cfg); len(warnings) != 0 {
		t.Errorf("expected no findings with no candidate, got: %v", warnings)
	}
}

func TestDiffClusterFields_LocalDomainsReported(t *testing.T) {
	live := config.Cluster{LocalDomains: []config.LocalDomain{{Name: "foo.lan", TTL: 3600}}}
	candidate := config.Cluster{LocalDomains: []config.LocalDomain{
		{Name: "foo.lan", TTL: 3600},
		{Name: "bar.lan", TTL: 60, Records: []config.LocalDomainHost{{Host: "nas1", Type: "A", Value: "10.0.0.1"}}},
	}}
	diffs := diffClusterFields(live, candidate)

	var found bool
	for _, d := range diffs {
		if d.Label == "local_domains" && strings.Contains(d.Detail, "bar.lan") {
			found = true
		}
	}
	if !found {
		t.Errorf("diffs = %+v, want a local_domains entry naming the newly-added bar.lan", diffs)
	}
}

func TestDiffClusterFields_LocalDomainsUnchangedReportsNothing(t *testing.T) {
	domains := []config.LocalDomain{{Name: "foo.lan", TTL: 3600}}
	live := config.Cluster{LocalDomains: domains}
	candidate := config.Cluster{LocalDomains: append([]config.LocalDomain(nil), domains...)}
	diffs := diffClusterFields(live, candidate)
	for _, d := range diffs {
		if d.Label == "local_domains" {
			t.Errorf("unchanged LocalDomains produced a diff entry: %+v", d)
		}
	}
}

func TestDiffClusterFields_BackupFieldsReported(t *testing.T) {
	live := config.Cluster{}
	candidate := config.Cluster{
		BackupEnabled: true, BackupIntervalHours: 12, BackupRetentionCount: 14,
		BackupPassword: "hunter2", BackupReplicateToPeers: true,
	}
	diffs := diffClusterFields(live, candidate)

	byLabel := map[string]clusterDiffEntry{}
	for _, d := range diffs {
		byLabel[d.Label] = d
	}
	if d, ok := byLabel["backup_enabled"]; !ok || !strings.Contains(d.Detail, "true") {
		t.Errorf("backup_enabled diff = %+v, want a real before/after entry", d)
	}
	if d, ok := byLabel["backup_interval_hours"]; !ok || !strings.Contains(d.Detail, "12") {
		t.Errorf("backup_interval_hours diff = %+v, want a real before/after entry", d)
	}
	if d, ok := byLabel["backup_retention_count"]; !ok || !strings.Contains(d.Detail, "14") {
		t.Errorf("backup_retention_count diff = %+v, want a real before/after entry", d)
	}
	if d, ok := byLabel["backup_password"]; !ok || strings.Contains(d.Detail, "hunter2") {
		t.Errorf("backup_password diff = %+v, want a changed entry that does NOT leak the actual password", d)
	}
	if d, ok := byLabel["backup_replicate_to_peers"]; !ok || !strings.Contains(d.Detail, "true") {
		t.Errorf("backup_replicate_to_peers diff = %+v, want a real before/after entry", d)
	}
}

func TestDiffClusterFields_BackupFieldsUnchangedReportsNothing(t *testing.T) {
	c := config.Cluster{BackupEnabled: true, BackupIntervalHours: 12, BackupRetentionCount: 14, BackupPassword: "x", BackupReplicateToPeers: true}
	diffs := diffClusterFields(c, c)
	for _, d := range diffs {
		if strings.HasPrefix(d.Label, "backup_") {
			t.Errorf("unchanged backup fields produced a diff entry: %+v", d)
		}
	}
}

func TestDiffClusterFields_LocalDomainsUnlinkReported(t *testing.T) {
	live := config.Cluster{LocalDomains: []config.LocalDomain{{Name: "fork.lan", TTL: 60, ForkedFrom: "foo.lan"}}}
	candidate := config.Cluster{LocalDomains: []config.LocalDomain{{Name: "fork.lan", TTL: 60}}}
	diffs := diffClusterFields(live, candidate)

	var found bool
	for _, d := range diffs {
		if d.Label == "local_domains" {
			found = true
		}
	}
	if !found {
		t.Errorf("diffs = %+v, want a local_domains entry for the unlink (ForkedFrom cleared)", diffs)
	}
}
