// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func renderScopes(t *testing.T, rows []scopeRow, probeHosts bool) string {
	t.Helper()
	data := scopesPageData{Rows: rows, Total: len(rows), Page: 1, TotalPages: 1, HasProbeHosts: probeHosts,
		Headers: scopeSortHeaders("scope", false, nil, probeHosts)}
	var b strings.Builder
	if err := scopesTmpl.Execute(&b, data); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestScopesTmpl_RowActionsLiveInOneMenu(t *testing.T) {
	out := renderScopes(t, []scopeRow{
		{Name: "alpha", Display: "alpha"},
		{Name: "beta", Display: "beta", Disabled: true},
	}, false)
	for _, want := range []string{
		`<details class="row-menu">`, `aria-haspopup="menu"`,
		`href="/scopes/alpha"`, `action="/scopes/alpha/toggle-disabled"`, `action="/scopes/alpha/rebalance"`, `action="/scopes/alpha/delete"`,
		"Disable</button>", "Enable</button>", "Rebalance to preferred core", `class="danger"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in the row menu", want)
		}
	}
	for _, old := range []string{`class="btn-danger">delete`, `class="btn-warn">disable`, `class="btn-success">enable`} {
		if strings.Contains(out, old) {
			t.Errorf("the old button %q must be gone from the row", old)
		}
	}
	if strings.Count(out, `class="row-menu"`) != 2 {
		t.Errorf("want one menu per row, got %d", strings.Count(out, `class="row-menu"`))
	}
	for _, confirm := range []string{"stage a pending change on every configured node (disable scope alpha)", "stage a pending change on every configured node (enable scope beta)", "Really delete scope alpha", "rebalance of scope alpha"} {
		if !strings.Contains(strings.ReplaceAll(out, "&#39;", "'"), confirm) && !strings.Contains(out, confirm) {
			t.Errorf("the confirm text %q must stay on its action", confirm)
		}
	}
}

func TestScopesTmpl_RebalanceAllIsQuietRightAlignedAndSaysItIsAPendingChange(t *testing.T) {
	out := renderScopes(t, []scopeRow{{Name: "alpha", Display: "alpha"}}, false)
	for _, want := range []string{`class="btn-quiet"`, "(pending change)", `action="/scopes/rebalance-all"`, "justify-content:space-between", "not a trivial change"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q", want)
		}
	}
	if strings.Contains(renderScopes(t, nil, false), `action="/scopes/rebalance-all"`) {
		t.Error("without scopes there is nothing to rebalance")
	}
}

func TestScopesAndProbesPages_CarryTheProbeDetailPopup(t *testing.T) {
	cell := []probeCellData{{Scope: "alpha", Worker: "probe", DNSText: "DNS✔", DNSClass: "ok"}}
	scopes := renderScopes(t, []scopeRow{{Name: "alpha", Display: "alpha", ProbeCells: cell}}, true)
	for _, want := range []string{`<dialog id="probe-dialog"`, `class="dim probe-detail"`, `class="probe-now-form"`, `a.probe-detail`, "fragment=1"} {
		if !strings.Contains(scopes, want) {
			t.Errorf("scope list: expected %q", want)
		}
	}
	var b strings.Builder
	data := probesPageData{ProbeHostNames: []string{"probe"}, Rows: []probeRow{{Scope: "alpha", ProbeHostCells: cell}},
		probeManagementData: probeManagementData{ProbeHostDisplayNames: map[string]string{}}}
	if err := probesTmpl.Execute(&b, data); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `<dialog id="probe-dialog"`) || !strings.Contains(b.String(), `class="dim probe-detail"`) {
		t.Error("the Probes page needs the same popup")
	}
}

func TestProbeDetailFragment_IsTheContentWithoutThePage(t *testing.T) {
	data := probeDetailData{Scope: "alpha", Worker: "probe", Enabled: true, Reachable: true, ProbedAt: "2026-11-08 10:00:00 CET",
		DHCPVerdict: "ok", DHCPValid: true, DNSAnswered: true, DNSValid: true, BackHref: "/probes", BackText: "back to Probes"}
	var frag, page strings.Builder
	if err := probeDetailFragmentTmpl.ExecuteTemplate(&frag, "fragment", data); err != nil {
		t.Fatal(err)
	}
	if err := probeDetailTmpl.Execute(&page, data); err != nil {
		t.Fatal(err)
	}
	f := frag.String()
	for _, want := range []string{"Probe detail: alpha", `class="probe-now-form"`, `action="/probes/alpha/probe/refresh"`, "<h2>DHCP</h2>", "<h2>DNS</h2>", "Probed at: 2026-11-08"} {
		if !strings.Contains(f, want) {
			t.Errorf("fragment: expected %q", want)
		}
	}
	for _, not := range []string{"<!doctype", "<nav", "back to Probes"} {
		if strings.Contains(f, not) {
			t.Errorf("fragment must not carry the page chrome (%q)", not)
		}
	}
	p := page.String()
	if !strings.Contains(p, "<h2>DHCP</h2>") || !strings.Contains(p, "<!doctype") || !strings.Contains(p, "back to Probes") {
		t.Error("the full page must be unchanged: chrome plus the same body")
	}
}

func TestHandleProbeDetail_FragmentModeReturnsOnlyTheFragment(t *testing.T) {
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"scope": "alpha", "enabled": true, "reachable": true,
			"dhcp": map[string]interface{}{"verdict": "ok", "valid": true}, "dns": map[string]interface{}{"answered": true, "valid": true}})
	}))
	defer probe.Close()
	ref := newConfigRef(&WebConfig{ProbeHosts: []NodeConfig{{Name: "probe", Addr: strings.TrimPrefix(probe.URL, "http://")}}})
	mux := http.NewServeMux()
	mux.HandleFunc("/probes/{scope}/{worker}", handleProbeDetail(ref))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/probes/alpha/probe?fragment=1", nil))

	body := rec.Body.String()
	if rec.Code != http.StatusOK || strings.Contains(body, "<!doctype") || !strings.Contains(body, "Probe detail: alpha") || !strings.Contains(body, "<h2>DHCP</h2>") {
		t.Fatalf("status %d body %q, want the bare fragment", rec.Code, body)
	}
}
