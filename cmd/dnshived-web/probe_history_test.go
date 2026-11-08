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
	"time"
)

func historyProbe(t *testing.T, recs []historyRecord, set historySettings) (*httptest.Server, *url.Values) {
	t.Helper()
	var last url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/history" {
			http.NotFound(w, r)
			return
		}
		last = r.URL.Query()
		json.NewEncoder(w).Encode(historyResponse{Records: recs, Settings: set, SizeBytes: 3 << 20, Dropped: 2})
	}))
	t.Cleanup(srv.Close)
	return srv, &last
}

func cfgFor(srv *httptest.Server) *configRef {
	return newConfigRef(&WebConfig{ProbeHosts: []NodeConfig{{Name: "probe", Addr: strings.TrimPrefix(srv.URL, "http://")}}})
}

var histOn = historySettings{DHCP: "all", DNS: "failures", Syslog: true, MaxFileMB: 25, MaxFiles: 4, MaxAgeDays: 7}

func sampleRecords() []historyRecord {
	now := time.Now()
	return []historyRecord{
		{Time: now, Scope: "scope-001", Leg: "dhcp", Outcome: "recovered", Verdict: "ok", Servers: []string{"10.0.0.22"}, OfferMS: 3012, FailingForMS: 95000},
		{Time: now.Add(-time.Minute), Scope: "scope-001", Leg: "dhcp", Outcome: "failed", Verdict: "no_answer", Reason: "no answer", Flags: []string{"retried"}},
		{Time: now.Add(-2 * time.Minute), Scope: "=cmd|calc", Leg: "dns", Outcome: "failed", Checks: []historyCheck{{Name: "claude.ai.", Type: "A", Against: "10.0.0.22", Error: "timeout"}}},
	}
}

func TestHistoryRows_ClassesDetailsAndRecoveryDuration(t *testing.T) {
	rows := historyRows(sampleRecords())
	if rows[0].Class != "ok" || rows[0].Failing != "1m35s" || !strings.Contains(rows[0].Detail, "offer after 3012 ms") {
		t.Errorf("recovered row %+v", rows[0])
	}
	if rows[1].Class != "crit" || !strings.Contains(rows[1].Detail, "no_answer; no answer") || rows[1].Flags != "retried" {
		t.Errorf("failed dhcp row %+v", rows[1])
	}
	if !strings.Contains(rows[2].Detail, "claude.ai. A @10.0.0.22: timeout") {
		t.Errorf("failed dns row %+v, want the failing check named with the core it asked", rows[2])
	}
}

func TestHandleProbeHistory_PassesFiltersToTheProbeAndRendersTheRows(t *testing.T) {
	srv, got := historyProbe(t, sampleRecords(), histOn)
	w := httptest.NewRecorder()

	handleProbeHistory(cfgFor(srv))(w, httptest.NewRequest(http.MethodGet, "/probes/history?scope=scope-001&leg=dhcp&outcome=failures&range=6h", nil))

	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "no_answer; no answer") || !strings.Contains(body, "3.0 MB on disk") || !strings.Contains(body, "2 dropped") {
		t.Fatalf("status %d, body missing rows, size or the dropped count: %.300s", w.Code, body)
	}
	q := *got
	if q.Get("scope") != "scope-001" || q.Get("leg") != "dhcp" || q.Get("outcome") != "failures" || q.Get("limit") != "200" {
		t.Errorf("probe query %v, want the filters passed on", q)
	}
	since, err := time.Parse(time.RFC3339Nano, q.Get("since"))
	if err != nil || time.Since(since) < 5*time.Hour || time.Since(since) > 7*time.Hour {
		t.Errorf("since %q, want about six hours ago", q.Get("since"))
	}
}

func TestHandleProbeHistory_OffAndErrorsAreSaidPlainly(t *testing.T) {
	srv, _ := historyProbe(t, nil, historySettings{DHCP: "none", DNS: "none"})
	w := httptest.NewRecorder()
	handleProbeHistory(cfgFor(srv))(w, httptest.NewRequest(http.MethodGet, "/probes/history", nil))
	if !strings.Contains(w.Body.String(), "History is switched off for this probe host") {
		t.Error("an off history must say so and link to the setting")
	}
	old := httptest.NewServer(http.NotFoundHandler())
	defer old.Close()
	w = httptest.NewRecorder()
	handleProbeHistory(cfgFor(old))(w, httptest.NewRequest(http.MethodGet, "/probes/history", nil))
	if !strings.Contains(w.Body.String(), "needs an upgrade") {
		t.Error("a probe without the feature must say it needs an upgrade")
	}
	w = httptest.NewRecorder()
	handleProbeHistory(cfgFor(srv))(w, httptest.NewRequest(http.MethodGet, "/probes/history?leg=bogus", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400 for a bad leg", w.Code)
	}
}

func TestHandleProbeHistory_CSVNeutralisesFormulasAndKeepsFiltersInTheLinks(t *testing.T) {
	srv, _ := historyProbe(t, sampleRecords(), histOn)
	w := httptest.NewRecorder()
	handleProbeHistory(cfgFor(srv))(w, httptest.NewRequest(http.MethodGet, "/probes/history?format=csv", nil))
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/csv") || !strings.Contains(w.Header().Get("Content-Disposition"), "probe-history.csv") {
		t.Fatalf("status %d headers %v", w.Code, w.Header())
	}
	if !strings.Contains(w.Body.String(), "'=cmd|calc") || strings.Contains(w.Body.String(), ",=cmd|calc") {
		t.Errorf("a scope starting with = must not reach a spreadsheet as a formula: %q", w.Body.String())
	}
	full := make([]historyRecord, 200)
	for i := range full {
		full[i] = historyRecord{Time: time.Now().Add(-time.Duration(i) * time.Second), Scope: "s", Leg: "dns", Outcome: "ok"}
	}
	srv2, _ := historyProbe(t, full, histOn)
	w = httptest.NewRecorder()
	handleProbeHistory(cfgFor(srv2))(w, httptest.NewRequest(http.MethodGet, "/probes/history?leg=dns&range=7d", nil))
	if !strings.Contains(w.Body.String(), "older &rarr;") || !strings.Contains(w.Body.String(), "until=") || !strings.Contains(w.Body.String(), "format=csv") {
		t.Error("a full page must offer older results, keeping the filters, and a CSV link")
	}
}

func TestHandleProbeHistorySettings_PostsOnlyWhatWasFilledIn(t *testing.T) {
	var got map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	form := url.Values{"addr": {addr}, "dhcp": {"failures"}, "dns": {"none"}, "syslog": {"on"}, "max_files": {"8"}}
	r := httptest.NewRequest(http.MethodPost, "/probes/history", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handleProbeHistorySettings(cfgFor(srv))(w, r)

	h, _ := got["history"].(map[string]interface{})
	if w.Code != http.StatusSeeOther || h["dhcp"] != "failures" || h["dns"] != "none" || h["syslog"] != true || h["max_files"].(float64) != 8 {
		t.Fatalf("status %d patch %v", w.Code, got)
	}
	if _, set := h["max_file_mb"]; set {
		t.Error("an empty limit must be left out so the probe keeps its default")
	}
	form.Set("max_age_days", "many")
	r = httptest.NewRequest(http.MethodPost, "/probes/history", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handleProbeHistorySettings(cfgFor(srv))(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400 for a limit that is not a number", w.Code)
	}
}

func TestProbesTmpl_HistorySettingsForm(t *testing.T) {
	data := probesPageData{ProbeHostNames: []string{"probe"}, probeManagementData: probeManagementData{
		ProbeHostDisplayNames: map[string]string{},
		HistoryHosts: []historyHostRow{{Name: "probe", Addr: "192.0.2.5:9444", Size: "3.0 MB", Dropped: 2,
			Settings: historySettings{DHCP: "failures", DNS: "none", Syslog: true, MaxFileMB: 25, MaxFiles: 4, MaxAgeDays: 7}}},
	}}
	var b strings.Builder
	if err := probesTmpl.Execute(&b, data); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{`id="history"`, `action="/probes/history"`, `name="dhcp" value="failures" checked`, `name="dns" value="none" checked`,
		`name="syslog" checked`, `name="max_files" min="1" max="50" value="4"`, "3.0 MB on disk", "2 record(s) dropped", "a lot of data"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q", want)
		}
	}
}

func TestProbeDetail_ShowsRecentHistoryOrSaysWhyNot(t *testing.T) {
	srv, _ := historyProbe(t, sampleRecords()[:2], histOn)
	host := NodeConfig{Name: "probe", Addr: strings.TrimPrefix(srv.URL, "http://")}
	d := probeDetailData{Scope: "scope-001", Worker: "probe"}
	attachScopeHistory(&d, host)
	var b strings.Builder
	if err := probeDetailFragmentTmpl.ExecuteTemplate(&b, "fragment", d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "<h2>Recent history</h2>") || !strings.Contains(b.String(), "no_answer; no answer") || !strings.Contains(b.String(), "/probes/history?scope=scope-001") {
		t.Errorf("detail %q, want the recent results and a link to the full history", b.String())
	}
	off, _ := historyProbe(t, nil, historySettings{DHCP: "none", DNS: "none"})
	d2 := probeDetailData{Scope: "x", Worker: "probe"}
	attachScopeHistory(&d2, NodeConfig{Name: "probe", Addr: strings.TrimPrefix(off.URL, "http://")})
	if !d2.HistoryOff {
		t.Error("an off history must be flagged so the page can say so")
	}
}
