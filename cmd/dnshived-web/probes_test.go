// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"encoding/json"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"dnshived/internal/config"
)

func TestProbesTmpl_RendersWithProbeHostColumns(t *testing.T) {
	data := probesPageData{
		Total:          1,
		Page:           1,
		TotalPages:     1,
		NextRefreshAt:  "12:00:00",
		ProbeHostNames: []string{"probe-a", "probe-b"},
		Rows: []probeRow{
			{
				Scope: "office",
				ProbeHostCells: []probeCellData{
					{DNSText: "DNS✔", DNSClass: "ok", DHCPText: "DHCP✔", DHCPClass: "ok"},
					{DNSText: "DNS✖", DNSClass: "crit", DHCPText: "DHCP-NONE", DHCPClass: "crit", Note: "unreachable"},
				},
			},
		},
	}
	var buf bytes.Buffer
	if err := probesTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("probesTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "from probe-a") || !strings.Contains(out, "from probe-b") {
		t.Error("expected probe-host column headers to render")
	}
	if !strings.Contains(out, "DNS✖") || !strings.Contains(out, "DHCP-NONE") || !strings.Contains(out, "unreachable") {
		t.Error("expected probe-b's cell content and note to render")
	}
}

func TestProbesTmpl_SettingsRenderAboveResults(t *testing.T) {
	data := probesPageData{
		Total: 1, Page: 1, TotalPages: 1, NextRefreshAt: "12:00:00",
		ProbeHostNames: []string{"probe-a"},
		Rows:           []probeRow{{Scope: "office", ProbeHostCells: []probeCellData{{DNSText: "DNS✔", DNSClass: "ok"}}}},
	}
	var buf bytes.Buffer
	if err := probesTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("probesTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	settingsIdx := strings.Index(out, `id="settings"`)
	resultsIdx := strings.Index(out, `id="results"`)
	if settingsIdx == -1 || resultsIdx == -1 {
		t.Fatalf("expected both the settings and results sections to render, got:\n%s", out)
	}
	if !(settingsIdx < resultsIdx) {
		t.Errorf("expected settings to render ABOVE results, got settingsIdx=%d resultsIdx=%d", settingsIdx, resultsIdx)
	}
}

func TestProbesTmpl_RendersErrorCount(t *testing.T) {
	data := probesPageData{
		Total: 3, ErrorCount: 2, Page: 1, TotalPages: 1, NextRefreshAt: "12:00:00",
	}
	var buf bytes.Buffer
	if err := probesTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("probesTmpl.Execute failed: %v", err)
	}
	if !strings.Contains(buf.String(), "2 error(s)") {
		t.Errorf("expected \"2 error(s)\" in rendered output, got: %s", buf.String())
	}
}

func TestNoProbeHostTmpl_SaysSoAndStillOffersToAddOne(t *testing.T) {
	var buf bytes.Buffer
	data := noProbeHostPageData{probeManagementData: probeManagementData{ProbeHostDisplayNames: map[string]string{}}}
	if err := noProbeHostTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("noProbeHostTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "No probe host configured") {
		t.Error("expected a \"No probe host configured\" message")
	}
	if !strings.Contains(out, `action="/nodes/probe/add"`) {
		t.Error("expected the Add probe form to still be reachable with zero probe hosts configured")
	}
	if strings.Contains(out, "<table") {
		t.Error("expected no RESULTS table when no probe host is configured (the management section's own forms have no table to show either, at zero hosts)")
	}
}

// Test cases ported from cmd/dnshived-top/main_test.go — same logic,
// ANSI colors replaced with CSS classes.

func TestProbeClass_Pending(t *testing.T) {
	text, class := probeClass(probeResult{}, false)
	if text != "pending..." {
		t.Errorf("text = %q, want %q", text, "pending...")
	}
	if class != "dim" {
		t.Errorf("class = %q, want dim", class)
	}
}

func TestProbeClass_DisabledScopeIsDimNotFailure(t *testing.T) {
	pr := probeResult{Scope: "rw-100", Enabled: false, Reachable: true}
	text, class := probeClass(pr, true)
	if class != "dim" {
		t.Errorf("class = %q, want dim for a disabled scope, not a failure class", class)
	}
	if text != "probe off" {
		t.Errorf("text = %q, want %q", text, "probe off")
	}
}

func TestProbeClass_TransportErrorNotMisreportedAsDisabled(t *testing.T) {
	pr := probeResult{Scope: "rw-100", Enabled: false, Reachable: true}
	pr.DHCP.Error = "connection refused"
	pr.DNS.Error = "connection refused"
	text, class := probeClass(pr, true)
	if text == "probe off" {
		t.Error("a transport error must not render as \"disabled\" — those are different signals")
	}
	if class != "dim" || text != "DNS? DHCP?" {
		t.Errorf("got (%q, %q), want (\"DNS? DHCP?\", \"dim\")", text, class)
	}
}

func TestProbeClass_UnreachableIsNotMisreportedAsDisabled(t *testing.T) {
	pr := probeResult{Scope: "dgdgdgddgd", Enabled: false, Reachable: false}
	text, class := probeClass(pr, true)
	if text == "probe off" {
		t.Error("an unreachable scope (no VLAN coverage yet) must not render as \"disabled\" — those are different signals")
	}
	if text != "no coverage" || class != "dim" {
		t.Errorf("got (%q, %q), want (\"no coverage\", \"dim\")", text, class)
	}
}

func TestProbeClassParts_UnreachableIsNotMisreportedAsDisabled(t *testing.T) {
	pr := probeResult{Scope: "dgdgdgddgd", Enabled: false, Reachable: false}
	dnsText, dnsClass, dhcpText, dhcpClass := probeClassParts(pr, true, false)
	if dnsText == "probe off" {
		t.Error("an unreachable scope must not render as \"disabled\" here either")
	}
	if dnsText != "no coverage" || dnsClass != "dim" || dhcpText != "" || dhcpClass != "" {
		t.Errorf("got (%q, %q, %q, %q), want (\"no coverage\", \"dim\", \"\", \"\")", dnsText, dnsClass, dhcpText, dhcpClass)
	}
}

func TestProbeClass_BothOK(t *testing.T) {
	var pr probeResult
	pr.Enabled = true
	pr.Reachable = true
	pr.DNS.Answered = true
	pr.DNS.Valid = true
	pr.DHCP.Verdict = "ok"

	text, class := probeClass(pr, true)
	if class != "ok" {
		t.Errorf("class = %q, want ok for a fully healthy result", class)
	}
	if text != "DNS✔ DHCP✔" {
		t.Errorf("text = %q, want %q", text, "DNS✔ DHCP✔")
	}
}

func TestProbeClass_DHCPNoAnswerIsNotHealthy(t *testing.T) {
	var pr probeResult
	pr.Enabled = true
	pr.Reachable = true
	pr.DNS.Answered = true
	pr.DNS.Valid = true
	pr.DHCP.Verdict = "no_answer"

	_, class := probeClass(pr, true)
	if class != "crit" {
		t.Errorf("class = %q, want crit — no_answer means nothing on the segment answered, as serious as dual-active", class)
	}
}

func TestProbeClass_DualActiveIsCritRegardlessOfDNS(t *testing.T) {
	var pr probeResult
	pr.Enabled = true
	pr.Reachable = true
	pr.DNS.Answered = true
	pr.DNS.Valid = true
	pr.DHCP.Verdict = "dual_active"

	text, class := probeClass(pr, true)
	if class != "crit" {
		t.Errorf("class = %q, want crit — dual-active must always dominate the cell's class", class)
	}
	if text != "DNS✔ DHCP✖DUAL" {
		t.Errorf("text = %q, want it to include DHCP✖DUAL", text)
	}
}

func TestProbeClass_TransportErrorIsDimNotCrit(t *testing.T) {
	var pr probeResult
	pr.Reachable = true
	pr.DNS.Error = "connection refused"
	pr.DHCP.Error = "connection refused"

	text, class := probeClass(pr, true)
	if class != "dim" {
		t.Errorf("class = %q, want dim for a transport-level error, not crit", class)
	}
	if text != "DNS? DHCP?" {
		t.Errorf("text = %q, want %q", text, "DNS? DHCP?")
	}
}

func TestProbeClass_DNSDownButDHCPOKIsWarn(t *testing.T) {
	var pr probeResult
	pr.Enabled = true
	pr.Reachable = true
	pr.DNS.Answered = false
	pr.DHCP.Verdict = "ok"

	_, class := probeClass(pr, true)
	if class != "warn" {
		t.Errorf("class = %q, want warn — a partial failure (DNS down, DHCP fine) isn't as severe as dual-active but isn't fully healthy either", class)
	}
}

func TestProbeClassParts_ConfirmedMismatchDowngradesOkToWarn(t *testing.T) {
	var pr probeResult
	pr.Enabled = true
	pr.Reachable = true
	pr.DNS.Answered = true
	pr.DNS.Valid = true
	pr.DHCP.Verdict = "ok"

	_, _, dhcpText, dhcpClass := probeClassParts(pr, true, true)
	if dhcpText != "DHCP✔" {
		t.Errorf("dhcpText = %q, want DHCP✔ (verdict text unchanged, only the class reflects the mismatch)", dhcpText)
	}
	if dhcpClass != "warn" {
		t.Errorf("dhcpClass = %q, want warn for a confirmed mismatch", dhcpClass)
	}
}

func TestProbeClassParts_DualActiveStaysCritRegardlessOfMismatchFlag(t *testing.T) {
	var pr probeResult
	pr.Enabled = true
	pr.Reachable = true
	pr.DNS.Answered = true
	pr.DNS.Valid = true
	pr.DHCP.Verdict = "dual_active"

	_, _, _, dhcpClass := probeClassParts(pr, true, true)
	if dhcpClass != "crit" {
		t.Errorf("dhcpClass = %q, want crit — dual-active must never be downgraded to warn", dhcpClass)
	}
}

// confirmProbeMismatches tests.
func TestConfirmProbeMismatches_SingleObservationNotSurfaced(t *testing.T) {
	mismatches := map[string]bool{"av-dante|core-2": true}
	confirmedLines, confirmedKeys := confirmProbeMismatches(mismatches, nil)
	if len(confirmedLines) != 0 {
		t.Errorf("confirmed = %v, want none — a single observation must not be surfaced", confirmedLines)
	}
	if len(confirmedKeys) != 0 {
		t.Errorf("confirmedKeys = %v, want none", confirmedKeys)
	}
}

func TestConfirmProbeMismatches_ConfirmedOnSecondConsecutiveTick(t *testing.T) {
	mismatches := map[string]bool{"av-dante|core-2": true}
	confirmedLines, confirmedKeys := confirmProbeMismatches(mismatches, mismatches)
	if len(confirmedLines) != 1 || confirmedLines[0].Scope != "av-dante" || confirmedLines[0].Worker != "core-2" {
		t.Fatalf("confirmed = %v, want one line for av-dante/core-2", confirmedLines)
	}
	if confirmedLines[0].Detail != "no valid arbiter token authorizes this scope" {
		t.Errorf("Detail = %q, want the token-authorization detail", confirmedLines[0].Detail)
	}
	if confirmedLines[0].DHCPClass != "warn" {
		t.Errorf("confirmed[0].DHCPClass = %q, want \"warn\" — a token mismatch on otherwise-healthy DHCP is not as severe as a confirmed dual-active/no-answer", confirmedLines[0].DHCPClass)
	}
	if !confirmedKeys["av-dante|core-2"] {
		t.Errorf("confirmedKeys = %v, want av-dante|core-2 present", confirmedKeys)
	}
}

func TestConfirmProbeMismatches_ResolvedMismatchIsNotConfirmed(t *testing.T) {
	prev := map[string]bool{"av-dante|core-2": true}
	current := map[string]bool{}
	confirmedLines, confirmedKeys := confirmProbeMismatches(current, prev)
	if len(confirmedLines) != 0 {
		t.Errorf("confirmed = %v, want none — a resolved mismatch must not be reported", confirmedLines)
	}
	if len(confirmedKeys) != 0 {
		t.Errorf("confirmedKeys = %v, want none", confirmedKeys)
	}
}

func TestCheckProbeHostIssues_SurfacesExternalProbeHostFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var pr probeResult
		pr.Enabled = true
		pr.Reachable = true
		pr.DNS.Answered = true
		pr.DNS.Valid = true
		pr.DHCP.Verdict = "no_answer"
		pr.DHCP.Reason = "no answer"
		json.NewEncoder(w).Encode(pr)
	}))
	defer srv.Close()

	probeHost := NodeConfig{Name: "probe-a", Addr: strings.TrimPrefix(srv.URL, "http://")}
	serving := map[string]bool{"rw-129": true}
	issues, _, _ := checkProbeHostIssues([]string{"rw-129"}, []NodeConfig{probeHost}, nil, nil, serving)
	if len(issues) != 1 || issues[0].Scope != "rw-129" || issues[0].Worker != "probe-a" {
		t.Fatalf("issues = %v, want one line for rw-129/probe-a", issues)
	}
	if issues[0].DHCPText != "DHCP-NONE" || issues[0].DHCPClass != "crit" {
		t.Errorf("DHCPText/DHCPClass = %q/%q, want DHCP-NONE/crit — no_answer is a confirmed failure, same severity dual-active gets", issues[0].DHCPText, issues[0].DHCPClass)
	}
	if issues[0].Detail != "  [DHCP: no answer]" {
		t.Errorf("Detail = %q, want the surfaced probe-host reason", issues[0].Detail)
	}
}

func TestCheckProbeHostIssues_UnclaimedScopeNeverReportsAConfirmedIssue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var pr probeResult
		pr.Enabled = true
		pr.DNS.Answered = true
		pr.DNS.Valid = true
		pr.DHCP.Verdict = "no_answer"
		pr.DHCP.Reason = "no answer"
		json.NewEncoder(w).Encode(pr)
	}))
	defer srv.Close()

	probeHost := NodeConfig{Name: "probe-a", Addr: strings.TrimPrefix(srv.URL, "http://")}
	// serving is nil/empty — no worker claims rw-129 yet (still starting).
	issues, _, _ := checkProbeHostIssues([]string{"rw-129"}, []NodeConfig{probeHost}, nil, nil, nil)
	if len(issues) != 0 {
		t.Errorf("issues = %v, want none — a scope nobody currently claims to serve must not report a confirmed issue", issues)
	}
}

func TestCheckProbeHostIssues_UnclaimedScopeStillCatchesUnauthorizedAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var pr probeResult
		pr.Enabled = true
		pr.DNS.Answered = true
		pr.DNS.Valid = true
		pr.DHCP.Verdict = "ok"
		json.NewEncoder(w).Encode(pr)
	}))
	defer srv.Close()

	probeHost := NodeConfig{Name: "probe-a", Addr: strings.TrimPrefix(srv.URL, "http://")}
	_, mismatches, _ := checkProbeHostIssues([]string{"rw-129"}, []NodeConfig{probeHost}, nil, nil, nil)
	if !mismatches["rw-129|probe-a"] {
		t.Errorf("mismatches = %v, want rw-129|probe-a flagged — DHCP answering with no valid token must still be caught", mismatches)
	}
}

func TestCheckProbeHostIssues_ExcludesStaleReadingsFromOwnerRestart(t *testing.T) {
	now := time.Now()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var pr probeResult
		pr.Enabled = true
		pr.DNS.Answered = true
		pr.DNS.Valid = true
		pr.DHCP.Verdict = "no_answer"
		pr.DHCP.Reason = "no answer"
		pr.ProbedAt = now.Add(-90 * time.Second).UTC().Format(time.RFC3339)
		json.NewEncoder(w).Encode(pr)
	}))
	defer srv.Close()

	probeHost := NodeConfig{Name: "probe-a", Addr: strings.TrimPrefix(srv.URL, "http://")}
	tokens := map[string]tokenInfo{"rw-129": {Owner: "dnshived1022"}}
	// Owner's dnshived has been up only 30s — the 90s-old probe reading
	// predates this restart.
	ownerUptime := map[string]int64{"dnshived1022": 30}
	serving := map[string]bool{"rw-129": true}

	issues, _, _ := checkProbeHostIssues([]string{"rw-129"}, []NodeConfig{probeHost}, tokens, ownerUptime, serving)
	if len(issues) != 0 {
		t.Errorf("issues = %v, want none — the reading predates the owner's own restart, so it must not be a confirmed issue", issues)
	}
}

func TestProbeCellTemplate_RendersProbeNowButton(t *testing.T) {
	tmpl := template.Must(template.New("t").Parse(probeCellDefineHTML + `{{template "probecell" .}}`))
	var buf strings.Builder
	data := probeCellData{Scope: "office", Worker: "core-1", DNSText: "DNS✔", DNSClass: "ok"}
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `action="/probes/office/core-1/refresh"`) {
		t.Errorf("expected a probe-now form posting to /probes/office/core-1/refresh, got: %s", out)
	}
	if !strings.Contains(out, `probe now`) {
		t.Errorf("expected a \"probe now\" button, got: %s", out)
	}
}

func TestProbeCellDisplay_NotQueriedHasNoAge(t *testing.T) {
	dnsText, dnsClass, dhcpText, _, note := probeCellDisplay(time.Now(), probeResult{}, nil, false, false, false)
	if dnsText != "pending..." || dnsClass != "dim" || dhcpText != "" || note != "" {
		t.Errorf("got (%q, %q, %q, note=%q), want (pending..., dim, \"\", \"\")", dnsText, dnsClass, dhcpText, note)
	}
}

func TestProbeCellDisplay_FetchErrorIsDimWithErrorNote(t *testing.T) {
	dnsText, dnsClass, _, _, note := probeCellDisplay(time.Now(), probeResult{}, errFakeTransport, true, false, false)
	if dnsText != "pending..." || dnsClass != "dim" {
		t.Errorf("got (%q, %q), want (pending..., dim)", dnsText, dnsClass)
	}
	if note != errFakeTransport.Error() {
		t.Errorf("note = %q, want the error text %q", note, errFakeTransport.Error())
	}
}

func TestProbeCellDisplay_PendingDaemonIsDimNotConfirmedFailure(t *testing.T) {
	pr := probeResult{Scope: "office", Pending: true}
	dnsText, dnsClass, _, _, note := probeCellDisplay(time.Now(), pr, nil, true, false, false)
	if dnsText != "pending..." || dnsClass != "dim" {
		t.Errorf("got (%q, %q), want (pending..., dim) — a daemon that hasn't probed yet is not a confirmed failure", dnsText, dnsClass)
	}
	if note != "not yet probed" {
		t.Errorf("note = %q, want %q", note, "not yet probed")
	}
}

func TestProbeCellDisplay_FreshGoodResultShowsAge(t *testing.T) {
	now := time.Now()
	pr := probeResult{Enabled: true, Reachable: true, ProbedAt: now.Add(-3 * time.Second).UTC().Format(time.RFC3339)}
	pr.DNS.Answered = true
	pr.DNS.Valid = true
	pr.DHCP.Verdict = "ok"

	dnsText, dnsClass, dhcpText, dhcpClass, note := probeCellDisplay(now, pr, nil, true, false, false)
	if dnsClass != "ok" || dhcpClass != "ok" {
		t.Errorf("dnsClass, dhcpClass = %q, %q, want ok, ok", dnsClass, dhcpClass)
	}
	if dnsText != "DNS✔" || dhcpText != "DHCP✔" {
		t.Errorf("dnsText, dhcpText = %q, %q, want DNS✔, DHCP✔", dnsText, dhcpText)
	}
	if note != "3s ago" {
		t.Errorf("note = %q, want %q", note, "3s ago")
	}
}

// TestProbeCellDisplay_DHCPFailureDoesNotColorHealthyDNS checks a DHCP
// failure leaves a healthy DNS half green.
func TestProbeCellDisplay_DHCPFailureDoesNotColorHealthyDNS(t *testing.T) {
	now := time.Now()
	pr := probeResult{Enabled: true, Reachable: true, ProbedAt: now.Format(time.RFC3339)}
	pr.DNS.Answered = true
	pr.DNS.Valid = true
	pr.DHCP.Verdict = "no_answer"

	dnsText, dnsClass, dhcpText, dhcpClass, _ := probeCellDisplay(now, pr, nil, true, false, false)
	if dnsText != "DNS✔" || dnsClass != "ok" {
		t.Errorf("dnsText, dnsClass = %q, %q, want DNS✔, ok — DHCP failing must not color DNS", dnsText, dnsClass)
	}
	if dhcpText != "DHCP-NONE" || dhcpClass != "crit" {
		t.Errorf("dhcpText, dhcpClass = %q, %q, want DHCP-NONE, crit", dhcpText, dhcpClass)
	}
}

func TestProbeCellDisplay_NoteIncludesReason(t *testing.T) {
	now := time.Now()
	pr := probeResult{Enabled: true, ProbedAt: now.Add(-3 * time.Second).UTC().Format(time.RFC3339)}
	pr.DNS.Answered = true
	pr.DNS.Valid = true
	pr.DHCP.Verdict = "ok"
	pr.DHCP.Valid = false
	pr.DHCP.Reason = "no arbiter token exists for this scope"

	_, _, _, _, note := probeCellDisplay(now, pr, nil, true, false, false)
	want := "3s ago DHCP: no arbiter token exists for this scope"
	if note != want {
		t.Errorf("note = %q, want %q", note, want)
	}
}

func TestProbeCellDisplay_MismatchNoteWhenNoOtherReason(t *testing.T) {
	now := time.Now()
	pr := probeResult{Enabled: true, Reachable: true, ProbedAt: now.Add(-3 * time.Second).UTC().Format(time.RFC3339)}
	pr.DNS.Answered = true
	pr.DNS.Valid = true
	pr.DHCP.Verdict = "ok"

	_, _, _, dhcpClass, note := probeCellDisplay(now, pr, nil, true, true, false)
	if dhcpClass != "warn" {
		t.Errorf("dhcpClass = %q, want warn", dhcpClass)
	}
	want := "3s ago DHCP is being answered but no valid arbiter token authorizes this scope"
	if note != want {
		t.Errorf("note = %q, want %q", note, want)
	}
}

func TestProbeCellDisplay_BlankProbedAtHasNoAgeNote(t *testing.T) {
	pr := probeResult{}
	pr.DNS.Answered = true
	pr.DNS.Valid = true
	pr.DHCP.Verdict = "ok"

	_, _, _, _, note := probeCellDisplay(time.Now(), pr, nil, true, false, false)
	if note != "" {
		t.Errorf("note = %q, want blank when probed_at doesn't parse", note)
	}
}

func TestProbeStale_TrueWhenReadingPredatesOwnerRestart(t *testing.T) {
	now := time.Now()
	// Owner's dnshived has been up 30s; the probe reading is 90s old —
	// it predates this restart by a full minute.
	probedAt := now.Add(-90 * time.Second)
	if !probeStale(probedAt, 30, true, now) {
		t.Error("expected stale=true for a reading older than the owner's own uptime")
	}
}

func TestProbeStale_FalseWhenReadingIsAfterOwnerRestart(t *testing.T) {
	now := time.Now()
	// Owner's dnshived has been up 90s; the probe reading is only 10s
	// old — well after the restart completed.
	probedAt := now.Add(-10 * time.Second)
	if probeStale(probedAt, 90, true, now) {
		t.Error("expected stale=false for a reading taken after the owner's restart")
	}
}

func TestProbeStale_TrueWhenReadingLandsInSettleGraceWindow(t *testing.T) {
	now := time.Now()
	probedAt := now.Add(-2 * time.Second)
	if !probeStale(probedAt, 5, true, now) {
		t.Error("expected stale=true for a reading taken during the owner's settle grace window")
	}
}

func TestProbeStale_FalseWhenOwnerUptimeUnknown(t *testing.T) {
	now := time.Now()
	if probeStale(now.Add(-time.Hour), 0, false, now) {
		t.Error("expected stale=false when owner uptime is unknown (hasUptime=false)")
	}
}

// TestProbeStale_FalseWhenProbedAtIsZero confirms a never-probed
// (zero-value time.Time) reading isn't misreported as "stale".
func TestProbeStale_FalseWhenProbedAtIsZero(t *testing.T) {
	if probeStale(time.Time{}, 30, true, time.Now()) {
		t.Error("expected stale=false for a zero-value probedAt")
	}
}

func TestProbeCellDisplay_StaleRendersAsPendingNotConfirmedFailure(t *testing.T) {
	now := time.Now()
	pr := probeResult{Enabled: true, ProbedAt: now.Add(-90 * time.Second).UTC().Format(time.RFC3339)}
	pr.DNS.Answered = true
	pr.DNS.Valid = true
	pr.DHCP.Verdict = "no_answer"

	dnsText, dnsClass, dhcpText, dhcpClass, note := probeCellDisplay(now, pr, nil, true, false, true)
	if dnsClass != "dim" || dhcpClass != "" {
		t.Errorf("dnsClass, dhcpClass = %q, %q, want dim, \"\" — a stale reading must render as pending, not the confirmed no_answer failure it stores", dnsClass, dhcpClass)
	}
	if dnsText != "pending..." || dhcpText != "" {
		t.Errorf("dnsText, dhcpText = %q, %q, want pending..., \"\"", dnsText, dhcpText)
	}
	if note == "" {
		t.Error("expected a non-empty note explaining why this cell is showing pending instead of a verdict")
	}
}

// TestScopeDisplayName_TagsIoTScopesConsistently mirrors dnshived-top's
// identical test.
func TestScopeDisplayName_TagsIoTScopesConsistently(t *testing.T) {
	if got := scopeDisplayName("rw-129", true); got != "rw-129 [IoT]" {
		t.Errorf("scopeDisplayName(iot=true) = %q, want %q", got, "rw-129 [IoT]")
	}
	if got := scopeDisplayName("rw-129", false); got != "rw-129" {
		t.Errorf("scopeDisplayName(iot=false) = %q, want the bare name", got)
	}
}

// TestIoTScopeSet_UnionsAcrossReachableWorkersOnly pins that an
// unreachable/errored node or the arbiter never contributes to the set.
func TestIoTScopeSet_UnionsAcrossReachableCoreNodesOnly(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", IoTScopes: []string{"rw-100"}}},
		{Node: NodeConfig{Name: "core-2"}, FetchError: "unreachable", Status: nodeStatus{Role: "core-2", IoTScopes: []string{"rw-999"}}},
		{Node: NodeConfig{Name: "core-3"}, Status: nodeStatus{Role: "core-3", IoTScopes: []string{"rw-888"}}},
	}
	set := iotScopeSet(rows)
	if !set["rw-100"] {
		t.Errorf("set = %v, want rw-100 present (reachable core-1)", set)
	}
	if !set["rw-888"] {
		t.Errorf("set = %v, want rw-888 present — core-3 genuinely contributes now, no longer excluded", set)
	}
	if set["rw-999"] {
		t.Errorf("set = %v, want rw-999 absent (real fetch error)", set)
	}
}

// errFakeTransport is a stand-in transport error for tests — its exact
// type doesn't matter, only that probeCellDisplay surfaces its text.
var errFakeTransport = fakeErr("connection refused")

type fakeErr string

func (e fakeErr) Error() string { return string(e) }

func TestProbeResult_DecodesDNSChecksAndDHCPOffers(t *testing.T) {
	raw := `{
		"scope": "office", "enabled": true,
		"dhcp": {"verdict": "ok", "servers": ["172.16.100.22"], "valid": true,
			"offers": [{"server_id": "172.16.100.22", "offered_ip": "172.16.100.150"}]},
		"dns": {"answered": true, "latency_ms": 3},
		"dns_checks": [{"name": "nas.office.lan.", "type": "A", "against": "172.16.100.22",
			"answered": true, "expected": "192.168.100.50", "got": "192.168.100.50", "valid": true}]
	}`
	var pr probeResult
	if err := json.Unmarshal([]byte(raw), &pr); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(pr.DHCP.Offers) != 1 || pr.DHCP.Offers[0].OfferedIP != "172.16.100.150" {
		t.Errorf("DHCP.Offers = %+v, want one offer with OfferedIP=172.16.100.150", pr.DHCP.Offers)
	}
	if len(pr.DNSChecks) != 1 || pr.DNSChecks[0].Got != "192.168.100.50" {
		t.Errorf("DNSChecks = %+v, want one check with Got=192.168.100.50", pr.DNSChecks)
	}
}

func TestProbeDetailTmpl_RendersDHCPOffersAndDNSChecks(t *testing.T) {
	data := probeDetailData{
		Scope: "office", Worker: "probe-a", Enabled: true, ProbedAt: "2026-08-07T12:00:00Z",
		DHCPVerdict: "ok", DHCPServers: []string{"172.16.100.22"}, DHCPValid: true,
		DHCPOffers:  []probeDHCPOffer{{ServerID: "172.16.100.22", OfferedIP: "172.16.100.150"}},
		DNSAnswered: true, DNSLatencyMS: 3,
		DNSChecks: []probeDNSCheck{
			{Name: "nas.office.lan.", Type: "A", Against: "172.16.100.22", Answered: true,
				Expected: "192.168.100.50", Got: "192.168.100.50", Valid: true},
		},
	}
	var buf bytes.Buffer
	if err := probeDetailTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("probeDetailTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "172.16.100.150") {
		t.Error("expected the offered IP to appear in the rendered page")
	}
	if !strings.Contains(out, "192.168.100.50") {
		t.Error("expected the actual DNS answer (Got) to appear in the rendered page")
	}
}

func TestProbeDetailTmpl_DefaultCheckWithNoExpectedShowsRealValid(t *testing.T) {
	data := probeDetailData{
		Scope: "office", Worker: "probe-a",
		DNSChecks: []probeDNSCheck{
			{Name: "claude.ai.", Type: "A", Against: "172.16.100.22", Answered: true, Valid: true},
		},
	}
	var buf bytes.Buffer
	if err := probeDetailTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("probeDetailTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "n/a") {
		t.Errorf("expected a real Valid=true rendered, not n/a, got:\n%s", out)
	}
	if !strings.Contains(out, `class="ok">true`) {
		t.Errorf("expected an ok-classed \"true\", got:\n%s", out)
	}
}

func TestProbeDetailTmpl_DefaultCheckRefusedShowsWarnAndReason(t *testing.T) {
	data := probeDetailData{
		Scope: "test7", Worker: "probe-42",
		DNSChecks: []probeDNSCheck{
			{Name: "claude.ai.", Type: "A", Against: "192.168.12.22", Answered: true, Valid: false,
				Reason: "no upstream configured for this scope — dnsmasq has nowhere to forward an external name"},
		},
	}
	var buf bytes.Buffer
	if err := probeDetailTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("probeDetailTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `class="warn">false`) {
		t.Errorf("expected a warn-classed \"false\", got:\n%s", out)
	}
	if !strings.Contains(out, "no upstream configured for this scope") {
		t.Errorf("expected the Reason text rendered, got:\n%s", out)
	}
}

func TestProbeDetailTmpl_SkippedCheckStillShowsNA(t *testing.T) {
	data := probeDetailData{
		Scope: "office", Worker: "probe-a",
		DNSChecks: []probeDNSCheck{
			{Name: "weird.office.lan", Type: "BOGUS", Skipped: "type BOGUS not supported"},
		},
	}
	var buf bytes.Buffer
	if err := probeDetailTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("probeDetailTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "n/a") {
		t.Errorf("expected \"n/a\" for a Skipped check, got:\n%s", out)
	}
}

func TestProbeDetailTmpl_RendersEmptyStatesCleanly(t *testing.T) {
	data := probeDetailData{Scope: "office", Worker: "probe-a", DHCPVerdict: "no_answer"}
	var buf bytes.Buffer
	if err := probeDetailTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("probeDetailTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "no offers received") || !strings.Contains(out, "no per-record DNS checks") {
		t.Errorf("expected both empty-state messages, got:\n%s", out)
	}
}

func TestHandleProbeDetail_UnknownWorker404s(t *testing.T) {
	cfg := &WebConfig{ProbeHosts: []NodeConfig{{Name: "probe-a", Addr: "127.0.0.1:1"}}}
	req := httptest.NewRequest("GET", "/probes/office/nonexistent", nil)
	req.SetPathValue("scope", "office")
	req.SetPathValue("worker", "nonexistent")
	rec := httptest.NewRecorder()

	handleProbeDetail(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestHandleProbeDetail_RendersRealFetchedData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var pr probeResult
		pr.Enabled = true
		pr.Reachable = true
		pr.DHCP.Verdict = "ok"
		pr.DHCP.Servers = []string{"172.16.100.22"}
		pr.DHCP.Valid = true
		pr.DHCP.Offers = []probeDHCPOffer{{ServerID: "172.16.100.22", OfferedIP: "172.16.100.150"}}
		pr.DNS.Answered = true
		pr.DNS.Valid = true
		pr.DNSChecks = []probeDNSCheck{
			{Name: "nas.office.lan.", Type: "A", Against: "172.16.100.22", Answered: true, Got: "192.168.100.50", Valid: true},
		}
		json.NewEncoder(w).Encode(pr)
	}))
	defer srv.Close()

	cfg := &WebConfig{ProbeHosts: []NodeConfig{{Name: "probe-a", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest("GET", "/probes/office/probe-a", nil)
	req.SetPathValue("scope", "office")
	req.SetPathValue("worker", "probe-a")
	rec := httptest.NewRecorder()

	handleProbeDetail(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "172.16.100.150") {
		t.Error("expected the real fetched offered IP to appear in the response")
	}
	if !strings.Contains(body, "192.168.100.50") {
		t.Error("expected the real fetched DNS answer to appear in the response")
	}
}

func TestHandleProbeDetail_ShowsPendingWarningWhenBaselineIsACandidate(t *testing.T) {
	probeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var pr probeResult
		pr.Enabled = false
		json.NewEncoder(w).Encode(pr)
	}))
	defer probeSrv.Close()

	clusterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"exists": true,
				"candidate": config.Cluster{
					Scopes: map[string]config.ScopeConfig{
						"office": {VIP: "172.16.100.1/24", ProbeDisabled: false},
					},
				},
			})
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer clusterSrv.Close()

	cfg := &WebConfig{
		Nodes:      []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(clusterSrv.URL, "http://")}},
		ProbeHosts: []NodeConfig{{Name: "probe-a", Addr: strings.TrimPrefix(probeSrv.URL, "http://")}},
	}
	req := httptest.NewRequest("GET", "/probes/office/probe-a", nil)
	req.SetPathValue("scope", "office")
	req.SetPathValue("worker", "probe-a")
	rec := httptest.NewRecorder()

	handleProbeDetail(newConfigRef(cfg))(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "PENDING candidate") {
		t.Errorf("expected the pending-candidate warning since the baseline came from a candidate, got:\n%s", body)
	}
}

// TestHandleProbeRefresh_UnknownWorker404s mirrors
// TestHandleProbeDetail_UnknownWorker404s.
func TestHandleProbeRefresh_UnknownWorker404s(t *testing.T) {
	cfg := &WebConfig{ProbeHosts: []NodeConfig{{Name: "probe-a", Addr: "127.0.0.1:1"}}}
	req := httptest.NewRequest("POST", "/probes/office/nonexistent/refresh", nil)
	req.SetPathValue("scope", "office")
	req.SetPathValue("worker", "nonexistent")
	rec := httptest.NewRecorder()

	handleProbeRefresh(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for an unknown probe host", rec.Code)
	}
}

func TestHandleProbeRefresh_RendersFreshTriggeredResult(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		var pr probeResult
		pr.Enabled = true
		pr.Reachable = true
		pr.DHCP.Verdict = "ok"
		pr.DHCP.Valid = true
		pr.DHCP.Offers = []probeDHCPOffer{{ServerID: "172.16.100.22", OfferedIP: "172.16.100.199"}}
		json.NewEncoder(w).Encode(pr)
	}))
	defer srv.Close()

	cfg := &WebConfig{ProbeHosts: []NodeConfig{{Name: "probe-a", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest("POST", "/probes/office/probe-a/refresh", nil)
	req.SetPathValue("scope", "office")
	req.SetPathValue("worker", "probe-a")
	rec := httptest.NewRecorder()

	handleProbeRefresh(newConfigRef(cfg))(rec, req)

	if gotMethod != http.MethodPost {
		t.Errorf("probe host received method %q, want POST — a refresh must trigger the on-demand endpoint, not the plain cached GET", gotMethod)
	}
	if !strings.HasSuffix(gotPath, "/refresh") {
		t.Errorf("probe host received path %q, want it to end in /refresh", gotPath)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "172.16.100.199") {
		t.Error("expected the freshly-triggered offered IP to appear in the rendered response")
	}
	if !strings.Contains(rec.Body.String(), "Probe successful") {
		t.Error("expected a \"Probe successful\" confirmation banner on a successful on-demand trigger")
	}
}

func TestHandleProbeRefresh_UnreachableNeverClaimsSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var pr probeResult
		pr.Enabled = false
		pr.Reachable = false
		json.NewEncoder(w).Encode(pr)
	}))
	defer srv.Close()

	cfg := &WebConfig{ProbeHosts: []NodeConfig{{Name: "probe-a", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest("POST", "/probes/office/probe-a/refresh", nil)
	req.SetPathValue("scope", "office")
	req.SetPathValue("worker", "probe-a")
	rec := httptest.NewRecorder()

	handleProbeRefresh(newConfigRef(cfg))(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, "Probe successful") {
		t.Error(`rendered "Probe successful" for an unreachable scope where no real probe ever ran`)
	}
	if !strings.Contains(body, "Unreachable") {
		t.Errorf("expected an \"Unreachable\" explanation distinct from the generic probe_disabled message, body: %s", body)
	}
}

var dateTimeSpaceFormat = regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \S+$`)

func TestFormatProbedAt_ReadableFromRawWireTimestamp(t *testing.T) {
	got := formatProbedAt("2026-08-08T14:02:19.123309018+02:00")
	if strings.Contains(got, ".123309018") {
		t.Errorf("formatProbedAt(...) = %q, still contains raw sub-second noise", got)
	}
	if !dateTimeSpaceFormat.MatchString(got) {
		t.Errorf("formatProbedAt(...) = %q, want a plain \"YYYY-MM-DD HH:MM:SS TZ\"-style local date/time, not a raw RFC3339 string", got)
	}
}

func TestFormatProbedAt_UnparseableOrZeroFallsBackToRaw(t *testing.T) {
	for _, raw := range []string{"", "not-a-timestamp", "0001-01-01T00:00:00Z"} {
		if got := formatProbedAt(raw); got != raw {
			t.Errorf("formatProbedAt(%q) = %q, want unchanged passthrough", raw, got)
		}
	}
}

func TestHandleProbeRefresh_ShowsQueueWaitWhenNonzero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var pr probeResult
		pr.Enabled = true
		pr.Reachable = true
		pr.DHCP.Verdict = "ok"
		pr.QueueWaitMS = 6042
		json.NewEncoder(w).Encode(pr)
	}))
	defer srv.Close()

	cfg := &WebConfig{ProbeHosts: []NodeConfig{{Name: "probe-a", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest("POST", "/probes/office/probe-a/refresh", nil)
	req.SetPathValue("scope", "office")
	req.SetPathValue("worker", "probe-a")
	rec := httptest.NewRecorder()

	handleProbeRefresh(newConfigRef(cfg))(rec, req)

	if !strings.Contains(rec.Body.String(), "6042ms") {
		t.Errorf("expected the queue-wait duration in the rendered response, body: %s", rec.Body.String())
	}
}

// TestHandleProbeRefresh_NoQueueWaitTextWhenZero confirms the queue-wait
// note is entirely absent for the normal case (no real queueing).
func TestHandleProbeRefresh_NoQueueWaitTextWhenZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var pr probeResult
		pr.Enabled = true
		pr.Reachable = true
		pr.DHCP.Verdict = "ok"
		json.NewEncoder(w).Encode(pr)
	}))
	defer srv.Close()

	cfg := &WebConfig{ProbeHosts: []NodeConfig{{Name: "probe-a", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest("POST", "/probes/office/probe-a/refresh", nil)
	req.SetPathValue("scope", "office")
	req.SetPathValue("worker", "probe-a")
	rec := httptest.NewRecorder()

	handleProbeRefresh(newConfigRef(cfg))(rec, req)

	if strings.Contains(rec.Body.String(), "Waited") {
		t.Error("expected no queue-wait note when QueueWaitMS is zero")
	}
}

// TestHandleProbeRefresh_NoSuccessBannerOnTransportError confirms the
// success banner and the error message are mutually exclusive.
func TestHandleProbeRefresh_NoSuccessBannerOnTransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{"error": "a probe for this scope is already running"})
	}))
	defer srv.Close()

	cfg := &WebConfig{ProbeHosts: []NodeConfig{{Name: "probe-a", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest("POST", "/probes/office/probe-a/refresh", nil)
	req.SetPathValue("scope", "office")
	req.SetPathValue("worker", "probe-a")
	rec := httptest.NewRecorder()

	handleProbeRefresh(newConfigRef(cfg))(rec, req)

	if strings.Contains(rec.Body.String(), "Probe successful") {
		t.Error("expected no \"Probe successful\" banner when the trigger itself failed")
	}
}

// TestHandleProbeDetail_NoSuccessBannerOnPlainGet confirms a plain page
// load (not a refresh trigger) never shows the "just refreshed" banner.
func TestHandleProbeDetail_NoSuccessBannerOnPlainGet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var pr probeResult
		pr.Enabled = true
		pr.Reachable = true
		pr.DHCP.Verdict = "ok"
		pr.DHCP.Valid = true
		json.NewEncoder(w).Encode(pr)
	}))
	defer srv.Close()

	cfg := &WebConfig{ProbeHosts: []NodeConfig{{Name: "probe-a", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest("GET", "/probes/office/probe-a", nil)
	req.SetPathValue("scope", "office")
	req.SetPathValue("worker", "probe-a")
	rec := httptest.NewRecorder()

	handleProbeDetail(newConfigRef(cfg))(rec, req)

	if strings.Contains(rec.Body.String(), "Probe successful") {
		t.Error("expected no \"Probe successful\" banner on a plain GET page load")
	}
}

func TestHandleProbeRefresh_TransportErrorRendersFetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{"error": "a probe for this scope is already running"})
	}))
	defer srv.Close()

	cfg := &WebConfig{ProbeHosts: []NodeConfig{{Name: "probe-a", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest("POST", "/probes/office/probe-a/refresh", nil)
	req.SetPathValue("scope", "office")
	req.SetPathValue("worker", "probe-a")
	rec := httptest.NewRecorder()

	handleProbeRefresh(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the page itself renders fine, the error shows inline)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "already running") {
		t.Errorf("expected the rejection reason to appear in the rendered page, got: %s", rec.Body.String())
	}
}

// TestCheckProbeHostIssues_CountsPendingSeparatelyFromIssues confirms a
// scope with no completed sweep yet is neither a confirmed issue NOR
// silently invisible.
func TestClassifyProbeResults_FlagsRogueDHCPProminently(t *testing.T) {
	res := probeFetch{scope: "office", worker: "core-1"}
	res.pr.Reachable = true
	res.pr.Enabled = true
	res.pr.DHCP.Verdict = "dual_active"
	res.pr.DHCP.Reason = "ROGUE DHCP: unrecognized server(s) [10.0.0.99] among responders [10.0.0.23 10.0.0.99]"
	serving := map[string]bool{"office": true}

	issues, _, _ := classifyProbeResults([]probeFetch{res}, nil, nil, serving)
	if len(issues) != 1 {
		t.Fatalf("issues = %v, want exactly one", issues)
	}
	if !issues[0].Rogue {
		t.Error("Rogue = false, want true for a DHCP.Reason naming an unrecognized server")
	}
}

// TestClassifyProbeResults_OrdinaryDualActiveIsNotFlaggedRogue confirms an
// ordinary (non-rogue) dual-active finding.
func TestClassifyProbeResults_OrdinaryDualActiveIsNotFlaggedRogue(t *testing.T) {
	res := probeFetch{scope: "office", worker: "core-1"}
	res.pr.Reachable = true
	res.pr.Enabled = true
	res.pr.DHCP.Verdict = "dual_active"
	res.pr.DHCP.Servers = []string{"10.0.0.22", "10.0.0.23"}
	serving := map[string]bool{"office": true}

	issues, _, _ := classifyProbeResults([]probeFetch{res}, nil, nil, serving)
	if len(issues) != 1 {
		t.Fatalf("issues = %v, want exactly one", issues)
	}
	if issues[0].Rogue {
		t.Error("Rogue = true, want false for an ordinary dual-active finding among known servers")
	}
}

func TestCheckProbeHostIssues_CountsPendingSeparatelyFromIssues(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(probeResult{Pending: true})
	}))
	defer srv.Close()

	probeHost := NodeConfig{Name: "probe-a", Addr: strings.TrimPrefix(srv.URL, "http://")}
	issues, _, pending := checkProbeHostIssues([]string{"rw-129"}, []NodeConfig{probeHost}, nil, nil, nil)
	if len(issues) != 0 {
		t.Errorf("issues = %v, want none — a pending result is not a confirmed failure", issues)
	}
	if pending != 1 {
		t.Errorf("pending = %d, want 1", pending)
	}
}

func TestProbeHealthSummary_ZeroIssuesZeroPendingIsHealthy(t *testing.T) {
	text, class := probeHealthSummary(nil, 0)
	if class != "ok" || text != "all healthy" {
		t.Errorf("probeHealthSummary(nil, 0) = (%q, %q), want (\"all healthy\", \"ok\")", text, class)
	}
}

func TestProbeHealthSummary_IssuesTakePriorityOverPending(t *testing.T) {
	text, class := probeHealthSummary([]probeIssue{{Scope: "x", Worker: "probe-a", DHCPClass: "crit"}}, 5)
	if class != "crit" {
		t.Errorf("class = %q, want crit — a confirmed issue must win over pending count", class)
	}
	if text != "1 issue(s) — see below" {
		t.Errorf("text = %q", text)
	}
}

func TestProbeHealthSummary_ZeroIssuesButPendingIsNotHealthy(t *testing.T) {
	text, class := probeHealthSummary(nil, 8)
	if class == "ok" {
		t.Errorf("class = %q, must not be \"ok\" (green) while 8 scopes are still pending their first sweep", class)
	}
	if class != "warn" {
		t.Errorf("class = %q, want warn", class)
	}
	if !strings.Contains(text, "8") {
		t.Errorf("text = %q, must mention the pending count", text)
	}
}

func TestHandleProbes_PendingCountIsAlwaysFreshNotStale(t *testing.T) {
	nodeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/status":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"role": "core-1", "configured_scopes": []string{"rw-100"},
			})
		case "/api/v1/daemons":
			json.NewEncoder(w).Encode(map[string]interface{}{"units": []interface{}{}})
		default:
			w.Write([]byte("{}"))
		}
	}))
	defer nodeSrv.Close()

	probeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every (scope, host) pair reports NOT pending — the page must
		// show 0 pending, computed fresh from exactly these responses.
		w.Write([]byte(`{"reachable":true,"enabled":true,"dns":{"answered":true}}`))
	}))
	defer probeSrv.Close()

	cfg := &WebConfig{
		Nodes:      []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(nodeSrv.URL, "http://")}},
		ProbeHosts: []NodeConfig{{Name: "probe-a", Addr: strings.TrimPrefix(probeSrv.URL, "http://")}},
	}

	req := httptest.NewRequest(http.MethodGet, "/probes", nil)
	rec := httptest.NewRecorder()
	handleProbes(newConfigRef(cfg))(rec, req)

	if strings.Contains(rec.Body.String(), "pending</span>") {
		t.Errorf("expected 0 pending (fresh, matching the mocked responses — none reported pending), got: %s", rec.Body.String())
	}
}

func TestSweptScopeCount_NormalCase(t *testing.T) {
	if got := sweptScopeCount(20, 5); got != 15 {
		t.Errorf("sweptScopeCount(20, 5) = %d, want 15", got)
	}
}

func TestSweptScopeCount_ClampsAtZero(t *testing.T) {
	if got := sweptScopeCount(5, 8); got != 0 {
		t.Errorf("sweptScopeCount(5, 8) = %d, want 0 (clamped)", got)
	}
}

func TestProbeHostRowStatus_PendingIsWarnRegardlessOfSettling(t *testing.T) {
	class, info := probeHostRowStatus(3, 5, 2, false)
	if class != "warn" {
		t.Errorf("class = %q, want warn (pending > 0)", class)
	}
	if info != "3/5 scope(s) swept" {
		t.Errorf("info = %q, want unqualified swept text", info)
	}
}

func TestProbeHostRowStatus_SettlingWithZeroPendingIsWarnAndQualified(t *testing.T) {
	class, info := probeHostRowStatus(1, 1, 0, true)
	if class != "warn" {
		t.Errorf("class = %q, want warn (settling, even with pending==0)", class)
	}
	if !strings.Contains(info, "1/1 scope(s) swept") || !strings.Contains(info, "predates the cluster's current settling") {
		t.Errorf("info = %q, want the swept count plus a settling qualifier", info)
	}
}

// TestProbeHostRowStatus_FullySettledIsOk pins the clean-slate case — no
// pending, cluster not settling, a real all-clear.
func TestProbeHostRowStatus_FullySettledIsOk(t *testing.T) {
	class, info := probeHostRowStatus(5, 5, 0, false)
	if class != "ok" {
		t.Errorf("class = %q, want ok", class)
	}
	if info != "5/5 scope(s) swept" {
		t.Errorf("info = %q, want unqualified swept text", info)
	}
}

func TestHandleProbeToggle_FlipsProbeDisabledPreservesEverythingElse(t *testing.T) {
	var pushedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				PSK: "secret-psk",
				Scopes: map[string]config.ScopeConfig{
					"rw-100": {VIP: "172.16.100.1/24", ProbeDisabled: false},
					"rw-101": {VIP: "172.16.101.1/24", ProbeDisabled: true},
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
	form := url.Values{"worker": {"probe-a"}}
	req := httptest.NewRequest(http.MethodPost, "/probes/rw-100/toggle-probe", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("scope", "rw-100")
	rec := httptest.NewRecorder()

	handleProbeToggle(newConfigRef(cfg))(rec, req)

	var pushed configPushPayload
	if err := json.Unmarshal([]byte(pushedBody), &pushed); err != nil {
		t.Fatalf("unmarshal pushed payload: %v, body=%s", err, pushedBody)
	}
	if !pushed.Scopes["rw-100"].ProbeDisabled {
		t.Errorf("rw-100.ProbeDisabled = false, want true (toggled from false)")
	}
	if pushed.Scopes["rw-100"].VIP != "172.16.100.1/24" {
		t.Errorf("rw-100's other fields were disturbed: %+v", pushed.Scopes["rw-100"])
	}
	if !pushed.Scopes["rw-101"].ProbeDisabled || pushed.Scopes["rw-101"].VIP != "172.16.101.1/24" {
		t.Errorf("rw-101 was disturbed by an rw-100 toggle: %+v", pushed.Scopes["rw-101"])
	}
	if pushed.PSK != "secret-psk" {
		t.Errorf("expected PSK preserved untouched, got %q", pushed.PSK)
	}
	if !strings.Contains(rec.Body.String(), `href="/probes/rw-100/probe-a"`) {
		t.Errorf("expected the back link to point at the originating probe detail page, got:\n%s", rec.Body.String())
	}
}

// TestHandleProbeToggle_UnknownScopeReturns404 mirrors
// TestHandleScopeConfigPost_UnknownScopeReturns404.
func TestHandleProbeToggle_UnknownScopeReturns404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{Scopes: map[string]config.ScopeConfig{"rw-100": {}}})
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	form := url.Values{"worker": {"probe-a"}}
	req := httptest.NewRequest(http.MethodPost, "/probes/nonexistent/toggle-probe", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("scope", "nonexistent")
	rec := httptest.NewRecorder()

	handleProbeToggle(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for an unknown scope", rec.Code)
	}
}

func TestProbeDetailTmpl_ToggleButtonReflectsActualProbeDisabled(t *testing.T) {
	data := probeDetailData{
		Scope: "office", Worker: "probe-a",
		Enabled: false, Reachable: false,
		ProbeDisabled: false, ProbeDisabledKnown: true,
	}
	var buf strings.Builder
	if err := probeDetailTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Disable probing for this scope") {
		t.Errorf("expected a 'Disable probing' button for a genuinely-enabled scope, got:\n%s", out)
	}
	if strings.Contains(out, "Enable probing for this scope") {
		t.Errorf("did not expect an 'Enable probing' button for a genuinely-enabled scope, got:\n%s", out)
	}
}

// TestProbeDetailTmpl_ToggleButtonOffersEnableWhenDisabled is the inverse
// case.
func TestProbeDetailTmpl_ToggleButtonOffersEnableWhenDisabled(t *testing.T) {
	data := probeDetailData{
		Scope: "office", Worker: "probe-a",
		ProbeDisabled: true, ProbeDisabledKnown: true,
	}
	var buf strings.Builder
	if err := probeDetailTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Enable probing for this scope") {
		t.Errorf("expected an 'Enable probing' button for a disabled scope, got:\n%s", out)
	}
}

func TestProbeDetailTmpl_HidesToggleWhenProbeDisabledUnknown(t *testing.T) {
	data := probeDetailData{Scope: "office", Worker: "probe-a", ProbeDisabledKnown: false}
	var buf strings.Builder
	if err := probeDetailTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "toggle-probe") {
		t.Errorf("expected the toggle form to be hidden when ProbeDisabledKnown is false, got:\n%s", out)
	}
}

func TestProbeDetailTmpl_ShowsPendingWarningWhenCandidatePending(t *testing.T) {
	data := probeDetailData{
		Scope: "office", Worker: "probe-a",
		ProbeDisabled: false, ProbeDisabledKnown: true, CandidatePending: true,
	}
	var buf strings.Builder
	if err := probeDetailTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "PENDING candidate") {
		t.Errorf("expected a pending-candidate warning near the toggle, got:\n%s", out)
	}
}

func TestProbeDetailTmpl_NoPendingWarningWhenNotPending(t *testing.T) {
	data := probeDetailData{
		Scope: "office", Worker: "probe-a",
		ProbeDisabled: false, ProbeDisabledKnown: true, CandidatePending: false,
	}
	var buf strings.Builder
	if err := probeDetailTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "PENDING candidate") {
		t.Errorf("did not expect a pending-candidate warning when CandidatePending is false, got:\n%s", out)
	}
}

func TestDisabledScopeSet_UnionsReachableCoreNodesOnly(t *testing.T) {
	rows := []statusRow{
		{Status: nodeStatus{Role: "core-1", DisabledScopes: []string{"test-2"}}},
		{Status: nodeStatus{Role: "core-2", DisabledScopes: []string{"x"}}, FetchError: "down"},
		{Status: nodeStatus{Role: "probe", DisabledScopes: []string{"y"}}},
	}
	got := disabledScopeSet(rows)
	if len(got) != 1 || !got["test-2"] {
		t.Errorf("disabledScopeSet = %v, want only test-2", got)
	}
}

func TestScopeDisabledCell_NeverReadsAsProbeOnly(t *testing.T) {
	c := scopeDisabledCell("test-2", "probe")
	if c.DNSText != "scope disabled" || c.DNSClass != "warn" || c.DHCPText != "" || c.Note != "" || c.Title == "" {
		t.Errorf("cell = %+v", c)
	}
}
