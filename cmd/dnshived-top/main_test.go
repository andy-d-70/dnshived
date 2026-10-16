// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// TestFormatDuration_SecondPrecision pins that this is meant to read like
// a running stopwatch (HH:MM:SS), unlike formatUptime's coarser "3d 20h"
// rounding.
func TestFormatDuration_SecondPrecision(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "00:00:00"},
		{45 * time.Second, "00:00:45"},
		{90 * time.Minute, "01:30:00"},
		{25*time.Hour + 3*time.Minute + 9*time.Second, "1d 01:03:09"},
	}
	for _, c := range cases {
		if got := formatDuration(c.d); got != c.want {
			t.Errorf("formatDuration(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

// TestClusterStableSince_LatestAmongAllNodes pins the "weakest link"
// semantics: the cluster is only as continuously stable as its most
// recently transitioned node.
func TestClusterStableSince_LatestAmongAllNodes(t *testing.T) {
	older := time.Date(2026, 8, 2, 9, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 8, 2, 9, 30, 0, 0, time.UTC)
	nodes := []nodeData{
		{Reachable: true, Status: &nodeStatus{StateSince: older.Format(time.RFC3339)}},
		{Reachable: true, Status: &nodeStatus{StateSince: newer.Format(time.RFC3339)}},
	}
	got, ok := clusterStableSince(nodes)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if !got.Equal(newer) {
		t.Errorf("got = %v, want the later (weakest-link) timestamp %v", got, newer)
	}
}

func TestClusterStableSince_UnreachableNodeMeansUnknown(t *testing.T) {
	nodes := []nodeData{
		{Reachable: true, Status: &nodeStatus{StateSince: time.Now().Format(time.RFC3339)}},
		{Reachable: false},
	}
	if _, ok := clusterStableSince(nodes); ok {
		t.Error("ok = true, want false — an unreachable node must not be silently ignored")
	}
}

func TestBannerText_GettingThereBeforeScopesStart(t *testing.T) {
	// stable=2/2, armed, but only 0 of 2 configured scopes serving yet.
	// Well under settlingTimeout — this is the normal, expected case.
	text, color := bannerText(2, 2, 2, 2, 0, 5*time.Second)
	if color != cYellow {
		t.Errorf("color = %q, want cYellow while scopes haven't started serving", color)
	}
	if !strings.Contains(text, "GETTING THERE") {
		t.Errorf("text = %q, want it to say GETTING THERE", text)
	}
}

func TestBannerText_ProductionActiveOnceServing(t *testing.T) {
	text, color := bannerText(2, 2, 2, 2, 2, 0)
	if color != cGreen {
		t.Errorf("color = %q, want cGreen once every configured scope is being served", color)
	}
	if !strings.Contains(text, "PRODUCTION ACTIVE") {
		t.Errorf("text = %q, want PRODUCTION ACTIVE", text)
	}
}

func TestBannerText_ProductionActiveWhenNoScopesConfigured(t *testing.T) {
	text, color := bannerText(1, 1, 1, 0, 0, 0)
	if color != cGreen {
		t.Errorf("color = %q, want cGreen when there are no configured scopes to wait on", color)
	}
	if !strings.Contains(text, "PRODUCTION ACTIVE") {
		t.Errorf("text = %q, want PRODUCTION ACTIVE", text)
	}
}

func TestBannerText_NodeDownTakesPriorityOverSettling(t *testing.T) {
	// reachable < total: a node is actually down. That must show, not
	// get masked by the (irrelevant, since not-yet-stable) settling case.
	text, color := bannerText(2, 2, 3, 2, 2, 0)
	if color != cRed {
		t.Errorf("color = %q, want cRed — a node is down", color)
	}
	if !strings.Contains(text, "NODE DOWN") {
		t.Errorf("text = %q, want NODE DOWN", text)
	}
}

func TestBannerText_EscalatesAfterSettlingTimeout(t *testing.T) {
	text, color := bannerText(2, 2, 2, 2, 0, settlingTimeout+time.Second)
	if color != cRed {
		t.Errorf("color = %q, want cRed once stuck past settlingTimeout", color)
	}
	if !strings.Contains(text, "NOT CONVERGING") {
		t.Errorf("text = %q, want it to say NOT CONVERGING", text)
	}
}

func TestBannerText_StillGettingThereRightAtTheTimeoutBoundary(t *testing.T) {
	// Exactly at the threshold must not yet escalate — only strictly
	// past it should (avoids a test/behavior mismatch on the boundary).
	text, color := bannerText(2, 2, 2, 2, 0, settlingTimeout)
	if color != cYellow {
		t.Errorf("color = %q, want cYellow exactly at the boundary, not yet escalated", color)
	}
	if !strings.Contains(text, "GETTING THERE") {
		t.Errorf("text = %q, want GETTING THERE at the boundary", text)
	}
}

func TestProbeCell_Pending(t *testing.T) {
	text, color := probeCell(probeResult{}, false)
	if text != "pending..." {
		t.Errorf("text = %q, want %q", text, "pending...")
	}
	if color != cDim {
		t.Errorf("color = %q, want cDim", color)
	}
}

func TestProbeCell_DisabledScopeIsDimNotFailure(t *testing.T) {
	pr := probeResult{Scope: "rw-100", Enabled: false}
	text, color := probeCell(pr, true)
	if color != cDim {
		t.Errorf("color = %q, want cDim for a disabled scope, not a failure color", color)
	}
	if text != "probe off" {
		t.Errorf("text = %q, want %q", text, "probe off")
	}
}

func TestProbeCell_TransportErrorNotMisreportedAsDisabled(t *testing.T) {
	pr := probeResult{Scope: "rw-100", Enabled: false}
	pr.DHCP.Error = "connection refused"
	pr.DNS.Error = "connection refused"
	text, color := probeCell(pr, true)
	if text == "probe off" {
		t.Error("a transport error must not render as \"disabled\" — those are different signals")
	}
	if color != cDim {
		t.Errorf("color = %q, want cDim for a transport error", color)
	}
	if text != "DNS? DHCP?" {
		t.Errorf("text = %q, want %q", text, "DNS? DHCP?")
	}
}

func TestCheckProbeHostIssues_DisabledScopesProduceNoIssues(t *testing.T) {
	disabled := probeResult{Scope: "rw-100", Enabled: false}
	results := map[string]map[string]probeResult{
		"192.168.0.42:9444": {"rw-100": disabled},
	}
	issues, mismatches := checkProbeHostIssues(results, []string{"192.168.0.42:9444"}, nil, map[string]tokenInfo{}, nil, nil)
	if len(issues) != 0 {
		t.Errorf("issues = %v, want none — disabled scopes were never actually tested", issues)
	}
	if len(mismatches) != 0 {
		t.Errorf("mismatches = %v, want none", mismatches)
	}
}

func TestProbeCell_BothOK(t *testing.T) {
	var pr probeResult
	pr.Enabled = true
	pr.DNS.Answered = true
	pr.DHCP.Verdict = "ok"

	text, color := probeCell(pr, true)
	if color != cGreen {
		t.Errorf("color = %q, want cGreen for a fully healthy result", color)
	}
	if text != "DNS✔ DHCP✔" {
		t.Errorf("text = %q, want %q", text, "DNS✔ DHCP✔")
	}
}

func TestProbeCell_DHCPNoAnswerIsNotHealthy(t *testing.T) {
	var pr probeResult
	pr.Enabled = true
	pr.DNS.Answered = true
	pr.DHCP.Verdict = "no_answer"

	_, color := probeCell(pr, true)
	if color != cRed {
		t.Errorf("color = %q, want cRed — no_answer means nothing on the segment answered, as serious as dual-active", color)
	}
}

func TestProbeCell_DualActiveIsRedRegardlessOfDNS(t *testing.T) {
	var pr probeResult
	pr.Enabled = true
	pr.DNS.Answered = true
	pr.DHCP.Verdict = "dual_active"

	text, color := probeCell(pr, true)
	if color != cRed {
		t.Errorf("color = %q, want cRed — dual-active must always dominate the cell's color", color)
	}
	if text != "DNS✔ DHCP✖DUAL" {
		t.Errorf("text = %q, want it to include DHCP✖DUAL", text)
	}
}

func TestProbeCellParts_DHCPFailureDoesNotColorHealthyDNS(t *testing.T) {
	var pr probeResult
	pr.Enabled = true
	pr.DNS.Answered = true
	pr.DHCP.Verdict = "dual_active"

	dnsText, dnsColor, dhcpText, dhcpColor := probeCellParts(pr, true, false)
	if dnsText != "DNS✔" || dnsColor != cGreen {
		t.Errorf("dnsText, dnsColor = %q, %q, want DNS✔, cGreen — DHCP failing must not color DNS", dnsText, dnsColor)
	}
	if dhcpText != "DHCP✖DUAL" || dhcpColor != cRed {
		t.Errorf("dhcpText, dhcpColor = %q, %q, want DHCP✖DUAL, cRed", dhcpText, dhcpColor)
	}
}

func TestProbeCellParts_ConfirmedMismatchDowngradesGreenToYellow(t *testing.T) {
	var pr probeResult
	pr.Enabled = true
	pr.DNS.Answered = true
	pr.DHCP.Verdict = "ok"

	_, _, dhcpText, dhcpColor := probeCellParts(pr, true, true)
	if dhcpText != "DHCP✔" {
		t.Errorf("dhcpText = %q, want DHCP✔ (verdict text unchanged, only the color reflects the mismatch)", dhcpText)
	}
	if dhcpColor != cYellow {
		t.Errorf("dhcpColor = %q, want cYellow for a confirmed mismatch", dhcpColor)
	}
}

func TestProbeCellParts_DualActiveStaysRedRegardlessOfMismatchFlag(t *testing.T) {
	var pr probeResult
	pr.Enabled = true
	pr.DNS.Answered = true
	pr.DHCP.Verdict = "dual_active"

	_, _, _, dhcpColor := probeCellParts(pr, true, true)
	if dhcpColor != cRed {
		t.Errorf("dhcpColor = %q, want cRed — dual-active must never be downgraded to yellow", dhcpColor)
	}
}

func TestRenderProbeCell_PadsOnPlainTextWidthNotColoredWidth(t *testing.T) {
	var pr probeResult
	pr.Enabled = true
	pr.DNS.Answered = true
	pr.DHCP.Verdict = "ok"

	got := renderProbeCell(pr, true, 20, false)
	plainLen := utf8.RuneCountInString("DNS✔ DHCP✔") // 10 visible characters
	want := cGreen + "DNS✔" + cReset + " " + cGreen + "DHCP✔" + cReset + strings.Repeat(" ", 20-plainLen)
	if got != want {
		t.Errorf("renderProbeCell = %q, want %q", got, want)
	}
}

func TestProbeCell_TransportErrorIsDimNotRed(t *testing.T) {
	// A probe that couldn't even reach the node's API (network blip, node
	// restarting) is a "don't know," not a confirmed failure.
	var pr probeResult
	pr.DNS.Error = "connection refused"
	pr.DHCP.Error = "connection refused"

	text, color := probeCell(pr, true)
	if color != cDim {
		t.Errorf("color = %q, want cDim for a transport-level error, not cRed", color)
	}
	if text != "DNS? DHCP?" {
		t.Errorf("text = %q, want %q", text, "DNS? DHCP?")
	}
}

func TestProbeCell_ErrorFieldsAreDimNotYellow(t *testing.T) {
	var pr probeResult
	pr.DHCP.Error = "not yet probed — pending this node's first probe tick"
	pr.DNS.Error = "not yet probed — pending this node's first probe tick"

	_, color := probeCell(pr, true)
	if color != cDim {
		t.Errorf("color = %q, want cDim for a degraded round, not a confirmed failure color", color)
	}
}

func TestCheckProbeHostIssues_NoIssuesWhenAllHealthy(t *testing.T) {
	var okPR probeResult
	okPR.Enabled = true
	okPR.DNS.Answered = true
	okPR.DHCP.Verdict = "ok"

	results := map[string]map[string]probeResult{
		"192.168.0.42:9444": {"office": okPR},
	}
	tokens := map[string]tokenInfo{"office": {Owner: "dnshived1022"}}
	issues, mismatches := checkProbeHostIssues(results, []string{"192.168.0.42:9444"}, nil, tokens, nil, map[string]bool{"office": true})
	if len(issues) != 0 {
		t.Errorf("issues = %v, want none for an all-healthy, authorized round", issues)
	}
	if len(mismatches) != 0 {
		t.Errorf("mismatches = %v, want none", mismatches)
	}
}

func TestCheckProbeHostIssues_PendingOrTransportErrorIsNotAnIssue(t *testing.T) {
	// A transport error (or a degraded-round marker with no known-good
	// fallback) renders cDim, meaning "don't know yet".
	var degraded probeResult
	degraded.DHCP.Error = "connection refused"
	degraded.DNS.Error = "connection refused"

	results := map[string]map[string]probeResult{
		"192.168.0.42:9444": {"office": degraded},
	}
	if issues, _ := checkProbeHostIssues(results, []string{"192.168.0.42:9444"}, nil, nil, nil, map[string]bool{"office": true}); len(issues) != 0 {
		t.Errorf("issues = %v, want none — a transport error is not a confirmed failure", issues)
	}
}

func TestCheckProbeHostIssues_UnclaimedScopeNeverReportsAConfirmedIssue(t *testing.T) {
	var noAnswer probeResult
	noAnswer.Enabled = true
	noAnswer.DNS.Answered = true
	noAnswer.DHCP.Verdict = "no_answer"

	results := map[string]map[string]probeResult{
		"192.168.0.42:9444": {"rw-129": noAnswer},
	}
	// serving is nil — no worker claims rw-129 yet (still starting).
	issues, _ := checkProbeHostIssues(results, []string{"192.168.0.42:9444"}, nil, nil, nil, nil)
	if len(issues) != 0 {
		t.Errorf("issues = %v, want none — a scope nobody currently claims to serve must not report a confirmed issue", issues)
	}
}

func TestCheckProbeHostIssues_NoAnswerAndDualActiveAreReported(t *testing.T) {
	var noAnswer probeResult
	noAnswer.Enabled = true
	noAnswer.DNS.Answered = true
	noAnswer.DHCP.Verdict = "no_answer"

	var dual probeResult
	dual.Enabled = true
	dual.DNS.Answered = true
	dual.DHCP.Verdict = "dual_active"

	results := map[string]map[string]probeResult{
		"192.168.0.42:9444": {"office": noAnswer, "av-dante": dual},
	}
	tokens := map[string]tokenInfo{"av-dante": {Owner: "dnshived1022"}}
	serving := map[string]bool{"office": true, "av-dante": true}
	issues, _ := checkProbeHostIssues(results, []string{"192.168.0.42:9444"}, nil, tokens, nil, serving)
	if len(issues) != 2 {
		t.Fatalf("issues = %v, want 2 entries", issues)
	}
	if issues[0].Text != "av-dante (from 192.168.0.42): DHCP✖DUAL" {
		t.Errorf("issues[0] = %q, want the av-dante dual-active line (scopes sorted first)", issues[0])
	}
	if issues[1].Text != "office (from 192.168.0.42): DHCP-NONE" {
		t.Errorf("issues[1] = %q, want the office no_answer line", issues[1])
	}
	if issues[0].Color != cRed || issues[1].Color != cRed {
		t.Errorf("issues = %v, want both colored cRed — dual-active and no-answer are both confirmed failures", issues)
	}
}

// TestProbeIssueText_KeepsDNSWhenItsAlsoAProblem pins the other half: when
// DNS itself is down (not just DHCP), the full two-part text stays.
func TestProbeIssueText_KeepsDNSWhenItsAlsoAProblem(t *testing.T) {
	var pr probeResult
	pr.DNS.Error = "timeout"
	pr.DHCP.Verdict = "no_answer"
	got := probeIssueText(pr)
	want := "DNS? DHCP-NONE  [DNS: timeout]"
	if got != want {
		t.Errorf("probeIssueText = %q, want %q (full DNS+DHCP text, plus the actual reason) when DNS itself is a problem", got, want)
	}
}

func TestProbeIssueText_SurfacesProbeHostReason(t *testing.T) {
	var pr probeResult
	pr.Enabled = true
	pr.DNS.Answered = true
	pr.DHCP.Verdict = "ok"
	pr.DHCP.Valid = false
	pr.DHCP.Reason = "answered by [172.16.1.2], expected token owner worker-a (172.16.1.1)"
	got := probeIssueText(pr)
	want := "DHCP✔  [DHCP: answered by [172.16.1.2], expected token owner worker-a (172.16.1.1)]"
	if got != want {
		t.Errorf("probeIssueText = %q, want %q", got, want)
	}
}

func TestProbeIssueText_SurfacesDualActiveServers(t *testing.T) {
	var pr probeResult
	pr.Enabled = true
	pr.DNS.Answered = true
	pr.DHCP.Verdict = "dual_active"
	pr.DHCP.Servers = []string{"172.16.1.1", "172.16.1.2"}
	got := probeIssueText(pr)
	want := "DHCP✖DUAL  [DHCP: answered by [172.16.1.1 172.16.1.2]]"
	if got != want {
		t.Errorf("probeIssueText = %q, want %q", got, want)
	}
}

func TestCheckProbeHostIssues_PartialFailureIsReported(t *testing.T) {
	// DNS down but DHCP fine renders cYellow via probeCell.
	var partial probeResult
	partial.Enabled = true
	partial.DNS.Answered = false
	partial.DHCP.Verdict = "ok"

	results := map[string]map[string]probeResult{
		"192.168.0.42:9444": {"office": partial},
	}
	tokens := map[string]tokenInfo{"office": {Owner: "dnshived1022"}}
	issues, _ := checkProbeHostIssues(results, []string{"192.168.0.42:9444"}, nil, tokens, nil, map[string]bool{"office": true})
	if len(issues) != 1 {
		t.Fatalf("issues = %v, want 1 entry for a partial (yellow) failure", issues)
	}
}

func TestCheckProbeHostIssues_AnsweringWithNoValidTokenIsReported(t *testing.T) {
	var okPR probeResult
	okPR.Enabled = true
	okPR.DNS.Answered = true
	okPR.DHCP.Verdict = "ok"

	results := map[string]map[string]probeResult{
		"192.168.0.42:9444": {"orphan-scope": okPR},
	}
	issues, mismatches := checkProbeHostIssues(results, []string{"192.168.0.42:9444"}, nil, map[string]tokenInfo{}, nil, nil) // no token at all
	if len(issues) != 0 {
		t.Errorf("issues = %v, want none — the token mismatch is never an immediate issue", issues)
	}
	if !mismatches["orphan-scope|192.168.0.42"] {
		t.Fatalf("mismatches = %v, want orphan-scope|192.168.0.42 present", mismatches)
	}

	// Confirmed once the SAME mismatch is seen on a second, independent round.
	confirmedLines, confirmedKeys := confirmProbeMismatches(mismatches, mismatches)
	want := "orphan-scope (from 192.168.0.42): DHCP is being answered but no valid arbiter token authorizes this scope"
	if len(confirmedLines) != 1 || confirmedLines[0].Text != want {
		t.Errorf("confirmed = %v, want [%q]", confirmedLines, want)
	}
	if confirmedLines[0].Color != cYellow {
		t.Errorf("confirmed[0].Color = %q, want cYellow — a token mismatch on otherwise-healthy DHCP is not as severe as a confirmed dual-active/no-answer", confirmedLines[0].Color)
	}
	if !confirmedKeys["orphan-scope|192.168.0.42"] {
		t.Errorf("confirmedKeys = %v, want orphan-scope|192.168.0.42 present", confirmedKeys)
	}
}

func TestConfirmProbeMismatches_SingleObservationNotSurfaced(t *testing.T) {
	mismatches := map[string]bool{"av-dante|core-2": true}
	confirmedLines, confirmedKeys := confirmProbeMismatches(mismatches, nil) // no prior round
	if len(confirmedLines) != 0 {
		t.Errorf("confirmed = %v, want none — a single observation must not be surfaced", confirmedLines)
	}
	if len(confirmedKeys) != 0 {
		t.Errorf("confirmedKeys = %v, want none", confirmedKeys)
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

// TestCheckProbeHealth_ExpiredTokenAlsoCountsAsNoValidToken pins that an
// EXPIRED token doesn't count as authorization.
func TestCheckProbeHostIssues_ExpiredTokenAlsoCountsAsNoValidToken(t *testing.T) {
	var okPR probeResult
	okPR.Enabled = true
	okPR.DNS.Answered = true
	okPR.DHCP.Verdict = "ok"

	results := map[string]map[string]probeResult{
		"192.168.0.42:9444": {"office": okPR},
	}
	tokens := map[string]tokenInfo{"office": {Owner: "dnshived1022", Expired: true}}
	issues, mismatches := checkProbeHostIssues(results, []string{"192.168.0.42:9444"}, nil, tokens, nil, map[string]bool{"office": true})
	if len(issues) != 0 {
		t.Fatalf("issues = %v, want none from checkProbeHostIssues directly", issues)
	}
	issues, _ = confirmProbeMismatches(mismatches, mismatches)
	if len(issues) != 1 {
		t.Fatalf("issues = %v, want 1 entry — an expired token doesn't authorize serving", issues)
	}
}

func TestCheckProbeHostIssues_SurfacesExternalProbeFailures(t *testing.T) {
	var bad probeResult
	bad.Enabled = true
	bad.DNS.Answered = true
	bad.DHCP.Verdict = "no_answer"
	bad.DHCP.Reason = "no answer"

	var good probeResult
	good.Enabled = true
	good.DNS.Answered = true
	good.DHCP.Verdict = "ok"

	results := map[string]map[string]probeResult{
		"192.168.0.42:9444": {"rw-129": bad, "rw-111": good},
		"192.168.0.43:9444": {"rw-129": good},
	}
	serving := map[string]bool{"rw-129": true, "rw-111": true}
	issues, _ := checkProbeHostIssues(results, []string{"192.168.0.42:9444", "192.168.0.43:9444"}, nil, nil, nil, serving)
	want := []string{"rw-129 (from 192.168.0.42): DHCP-NONE  [DHCP: no answer]"}
	if len(issues) != len(want) || issues[0].Text != want[0] {
		t.Errorf("issues = %v, want %v", issues, want)
	}
}

// TestCheckProbeHostIssues_DetectsTokenMismatch pins that probe hosts now
// get the SAME token cross-check core workers already had.
func TestCheckProbeHostIssues_DetectsTokenMismatch(t *testing.T) {
	var answering probeResult
	answering.Enabled = true
	answering.DNS.Answered = true
	answering.DHCP.Verdict = "ok"

	results := map[string]map[string]probeResult{
		"192.168.0.42:9444": {"orphan-scope": answering},
	}
	_, mismatches := checkProbeHostIssues(results, []string{"192.168.0.42:9444"}, nil, map[string]tokenInfo{}, nil, nil)
	if !mismatches["orphan-scope|192.168.0.42"] {
		t.Errorf("mismatches = %v, want orphan-scope|192.168.0.42 present", mismatches)
	}
}

// TestProbeHostLabel_PrefersConfiguredName checks a configured probe-host
// name is shown instead of the bare IP.
func TestProbeHostLabel_PrefersConfiguredName(t *testing.T) {
	s := &appState{probeHostNames: map[string]string{"192.168.0.42:9444": "probe"}}
	if got := probeHostLabel(s, "192.168.0.42:9444"); got != "probe" {
		t.Errorf("probeHostLabel = %q, want the configured name %q", got, "probe")
	}
}

// TestProbeHostLabel_FallsBackToAddressWhenUnnamed checks an unnamed probe
// host is labeled by its address.
func TestProbeHostLabel_FallsBackToAddressWhenUnnamed(t *testing.T) {
	s := &appState{probeHostNames: map[string]string{}}
	if got := probeHostLabel(s, "192.168.0.42:9444"); got != "192.168.0.42" {
		t.Errorf("probeHostLabel = %q, want the stripped address %q", got, "192.168.0.42")
	}
}

// TestScopeDisplayName_TagsIoTScopesConsistently pins the exact,
// fixed-width-safe tag format used identically in the Scopes and Probes
// tabs.
func TestScopeDisplayName_TagsIoTScopesConsistently(t *testing.T) {
	if got := scopeDisplayName("rw-129", true); got != "rw-129 [IoT]" {
		t.Errorf("scopeDisplayName(iot=true) = %q, want %q", got, "rw-129 [IoT]")
	}
	if got := scopeDisplayName("rw-129", false); got != "rw-129" {
		t.Errorf("scopeDisplayName(iot=false) = %q, want the bare name", got)
	}
}

// TestIoTScopeSet_UnionsAcrossReachableCoreNodesOnly pins that only an
// unreachable node fails to contribute to the set.
func TestIoTScopeSet_UnionsAcrossReachableCoreNodesOnly(t *testing.T) {
	nodes := []nodeData{
		{Reachable: true, Status: &nodeStatus{Role: "core-1", IoTScopes: []string{"rw-100"}}},
		{Reachable: false, Status: &nodeStatus{Role: "core-2", IoTScopes: []string{"rw-999"}}},
		{Reachable: true, Status: &nodeStatus{Role: "core-3", IoTScopes: []string{"rw-888"}}},
	}
	set := iotScopeSet(nodes)
	if !set["rw-100"] {
		t.Errorf("set = %v, want rw-100 present (reachable core-1)", set)
	}
	if !set["rw-888"] {
		t.Errorf("set = %v, want rw-888 present — core-3 genuinely contributes now, no longer excluded", set)
	}
	if set["rw-999"] {
		t.Errorf("set = %v, want rw-999 absent (unreachable node)", set)
	}
}

func TestDaemonCell_ActiveIsGreen(t *testing.T) {
	text, color := daemonCell(daemonStatus{LoadState: "loaded", ActiveState: "active", SubState: "running"})
	if color != cGreen {
		t.Errorf("color = %q, want cGreen for an active/running unit", color)
	}
	if text != "active/running" {
		t.Errorf("text = %q, want %q", text, "active/running")
	}
}

func TestDaemonCell_FailedIsRed(t *testing.T) {
	_, color := daemonCell(daemonStatus{LoadState: "loaded", ActiveState: "failed", SubState: "failed"})
	if color != cRed {
		t.Errorf("color = %q, want cRed for a failed unit", color)
	}
}

func TestDaemonCell_DnsmasqAggregateAllActiveIsGreen(t *testing.T) {
	text, color := daemonCell(daemonStatus{Unit: "dnsmasq", ActiveCount: 20, TotalCount: 20})
	if text != "20/20 active" {
		t.Errorf("text = %q, want %q", text, "20/20 active")
	}
	if color != cGreen {
		t.Errorf("color = %q, want cGreen when every scope's dnsmasq unit is active", color)
	}
}

func TestDaemonCell_DnsmasqAggregatePartialIsRed(t *testing.T) {
	text, color := daemonCell(daemonStatus{Unit: "dnsmasq", ActiveCount: 18, TotalCount: 20})
	if text != "18/20 active" {
		t.Errorf("text = %q, want %q", text, "18/20 active")
	}
	if color != cRed {
		t.Errorf("color = %q, want cRed when fewer than all scopes' dnsmasq units are active", color)
	}
}

func TestDaemonCell_LoadedButInactiveIsRed(t *testing.T) {
	_, color := daemonCell(daemonStatus{LoadState: "loaded", ActiveState: "inactive", SubState: "dead"})
	if color != cRed {
		t.Errorf("color = %q, want cRed for a loaded-but-inactive unit", color)
	}
}

func TestDaemonCell_NotFoundIsDimNotRed(t *testing.T) {
	text, color := daemonCell(daemonStatus{LoadState: "not-found", ActiveState: "inactive", SubState: "dead"})
	if color != cDim {
		t.Errorf("color = %q, want cDim for a not-installed unit, not cRed", color)
	}
	if text != "not installed" {
		t.Errorf("text = %q, want %q", text, "not installed")
	}
}

func TestDaemonCell_TransportErrorIsDim(t *testing.T) {
	_, color := daemonCell(daemonStatus{Error: "systemctl show: exit status 1"})
	if color != cDim {
		t.Errorf("color = %q, want cDim for a query error, not a confirmed state", color)
	}
}

func TestDaemonCell_ActivatingIsYellow(t *testing.T) {
	_, color := daemonCell(daemonStatus{LoadState: "loaded", ActiveState: "activating", SubState: "start"})
	if color != cYellow {
		t.Errorf("color = %q, want cYellow for a mid-transition unit", color)
	}
}

func TestDaemonCell_DhcpRelayAggregateAllActiveIsGreen(t *testing.T) {
	text, color := daemonCell(daemonStatus{Unit: "dhcp-relay", ActiveCount: 3, TotalCount: 3})
	if text != "3/3 active" {
		t.Errorf("text = %q, want %q", text, "3/3 active")
	}
	if color != cGreen {
		t.Errorf("color = %q, want cGreen when every relayed VLAN is active", color)
	}
}

// TestDaemonCell_DhcpRelayZeroEligibleIsDimNotRed mirrors
// cmd/dnshived-web's identical test.
func TestDaemonCell_DhcpRelayZeroEligibleIsDimNotRed(t *testing.T) {
	text, color := daemonCell(daemonStatus{Unit: "dhcp-relay", LoadState: "loaded", ActiveState: "inactive", TotalCount: 0})
	if color != cDim {
		t.Errorf("color = %q, want cDim when zero scopes are relay-eligible, not cRed", color)
	}
	if text != "no scope eligible yet" {
		t.Errorf("text = %q, want %q", text, "no scope eligible yet")
	}
}

// TestDaemonCell_RealRelayUnitZeroEligibleIsDimNotRed mirrors
// cmd/dnshived-web's identical test.
func TestDaemonCell_RealRelayUnitZeroEligibleIsDimNotRed(t *testing.T) {
	text, color := daemonCell(daemonStatus{Unit: "dnshived-relay.service", LoadState: "loaded", ActiveState: "inactive", TotalCount: 0})
	if color != cDim {
		t.Errorf("color = %q, want cDim when zero scopes are relay-eligible, not cRed", color)
	}
	if text != "no scope eligible yet" {
		t.Errorf("text = %q, want %q", text, "no scope eligible yet")
	}
}

func TestDaemonCell_RealRelayUnitActiveStaysGreenEvenWithZeroEligible(t *testing.T) {
	text, color := daemonCell(daemonStatus{Unit: "dnshived-relay.service", LoadState: "loaded", ActiveState: "active", TotalCount: 0})
	if color != cGreen {
		t.Errorf("color = %q, want cGreen for a genuinely active unit regardless of TotalCount", color)
	}
	if text != "active" {
		t.Errorf("text = %q, want %q", text, "active")
	}
}

// TestDaemonCell_RealRelayUnitActiveWithNonzeroEligibleStaysGreen mirrors
// cmd/dnshived-web's identical test.
func TestDaemonCell_RealRelayUnitActiveWithNonzeroEligibleStaysGreen(t *testing.T) {
	text, color := daemonCell(daemonStatus{Unit: "dnshived-relay.service", LoadState: "loaded", ActiveState: "active", TotalCount: 1})
	if color != cGreen {
		t.Errorf("color = %q, want cGreen — a real unit's TotalCount is an eligibility signal, never an N/M display driver", color)
	}
	if text != "active" {
		t.Errorf("text = %q, want %q", text, "active")
	}
}

// TestIsRelayClientEntry mirrors cmd/dnshived-web's identical test.
func TestIsRelayClientEntry(t *testing.T) {
	cases := map[string]bool{
		"dhcp-relay: central-test-1 (ens19.200)": true,
		"dhcp-relay: ens19.201":                  true,
		"dhcp-relay":                             false,
		"dnshived-relay.service":                 false,
	}
	for unit, want := range cases {
		if got := isRelayClientEntry(unit); got != want {
			t.Errorf("isRelayClientEntry(%q) = %v, want %v", unit, got, want)
		}
	}
}

func TestIsDnsmasqScopeUnit_ExcludesReservedCoreUnits(t *testing.T) {
	cases := map[string]bool{
		"dnshived-dnsmasq@office.service":    true,
		"dnshived-dnsmasq@core-dns.service":  false,
		"dnshived-dnsmasq@core-dhcp.service": false,
		"dnsmasq":                            false,
	}
	for unit, want := range cases {
		if got := isDnsmasqScopeUnit(unit); got != want {
			t.Errorf("isDnsmasqScopeUnit(%q) = %v, want %v", unit, got, want)
		}
	}
}

// TestRunningAsText_* mirrors cmd/dnshived-web's own identical tests.
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

func TestLevelColor_KnownLevels(t *testing.T) {
	cases := map[string]string{
		"WARNING":  cYellow,
		"ERROR":    cRed,
		"CRITICAL": cRed,
		"INFO":     cCyan,
	}
	for level, want := range cases {
		if got := levelColor(level); got != want {
			t.Errorf("levelColor(%q) = %q, want %q", level, got, want)
		}
	}
}

func TestLevelColor_UnknownLevelIsDim(t *testing.T) {
	if got := levelColor("DEBUG"); got != cDim {
		t.Errorf("levelColor(DEBUG) = %q, want cDim", got)
	}
	if got := levelColor(""); got != cDim {
		t.Errorf("levelColor(\"\") = %q, want cDim", got)
	}
}

func TestNodeIdentityColor_KnownRoles(t *testing.T) {
	if got := nodeIdentityColor("core-1"); got != cNodeA {
		t.Errorf("nodeIdentityColor(worker-a) = %q, want cNodeA", got)
	}
	if got := nodeIdentityColor("core-2"); got != cNodeB {
		t.Errorf("nodeIdentityColor(worker-b) = %q, want cNodeB", got)
	}
}

// TestWorkerIdentityColors_MatchWebRedBlueConvention pins the real ANSI
// values, not just symbolic equality.
func TestWorkerIdentityColors_MatchWebRedBlueConvention(t *testing.T) {
	if cNodeA != "\033[31m" {
		t.Errorf("cNodeA = %q, want plain red (\\033[31m) to match -web's worker-a=red", cNodeA)
	}
	if cNodeB != "\033[34m" {
		t.Errorf("cNodeB = %q, want plain blue (\\033[34m) to match -web's worker-b=blue", cNodeB)
	}
	if cNodeA == cRed {
		t.Error("cNodeA must not equal cRed — worker-a's identity color would be mistaken for the critical/fail health signal")
	}
}

func TestNodeIdentityColor_Core3GetsItsOwnDedicatedColor(t *testing.T) {
	if got := nodeIdentityColor("core-3"); got != cNodeC {
		t.Errorf("nodeIdentityColor(core-3) = %q, want cNodeC", got)
	}
	if cNodeC == cCyan || cNodeC == cNodeA || cNodeC == cNodeB {
		t.Error("cNodeC must be visually distinct from the fallback and from core-1/core-2's own colors")
	}
}

func TestNodeIdentityColor_UnknownRoleIsPlainCyan(t *testing.T) {
	if got := nodeIdentityColor("some-future-role"); got != cCyan {
		t.Errorf("nodeIdentityColor(some-future-role) = %q, want cCyan", got)
	}
	if got := nodeIdentityColor(""); got != cCyan {
		t.Errorf("nodeIdentityColor(\"\") = %q, want cCyan", got)
	}
}

func TestNodeIdentityColor_NotFooledByNodeIDNumbers(t *testing.T) {
	if got := nodeIdentityColor("dnshived1022"); got != cCyan {
		t.Errorf("nodeIdentityColor(dnshived1022) = %q, want cCyan (not a role, must not match worker-a by digit coincidence)", got)
	}
}

func TestRoleByNodeID_ResolvesFromStatus(t *testing.T) {
	nodes := []nodeData{
		{Status: &nodeStatus{NodeID: "dnshived1022", Role: "core-1"}},
		{Status: &nodeStatus{NodeID: "dnshived1023", Role: "core-2"}},
		{Addr: "unreachable-node", Status: nil}, // Reachable == false, no Status
	}
	roles := roleByNodeID(nodes)
	if roles["dnshived1022"] != "core-1" {
		t.Errorf("roles[dnshived1022] = %q, want worker-a", roles["dnshived1022"])
	}
	if roles["dnshived1023"] != "core-2" {
		t.Errorf("roles[dnshived1023] = %q, want worker-b", roles["dnshived1023"])
	}
	if len(roles) != 2 {
		t.Errorf("len(roles) = %d, want 2 (unreachable node with nil Status must be skipped)", len(roles))
	}
}

func TestProbeCell_DNSDownButDHCPOKIsYellow(t *testing.T) {
	var pr probeResult
	pr.Enabled = true
	pr.DNS.Answered = false // real failure, not an error/unknown
	pr.DHCP.Verdict = "ok"

	_, color := probeCell(pr, true)
	if color != cYellow {
		t.Errorf("color = %q, want cYellow — a partial failure (DNS down, DHCP fine) isn't as severe as dual-active but isn't fully healthy either", color)
	}
}

func TestProbeAge_NotHavingDataIsBlank(t *testing.T) {
	if got := probeAge(probeResult{}, false); got != "" {
		t.Errorf("probeAge(zero, false) = %q, want blank", got)
	}
}

func TestProbeAge_BlankProbedAtIsBlank(t *testing.T) {
	if got := probeAge(probeResult{}, true); got != "" {
		t.Errorf("probeAge(no ProbedAt, true) = %q, want blank", got)
	}
}

func TestProbeAge_ShowsElapsedSeconds(t *testing.T) {
	pr := probeResult{Enabled: true, ProbedAt: time.Now().Add(-5 * time.Second).UTC().Format(time.RFC3339)}
	got := probeAge(pr, true)
	if !strings.Contains(got, "5s ago") && !strings.Contains(got, "4s ago") {
		t.Errorf("probeAge = %q, want it to mention ~5s ago", got)
	}
}

func TestProbeAgeDisplay_FixedWidthRegardlessOfAgePresence(t *testing.T) {
	withAge := probeAgeDisplay(probeResult{Enabled: true, ProbedAt: time.Now().Add(-5 * time.Second).UTC().Format(time.RFC3339)}, true)
	withoutAge := probeAgeDisplay(probeResult{Enabled: false}, true)
	if len(withAge) != len(withoutAge) {
		t.Errorf("len(withAge)=%d != len(withoutAge)=%d — %q vs %q, column alignment breaks when these differ",
			len(withAge), len(withoutAge), withAge, withoutAge)
	}
}

func TestCycleLogFilter_ForwardWrapsAround(t *testing.T) {
	got := "all"
	for _, want := range []string{"core-1", "core-2", "core-3", "all"} {
		got = cycleLogFilter(got, true)
		if got != want {
			t.Fatalf("cycleLogFilter forward = %q, want %q", got, want)
		}
	}
}

// TestCycleLogFilter_BackwardWrapsAround confirms the reverse direction is
// the exact mirror, not just "forward minus one" with an off-by-one at the
// wrap boundary.
func TestCycleLogFilter_BackwardWrapsAround(t *testing.T) {
	got := "all"
	for _, want := range []string{"core-3", "core-2", "core-1", "all"} {
		got = cycleLogFilter(got, false)
		if got != want {
			t.Fatalf("cycleLogFilter backward = %q, want %q", got, want)
		}
	}
}

func TestCycleLogFilter_UnknownCurrentValueDoesNotPanic(t *testing.T) {
	got := cycleLogFilter("not-a-real-filter", true)
	if got != "core-1" {
		t.Errorf("cycleLogFilter(unknown, forward) = %q, want %q (index 0's successor)", got, "core-1")
	}
}

func TestTabOrder_MatchesDnshivedWebNavOrder(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	origStdout := os.Stdout
	os.Stdout = w
	renderTabs(1)
	w.Close()
	os.Stdout = origStdout

	out, _ := io.ReadAll(r)
	text := string(out)

	want := []string{"Overview", "Scopes", "Probes", "Daemons", "Logs"}
	lastIdx := -1
	for _, label := range want {
		idx := strings.Index(text, label)
		if idx == -1 {
			t.Fatalf("expected tab label %q to appear, got:\n%s", label, text)
		}
		if idx <= lastIdx {
			t.Errorf("expected %q to appear after the previous tab, got order:\n%s", label, text)
		}
		lastIdx = idx
	}
}

func TestRenderOverview_ProbeHostShowsRunningStatusWord(t *testing.T) {
	s := &appState{
		probeHostAddrs: []string{"192.168.0.42:9444", "192.168.0.43:9444", "192.168.0.44:9444"},
		probeHostErrors: map[string]string{
			"192.168.0.43:9444": "connection refused",
		},
		probeHosts: map[string]nodeStatus{
			"192.168.0.42:9444": {ConfiguredScopes: []string{"rw-200", "rw-201"}},
		},
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	origStdout := os.Stdout
	os.Stdout = w
	renderOverview(s)
	w.Close()
	os.Stdout = origStdout

	out, _ := io.ReadAll(r)
	lines := strings.Split(string(out), "\n")

	var healthyLine, downLine, waitingLine string
	for _, l := range lines {
		switch {
		case strings.Contains(l, "192.168.0.42:9444"):
			healthyLine = l
		case strings.Contains(l, "192.168.0.43:9444"):
			downLine = l
		case strings.Contains(l, "192.168.0.44:9444"):
			waitingLine = l
		}
	}

	if !strings.Contains(healthyLine, "RUNNING") {
		t.Errorf("healthy probe host line = %q, want it to contain RUNNING", healthyLine)
	}
	if !strings.Contains(downLine, "DOWN") {
		t.Errorf("down probe host line = %q, want it to contain DOWN", downLine)
	}
	if !strings.Contains(waitingLine, "waiting for first sweep") {
		t.Errorf("waiting probe host line = %q, want it to contain \"waiting for first sweep\"", waitingLine)
	}

	nameCol := func(l string) int { return strings.Index(l, "192.168.0.4") }
	if nameCol(healthyLine) != nameCol(downLine) || nameCol(downLine) != nameCol(waitingLine) {
		t.Errorf("addr column not aligned across row states: healthy=%d down=%d waiting=%d",
			nameCol(healthyLine), nameCol(downLine), nameCol(waitingLine))
	}
}

func TestRenderProbes_HeaderShowsErrorCountFromSharedProbeIssues(t *testing.T) {
	s := &appState{
		probeHostAddrs: []string{"192.168.0.42:9444"},
		probeHostNames: map[string]string{"192.168.0.42:9444": "probe-a"},
		nodes: []nodeData{
			{Reachable: true, Status: &nodeStatus{Role: "worker", ConfiguredScopes: []string{"office"}}},
		},
		probeIssues: []probeIssue{
			{Text: "office (from probe-a): DHCP✖ DHCP-NONE", Color: cRed},
		},
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	origStdout := os.Stdout
	os.Stdout = w
	renderProbes(s)
	w.Close()
	os.Stdout = origStdout

	out, _ := io.ReadAll(r)
	first := strings.SplitN(string(out), "\n", 2)[0]
	if !strings.Contains(first, "1 error(s)") {
		t.Errorf("header line = %q, want it to contain \"1 error(s)\" (len(s.probeIssues))", first)
	}
}

// TestProbeStale_TrueWhenReadingPredatesOwnerRestart ports
// cmd/dnshived-web's identical test.
func TestProbeStale_TrueWhenReadingPredatesOwnerRestart(t *testing.T) {
	now := time.Now()
	probedAt := now.Add(-90 * time.Second)
	if !probeStale(probedAt, 30, true, now) {
		t.Error("expected stale=true for a reading older than the owner's own uptime")
	}
}

func TestProbeStale_FalseWhenReadingIsAfterOwnerRestart(t *testing.T) {
	now := time.Now()
	probedAt := now.Add(-10 * time.Second)
	if probeStale(probedAt, 90, true, now) {
		t.Error("expected stale=false for a reading taken after the owner's restart")
	}
}

// TestProbeStale_TrueWhenReadingLandsInSettleGraceWindow ports
// cmd/dnshived-web's identical test.
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

func TestProbeStale_FalseWhenProbedAtIsZero(t *testing.T) {
	if probeStale(time.Time{}, 30, true, time.Now()) {
		t.Error("expected stale=false for a zero-value probedAt")
	}
}

func TestOwnerDaemonUptime_ReadsFromExistingDaemonsData(t *testing.T) {
	nodes := []nodeData{
		{
			Reachable: true,
			Status:    &nodeStatus{NodeID: "dnshived1022"},
			Daemons: []daemonStatus{
				{Unit: "dnshived.service", UptimeSec: 42},
				{Unit: "dnshived-helper.service", UptimeSec: 9999},
			},
		},
		{Reachable: false, Status: &nodeStatus{NodeID: "dnshived1023"}},
	}
	got := ownerDaemonUptime(nodes)
	if got["dnshived1022"] != 42 {
		t.Errorf("got[dnshived1022] = %d, want 42 (dnshived.service's own uptime, not dnshived-helper's)", got["dnshived1022"])
	}
	if _, ok := got["dnshived1023"]; ok {
		t.Error("expected no entry for an unreachable node")
	}
}

// TestCheckProbeHostIssues_ExcludesStaleReadingsFromOwnerRestart ports
// cmd/dnshived-web's identical test.
func TestCheckProbeHostIssues_ExcludesStaleReadingsFromOwnerRestart(t *testing.T) {
	now := time.Now()
	pr := probeResult{Enabled: true, ProbedAt: now.Add(-90 * time.Second).UTC().Format(time.RFC3339)}
	pr.DNS.Answered = true
	pr.DHCP.Verdict = "no_answer"
	pr.DHCP.Reason = "no answer"
	results := map[string]map[string]probeResult{"192.168.0.42:9444": {"rw-129": pr}}
	tokens := map[string]tokenInfo{"rw-129": {Owner: "dnshived1022"}}
	// Owner's dnshived has been up only 30s — the 90s-old reading
	// predates this restart.
	ownerUptime := map[string]int64{"dnshived1022": 30}

	issues, _ := checkProbeHostIssues(results, []string{"192.168.0.42:9444"}, nil, tokens, ownerUptime, map[string]bool{"rw-129": true})
	if len(issues) != 0 {
		t.Errorf("issues = %v, want none — the reading predates the owner's own restart", issues)
	}
}

// TestCheckCoherence_PlaneWarningsSurfacedWithNodeIdentity ports
// cmd/dnshived-web's identical test.
func TestCheckCoherence_PlaneWarningsSurfacedWithNodeIdentity(t *testing.T) {
	nodes := []nodeData{
		{Reachable: true, Status: &nodeStatus{Role: "core-1", NodeID: "n1",
			PlaneWarnings: []string{"scope rw-101: gate nftables gate is open, this node last set it closed"}}},
		{Reachable: true, Status: &nodeStatus{Role: "core-2", NodeID: "n2"}},
	}
	warnings := checkCoherence(nodes, map[string]tokenInfo{})
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "PLANE (core-1)") && strings.Contains(w, "rw-101") {
			found = true
		}
	}
	if !found {
		t.Errorf("checkCoherence() = %v, want a PLANE (core-1) warning naming rw-101", warnings)
	}
}

func TestCheckCoherence_UnreachableNodePlaneWarningsIgnored(t *testing.T) {
	nodes := []nodeData{
		{Reachable: false, Addr: "192.168.0.22:9443"},
	}
	warnings := checkCoherence(nodes, map[string]tokenInfo{})
	for _, w := range warnings {
		if strings.Contains(w, "PLANE") {
			t.Errorf("checkCoherence() = %v, want no PLANE warning from an unreachable node", warnings)
		}
	}
}

func TestScopesMismatch_SameHashAcrossWorkersIsOK(t *testing.T) {
	nodes := []nodeData{
		{Reachable: true, Status: &nodeStatus{Role: "core-1", ScopesHash: "abc123"}},
		{Reachable: true, Status: &nodeStatus{Role: "core-2", ScopesHash: "abc123"}},
	}
	if scopesMismatch(nodes) {
		t.Error("scopesMismatch() = true, want false — both workers agree")
	}
}

func TestScopesMismatch_DifferentHashIsAViolation(t *testing.T) {
	nodes := []nodeData{
		{Reachable: true, Status: &nodeStatus{Role: "core-1", ScopesHash: "abc123"}},
		{Reachable: true, Status: &nodeStatus{Role: "core-2", ScopesHash: "def456"}},
	}
	if !scopesMismatch(nodes) {
		t.Error("scopesMismatch() = false, want true — workers disagree")
	}
}

func TestScopesMismatch_AllThreeCoreRolesCompared(t *testing.T) {
	agreeing := []nodeData{
		{Reachable: true, Status: &nodeStatus{Role: "core-1", ScopesHash: "abc123"}},
		{Reachable: true, Status: &nodeStatus{Role: "core-2", ScopesHash: "abc123"}},
		{Reachable: true, Status: &nodeStatus{Role: "core-3", ScopesHash: "abc123"}},
	}
	if scopesMismatch(agreeing) {
		t.Error("scopesMismatch() = true, want false — all three core roles genuinely agree")
	}

	drifted := []nodeData{
		{Reachable: true, Status: &nodeStatus{Role: "core-1", ScopesHash: "abc123"}},
		{Reachable: true, Status: &nodeStatus{Role: "core-2", ScopesHash: "abc123"}},
		{Reachable: true, Status: &nodeStatus{Role: "core-3", ScopesHash: "000000"}},
	}
	if !scopesMismatch(drifted) {
		t.Error("scopesMismatch() = false, want true — core-3's genuinely differing hash is now a real drift finding")
	}
}

func TestVersionMismatchWarning_AllAgreeIsEmpty(t *testing.T) {
	nodes := []nodeData{
		{Reachable: true, Status: &nodeStatus{Role: "core-1", Version: "0.9.7-dev+abc"}},
		{Reachable: true, Status: &nodeStatus{Role: "core-2", Version: "0.9.7-dev+abc"}},
	}
	if got := versionMismatchWarning(nodes); got != "" {
		t.Errorf("got %q, want \"\" when every node agrees", got)
	}
}

func TestVersionMismatchWarning_NamesWhichNodeRunsWhichVersion(t *testing.T) {
	nodes := []nodeData{
		{Reachable: true, Status: &nodeStatus{Role: "core-1", Version: "0.9.7-dev+abc"}},
		{Reachable: true, Status: &nodeStatus{Role: "core-2", Version: "0.9.7-dev+def"}},
		{Reachable: true, Status: &nodeStatus{Role: "core-3", Version: "0.9.7-dev+def"}},
	}
	got := versionMismatchWarning(nodes)
	for _, want := range []string{"abc", "def", "core-1", "core-2,core-3"} {
		if !strings.Contains(got, want) {
			t.Errorf("versionMismatchWarning() = %q missing %q — must name which node runs which version", got, want)
		}
	}
}

func TestVersionMismatchWarning_UnreachableNodeIgnored(t *testing.T) {
	nodes := []nodeData{
		{Reachable: true, Status: &nodeStatus{Role: "core-1", Version: "0.9.7-dev+abc"}},
		{Reachable: false, Status: &nodeStatus{Role: "core-2", Version: "0.9.7-dev+def"}},
	}
	if got := versionMismatchWarning(nodes); got != "" {
		t.Errorf("got %q, want \"\" — an unreachable node's stale version must not count", got)
	}
}

func TestDisabledScopeSet_ReachableCoreNodesOnly(t *testing.T) {
	nodes := []nodeData{
		{Reachable: true, Status: &nodeStatus{Role: "core-1", DisabledScopes: []string{"test-2"}}},
		{Reachable: false, Status: &nodeStatus{Role: "core-2", DisabledScopes: []string{"x"}}},
	}
	got := disabledScopeSet(nodes)
	if len(got) != 1 || !got["test-2"] {
		t.Errorf("disabledScopeSet = %v, want only test-2", got)
	}
}

func TestWithoutDisabledScopes_DropsOnlyDisabled(t *testing.T) {
	in := map[string]map[string]probeResult{"p:1": {"test-2": {}, "test3": {}}}
	out := withoutDisabledScopes(in, map[string]bool{"test-2": true})
	if _, ok := out["p:1"]["test-2"]; ok || len(out["p:1"]) != 1 {
		t.Errorf("withoutDisabledScopes = %v, want only test3", out)
	}
}
