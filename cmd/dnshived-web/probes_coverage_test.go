package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func fetchOK(scope string, at time.Time) probeFetch {
	return probeFetch{scope: scope, worker: "probe-42", pr: probeResult{Enabled: true, Reachable: true, ProbedAt: at.Format(time.RFC3339)}}
}

// The summary must account for every configured scope, including ones with
// probing disabled.
func TestProbeCoverage_DisabledScopeIsShownNotHidden(t *testing.T) {
	now := time.Now()
	results := []probeFetch{
		fetchOK("a", now), fetchOK("b", now),
		{scope: "c", worker: "probe-42", pr: probeResult{Enabled: false, Reachable: true}},
	}
	cov := probeCoverageOf(results, now, nil)
	if cov.Total != 3 || cov.Probed != 2 || cov.Disabled != 1 {
		t.Fatalf("coverage = %+v, want 2 probed + 1 disabled of 3", cov)
	}
	text, class := probeSummaryWithCoverage(nil, 0, cov)
	if !strings.Contains(text, "probed 2 of 3 scope(s)") || !strings.Contains(text, "1 probe switched off") {
		t.Errorf("summary %q lacks the coverage clause", text)
	}
	if class != "ok" {
		t.Errorf("class = %q, want ok — a deliberate opt-out is not a fault", class)
	}
}

func TestProbeCoverage_AllProbed(t *testing.T) {
	now := time.Now()
	cov := probeCoverageOf([]probeFetch{fetchOK("a", now), fetchOK("b", now)}, now, nil)
	text, class := probeSummaryWithCoverage(nil, 0, cov)
	if text != "all healthy — probed 2 of 2 scope(s)" || class != "ok" {
		t.Errorf("got (%q, %q)", text, class)
	}
}

// A stale result (probe host stopped refreshing it) is neither healthy nor
// silently counted as probed; pending and no-coverage need attention too.
func TestProbeCoverage_StalePendingNoCoverageNeedAttention(t *testing.T) {
	now := time.Now()
	old := now.Add(-2 * probeStaleAfter)
	results := []probeFetch{
		fetchOK("fresh", now),
		fetchOK("stale", old),
		{scope: "pend", worker: "probe-42", pr: probeResult{Pending: true}},
		{scope: "nocov", worker: "probe-42", pr: probeResult{}},
		{scope: "down", worker: "probe-42", err: errors.New("dial: refused")},
	}
	cov := probeCoverageOf(results, now, nil)
	if cov.Probed != 1 || cov.Stale != 1 || cov.Pending != 1 || cov.NoCoverage != 1 || cov.Unknown != 1 {
		t.Fatalf("coverage = %+v", cov)
	}
	text, class := probeSummaryWithCoverage(nil, cov.Pending, cov)
	if class == "ok" {
		t.Errorf("class = ok for %q, want warn or worse", text)
	}
	for _, want := range []string{"probed 1 of 5", "stale", "pending first sweep", "no VLAN coverage", "unreachable"} {
		if !strings.Contains(text, want) {
			t.Errorf("summary %q missing %q", text, want)
		}
	}
}

func TestProbeCoverage_MultipleHostsCountChecks(t *testing.T) {
	now := time.Now()
	a, b := fetchOK("a", now), fetchOK("a", now)
	b.worker = "probe-43"
	if got := probeCoverageOf([]probeFetch{a, b}, now, nil).text(); got != "probed 2 of 2 probe check(s)" {
		t.Errorf("text = %q", got)
	}
}

// A disabled scope is counted as such, not as a probe-only opt-out, and
// never needs attention.
func TestProbeCoverage_ScopeDisabledCountedSeparately(t *testing.T) {
	now := time.Now()
	results := []probeFetch{
		fetchOK("a", now),
		{scope: "off", worker: "probe-42", pr: probeResult{Enabled: false, Reachable: true}},
		{scope: "probeoff", worker: "probe-42", pr: probeResult{Enabled: false, Reachable: true}},
	}
	cov := probeCoverageOf(results, now, map[string]bool{"off": true})
	if cov.ScopeDisabled != 1 || cov.Disabled != 1 || cov.Probed != 1 {
		t.Fatalf("coverage = %+v, want 1 scope disabled, 1 probe off, 1 probed", cov)
	}
	text, class := probeSummaryWithCoverage(nil, 0, cov)
	if !strings.Contains(text, "1 not probed (scope disabled)") || !strings.Contains(text, "1 probe switched off") {
		t.Errorf("summary %q does not tell the two apart", text)
	}
	if class != "ok" {
		t.Errorf("class = %q, want ok", class)
	}
}
