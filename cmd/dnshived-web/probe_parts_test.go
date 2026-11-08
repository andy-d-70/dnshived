// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProbeClassParts_PendingPartIsDimNotRed(t *testing.T) {
	pr := probeResult{Enabled: true, Reachable: true, DHCPPending: true}
	pr.DNS.Valid = true

	dnsText, dnsClass, dhcpText, dhcpClass := probeClassParts(pr, true, false)

	if dnsText != "DNS✔" || dnsClass != "ok" {
		t.Errorf("dns = %q/%q, want the DNS result shown while DHCP is pending", dnsText, dnsClass)
	}
	if dhcpText != "DHCP…" || dhcpClass != "warn" {
		t.Errorf("dhcp = %q/%q, want an orange pending marker, not a red failure", dhcpText, dhcpClass)
	}
}

func TestProbeClass_PendingPartKeepsAFailingPartVisible(t *testing.T) {
	pr := probeResult{Enabled: true, Reachable: true, DHCPPending: true}
	text, class := probeClass(pr, true)
	if class != "warn" || text != "DNS✖ DHCP…" {
		t.Errorf("got %q/%q, want a failing DNS leg to stay a warning beside the pending DHCP leg", text, class)
	}
	pr.DNS.Valid = true
	if _, class := probeClass(pr, true); class != "dim" {
		t.Errorf("class = %q, want dim while one leg is good and the other pending", class)
	}
}

func TestProbeResult_OldestProbedAtIsThePartThatIsStalest(t *testing.T) {
	now := time.Now().UTC()
	pr := probeResult{
		ProbedAt:     now.Format(time.RFC3339),
		DHCPProbedAt: now.Add(-8 * time.Minute).Format(time.RFC3339),
		DNSProbedAt:  now.Format(time.RFC3339),
	}
	if got := pr.oldestProbedAt(); now.Sub(got) < 7*time.Minute {
		t.Errorf("oldestProbedAt = %v, want the DHCP stamp from 8 minutes ago", got)
	}
	pr.DHCPPending = true
	if got := pr.oldestProbedAt(); now.Sub(got) > time.Minute {
		t.Errorf("oldestProbedAt = %v, want a pending part ignored", got)
	}
	old := probeResult{ProbedAt: now.Add(-time.Hour).Format(time.RFC3339)}
	if got := old.oldestProbedAt(); now.Sub(got) < 59*time.Minute {
		t.Errorf("oldestProbedAt = %v, want the single stamp of an older probe host", got)
	}
}

func TestProbeCoverage_StaleIsJudgedPerPartAndPendingPartsAreCounted(t *testing.T) {
	now := time.Now().UTC()
	fresh := now.Format(time.RFC3339)
	old := now.Add(-probeStaleAfter - time.Minute).Format(time.RFC3339)
	mk := func(pr probeResult) probeFetch {
		pr.Enabled, pr.Reachable = true, true
		return probeFetch{scope: "s", worker: "probe", pr: pr}
	}
	results := []probeFetch{
		mk(probeResult{ProbedAt: fresh, DHCPProbedAt: fresh, DNSProbedAt: fresh}),
		mk(probeResult{ProbedAt: fresh, DHCPProbedAt: old, DNSProbedAt: fresh}),
		mk(probeResult{ProbedAt: fresh, DNSProbedAt: fresh, DHCPPending: true}),
	}

	c := probeCoverageOf(results, now, nil)

	if c.Probed != 1 || c.Stale != 1 || c.Pending != 1 {
		t.Errorf("coverage probed=%d stale=%d pending=%d, want 1/1/1", c.Probed, c.Stale, c.Pending)
	}
}

func TestProbeNumbersAgree_PendingPartsAreCountedTheSameEverywhere(t *testing.T) {
	now := time.Now().UTC()
	fresh := now.Format(time.RFC3339)
	mk := func(scope string, pr probeResult) probeFetch {
		pr.Enabled, pr.Reachable = true, true
		return probeFetch{scope: scope, worker: "probe", pr: pr}
	}
	results := []probeFetch{
		mk("a", probeResult{ProbedAt: fresh, DHCPProbedAt: fresh, DNSProbedAt: fresh}),
		mk("b", probeResult{ProbedAt: fresh, DNSProbedAt: fresh, DHCPPending: true}),
		mk("c", probeResult{ProbedAt: fresh, DHCPProbedAt: fresh, DNSPending: true}),
		mk("d", probeResult{Pending: true}),
	}

	cov := probeCoverageOf(results, now, nil)
	_, _, pending := classifyProbeResults(results, nil, nil, map[string]bool{})

	if cov.Pending != 3 || pending != cov.Pending {
		t.Fatalf("coverage pending=%d, classified pending=%d, want both 3", cov.Pending, pending)
	}
	if swept := sweptScopeCount(len(results), pending); swept != cov.Probed {
		t.Errorf("swept=%d probed=%d, want the same number", swept, cov.Probed)
	}
}

func TestBuildProbeDetailData_PendingPartIsFlaggedNotShownAsNoAnswer(t *testing.T) {
	pr := probeResult{Enabled: true, Reachable: true, DHCPPending: true}
	pr.DNS.Valid = true

	d := buildProbeDetailData("s1", "probe", pr, nil, false, true, false)

	if !d.DHCPPending || d.DNSPending || d.DHCPVerdict != "" {
		t.Fatalf("detail %+v, want DHCP flagged pending with no verdict", d)
	}
}

func TestManualProbeRowOf_WordingAndColors(t *testing.T) {
	now := time.Now().UTC()
	at := now.Add(-30 * time.Second).Format(time.RFC3339)
	tests := []struct {
		name  string
		in    watchResult
		text  string
		class string
	}{
		{"pending is orange", watchResult{Name: "a", Interface: "ens19", Pending: true}, "pending…", "warn"},
		{"rogue is red", watchResult{Name: "a", Interface: "ens19", Verdict: "rogue", Unexpected: []string{"10.0.0.99"}, ProbedAt: at}, "ROGUE 10.0.0.99", "crit"},
		{"expected only is green", watchResult{Name: "a", Interface: "ens19", Verdict: "ok", ProbedAt: at}, "only known servers", "ok"},
		{"quiet is green", watchResult{Name: "a", Interface: "ens19", Verdict: "clear", ProbedAt: at}, "no DHCP server answered", "ok"},
		{"error is never green", watchResult{Name: "a", Interface: "ens19", Verdict: "error", Error: "no such interface", ProbedAt: at}, "error: no such interface", "warn"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			row := manualProbeRowOf(tt.in, now, false)
			if row.ResultText != tt.text || row.ResultClass != tt.class {
				t.Errorf("got %q/%q, want %q/%q", row.ResultText, row.ResultClass, tt.text, tt.class)
			}
		})
	}
	if row := manualProbeRowOf(watchResult{Name: "a", Interface: "ens19", VLANID: 300, Verdict: "clear", ProbedAt: at}, now, false); row.VLAN != "300" || row.Age != "30s ago" {
		t.Errorf("row %+v, want VLAN 300 and an age", row)
	}
}

func TestParseExpectedServers(t *testing.T) {
	got := parseExpectedServers("10.0.0.1, 10.0.0.2\n10.0.0.3  10.0.0.4")
	if strings.Join(got, "|") != "10.0.0.1|10.0.0.2|10.0.0.3|10.0.0.4" {
		t.Errorf("got %v", got)
	}
	if got := parseExpectedServers("  \n"); len(got) != 0 {
		t.Errorf("got %v, want none", got)
	}
}

func TestManualProbeIssues_OnlyARogueFindingIsAnIssue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"manual_probes": []watchResult{
			{Name: "quiet", Interface: "ens18", Verdict: "clear"},
			{Name: "bad", Interface: "ens19", VLANID: 300, Verdict: "rogue", Unexpected: []string{"10.0.0.99"}},
			{Name: "wait", Interface: "ens20", Pending: true},
		}})
	}))
	defer srv.Close()

	issues := manualProbeIssues([]NodeConfig{{Name: "probe", Addr: strings.TrimPrefix(srv.URL, "http://")}})

	if len(issues) != 1 || !issues[0].Rogue || issues[0].DHCPClass != "crit" || !strings.Contains(issues[0].Detail, "ens19 VLAN 300") {
		t.Fatalf("issues = %+v, want exactly the rogue finding, naming its interface and VLAN", issues)
	}
}

func TestProbesTmpl_PagingLinksKeepThePositionOnTheResultsTable(t *testing.T) {
	data := probesPageData{
		ProbeHostNames: []string{"probe"},
		Page:           2, TotalPages: 3, PrevPage: 1, NextPage: 3,
		probeManagementData: probeManagementData{ProbeHostDisplayNames: map[string]string{}},
	}
	var buf strings.Builder
	if err := probesTmpl.Execute(&buf, data); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{`href="/probes?page=1#results"`, `href="/probes?page=3#results"`, `href="?page=2#results"`} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q: without the anchor the browser loads the page from the top, far above the results table", want)
		}
	}
}

func TestManualProbeChips_KnownUnknownSilentAndServedSegments(t *testing.T) {
	w := watchResult{Name: "seg", Interface: "ens18", Verdict: "rogue",
		Servers: []string{"192.168.0.1", "192.168.0.99"}, ExpectedServers: []string{"192.168.0.1", "192.168.0.7"}, Unexpected: []string{"192.168.0.99"}}

	row := manualProbeRowOf(w, time.Now(), false)

	if len(row.Chips) != 3 {
		t.Fatalf("chips = %+v, want known, unknown and known-but-silent", row.Chips)
	}
	got := map[string]serverChip{}
	for _, c := range row.Chips {
		got[c.Server] = c
	}
	if c := got["192.168.0.1"]; c.Label != "known" || c.Class != "ok" || c.Action != "unack" || !c.CanToggle {
		t.Errorf("known chip = %+v", c)
	}
	if c := got["192.168.0.99"]; c.Label != "unknown" || c.Class != "crit" || c.Action != "ack" || !c.CanToggle {
		t.Errorf("unknown chip = %+v", c)
	}
	if c := got["192.168.0.7"]; c.Label != "known, silent" || c.Class != "dim" || c.Action != "unack" {
		t.Errorf("silent chip = %+v", c)
	}

	served := manualProbeRowOf(w, time.Now(), true)
	for _, c := range served.Chips {
		if c.Server == "192.168.0.99" && (c.CanToggle || !strings.Contains(c.Title, "cannot be acknowledged")) {
			t.Errorf("on a served segment an unknown server must not be acknowledgeable: %+v", c)
		}
	}
}

func TestEditExpected_AddsAndRemovesOnlyOnTheNamedProbe(t *testing.T) {
	current := []watchResult{
		{Name: "a", Interface: "ens18", ExpectedServers: []string{"10.0.0.1"}},
		{Name: "b", Interface: "ens19", VLANID: 300, ExpectedServers: []string{"10.0.0.5"}},
	}
	list, found := editExpected(current, "a", "10.0.0.2", true)
	if !found || strings.Join(list[0].ExpectedServers, ",") != "10.0.0.1,10.0.0.2" || strings.Join(list[1].ExpectedServers, ",") != "10.0.0.5" {
		t.Fatalf("add: %+v", list)
	}
	list, _ = editExpected(current, "a", "10.0.0.1", false)
	if len(list[0].ExpectedServers) != 0 || list[1].VLANID != 300 {
		t.Fatalf("remove: %+v", list)
	}
	if _, found := editExpected(current, "nope", "10.0.0.1", true); found {
		t.Error("an unknown probe name must not be found")
	}
}
