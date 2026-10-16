// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"

	"dnshived/internal/config"
)

func TestProbeHostRowName_UsesDisplayNameFallback(t *testing.T) {
	if got := probeHostRowName(NodeConfig{Name: "probe", DisplayName: "Lab Probe"}); got != "Lab Probe" {
		t.Errorf("probeHostRowName(...) = %q, want %q", got, "Lab Probe")
	}
	if got := probeHostRowName(NodeConfig{Name: "probe2"}); got != "probe2" {
		t.Errorf("probeHostRowName(...) = %q, want %q (fallback to Name)", got, "probe2")
	}
}

func TestStatusTmpl_RendersProbeHostRows(t *testing.T) {
	data := overviewData{
		ClusterState: "STABLE",
		ClusterClass: "ok",
		ProbeHostRows: []probeHostOverviewRow{
			{Name: "probe-a", Addr: "192.168.0.42:9444", Icon: "✔", Class: "ok", Info: "0 scope(s)", Version: "0.9.7-dev+1155c7e", SysStr: "load 0.05  mem 24%"},
			{Name: "probe-b", Addr: "192.168.0.43:9444", Icon: "DOWN", Class: "crit", Info: "dial tcp: timeout"},
		},
	}
	var buf bytes.Buffer
	if err := statusTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("statusTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "load 0.05  mem 24%") {
		t.Error("expected probe-a's row and load/mem to render")
	}
	if !strings.Contains(out, `<td class="node-probe">probe-a</td>`) {
		t.Error("expected probe host row's Name column to show its own nickname (probe-a), not a hardcoded label")
	}
	if !strings.Contains(out, `<td class="node-probe">probe</td>`) {
		t.Error("expected probe host row's Role column to still show the fixed \"probe\" label")
	}
	if !strings.Contains(out, "0.9.7-dev") || !strings.Contains(out, "1155c7e") {
		t.Error("expected probe-a's version to render")
	}
	if !strings.Contains(out, "dial tcp: timeout") {
		t.Error("expected probe-b's error text to render")
	}
}

func TestStatusTmpl_ProbeHostRowShowsRunningStatusWord(t *testing.T) {
	data := overviewData{
		ClusterState: "STABLE",
		ClusterClass: "ok",
		ProbeHostRows: []probeHostOverviewRow{
			{Name: "probe-a", Addr: "192.168.0.42:9444", Icon: "✔", Class: "ok", State: "RUNNING", Info: "0 scope(s)"},
			{Name: "probe-b", Addr: "192.168.0.43:9444", Icon: "✖", Class: "crit", State: "DOWN", Info: "dial tcp: timeout"},
		},
	}
	var buf bytes.Buffer
	if err := statusTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("statusTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "RUNNING") {
		t.Error("expected the healthy probe host row to show RUNNING")
	}
	if !strings.Contains(out, "DOWN") {
		t.Error("expected the unreachable probe host row to show DOWN")
	}
}

// TestStatusTmpl_OmitsProbeHostRowsWhenUnset confirms no divider/rows
// appear when no probe hosts are configured (the common case).
func TestComputeRowDisplay_NicknameFallsBackToNodeName(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1", DisplayName: "office-rack-3"}},
		{Node: NodeConfig{Name: "core-2"}},
		{Node: NodeConfig{Name: "core-3"}, FetchError: "dial tcp: timeout"},
	}
	computeRowDisplay(rows)
	if rows[0].Nickname != "office-rack-3" {
		t.Errorf("rows[0].Nickname = %q, want the operator's own DisplayName", rows[0].Nickname)
	}
	if rows[1].Nickname != "core-2" {
		t.Errorf("rows[1].Nickname = %q, want the plain role as fallback", rows[1].Nickname)
	}
	if rows[2].Nickname != "core-3" {
		t.Errorf("rows[2].Nickname = %q, want the plain role even on an unreachable row", rows[2].Nickname)
	}
}

func TestComputeRowDisplay_HoldsMgmtVIP(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", HoldsMgmtVIP: true}},
		{Node: NodeConfig{Name: "core-2"}, Status: nodeStatus{Role: "core-2", HoldsMgmtVIP: false}},
		{Node: NodeConfig{Name: "probe-1"}, Status: nodeStatus{Role: "probe", HoldsMgmtVIP: true}},
		{Node: NodeConfig{Name: "core-3"}, Status: nodeStatus{Role: "core-3", HoldsMgmtVIP: true}, FetchError: "dial tcp: timeout"},
	}
	computeRowDisplay(rows)
	if !rows[0].HoldsMgmtVIP {
		t.Error("rows[0].HoldsMgmtVIP = false, want true (reachable core role, currently MASTER)")
	}
	if rows[1].HoldsMgmtVIP {
		t.Error("rows[1].HoldsMgmtVIP = true, want false (reachable core role, not MASTER)")
	}
	if rows[2].HoldsMgmtVIP {
		t.Error("rows[2].HoldsMgmtVIP = true, want false — a probe host never runs the mgmt-VIP instance")
	}
	if rows[3].HoldsMgmtVIP {
		t.Error("rows[3].HoldsMgmtVIP = true, want false — an unreachable row must never claim to hold the VIP")
	}
}

// TestStatusTmpl_RendersHostnameAndNicknameColumns is the full render-path
// regression test for the same feature.
func TestStatusTmpl_RendersHostnameAndNicknameColumns(t *testing.T) {
	data := overviewData{
		ClusterState: "STABLE",
		ClusterClass: "ok",
		Rows: []statusRow{
			{
				Node:     NodeConfig{Name: "core-1", Addr: "192.168.0.25:9443", DisplayName: "the fast one"},
				Status:   nodeStatus{Role: "core-1", Hostname: "node-a", State: "STABLE"},
				Nickname: "the fast one",
				Class:    "ok",
			},
		},
	}
	var buf bytes.Buffer
	if err := statusTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("statusTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "<th>Host</th>") {
		t.Error("expected a Host column header in the Workers table")
	}
	if !strings.Contains(out, "the fast one") {
		t.Error("expected the row's nickname to render in the Name column")
	}
	if !strings.Contains(out, "node-a") {
		t.Error("expected the row's real OS hostname to render in the Host column")
	}
	if !strings.Contains(out, "192.168.0.25:9443") {
		t.Error("expected the Addr column to still render the real IP alongside hostname")
	}
}

// TestStatusTmpl_RendersVIPBadgeWhenHoldsMgmtVIP checks the mgmt VIP badge
// renders on the holding node.
func TestStatusTmpl_RendersVIPBadgeWhenHoldsMgmtVIP(t *testing.T) {
	data := overviewData{
		ClusterState: "STABLE",
		ClusterClass: "ok",
		Rows: []statusRow{
			{
				Node:         NodeConfig{Name: "core-3"},
				Status:       nodeStatus{Role: "core-3", State: "STABLE"},
				Nickname:     "core-3",
				Class:        "ok",
				HoldsMgmtVIP: true,
			},
			{
				Node:     NodeConfig{Name: "core-1"},
				Status:   nodeStatus{Role: "core-1", State: "STABLE"},
				Nickname: "core-1",
				Class:    "ok",
			},
		},
	}
	var buf bytes.Buffer
	if err := statusTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("statusTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	if n := strings.Count(out, `class="vip-badge"`); n != 1 {
		t.Errorf(`expected exactly one class="vip-badge" span in the rendered output, got %d occurrence(s)`, n)
	}
}

func TestStatusTmpl_OmitsProbeHostRowsWhenUnset(t *testing.T) {
	data := overviewData{ClusterState: "STABLE", ClusterClass: "ok"}
	var buf bytes.Buffer
	if err := statusTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("statusTmpl.Execute failed: %v", err)
	}
	if strings.Contains(buf.String(), "border-top:3px solid #888") {
		t.Error("expected no probe-host divider row when ProbeHostRows is empty")
	}
	if strings.Contains(buf.String(), "<td>probe</td>") {
		t.Error("expected no probe-host rows when ProbeHostRows is empty")
	}
}

func TestStatusTmpl_ProbeIssuesColorEachLegIndependently(t *testing.T) {
	data := overviewData{
		ClusterState: "STABLE",
		ClusterClass: "ok",
		ProbeIssues: []probeIssue{
			{Scope: "rw-200", Worker: "probe-a", DNSText: "DNS✖", DNSClass: "crit", DHCPText: "DHCP✔", DHCPClass: "ok"},
			{Scope: "rw-201", Worker: "probe-a", DHCPText: "DHCP✖DUAL", DHCPClass: "crit"},
		},
	}
	var buf bytes.Buffer
	if err := statusTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("statusTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `<a href="/probes/rw-200/probe-a">rw-200</a>`) {
		t.Errorf("expected rw-200's scope name to link to its own probe detail page, got:\n%s", out)
	}
	if !strings.Contains(out, `<span class="crit">DNS✖</span>`) {
		t.Errorf("expected rw-200's DNS leg to render crit independently, got:\n%s", out)
	}
	if !strings.Contains(out, `<span class="ok">DHCP✔</span>`) {
		t.Errorf("expected rw-200's healthy DHCP✔ leg to render ok, NOT inherit the line's DNS crit color, got:\n%s", out)
	}
	if !strings.Contains(out, `<span class="crit">DHCP✖DUAL</span>`) {
		t.Errorf("expected rw-201's DHCP leg to render crit, got:\n%s", out)
	}
}

func TestScopesMismatch_AllThreeCoreRolesCompared(t *testing.T) {
	agreeing := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", ScopesHash: "abc123"}},
		{Node: NodeConfig{Name: "core-2"}, Status: nodeStatus{Role: "core-2", ScopesHash: "abc123"}},
		{Node: NodeConfig{Name: "core-3"}, Status: nodeStatus{Role: "core-3", ScopesHash: "abc123"}},
	}
	if scopesMismatch(agreeing) {
		t.Error("scopesMismatch() = true, want false — all three core roles genuinely agree")
	}

	drifted := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", ScopesHash: "abc123"}},
		{Node: NodeConfig{Name: "core-2"}, Status: nodeStatus{Role: "core-2", ScopesHash: "abc123"}},
		{Node: NodeConfig{Name: "core-3"}, Status: nodeStatus{Role: "core-3", ScopesHash: "000000"}},
	}
	if !scopesMismatch(drifted) {
		t.Error("scopesMismatch() = false, want true — core-3's genuinely differing hash is now a real drift finding, not exempt")
	}
}

func TestArbiterQuorumStatus_AllThreeReachable(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: config.RoleCore1, PeersVisible: []string{"c2", "c3"}}},
		{Node: NodeConfig{Name: "core-2"}, Status: nodeStatus{Role: config.RoleCore2, PeersVisible: []string{"c1", "c3"}}},
		{Node: NodeConfig{Name: "core-3"}, Status: nodeStatus{Role: config.RoleCore3, PeersVisible: []string{"c1", "c2"}}},
	}
	text, class := arbiterQuorumStatus(rows)
	if class != "ok" {
		t.Errorf("class = %q, want ok for 3/3 reachable with full peer knowledge", class)
	}
	if !strings.HasPrefix(text, "3/3") {
		t.Errorf("text = %q, want it to start with 3/3", text)
	}
}

func TestArbiterQuorumStatus_ArbiterDown_StillHasQuorum(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: config.RoleCore1, PeersVisible: []string{"c2"}, PeersUnreachable: []string{"c3"}}},
		{Node: NodeConfig{Name: "core-2"}, Status: nodeStatus{Role: config.RoleCore2, PeersVisible: []string{"c1"}, PeersUnreachable: []string{"c3"}}},
		{Node: NodeConfig{Name: "core-3"}, FetchError: "connection refused"},
	}
	text, class := arbiterQuorumStatus(rows)
	if class != "warn" {
		t.Errorf("class = %q, want warn for 2/3 reachable (quorum still held)", class)
	}
	if !strings.HasPrefix(text, "2/3") {
		t.Errorf("text = %q, want it to start with 2/3", text)
	}
}

func TestArbiterQuorumStatus_QuorumLost(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: config.RoleCore1, PeersUnreachable: []string{"c2", "c3"}}},
		{Node: NodeConfig{Name: "core-2"}, FetchError: "connection refused"},
		{Node: NodeConfig{Name: "core-3"}, FetchError: "connection refused"},
	}
	text, class := arbiterQuorumStatus(rows)
	if class != "crit" {
		t.Errorf("class = %q, want crit for 1/3 reachable (quorum lost)", class)
	}
	if !strings.HasPrefix(text, "1/3") {
		t.Errorf("text = %q, want it to start with 1/3", text)
	}
}

func TestArbiterQuorumStatus_ProbeHostsIgnored(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: config.RoleCore1, PeersVisible: []string{"c2", "c3"}}},
		{Node: NodeConfig{Name: "core-2"}, Status: nodeStatus{Role: config.RoleCore2, PeersVisible: []string{"c1", "c3"}}},
		{Node: NodeConfig{Name: "core-3"}, Status: nodeStatus{Role: config.RoleCore3, PeersVisible: []string{"c1", "c2"}}},
		{Node: NodeConfig{Name: "probe-1"}, Status: nodeStatus{Role: "probe"}},
	}
	text, _ := arbiterQuorumStatus(rows)
	if !strings.HasPrefix(text, "3/3") {
		t.Errorf("text = %q, want 3/3 — a probe host row must never inflate the count", text)
	}
}

func TestArbiterQuorumStatus_DegradedPeerKnowledgeStillWarn(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: config.RoleCore1, PeersVisible: []string{"c2"}}},
		{Node: NodeConfig{Name: "core-2"}, Status: nodeStatus{Role: config.RoleCore2, PeersVisible: []string{"c1"}}},
		{Node: NodeConfig{Name: "core-3"}, Status: nodeStatus{Role: config.RoleCore3, PeersVisible: []string{"c1", "c2"}}},
	}
	text, class := arbiterQuorumStatus(rows)
	if class != "warn" {
		t.Errorf("class = %q, want warn — all 3 reachable but a real peer-knowledge gap exists", class)
	}
	if !strings.HasPrefix(text, "3/3") {
		t.Errorf("text = %q, want it to still start with 3/3 (all 3 ARE reachable)", text)
	}
	if !strings.Contains(text, "knows only 1/2") {
		t.Errorf("text = %q, want it to name the real degraded-peer-knowledge finding", text)
	}
}

func TestScopesMismatch_RealWorkerDivergenceDetected(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", ScopesHash: "abc123"}},
		{Node: NodeConfig{Name: "core-2"}, Status: nodeStatus{Role: "core-2", ScopesHash: "def456"}},
		{Node: NodeConfig{Name: "core-3"}, Status: nodeStatus{Role: "core-3", ScopesHash: "000000"}},
	}
	if !scopesMismatch(rows) {
		t.Error("scopesMismatch() = false, want true — the two workers genuinely disagree")
	}
}

func TestScopesMismatch_UnreachableNodeIgnored(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", ScopesHash: "abc123"}},
		{Node: NodeConfig{Name: "core-2"}, FetchError: "connection refused"},
	}
	if scopesMismatch(rows) {
		t.Error("scopesMismatch() = true, want false — an unreachable node has no hash to compare, shouldn't be treated as a mismatch")
	}
}

// TestConfigHashMismatch_AllThreeRolesAgreeIsNoMismatch confirms the
// arbiter is compared on equal footing here, unlike scopesMismatch.
func TestConfigHashMismatch_AllThreeRolesAgreeIsNoMismatch(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", ConfigHash: "abc123"}},
		{Node: NodeConfig{Name: "core-2"}, Status: nodeStatus{Role: "core-2", ConfigHash: "abc123"}},
		{Node: NodeConfig{Name: "core-3"}, Status: nodeStatus{Role: "core-3", ConfigHash: "abc123"}},
	}
	if configHashMismatch(rows) {
		t.Error("configHashMismatch() = true, want false — all three roles genuinely agree")
	}
}

func TestConfigHashMismatch_ArbiterStaleAfterPartialPush(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", ConfigHash: "new-hash"}},
		{Node: NodeConfig{Name: "core-2"}, Status: nodeStatus{Role: "core-2", ConfigHash: "new-hash"}},
		{Node: NodeConfig{Name: "core-3"}, Status: nodeStatus{Role: "core-3", ConfigHash: "old-stale-hash"}},
	}
	if !configHashMismatch(rows) {
		t.Error("configHashMismatch() = false, want true — the arbiter's own copy genuinely drifted from the two workers")
	}
}

func TestConfigHashMismatch_UnreachableNodeIgnored(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", ConfigHash: "abc123"}},
		{Node: NodeConfig{Name: "core-2"}, FetchError: "connection refused"},
	}
	if configHashMismatch(rows) {
		t.Error("configHashMismatch() = true, want false — an unreachable node has no hash to compare, shouldn't be treated as a mismatch")
	}
}

func TestVersionMismatchWarning_AllAgreeIsEmpty(t *testing.T) {
	rows := []statusRow{
		{Status: nodeStatus{Role: "core-1", Version: "0.9.7-dev+abc"}},
		{Status: nodeStatus{Role: "core-2", Version: "0.9.7-dev+abc"}},
	}
	if got := versionMismatchWarning(rows); got != "" {
		t.Errorf("got %q, want \"\" when every node agrees", got)
	}
}

func TestVersionMismatchWarning_NamesWhichNodeRunsWhichVersion(t *testing.T) {
	rows := []statusRow{
		{Status: nodeStatus{Role: "core-1", Version: "0.9.7-dev+abc"}},
		{Status: nodeStatus{Role: "core-2", Version: "0.9.7-dev+def"}},
		{Status: nodeStatus{Role: "core-3", Version: "0.9.7-dev+def"}},
	}
	got := versionMismatchWarning(rows)
	for _, want := range []string{"abc", "def", "core-1", "core-2,core-3"} {
		if !strings.Contains(got, want) {
			t.Errorf("versionMismatchWarning() = %q missing %q — must name which node runs which version", got, want)
		}
	}
}

func TestVersionMismatchWarning_UnreachableNodeIgnored(t *testing.T) {
	rows := []statusRow{
		{Status: nodeStatus{Role: "core-1", Version: "0.9.7-dev+abc"}},
		{FetchError: "connection refused", Status: nodeStatus{Role: "core-2", Version: "0.9.7-dev+def"}},
	}
	if got := versionMismatchWarning(rows); got != "" {
		t.Errorf("got %q, want \"\" — an unreachable node's stale version must not count", got)
	}
}

// clusterStableSince/formatDuration tests — ported identically from
// dnshived-top's own copies.

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

func TestClusterStableSince_LatestAmongAllNodes(t *testing.T) {
	older := time.Date(2026, 8, 2, 9, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 8, 2, 9, 30, 0, 0, time.UTC)
	rows := []statusRow{
		{Status: nodeStatus{StateSince: older.Format(time.RFC3339)}},
		{Status: nodeStatus{StateSince: newer.Format(time.RFC3339)}},
	}
	got, ok := clusterStableSince(rows)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if !got.Equal(newer) {
		t.Errorf("got = %v, want the later (weakest-link) timestamp %v", got, newer)
	}
}

func TestClusterStableSince_UnreachableNodeMeansUnknown(t *testing.T) {
	rows := []statusRow{
		{Status: nodeStatus{StateSince: time.Now().Format(time.RFC3339)}},
		{FetchError: "connection refused"},
	}
	if _, ok := clusterStableSince(rows); ok {
		t.Error("ok = true, want false — an unreachable node must not be silently ignored")
	}
}

// A node that only lost its mgmt path (a reachable peer confirms it alive
// via fallback) must not void the cluster's stable-since time.
func TestClusterStableSince_MgmtOnlyDownNodeIsSkippedNotFatal(t *testing.T) {
	newer := time.Date(2026, 8, 2, 9, 30, 0, 0, time.UTC)
	rows := []statusRow{
		{Node: NodeConfig{Addr: "10.0.0.1:9443"}, Status: nodeStatus{StateSince: newer.Add(-time.Hour).Format(time.RFC3339)}},
		{Node: NodeConfig{Addr: "10.0.0.2:9443"}, Status: nodeStatus{StateSince: newer.Format(time.RFC3339)}},
		{Node: NodeConfig{Addr: "10.0.0.3:9443"}, FetchError: "dial tcp: network is unreachable"},
	}
	got, ok := clusterStableSince(rows, map[string]bool{"10.0.0.3:9443": true})
	if !ok || !got.Equal(newer) {
		t.Fatalf("got (%v, %v), want (%v, true) — mgmt-only-down node must be skipped", got, ok, newer)
	}
	if _, ok := clusterStableSince(rows); ok {
		t.Error("ok = true without a skip set, want false")
	}
}

// bannerText test cases ported from cmd/dnshived-top/main_test.go —
// same logic, ANSI colors replaced with CSS classes.

func TestBannerText_GettingThereBeforeScopesStart(t *testing.T) {
	text, class := bannerText(2, 2, 2, 2, 0, 5*time.Second)
	if class != "warn" {
		t.Errorf("class = %q, want warn while scopes haven't started serving", class)
	}
	if !strings.Contains(text, "GETTING THERE") {
		t.Errorf("text = %q, want it to say GETTING THERE", text)
	}
}

func TestBannerText_ProductionActiveOnceServing(t *testing.T) {
	text, class := bannerText(2, 2, 2, 2, 2, 0)
	if class != "ok" {
		t.Errorf("class = %q, want ok once every configured scope is being served", class)
	}
	if !strings.Contains(text, "PRODUCTION ACTIVE") {
		t.Errorf("text = %q, want PRODUCTION ACTIVE", text)
	}
}

func TestBannerText_ProductionActiveWhenNoScopesConfigured(t *testing.T) {
	text, class := bannerText(1, 1, 1, 0, 0, 0)
	if class != "ok" {
		t.Errorf("class = %q, want ok when there are no configured scopes to wait on", class)
	}
	if !strings.Contains(text, "PRODUCTION ACTIVE") {
		t.Errorf("text = %q, want PRODUCTION ACTIVE", text)
	}
}

func TestBannerText_NodeDownTakesPriorityOverSettling(t *testing.T) {
	text, class := bannerText(2, 2, 3, 2, 2, 0)
	if class != "crit" {
		t.Errorf("class = %q, want crit — a node is down", class)
	}
	if !strings.Contains(text, "NODE DOWN") {
		t.Errorf("text = %q, want NODE DOWN", text)
	}
}

func TestBannerText_EscalatesAfterSettlingTimeout(t *testing.T) {
	text, class := bannerText(2, 2, 2, 2, 0, settlingTimeout+time.Second)
	if class != "crit" {
		t.Errorf("class = %q, want crit once stuck past settlingTimeout", class)
	}
	if !strings.Contains(text, "NOT CONVERGING") {
		t.Errorf("text = %q, want it to say NOT CONVERGING", text)
	}
}

func TestBannerText_StillGettingThereRightAtTheTimeoutBoundary(t *testing.T) {
	text, class := bannerText(2, 2, 2, 2, 0, settlingTimeout)
	if class != "warn" {
		t.Errorf("class = %q, want warn exactly at the boundary, not yet escalated", class)
	}
	if !strings.Contains(text, "GETTING THERE") {
		t.Errorf("text = %q, want GETTING THERE at the boundary", text)
	}
}

// checkCoherence has no upstream tests to port (dnshived-top's own copy
// has none) — fresh cases covering each of the 7 categories.

func TestCheckCoherence_DualActive(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", NodeID: "n1", Serving: []string{"office"}, Version: "v1"}},
		{Node: NodeConfig{Name: "core-2"}, Status: nodeStatus{Role: "core-2", NodeID: "n2", Serving: []string{"office"}, Version: "v1"}},
	}
	tokens := map[string]tokenInfo{"office": {Owner: "n1"}}
	warnings := checkCoherence(rows, tokens)
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "DUAL-ACTIVE") {
			found = true
		}
	}
	if !found {
		t.Errorf("checkCoherence() = %v, want a DUAL-ACTIVE warning", warnings)
	}
}

func TestCheckCoherence_NoTokenAndOrphanToken(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", NodeID: "n1", Serving: []string{"office"}, Version: "v1"}},
	}
	tokens := map[string]tokenInfo{"av-dante": {Owner: "n2"}}
	warnings := checkCoherence(rows, tokens)
	var hasNoToken, hasUnserved bool
	for _, w := range warnings {
		if strings.Contains(w, "NO TOKEN") {
			hasNoToken = true
		}
		if strings.Contains(w, "UNSERVED") {
			hasUnserved = true
		}
	}
	if !hasNoToken {
		t.Errorf("checkCoherence() = %v, want a NO TOKEN warning for office", warnings)
	}
	if !hasUnserved {
		t.Errorf("checkCoherence() = %v, want an UNSERVED warning for av-dante", warnings)
	}
}

func TestCheckCoherence_TokenMismatch(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", NodeID: "n1", Serving: []string{"office"}, Version: "v1"}},
	}
	tokens := map[string]tokenInfo{"office": {Owner: "n-someone-else"}}
	warnings := checkCoherence(rows, tokens)
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "TOKEN MISMATCH") {
			found = true
		}
	}
	if !found {
		t.Errorf("checkCoherence() = %v, want a TOKEN MISMATCH warning", warnings)
	}
}

func TestCheckCoherence_VersionMismatch(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", NodeID: "n1", Version: "0.9.7-dev"}},
		{Node: NodeConfig{Name: "core-2"}, Status: nodeStatus{Role: "core-2", NodeID: "n2", Version: "0.9.6-dev"}},
	}
	warnings := checkCoherence(rows, map[string]tokenInfo{})
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "VERSION MISMATCH") {
			found = true
		}
	}
	if !found {
		t.Errorf("checkCoherence() = %v, want a VERSION MISMATCH warning", warnings)
	}
}

func TestCheckCoherence_EpochDivergenceOnlyWhenBothStable(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", NodeID: "n1", State: "STABLE", Epoch: 5}},
		{Node: NodeConfig{Name: "core-2"}, Status: nodeStatus{Role: "core-2", NodeID: "n2", State: "STABLE", Epoch: 6}},
	}
	warnings := checkCoherence(rows, map[string]tokenInfo{})
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "EPOCH DIVERGENCE") {
			found = true
		}
	}
	if !found {
		t.Errorf("checkCoherence() = %v, want an EPOCH DIVERGENCE warning when both STABLE with different epochs", warnings)
	}

	// Not both STABLE — must not warn.
	rows[1].Status.State = "SETTLING"
	warnings = checkCoherence(rows, map[string]tokenInfo{})
	for _, w := range warnings {
		if strings.Contains(w, "EPOCH DIVERGENCE") {
			t.Errorf("checkCoherence() = %v, want no EPOCH DIVERGENCE when not both STABLE", warnings)
		}
	}
}

func TestCheckCoherence_ClockSkew(t *testing.T) {
	skewed := time.Now().Add(-30 * time.Second).UTC().Format(time.RFC3339)
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", NodeID: "n1", ServerTime: skewed}},
	}
	warnings := checkCoherence(rows, map[string]tokenInfo{})
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "CLOCK SKEW") {
			found = true
		}
	}
	if !found {
		t.Errorf("checkCoherence() = %v, want a CLOCK SKEW warning for a 30s-off server_time", warnings)
	}
}

func TestCheckCoherence_ClockSkew_UsesFetchedAtNotWallClock(t *testing.T) {
	fetchedAt := time.Now().Add(-11 * time.Second) // this row's own fetch returned 11s ago
	serverTime := fetchedAt.UTC().Format(time.RFC3339)
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", NodeID: "n1", ServerTime: serverTime}, FetchedAt: fetchedAt},
	}
	warnings := checkCoherence(rows, map[string]tokenInfo{})
	for _, w := range warnings {
		if strings.Contains(w, "CLOCK SKEW") {
			t.Errorf("checkCoherence() = %v, want no CLOCK SKEW warning — server_time matches its own FetchedAt exactly, real wall-clock time moving on since then is irrelevant", warnings)
		}
	}
}

func TestCheckCoherence_ClockSkew_StillCaughtRelativeToFetchedAt(t *testing.T) {
	fetchedAt := time.Now().Add(-11 * time.Second)
	serverTime := fetchedAt.Add(-30 * time.Second).UTC().Format(time.RFC3339)
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", NodeID: "n1", ServerTime: serverTime}, FetchedAt: fetchedAt},
	}
	warnings := checkCoherence(rows, map[string]tokenInfo{})
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "CLOCK SKEW") {
			found = true
		}
	}
	if !found {
		t.Errorf("checkCoherence() = %v, want a CLOCK SKEW warning — genuinely 30s off relative to its own FetchedAt", warnings)
	}
}

func TestCheckCoherence_Partition(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1", Addr: "192.168.0.22:9443"}, Status: nodeStatus{Role: "core-1", NodeID: "n1", PeersUnreachable: []string{"192.168.0.23:9443"}}},
		{Node: NodeConfig{Name: "core-2", Addr: "192.168.0.23:9443"}, Status: nodeStatus{Role: "core-2", NodeID: "n2"}},
	}
	warnings := checkCoherence(rows, map[string]tokenInfo{})
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "PARTITION") {
			found = true
		}
	}
	if !found {
		t.Errorf("checkCoherence() = %v, want a PARTITION warning — worker-b is reachable from here but worker-a can't see it", warnings)
	}
}

// TestConfigSaneStatus_SurfacesFindingWithNodeIdentity.
func TestConfigSaneStatus_SurfacesFindingWithNodeIdentity(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", NodeID: "n1",
			PlaneWarnings: []string{"scope rw-101: gate nftables gate is open, this node last set it closed"}}},
		{Node: NodeConfig{Name: "core-2"}, Status: nodeStatus{Role: "core-2", NodeID: "n2"}},
	}
	text, class, _ := configSaneStatus(rows)
	if class != "crit" {
		t.Errorf("configSaneStatus() class = %q, want crit", class)
	}
	if !strings.Contains(text, "core-1") || !strings.Contains(text, "rw-101") {
		t.Errorf("configSaneStatus() text = %q, want it to name worker-a and rw-101", text)
	}
}

func TestConfigSaneStatus_NoWarningsIsSane(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", NodeID: "n1"}},
	}
	text, class, title := configSaneStatus(rows)
	if class != "ok" || text != "yes" || title != "" {
		t.Errorf("configSaneStatus() = (%q, %q, %q), want (\"yes\", \"ok\", \"\") when PlaneWarnings is empty", text, class, title)
	}
}

func TestConfigSaneStatus_UnreachableNodeIgnored(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, FetchError: "timeout", Status: nodeStatus{Role: "core-1", NodeID: "n1",
			PlaneWarnings: []string{"scope rw-101: gate stale finding"}}},
	}
	text, class, _ := configSaneStatus(rows)
	if class != "ok" || text != "yes" {
		t.Errorf("configSaneStatus() = (%q, %q), want (\"yes\", \"ok\") — a stale finding from an unreachable node must be ignored", text, class)
	}
}

// TestConfigSaneStatus_GateVRRPCoherenceOnlyIsWarnNotCrit.
func TestConfigSaneStatus_GateVRRPCoherenceOnlyIsWarnNotCrit(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", NodeID: "n1",
			PlaneWarnings: []string{"scope debugwalk-1: gate_vrrp_coherence DHCP gate is open but VRRP state is BACKUP, not MASTER"}}},
	}
	text, class, title := configSaneStatus(rows)
	if class != "warn" {
		t.Errorf("configSaneStatus() class = %q, want warn (gate_vrrp_coherence is confirmed safe-by-design, must not render crit)", class)
	}
	if !strings.Contains(text, "debugwalk-1") {
		t.Errorf("configSaneStatus() text = %q, want it to still name the scope", text)
	}
	if title == "" || !strings.Contains(title, "preferred_worker") {
		t.Errorf("configSaneStatus() title = %q, want a real explanation mentioning preferred_worker", title)
	}
}

// TestConfigSaneStatus_MixedFindingsStayCrit.
func TestConfigSaneStatus_MixedFindingsStayCrit(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", NodeID: "n1",
			PlaneWarnings: []string{
				"scope debugwalk-1: gate_vrrp_coherence DHCP gate is open but VRRP state is BACKUP, not MASTER",
				"scope test43: interface ens19.43 missing",
			}}},
	}
	text, class, _ := configSaneStatus(rows)
	if class != "crit" {
		t.Errorf("configSaneStatus() class = %q, want crit — a real actionable finding is present alongside the soft one", class)
	}
	if !strings.Contains(text, "debugwalk-1") || !strings.Contains(text, "test43") {
		t.Errorf("configSaneStatus() text = %q, want both findings named", text)
	}
}

func TestInterfaceHealthStatus_NoTrunkFindingsIsHealthy(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", NodeID: "n1",
			PlaneWarnings: []string{"scope test43: interface ens19.43 missing"}}},
	}
	text, class := interfaceHealthStatus(rows)
	if text != "healthy" || class != "ok" {
		t.Errorf("interfaceHealthStatus() = (%q, %q), want (\"healthy\", \"ok\") — no trunk_link_down finding present", text, class)
	}
}

// TestInterfaceHealthStatus_TrunkLinkDownSurfacesAsCrit is the direct
// regression for the actual finding this row exists to surface.
func TestInterfaceHealthStatus_TrunkLinkDownSurfacesAsCrit(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", NodeID: "n1",
			PlaneWarnings: []string{"scope ens19: trunk_link_down carrier lost on ens19 — every scope on this trunk force-closed"}}},
	}
	text, class := interfaceHealthStatus(rows)
	if class != "crit" {
		t.Errorf("interfaceHealthStatus() class = %q, want crit", class)
	}
	if !strings.Contains(text, "core-1") || !strings.Contains(text, "ens19") {
		t.Errorf("interfaceHealthStatus() text = %q, want it to name core-1 and ens19", text)
	}
}

// TestInterfaceHealthStatus_UnreachableNodeIgnored mirrors
// TestConfigSaneStatus_UnreachableNodeIgnored.
func TestInterfaceHealthStatus_UnreachableNodeIgnored(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, FetchError: "timeout", Status: nodeStatus{Role: "core-1", NodeID: "n1",
			PlaneWarnings: []string{"scope ens19: trunk_link_down stale finding"}}},
	}
	text, class := interfaceHealthStatus(rows)
	if text != "healthy" || class != "ok" {
		t.Errorf("interfaceHealthStatus() = (%q, %q), want (\"healthy\", \"ok\") — a stale finding from an unreachable node must be ignored", text, class)
	}
}

func TestInterfaceHealthStatus_PeerMgmtDownSurfacesAsCrit(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", NodeID: "n1",
			PlaneWarnings: []string{"scope core-2: peer_mgmt_down core-2 (core-2-addr) is unreachable via its mgmt/control address, but confirmed alive via its own scope-VLAN address (10.200.18.23:9443)"}}},
	}
	text, class := interfaceHealthStatus(rows)
	if class != "crit" {
		t.Errorf("interfaceHealthStatus() class = %q, want crit", class)
	}
	if !strings.Contains(text, "core-1") || !strings.Contains(text, "core-2") {
		t.Errorf("interfaceHealthStatus() text = %q, want it to name the reporting node core-1 and the affected peer core-2", text)
	}
}

func TestInterfaceHealthStatus_PeerMgmtDownGroupedAcrossObservers(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", NodeID: "n1",
			PlaneWarnings: []string{peerMgmtDownWarning}}},
		{Node: NodeConfig{Name: "core-3"}, Status: nodeStatus{Role: "core-3", NodeID: "n3",
			PlaneWarnings: []string{peerMgmtDownWarning}}},
	}
	text, class := interfaceHealthStatus(rows)
	if class != "crit" {
		t.Errorf("class = %q, want crit", class)
	}
	if !strings.HasPrefix(text, "1 issue(s)") {
		t.Errorf("text = %q, want exactly 1 collapsed issue for the one genuinely down peer, not 2", text)
	}
	if !strings.Contains(text, "confirmed by core-1, core-3") {
		t.Errorf("text = %q, want it to name both confirming observers", text)
	}
}

// TestInterfaceHealthStatus_DifferentPeersMgmtDownNotMerged confirms the
// grouping above doesn't over-collapse.
func TestInterfaceHealthStatus_DifferentPeersMgmtDownNotMerged(t *testing.T) {
	other := "scope core-3: peer_mgmt_down core-3 (core-3-addr) is unreachable via its mgmt/control address, but confirmed alive via its own scope-VLAN address (10.200.18.43:9443)"
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", NodeID: "n1",
			PlaneWarnings: []string{peerMgmtDownWarning, other}}},
	}
	text, _ := interfaceHealthStatus(rows)
	if !strings.HasPrefix(text, "2 issue(s)") {
		t.Errorf("text = %q, want 2 distinct issues for 2 genuinely different down peers", text)
	}
}

func TestUnreachableNodeNames_NamesGenuinelyUnreachableRows(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1"}},
		{Node: NodeConfig{Name: "core-2", Addr: "192.168.0.22:9443"}, FetchError: "connection refused"},
		{Node: NodeConfig{Name: "core-3", Addr: "192.168.0.24:9443"}, FetchError: "timeout"},
	}
	mgmtOnly := map[string]bool{"192.168.0.22:9443": true}
	got := unreachableNodeNames(rows, mgmtOnly)
	if len(got) != 1 || got[0] != "core-3" {
		t.Errorf("unreachableNodeNames() = %v, want [\"core-3\"] — core-1 is fine, core-2 is mgmt-only-down (not genuinely unreachable)", got)
	}
}

func TestUnreachableNodeNames_FallsBackToAddrWhenNameEmpty(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Addr: "192.168.0.99:9443"}, FetchError: "timeout"},
	}
	got := unreachableNodeNames(rows, map[string]bool{})
	if len(got) != 1 || got[0] != "192.168.0.99:9443" {
		t.Errorf("unreachableNodeNames() = %v, want the addr as a fallback name", got)
	}
}

const peerMgmtDownWarning = "scope core-2: peer_mgmt_down core-2 (192.168.0.22:9443) is unreachable via its mgmt/control address, but confirmed alive via its own scope-VLAN address (10.200.18.23:9443)"

func TestConfigSaneStatus_InterfaceWarningsBelongToInterfacesRowOnly(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", NodeID: "n1",
			PlaneWarnings: []string{peerMgmtDownWarning}}},
		{Node: NodeConfig{Name: "core-2"}, Status: nodeStatus{Role: "core-2", NodeID: "n2",
			PlaneWarnings: []string{"scope eth0: trunk_link_down carrier lost on eth0 (management interface)"}}},
	}
	text, class, _ := configSaneStatus(rows)
	if text != "yes" || class != "ok" {
		t.Errorf("configSaneStatus() = (%q, %q), want (\"yes\", \"ok\") — interface findings are the Interfaces row's, not config sanity's", text, class)
	}
	itext, iclass := interfaceHealthStatus(rows)
	if iclass != "crit" || !strings.Contains(itext, "2 issue(s)") {
		t.Errorf("interfaceHealthStatus() = (%q, %q), want both findings still reported there", itext, iclass)
	}
}

func TestConfigSaneStatus_RealFindingStillShownAlongsideInterfaceOne(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: "core-1", NodeID: "n1",
			PlaneWarnings: []string{peerMgmtDownWarning, "scope rw-101: gate nftables gate is open, this node last set it closed"}}},
	}
	text, _, _ := configSaneStatus(rows)
	if !strings.Contains(text, "1 issue(s)") || !strings.Contains(text, "rw-101") || strings.Contains(text, "peer_mgmt_down") {
		t.Errorf("configSaneStatus() text = %q, want exactly the gate finding, no peer_mgmt_down", text)
	}
}

func TestMgmtOnlyDownAddrs_ReportedByReachablePeerOnly(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Addr: "192.168.0.23:9443"}, Status: nodeStatus{Role: "core-1", PlaneWarnings: []string{peerMgmtDownWarning}}},
		{Node: NodeConfig{Addr: "192.168.0.22:9443"}, FetchError: "node offline"},
		// A stale warning on an unreachable row must never count.
		{Node: NodeConfig{Addr: "192.168.0.24:9443"}, FetchError: "timeout", Status: nodeStatus{PlaneWarnings: []string{
			"scope core-1: peer_mgmt_down core-1 (192.168.0.23:9443) is unreachable via its mgmt/control address"}}},
	}
	got := mgmtOnlyDownAddrs(rows)
	if !got["192.168.0.22:9443"] {
		t.Errorf("mgmtOnlyDownAddrs() = %v, want 192.168.0.22:9443 (core-2, confirmed alive via fallback)", got)
	}
	if len(got) != 1 {
		t.Errorf("mgmtOnlyDownAddrs() = %v, want exactly one entry — a stale warning from an unreachable row must be ignored", got)
	}
}

func TestMgmtOnlyDownAddrs_NoWarningsIsEmpty(t *testing.T) {
	rows := []statusRow{{Node: NodeConfig{Addr: "a:1"}, Status: nodeStatus{Role: "core-1"}}, {Node: NodeConfig{Addr: "b:1"}, FetchError: "x"}}
	if got := mgmtOnlyDownAddrs(rows); len(got) != 0 {
		t.Errorf("mgmtOnlyDownAddrs() = %v, want empty — a genuinely dead node has no peer_mgmt_down report", got)
	}
}

func TestServingText(t *testing.T) {
	if got := servingText(32, 32, 0, 0); got != "32 of 32 scope(s)" {
		t.Errorf("servingText() = %q", got)
	}
	if got := servingText(17, 32, 0, 1); !strings.Contains(got, "17 of 32") || !strings.Contains(got, "fallback") {
		t.Errorf("servingText() = %q, want the visible count plus the fallback-only note", got)
	}
	if got := servingText(1, 1, 1, 0); got != "1 of 1 scope(s), 1 disabled" {
		t.Errorf("servingText() = %q, want the disabled scope listed separately", got)
	}
}

func partitionLines(ws []string) []string {
	var out []string
	for _, w := range ws {
		if strings.HasPrefix(w, "PARTITION:") {
			out = append(out, w)
		}
	}
	return out
}

// Both directions of one pair fold into one line, and the message names
// the observing node.
func TestCheckCoherence_Partition_PairFoldedAndObserverNamed(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Addr: "10.0.0.1:9443"}, Status: nodeStatus{Role: "core-1", NodeID: "n1", PeersUnreachable: []string{"10.0.0.2:9443"}}},
		{Node: NodeConfig{Addr: "10.0.0.2:9443"}, Status: nodeStatus{Role: "core-2", NodeID: "n2", PeersUnreachable: []string{"10.0.0.1:9443"}}},
	}
	got := partitionLines(checkCoherence(rows, map[string]tokenInfo{}, "core-3"))
	if len(got) != 1 {
		t.Fatalf("PARTITION lines = %v, want exactly 1 for the undirected pair", got)
	}
	for _, want := range []string{"n1 and n2 cannot see each other", "served by core-3"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("line %q missing %q", got[0], want)
		}
	}
}

// A node that reaches its peer over the fallback path is a mgmt-only loss,
// not a partition — it must not produce a PARTITION line at all.
func TestCheckCoherence_Partition_FallbackReachableIsNotAPartition(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Addr: "10.0.0.1:9443"}, Status: nodeStatus{Role: "core-1", NodeID: "n1",
			PeersUnreachable: []string{"10.0.0.2:9443"}, FallbackPeers: map[string]string{"10.0.0.2:9443": "172.16.5.23:9443"}}},
		{Node: NodeConfig{Addr: "10.0.0.2:9443"}, Status: nodeStatus{Role: "core-2", NodeID: "n2",
			PeersUnreachable: []string{"10.0.0.1:9443"}, FallbackPeers: map[string]string{"10.0.0.1:9443": "172.16.5.22:9443"}}},
	}
	if got := partitionLines(checkCoherence(rows, map[string]tokenInfo{}, "core-3")); len(got) != 0 {
		t.Errorf("PARTITION lines = %v, want none — both nodes reach each other via the fallback path", got)
	}
}

// One-directional loss reads as such (and only fires for the direction
// that is really unreachable).
func TestCheckCoherence_Partition_OneDirection(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Addr: "10.0.0.1:9443"}, Status: nodeStatus{Role: "core-1", NodeID: "n1", PeersUnreachable: []string{"10.0.0.2:9443"}}},
		{Node: NodeConfig{Addr: "10.0.0.2:9443"}, Status: nodeStatus{Role: "core-2", NodeID: "n2"}},
	}
	got := partitionLines(checkCoherence(rows, map[string]tokenInfo{}))
	if len(got) != 1 || !strings.Contains(got[0], "n1 cannot see n2, but n2 can see it") {
		t.Fatalf("PARTITION lines = %v, want one one-directional line", got)
	}
}

func TestClusterPathRows_BuildsOneRowPerReportedPath(t *testing.T) {
	rows := []statusRow{
		{
			Node: NodeConfig{Name: "core-1"},
			Status: nodeStatus{Role: config.RoleCore1, Paths: []nodePathStatus{
				{Role: config.RoleCore2, Parent: "ens20", Addr: "10.0.20.23:9443", Reachable: true},
				{Role: config.RoleCore2, Parent: "ens19", Addr: "10.0.19.23:9443", Reachable: false, LastError: "dial timeout"},
			}},
		},
		{Node: NodeConfig{Name: "core-2"}, FetchError: "connection refused"},
	}
	got := clusterPathRows(rows)
	if len(got) != 2 {
		t.Fatalf("clusterPathRows() = %v, want 2 rows (unreachable row skipped)", got)
	}
	// Sorted by Trunk within the same From/To pair: ens19 before ens20.
	if got[0].Trunk != "ens19" || got[0].Reachable || got[0].Class != "crit" || got[0].Text != "unreachable" {
		t.Errorf("got[0] = %+v, want unreachable ens19 row first", got[0])
	}
	if got[0].LastError != "dial timeout" {
		t.Errorf("got[0].LastError = %q, want %q", got[0].LastError, "dial timeout")
	}
	if got[1].Trunk != "ens20" || !got[1].Reachable || got[1].Class != "ok" || got[1].Text != "reachable" {
		t.Errorf("got[1] = %+v, want reachable ens20 row second", got[1])
	}
	if got[0].From != config.RoleCore1 || got[0].To != config.RoleCore2 {
		t.Errorf("got[0].From/To = %q/%q, want %q/%q", got[0].From, got[0].To, config.RoleCore1, config.RoleCore2)
	}
}

func TestClusterPathRows_NoPathsIsEmptyNotNilPanic(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: config.RoleCore1}},
	}
	if got := clusterPathRows(rows); len(got) != 0 {
		t.Errorf("clusterPathRows() = %v, want empty", got)
	}
}

func TestClusterPathRows_UsesNicknameWhenSet(t *testing.T) {
	rows := []statusRow{
		{
			Node:     NodeConfig{Name: "core-1"},
			Nickname: "worker-a",
			Status: nodeStatus{Role: config.RoleCore1, Paths: []nodePathStatus{
				{Role: config.RoleCore2, Parent: "ens19", Reachable: true},
			}},
		},
	}
	got := clusterPathRows(rows)
	if len(got) != 1 || got[0].From != "worker-a" {
		t.Fatalf("clusterPathRows() = %v, want From = worker-a", got)
	}
}

func TestTrustBarColor_EndpointsAndClamping(t *testing.T) {
	if got := trustBarColor(100); got != "hsl(120,70%,42%)" {
		t.Errorf("trustBarColor(100) = %q, want green (hue 120)", got)
	}
	if got := trustBarColor(0); got != "hsl(0,70%,42%)" {
		t.Errorf("trustBarColor(0) = %q, want red (hue 0)", got)
	}
	if got := trustBarColor(150); got != trustBarColor(100) {
		t.Errorf("trustBarColor(150) = %q, want clamped to trustBarColor(100)", got)
	}
	if got := trustBarColor(-5); got != trustBarColor(0) {
		t.Errorf("trustBarColor(-5) = %q, want clamped to trustBarColor(0)", got)
	}
}

// TestPathsSummary_SeverityMatchesWorstFinding confirms the three real
// cases: no data, everything reachable with high trust, and a down path.
func TestPathsSummary_SeverityMatchesWorstFinding(t *testing.T) {
	if text, class := pathsSummary(nil); class != "dim" || text != "no data yet" {
		t.Errorf("pathsSummary(nil) = (%q, %q), want (no data yet, dim)", text, class)
	}
	healthy := []clusterPathRow{{Reachable: true, Score: 100}, {Reachable: true, Score: 97}}
	if _, class := pathsSummary(healthy); class != "ok" {
		t.Errorf("pathsSummary(healthy) class = %q, want ok", class)
	}
	flapping := []clusterPathRow{{Reachable: true, Score: 70}}
	if _, class := pathsSummary(flapping); class != "warn" {
		t.Errorf("pathsSummary(flapping) class = %q, want warn (decayed but still up)", class)
	}
	down := []clusterPathRow{{Reachable: true, Score: 100}, {Reachable: false, Score: 70}}
	if text, class := pathsSummary(down); class != "crit" || !strings.Contains(text, "1 down") {
		t.Errorf("pathsSummary(down) = (%q, %q), want crit and to mention 1 down", text, class)
	}
}

func TestStatusTmpl_RendersClusterPathsSummaryAndDetailPopup(t *testing.T) {
	rows := []clusterPathRow{
		{From: "core-1", To: "core-2", Trunk: "ens19", Reachable: true, Class: "ok", Text: "reachable", Score: 97, BarWidth: 97, BarColor: trustBarColor(97)},
	}
	text, class := pathsSummary(rows)
	data := overviewData{
		ClusterState:      "STABLE",
		ClusterClass:      "ok",
		PathRows:          rows,
		PathsSummaryText:  text,
		PathsSummaryClass: class,
	}
	var buf bytes.Buffer
	if err := statusTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("statusTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `<dialog id="paths-modal">`) {
		t.Error("expected the paths detail popup to render")
	}
	if !strings.Contains(out, "1 path(s), min trust 97%") {
		t.Errorf("expected the summary line to render, got: %s", out)
	}
	if !strings.Contains(out, "trust-bar-fill") || !strings.Contains(out, "width:97%") {
		t.Error("expected a real trust-index bar for the row")
	}
	if strings.Contains(out, "ZgotmplZ") {
		t.Error("BarColor was escaped to the html/template CSS-sanitizer placeholder — must be template.CSS, not a plain string")
	}
	if !strings.Contains(out, string(trustBarColor(97))) {
		t.Errorf("expected the real color value %q to appear in the rendered bar, got: %s", trustBarColor(97), out)
	}
	if !strings.Contains(out, `document.getElementById('paths-modal').showModal()`) {
		t.Error("expected the details link to open the popup")
	}
}

func TestStatusTmpl_PathsModalCloseButtonIsAtTheTop(t *testing.T) {
	rows := []clusterPathRow{
		{From: "core-1", To: "core-2", Trunk: "ens19", Reachable: true, Class: "ok", Text: "reachable", Score: 97, BarWidth: 97, BarColor: trustBarColor(97)},
	}
	text, class := pathsSummary(rows)
	data := overviewData{
		ClusterState:      "STABLE",
		ClusterClass:      "ok",
		PathRows:          rows,
		PathsSummaryText:  text,
		PathsSummaryClass: class,
	}
	var buf bytes.Buffer
	if err := statusTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("statusTmpl.Execute failed: %v", err)
	}
	out := buf.String()

	dialogIdx := strings.Index(out, `<dialog id="paths-modal">`)
	if dialogIdx == -1 {
		t.Fatalf("expected the paths-modal dialog to render, got:\n%s", out)
	}
	modal := out[dialogIdx:]
	headIdx := strings.Index(modal, `<div class="modal-head">`)
	closeIdx := strings.Index(modal, `<form method="dialog"><button>Close</button></form>`)
	tableWrapIdx := strings.Index(modal, `<div class="table-wrap">`)
	if headIdx == -1 || closeIdx == -1 || tableWrapIdx == -1 {
		t.Fatalf("expected modal-head, a Close form, and a table-wrap inside the paths-modal dialog, got:\n%s", modal)
	}
	if !(headIdx < closeIdx && closeIdx < tableWrapIdx) {
		t.Errorf("expected the Close button inside .modal-head, before any scrollable table content — got head@%d close@%d table@%d",
			headIdx, closeIdx, tableWrapIdx)
	}
	// Exactly one Close form — no second copy left behind at the
	// bottom of the modal.
	if n := strings.Count(out, "<button>Close</button>"); n != 1 {
		t.Errorf("expected exactly one Close button in the paths popup, got %d", n)
	}
}

func TestStatusTmpl_NoPathRowsOmitsPopupAndDetailsLink(t *testing.T) {
	text, class := pathsSummary(nil)
	data := overviewData{
		ClusterState:      "STABLE",
		ClusterClass:      "ok",
		PathsSummaryText:  text,
		PathsSummaryClass: class,
	}
	var buf bytes.Buffer
	if err := statusTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("statusTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, `<dialog id="paths-modal">`) {
		t.Error("expected no popup when there are no path rows")
	}
	if strings.Contains(out, "showModal()") {
		t.Error("expected no details link when there are no path rows")
	}
	if !strings.Contains(out, "no data yet") {
		t.Error("expected the summary line to say 'no data yet'")
	}
}

func TestStatusTmpl_ClusterTableRowsCarryInfoIcons(t *testing.T) {
	data := overviewData{ClusterState: "STABLE", ClusterClass: "ok"}
	var buf bytes.Buffer
	if err := statusTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("statusTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	if n := strings.Count(out, "info-ico"); n < 9 {
		t.Errorf("found %d info-ico occurrences in the Cluster table, want at least 9 (State, Configuration sane, Interfaces, Witness, Arbiter quorum, Serving, Daemons, Probes, Cluster paths)", n)
	}
	for _, label := range []string{">State ", ">Witness ", ">Serving ", ">Daemons ", ">Probes "} {
		if !strings.Contains(out, label) {
			t.Errorf("expected label %q to be followed by an info-ico span, not just plain text", label)
		}
	}
}

func TestCheckCoherence_MembershipStaleAndMissingPeers(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1", Addr: "10.0.0.1:9443"}, Status: nodeStatus{Role: "core-1", NodeID: "n1", PeersVisible: []string{"10.0.0.3:9443"}, Version: "v1"}},
		{Node: NodeConfig{Name: "core-3", Addr: "10.0.0.3:9443"}, Status: nodeStatus{Role: "core-3", NodeID: "n3", PeersVisible: []string{"10.0.0.1:9443"}, PeersUnreachable: []string{"10.0.0.2:9443"}, Version: "v1"}},
	}
	warnings := membershipWarnings(rows)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "core-3 still lists 10.0.0.2:9443") {
		t.Errorf("membershipWarnings() = %v, want exactly core-3's stale 10.0.0.2 entry", warnings)
	}

	rows[0].Status.PeersVisible = nil
	warnings = membershipWarnings(rows)
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "core-1 does not list core-3") {
			found = true
		}
	}
	if !found {
		t.Errorf("membershipWarnings() = %v, want core-1 missing core-3", warnings)
	}
}

func TestCheckCoherence_MembershipAgreeingClusterIsQuiet(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1", Addr: "10.0.0.1:9443"}, Status: nodeStatus{Role: "core-1", PeersVisible: []string{"10.0.0.3:9443"}}},
		{Node: NodeConfig{Name: "core-3", Addr: "10.0.0.3:9443"}, Status: nodeStatus{Role: "core-3", PeersUnreachable: []string{"10.0.0.1:9443"}}},
		{Node: NodeConfig{Name: "probe-1", Addr: "10.0.0.9:9444"}, Status: nodeStatus{Role: "probe"}},
	}
	if w := membershipWarnings(rows); len(w) != 0 {
		t.Errorf("membershipWarnings() = %v, want none", w)
	}
}

func TestTrunkPathWarnings(t *testing.T) {
	core := func(role, state string, trunks []string, heardOn ...string) statusRow {
		var topo []nodeTopoSighting
		for _, i := range heardOn {
			topo = append(topo, nodeTopoSighting{MyIface: i, MyKind: "trunk", PeerRole: "core-x", PeerKind: "trunk"})
		}
		topo = append(topo, nodeTopoSighting{MyIface: "ens18", MyKind: "mgmt", PeerRole: "core-x", PeerKind: "mgmt"})
		return statusRow{Status: nodeStatus{Role: role, State: state, TopologyTrunks: trunks, Topology: topo}}
	}

	rows := []statusRow{
		core("core-1", "STABLE", []string{"ens19", "ens20"}, "ens19"),
		core("core-2", "STABLE", []string{"ens19"}, "ens19"),
		core("core-3", "SETTLING", []string{"ens19"}),
	}
	got := trunkPathWarnings(rows)
	want := []string{"TRUNK PATH: core-1 hears no beacon from any peer on ens20"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("trunkPathWarnings = %v, want %v (core-3 is not STABLE yet, so not judged)", got, want)
	}
	if coherenceWarningTitle(got[0]) == "" {
		t.Error("TRUNK PATH warning has no tooltip")
	}

	alone := []statusRow{core("core-1", "STABLE", []string{"ens19"}), {FetchError: "unreachable"}}
	if got := trunkPathWarnings(alone); got != nil {
		t.Errorf("with no other reachable core, trunkPathWarnings = %v, want nil", got)
	}
}

func TestTrunkVerificationStatus(t *testing.T) {
	core := func(role, state string, trunks []string, heardOn ...string) statusRow {
		var topo []nodeTopoSighting
		for _, i := range heardOn {
			topo = append(topo, nodeTopoSighting{MyIface: i, MyKind: "trunk", PeerRole: "core-x", PeerKind: "trunk"})
		}
		return statusRow{Status: nodeStatus{Role: role, State: state, TopologyTrunks: trunks, Topology: topo}}
	}

	text, class, title := trunkVerificationStatus([]statusRow{
		core("core-1", "STABLE", []string{"ens19", "ens20"}, "ens19"),
		core("core-2", "STABLE", []string{"ens19", "ens20"}, "ens19", "ens20"),
		core("core-3", "SETTLING", []string{"eth1"}),
	})
	if text != "verified 3/4 — assumed: core-1 ens20" || class != "warn" || title == "" {
		t.Errorf("partly verified = %q %q %q", text, class, title)
	}

	text, class, _ = trunkVerificationStatus([]statusRow{
		core("core-1", "STABLE", []string{"ens19"}, "ens19"),
		core("core-2", "STABLE", []string{"ens19"}, "ens19"),
	})
	if text != "verified 2/2" || class != "ok" {
		t.Errorf("all verified = %q %q", text, class)
	}

	if text, _, _ := trunkVerificationStatus([]statusRow{core("core-1", "STABLE", nil), core("core-2", "STABLE", nil)}); text != "no trunk configured" {
		t.Errorf("no trunks = %q", text)
	}
	if text, class, _ := trunkVerificationStatus([]statusRow{core("core-1", "STABLE", []string{"ens19"}), {FetchError: "unreachable"}}); class != "dim" || !strings.HasPrefix(text, "not checkable") {
		t.Errorf("one reachable core = %q %q", text, class)
	}
}

func TestClusterPathGroups_VLANsUnderTheirTrunk(t *testing.T) {
	rows := []statusRow{{Status: nodeStatus{Role: "core-1",
		Paths: []nodePathStatus{
			{Role: "core-2", Parent: "ens19", Reachable: true, Score: 100},
			{Role: "core-2", Parent: "ens20", Reachable: true, Score: 100},
		},
		ScopePaths: []nodeScopeBeaconStatus{
			{Scope: "s12", PeerRole: "core-2", Reachable: true, Parent: "ens19", VLANID: 12},
			{Scope: "s13", PeerRole: "core-2", Reachable: false, ConsecutiveMisses: 3, Parent: "ens19", VLANID: 13},
			{Scope: "s99", PeerRole: "core-2", Reachable: true, Parent: "ens21", VLANID: 99},
			{Scope: "old", PeerRole: "core-2", Reachable: true},
		},
	}}}
	groups := clusterPathGroups(clusterPathRows(rows))
	byTrunk := map[string]clusterPathGroup{}
	for _, g := range groups {
		byTrunk[g.Row.Trunk] = g
	}
	ens19 := byTrunk["ens19"]
	if len(ens19.VLANs) != 2 || ens19.VLANsDown != 1 || ens19.VLANSummary != "1/2 VLANs unreachable" {
		t.Errorf("ens19 group = %d VLANs, %d down, summary %q; want 2, 1, \"1/2 VLANs unreachable\"", len(ens19.VLANs), ens19.VLANsDown, ens19.VLANSummary)
	}
	if g := byTrunk["ens20"]; len(g.VLANs) != 0 || g.VLANSummary != "" {
		t.Errorf("ens20 has no VLANs, got %+v", g)
	}
	if _, ok := byTrunk["VLAN 99 · s99"]; !ok {
		t.Error("a VLAN path whose trunk isn't reported must still be listed on its own")
	}
	if _, ok := byTrunk["scope:old"]; !ok {
		t.Error("a VLAN path from a daemon that doesn't report its parent must still be listed")
	}
	if len(groups) != 4 {
		t.Errorf("groups = %d, want 4 (ens19, ens20, s99 alone, old alone)", len(groups))
	}
}

func TestStatusTmpl_RendersCollapsedVLANPathsUnderTrunk(t *testing.T) {
	rows := []statusRow{{Status: nodeStatus{Role: "core-1",
		Paths:      []nodePathStatus{{Role: "core-2", Parent: "ens19", Reachable: true, Score: 100}},
		ScopePaths: []nodeScopeBeaconStatus{{Scope: "s12", PeerRole: "core-2", Reachable: true, Parent: "ens19", VLANID: 12}},
	}}}
	flat := clusterPathRows(rows)
	data := overviewData{ClusterState: "STABLE", ClusterClass: "ok", PathRows: flat}
	var buf bytes.Buffer
	if err := statusTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("statusTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	for _, want := range []string{`<tr data-pg="pg0" hidden>`, `↳ VLAN 12 · s12`, `1 VLAN<`} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered Cluster paths lacks %q", want)
		}
	}
}
