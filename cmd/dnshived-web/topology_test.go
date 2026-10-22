// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"dnshived/internal/config"
)

func TestInterfaceLabel_FallsBackToRawNameWhenUnset(t *testing.T) {
	labels := map[string]string{"ens19": "Interface Office"}
	if got := interfaceLabel(labels, "ens19"); got != "Interface Office" {
		t.Errorf("interfaceLabel(ens19) = %q, want Interface Office", got)
	}
	if got := interfaceLabel(labels, "ens20"); got != "ens20" {
		t.Errorf("interfaceLabel(ens20, unset) = %q, want ens20 (raw fallback)", got)
	}
	if got := interfaceLabel(nil, "ens20"); got != "ens20" {
		t.Errorf("interfaceLabel(nil map) = %q, want ens20", got)
	}
}

func TestRoleClass_MapsAllFourKinds(t *testing.T) {
	cases := map[string]string{
		config.RoleCore1: "node-core-1",
		config.RoleCore2: "node-core-2",
		config.RoleCore3: "node-core-3",
		"probe":          "node-probe",
		"":               "node-probe", // unknown/unreachable falls back, never panics
	}
	for role, want := range cases {
		if got := roleClass(role); got != want {
			t.Errorf("roleClass(%q) = %q, want %q", role, got, want)
		}
	}
}

func TestBuildTopologyNode_GroupsScopesUnderTheirParentInterfaceSortedByVLAN(t *testing.T) {
	c := config.Cluster{
		Platform: &config.Platform{Mgmt: "ens18", Workers: []string{"ens19"}},
		Scopes: map[string]config.ScopeConfig{
			"office": {Parent: "ens19", VLANID: 104, VIP: "192.168.104.1/24", NodeIP: "192.168.104.22/24", VRRPID: 4, PreferredWorker: "core-1", Color: "#f58231"},
			"guest":  {Parent: "ens19", VLANID: 100, VIP: "192.168.100.1/24", NodeIP: "192.168.100.22/24", VRRPID: 1, PreferredWorker: "core-2"},
		},
	}
	st := nodeStatus{Role: config.RoleCore1, Serving: []string{"office"}}

	tn := buildTopologyNode(NodeConfig{Name: "core-1"}, st, nil, c, nil)

	if tn.RoleClass != "node-core-1" {
		t.Errorf("RoleClass = %q, want node-core-1", tn.RoleClass)
	}
	if tn.MgmtIface != "ens18" {
		t.Errorf("MgmtIface = %q, want ens18", tn.MgmtIface)
	}
	if len(tn.Interfaces) != 1 || tn.Interfaces[0].Name != "ens19" {
		t.Fatalf("Interfaces = %+v, want exactly one entry for ens19", tn.Interfaces)
	}
	vlans := tn.Interfaces[0].VLANs
	if len(vlans) != 2 {
		t.Fatalf("got %d VLANs, want 2", len(vlans))
	}
	if vlans[0].ScopeName != "guest" || vlans[0].VLANID != 100 {
		t.Errorf("vlans[0] = %+v, want guest/100 sorted first", vlans[0])
	}
	if vlans[1].ScopeName != "office" || vlans[1].VLANID != 104 {
		t.Errorf("vlans[1] = %+v, want office/104 sorted second", vlans[1])
	}
	if vlans[1].Badge != "serving" || vlans[1].BadgeClass != "ok" {
		t.Errorf("office (in st.Serving) Badge/BadgeClass = %q/%q, want serving/ok", vlans[1].Badge, vlans[1].BadgeClass)
	}
	if vlans[0].Badge != "standby" || vlans[0].BadgeClass != "dim" {
		t.Errorf("guest Badge/BadgeClass = %q/%q, want standby/dim", vlans[0].Badge, vlans[0].BadgeClass)
	}
	if vlans[1].DnsmasqUnit != "dnshived-dnsmasq@office.service" {
		t.Errorf("DnsmasqUnit = %q", vlans[1].DnsmasqUnit)
	}
	if vlans[1].Color != "#f58231" {
		t.Errorf("office Color = %q, want #f58231", vlans[1].Color)
	}
	if vlans[0].Color != "" {
		t.Errorf("guest Color = %q, want empty (unset)", vlans[0].Color)
	}
}

func TestBuildTopologyNode_Core3GetsFullTreeLikeAnyOtherRole(t *testing.T) {
	c := config.Cluster{
		Platform: &config.Platform{Mgmt: "ens18", Workers: []string{"ens19"}},
		MgmtVIP:  &config.MgmtVIPConfig{VIP: "192.0.2.230/24", VRRPID: 60},
		Scopes: map[string]config.ScopeConfig{
			"office": {Parent: "ens19", VLANID: 104},
		},
	}
	st := nodeStatus{Role: config.RoleCore3, Serving: nil}

	tn := buildTopologyNode(NodeConfig{Name: "core-3"}, st, nil, c, nil)

	if len(tn.Interfaces) != 1 || tn.Interfaces[0].Name != "ens19" {
		t.Fatalf("Interfaces = %+v, want one real entry for ens19 — core-3 builds the same tree as any other role now", tn.Interfaces)
	}
	if len(tn.Interfaces[0].VLANs) != 1 || tn.Interfaces[0].VLANs[0].ScopeName != "office" {
		t.Fatalf("Interfaces[0].VLANs = %+v, want the office scope", tn.Interfaces[0].VLANs)
	}
	if tn.Interfaces[0].VLANs[0].Badge != "standby" {
		t.Errorf("Badge = %q, want standby — st.Serving is nil in this fixture", tn.Interfaces[0].VLANs[0].Badge)
	}
	if tn.MgmtVIP != "192.0.2.230/24" {
		t.Errorf("MgmtVIP = %q, want the real configured VIP — core-3 is the mgmt VIP's preferred holder now, not excluded from it", tn.MgmtVIP)
	}
	if tn.MgmtIface != "ens18" {
		t.Errorf("MgmtIface = %q, want ens18", tn.MgmtIface)
	}
	if tn.Note != "" {
		t.Errorf("Note = %q, want empty — no producer sets it any more (see its own doc comment)", tn.Note)
	}
}

func TestBuildTopologyNode_StrayParentNotInPlatformWorkersStillSurfaces(t *testing.T) {
	c := config.Cluster{
		Platform: &config.Platform{Mgmt: "ens18", Workers: []string{"ens19"}},
		Scopes: map[string]config.ScopeConfig{
			"orphaned": {Parent: "ens20", VLANID: 50},
		},
	}
	tn := buildTopologyNode(NodeConfig{Name: "core-1"}, nodeStatus{Role: config.RoleCore1}, nil, c, nil)

	if len(tn.Interfaces) != 2 {
		t.Fatalf("Interfaces = %+v, want 2 (ens19 empty + stray ens20)", tn.Interfaces)
	}
	if tn.Interfaces[0].Name != "ens19" || len(tn.Interfaces[0].VLANs) != 0 {
		t.Errorf("Interfaces[0] = %+v, want ens19 with 0 VLANs", tn.Interfaces[0])
	}
	if tn.Interfaces[1].Name != "ens20" || len(tn.Interfaces[1].VLANs) != 1 {
		t.Fatalf("Interfaces[1] = %+v, want the stray ens20 parent surfaced with its 1 scope", tn.Interfaces[1])
	}
}

func TestBuildTopologyNode_StatusFetchErrorSetsFetchErrorAndSkipsConfig(t *testing.T) {
	tn := buildTopologyNode(NodeConfig{Name: "core-1"}, nodeStatus{}, errors.New("connection refused"), config.Cluster{}, nil)
	if tn.FetchError == "" {
		t.Error("expected FetchError to be set when status fetch failed")
	}
	if len(tn.Interfaces) != 0 {
		t.Error("expected no interfaces when status fetch failed")
	}
}

func TestBuildTopologyNode_ConfigFetchErrorSetsFetchError(t *testing.T) {
	tn := buildTopologyNode(NodeConfig{Name: "core-1"}, nodeStatus{Role: config.RoleCore1}, nil, config.Cluster{}, errors.New("401"))
	if tn.FetchError == "" {
		t.Error("expected FetchError to be set when config fetch failed")
	}
	if tn.RoleClass != "node-core-1" {
		t.Errorf("RoleClass should still be set from the successful status fetch, got %q", tn.RoleClass)
	}
}

func TestBuildProbeTopologyNode_MarksReachableAndUnreachableScopesSortedByVLAN(t *testing.T) {
	scopes := map[string]config.ScopeConfig{
		"office": {VLANID: 104, VIP: "192.168.104.1/24", VRRPID: 4},
		"guest":  {VLANID: 100, VIP: "192.168.100.1/24", VRRPID: 1},
	}
	var officeResult probeResult
	officeResult.Reachable = true
	officeResult.Enabled = true
	officeResult.ProbedAt = "2026-08-14T03:07:28Z"
	officeResult.DHCP.Verdict = "ok"
	officeResult.DNS.Answered = true
	results := map[string]probeResult{"office": officeResult}
	fetched := map[string]bool{"office": true} // "guest" was never fetched at all

	tn := buildProbeTopologyNode(NodeConfig{Name: "probe-42"}, "ens19", nil, scopes, results, fetched, nil)

	if tn.RoleClass != "node-probe" || tn.RoleLabel != "probe" || !tn.IsProbeHost {
		t.Errorf("tn = %+v, want probe role/class set and IsProbeHost true", tn)
	}
	if len(tn.Interfaces) != 1 || tn.Interfaces[0].Name != "ens19" {
		t.Fatalf("Interfaces = %+v, want exactly one ens19 entry", tn.Interfaces)
	}
	vlans := tn.Interfaces[0].VLANs
	if len(vlans) != 2 || vlans[0].ScopeName != "guest" || vlans[1].ScopeName != "office" {
		t.Fatalf("vlans = %+v, want guest(100) then office(104)", vlans)
	}
	if vlans[0].Badge != "not trunked" || vlans[0].BadgeClass != "dim" {
		t.Errorf("guest (never fetched) Badge/BadgeClass = %q/%q, want 'not trunked'/dim", vlans[0].Badge, vlans[0].BadgeClass)
	}
	if vlans[0].DHCPText != "" {
		t.Errorf("guest (never fetched) DHCPText = %q, want empty (pending, not a false result)", vlans[0].DHCPText)
	}
	if vlans[1].Badge != "trunked" || vlans[1].BadgeClass != "ok" {
		t.Errorf("office (reachable=true) Badge/BadgeClass = %q/%q, want trunked/ok", vlans[1].Badge, vlans[1].BadgeClass)
	}
	if vlans[1].IfaceName != "ens19.104" {
		t.Errorf("IfaceName = %q, want ens19.104 (falls back to trunk_parent since these fixture scopes set no Parent of their own)", vlans[1].IfaceName)
	}
	if vlans[1].DHCPText == "" || vlans[1].DNSText == "" {
		t.Errorf("office DHCPText/DNSText = %q/%q, want non-empty verdicts from a real probeResult", vlans[1].DHCPText, vlans[1].DNSText)
	}
	if vlans[1].ProbedAt == "" || vlans[1].ProbedAt == officeResult.ProbedAt {
		t.Errorf("ProbedAt = %q, want it reformatted (via formatProbedAt) from the raw RFC3339 wire value", vlans[1].ProbedAt)
	}
}

func TestBuildProbeTopologyNode_GroupsByEachScopesOwnParentNotJustTrunkParent(t *testing.T) {
	scopes := map[string]config.ScopeConfig{
		"office": {Parent: "ens19", VLANID: 100},
		"rw-130": {Parent: "ens20", VLANID: 130}, // second trunk, different parent from trunk_parent
	}
	fetched := map[string]bool{"office": true, "rw-130": true}
	results := map[string]probeResult{
		"office": {Reachable: true},
		"rw-130": {Reachable: true},
	}

	tn := buildProbeTopologyNode(NodeConfig{Name: "probe-42"}, "ens19", nil, scopes, results, fetched, nil)

	if len(tn.Interfaces) != 2 {
		t.Fatalf("Interfaces = %+v, want 2 (ens19 and ens20, one per distinct scope parent)", tn.Interfaces)
	}
	if tn.Interfaces[0].Name != "ens19" || tn.Interfaces[1].Name != "ens20" {
		t.Fatalf("Interfaces = %+v, want [ens19, ens20] sorted", tn.Interfaces)
	}
	if len(tn.Interfaces[1].VLANs) != 1 || tn.Interfaces[1].VLANs[0].IfaceName != "ens20.130" {
		t.Errorf("ens20 branch = %+v, want one VLAN with IfaceName ens20.130 (the scope's own parent, not trunk_parent)", tn.Interfaces[1].VLANs)
	}
}

func TestBuildProbeTopologyNode_StatusFetchErrorSetsFetchError(t *testing.T) {
	tn := buildProbeTopologyNode(NodeConfig{Name: "probe-42"}, "", errors.New("connection refused"), nil, nil, nil, nil)
	if tn.FetchError == "" {
		t.Error("expected FetchError to be set when the probe host's own status fetch failed")
	}
}

func TestBuildProbeTopologyNode_EmptyTrunkParentIsAFetchError(t *testing.T) {
	tn := buildProbeTopologyNode(NodeConfig{Name: "probe-42"}, "", nil, map[string]config.ScopeConfig{"x": {VLANID: 1}}, nil, nil, nil)
	if tn.FetchError == "" {
		t.Error("expected FetchError to be set when trunk_parent is empty despite a successful status fetch")
	}
}

func TestBuildCombinedTopology_CarriesScopeColorThrough(t *testing.T) {
	workerA := topologyNode{
		Name: "core-1", RoleClass: "node-core-1", RoleLabel: config.RoleCore1,
		Interfaces: []topologyInterface{{Name: "ens19", VLANs: []topologyVLAN{
			{ScopeName: "office", VLANID: 104, Badge: "serving", BadgeClass: "ok", Color: "#f58231"},
		}}},
	}
	combined := buildCombinedTopology([]topologyNode{workerA})
	if len(combined) != 1 || len(combined[0].Scopes) != 1 {
		t.Fatalf("combined = %+v, want one interface with one scope", combined)
	}
	if got := combined[0].Scopes[0].Color; got != "#f58231" {
		t.Errorf("Color = %q, want #f58231", got)
	}
}

func TestBuildCombinedTopology_PivotsWorkerAThenWorkerBThenProbeOrder(t *testing.T) {
	workerA := topologyNode{
		Name: "core-1", RoleClass: "node-core-1", RoleLabel: config.RoleCore1,
		Interfaces: []topologyInterface{{Name: "ens19", VLANs: []topologyVLAN{
			{ScopeName: "office", VLANID: 104, VIP: "192.168.104.1/24", Badge: "serving", BadgeClass: "ok"},
		}}},
	}
	workerB := topologyNode{
		Name: "core-2", RoleClass: "node-core-2", RoleLabel: config.RoleCore2,
		Interfaces: []topologyInterface{{Name: "ens19", VLANs: []topologyVLAN{
			{ScopeName: "office", VLANID: 104, VIP: "192.168.104.1/24", Badge: "standby", BadgeClass: "dim"},
		}}},
	}
	probe := topologyNode{
		Name: "probe-42", RoleClass: "node-probe", RoleLabel: "probe", IsProbeHost: true,
		Interfaces: []topologyInterface{{Name: "ens19", VLANs: []topologyVLAN{
			{ScopeName: "office", VLANID: 104, Badge: "trunked", BadgeClass: "ok", DHCPText: "DHCP✔", DNSText: "DNS✔"},
		}}},
	}

	combined := buildCombinedTopology([]topologyNode{workerA, workerB, probe})

	if len(combined) != 1 || combined[0].Name != "ens19" {
		t.Fatalf("combined = %+v, want one ens19 interface", combined)
	}
	scopes := combined[0].Scopes
	if len(scopes) != 1 || scopes[0].ScopeName != "office" {
		t.Fatalf("scopes = %+v, want one office scope", scopes)
	}
	sc := scopes[0]
	if len(sc.Endpoints) != 3 {
		t.Fatalf("Endpoints = %+v, want 3 (worker-a, worker-b, probe-42)", sc.Endpoints)
	}
	if sc.Endpoints[0].NodeName != "core-1" || sc.Endpoints[1].NodeName != "core-2" || sc.Endpoints[2].NodeName != "probe-42" {
		t.Errorf("Endpoints order = [%s, %s, %s], want worker-a, worker-b, probe-42",
			sc.Endpoints[0].NodeName, sc.Endpoints[1].NodeName, sc.Endpoints[2].NodeName)
	}
	if sc.ServingLabel != "core-1" || sc.ServingClass != "ok" {
		t.Errorf("ServingLabel/Class = %q/%q, want worker-a/ok", sc.ServingLabel, sc.ServingClass)
	}
}

func TestBuildCombinedTopology_Core3AppearsWhenServing(t *testing.T) {
	core3 := topologyNode{
		Name: "core-3", RoleClass: "node-core-3", RoleLabel: config.RoleCore3,
		Interfaces: []topologyInterface{{Name: "ens19", VLANs: []topologyVLAN{
			{ScopeName: "office", VLANID: 104, Badge: "serving", BadgeClass: "ok"},
		}}},
	}
	combined := buildCombinedTopology([]topologyNode{core3})
	if len(combined) != 1 || len(combined[0].Scopes) != 1 {
		t.Fatalf("combined = %+v, want one ens19 interface with one office scope — core-3 is no longer excluded", combined)
	}
	sc := combined[0].Scopes[0]
	if sc.ServingLabel != "core-3" || sc.ServingClass != "ok" {
		t.Errorf("ServingLabel/Class = %q/%q, want core-3/ok", sc.ServingLabel, sc.ServingClass)
	}
	if sc.ChipClass != "serve-3" {
		t.Errorf("ChipClass = %q, want serve-3", sc.ChipClass)
	}
	if sc.HasError {
		t.Error("a genuinely served scope should not have HasError set")
	}
}

func TestBuildCombinedTopology_SkipsNodesWithFetchError(t *testing.T) {
	unreachable := topologyNode{Name: "core-1", RoleLabel: config.RoleCore1, FetchError: "connection refused"}
	combined := buildCombinedTopology([]topologyNode{unreachable})
	if len(combined) != 0 {
		t.Errorf("combined = %+v, want empty — a node with FetchError has no usable Interfaces data", combined)
	}
}

func TestBuildCombinedTopology_NoWorkerServingFallsBackToCrit(t *testing.T) {
	workerA := topologyNode{
		Name: "core-1", RoleLabel: config.RoleCore1,
		Interfaces: []topologyInterface{{Name: "ens19", VLANs: []topologyVLAN{
			{ScopeName: "office", VLANID: 104, Badge: "standby", BadgeClass: "dim"},
		}}},
	}
	combined := buildCombinedTopology([]topologyNode{workerA})
	sc := combined[0].Scopes[0]
	if sc.ServingLabel != "no node serving" || sc.ServingClass != "crit" {
		t.Errorf("ServingLabel/Class = %q/%q, want 'no node serving'/crit", sc.ServingLabel, sc.ServingClass)
	}
}

func TestBuildCombinedTopology_ChipClassMatchesServingWorker(t *testing.T) {
	workerA := topologyNode{
		Name: "core-1", RoleLabel: config.RoleCore1,
		Interfaces: []topologyInterface{{Name: "ens19", VLANs: []topologyVLAN{
			{ScopeName: "office", VLANID: 104, Badge: "serving", BadgeClass: "ok"},
		}}},
	}
	workerB := topologyNode{
		Name: "core-2", RoleLabel: config.RoleCore2,
		Interfaces: []topologyInterface{{Name: "ens19", VLANs: []topologyVLAN{
			{ScopeName: "guest", VLANID: 100, Badge: "serving", BadgeClass: "ok"},
			{ScopeName: "office", VLANID: 104, Badge: "standby", BadgeClass: "dim"},
		}}},
	}
	combined := buildCombinedTopology([]topologyNode{workerA, workerB})
	byName := map[string]topologyScopeCombined{}
	for _, sc := range combined[0].Scopes {
		byName[sc.ScopeName] = sc
	}
	if byName["office"].ChipClass != "serve-1" {
		t.Errorf("office ChipClass = %q, want serve-1", byName["office"].ChipClass)
	}
	if byName["guest"].ChipClass != "serve-2" {
		t.Errorf("guest ChipClass = %q, want serve-2", byName["guest"].ChipClass)
	}
	if byName["office"].HasError || byName["guest"].HasError {
		t.Errorf("healthy scopes should not have HasError set: office=%v guest=%v", byName["office"].HasError, byName["guest"].HasError)
	}
}

func TestBuildCombinedTopology_HasErrorOnNoServerAndOnCritProbeResult(t *testing.T) {
	workerA := topologyNode{
		Name: "core-1", RoleLabel: config.RoleCore1,
		Interfaces: []topologyInterface{{Name: "ens19", VLANs: []topologyVLAN{
			{ScopeName: "orphan", VLANID: 108, Badge: "standby", BadgeClass: "dim"},
			{ScopeName: "office", VLANID: 104, Badge: "serving", BadgeClass: "ok"},
		}}},
	}
	probe := topologyNode{
		Name: "probe-42", RoleLabel: "probe", IsProbeHost: true,
		Interfaces: []topologyInterface{{Name: "ens19", VLANs: []topologyVLAN{
			{ScopeName: "office", VLANID: 104, Badge: "trunked", BadgeClass: "ok",
				DHCPText: "DHCP-NONE", DHCPClass: "crit", DNSText: "DNS✔", DNSClass: "ok"},
		}}},
	}
	combined := buildCombinedTopology([]topologyNode{workerA, probe})
	byName := map[string]topologyScopeCombined{}
	for _, sc := range combined[0].Scopes {
		byName[sc.ScopeName] = sc
	}
	orphan := byName["orphan"]
	if !orphan.HasError || orphan.ChipClass != "serve-none" {
		t.Errorf("orphan (no server) = %+v, want HasError true and ChipClass serve-none", orphan)
	}
	if orphan.ErrorReason == "" {
		t.Error("orphan.ErrorReason should explain the no-server condition")
	}
	office := byName["office"]
	if !office.HasError {
		t.Errorf("office = %+v, want HasError true — the probe host saw a crit DHCP result", office)
	}
	if office.ErrorReason == "" {
		t.Error("office.ErrorReason should include the probe host's DHCP failure")
	}
}

func TestSummarizeCombined_CountsTotalAndErrorScopes(t *testing.T) {
	combined := []topologyInterfaceCombined{
		{Name: "ens19", Scopes: []topologyScopeCombined{
			{ScopeName: "a", HasError: false},
			{ScopeName: "b", HasError: true, ErrorReason: "no server"},
		}},
		{Name: "ens20", Scopes: []topologyScopeCombined{
			{ScopeName: "c", HasError: true, ErrorReason: "probe error"},
		}},
	}
	total, errs, errList := summarizeCombined(combined)
	if total != 3 || errs != 2 {
		t.Errorf("summarizeCombined = (%d, %d, _), want (3, 2, _)", total, errs)
	}
	if len(errList) != 2 || errList[0].Name != "b" || errList[1].Name != "c" {
		t.Errorf("errList = %+v, want [b, c] (sorted), naming which scopes actually need attention — direct instruction: \"1 need(s) attention - but which one?\"", errList)
	}
	if errList[0].Reason != "no server" {
		t.Errorf("errList[0].Reason = %q, want the scope's own ErrorReason carried through", errList[0].Reason)
	}
}

func TestTopologyTmpl_LinksBackToScopeListView(t *testing.T) {
	var buf bytes.Buffer
	if err := topologyTmpl.Execute(&buf, topologyPageData{}); err != nil {
		t.Fatalf("topologyTmpl.Execute failed: %v", err)
	}
	if !strings.Contains(buf.String(), `href="/scopes"`) {
		t.Error("expected a link back to /scopes (the new List view tab)")
	}
}

func TestTopologyTmpl_SummaryLinksToTheSpecificErroringScope(t *testing.T) {
	data := topologyPageData{
		TotalScopes:    59,
		ErrorScopes:    1,
		ErrorScopeList: []topologyErrorScope{{Name: "rand-ens20-0042", Reason: "no server"}},
		HealthyClass:   "crit",
	}
	var buf bytes.Buffer
	if err := topologyTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("topologyTmpl.Execute failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `<a href="#pop-rand-ens20-0042"`) {
		t.Errorf("expected a link naming the specific erroring scope, got:\n%s", out)
	}
	if !strings.Contains(out, "rand-ens20-0042") {
		t.Error("expected the erroring scope's own name to actually appear in the summary")
	}
}

func TestBuildTopologyRail_OrdersCore1Core2Core3ThenProbeExcludesUnreachable(t *testing.T) {
	nodes := []topologyNode{
		{Name: "probe-42", RoleClass: "node-probe", RoleLabel: "probe"},
		{Name: "core-3", RoleClass: "node-core-3", RoleLabel: config.RoleCore3},
		{Name: "core-2", RoleClass: "node-core-2", RoleLabel: config.RoleCore2},
		{Name: "core-1", RoleClass: "node-core-1", RoleLabel: config.RoleCore1},
		{Name: "worker-x", RoleLabel: config.RoleCore1, FetchError: "timeout"},
	}
	rail := buildTopologyRail(nodes)
	if len(rail) != 4 {
		t.Fatalf("rail = %+v, want 4 (core-3 included, only the unreachable node excluded)", rail)
	}
	if rail[0].Name != "core-1" || rail[1].Name != "core-2" || rail[2].Name != "core-3" || rail[3].Name != "probe-42" {
		t.Errorf("rail order = [%s, %s, %s, %s], want core-1, core-2, core-3, probe-42",
			rail[0].Name, rail[1].Name, rail[2].Name, rail[3].Name)
	}
}

func TestFormatProbeAge_EmptyOnUnparseableTimestamp(t *testing.T) {
	if got := formatProbeAge("not-a-time"); got != "" {
		t.Errorf("formatProbeAge(bad input) = %q, want empty", got)
	}
	if got := formatProbeAge(""); got != "" {
		t.Errorf("formatProbeAge(\"\") = %q, want empty", got)
	}
}

func TestBuildTopologyNode_InterfaceLabelSurfacedWhenConfigured(t *testing.T) {
	c := config.Cluster{
		Platform: &config.Platform{Mgmt: "ens18", Workers: []string{"ens19", "ens20"},
			InterfaceLabels: map[string]string{"ens19": "Interface Office"}},
	}
	tn := buildTopologyNode(NodeConfig{Name: "core-1"}, nodeStatus{Role: config.RoleCore1}, nil, c, nil)
	if len(tn.Interfaces) != 2 {
		t.Fatalf("Interfaces = %+v, want 2", tn.Interfaces)
	}
	if tn.Interfaces[0].Label != "Interface Office" {
		t.Errorf("ens19 Label = %q, want Interface Office", tn.Interfaces[0].Label)
	}
	if tn.Interfaces[1].Label != "ens20" {
		t.Errorf("ens20 (no label configured) Label = %q, want raw fallback ens20", tn.Interfaces[1].Label)
	}
}

func TestBuildCombinedTopology_CarriesInterfaceLabelThrough(t *testing.T) {
	workerA := topologyNode{
		Name: "core-1", RoleLabel: config.RoleCore1,
		Interfaces: []topologyInterface{{Name: "ens19", Label: "Interface Office", VLANs: []topologyVLAN{
			{ScopeName: "office", VLANID: 104, Badge: "serving", BadgeClass: "ok"},
		}}},
	}
	combined := buildCombinedTopology([]topologyNode{workerA})
	if len(combined) != 1 || combined[0].Label != "Interface Office" {
		t.Errorf("combined = %+v, want Label Interface Office", combined)
	}
}

func TestBuildTopologyNode_MgmtVIPSurfacedWhenPresent(t *testing.T) {
	c := config.Cluster{
		Platform: &config.Platform{Mgmt: "ens18"},
		MgmtVIP:  &config.MgmtVIPConfig{VIP: "192.0.2.100/24", VRRPID: 99},
	}
	tn := buildTopologyNode(NodeConfig{Name: "core-1"}, nodeStatus{Role: config.RoleCore1}, nil, c, nil)
	if tn.MgmtVIP != "192.0.2.100/24" {
		t.Errorf("MgmtVIP = %q, want 192.0.2.100/24", tn.MgmtVIP)
	}
}
