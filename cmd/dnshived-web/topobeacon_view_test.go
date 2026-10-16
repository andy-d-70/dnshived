// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"strings"
	"testing"
	"time"
)

func rowWithTopology(role, nickname string, sightings []nodeTopoSighting) statusRow {
	return statusRow{
		Nickname: nickname,
		Status:   nodeStatus{Role: role, Topology: sightings},
	}
}

func TestHumanAgeShort(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{5 * time.Second, "5s ago"},
		{90 * time.Second, "1m ago"},
		{2 * time.Hour, "2h ago"},
		{-3 * time.Second, "0s ago"}, // negative (clock skew) never renders as negative
	}
	for _, c := range cases {
		if got := humanAgeShort(c.d); got != c.want {
			t.Errorf("humanAgeShort(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

func TestTopoSightingRows_FlattensAcrossNodesAndSightings(t *testing.T) {
	now := time.Now()
	rows := []statusRow{
		rowWithTopology("core-1", "", []nodeTopoSighting{
			{MyIface: "ens19", MyKind: "trunk", PeerRole: "core-2", PeerIface: "ens19", PeerKind: "trunk", Count: 5, LastSeen: now.Add(-3 * time.Second)},
			{MyIface: "mgmt0", MyKind: "mgmt", PeerRole: "core-3", PeerIface: "eth0", PeerKind: "mgmt", Count: 2, LastSeen: now.Add(-1 * time.Second)},
		}),
	}

	got := topoSightingRows(rows, now)
	if len(got) != 2 {
		t.Fatalf("topoSightingRows() = %d rows, want 2, got %+v", len(got), got)
	}
	if got[0].From != "core-1" {
		t.Errorf("From = %q, want %q (fallback to Status.Role when Nickname is empty)", got[0].From, "core-1")
	}
}

func TestTopoSightingRows_SkipsFetchErrorRows(t *testing.T) {
	rows := []statusRow{
		{FetchError: "timeout", Status: nodeStatus{Role: "core-2", Topology: []nodeTopoSighting{{MyIface: "ens19", PeerRole: "core-1", PeerIface: "ens19"}}}},
	}
	if got := topoSightingRows(rows, time.Now()); len(got) != 0 {
		t.Fatalf("topoSightingRows() = %+v, want empty (FetchError row must be skipped)", got)
	}
}

func TestTopoSightingRows_NicknameOverridesRole(t *testing.T) {
	now := time.Now()
	rows := []statusRow{
		rowWithTopology("core-1", "the-office-node", []nodeTopoSighting{
			{MyIface: "ens19", PeerRole: "core-2", PeerIface: "ens19", LastSeen: now},
		}),
	}
	got := topoSightingRows(rows, now)
	if len(got) != 1 || got[0].From != "the-office-node" {
		t.Fatalf("topoSightingRows() = %+v, want From=%q", got, "the-office-node")
	}
}

func TestTopoEdges_SingleSightingProducesOneEdgeWithBothRawIfaceNames(t *testing.T) {
	rows := []statusRow{
		rowWithTopology("core-1", "", []nodeTopoSighting{
			{MyIface: "ens19", MyKind: "trunk", PeerRole: "core-3", PeerIface: "eth1", PeerKind: "trunk"},
		}),
	}
	edges := topoEdges(rows)
	if len(edges) != 1 {
		t.Fatalf("topoEdges() = %+v, want 1 edge", edges)
	}
	e := edges[0]
	// core-1 < core-3 lexicographically, so A=core-1/ens19, B=core-3/eth1.
	if e.RoleA != "core-1" || e.IfaceA != "ens19" || e.RoleB != "core-3" || e.IfaceB != "eth1" {
		t.Errorf("edge = %+v, want RoleA=core-1/ens19 RoleB=core-3/eth1", e)
	}
}

func TestTopoEdges_MutualReportDeduplicatesToOneEdge(t *testing.T) {
	rows := []statusRow{
		rowWithTopology("core-1", "", []nodeTopoSighting{
			{MyIface: "ens19", MyKind: "trunk", PeerRole: "core-3", PeerIface: "eth1", PeerKind: "trunk"},
		}),
		rowWithTopology("core-3", "", []nodeTopoSighting{
			{MyIface: "eth1", MyKind: "trunk", PeerRole: "core-1", PeerIface: "ens19", PeerKind: "trunk"},
		}),
	}
	edges := topoEdges(rows)
	if len(edges) != 1 {
		t.Fatalf("topoEdges() = %+v, want exactly 1 deduplicated edge for a mutually-reported pairing", edges)
	}
}

func TestTopoEdges_DifferentKindsAreNeverMerged(t *testing.T) {
	rows := []statusRow{
		rowWithTopology("core-1", "", []nodeTopoSighting{
			{MyIface: "ens19", MyKind: "trunk", PeerRole: "core-2", PeerIface: "ens19", PeerKind: "trunk"},
			{MyIface: "mgmt0", MyKind: "mgmt", PeerRole: "core-2", PeerIface: "mgmt0", PeerKind: "mgmt"},
		}),
	}
	edges := topoEdges(rows)
	if len(edges) != 2 {
		t.Fatalf("topoEdges() = %+v, want 2 distinct edges (trunk and mgmt between the same pair never merge)", edges)
	}
}

func TestTopoEdges_SkipsFetchErrorRows(t *testing.T) {
	rows := []statusRow{
		{FetchError: "timeout", Status: nodeStatus{Role: "core-2", Topology: []nodeTopoSighting{{MyIface: "ens19", PeerRole: "core-1", PeerIface: "ens19"}}}},
	}
	if got := topoEdges(rows); len(got) != 0 {
		t.Fatalf("topoEdges() = %+v, want empty (FetchError row must be skipped)", got)
	}
}

func TestTopoBeaconGraphSVG_RendersRealInterfaceNamesAndAllThreeNodes(t *testing.T) {
	rows := []statusRow{
		rowWithTopology("core-1", "", []nodeTopoSighting{
			{MyIface: "ens19", MyKind: "trunk", PeerRole: "core-3", PeerIface: "eth1", PeerKind: "trunk"},
		}),
	}
	svg := string(topoBeaconGraphSVG(rows, nil))

	for _, want := range []string{"<svg", "ens19", "eth1", "core-1", "core-2", "core-3", "var(--core-1)", "var(--core-2)", "var(--core-3)"} {
		if !strings.Contains(svg, want) {
			t.Errorf("rendered SVG missing %q:\n%s", want, svg)
		}
	}
}

func TestTopoBeaconGraphSVG_MgmtEdgeIsDashed(t *testing.T) {
	rows := []statusRow{
		rowWithTopology("core-1", "", []nodeTopoSighting{
			{MyIface: "mgmt0", MyKind: "mgmt", PeerRole: "core-2", PeerIface: "mgmt0", PeerKind: "mgmt"},
		}),
	}
	if svg := string(topoBeaconGraphSVG(rows, nil)); !strings.Contains(svg, "stroke-dasharray") {
		t.Errorf("mgmt-kind edge did not render dashed:\n%s", svg)
	}
}

func TestTopoBeaconGraphSVG_TrunkEdgeIsSolidNotDashed(t *testing.T) {
	rows := []statusRow{
		rowWithTopology("core-1", "", []nodeTopoSighting{
			{MyIface: "ens19", MyKind: "trunk", PeerRole: "core-2", PeerIface: "ens19", PeerKind: "trunk"},
		}),
	}
	if svg := string(topoBeaconGraphSVG(rows, nil)); strings.Contains(svg, "stroke-dasharray") {
		t.Errorf("trunk-kind edge rendered dashed, want solid:\n%s", svg)
	}
}

func TestTopoBeaconGraphSVG_NoDataStillRendersThreeBareNodes(t *testing.T) {
	svg := string(topoBeaconGraphSVG(nil, nil))
	for _, want := range []string{"core-1", "core-2", "core-3"} {
		if !strings.Contains(svg, want) {
			t.Errorf("rendered SVG (no data) missing %q:\n%s", want, svg)
		}
	}
	if strings.Contains(svg, "<line") {
		t.Errorf("rendered SVG with zero edges still drew a <line>:\n%s", svg)
	}
}

func TestTopoBeaconGraphSVG_EscapesUntrustedLookingIfaceNames(t *testing.T) {
	rows := []statusRow{
		rowWithTopology("core-1", "", []nodeTopoSighting{
			{MyIface: `</text><script>alert(1)</script>`, MyKind: "trunk", PeerRole: "core-2", PeerIface: "ens19", PeerKind: "trunk"},
		}),
	}
	svg := string(topoBeaconGraphSVG(rows, nil))
	if strings.Contains(svg, "<script>") {
		t.Fatalf("unescaped interface name produced a literal <script> tag:\n%s", svg)
	}
}

func TestTopoBeaconGraphSVG_MissingRoleRendersDarkGrey(t *testing.T) {
	svg := string(topoBeaconGraphSVG(nil, []string{"core-1"}))

	if !strings.Contains(svg, `fill="#4B5563"`) {
		t.Errorf("missing role core-1 did not render dark grey:\n%s", svg)
	}
	if strings.Contains(svg, "var(--core-1)") {
		t.Errorf("missing role core-1 still rendered its normal identity color:\n%s", svg)
	}
	if !strings.Contains(svg, "core-1 (missing)") {
		t.Errorf("missing role core-1's label was not marked missing:\n%s", svg)
	}
	// core-2/core-3 are NOT missing here — must keep their real identity colors.
	if !strings.Contains(svg, "var(--core-2)") || !strings.Contains(svg, "var(--core-3)") {
		t.Errorf("non-missing roles lost their normal identity color:\n%s", svg)
	}
}

// TestTopoBeaconGraphSVG_NoMissingRoles_AllNormalColors confirms the
// common case (nil/empty missingRoles) is completely unaffected.
func TestTopoBeaconGraphSVG_NoMissingRoles_AllNormalColors(t *testing.T) {
	svg := string(topoBeaconGraphSVG(nil, nil))

	if strings.Contains(svg, "#4B5563") {
		t.Errorf("no roles are missing, but a dark-grey fill was rendered anyway:\n%s", svg)
	}
	if strings.Contains(svg, "(missing)") {
		t.Errorf("no roles are missing, but a \"(missing)\" label was rendered anyway:\n%s", svg)
	}
}
