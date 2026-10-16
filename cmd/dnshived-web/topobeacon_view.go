// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"html/template"
	"sort"
	"strconv"
	"time"
)

// topoSightingRow is one rendered debug/evidence row in the Cluster Paths
// popup's new "Topology detail" table.
type topoSightingRow struct {
	From      string // reporting node's own display nickname
	MyIface   string
	MyKind    string
	PeerRole  string
	PeerIface string
	PeerKind  string
	Count     int64
	Age       string // human "Xs ago", pure/deterministic given a reference "now"
}

// topoSightingRows flattens every reachable row's own self-reported
// Status.Topology into one flat, sorted table.
func topoSightingRows(rows []statusRow, now time.Time) []topoSightingRow {
	var out []topoSightingRow
	for _, row := range rows {
		if row.FetchError != "" {
			continue
		}
		from := row.Nickname
		if from == "" {
			from = row.Status.Role
		}
		for _, s := range row.Status.Topology {
			out = append(out, topoSightingRow{
				From:      from,
				MyIface:   s.MyIface,
				MyKind:    s.MyKind,
				PeerRole:  s.PeerRole,
				PeerIface: s.PeerIface,
				PeerKind:  s.PeerKind,
				Count:     s.Count,
				Age:       humanAgeShort(now.Sub(s.LastSeen)),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		if out[i].MyIface != out[j].MyIface {
			return out[i].MyIface < out[j].MyIface
		}
		return out[i].PeerRole < out[j].PeerRole
	})
	return out
}

// humanAgeShort renders a duration as a short "Xs ago"/"Xm ago".
func humanAgeShort(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return strconv.Itoa(int(d.Seconds())) + "s ago"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + "m ago"
	default:
		return strconv.Itoa(int(d.Hours())) + "h ago"
	}
}

// topoEdge is one deduplicated physical-adjacency edge for the connection
// graph.
type topoEdge struct {
	RoleA, IfaceA string
	RoleB, IfaceB string
	Kind          string
}

func topoEdgeKey(roleA, roleB, kind string) string {
	if roleA > roleB {
		roleA, roleB = roleB, roleA
	}
	return roleA + "|" + roleB + "|" + kind
}

// topoEdges aggregates every reachable row's own Topology sightings into a
// deduplicated set of physical edges.
func topoEdges(rows []statusRow) []topoEdge {
	seen := make(map[string]topoEdge)
	for _, row := range rows {
		if row.FetchError != "" {
			continue
		}
		selfRole := row.Status.Role
		for _, s := range row.Status.Topology {
			if selfRole == "" || s.PeerRole == "" {
				continue
			}
			key := topoEdgeKey(selfRole, s.PeerRole, s.MyKind)
			if _, ok := seen[key]; ok {
				continue
			}
			roleA, ifaceA, roleB, ifaceB := selfRole, s.MyIface, s.PeerRole, s.PeerIface
			if roleA > roleB {
				roleA, ifaceA, roleB, ifaceB = roleB, ifaceB, roleA, ifaceA
			}
			seen[key] = topoEdge{RoleA: roleA, IfaceA: ifaceA, RoleB: roleB, IfaceB: ifaceB, Kind: s.MyKind}
		}
	}
	out := make([]topoEdge, 0, len(seen))
	for _, e := range seen {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RoleA != out[j].RoleA {
			return out[i].RoleA < out[j].RoleA
		}
		if out[i].RoleB != out[j].RoleB {
			return out[i].RoleB < out[j].RoleB
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

// topoBeaconGraphNodePos hardcodes each core role's own position in the
// connection graph.
var topoBeaconGraphNodePos = map[string][2]int{
	"core-1": {200, 48},
	"core-2": {128, 168},
	"core-3": {272, 168},
}

// topoBeaconGraphSVG renders the connection graph as inline SVG.
func topoBeaconGraphSVG(rows []statusRow, missingRoles []string) template.HTML {
	missing := make(map[string]bool, len(missingRoles))
	for _, r := range missingRoles {
		missing[r] = true
	}
	edges := topoEdges(rows)

	var b []byte
	b = append(b, []byte(`<svg viewBox="0 0 400 220" width="100%" height="220" style="max-width:420px">`)...)
	for _, e := range edges {
		posA, okA := topoBeaconGraphNodePos[e.RoleA]
		posB, okB := topoBeaconGraphNodePos[e.RoleB]
		if !okA || !okB {
			continue
		}
		dash := ""
		if e.Kind == "mgmt" {
			dash = ` stroke-dasharray="5,4"`
		}
		mx, my := (posA[0]+posB[0])/2, (posA[1]+posB[1])/2
		b = append(b, []byte(fmt.Sprintf(
			`<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#9CA3AF" stroke-width="1.8"%s/>`,
			posA[0], posA[1], posB[0], posB[1], dash))...)
		label := fmt.Sprintf("%s ↔ %s", e.IfaceA, e.IfaceB)
		b = append(b, []byte(fmt.Sprintf(
			`<text x="%d" y="%d" text-anchor="middle" font-size="10" fill="#6B7280">%s</text>`,
			mx, my-4, template.HTMLEscapeString(label)))...)
	}
	for _, role := range []string{"core-1", "core-2", "core-3"} {
		pos, ok := topoBeaconGraphNodePos[role]
		if !ok {
			continue
		}
		fill := `var(--` + role + `)`
		label := role
		if missing[role] {
			fill = "#4B5563"
			label += " (missing)"
		}
		b = append(b, []byte(fmt.Sprintf(
			`<circle cx="%d" cy="%d" r="11" fill="%s"/>`,
			pos[0], pos[1], fill))...)
		ly := pos[1] + 24
		if pos[1] < 100 {
			ly = pos[1] - 16
		}
		b = append(b, []byte(fmt.Sprintf(
			`<text x="%d" y="%d" text-anchor="middle" font-size="11" fill="%s">%s</text>`,
			pos[0], ly, fill, template.HTMLEscapeString(label)))...)
	}
	b = append(b, []byte(`</svg>`)...)
	return template.HTML(b)
}
