// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/url"
	"strings"
	"testing"
)

func names(rows []scopeRow) string {
	var out []string
	for _, r := range rows {
		out = append(out, r.Name)
	}
	return strings.Join(out, ",")
}

func TestNaturalLess(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"scope-2", "scope-10", true},
		{"scope-10", "scope-2", false},
		{"scope-002", "scope-10", true},
		{"ens19", "ens20", true},
		{"ens9", "ens10", true},
		{"a", "b", true},
		{"a", "a", false},
		{"a", "ab", true},
		{"x1y2", "x1y10", true},
	}
	for _, tt := range tests {
		if got := naturalLess(tt.a, tt.b); got != tt.want {
			t.Errorf("naturalLess(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func sortFixture() []scopeRow {
	return []scopeRow{
		{Name: "scope-10", Worker: "core-2", ParentInterface: "ens20", VLANID: 7, Subnet: "10.0.10.0/24", Token: "core-2", Class: "ok", PoolUsagePct: 10},
		{Name: "scope-2", Worker: "core-1", ParentInterface: "ens19", VLANID: 300, Subnet: "10.0.2.0/24", Token: "core-1", Class: "crit", PoolUsagePct: 90},
		{Name: "scope-3", Worker: "core-1", ParentInterface: "ens19", VLANID: 20, Subnet: "10.0.100.0/24", Token: "core-1", Class: "warn", PoolUsagePct: 50},
		{Name: "scope-1", Worker: "core-2", ParentInterface: "ens19", VLANID: 20, Subnet: "9.0.0.0/8", Token: "core-2", Class: "ok", PoolUsagePct: 50},
	}
}

func TestSortScopeRows_EveryColumnAndTheStableTieBreak(t *testing.T) {
	tests := []struct {
		col  string
		desc bool
		want string
	}{
		{"scope", false, "scope-1,scope-2,scope-3,scope-10"},
		{"scope", true, "scope-10,scope-3,scope-2,scope-1"},
		{"worker", false, "scope-2,scope-3,scope-1,scope-10"},
		{"interface", false, "scope-1,scope-3,scope-2,scope-10"},
		{"interface", true, "scope-10,scope-2,scope-1,scope-3"}, // ties keep the scope-name order
		{"vlan", false, "scope-10,scope-1,scope-3,scope-2"},
		{"subnet", false, "scope-1,scope-2,scope-10,scope-3"},
		{"status", false, "scope-2,scope-3,scope-1,scope-10"},
		{"pool", false, "scope-2,scope-1,scope-3,scope-10"},
	}
	for _, tt := range tests {
		t.Run(tt.col, func(t *testing.T) {
			rows := sortFixture()
			sortScopeRows(rows, tt.col, tt.desc)
			if got := names(rows); got != tt.want {
				t.Errorf("sort %s desc=%v = %s, want %s", tt.col, tt.desc, got, tt.want)
			}
		})
	}
}

func TestSortScopeRows_InterfaceSortsByVLANNumericallyNotAsText(t *testing.T) {
	rows := []scopeRow{
		{Name: "a", ParentInterface: "ens19", VLANID: 100},
		{Name: "b", ParentInterface: "ens19", VLANID: 20},
		{Name: "c", ParentInterface: "ens9", VLANID: 5},
	}
	sortScopeRows(rows, "interface", false)
	if got := names(rows); got != "c,b,a" {
		t.Errorf("got %s, want ens9 first (natural), then ens19 VLAN 20 before VLAN 100", got)
	}
}

func TestSortScopeRows_ProbeProblemsFirstUnansweredLast(t *testing.T) {
	rows := []scopeRow{
		{Name: "ok", ProbeCells: []probeCellData{{DNSClass: "ok", DHCPClass: "ok"}}},
		{Name: "none"},
		{Name: "bad", ProbeCells: []probeCellData{{DNSClass: "ok", DHCPClass: "crit"}}},
		{Name: "pending", ProbeCells: []probeCellData{{DNSClass: "ok", DHCPClass: "warn"}}},
	}
	sortScopeRows(rows, "probe", false)
	if got := names(rows); got != "bad,pending,ok,none" {
		t.Errorf("got %s, want crit, warn (pending), ok, then scopes without any probe result", got)
	}
}

func TestScopeSortHeaders_ClickSortsAscendingSecondClickReversesAndPagingIsDropped(t *testing.T) {
	h := scopeSortHeaders("vlan", false, nil, true)
	var vlan, scope sortHeader
	for _, x := range h {
		switch x.Label {
		case "VLAN":
			vlan = x
		case "Scope":
			scope = x
		}
	}
	if !vlan.Active || vlan.AriaSort != "ascending" || vlan.Arrow != "▲" || !strings.Contains(vlan.URL, "sort=vlan") || !strings.Contains(vlan.URL, "dir=desc") {
		t.Errorf("active header %+v, want ascending with a link that reverses it", vlan)
	}
	if scope.Active || scope.AriaSort != "none" || !strings.Contains(scope.URL, "dir=asc") || scope.Arrow != " " {
		t.Errorf("inactive header %+v, want a fixed-width blank arrow slot and an ascending link", scope)
	}
	if hd := scopeSortHeaders("vlan", true, url.Values{"page": {"3"}}, true); strings.Contains(hd[0].URL, "page=") {
		t.Error("changing the sort must return to page 1")
	}
	for _, x := range scopeSortHeaders("scope", false, nil, false) {
		if x.Label == "Probe" {
			t.Error("without probe hosts there is no Probe column to sort")
		}
	}
}

func TestPageURL_KeepsTheSort(t *testing.T) {
	got := pageURL(url.Values{"sort": {"interface"}, "dir": {"desc"}}, 4)
	if !strings.Contains(got, "sort=interface") || !strings.Contains(got, "dir=desc") || !strings.Contains(got, "page=4") {
		t.Errorf("pageURL = %s, want the sort kept so paging does not reset it", got)
	}
}

func TestScopesTmpl_HeadingsAreSortLinks(t *testing.T) {
	data := scopesPageData{Total: 1, Page: 1, TotalPages: 2, HasProbeHosts: true, NextURL: "/scopes?page=2&sort=vlan",
		Headers: scopeSortHeaders("vlan", false, nil, true)}
	var buf strings.Builder
	if err := scopesTmpl.Execute(&buf, data); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{`aria-sort="ascending"`, `href="/scopes?dir=desc&amp;sort=vlan"`, `href="/scopes?dir=asc&amp;sort=interface"`, `href="/scopes?page=2&amp;sort=vlan"`} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in the rendered list", want)
		}
	}
}

func topoFixture() topologyPageData {
	mk := func(name string, vlan int, bad bool) topologyScopeCombined {
		return topologyScopeCombined{ScopeName: name, VLANID: vlan, HasError: bad}
	}
	return topologyPageData{Combined: []topologyInterfaceCombined{
		{Name: "ens19", Label: "ens19", Scopes: []topologyScopeCombined{mk("scope-10", 5, false), mk("scope-2", 9, true), mk("scope-1", 7, false)}},
		{Name: "ens20", Label: "ens20", Scopes: []topologyScopeCombined{mk("x", 1, false)}},
	}}
}

func TestApplyTopologyView_EverythingCollapsedByDefaultWithTheProblemCountVisible(t *testing.T) {
	d := topoFixture()
	applyTopologyView(&d, "", "")
	for _, i := range d.Combined {
		if i.Open {
			t.Errorf("%s is open: the default is collapsed", i.Name)
		}
	}
	if d.Combined[0].ErrorCount != 1 || d.Combined[1].ErrorCount != 0 {
		t.Errorf("error counts %d/%d, want 1/0: a collapsed interface must still show its problems", d.Combined[0].ErrorCount, d.Combined[1].ErrorCount)
	}
	var got []string
	for _, s := range d.Combined[0].Scopes {
		got = append(got, s.ScopeName)
	}
	if strings.Join(got, ",") != "scope-10,scope-1,scope-2" || d.SortKey != "vlan" {
		t.Errorf("order %v key %s, want VLAN order by default", got, d.SortKey)
	}
}

func TestApplyTopologyView_OpenListAllAndNameSort(t *testing.T) {
	d := topoFixture()
	applyTopologyView(&d, "ens20, nope", "name")
	if d.Combined[0].Open || !d.Combined[1].Open {
		t.Errorf("open flags %v/%v, want only ens20 open (an unknown name is ignored)", d.Combined[0].Open, d.Combined[1].Open)
	}
	var got []string
	for _, s := range d.Combined[0].Scopes {
		got = append(got, s.ScopeName)
	}
	if strings.Join(got, ",") != "scope-1,scope-2,scope-10" {
		t.Errorf("name order %v, want natural order", got)
	}
	d = topoFixture()
	applyTopologyView(&d, "all", "bogus")
	if !d.AllOpen || !d.Combined[0].Open || !d.Combined[1].Open || d.SortKey != "vlan" {
		t.Errorf("open=all must open everything and a bad sort key falls back to VLAN: %+v", d.SortKey)
	}
}

func TestTopologyTmpl_CollapsedInterfacesKeepTheirCountsAndErrorLinksOpenTheInterface(t *testing.T) {
	d := topoFixture()
	d.TotalScopes, d.ErrorScopes = 4, 1
	d.ErrorScopeList = []topologyErrorScope{{Name: "scope-2", Iface: "ens19", Reason: "no server"}}
	applyTopologyView(&d, "", "vlan")
	var buf strings.Builder
	if err := topologyTmpl.Execute(&buf, d); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{`<details class="iface-branch" data-iface="ens19">`, "3 scope(s)", "1 need(s) attention", "healthy", `href="/topology?open=ens19#pop-scope-2"`, `href="/topology?open=all&amp;sort=vlan"`} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q", want)
		}
	}
	if strings.Contains(out, `data-iface="ens19" open`) {
		t.Error("a collapsed interface must not carry the open attribute")
	}
	d2 := topoFixture()
	applyTopologyView(&d2, "ens20", "vlan")
	buf.Reset()
	_ = topologyTmpl.Execute(&buf, d2)
	if !strings.Contains(buf.String(), `data-iface="ens20" open`) {
		t.Error("an interface listed in ?open= must be rendered open")
	}
}
