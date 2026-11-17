// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/url"
	"strings"
	"testing"
)

func TestListMatch(t *testing.T) {
	tests := []struct {
		name, q string
		fields  []string
		want    bool
	}{
		{"empty matches", "", []string{"x"}, true},
		{"substring", "dante", []string{"dante-001", "core-1"}, true},
		{"case ignored", "CORE", []string{"core-1"}, true},
		{"every word must occur", "dante core-2", []string{"dante-001", "core-1"}, false},
		{"words in different fields", "dante core-1", []string{"dante-001", "core-1"}, true},
		{"no match", "zzz", []string{"dante-001"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := listMatch(tt.q, tt.fields...); got != tt.want {
				t.Errorf("listMatch(%q) = %v, want %v", tt.q, got, tt.want)
			}
		})
	}
}

func TestListQueryAndShow(t *testing.T) {
	if got := listQuery(url.Values{"q": {"  dante  "}}); got != "dante" {
		t.Errorf("listQuery = %q", got)
	}
	if got := listQuery(url.Values{"q": {strings.Repeat("x", 500)}}); len(got) != listQueryMax {
		t.Errorf("a long filter must be cut to %d, got %d", listQueryMax, len(got))
	}
	if got := listShow("problems", "problems", "disabled"); got != "problems" {
		t.Errorf("listShow = %q", got)
	}
	if got := listShow("<script>", "problems"); got != "" {
		t.Errorf("an unknown chip must be dropped, got %q", got)
	}
}

func TestListChips_KeepSortFilterAndDropPage(t *testing.T) {
	keep := url.Values{"sort": {"vlan"}, "per": {"25"}, "q": {"dante"}, "page": {"3"}, "show": {"problems"}}
	chips := listChips("/scopes", "", keep, "problems", []chipDef{{"", "All", 102}, {"problems", "Problems", 3}})
	if len(chips) != 2 || chips[0].Label != "All 102" || chips[1].Label != "Problems 3" {
		t.Fatalf("chips = %+v", chips)
	}
	for _, c := range chips {
		if strings.Contains(c.URL, "page=") {
			t.Errorf("a chip must restart at page 1: %q", c.URL)
		}
		for _, want := range []string{"sort=vlan", "per=25", "q=dante"} {
			if !strings.Contains(c.URL, want) {
				t.Errorf("chip %q lost %s", c.URL, want)
			}
		}
	}
	if strings.Contains(chips[0].URL, "show=") || !strings.Contains(chips[1].URL, "show=problems") {
		t.Errorf("show handling wrong: %q %q", chips[0].URL, chips[1].URL)
	}
	if chips[0].Active || !chips[1].Active {
		t.Error("only the chosen chip is active")
	}
}

func TestHiddenFields(t *testing.T) {
	got := hiddenFields(url.Values{"sort": {"vlan"}, "dir": {""}, "per": {"25"}}, "sort", "dir", "per", "show")
	if len(got) != 2 || got[0] != (formField{"sort", "vlan"}) || got[1] != (formField{"per", "25"}) {
		t.Errorf("hiddenFields = %+v", got)
	}
}

func TestFilterScopeRows(t *testing.T) {
	rows := []scopeRow{
		{Name: "a-one", Worker: "core-1", VLANID: 10, Class: "ok", Status: "active"},
		{Name: "b-two", Worker: "core-2", VLANID: 20, Class: "crit", Status: "EXPIRED"},
		{Name: "c-three", Worker: "—", VLANID: 30, Class: "dim", Status: "not served"},
		{Name: "d-four", Worker: "core-1", VLANID: 40, Disabled: true, Class: "warn", Status: "disabled"},
	}
	names := func(r []scopeRow) string {
		var n []string
		for _, x := range r {
			n = append(n, x.Name)
		}
		return strings.Join(n, ",")
	}
	tests := []struct {
		name, q, show, want string
	}{
		{"no filter", "", "", "a-one,b-two,c-three,d-four"},
		{"text", "core-1", "", "a-one,d-four"},
		{"vlan number", "20", "", "b-two"},
		{"problems exclude disabled", "", "problems", "b-two,c-three"},
		{"disabled", "", "disabled", "d-four"},
		{"text and chip", "core", "disabled", "d-four"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := names(filterScopeRows(rows, tt.q, tt.show)); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSortKeep(t *testing.T) {
	got := sortKeep(url.Values{"sort": {"vlan"}, "per": {"50"}, "q": {"x"}, "show": {"problems"}, "page": {"2"}})
	if got.Get("per") != "50" || got.Get("q") != "x" || got.Get("show") != "problems" || got.Get("sort") != "" || got.Get("page") != "" {
		t.Errorf("sortKeep = %v", got)
	}
}
