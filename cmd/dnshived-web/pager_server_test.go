// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/url"
	"strings"
	"testing"
)

func TestPagerPer(t *testing.T) {
	tests := []struct {
		name, query, want string
	}{
		{"default", "", "10"},
		{"25", "per=25", "25"},
		{"all", "per=all", "all"},
		{"unknown falls back", "per=7", "10"},
		{"hostile falls back", "per=%27%3Cb%3E", "10"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, _ := url.ParseQuery(tt.query)
			if got := pagerPer(q); got != tt.want {
				t.Errorf("pagerPer(%q) = %q, want %q", tt.query, got, tt.want)
			}
		})
	}
}

func TestPagerSize(t *testing.T) {
	tests := []struct {
		per   string
		total int
		want  int
	}{{"10", 102, 10}, {"100", 102, 100}, {"all", 102, 102}, {"all", 0, 1}, {"bogus", 5, 10}}
	for _, tt := range tests {
		if got := pagerSize(tt.per, tt.total); got != tt.want {
			t.Errorf("pagerSize(%q,%d) = %d, want %d", tt.per, tt.total, got, tt.want)
		}
	}
}

func TestNewPagerBars(t *testing.T) {
	keep := url.Values{"sort": {"vlan"}, "dir": {"desc"}}
	top, bottom := newPagerBars("/scopes", keep, "25", 102, 2, 5, 25, 50)
	if !top.Show || !top.Top || bottom.Top {
		t.Fatalf("top/bottom flags wrong: %+v %+v", top, bottom)
	}
	if top.Range != "26–50 of 102" || top.PageText != "page 2 / 5" {
		t.Errorf("range/page = %q / %q", top.Range, top.PageText)
	}
	if !top.HasPrev || !top.HasNext {
		t.Error("page 2 of 5 has both neighbours")
	}
	for _, u := range []string{top.PrevURL, top.NextURL} {
		if !strings.Contains(u, "per=25") || !strings.Contains(u, "sort=vlan") {
			t.Errorf("link %q must keep the page size and the sort", u)
		}
	}
	if len(top.Sizes) != 5 || len(bottom.Sizes) != 0 {
		t.Errorf("only the top bar offers sizes: %d / %d", len(top.Sizes), len(bottom.Sizes))
	}
	for _, s := range top.Sizes {
		if strings.Contains(s.URL, "page=") {
			t.Errorf("a size link must restart at page 1: %q", s.URL)
		}
		if s.Active != (s.Label == "25") {
			t.Errorf("active flag wrong for %q", s.Label)
		}
	}
	if def := top.Sizes[0].URL; strings.Contains(def, "per=") {
		t.Errorf("the default size must not appear in the link: %q", def)
	}
}

func TestNewPagerBars_ShortAndAll(t *testing.T) {
	short, _ := newPagerBars("/scopes", nil, "10", 7, 1, 1, 0, 7)
	if short.Show {
		t.Error("a list of 10 or fewer rows needs no pager")
	}
	all, _ := newPagerBars("/scopes", nil, "all", 102, 1, 1, 0, 102)
	if all.PageText != "all rows" || all.HasPrev || all.HasNext {
		t.Errorf("all rows: %+v", all)
	}
	empty, _ := newPagerBars("/scopes", nil, "10", 0, 1, 1, 0, 0)
	if empty.Range != "0 of 0" {
		t.Errorf("empty range = %q", empty.Range)
	}
}

func TestPagerBar_Anchor(t *testing.T) {
	top, _ := newPagerBars("/probes", nil, "10", 40, 2, 4, 10, 20)
	top.anchor("#results")
	for _, u := range append([]string{top.PrevURL, top.NextURL}, top.Sizes[0].URL, top.Sizes[4].URL) {
		if !strings.HasSuffix(u, "#results") {
			t.Errorf("link %q lacks the anchor", u)
		}
	}
}
