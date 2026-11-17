// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"net/url"
	"strconv"
)

const pagerDefaultPer = "10"

var pagerPerChoices = []string{"10", "25", "50", "100", "all"}

type pagerLink struct {
	Label  string
	URL    string
	Active bool
}

// pagerBar is one slim bar of a server-paged list. Top carries the page-size
// choice; both bars carry the range and prev/next. Show is false while the list
// fits on one page of the default size.
type pagerBar struct {
	Show, Top bool
	Range     string
	Sizes     []pagerLink
	PageText  string
	PrevURL   string
	NextURL   string
	HasPrev   bool
	HasNext   bool
}

// pagerPer reads the page-size choice from the query: "10" (default), "25", "50",
// "100" or "all". Anything else falls back to the default.
func pagerPer(q url.Values) string {
	v := q.Get("per")
	for _, c := range pagerPerChoices {
		if v == c {
			return v
		}
	}
	return pagerDefaultPer
}

// pagerSize is the number of rows per page for a choice and a row count.
func pagerSize(per string, total int) int {
	if per == "all" {
		if total < 1 {
			return 1
		}
		return total
	}
	n, err := strconv.Atoi(per)
	if err != nil || n < 1 {
		n, _ = strconv.Atoi(pagerDefaultPer)
	}
	return n
}

// pagerKeep is the query a list link keeps besides the page: the caller's own
// keys plus the page-size choice when it is not the default.
func pagerKeep(keep url.Values, per string) url.Values {
	q := url.Values{}
	for k, v := range keep {
		q[k] = append([]string(nil), v...)
	}
	q.Del("page")
	q.Del("per")
	if per != pagerDefaultPer {
		q.Set("per", per)
	}
	return q
}

func pagerHref(path string, q url.Values) string {
	if enc := q.Encode(); enc != "" {
		return path + "?" + enc
	}
	return path
}

// newPagerBars builds the top and bottom bar for rows [start,end) of total on
// the given page of pages.
func newPagerBars(path string, keep url.Values, per string, total, page, pages, start, end int) (top, bottom pagerBar) {
	def, _ := strconv.Atoi(pagerDefaultPer)
	b := pagerBar{Show: total > def}
	if total > 0 {
		b.Range = fmt.Sprintf("%d–%d of %d", start+1, end, total)
	} else {
		b.Range = "0 of 0"
	}
	if per == "all" {
		b.PageText = "all rows"
	} else {
		b.PageText = fmt.Sprintf("page %d / %d", page, pages)
	}
	if per != "all" {
		if page > 1 {
			q := pagerKeep(keep, per)
			q.Set("page", strconv.Itoa(page-1))
			b.HasPrev, b.PrevURL = true, pagerHref(path, q)
		}
		if page < pages {
			q := pagerKeep(keep, per)
			q.Set("page", strconv.Itoa(page+1))
			b.HasNext, b.NextURL = true, pagerHref(path, q)
		}
	}
	bottom = b
	top = b
	top.Top = true
	for _, c := range pagerPerChoices {
		top.Sizes = append(top.Sizes, pagerLink{Label: c, URL: pagerHref(path, pagerKeep(keep, c)), Active: c == per})
	}
	return top, bottom
}

const pagerBarDefineHTML = `{{define "pagerbar"}}{{if .Show}}<div class="pager {{if .Top}}top{{else}}bottom{{end}}"><span class="pg-range">{{.Range}}</span><span class="pg-size">{{if .Top}}Show <span class="seg">{{range .Sizes}}<a href="{{.URL}}" aria-pressed="{{.Active}}">{{.Label}}</a>{{end}}</span>{{end}}</span><span class="pg-nav">{{if .HasPrev}}<a href="{{.PrevURL}}">‹ prev</a>{{else}}<span class="dis">‹ prev</span>{{end}}<span class="pg-page">{{.PageText}}</span>{{if .HasNext}}<a href="{{.NextURL}}">next ›</a>{{else}}<span class="dis">next ›</span>{{end}}</span></div>{{end}}{{end}}`

// anchor appends a fragment such as "#results" to every link of the bar.
func (b *pagerBar) anchor(a string) {
	if b.PrevURL != "" {
		b.PrevURL += a
	}
	if b.NextURL != "" {
		b.NextURL += a
	}
	for i := range b.Sizes {
		b.Sizes[i].URL += a
	}
}
