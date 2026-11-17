// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/url"
	"strconv"
	"strings"
)

const listQueryMax = 100

type listChip struct {
	Label  string
	URL    string
	Active bool
}

type chipDef struct {
	Show, Label string
	Count       int
}

type formField struct{ Name, Value string }

// listQuery is the filter text of a list page: trimmed and cut to a sane length.
func listQuery(q url.Values) string {
	v := strings.TrimSpace(q.Get("q"))
	if len(v) > listQueryMax {
		v = v[:listQueryMax]
	}
	return v
}

// listMatch reports whether every word of q occurs in one of the fields,
// ignoring case. An empty q matches everything.
func listMatch(q string, fields ...string) bool {
	q = strings.ToLower(q)
	if q == "" {
		return true
	}
	hay := strings.ToLower(strings.Join(fields, "\x00"))
	for _, w := range strings.Fields(q) {
		if !strings.Contains(hay, w) {
			return false
		}
	}
	return true
}

// listShow returns show when it is one of the allowed chip values, else "".
func listShow(show string, allowed ...string) string {
	for _, a := range allowed {
		if show == a {
			return show
		}
	}
	return ""
}

// listChips builds the filter chips of a list: each keeps the sort, the
// page-size choice and the filter text, and drops the page.
func listChips(path, anchor string, keep url.Values, show string, defs []chipDef) []listChip {
	out := make([]listChip, 0, len(defs))
	for _, d := range defs {
		q := url.Values{}
		for k, v := range keep {
			if k == "page" || k == "show" {
				continue
			}
			q[k] = append([]string(nil), v...)
		}
		if d.Show != "" {
			q.Set("show", d.Show)
		}
		out = append(out, listChip{Label: d.Label + " " + strconv.Itoa(d.Count), URL: pagerHref(path, q) + anchor, Active: d.Show == show})
	}
	return out
}

// hiddenFields turns the named keys of keep into hidden form inputs, so the
// filter form keeps the sort, the page size and the chip.
func hiddenFields(keep url.Values, names ...string) []formField {
	var out []formField
	for _, n := range names {
		if v := keep.Get(n); v != "" {
			out = append(out, formField{Name: n, Value: v})
		}
	}
	return out
}

const listBarStyle = `
.pagehead{display:flex;align-items:center;gap:.8rem;height:2.4rem;margin:0 0 .9rem}
.pagehead h1{margin:0}
.viewseg{display:inline-flex;border:1px solid var(--border);border-radius:8px;overflow:hidden;background:var(--panel)}
.viewseg a,.viewseg span{padding:.25rem .8rem;border-right:1px solid var(--border);color:var(--text);text-decoration:none}
.viewseg>:last-child{border-right:0}
.viewseg .on{background:var(--accent);color:var(--on-accent);font-weight:600}
.listbar{display:flex;align-items:center;gap:.6rem;height:2.6rem;margin:0 0 .6rem;flex-wrap:nowrap}
.listbar form{margin:0;display:flex;align-items:center}
.listbar input[type=search]{width:18rem;flex:none;min-height:0;height:2rem}
.listbar .grow{flex:1}
.listbar .lchip{flex:none;white-space:nowrap;padding:.1rem .6rem;border:1px solid var(--border);border-radius:999px;background:var(--panel);color:var(--text);text-decoration:none;font-size:var(--fs-sm)}
.listbar .lchip.sel{background:var(--accent);border-color:var(--accent);color:var(--on-accent);font-weight:600}
.listbar .lbtn{flex:none;white-space:nowrap;display:inline-flex;align-items:center;height:2rem;padding:0 .8rem;border:1px solid var(--border);border-radius:7px;background:var(--panel);color:var(--text);text-decoration:none;font-weight:600;cursor:pointer;min-height:0}
.listbar .lbtn.primary{background:var(--accent);border-color:var(--accent);color:var(--on-accent)}
.listbar .lbtn.caution{border-color:var(--warn)}
.list-table{table-layout:fixed;min-width:64rem}
.list-table td{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;height:2.6rem}
`
