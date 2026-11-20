// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"dnshived/internal/config"
)

const bulkShown = 200

type bulkSpec struct {
	Action string
	TTL    int
	Value  string
	Target string
}

type bulkChange struct{ Host, Type, Before, After string }

var bulkActions = map[string]string{
	"ttl":       "Set the TTL",
	"ttlclear":  "Follow the domain's TTL",
	"probe-on":  "Include in probe checks",
	"probe-off": "Exclude from probe checks",
	"value":     "Set the value",
	"move":      "Move to another domain",
	"copy":      "Copy to another domain",
	"delete":    "Delete",
}

func singleValueType(t string) bool {
	switch strings.ToUpper(t) {
	case "A", "AAAA", "CNAME", "PTR", "TXT":
		return true
	}
	return false
}

func parseBulkSpec(f url.Values) (bulkSpec, error) {
	spec := bulkSpec{Action: f.Get("action"), Value: strings.TrimSpace(f.Get("value")), Target: strings.TrimSpace(f.Get("target"))}
	if _, ok := bulkActions[spec.Action]; !ok {
		return spec, errors.New("choose an action")
	}
	switch spec.Action {
	case "ttl":
		n, err := strconv.Atoi(strings.TrimSpace(f.Get("ttl")))
		if err != nil || n < 1 || n > 2147483647 {
			return spec, errors.New("the TTL is a number of seconds, 1 or more")
		}
		spec.TTL = n
	case "value":
		if spec.Value == "" {
			return spec, errors.New("enter the new value")
		}
	case "move", "copy":
		if spec.Target == "" {
			return spec, errors.New("choose the target domain")
		}
	}
	return spec, nil
}

// bulkSelection is the set of record lines the action applies to: the ticked
// rows, or every static row of the current search with all=1.
func bulkSelection(cluster config.Cluster, d config.LocalDomain, f url.Values) (map[string]bool, error) {
	sel := map[string]bool{}
	if f.Get("all") == "1" {
		static, _ := domainRowsFor(cluster, d, false)
		for _, r := range domFilter(static, listQuery(f), listShow(f.Get("show"), "static", "dhcp")) {
			sel[r.Line] = true
		}
	} else {
		for _, l := range f["line"] {
			if l = strings.TrimSpace(l); l != "" {
				sel[l] = true
			}
		}
	}
	if len(sel) == 0 {
		return nil, errors.New("no record is selected")
	}
	return sel, nil
}

func cloneDomains(in []config.LocalDomain) []config.LocalDomain {
	out := make([]config.LocalDomain, len(in))
	for i, d := range in {
		d.Records = append([]config.LocalDomainHost(nil), d.Records...)
		out[i] = d
	}
	return out
}

func recordText(h config.LocalDomainHost) string { return formatDomainHostLine(h) }

type hostEntry struct {
	first, cname config.LocalDomainHost
	hasCNAME     bool
}

// recordIndex answers precheckRecord's question for many records without
// comparing each one against all others.
type recordIndex struct {
	same   map[config.LocalDomainHost]config.LocalDomainHost
	byHost map[string]*hostEntry
}

func newRecordIndex() *recordIndex {
	return &recordIndex{same: map[config.LocalDomainHost]config.LocalDomainHost{}, byHost: map[string]*hostEntry{}}
}

func normalizedRecord(h config.LocalDomainHost) config.LocalDomainHost {
	h.TTL = 0
	h.Host = strings.ToLower(domHostLabel(h.Host))
	h.Type = strings.ToUpper(h.Type)
	return h
}

func (x *recordIndex) add(h config.LocalDomainHost) {
	n := normalizedRecord(h)
	if _, ok := x.same[n]; !ok {
		x.same[n] = h
	}
	e := x.byHost[n.Host]
	if e == nil {
		e = &hostEntry{first: h}
		x.byHost[n.Host] = e
	}
	if n.Type == "CNAME" && !e.hasCNAME {
		e.hasCNAME, e.cname = true, h
	}
}

func (x *recordIndex) conflict(h config.LocalDomainHost) error {
	n := normalizedRecord(h)
	if e, ok := x.same[n]; ok {
		return fmt.Errorf("%s already has this record: %s", domHostLabel(e.Host), formatDomainHostLine(e))
	}
	e := x.byHost[n.Host]
	if e == nil {
		return nil
	}
	other := e.first
	switch {
	case n.Type == "CNAME":
	case e.hasCNAME:
		other = e.cname
	default:
		return nil
	}
	return fmt.Errorf("%s already has %s data, and a name with a CNAME may hold nothing else: %s", domHostLabel(other.Host), strings.ToUpper(other.Type), formatDomainHostLine(other))
}

// applyBulk returns the domains after the action and what changed. The input
// is not modified.
func applyBulk(in []config.LocalDomain, idx int, sel map[string]bool, spec bulkSpec) ([]config.LocalDomain, []bulkChange, error) {
	domains := cloneDomains(in)
	src := &domains[idx]
	var picked []int
	for i, h := range src.Records {
		if sel[formatDomainHostLine(h)] {
			picked = append(picked, i)
		}
	}
	if len(picked) == 0 {
		return nil, nil, errors.New("the selected records changed in the meantime; reload and select again")
	}
	var changes []bulkChange
	note := func(h config.LocalDomainHost, before, after string) {
		changes = append(changes, bulkChange{Host: domHostLabel(h.Host), Type: strings.ToUpper(h.Type), Before: before, After: after})
	}
	ttlLabel := func(t int) string {
		if t <= 0 {
			return "domain TTL"
		}
		return "TTL " + strconv.Itoa(t)
	}
	switch spec.Action {
	case "ttl":
		for _, i := range picked {
			h := &src.Records[i]
			if h.TTL != spec.TTL {
				note(*h, ttlLabel(h.TTL), ttlLabel(spec.TTL))
			}
			h.TTL = spec.TTL
		}
	case "ttlclear":
		for _, i := range picked {
			h := &src.Records[i]
			if h.TTL != 0 {
				note(*h, ttlLabel(h.TTL), ttlLabel(0))
			}
			h.TTL = 0
		}
	case "probe-on", "probe-off":
		off := spec.Action == "probe-off"
		label := func(b bool) string {
			if b {
				return "excluded from probe checks"
			}
			return "in probe checks"
		}
		for _, i := range picked {
			h := &src.Records[i]
			if h.ProbeDisabled != off {
				note(*h, label(h.ProbeDisabled), label(off))
			}
			h.ProbeDisabled = off
		}
	case "value":
		for _, i := range picked {
			if !singleValueType(src.Records[i].Type) {
				return nil, nil, fmt.Errorf("a value can be set only for A, AAAA, CNAME, PTR and TXT records; the selection holds a %s record", strings.ToUpper(src.Records[i].Type))
			}
		}
		for _, i := range picked {
			h := &src.Records[i]
			if h.Value != spec.Value {
				note(*h, h.Value, spec.Value)
			}
			h.Value = spec.Value
		}
		idx := newRecordIndex()
		isPicked := make(map[int]bool, len(picked))
		for _, i := range picked {
			isPicked[i] = true
		}
		for i, h := range src.Records {
			if !isPicked[i] {
				idx.add(h)
			}
		}
		for _, i := range picked {
			if err := idx.conflict(src.Records[i]); err != nil {
				return nil, nil, err
			}
			idx.add(src.Records[i])
		}
	case "delete":
		drop := map[int]bool{}
		for _, i := range picked {
			drop[i] = true
			note(src.Records[i], recordText(src.Records[i]), "removed")
		}
		kept := src.Records[:0]
		for i, h := range src.Records {
			if !drop[i] {
				kept = append(kept, h)
			}
		}
		src.Records = kept
	case "move", "copy":
		ti := -1
		for i := range domains {
			if domains[i].Name == spec.Target {
				ti = i
			}
		}
		switch {
		case ti < 0:
			return nil, nil, fmt.Errorf("domain %q not found", spec.Target)
		case ti == idx:
			return nil, nil, errors.New("choose a different domain")
		case domains[ti].ForkedFrom != "":
			return nil, nil, fmt.Errorf("%s is linked to %s; choose a standalone domain", spec.Target, domains[ti].ForkedFrom)
		}
		dst := &domains[ti]
		verb := "copied to " + dst.Name
		if spec.Action == "move" {
			verb = "moved to " + dst.Name
		}
		dstIdx := newRecordIndex()
		for _, h := range dst.Records {
			dstIdx.add(h)
		}
		for _, i := range picked {
			h := src.Records[i]
			if err := dstIdx.conflict(h); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", dst.Name, err)
			}
			dstIdx.add(h)
			dst.Records = append(dst.Records, h)
			note(h, recordText(h), verb)
		}
		if spec.Action == "move" {
			drop := map[int]bool{}
			for _, i := range picked {
				drop[i] = true
			}
			kept := src.Records[:0]
			for i, h := range src.Records {
				if !drop[i] {
					kept = append(kept, h)
				}
			}
			src.Records = kept
		}
		domains = config.PropagateForkedDomains(domains, dst.Name)
	}
	domains = config.PropagateForkedDomains(domains, in[idx].Name)
	return domains, changes, nil
}

// bulkPlan is one prepared bulk action: the staged result and its overview.
type bulkPlan struct {
	name    string
	current config.Cluster
	domains []config.LocalDomain
	changes []bulkChange
	spec    bulkSpec
	count   int
}

func prepareBulk(ref *configRef, r *http.Request, name string) (*bulkPlan, int, error) {
	if err := r.ParseForm(); err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("bad form: %w", err)
	}
	current, _, _, err := currentEditableConfig(nodesIncludingSelf(ref.Load()))
	if err != nil {
		return nil, http.StatusBadGateway, fmt.Errorf("could not read current config: %w", err)
	}
	idx := -1
	for i := range current.LocalDomains {
		if current.LocalDomains[i].Name == name {
			idx = i
		}
	}
	if idx < 0 {
		return nil, http.StatusNotFound, fmt.Errorf("domain %q not found", name)
	}
	if current.LocalDomains[idx].ForkedFrom != "" {
		return nil, http.StatusBadRequest, fmt.Errorf("this domain is linked to %s; edit the original", current.LocalDomains[idx].ForkedFrom)
	}
	spec, err := parseBulkSpec(r.PostForm)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	sel, err := bulkSelection(current, current.LocalDomains[idx], r.PostForm)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	domains, changes, err := applyBulk(current.LocalDomains, idx, sel, spec)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	probe := current
	probe.LocalDomains = domains
	if res := probe.ValidateExtended(); !res.OK() {
		return nil, http.StatusBadRequest, errors.New(strings.Join(res.Errors, "; "))
	}
	return &bulkPlan{name: name, current: current, domains: domains, changes: changes, spec: spec, count: len(sel)}, 0, nil
}

func bulkHidden(f url.Values) []formField {
	var out []formField
	for _, k := range []string{"action", "ttl", "value", "target", "all", "q", "show"} {
		if v := f.Get(k); v != "" {
			out = append(out, formField{Name: k, Value: v})
		}
	}
	if f.Get("all") != "1" {
		for _, l := range f["line"] {
			out = append(out, formField{Name: "line", Value: l})
		}
	}
	return out
}

type bulkPreviewData struct {
	Name    string
	Action  string
	Count   int
	Changes []bulkChange
	More    int
	Hidden  []formField
}

var bulkPreviewTmpl = template.Must(template.New("bulk").Parse(`<!doctype html>
<title>dnshived-web — bulk edit</title>
` + styleHTML + navHTML + `
<div class="pagehead"><h1>Bulk edit: {{.Name}}</h1></div>
<section class="card pend-card">
<p><b>{{.Action}}</b> for {{.Count}} selected record(s).{{if not .Changes}} Nothing changes: the records already have this setting.{{end}}</p>
{{if .Changes}}<div class="table-wrap"><table class="list-table" border="1" cellpadding="4">
<tr><th>Name</th><th>Type</th><th>Now</th><th>After</th></tr>
{{range .Changes}}<tr><td class="mono">{{.Host}}</td><td>{{.Type}}</td><td class="mono">{{.Before}}</td><td class="mono">{{.After}}</td></tr>
{{end}}</table></div>
{{if .More}}<p class="dim">and {{.More}} more.</p>{{end}}{{end}}
<p class="dim">Staging only prepares the change; it goes live when you commit it on Pending changes.</p>
<form method="post" action="/config/domains/{{.Name}}/bulk/stage">
{{range .Hidden}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">
{{end}}<button type="submit" class="btn-primary"{{if not .Changes}} disabled{{end}}>Stage {{len .Changes}} change(s)</button>
<a href="/config/domains?d={{.Name}}" class="btn">Cancel</a>
</form>
</section>
`))

func handleDomainBulk(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		plan, _, err := prepareBulk(ref, r, name)
		if err != nil {
			http.Redirect(w, r, domBack(name, "err", err.Error()), http.StatusSeeOther)
			return
		}
		data := bulkPreviewData{Name: name, Action: bulkActions[plan.spec.Action], Count: plan.count, Changes: plan.changes, Hidden: bulkHidden(r.PostForm)}
		if len(data.Changes) > bulkShown {
			data.More = len(data.Changes) - bulkShown
			data.Changes = data.Changes[:bulkShown]
		}
		renderTemplate(w, bulkPreviewTmpl, data, "bulk edit")
	}
}

func handleDomainBulkStage(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		plan, status, err := prepareBulk(ref, r, name)
		if err != nil {
			if status >= 500 {
				http.Error(w, err.Error(), status)
				return
			}
			http.Redirect(w, r, domBack(name, "err", err.Error()), http.StatusSeeOther)
			return
		}
		payload := clusterPushPayloadFrom(plan.current)
		payload.Scopes = plan.current.Scopes
		payload.LocalDomains = plan.domains
		user, _ := userFromContext(r)
		pushCandidateAndRenderResult(w, ref.Load(), payload, user, "/config/domains?d="+url.QueryEscape(name), "back to the records")
	}
}
