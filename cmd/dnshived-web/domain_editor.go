// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"dnshived/internal/config"
)

const domDHCPNames = "(DHCP names)"

var domRecordTypes = []string{"A", "AAAA", "CNAME", "MX", "TXT", "SRV", "PTR", "CAA"}

type domRow struct {
	Host, Type, Value, TTL string
	Line                   string
	Dynamic                bool
	Title                  string
}

type domRailItem struct {
	Name   string
	Count  int
	Active bool
	Linked bool
	URL    string
}

type domSortHeader struct {
	Label, URL, Arrow, AriaSort string
}

type domHeader struct {
	Name       string
	TTL        int
	ForkedFrom string
	Static     int
	Dynamic    int
}

type domEditorData struct {
	Pending      bool
	Rail         []domRailItem
	RailQ        string
	Domain       *domHeader
	Virtual      bool
	Rows         []domRow
	Total        int
	Q            string
	Show         string
	Chips        []listChip
	Headers      []domSortHeader
	FilterHidden []formField
	PagerTop     pagerBar
	PagerBottom  pagerBar
	Types        []string
	Error        string
	Done         string
	Linked       bool
	Names        []string
	Sets         []Template
	AddName      string
	AddType      string
	BulkTargets  []string
	BulkActions  []bulkOption
}

type bulkOption struct{ Value, Label string }

func domHostLabel(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return "@"
	}
	return host
}

func domValueText(h config.LocalDomainHost) string {
	switch strings.ToUpper(h.Type) {
	case "MX":
		return fmt.Sprintf("%d %s", h.Priority, h.Target)
	case "SRV":
		return fmt.Sprintf("%d %d %d %s", h.Priority, h.Weight, h.Port, h.Target)
	case "CAA":
		return fmt.Sprintf("%d %s %q", h.CAAFlags, h.CAATag, h.Value)
	case "NAPTR":
		return fmt.Sprintf("%d %d %q %q %q %s", h.NAPTROrder, h.Priority, h.NAPTRFlags, h.NAPTRService, h.NAPTRRegexp, h.Target)
	case "RAW":
		return fmt.Sprintf("type %d %s", h.RRType, h.RRDataHex)
	}
	return h.Value
}

// domDHCPRecords lists the names the reservations publish: the host name and
// every extra name, as A records for the reserved address.
func domDHCPRecords(cluster config.Cluster) []domRow {
	var out []domRow
	names := make([]string, 0, len(cluster.Scopes))
	for n := range cluster.Scopes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, scope := range names {
		for _, res := range cluster.Scopes[scope].Reservations {
			for _, n := range res.DNSNames() {
				out = append(out, domRow{Host: n, Type: "A", Value: res.IP, Dynamic: true,
					Title: "published from the reservation of " + res.MAC + " in scope " + scope + "; edit it on DHCP, Hosts"})
			}
		}
	}
	return out
}

func domainRowsFor(cluster config.Cluster, d config.LocalDomain, virtual bool) (static, dyn []domRow) {
	if !virtual {
		for _, h := range d.Records {
			static = append(static, domRow{Host: domHostLabel(h.Host), Type: strings.ToUpper(h.Type), Value: domValueText(h),
				TTL: ttlText(h.TTL), Line: formatDomainHostLine(h), Title: d.Name})
		}
	}
	suffix := "." + strings.ToLower(strings.TrimSuffix(d.Name, "."))
	for _, r := range domDHCPRecords(cluster) {
		low := strings.ToLower(r.Host)
		switch {
		case virtual:
			dyn = append(dyn, r)
		case strings.HasSuffix(low, suffix):
			r.Host = r.Host[:len(r.Host)-len(suffix)]
			dyn = append(dyn, r)
		}
	}
	return static, dyn
}

func ttlText(t int) string {
	if t <= 0 {
		return ""
	}
	return strconv.Itoa(t)
}

func domFilter(rows []domRow, q, show string) []domRow {
	q = strings.ToLower(strings.TrimSpace(q))
	var out []domRow
	for _, r := range rows {
		if show == "static" && r.Dynamic || show == "dhcp" && !r.Dynamic {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(r.Host+" "+r.Type+" "+r.Value), q) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func domSort(rows []domRow, key string, desc bool) {
	less := func(a, b domRow) bool {
		switch key {
		case "type":
			if a.Type != b.Type {
				return a.Type < b.Type
			}
		case "value":
			if a.Value != b.Value {
				return a.Value < b.Value
			}
		case "ttl":
			x, _ := strconv.Atoi(a.TTL)
			y, _ := strconv.Atoi(b.TTL)
			if x != y {
				return x < y
			}
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.Value < b.Value
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if desc {
			return less(rows[j], rows[i])
		}
		return less(rows[i], rows[j])
	})
}

func domSortHeaders(base url.Values, key string, desc bool) []domSortHeader {
	cols := []struct{ Label, Key string }{{"Name", "name"}, {"Type", "type"}, {"Value", "value"}, {"TTL", "ttl"}}
	out := make([]domSortHeader, len(cols))
	for i, c := range cols {
		v := url.Values{}
		for k, vs := range base {
			if k != "sort" && k != "dir" && k != "page" {
				v[k] = vs
			}
		}
		v.Set("sort", c.Key)
		h := domSortHeader{Label: c.Label, AriaSort: "none"}
		if key == c.Key {
			if desc {
				h.Arrow, h.AriaSort = "▼", "descending"
			} else {
				v.Set("dir", "desc")
				h.Arrow, h.AriaSort = "▲", "ascending"
			}
		}
		h.URL = "/config/domains?" + v.Encode()
		out[i] = h
	}
	return out
}

// buildDomEditor assembles the editor page from the staged (or live) config.
func buildDomEditor(cluster config.Cluster, pending bool, q url.Values) domEditorData {
	data := domEditorData{Pending: pending, Types: domRecordTypes}
	data.RailQ = strings.TrimSpace(q.Get("rq"))
	domains := append([]config.LocalDomain(nil), cluster.LocalDomains...)
	sort.Slice(domains, func(i, j int) bool { return strings.ToLower(domains[i].Name) < strings.ToLower(domains[j].Name) })
	chosen := q.Get("d")
	if chosen == "" && len(domains) > 0 {
		chosen = domains[0].Name
	}
	dyn := len(domDHCPRecords(cluster))
	rail := func(name string, n int, linked bool) domRailItem {
		v := url.Values{"d": {name}}
		return domRailItem{Name: name, Count: n, Active: name == chosen, Linked: linked, URL: "/config/domains?" + v.Encode()}
	}
	for _, d := range domains {
		if data.RailQ != "" && !strings.Contains(strings.ToLower(d.Name), strings.ToLower(data.RailQ)) {
			continue
		}
		data.Rail = append(data.Rail, rail(d.Name, len(d.Records), d.ForkedFrom != ""))
		data.Names = append(data.Names, d.Name)
	}
	data.Rail = append(data.Rail, rail(domDHCPNames, dyn, false))

	var cur config.LocalDomain
	virtual := chosen == domDHCPNames
	found := virtual
	for _, d := range domains {
		if d.Name == chosen {
			cur, found = d, true
		}
	}
	if !found {
		return data
	}
	if virtual {
		cur = config.LocalDomain{Name: domDHCPNames}
	}
	static, dynRows := domainRowsFor(cluster, cur, virtual)
	data.Virtual = virtual
	data.Linked = cur.ForkedFrom != ""
	data.Domain = &domHeader{Name: cur.Name, TTL: cur.TTL, ForkedFrom: cur.ForkedFrom, Static: len(static), Dynamic: len(dynRows)}
	all := append(append([]domRow(nil), static...), dynRows...)

	data.Q = listQuery(q)
	data.Show = listShow(q.Get("show"), "static", "dhcp")
	sortKey := q.Get("sort")
	desc := q.Get("dir") == "desc"
	per := pagerPer(q)
	keep := pagerKeep(url.Values{"d": {cur.Name}}, per)
	if data.Q != "" {
		keep.Set("q", data.Q)
	}
	if data.Show != "" {
		keep.Set("show", data.Show)
	}
	if sortKey != "" {
		keep.Set("sort", sortKey)
		if desc {
			keep.Set("dir", "desc")
		}
	}
	if !virtual && cur.ForkedFrom == "" {
		for _, d := range domains {
			if d.Name != cur.Name && d.ForkedFrom == "" {
				data.BulkTargets = append(data.BulkTargets, d.Name)
			}
		}
		for _, k := range []string{"ttl", "ttlclear", "probe-on", "probe-off", "value", "move", "copy", "delete"} {
			data.BulkActions = append(data.BulkActions, bulkOption{k, bulkActions[k]})
		}
	}
	data.Chips = listChips("/config/domains", "", keep, data.Show, []chipDef{{"", "All", len(all)}, {"static", "Static", len(static)}, {"dhcp", "DHCP names", len(dynRows)}})
	rows := domFilter(all, data.Q, data.Show)
	domSort(rows, sortKey, desc)
	data.Total = len(rows)
	size := pagerSize(per, len(rows))
	pages := (len(rows) + size - 1) / size
	if pages == 0 {
		pages = 1
	}
	page, _ := strconv.Atoi(q.Get("page"))
	page = min(max(page, 1), pages)
	start, end := (page-1)*size, min(page*size, len(rows))
	data.Rows = rows[start:end]
	data.PagerTop, data.PagerBottom = newPagerBars("/config/domains", keep, per, len(rows), page, pages, start, end)
	data.FilterHidden = hiddenFields(keep, "d", "per", "show", "sort", "dir")
	data.Headers = domSortHeaders(keep, sortKey, desc)
	return data
}

func handleDomainEditor(ref *configRef, templates *TemplateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cluster, _, pending, err := currentEditableConfig(nodesIncludingSelf(ref.Load()))
		if err != nil {
			http.Error(w, "could not read the configuration from any node: "+err.Error(), http.StatusBadGateway)
			return
		}
		data := buildDomEditor(cluster, pending, r.URL.Query())
		data.AddName = strings.TrimSpace(r.URL.Query().Get("addname"))
		data.AddType = strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("addtype")))
		data.Sets = templates.ByKind(TemplateKindDNS)
		data.Error = r.URL.Query().Get("err")
		data.Done = r.URL.Query().Get("done")
		renderTemplate(w, domEditorTmpl, data, "domains")
	}
}

// domRecordLine builds one record line from the quick-add fields.
func domRecordLine(f url.Values) (string, error) {
	typ := strings.ToUpper(strings.TrimSpace(f.Get("type")))
	name := strings.TrimSpace(f.Get("name"))
	if name == "" {
		name = "@"
	}
	value := strings.TrimSpace(f.Get("value"))
	target := strings.TrimSpace(f.Get("target"))
	num := func(k string) string {
		v := strings.TrimSpace(f.Get(k))
		if v == "" {
			return "0"
		}
		return v
	}
	for _, c := range name + value + target {
		if c == '|' || c == '\n' || c == '\r' {
			return "", fmt.Errorf("a name or value may not contain | or a line break")
		}
	}
	var line string
	switch typ {
	case "A", "AAAA", "CNAME", "TXT", "PTR":
		if value == "" {
			return "", fmt.Errorf("the value is required")
		}
		line = strings.Join([]string{typ, name, value}, "|")
	case "MX":
		if target == "" {
			return "", fmt.Errorf("the mail server name is required")
		}
		line = strings.Join([]string{typ, name, target, num("priority")}, "|")
	case "SRV":
		if target == "" {
			return "", fmt.Errorf("the target is required")
		}
		line = strings.Join([]string{typ, name, target, num("port"), num("priority"), num("weight")}, "|")
	case "CAA":
		if value == "" {
			return "", fmt.Errorf("the value is required")
		}
		tag := strings.TrimSpace(f.Get("caa_tag"))
		if tag == "" {
			tag = "issue"
		}
		line = strings.Join([]string{typ, name, "0", tag, value}, "|")
	default:
		return "", fmt.Errorf("unsupported record type %q", typ)
	}
	if ttl := strings.TrimSpace(f.Get("ttl")); ttl != "" {
		if _, err := strconv.Atoi(ttl); err != nil {
			return "", fmt.Errorf("the TTL must be a number of seconds")
		}
		line += "|ttl=" + ttl
	}
	return line, nil
}

func sameRecord(a, b config.LocalDomainHost) bool {
	a.TTL, b.TTL = 0, 0
	a.Host, b.Host = domHostLabel(a.Host), domHostLabel(b.Host)
	a.Host, b.Host = strings.ToLower(a.Host), strings.ToLower(b.Host)
	a.Type, b.Type = strings.ToUpper(a.Type), strings.ToUpper(b.Type)
	return a == b
}

// precheckRecord refuses a duplicate and a CNAME that would sit beside other
// data at the same name, with a message that says what is already there.
func precheckRecord(existing []config.LocalDomainHost, h config.LocalDomainHost, skip int) error {
	host := strings.ToLower(domHostLabel(h.Host))
	for i, e := range existing {
		if i == skip {
			continue
		}
		if sameRecord(e, h) {
			return fmt.Errorf("%s already has this record: %s", domHostLabel(e.Host), formatDomainHostLine(e))
		}
		if strings.ToLower(domHostLabel(e.Host)) != host {
			continue
		}
		ec, nc := strings.EqualFold(e.Type, "CNAME"), strings.EqualFold(h.Type, "CNAME")
		if nc && !ec || ec && !nc || nc && ec {
			return fmt.Errorf("%s already has %s data, and a name with a CNAME may hold nothing else: %s", domHostLabel(e.Host), strings.ToUpper(e.Type), formatDomainHostLine(e))
		}
	}
	return nil
}

func domBack(name, key, msg string) string {
	v := url.Values{"d": {name}}
	v.Set(key, msg)
	return "/config/domains?" + v.Encode()
}

// mutateDomain applies f to one domain's records and stages the result.
func mutateDomain(ref *configRef, w http.ResponseWriter, r *http.Request, name string, f func(d *config.LocalDomain) error) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
		return
	}
	cfg := ref.Load()
	current, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
	if err != nil {
		http.Error(w, "could not read current config: "+err.Error(), http.StatusBadGateway)
		return
	}
	domains := make([]config.LocalDomain, len(current.LocalDomains))
	copy(domains, current.LocalDomains)
	idx := -1
	for i := range domains {
		if domains[i].Name == name {
			idx = i
		}
	}
	if idx < 0 {
		http.Error(w, fmt.Sprintf("domain %q not found", name), http.StatusNotFound)
		return
	}
	if domains[idx].ForkedFrom != "" {
		http.Redirect(w, r, domBack(name, "err", "this domain is linked to "+domains[idx].ForkedFrom+"; edit the original, the change is copied to the link"), http.StatusSeeOther)
		return
	}
	d := domains[idx]
	d.Records = append([]config.LocalDomainHost(nil), d.Records...)
	if err := f(&d); err != nil {
		http.Redirect(w, r, domBack(name, "err", err.Error()), http.StatusSeeOther)
		return
	}
	domains[idx] = d
	domains = config.PropagateForkedDomains(domains, name)
	payload := clusterPushPayloadFrom(current)
	payload.Scopes = current.Scopes
	payload.LocalDomains = domains
	user, _ := userFromContext(r)
	pushCandidateAndRenderResult(w, cfg, payload, user, "/config/domains?d="+url.QueryEscape(name), "back to the records")
}

func handleDomainRecordAdd(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		mutateDomain(ref, w, r, name, func(d *config.LocalDomain) error {
			line, err := domRecordLine(r.PostForm)
			if err != nil {
				return err
			}
			h, err := parseDomainHostLine(line)
			if err != nil {
				return err
			}
			if err := precheckRecord(d.Records, h, -1); err != nil {
				return err
			}
			d.Records = append(d.Records, h)
			return nil
		})
	}
}

func findRecordByLine(records []config.LocalDomainHost, line string) int {
	line = strings.TrimSpace(line)
	for i, h := range records {
		if formatDomainHostLine(h) == line {
			return i
		}
	}
	return -1
}

func handleDomainRecordEdit(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		mutateDomain(ref, w, r, name, func(d *config.LocalDomain) error {
			i := findRecordByLine(d.Records, r.PostForm.Get("old"))
			if i < 0 {
				return fmt.Errorf("the record changed in the meantime; reload and try again")
			}
			h, err := parseDomainHostLine(strings.TrimSpace(r.PostForm.Get("line")))
			if err != nil {
				return err
			}
			if err := precheckRecord(d.Records, h, i); err != nil {
				return err
			}
			d.Records[i] = h
			return nil
		})
	}
}

func handleDomainRecordDelete(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		mutateDomain(ref, w, r, name, func(d *config.LocalDomain) error {
			i := findRecordByLine(d.Records, r.PostForm.Get("line"))
			if i < 0 {
				return fmt.Errorf("the record is already gone; reload")
			}
			d.Records = append(d.Records[:i], d.Records[i+1:]...)
			return nil
		})
	}
}

func handleDomainTTL(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		mutateDomain(ref, w, r, name, func(d *config.LocalDomain) error {
			v := strings.TrimSpace(r.PostForm.Get("ttl"))
			ttl := 0
			if v != "" {
				n, err := strconv.Atoi(v)
				if err != nil || n < 0 || n > 2147483647 {
					return fmt.Errorf("the default TTL is a number of seconds, or empty for the DNS server default")
				}
				ttl = n
			}
			d.TTL = ttl
			if r.PostForm.Get("follow") == "1" {
				for i := range d.Records {
					d.Records[i].TTL = 0
				}
			}
			return nil
		})
	}
}

var domEditorTmpl = template.Must(template.New("domains").Parse(pagerBarDefineHTML + `<!doctype html>
<title>dnshived-web — DNS domains</title>
` + styleHTML + `
` + navHTML + pendingBannerHTML + `
<div class="pagehead"><h1>DNS</h1></div>
` + dnsTabs("/config/domains") + `
{{if .Error}}<p class="crit">{{.Error}}</p>{{end}}
{{if .Done}}<p class="ok">{{.Done}}</p>{{end}}
<div class="dom-layout">
<aside class="dom-rail card">
<form method="get" action="/config/domains"><input type="search" name="rq" value="{{.RailQ}}" placeholder="Find a domain…" aria-label="Find a domain"></form>
<ul class="rail-list">{{range .Rail}}<li{{if .Active}} class="on"{{end}}><a href="{{.URL}}">{{.Name}}{{if .Linked}} <span class="dim" title="linked domain">⛓</span>{{end}}</a><span class="dim">{{.Count}}</span></li>{{end}}</ul>
<form method="post" action="/config/domains/new" class="rail-add"><input name="name" placeholder="new-domain.lan" required aria-label="New domain name"><button type="submit">+ Add domain</button></form>
</aside>
<section class="dom-main">
{{if .Domain}}
<div class="dom-head"><h2>{{.Domain.Name}}</h2>
{{if .Domain.ForkedFrom}}<span class="chip warn" title="read-only here: edit the original, the change is copied">⛓ linked to {{.Domain.ForkedFrom}}</span>{{end}}
<span class="dim">{{.Domain.Static}} static · {{.Domain.Dynamic}} from DHCP</span></div>
{{if .Virtual}}<p class="dim">Names published from DHCP reservations (the host name and the extra names). Edit them on DHCP, Hosts.</p>{{end}}
{{if and (not .Virtual) (not .Linked)}}
<form method="post" action="/config/domains/{{.Domain.Name}}/records/add" class="quickadd" id="quickadd">
<select name="type" id="qa-type" class="js-combo">{{range .Types}}<option{{if eq . $.AddType}} selected{{end}}>{{.}}</option>{{end}}</select>
<input name="name" value="{{.AddName}}" placeholder="name (@ for the domain)" aria-label="Name" size="22">
<input name="value" id="qa-value" placeholder="value" aria-label="Value" size="26">
<span class="qa-x" data-for="MX SRV"><input name="priority" placeholder="priority" size="6" aria-label="Priority"></span>
<span class="qa-x" data-for="SRV"><input name="weight" placeholder="weight" size="6" aria-label="Weight"><input name="port" placeholder="port" size="6" aria-label="Port"></span>
<span class="qa-x" data-for="MX SRV"><input name="target" placeholder="target host" size="22" aria-label="Target"></span>
<span class="qa-x" data-for="CAA"><select name="caa_tag"><option>issue</option><option>issuewild</option><option>iodef</option></select></span>
<input name="ttl" placeholder="TTL" size="6" aria-label="TTL">
<button type="submit" class="btn-primary">+ Add record</button>
</form>
{{end}}
<div class="listbar">
<form method="get" action="/config/domains">{{range .FilterHidden}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">{{end}}<input type="search" name="q" value="{{.Q}}" placeholder="Search name, type or value…" aria-label="Search records"></form>
{{range .Chips}}<a class="lchip{{if .Active}} sel{{end}}" href="{{.URL}}">{{.Label}}</a>{{end}}
<span class="grow"></span>
{{if not .Virtual}}{{if not .Linked}}<button type="button" class="btn quiet sm" id="imp-open" title="Paste or load a zone file or record lines; you see what is new first">Import…</button><button type="button" class="btn quiet sm" id="mail-open" title="Build SPF, DMARC and DKIM records for this domain; you see what is new first">Mail records…</button>{{if .Sets}}<button type="button" class="btn quiet sm" id="set-open" title="Add the records of a record set to this domain; you see collisions first">Apply a record set…</button>{{end}}{{end}}<a class="lbtn" href="/config/domains/{{.Domain.Name}}/export" title="Download the records as a zone file">Export</a>{{end}}
</div>
{{template "pagerbar" .PagerTop}}
{{if .BulkActions}}<style>.bulkbar{display:flex;align-items:center;gap:.5rem;min-height:2.4rem;margin:.2rem 0}</style><form method="post" action="/config/domains/{{.Domain.Name}}/bulk" id="bulk-form" class="bulkbar" data-total="{{.Total}}" data-shown="{{len .Rows}}">
<span id="bulk-count" class="dim">Select records to change several at once.</span>
<span id="bulk-ctl" style="display:none"><select name="action" id="bulk-action" class="js-combo" aria-label="Bulk action">{{range .BulkActions}}<option value="{{.Value}}">{{.Label}}</option>{{end}}</select>
<input name="ttl" id="bulk-ttl" placeholder="seconds" size="8" inputmode="numeric" aria-label="TTL in seconds" style="display:none">
<input name="value" id="bulk-value" placeholder="new value" size="24" aria-label="New value" style="display:none">
<span id="bulk-target-wrap" style="display:none"><select name="target" id="bulk-target" class="js-combo" aria-label="Target domain">{{range .BulkTargets}}<option>{{.}}</option>{{end}}</select></span>
<input type="hidden" name="q" value="{{.Q}}"><input type="hidden" name="show" value="{{.Show}}"><input type="hidden" name="all" id="bulk-all" value="">
<button type="submit" class="btn-primary sm">Preview…</button> <a href="#" id="bulk-allmatch" style="display:none"></a></span></form>{{end}}
<div class="table-wrap"><table class="list-table dom-table" border="1" cellpadding="4">
<colgroup><col style="width:2.2rem"><col style="width:22%"><col style="width:7%"><col><col style="width:7%"><col style="width:3.5rem"></colgroup>
<tr><th>{{if .BulkActions}}<input type="checkbox" id="sel-all" aria-label="Select the shown records">{{end}}</th>{{range .Headers}}<th aria-sort="{{.AriaSort}}"><a href="{{.URL}}" style="color:inherit;text-decoration:none">{{.Label}}<span style="display:inline-block;width:1em">{{.Arrow}}</span></a></th>{{end}}<th></th></tr>
{{range .Rows}}<tr>
<td style="text-align:center">{{if and .Line $.BulkActions}}<input type="checkbox" class="sel" name="line" value="{{.Line}}" form="bulk-form" aria-label="Select {{.Host}} {{.Type}}">{{end}}</td>
<td class="mono">{{.Host}}{{if .Dynamic}} <span class="chip" title="{{.Title}}">DHCP</span>{{end}}</td><td>{{.Type}}</td><td class="mono" title="{{.Value}}">{{.Value}}</td><td>{{.TTL}}</td>
<td style="width:3rem;text-align:center">{{if .Line}}{{if not $.Linked}}<details class="row-menu"><summary aria-haspopup="menu" title="actions">&#9776;</summary><div class="row-menu-list" role="menu">
<button type="button" role="menuitem" class="rec-edit" data-line="{{.Line}}">Edit…</button>
{{if or (eq .Type "A") (eq .Type "AAAA") (eq .Type "CNAME")}}<form method="post" action="/config/domains/{{$.Domain.Name}}/template" onsubmit="var n=prompt('Name of the record set made from {{.Host}} (its records, service records and aliases):','{{.Host}}');if(!n)return false;this.set_name.value=n;return true"><input type="hidden" name="host" value="{{.Host}}"><input type="hidden" name="set_name"><button type="submit" role="menuitem">Make a record set…</button></form>{{end}}
<form method="post" action="/config/domains/{{$.Domain.Name}}/records/delete" onsubmit="return confirm('Delete this record?')"><input type="hidden" name="line" value="{{.Line}}"><button type="submit" role="menuitem" class="danger">Delete…</button></form>
</div></details>{{end}}{{end}}</td></tr>
{{else}}<tr><td colspan="6" class="dim">{{if or .Q .Show}}No record matches.{{else}}No records yet. Add one above.{{end}}</td></tr>
{{end}}
</table></div>
{{template "pagerbar" .PagerBottom}}
{{if not .Virtual}}
<div class="dom-actions">
{{if not .Domain.ForkedFrom}}<form method="post" action="/config/domains/{{.Domain.Name}}/ttl" class="dom-ttl" style="display:inline"><label>Default TTL <input name="ttl" value="{{if .Domain.TTL}}{{.Domain.TTL}}{{end}}" placeholder="server default" size="9" inputmode="numeric" aria-label="Default TTL in seconds for this domain" title="Seconds; applies to records without their own TTL. Empty uses the DNS server default."></label> <label title="Clear the TTL of every record in this domain so all follow the default"><input type="checkbox" name="follow" value="1"> records follow it</label> <button type="submit">Set</button></form>
{{end}}{{if .Domain.ForkedFrom}}<form method="post" action="/config/domains/{{.Domain.Name}}/unlink" onsubmit="return confirm('Make {{.Domain.Name}} standalone? It keeps a copy of the records and is no longer updated from {{.Domain.ForkedFrom}}.')" style="display:inline"><button type="submit">Unlink (make standalone)</button></form>
{{else}}<form method="post" action="/config/domains/{{.Domain.Name}}/fork" onsubmit="var n=prompt('Name of the new linked domain (it answers with the same records):','');if(!n)return false;this.new_name.value=n;return true" style="display:inline"><input type="hidden" name="new_name"><button type="submit">Link a new domain…</button></form>{{end}}
<form method="post" action="/config/domains/{{.Domain.Name}}/delete" onsubmit="return confirm('Delete the domain {{.Domain.Name}} and all its records?')" style="display:inline"><button type="submit" class="btn-danger">Delete domain…</button></form>
</div>
{{end}}
{{if and (not .Virtual) (not .Linked)}}<dialog id="imp-dialog"><form method="post" action="/config/domains/{{.Domain.Name}}/import">
<h3 style="margin-top:0">Import records into {{.Domain.Name}}</h3>
<p class="dim">A zone file (A, AAAA, CNAME, PTR, MX, SRV, TXT, CAA) or the record lines of the text editor. You see what is new, a duplicate or in conflict before anything is staged.</p>
<textarea name="text" id="imp-text" rows="12" style="width:100%" aria-label="Records to import"></textarea>
<p><input type="file" id="imp-file" aria-label="Load a file"></p>
<p style="margin-bottom:0"><button type="submit" class="btn-primary">Preview</button> <button type="button" id="imp-cancel">Cancel</button></p>
</form></dialog>{{end}}
{{if and (not .Virtual) (not .Linked)}}<dialog id="mail-dialog"><form method="post" action="/config/domains/{{.Domain.Name}}/mail" class="mailform">
<h3 style="margin-top:0">Mail records for {{.Domain.Name}}</h3>
<fieldset><legend><label><input type="checkbox" name="spf" value="1" checked> SPF: who may send mail for this domain</label></legend>
<label><input type="checkbox" name="spf_mx" value="1" checked> this domain's mail servers (mx)</label> <label><input type="checkbox" name="spf_a" value="1"> this domain's address (a)</label><br>
<label>Also allow (one host per line or comma): <input name="spf_include" size="34" placeholder="_spf.example.com"></label>
<label>Everything else: <select name="spf_end" class="js-combo"><option value="~all">soft fail (~all)</option><option value="-all">reject (-all)</option><option value="?all">neutral (?all)</option></select></label></fieldset>
<fieldset><legend><label><input type="checkbox" name="dmarc" value="1" checked> DMARC: what to do with mail that fails the checks</label></legend>
<label>Policy <select name="dmarc_policy" class="js-combo"><option value="none">none (only report)</option><option value="quarantine">quarantine</option><option value="reject">reject</option></select></label>
<label>Reports to <input name="dmarc_rua" size="26" placeholder="dmarc@example.com"></label>
<label>Apply to <input name="dmarc_pct" size="4" placeholder="100"> %</label>
<label>DKIM alignment <select name="dmarc_adkim"><option value="r">relaxed</option><option value="s">strict</option></select></label>
<label>SPF alignment <select name="dmarc_aspf"><option value="r">relaxed</option><option value="s">strict</option></select></label></fieldset>
<fieldset><legend>DKIM: the public key of your mail system</legend>
<label>Selector <input name="dkim_selector" size="14" placeholder="mail"></label>
<label>Public key or the whole record <textarea name="dkim_key" rows="3" style="width:100%" placeholder="MIIBIjANBgkq… or v=DKIM1; k=rsa; p=…"></textarea></label></fieldset>
<p class="dim">Long keys are stored as one value and served in 255-character parts, which resolvers join again.</p>
<p style="margin-bottom:0"><button type="submit" class="btn-primary">Preview</button> <button type="button" id="mail-cancel">Cancel</button></p>
</form></dialog>{{end}}
{{if and (not .Virtual) (not .Linked) .Sets}}<dialog id="set-dialog"><form method="post" action="/config/domains/{{.Domain.Name}}/apply">
<h3 style="margin-top:0">Apply a record set to {{.Domain.Name}}</h3>
<p class="dim">The set's example domain becomes {{.Domain.Name}}. You see which records are new, duplicate or in conflict before anything is staged.</p>
<select name="set" class="js-combo" aria-label="Record set">{{range .Sets}}<option value="{{.ID}}">{{.Name}}</option>{{end}}</select>
<p style="margin-bottom:0"><button type="submit" class="btn-primary">Preview</button> <button type="button" id="set-cancel">Cancel</button></p>
</form></dialog>{{end}}
<dialog id="rec-dialog"><form method="post" id="rec-form" action="/config/domains/{{.Domain.Name}}/records/edit">
<h3 style="margin-top:0">Edit record</h3>
<p class="dim">TYPE|NAME|VALUE… as in the text editor; add |ttl=N for a TTL.</p>
<input type="hidden" name="old" id="rec-old"><input name="line" id="rec-line" style="width:100%" aria-label="Record line">
<p style="margin-bottom:0"><button type="submit" class="btn-primary">Stage change</button> <button type="button" id="rec-cancel">Cancel</button></p>
</form></dialog>
{{else}}<p class="dim">No domain yet. Add one on the left.</p>{{end}}
</section>
</div>
<script>
(function(){
var t=document.getElementById('qa-type'),v=document.getElementById('qa-value');
function sync(){
 if(!t)return;var ty=t.value;
 document.querySelectorAll('.qa-x').forEach(function(s){s.style.display=s.getAttribute('data-for').split(' ').indexOf(ty)>=0?'inline':'none'});
 if(v)v.style.display=(ty==='MX'||ty==='SRV')?'none':'';
}
if(t){t.addEventListener('change',sync);t.addEventListener('input',sync);sync()}
var dlg=document.getElementById('rec-dialog');
document.querySelectorAll('.rec-edit').forEach(function(b){b.addEventListener('click',function(){
 if(!dlg||!dlg.showModal)return;
 document.getElementById('rec-old').value=b.getAttribute('data-line');
 document.getElementById('rec-line').value=b.getAttribute('data-line');
 dlg.showModal();
})});
var io=document.getElementById('imp-open'),id=document.getElementById('imp-dialog');
if(io&&id){io.addEventListener('click',function(){id.showModal()});
 document.getElementById('imp-cancel').addEventListener('click',function(){id.close()});
 var f=document.getElementById('imp-file');
 f.addEventListener('change',function(){var x=f.files[0];if(!x)return;var rd=new FileReader();rd.onload=function(){document.getElementById('imp-text').value=String(rd.result)};rd.readAsText(x)})}
var mo=document.getElementById('mail-open'),md=document.getElementById('mail-dialog');
if(mo&&md){mo.addEventListener('click',function(){md.showModal()});document.getElementById('mail-cancel').addEventListener('click',function(){md.close()})}
var so=document.getElementById('set-open'),sd=document.getElementById('set-dialog');
if(so&&sd){so.addEventListener('click',function(){sd.showModal()});document.getElementById('set-cancel').addEventListener('click',function(){sd.close()})}
var bf=document.getElementById('bulk-form');
if(bf){
 var boxes=function(){return Array.prototype.slice.call(document.querySelectorAll('input.sel'))};
 var cnt=document.getElementById('bulk-count'),ctl=document.getElementById('bulk-ctl'),act=document.getElementById('bulk-action'),
  tt=document.getElementById('bulk-ttl'),vv=document.getElementById('bulk-value'),tg=document.getElementById('bulk-target-wrap'),
  al=document.getElementById('bulk-all'),am=document.getElementById('bulk-allmatch'),sa=document.getElementById('sel-all'),
  total=parseInt(bf.getAttribute('data-total'),10)||0;
 var upd=function(){
  var n=boxes().filter(function(b){return b.checked}).length,all=al.value==='1';
  ctl.style.display=(n||all)?'inline':'none';
  cnt.textContent=all?('All '+total+' matching records selected'):(n?(n+' selected'):'Select records to change several at once.');
  cnt.className=n||all?'':'dim';
  var a=act.value;
  tt.style.display=a==='ttl'?'':'none';vv.style.display=a==='value'?'':'none';tg.style.display=(a==='move'||a==='copy')?'':'none';
  var every=n>0&&n===boxes().length;
  if(every&&total>n&&!all){am.style.display='';am.textContent='Select all '+total+' matching';}
  else if(all){am.style.display='';am.textContent='Select only the shown records';}
  else am.style.display='none';
 };
 boxes().forEach(function(b){b.addEventListener('change',function(){al.value='';upd()})});
 if(sa)sa.addEventListener('change',function(){boxes().forEach(function(b){b.checked=sa.checked});al.value='';upd()});
 act.addEventListener('change',upd);act.addEventListener('input',upd);
 am.addEventListener('click',function(e){e.preventDefault();if(al.value==='1'){al.value='';}else{al.value='1';}upd()});
 upd();
}
var c=document.getElementById('rec-cancel');if(c&&dlg)c.addEventListener('click',function(){dlg.close()});
})();
</script>
` + rowMenuScriptHTML + comboboxScriptHTML + `
`))
