// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type dsPublished struct {
	Rev        uint64   `json:"rev"`
	Digest     string   `json:"digest"`
	Names      int      `json:"names"`
	Records    int      `json:"records"`
	BuiltAt    string   `json:"built_at"`
	RowErrors  []string `json:"row_errors"`
	RowErrN    int      `json:"row_error_count"`
	Dangling   []string `json:"dangling"`
	DanglingN  int      `json:"dangling_count"`
	Error      string   `json:"error"`
	Collisions []struct {
		Name   string `json:"name"`
		MAC    string `json:"mac"`
		Scope  string `json:"scope"`
		IP     string `json:"ip"`
		Holder string `json:"holder"`
	} `json:"collisions"`
}

type dsStatus struct {
	Rev         uint64       `json:"rev"`
	Commit      uint64       `json:"commit_index"`
	Head        uint64       `json:"head"`
	Auth        bool         `json:"authoritative"`
	Serving     bool         `json:"serving"`
	Hosts       int          `json:"hosts"`
	Records     int          `json:"records"`
	Published   *dsPublished `json:"published"`
	Replication *struct {
		Role   string   `json:"role"`
		Leader string   `json:"leader"`
		Self   string   `json:"self"`
		Term   uint64   `json:"term"`
		Voters []string `json:"voters"`
	} `json:"replication"`
}

type dsNodeState struct {
	Node   NodeConfig
	Status *dsStatus
	Err    string
}

// dsFetchStatuses asks every core for the store status in parallel.
func dsFetchStatuses(nodes []NodeConfig) []dsNodeState {
	out := make([]dsNodeState, len(nodes))
	var wg sync.WaitGroup
	for i, n := range nodes {
		wg.Add(1)
		go func(i int, n NodeConfig) {
			defer wg.Done()
			out[i].Node = n
			var st dsStatus
			code, err := doGet(httpClient, n, "/api/v1/dnsstore/status", &st)
			switch {
			case err != nil && code == http.StatusNotFound:
				out[i].Err = "not enabled"
			case err != nil:
				out[i].Err = err.Error()
			case code != http.StatusOK:
				out[i].Err = "HTTP " + strconv.Itoa(code)
			default:
				out[i].Status = &st
			}
		}(i, n)
	}
	wg.Wait()
	return out
}

// dsOrder puts the leader first, then the other cores that run the store, so a write tries the right node first.
func dsOrder(states []dsNodeState) []dsNodeState {
	out := append([]dsNodeState(nil), states...)
	sort.SliceStable(out, func(i, j int) bool {
		rank := func(s dsNodeState) int {
			switch {
			case s.Status != nil && s.Status.Replication != nil && s.Status.Replication.Role == "leader":
				return 0
			case s.Status != nil:
				return 1
			}
			return 2
		}
		return rank(out[i]) < rank(out[j])
	})
	return out
}

func dsPost(n NodeConfig, path string, payload any) (int, map[string]any, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest(http.MethodPost, n.baseURL()+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if n.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+n.AdminToken)
	}
	resp, err := bigDocHTTPClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		out = map[string]any{"error": strings.TrimSpace(string(raw))}
	}
	return resp.StatusCode, out, nil
}

// dsWrite sends a write to the leader, following the cores in leader-first order, and words the answer for the page.
func dsWrite(cfg *WebConfig, path string, payload any) (map[string]any, string) {
	states := dsOrder(dsFetchStatuses(nodesIncludingSelf(cfg)))
	var last string
	for _, s := range states {
		if s.Status == nil {
			continue
		}
		code, out, err := dsPost(s.Node, path, payload)
		if err != nil {
			last = s.Node.Name + ": " + err.Error()
			continue
		}
		if code == http.StatusConflict && out["error"] == "not_leader" {
			last = "no core accepted the write as leader"
			continue
		}
		if code == http.StatusOK {
			return out, ""
		}
		return out, dsErrorText(code, out)
	}
	if last == "" {
		last = "the DNS store is not enabled on any core"
	}
	return nil, last
}

func dsErrorText(code int, out map[string]any) string {
	var parts []string
	if errs, ok := out["errors"].([]any); ok {
		for _, e := range errs {
			parts = append(parts, fmt.Sprint(e))
		}
	}
	if e, ok := out["error"].(string); ok && e != "" {
		parts = append(parts, e)
	}
	if len(parts) == 0 {
		return "the core answered HTTP " + strconv.Itoa(code)
	}
	return strings.Join(parts, "; ")
}

func dsRedirect(w http.ResponseWriter, r *http.Request, msg, errText string) {
	q := url.Values{}
	if k := r.FormValue("kind"); k == "records" {
		q.Set("kind", k)
	}
	if msg != "" {
		q.Set("msg", msg)
	}
	if errText != "" {
		q.Set("err", errText)
	}
	http.Redirect(w, r, "/dns/store?"+q.Encode(), http.StatusSeeOther)
}

func dsActor(r *http.Request) string {
	if u, ok := userFromContext(r); ok {
		return u.Name
	}
	return "web"
}

func handleDNSStoreImport(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		dry := r.FormValue("dry") != ""
		out, errText := dsWrite(cfg, "/api/v1/dnsstore/import", map[string]any{"dry_run": dry, "author": dsActor(r)})
		if errText != "" {
			dsRedirect(w, r, "", errText)
			return
		}
		n, _ := out["records"].(float64)
		skipped, _ := out["skipped"].([]any)
		msg := fmt.Sprintf("%d record(s) from the configuration", int(n))
		if dry {
			msg = "Preview: " + msg + " would be imported"
		} else {
			msg = "Imported " + msg
			auditAll(cfg, dsActor(r), "dnsstore.import", msg)
		}
		if len(skipped) > 0 {
			msg += fmt.Sprintf("; %d skipped, first: %v", len(skipped), skipped[0])
		}
		dsRedirect(w, r, msg, "")
	}
}

func handleDNSStoreCutover(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		on := r.FormValue("authoritative") == "on"
		out, errText := dsWrite(cfg, "/api/v1/dnsstore/settings", map[string]any{"authoritative": on, "author": dsActor(r)})
		if errText != "" {
			dsRedirect(w, r, "", errText)
			return
		}
		_ = out
		msg := "The DNS store answers only the records it holds; everything else is forwarded again."
		if on {
			msg = "The DNS store now answers for the whole of its domains."
		}
		auditAll(cfg, dsActor(r), "dnsstore.cutover", msg)
		dsRedirect(w, r, msg, "")
	}
}

type dsHostRow struct {
	ID, Label, Domains, Addrs string
	TTL                       uint32
}

type dsRecRow struct {
	ID, Owner, Type, Data string
	TTL                   uint32
}

type dsNodeRow struct{ Name, Role, Head, Commit, Err string }

type dsPage struct {
	Msg, Err    string
	Tabs        template.HTML
	Enabled     bool
	Status      *dsStatus
	Mode        string
	Leader      string
	Nodes       []dsNodeRow
	Kind        string
	Q           string
	Chips       []listChip
	FilterHid   []formField
	Hosts       []dsHostRow
	Records     []dsRecRow
	Total       int
	PagerTop    pagerBar
	PagerBottom pagerBar
}

func handleDNSStore(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		nodes := nodesIncludingSelf(cfg)
		states := dsFetchStatuses(nodes)
		ordered := dsOrder(states)
		data := dsPage{Msg: r.URL.Query().Get("msg"), Err: r.URL.Query().Get("err"), Tabs: template.HTML(dnsTabs("/dns/store")), Kind: "hosts"}
		if r.URL.Query().Get("kind") == "records" {
			data.Kind = "records"
		}
		for _, s := range states {
			row := dsNodeRow{Name: s.Node.Name, Err: s.Err}
			if s.Status != nil {
				row.Head, row.Commit, row.Role = strconv.FormatUint(s.Status.Head, 10), strconv.FormatUint(s.Status.Commit, 10), "single"
				if s.Status.Replication != nil {
					row.Role = s.Status.Replication.Role
				}
			}
			data.Nodes = append(data.Nodes, row)
		}
		var reader *dsNodeState
		for i := range ordered {
			if ordered[i].Status != nil {
				reader = &ordered[i]
				break
			}
		}
		if reader == nil {
			renderTemplate(w, dsTmpl, data, "dns store")
			return
		}
		data.Enabled, data.Status = true, reader.Status
		data.Mode = "overlay: records in the store are answered, everything else is forwarded"
		if reader.Status.Auth {
			data.Mode = "authoritative: the store answers for the whole of its domains"
		}
		if reader.Status.Replication != nil {
			data.Leader = reader.Status.Replication.Leader
		}
		q := listQuery(r.URL.Query())
		data.Q = q
		per := pagerPer(r.URL.Query())
		keep := pagerKeep(url.Values{}, per)
		keep.Set("kind", data.Kind)
		if q != "" {
			keep.Set("q", q)
		}
		data.Chips = []listChip{
			{Label: "Hosts " + strconv.Itoa(reader.Status.Hosts), URL: "/dns/store?kind=hosts", Active: data.Kind == "hosts"},
			{Label: "Records " + strconv.Itoa(reader.Status.Records), URL: "/dns/store?kind=records", Active: data.Kind == "records"},
		}
		data.FilterHid = hiddenFields(keep, "per", "kind")
		total := reader.Status.Hosts
		if data.Kind == "records" {
			total = reader.Status.Records
		}
		size := min(pagerSize(per, max(total, 1)), 500)
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		page = max(page, 1)
		fetch := func(page int) (int, error) {
			var resp struct {
				Total int             `json:"total"`
				Items json.RawMessage `json:"items"`
			}
			path := fmt.Sprintf("/api/v1/dnsstore/%s?q=%s&limit=%d&offset=%d", data.Kind, url.QueryEscape(q), size, (page-1)*size)
			if _, err := doGet(httpClient, reader.Node, path, &resp); err != nil {
				return 0, err
			}
			if data.Kind == "hosts" {
				var items []struct {
					ID      string   `json:"id"`
					Label   string   `json:"label"`
					Domains []string `json:"domains"`
					Addrs   []struct {
						IP string `json:"ip"`
					} `json:"addrs"`
					TTL uint32 `json:"ttl"`
				}
				_ = json.Unmarshal(resp.Items, &items)
				data.Hosts = nil
				for _, it := range items {
					var ips []string
					for _, a := range it.Addrs {
						ips = append(ips, a.IP)
					}
					data.Hosts = append(data.Hosts, dsHostRow{ID: it.ID, Label: it.Label, Domains: strings.Join(it.Domains, ", "), Addrs: strings.Join(ips, ", "), TTL: it.TTL})
				}
			} else {
				var items []struct {
					ID     string `json:"id"`
					Host   string `json:"host"`
					Sub    string `json:"sub"`
					Owner  string `json:"owner"`
					Type   string `json:"type"`
					Value  string `json:"value"`
					Target string `json:"target"`
					Pref   int    `json:"pref"`
					Prio   int    `json:"priority"`
					Weight int    `json:"weight"`
					Port   int    `json:"port"`
					Raw    string `json:"raw"`
					TTL    uint32 `json:"ttl"`
				}
				_ = json.Unmarshal(resp.Items, &items)
				data.Records = nil
				for _, it := range items {
					owner := it.Owner
					if it.Host != "" {
						owner = strings.Trim(it.Sub+" (of host "+it.Host[:8]+")", " ")
					}
					d := it.Value
					switch it.Type {
					case "SRV":
						d = fmt.Sprintf("%d %d %d %s", it.Prio, it.Weight, it.Port, it.Target)
					case "MX":
						d = fmt.Sprintf("%d %s", it.Pref, it.Target)
					}
					if it.Raw != "" {
						d = "hex " + it.Raw
					}
					data.Records = append(data.Records, dsRecRow{ID: it.ID, Owner: owner, Type: it.Type, Data: d, TTL: it.TTL})
				}
			}
			return resp.Total, nil
		}
		n, err := fetch(page)
		if err != nil {
			data.Err = "reading the store: " + err.Error()
		}
		pages := max((n+size-1)/size, 1)
		if page > pages {
			page = pages
			n, _ = fetch(page)
		}
		data.Total = n
		start, end := (page-1)*size, min(page*size, n)
		data.PagerTop, data.PagerBottom = newPagerBars("/dns/store", keep, per, n, page, pages, start, end)
		data.PagerTop.Show = true
		renderTemplate(w, dsTmpl, data, "dns store")
	}
}

var dsTmpl = template.Must(template.New("dnsstore").Parse(`<!doctype html>
<title>dnshived-web — DNS store</title>
` + styleHTML + `
` + navHTML + `
` + pagerBarDefineHTML + `
<div class="pagehead"><h1>DNS</h1></div>
{{.Tabs}}
{{if .Err}}<p class="crit">{{.Err}}</p>{{end}}
{{if .Msg}}<p class="ok">{{.Msg}}</p>{{end}}
{{if not .Enabled}}
<p class="dim">The DNS store is not running on any core. Create the file <code>/etc/dnshived/dns-store.enable</code> on every core and restart the daemons to switch it on.</p>
{{else}}
<p class="dim" title="Overlay keeps dnsmasq answering everything the store does not hold; the cutover makes the store answer for its whole domains and needs the records imported first.">Mode: <b>{{.Mode}}</b>{{if .Leader}} · leader: <b>{{.Leader}}</b>{{end}} · revision {{.Status.Rev}}{{if not .Status.Serving}} · <span class="warn" title="The last attempt to build and publish the answer table on this core failed">this core cannot serve</span>{{end}}{{with .Status.Published}} · table {{.Names}} names, {{.Records}} records{{end}}</p>
{{with .Status.Published}}{{if .Error}}<p class="crit" title="The last attempt to publish the answer table failed; the relays keep serving the previous one.">Publishing failed: {{.Error}}</p>{{end}}
{{if .RowErrors}}<p class="warn" title="These rows are skipped when the table is built; the rest is served. The first one is shown as an example.">{{.RowErrN}} row(s) are skipped, for example: {{index .RowErrors 0}}</p>{{end}}
{{if .Dangling}}<p class="warn" title="A host lists a domain that is not in the domain list any more; it is served under its other domains.">{{.DanglingN}} name(s) use a domain that is not in the domain list, for example {{index .Dangling 0}}</p>{{end}}
{{if .Collisions}}<p class="warn" title="A DHCP lease asked for a name that is already taken; the lease works, it just has no DNS name">{{len .Collisions}} DHCP name(s) are taken by another host: {{with index .Collisions 0}}{{.Name}} (held by {{.Holder}}){{end}}</p>{{end}}{{end}}
<div class="listbar">
<form method="get" action="/dns/store">{{range .FilterHid}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">{{end}}<input type="hidden" name="kind" value="{{.Kind}}"><input type="search" name="q" value="{{.Q}}" placeholder="Name, domain, address, type or value…" aria-label="Search the store"></form>
{{range .Chips}}<a class="lchip{{if .Active}} sel{{end}}" href="{{.URL}}">{{.Label}}</a>{{end}}
<span class="grow"></span>
<form method="post" action="/dns/store/import" style="display:inline"><input type="hidden" name="kind" value="{{.Kind}}"><button class="btn quiet sm" name="dry" value="1" title="Count the DNS records of the configuration that would be copied into the store">Preview import</button> <button class="btn quiet sm" title="Copy every DNS record of the configuration into the store; importing again changes nothing">Import from configuration</button></form>
<form method="post" action="/dns/store/cutover" style="display:inline" onsubmit="return confirm(this.dataset.ask)" data-ask="{{if .Status.Auth}}Go back to overlay mode? Names the store lacks are forwarded to dnsmasq again.{{else}}Make the store authoritative? Names inside its domains that it does not hold then get a negative answer. Import the configuration records first.{{end}}"><input type="hidden" name="kind" value="{{.Kind}}"><input type="hidden" name="authoritative" value="{{if .Status.Auth}}off{{else}}on{{end}}"><button class="btn quiet sm" title="{{if .Status.Auth}}Back to overlay mode{{else}}Switch from overlay to authoritative answers{{end}}">{{if .Status.Auth}}Back to overlay{{else}}Go authoritative{{end}}</button></form>
</div>
{{template "pagerbar" .PagerTop}}
<div class="table-wrap">
{{if eq .Kind "hosts"}}
<table class="list-table" border="1" cellpadding="4" cellspacing="0" style="min-width:48rem">
<colgroup><col style="width:22%"><col style="width:28%"><col style="width:40%"><col style="width:10%"></colgroup>
<tr><th>Name</th><th>Domains</th><th>Addresses</th><th>TTL</th></tr>
{{range .Hosts}}<tr>
<td style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{{.Label}}">{{.Label}}</td>
<td style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{{.Domains}}">{{.Domains}}</td>
<td style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-variant-numeric:tabular-nums" title="{{.Addrs}}">{{.Addrs}}</td>
<td style="font-variant-numeric:tabular-nums">{{if .TTL}}{{.TTL}}{{else}}<span class="dim">default</span>{{end}}</td>
</tr>{{end}}
</table>
{{else}}
<table class="list-table" border="1" cellpadding="4" cellspacing="0" style="min-width:48rem">
<colgroup><col style="width:32%"><col style="width:8%"><col style="width:48%"><col style="width:12%"></colgroup>
<tr><th>Owner</th><th>Type</th><th>Data</th><th>TTL</th></tr>
{{range .Records}}<tr>
<td style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{{.Owner}}">{{.Owner}}</td>
<td>{{.Type}}</td>
<td style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{{.Data}}">{{.Data}}</td>
<td style="font-variant-numeric:tabular-nums">{{if .TTL}}{{.TTL}}{{else}}<span class="dim">default</span>{{end}}</td>
</tr>{{end}}
</table>
{{end}}
</div>
{{template "pagerbar" .PagerBottom}}
{{if eq .Total 0}}<p class="dim">{{if .Q}}(nothing matches the search){{else}}(nothing here yet){{end}}</p>{{end}}
<table class="list-table" border="1" cellpadding="4" cellspacing="0" style="min-width:48rem;margin-top:1rem">
<colgroup><col style="width:20%"><col style="width:20%"><col style="width:20%"><col style="width:20%"><col style="width:20%"></colgroup>
<tr><th>Core</th><th>Role</th><th>Head</th><th>Committed</th><th></th></tr>
{{range .Nodes}}<tr><td>{{.Name}}</td><td>{{if .Err}}<span class="dim">{{.Err}}</span>{{else}}{{.Role}}{{end}}</td><td style="font-variant-numeric:tabular-nums">{{.Head}}</td><td style="font-variant-numeric:tabular-nums">{{.Commit}}</td><td></td></tr>{{end}}
</table>
<p class="dim">This page shows the store and switches its mode; hosts and records are edited on the <a href="/config/domains">Domains</a> page. <b>Overlay</b>: the store answers the names it holds and everything else still goes to dnsmasq, so nothing existing breaks. <b>Authoritative</b> is the cutover: do it after importing the configuration's records, and from then on the configuration's own DNS records cannot be changed.</p>
{{end}}
`))
