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
	DNSVIP      string       `json:"dns_vip"`
	VRRPID      int          `json:"dns_vip_vrrp_id"`
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

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' || r == ';' })
}

func dsDone(cfg *WebConfig, r *http.Request, action, summary string, out map[string]any) string {
	auditAll(cfg, dsActor(r), action, summary)
	msg := summary
	if w, ok := out["warnings"].([]any); ok && len(w) > 0 {
		var ws []string
		for _, x := range w {
			if m, ok := x.(map[string]any); ok {
				ws = append(ws, fmt.Sprint(m["Msg"]))
			}
		}
		msg += " Warning: " + strings.Join(ws, "; ")
	}
	return msg
}

func handleDNSStoreHost(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		label := strings.TrimSpace(r.FormValue("label"))
		domains := splitList(r.FormValue("domains"))
		var addrs []map[string]any
		ptr := r.FormValue("ptr") != ""
		for _, a := range splitList(r.FormValue("addrs")) {
			addrs = append(addrs, map[string]any{"ip": a, "ptr": ptr})
		}
		ttl, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("ttl")))
		if label == "" || len(domains) == 0 {
			dsRedirect(w, r, "", "a host needs a name and at least one domain")
			return
		}
		host := map[string]any{"label": label, "domains": domains, "addrs": addrs}
		if ttl > 0 {
			host["ttl"] = ttl
		}
		out, errText := dsWrite(cfg, "/api/v1/dnsstore/commit", map[string]any{"author": dsActor(r), "ops": []any{map[string]any{"op": "put", "kind": "host", "host": host}}})
		if errText != "" {
			dsRedirect(w, r, "", errText)
			return
		}
		dsRedirect(w, r, dsDone(cfg, r, "dnsstore.host.add", "added host "+label, out), "")
	}
}

func handleDNSStoreRecord(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		typ := strings.ToUpper(strings.TrimSpace(r.FormValue("type")))
		owner := strings.TrimSpace(r.FormValue("owner"))
		if owner == "" || typ == "" {
			dsRedirect(w, r, "", "a record needs an owner name and a type")
			return
		}
		num := func(k string) int { n, _ := strconv.Atoi(strings.TrimSpace(r.FormValue(k))); return n }
		rec := map[string]any{"type": typ, "owner": owner}
		if v := strings.TrimSpace(r.FormValue("value")); v != "" {
			rec["value"] = v
		}
		if v := strings.TrimSpace(r.FormValue("target")); v != "" {
			rec["target"] = v
		}
		if typ == "MX" {
			rec["pref"] = num("priority")
		} else {
			rec["priority"] = num("priority")
		}
		rec["weight"], rec["port"] = num("weight"), num("port")
		if t := num("ttl"); t > 0 {
			rec["ttl"] = t
		}
		out, errText := dsWrite(cfg, "/api/v1/dnsstore/commit", map[string]any{"author": dsActor(r), "ops": []any{map[string]any{"op": "put", "kind": "record", "record": rec}}})
		if errText != "" {
			dsRedirect(w, r, "", errText)
			return
		}
		dsRedirect(w, r, dsDone(cfg, r, "dnsstore.record.add", "added "+typ+" record "+owner, out), "")
	}
}

func handleDNSStoreDelete(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		kind, id := r.FormValue("kind"), strings.TrimSpace(r.FormValue("id"))
		if kind != "host" && kind != "record" || len(id) != 32 {
			dsRedirect(w, r, "", "nothing to delete")
			return
		}
		out, errText := dsWrite(cfg, "/api/v1/dnsstore/commit", map[string]any{"author": dsActor(r), "ops": []any{map[string]any{"op": "del", "kind": kind, "id": id}}})
		if errText != "" {
			dsRedirect(w, r, "", errText)
			return
		}
		dsRedirect(w, r, dsDone(cfg, r, "dnsstore."+kind+".delete", "deleted a "+kind, out), "")
	}
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

func handleDNSStoreVIP(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		vip := strings.TrimSpace(r.FormValue("vip"))
		if r.FormValue("remove") != "" {
			vip = ""
		}
		id, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("vrrp_id")))
		if _, errText := dsWrite(cfg, "/api/v1/dnsstore/settings", map[string]any{"dns_vip": vip, "vrrp_id": id, "author": dsActor(r)}); errText != "" {
			dsRedirect(w, r, "", errText)
			return
		}
		msg := "The DNS VIP is removed."
		if vip != "" {
			msg = "The DNS VIP " + vip + " is set; the cores apply it to their keepalived and relay within seconds."
		}
		auditAll(cfg, dsActor(r), "dnsstore.dnsvip", msg)
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
	Types       []string
	DomainNames []string
}

var dsRecordTypes = []string{"A", "AAAA", "CNAME", "TXT", "SRV", "MX", "PTR", "CAA", "NAPTR"}

func handleDNSStore(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		nodes := nodesIncludingSelf(cfg)
		states := dsFetchStatuses(nodes)
		ordered := dsOrder(states)
		data := dsPage{Msg: r.URL.Query().Get("msg"), Err: r.URL.Query().Get("err"), Tabs: template.HTML(dnsTabs("/dns/store")), Types: dsRecordTypes, Kind: "hosts"}
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
		if cluster, _, err := firstReachableConfig(nodes); err == nil {
			for _, d := range cluster.LocalDomains {
				data.DomainNames = append(data.DomainNames, d.Name)
			}
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
<p class="dim" title="Overlay keeps dnsmasq answering everything the store does not hold; the cutover makes the store answer for its whole domains and needs the records imported first.">Mode: <b>{{.Mode}}</b>{{if .Leader}} · leader: <b>{{.Leader}}</b>{{end}} · revision {{.Status.Rev}}{{with .Status.Published}} · table {{.Names}} names, {{.Records}} records{{end}}</p>
<p class="dim" title="An extra address on the management network that answers DNS and follows the health of the DNS table, not the cluster's quorum, so DNS keeps being answered while DHCP waits for a majority. It needs the management VIP.">DNS VIP: {{if .Status.DNSVIP}}<b>{{.Status.DNSVIP}}</b> (VRRP id {{.Status.VRRPID}}) · this core {{if .Status.Serving}}serves{{else}}<span class="warn">cannot serve</span>{{end}}{{else}}not set{{end}}
<form method="post" action="/dns/store/vip" style="display:inline;margin-left:.6rem"><input type="hidden" name="kind" value="{{.Kind}}"><input name="vip" placeholder="address/prefix" size="18" aria-label="DNS VIP address"{{if .Status.DNSVIP}} value="{{.Status.DNSVIP}}"{{end}}><input name="vrrp_id" placeholder="VRRP id" size="6" aria-label="VRRP id"{{if .Status.VRRPID}} value="{{.Status.VRRPID}}"{{end}}><button class="btn quiet sm">Set</button>{{if .Status.DNSVIP}} <button class="btn quiet sm" name="remove" value="1" onclick="return confirm('Remove the DNS VIP?')">Remove</button>{{end}}</form></p>
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
<details style="margin:.4rem 0 .8rem"><summary class="dim" style="cursor:pointer">Add a host or a record</summary>
<form method="post" action="/dns/store/host" class="listbar" style="margin:.5rem 0"><input type="hidden" name="kind" value="hosts">
<input name="label" placeholder="host name" size="16" required aria-label="Host name">
<input name="domains" list="dsdomains" placeholder="domain(s), comma separated" size="26" required aria-label="Domains">
<input name="addrs" placeholder="address(es)" size="24" aria-label="Addresses">
<input name="ttl" placeholder="TTL" size="6" aria-label="TTL">
<label title="Publish a reverse record for each address"><input type="checkbox" name="ptr" value="1" checked> PTR</label>
<button class="btn-primary" type="submit">+ Add host</button></form>
<form method="post" action="/dns/store/record" class="listbar" style="margin:.5rem 0"><input type="hidden" name="kind" value="records">
<select name="type" class="js-combo" aria-label="Type">{{range .Types}}<option>{{.}}</option>{{end}}</select>
<input name="owner" placeholder="full name, e.g. _sip._tcp.example.lan" size="30" required aria-label="Owner name">
<input name="value" placeholder="value" size="22" aria-label="Value">
<input name="target" placeholder="target host (MX, SRV)" size="22" aria-label="Target">
<input name="priority" placeholder="priority" size="6" aria-label="Priority">
<input name="weight" placeholder="weight" size="6" aria-label="Weight"><input name="port" placeholder="port" size="6" aria-label="Port">
<input name="ttl" placeholder="TTL" size="6" aria-label="TTL">
<button class="btn-primary" type="submit">+ Add record</button></form>
<datalist id="dsdomains">{{range .DomainNames}}<option value="{{.}}">{{end}}</datalist>
</details>
{{template "pagerbar" .PagerTop}}
<div class="table-wrap">
{{if eq .Kind "hosts"}}
<table class="list-table" border="1" cellpadding="4" cellspacing="0" style="min-width:48rem">
<colgroup><col style="width:20%"><col style="width:26%"><col style="width:36%"><col style="width:10%"><col style="width:8%"></colgroup>
<tr><th>Name</th><th>Domains</th><th>Addresses</th><th>TTL</th><th></th></tr>
{{range .Hosts}}<tr>
<td style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{{.Label}}">{{.Label}}</td>
<td style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{{.Domains}}">{{.Domains}}</td>
<td style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-variant-numeric:tabular-nums" title="{{.Addrs}}">{{.Addrs}}</td>
<td style="font-variant-numeric:tabular-nums">{{if .TTL}}{{.TTL}}{{else}}<span class="dim">default</span>{{end}}</td>
<td style="width:3rem;text-align:center"><details class="row-menu"><summary aria-haspopup="menu" title="actions for {{.Label}}">&#9776;</summary><div class="row-menu-list" role="menu">
<form method="post" action="/dns/store/delete" onsubmit="return confirm('Delete the host {{.Label}}? Its names stop answering.')"><input type="hidden" name="kind" value="host"><input type="hidden" name="id" value="{{.ID}}"><button type="submit" role="menuitem" class="danger" title="Delete this host; it is committed at once">Delete…</button></form>
</div></details></td>
</tr>{{end}}
</table>
{{else}}
<table class="list-table" border="1" cellpadding="4" cellspacing="0" style="min-width:48rem">
<colgroup><col style="width:30%"><col style="width:8%"><col style="width:42%"><col style="width:10%"><col style="width:8%"></colgroup>
<tr><th>Owner</th><th>Type</th><th>Data</th><th>TTL</th><th></th></tr>
{{range .Records}}<tr>
<td style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{{.Owner}}">{{.Owner}}</td>
<td>{{.Type}}</td>
<td style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{{.Data}}">{{.Data}}</td>
<td style="font-variant-numeric:tabular-nums">{{if .TTL}}{{.TTL}}{{else}}<span class="dim">default</span>{{end}}</td>
<td style="width:3rem;text-align:center"><details class="row-menu"><summary aria-haspopup="menu" title="actions for {{.Owner}}">&#9776;</summary><div class="row-menu-list" role="menu">
<form method="post" action="/dns/store/delete" onsubmit="return confirm('Delete this {{.Type}} record of {{.Owner}}?')"><input type="hidden" name="kind" value="record"><input type="hidden" name="id" value="{{.ID}}"><button type="submit" role="menuitem" class="danger" title="Delete this record; it is committed at once">Delete…</button></form>
</div></details></td>
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
<p class="dim"><b>Changes are committed at once</b> through the leader and copied to every core before they count; there is no pending step. <b>Overlay</b>: the store answers the names it holds and everything else still goes to dnsmasq, so nothing existing breaks. <b>Authoritative</b> is the cutover: do it after importing the configuration's records, and from then on the configuration's own DNS records cannot be changed.</p>
{{end}}
`))
