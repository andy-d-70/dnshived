// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"html/template"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"dnshived/internal/config"
)

const hostsDefaultLeaseTime = 12 * time.Hour

type hostRow struct {
	Scope     string
	MAC       string
	IP        string
	Name      string
	Icon      string
	IconTitle string
	Private   bool
	Reserved  bool
	Seen      bool
	TTL       string
	Renewed   string
	addr      netip.Addr
}

func leaseDuration(s string) time.Duration {
	s = strings.TrimSpace(s)
	if s == "" {
		return hostsDefaultLeaseTime
	}
	if s == "infinite" {
		return 0
	}
	unit := time.Second
	switch s[len(s)-1] {
	case 's':
		s = s[:len(s)-1]
	case 'm':
		unit, s = time.Minute, s[:len(s)-1]
	case 'h':
		unit, s = time.Hour, s[:len(s)-1]
	case 'd':
		unit, s = 24*time.Hour, s[:len(s)-1]
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return hostsDefaultLeaseTime
	}
	return time.Duration(n) * unit
}

func spanText(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
	case d >= time.Hour:
		return fmt.Sprintf("%dh %02dm", int(d.Hours()), int(d.Minutes())%60)
	case d >= time.Minute:
		return fmt.Sprintf("%dm %02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}

func hostTTL(now, expiry time.Time, never bool) string {
	if never {
		return "static"
	}
	if !expiry.After(now) {
		return "expired"
	}
	return spanText(expiry.Sub(now))
}

func hostRenewed(now, expiry time.Time, never bool, dur time.Duration) string {
	if never || dur <= 0 {
		return "—"
	}
	ago := now.Sub(expiry.Add(-dur))
	if ago < 0 {
		ago = 0
	}
	return spanText(ago) + " ago"
}

func privateMAC(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	b, err := strconv.ParseUint(mac[:2], 16, 8)
	return err == nil && b&0x02 != 0
}

var hostIconRules = []struct {
	words []string
	icon  string
	title string
}{
	{[]string{"iphone", "ipad", "ios"}, "\U0001F4F1", "Apple phone or tablet"},
	{[]string{"android", "galaxy", "pixel"}, "\U0001F4F1", "Android phone or tablet"},
	{[]string{"macbook", "imac", "mac-", "macmini"}, "\U0001F4BB", "Apple computer"},
	{[]string{"desktop-", "laptop-", "win"}, "\U0001F5A5", "Windows computer"},
	{[]string{"printer", "epson", "canon", "brother", "hp"}, "\U0001F5A8", "Printer"},
	{[]string{"cam", "camera"}, "\U0001F4F7", "Camera"},
	{[]string{"tv", "roku", "chromecast", "appletv"}, "\U0001F4FA", "TV or streaming box"},
	{[]string{"dante", "av-", "mixer", "amp", "stage", "ndi", "nmos"}, "\U0001F50A", "Audio or video device"},
}

func hostIcon(name string) (string, string) {
	n := strings.ToLower(name)
	for _, r := range hostIconRules {
		for _, w := range r.words {
			if strings.Contains(n, w) {
				return r.icon, r.title
			}
		}
	}
	return "□", "type not known"
}

func buildHostRows(scope string, sc config.ScopeConfig, leases []dnsmasqLease, now time.Time) []hostRow {
	dur := leaseDuration(sc.DHCPLeaseTime)
	reserved := make(map[string]config.Reservation, len(sc.Reservations))
	for _, r := range sc.Reservations {
		reserved[strings.ToLower(r.MAC)] = r
	}
	seen := map[string]bool{}
	var out []hostRow
	for _, l := range leases {
		mac := strings.ToLower(l.MAC)
		res, isRes := reserved[mac]
		name := l.Hostname
		if name == "" {
			name = res.Hostname
		}
		row := hostRow{Scope: scope, MAC: mac, IP: l.IP, Name: name, Reserved: isRes, Seen: true,
			TTL: hostTTL(now, l.Expiry, l.NeverExpires), Renewed: hostRenewed(now, l.Expiry, l.NeverExpires, dur), Private: privateMAC(mac)}
		row.Icon, row.IconTitle = hostIcon(name)
		row.addr, _ = netip.ParseAddr(l.IP)
		seen[mac] = true
		out = append(out, row)
	}
	for _, r := range sc.Reservations {
		mac := strings.ToLower(r.MAC)
		if seen[mac] {
			continue
		}
		row := hostRow{Scope: scope, MAC: mac, IP: r.IP, Name: r.Hostname, Reserved: true, TTL: "—", Renewed: "—", Private: privateMAC(mac)}
		row.Icon, row.IconTitle = hostIcon(r.Hostname)
		row.addr, _ = netip.ParseAddr(r.IP)
		out = append(out, row)
	}
	return out
}

func filterHostRows(rows []hostRow, q, show string) []hostRow {
	if q == "" && show == "" {
		return rows
	}
	q = strings.ToLower(q)
	out := rows[:0:0]
	for _, r := range rows {
		if show == "dynamic" && r.Reserved || show == "reserved" && !r.Reserved {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(r.Scope+" "+r.MAC+" "+r.IP+" "+r.Name), q) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func sortHostRows(rows []hostRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Scope != rows[j].Scope {
			return rows[i].Scope < rows[j].Scope
		}
		if rows[i].addr != rows[j].addr {
			return rows[i].addr.Less(rows[j].addr)
		}
		return rows[i].MAC < rows[j].MAC
	})
}

func fetchHostRows(scopes []scopeRow, cfgScopes map[string]config.ScopeConfig, nodes []NodeConfig, now time.Time) []hostRow {
	byName := make(map[string]NodeConfig, len(nodes))
	for _, n := range nodes {
		byName[n.Name] = n
	}
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		out []hostRow
	)
	sem := make(chan struct{}, 8)
	for _, s := range scopes {
		sc, ok := cfgScopes[s.Name]
		if !ok || s.Disabled {
			continue
		}
		node, served := byName[s.Worker]
		if !served {
			rows := buildHostRows(s.Name, sc, nil, now)
			mu.Lock()
			out = append(out, rows...)
			mu.Unlock()
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(name string, sc config.ScopeConfig, node NodeConfig) {
			defer wg.Done()
			defer func() { <-sem }()
			leases, _ := fetchDnsmasqLeases(node, name)
			rows := buildHostRows(name, sc, leases, now)
			mu.Lock()
			out = append(out, rows...)
			mu.Unlock()
		}(s.Name, sc, node)
	}
	wg.Wait()
	return out
}

type hostsPageData struct {
	Rows         []hostRow
	Total        int
	Q            string
	Chips        []listChip
	FilterHidden []formField
	PagerTop     pagerBar
	PagerBottom  pagerBar
	Tabs         template.HTML
}

func handleHosts(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		nodes := nodesIncludingSelf(cfg)
		rows := fetchAllStatus(cfg, nodes)
		tokens := fetchArbiterTokens(cfg, rows)
		cfgScopes := map[string]config.ScopeConfig{}
		if c, _, err := firstReachableConfig(nodes); err == nil {
			cfgScopes = c.Scopes
		}
		scopes := buildScopeRows(rows, cfgScopes, tokens, roleByNodeID(rows), iotScopeSet(rows), map[string]bool{})
		all := fetchHostRows(scopes, cfgScopes, nodes, time.Now())
		sortHostRows(all)

		q := listQuery(r.URL.Query())
		show := listShow(r.URL.Query().Get("show"), "dynamic", "reserved")
		var nRes int
		for _, h := range all {
			if h.Reserved {
				nRes++
			}
		}
		per := pagerPer(r.URL.Query())
		keep := pagerKeep(url.Values{}, per)
		if q != "" {
			keep.Set("q", q)
		}
		if show != "" {
			keep.Set("show", show)
		}
		chips := listChips("/hosts", "", keep, show, []chipDef{{"", "All", len(all)}, {"dynamic", "Dynamic", len(all) - nRes}, {"reserved", "Reserved", nRes}})
		list := filterHostRows(all, q, show)

		size := pagerSize(per, len(list))
		pages := (len(list) + size - 1) / size
		if pages == 0 {
			pages = 1
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		page = min(max(page, 1), pages)
		start, end := (page-1)*size, min(page*size, len(list))
		top, bottom := newPagerBars("/hosts", keep, per, len(list), page, pages, start, end)
		renderTemplate(w, hostsTmpl, hostsPageData{
			Rows: list[start:end], Total: len(list), Q: q, Chips: chips,
			FilterHidden: hiddenFields(keep, "per", "show"), PagerTop: top, PagerBottom: bottom,
			Tabs: template.HTML(tabLinksHTML([][2]string{{"/hosts", "Hosts"}, {"/config/dhcp", "Default options &amp; sets"}}, "/hosts")),
		}, "hosts")
	}
}

var hostsTmpl = template.Must(template.New("hosts").Parse(`<!doctype html>
<title>dnshived-web — hosts</title>
` + styleHTML + `
` + navHTML + `
<div class="pagehead"><h1>DHCP</h1></div>
{{.Tabs}}
<div class="listbar">
<form method="get" action="/hosts">{{range .FilterHidden}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">{{end}}<input type="search" name="q" value="{{.Q}}" placeholder="Search anything: name, MAC, address, scope…" aria-label="Search hosts"></form>
{{range .Chips}}<a class="lchip{{if .Active}} sel{{end}}" href="{{.URL}}">{{.Label}}</a>{{end}}
<span class="grow"></span>
</div>
` + pagerBarDefineHTML + `
{{template "pagerbar" .PagerTop}}
<div class="table-wrap">
<table class="list-table" border="1" cellpadding="4" cellspacing="0" style="min-width:56rem">
<colgroup><col style="width:12%"><col style="width:21%"><col style="width:12%"><col style="width:15%"><col style="width:9%"><col style="width:12%"><col style="width:5%"><col style="width:9%"><col style="width:5%"></colgroup>
<tr><th>Scope</th><th>Name</th><th>Address</th><th>MAC</th><th>TTL left</th><th>Last renewed</th><th>Type</th><th>Kind</th><th></th></tr>
{{range .Rows}}
<tr>
  <td style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis"><a href="/scopes/{{.Scope}}">{{.Scope}}</a></td>
  <td style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{{.Name}}">{{if .Name}}{{.Name}}{{else}}—{{end}}</td>
  <td style="font-variant-numeric:tabular-nums">{{.IP}}</td>
  <td style="font-variant-numeric:tabular-nums;white-space:nowrap">{{.MAC}}{{if .Private}} <span class="dim" title="A private (randomized) MAC address: the device may use a different one on another network, so a reservation or block by this MAC can stop matching.">P</span>{{end}}</td>
  <td style="font-variant-numeric:tabular-nums;white-space:nowrap">{{.TTL}}</td>
  <td style="font-variant-numeric:tabular-nums;white-space:nowrap">{{.Renewed}}</td>
  <td style="text-align:center" title="{{.IconTitle}}">{{.Icon}}</td>
  <td>{{if .Reserved}}reserved{{else}}dynamic{{end}}{{if and .Reserved (not .Seen)}}<span class="dim" title="reserved, not seen on the network right now"> ·</span>{{end}}</td>
  <td style="width:3rem;text-align:center">{{if .Seen}}<details class="row-menu"><summary aria-haspopup="menu" title="actions for {{.MAC}}">&#9776;</summary>
  <div class="row-menu-list" role="menu">
  {{if not .Reserved}}<form method="post" action="/scopes/{{.Scope}}/reservations"><input type="hidden" name="mac" value="{{.MAC}}"><input type="hidden" name="ip" value="{{.IP}}"><input type="hidden" name="hostname" value="{{.Name}}"><button type="submit" role="menuitem" title="Reserve this address for this MAC; staged as a pending change">Make static</button></form>
  <form method="post" action="/scopes/{{.Scope}}/leases/release" onsubmit="return confirm('Release lease {{.IP}} ({{.MAC}})? The client will need to request an address again.')"><input type="hidden" name="mac" value="{{.MAC}}"><input type="hidden" name="ip" value="{{.IP}}"><button type="submit" role="menuitem">Release</button></form>{{end}}
  <form method="get" action="/config/access/blocked"><input type="hidden" name="mac" value="{{.MAC}}"><input type="hidden" name="addr" value="{{.IP}}"><button type="submit" role="menuitem" title="Open the blocked clients page with this client filled in; nothing is blocked until you stage and commit it">Block…</button></form>
  </div></details>{{end}}</td>
</tr>
{{end}}
</table>
</div>
{{template "pagerbar" .PagerBottom}}
{{if eq .Total 0}}<p class="dim">{{if .Q}}(no host matches the search){{else}}(no hosts yet){{end}}</p>{{end}}
<p class="dim">Dynamic hosts are the active leases of every scope; reserved hosts are the reservations in the scopes' configuration. Last renewed is derived from the lease expiry and the scope's lease time.</p>
` + rowMenuScriptHTML))
