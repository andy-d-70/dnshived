// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
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
	"dnshived/internal/dhcpcentralrender"
)

const hostsDefaultLeaseTime = 12 * time.Hour

type hostRow struct {
	Scope     string
	MAC       string
	IP        string
	Name      string
	ClientID  string
	Names     string
	ResName   string
	Icon      string
	IconTitle string
	Private   bool
	Reserved  bool
	Unknown   bool
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

const hostIconUnknown = "□"

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
	return hostIconUnknown, "type not known"
}

func ouiFallback(icon, title, mac string) (string, string) {
	if icon != hostIconUnknown {
		return icon, title
	}
	if i, t, ok := ouiIcon(mac); ok {
		return i, t
	}
	return icon, title
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
		row := hostRow{Scope: scope, MAC: mac, IP: l.IP, Name: name, ClientID: res.ClientID, Names: strings.Join(res.Names, ", "), ResName: res.Hostname, Reserved: isRes, Seen: true,
			TTL: hostTTL(now, l.Expiry, l.NeverExpires), Renewed: hostRenewed(now, l.Expiry, l.NeverExpires, dur), Private: privateMAC(mac)}
		row.Icon, row.IconTitle = hostIcon(name)
		row.Icon, row.IconTitle = ouiFallback(row.Icon, row.IconTitle, mac)
		row.addr, _ = netip.ParseAddr(l.IP)
		seen[mac] = true
		out = append(out, row)
	}
	for _, r := range sc.Reservations {
		mac := strings.ToLower(r.MAC)
		if seen[mac] {
			continue
		}
		row := hostRow{Scope: scope, MAC: mac, IP: r.IP, Name: r.Hostname, ClientID: r.ClientID, Names: strings.Join(r.Names, ", "), ResName: r.Hostname, Reserved: true, TTL: "—", Renewed: "—", Private: privateMAC(mac)}
		row.Icon, row.IconTitle = hostIcon(r.Hostname)
		row.Icon, row.IconTitle = ouiFallback(row.Icon, row.IconTitle, mac)
		row.addr, _ = netip.ParseAddr(r.IP)
		out = append(out, row)
	}
	return out
}

// addUnknownStatic adds a row for every host in the neighbor table that has no lease, no reservation and is not one of the cluster's own addresses.
func addUnknownStatic(rows []hostRow, scope string, neigh []scopeNeighbor, skip map[string]bool) []hostRow {
	known := make(map[string]bool, 2*len(rows))
	for _, r := range rows {
		known[r.IP] = true
		known[r.MAC] = true
	}
	for _, n := range neigh {
		mac := strings.ToLower(n.MAC)
		if !n.Complete || mac == "" || known[n.IP] || known[mac] || skip[n.IP] {
			continue
		}
		row := hostRow{Scope: scope, MAC: mac, IP: n.IP, Unknown: true, Seen: true, TTL: "—", Renewed: "—", Private: privateMAC(mac)}
		row.Icon, row.IconTitle = hostIcon("")
		row.Icon, row.IconTitle = ouiFallback(row.Icon, row.IconTitle, mac)
		row.addr, _ = netip.ParseAddr(n.IP)
		rows = append(rows, row)
	}
	return rows
}

// skipAddresses lists the addresses on a scope's VLAN that belong to the cluster itself.
func skipAddresses(cluster config.Cluster, sc config.ScopeConfig, probeOctet string) map[string]bool {
	skip := map[string]bool{}
	for _, a := range dhcpcentralrender.ScopeNodeAddresses(cluster, sc) {
		skip[a] = true
	}
	for _, a := range []string{strings.SplitN(sc.VIP, "/", 2)[0], sc.Gateway, strings.SplitN(sc.NodeIP, "/", 2)[0]} {
		if a != "" {
			skip[a] = true
		}
	}
	if probeOctet != "" {
		skip[strings.SplitN(nodeIPFromVIPAndOctet(sc.VIP, probeOctet), "/", 2)[0]] = true
	}
	return skip
}

func filterHostRows(rows []hostRow, q, show string) []hostRow {
	if q == "" && show == "" {
		return rows
	}
	q = strings.ToLower(q)
	out := rows[:0:0]
	for _, r := range rows {
		if show == "dynamic" && (r.Reserved || r.Unknown) || show == "reserved" && !r.Reserved || show == "static" && !r.Unknown {
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

func fetchHostRows(scopes []scopeRow, cluster config.Cluster, nodes []NodeConfig, probeOctet string, now time.Time) []hostRow {
	cfgScopes := cluster.Scopes
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
			if neigh, err := fetchNeighbors(node, name); err == nil {
				rows = addUnknownStatic(rows, name, neigh, skipAddresses(cluster, sc, probeOctet))
			}
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
		cluster, _, cerr := firstReachableConfig(nodes)
		cfgScopes := map[string]config.ScopeConfig{}
		if cerr == nil {
			cfgScopes = cluster.Scopes
		}
		probeOctet := ""
		if len(cfg.ProbeHosts) > 0 {
			probeOctet = nodeAddrLastOctet(cfg.ProbeHosts[0].Addr)
		}
		scopes := buildScopeRows(rows, cfgScopes, tokens, roleByNodeID(rows), iotScopeSet(rows), map[string]bool{})
		all := fetchHostRows(scopes, cluster, nodes, probeOctet, time.Now())
		sortHostRows(all)

		q := listQuery(r.URL.Query())
		show := listShow(r.URL.Query().Get("show"), "dynamic", "reserved", "static")
		var nRes, nUnknown int
		for _, h := range all {
			if h.Reserved {
				nRes++
			}
			if h.Unknown {
				nUnknown++
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
		chips := listChips("/hosts", "", keep, show, []chipDef{{"", "All", len(all)}, {"dynamic", "Dynamic", len(all) - nRes - nUnknown}, {"reserved", "Reserved", nRes}, {"static", "Unknown static", nUnknown}})
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
<a class="lbtn" href="/simulator" title="Work out what a client would get in a scope, without sending anything">Client simulator</a>
<button type="button" class="btn quiet sm" id="check-all" title="Ask the serving nodes which of the hosts on this page answer ARP right now">Check shown</button>
</div>
` + pagerBarDefineHTML + `
{{template "pagerbar" .PagerTop}}
<div class="table-wrap">
<table class="list-table" border="1" cellpadding="4" cellspacing="0" style="min-width:56rem">
<colgroup><col style="width:12%"><col style="width:21%"><col style="width:12%"><col style="width:15%"><col style="width:9%"><col style="width:12%"><col style="width:5%"><col style="width:9%"><col style="width:5%"></colgroup>
<tr><th>Scope</th><th>Name</th><th>Address</th><th>MAC</th><th>TTL left</th><th>Last renewed</th><th>Type</th><th>Kind</th><th></th></tr>
{{range .Rows}}
<tr data-scope="{{.Scope}}" data-ip="{{.IP}}">
  <td style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis"><a href="/scopes/{{.Scope}}">{{.Scope}}</a></td>
  <td style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="{{.Name}}{{if .Names}} ({{.Names}}){{end}}">{{if .Name}}{{.Name}}{{else}}—{{end}}{{if .Names}} <span class="dim">+</span>{{end}}</td>
  <td style="font-variant-numeric:tabular-nums;white-space:nowrap">{{.IP}}<span data-alive style="display:inline-block;width:1.2em;text-align:center"></span></td>
  <td style="font-variant-numeric:tabular-nums;white-space:nowrap">{{.MAC}}{{if .Private}} <span class="dim" title="A private (randomized) MAC address: the device may use a different one on another network, so a reservation or block by this MAC can stop matching.">P</span>{{end}}</td>
  <td style="font-variant-numeric:tabular-nums;white-space:nowrap">{{.TTL}}</td>
  <td style="font-variant-numeric:tabular-nums;white-space:nowrap">{{.Renewed}}</td>
  <td style="text-align:center" title="{{.IconTitle}}">{{.Icon}}</td>
  <td>{{if .Unknown}}static?{{else if .Reserved}}reserved{{else}}dynamic{{end}}{{if and .Reserved (not .Seen)}}<span class="dim" title="reserved, not seen on the network right now"> ·</span>{{end}}</td>
  <td style="width:3rem;text-align:center">{{if or .Seen .Reserved}}<details class="row-menu"><summary aria-haspopup="menu" title="actions for {{.MAC}}">&#9776;</summary>
  <div class="row-menu-list" role="menu">
  {{if .Unknown}}<form method="post" action="/scopes/{{.Scope}}/reservations"><input type="hidden" name="mac" value="{{.MAC}}"><input type="hidden" name="ip" value="{{.IP}}"><input type="hidden" name="hostname" value=""><button type="submit" role="menuitem" title="Reserve this address for this MAC; staged as a pending change">Reserve</button></form>{{end}}
  <button type="button" role="menuitem" data-check title="Ask the serving node whether this address answers ARP right now">Check now</button>
  {{if and (not .Reserved) (not .Unknown)}}<form method="post" action="/scopes/{{.Scope}}/reservations"><input type="hidden" name="mac" value="{{.MAC}}"><input type="hidden" name="ip" value="{{.IP}}"><input type="hidden" name="hostname" value="{{.Name}}"><button type="submit" role="menuitem" title="Reserve this address for this MAC; staged as a pending change">Make static</button></form>
  <form method="post" action="/scopes/{{.Scope}}/leases/release" onsubmit="return confirm('Release lease {{.IP}} ({{.MAC}})? The client will need to request an address again.')"><input type="hidden" name="mac" value="{{.MAC}}"><input type="hidden" name="ip" value="{{.IP}}"><button type="submit" role="menuitem">Release</button></form>{{end}}
  {{if .Reserved}}<form method="post" action="/scopes/{{.Scope}}/reservations" onsubmit="var n=prompt('Host name (letters, digits, dot, hyphen, underscore; empty clears it):',this.hostname.value);if(n===null)return false;this.hostname.value=n.trim();"><input type="hidden" name="mac" value="{{.MAC}}"><input type="hidden" name="ip" value="{{.IP}}"><input type="hidden" name="hostname" value="{{.ResName}}"><button type="submit" role="menuitem" title="Change the host name of this reservation; staged as a pending change">Rename…</button></form>
  <form method="post" action="/scopes/{{.Scope}}/reservations" onsubmit="var n=prompt('DHCP client identifier (option 61) as hex bytes like 01:aa:bb:cc:dd:ee:ff; empty = match by MAC only:',this.client_id.value);if(n===null)return false;this.client_id.value=n.trim();"><input type="hidden" name="mac" value="{{.MAC}}"><input type="hidden" name="ip" value="{{.IP}}"><input type="hidden" name="hostname" value="{{.ResName}}"><input type="hidden" name="client_id" value="{{.ClientID}}"><button type="submit" role="menuitem" title="The server then answers only when the MAC and this identifier both match">Client ID…</button></form>
  <form method="post" action="/scopes/{{.Scope}}/reservations" onsubmit="var n=prompt('Extra DNS names for this address, comma separated (up to 8); empty removes them:',this.names.value);if(n===null)return false;this.names.value=n.trim();"><input type="hidden" name="mac" value="{{.MAC}}"><input type="hidden" name="ip" value="{{.IP}}"><input type="hidden" name="hostname" value="{{.ResName}}"><input type="hidden" name="names" value="{{.Names}}"><button type="submit" role="menuitem" title="More names that resolve to this address; staged as a pending change">Names…</button></form>{{end}}
  <a role="menuitem" href="/simulator?c1={{.MAC}}&amp;s1={{.Scope}}" title="What this client would get in its scope">Simulate…</a>
  <form method="get" action="/config/access/blocked"><input type="hidden" name="mac" value="{{.MAC}}"><input type="hidden" name="addr" value="{{.IP}}"><button type="submit" role="menuitem" title="Open the blocked clients page with this client filled in; nothing is blocked until you stage and commit it">Block…</button></form>
  </div></details>{{end}}</td>
</tr>
{{end}}
</table>
</div>
{{template "pagerbar" .PagerBottom}}
{{if eq .Total 0}}<p class="dim">{{if .Q}}(no host matches the search){{else}}(no hosts yet){{end}}</p>{{end}}
<p class="dim">Dynamic hosts are the active leases of every scope; reserved hosts are the reservations in the scopes' configuration. Last renewed is derived from the lease expiry and the scope's lease time.</p>
` + hostsCheckScript + rowMenuScriptHTML))

const hostsCheckScript = `<script>
(function(){
  function post(scope,ips,tries){
    return fetch('/hosts/check',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'scope='+encodeURIComponent(scope)+'&ips='+encodeURIComponent(ips.join(','))}).then(function(r){
      if(r.status===429&&tries<3){return new Promise(function(f){setTimeout(f,2200);}).then(function(){return post(scope,ips,tries+1);});}
      if(!r.ok){return r.text().then(function(t){throw new Error(t);});}
      return r.json();
    });
  }
  function show(scope,ips,res,err){
    document.querySelectorAll('tr[data-scope]').forEach(function(tr){
      if(tr.getAttribute('data-scope')!==scope||ips.indexOf(tr.getAttribute('data-ip'))<0){return;}
      var s=tr.querySelector('[data-alive]');
      if(!s){return;}
      if(err){s.textContent='?';s.title=err;return;}
      var up=res.alive.indexOf(tr.getAttribute('data-ip'))>=0;
      s.textContent=up?'\u25CF':'\u25CB';
      s.style.color=up?'var(--ok)':'var(--muted)';
      s.title=(up?'answered ARP at ':'no ARP answer at ')+res.at;
    });
  }
  function run(scope,ips){
    return post(scope,ips,0).then(function(res){show(scope,ips,res,'');},function(e){show(scope,ips,null,String(e.message||e));});
  }
  document.addEventListener('click',function(e){
    var b=e.target.closest('[data-check]');
    if(b){var tr=b.closest('tr');var d=b.closest('details');if(d){d.removeAttribute('open');}run(tr.getAttribute('data-scope'),[tr.getAttribute('data-ip')]);return;}
    if(e.target.id==='check-all'){
      var by={};
      document.querySelectorAll('tr[data-scope]').forEach(function(tr){var k=tr.getAttribute('data-scope');(by[k]=by[k]||[]).push(tr.getAttribute('data-ip'));});
      Object.keys(by).forEach(function(k){
        var ips=by[k],chain=Promise.resolve();
        for(var i=0;i<ips.length;i+=16){(function(part){chain=chain.then(function(){return run(k,part);});})(ips.slice(i,i+16));}
      });
    }
  });
})();
</script>`

// handleHostsCheck (POST /hosts/check) asks the node that serves a scope whether some of its addresses answer ARP.
func handleHostsCheck(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scope := r.FormValue("scope")
		var ips []string
		for _, s := range strings.Split(r.FormValue("ips"), ",") {
			if s = strings.TrimSpace(s); s != "" {
				ips = append(ips, s)
			}
		}
		if scope == "" || len(ips) == 0 || len(ips) > 16 {
			http.Error(w, "scope and 1 to 16 addresses are required", http.StatusBadRequest)
			return
		}
		cfg := ref.Load()
		target := findScopeTargetNode(fetchAllStatus(cfg, nodesIncludingSelf(cfg)), scope)
		if target == nil {
			http.Error(w, "no reachable node currently serves this scope", http.StatusBadGateway)
			return
		}
		got, status, err := probeNeighbors(*target, scope, ips)
		if err != nil {
			if status == 0 {
				status = http.StatusBadGateway
			}
			http.Error(w, "check: "+err.Error(), status)
			return
		}
		alive := []string{}
		for _, n := range got {
			if n.Complete {
				alive = append(alive, n.IP)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"alive": alive, "checked": ips, "at": time.Now().Format("15:04:05")})
	}
}
