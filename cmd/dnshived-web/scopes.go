// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"dnshived/internal/config"
	"dnshived/internal/dhcpcentralrender"
	"dnshived/internal/dhcplease"
	"dnshived/internal/dnscentralrender"
	"dnshived/internal/ifname"
)

// scopesPerPage matches dnshived-top's own pagination size (15/page).
const scopesPerPage = 15

// scopeRow is one (scope, worker) pairing.
type scopeRow struct {
	// Name is the bare scope name, used for the /scopes/<name> link — must
	// never carry the "[IoT]" tag, or the link breaks.
	Name string
	// Display is what's actually shown in the table cell — Name, or Name+"
	// [IoT]" when flagged (see scopeDisplayName).
	Display string
	Worker  string
	// WorkerClass is the same worker-identity color topology.go's own
	// roleClass() uses everywhere else.
	WorkerClass string
	Token       string
	Status      string
	Class       string
	StatusTitle string
	// Color is this scope's own color tag (config.ScopeConfig.Color), looked
	// up by name from a fetched config.Cluster.Scopes.
	Color     string
	Interface string
	// ParentInterface is the trunk NIC name alone (e.g. "ens19"), without the
	// ".vlan_id" suffix Interface itself carries.
	ParentInterface string
	VLANID          int
	Subnet          string
	ProbeCells      []probeCellData
	// PoolSize/PoolUsed/PoolUsagePct back the Scopes overview's own DHCP pool
	// usage column.
	PoolSize, PoolUsed, PoolUsagePct int
	// PoolClass mirrors the .ok/.warn/.crit convention used everywhere else on
	// this page (see Class above).
	PoolClass string
	// PendingDelete is true when a staged (not yet committed) candidate exists
	// and no longer contains this scope.
	PendingDelete bool
	// Disabled mirrors config.ScopeConfig.DNSMasqDisabled.
	Disabled bool
}

func poolUsageClass(pct int) string {
	switch {
	case pct >= 90:
		return "crit"
	case pct >= 75:
		return "warn"
	default:
		return "ok"
	}
}

var scopesTmpl = template.Must(template.New("scopes").Parse(`<!doctype html>
<title>dnshived-web — scopes</title>
` + styleHTML + `
<h1>Scopes</h1>
` + navHTML + `
<div class="view-tabs"><span class="active">List view</span><a href="/topology">Topology view &rarr;</a></div>
<p><a href="/scopes/wizard">+ Add scope (guided wizard)</a></p>
{{if gt .Total 0}}<form method="post" action="/scopes/rebalance-all" style="display:inline" onsubmit="return confirm('Approve a rebalance to each scope\'s own preferred core, cluster-wide? This stages the approval as a pending change on every configured node — nothing moves until you commit from Pending changes, and each scope only actually moves once its own preferred core is confirmed alive and stable. Continue?')" title="a scope never moves back to its preferred core automatically while a different node is already serving it correctly — this explicitly approves doing so now, for every scope at once">
<button type="submit">Rebalance all scopes to their preferred core</button>
</form>{{end}}
<p>{{.Total}} configured scope(s) — page {{.Page}}/{{.TotalPages}}
{{if gt .Page 1}}<a href="/scopes?page={{.PrevPage}}">prev</a>{{else}}<span class="dim">prev</span>{{end}}
{{if lt .Page .TotalPages}}<a href="/scopes?page={{.NextPage}}">next</a>{{end}}
— <a href="/config/scopes#new-scope-slot">add via the bulk editor</a>
</p>
` + probeCellDefineHTML + `
<div class="table-wrap">
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>Scope</th><th>Worker</th><th title="the VLAN sub-interface actually constructed on the serving worker's trunk NIC — parent.vlan_id">Interface</th><th>VLAN</th><th>Subnet</th><th>Token Owner</th><th>Status</th><th title="DHCP pool usage — leased addresses out of the scope's own dhcp_range size">Pool</th>{{if .HasProbeHosts}}<th>Probe</th>{{end}}<th></th></tr>
{{range .Rows}}
<tr>
  <td>{{if .Color}}<span class="name-dot" style="background:{{.Color}}" title="color tag — change on the scope's own edit page"></span>{{end}}<a href="/scopes/{{.Name}}">{{.Display}}</a>{{if .PendingDelete}} <span class="crit" title="a pending change stages this scope's removal — still live and served until you commit from Pending changes">marked for deletion</span>{{end}}</td>
  <td class="{{.WorkerClass}}">{{.Worker}}</td>
  <td title="{{.Worker}}'s trunk NIC ({{.ParentInterface}}), VLAN-tagged for this scope">{{.Interface}}</td>
  <td>{{.VLANID}}</td>
  <td>{{.Subnet}}</td>
  <td>{{.Token}}</td>
  <td class="{{.Class}}"{{if .StatusTitle}} title="{{.StatusTitle}}"{{end}}>{{.Status}}</td>
  <td style="white-space:nowrap">{{if gt .PoolSize 0}}<span class="pool-bar"><span class="pool-fill {{.PoolClass}}" style="width:{{.PoolUsagePct}}%"></span></span><span class="{{.PoolClass}}">{{.PoolUsed}} of {{.PoolSize}} used</span>{{else}}<span class="dim">—</span>{{end}}</td>
  {{if $.HasProbeHosts}}<td style="white-space:nowrap">{{range .ProbeCells}}{{template "probecell" .}}<br>{{end}}</td>{{end}}
  <td>
  <form method="post" action="/scopes/{{.Name}}/toggle-disabled" style="display:inline" onsubmit="return confirm('This will stage a pending change on every configured node ({{if .Disabled}}enable{{else}}disable{{end}} scope {{.Name}}) — nothing is applied until you commit from Pending changes. {{if not .Disabled}}DHCP, DNS and probing stop for this scope; the VLAN interface and VIP/VRRP stay up.{{end}} Continue?')"><button type="submit" class="{{if .Disabled}}btn-success{{else}}btn-warn{{end}}">{{if .Disabled}}enable{{else}}disable{{end}}</button></form>
  <form method="post" action="/scopes/{{.Name}}/delete" style="display:inline" onsubmit="return confirm('Really delete scope {{.Name}}? This stages its removal as a pending change on every configured node — nothing is torn down until you commit from Pending changes. Continue?')"><button type="submit" class="btn-danger">delete</button></form>
  </td>
</tr>
{{end}}
</table>
</div>
{{if eq .Total 0}}<p class="dim">(no scopes configured)</p>{{end}}
<p class="dim">Interface is the VLAN sub-interface this scope is actually constructed
on, on the Worker column's node — parent trunk NIC + VLAN ID
(<code>parent.vlan_id</code>), the same naming the daemon itself uses.
Subnet is the scope's network address/prefix, not its VIP address.</p>
`))

type scopesPageData struct {
	Rows       []scopeRow
	Total      int
	Page       int
	TotalPages int
	PrevPage   int
	NextPage   int
	// HasProbeHosts gates the Probe column entirely.
	HasProbeHosts bool
}

// buildScopeRows builds the Scopes page's row set — extracted as a pure
// function so this logic is directly unit-testable without a full
// multi-node HTTP fetch.
func buildScopeRows(rows []statusRow, configScopes map[string]config.ScopeConfig, tokens map[string]tokenInfo, roles map[string]string, iotSet map[string]bool, pendingDeletes map[string]bool) []scopeRow {
	servedBy := make(map[string]statusRow)
	for _, row := range rows {
		if row.FetchError != "" || !isCoreRole(row.Status.Role) {
			continue
		}
		for _, sc := range row.Status.Serving {
			servedBy[sc] = row
		}
	}

	var scopes []scopeRow
	for name, cfgSc := range configScopes {
		row := scopeRow{Name: name, Display: scopeDisplayName(name, iotSet[name])}
		row.PendingDelete = pendingDeletes[name]
		row.Color = cfgSc.Color
		row.Disabled = cfgSc.DNSMasqDisabled
		row.Interface = ifname.InterfaceName(cfgSc.Parent, cfgSc.VLANID)
		row.ParentInterface = cfgSc.Parent
		row.VLANID = cfgSc.VLANID
		row.Subnet = scopeSubnetCIDR(cfgSc.VIP)
		if size, err := dhcplease.PoolSize(cfgSc.DHCPRange[0], cfgSc.DHCPRange[1]); err == nil {
			row.PoolSize = size
		}

		if servingRow, ok := servedBy[name]; ok {
			tok, class, status := "—", "ok", "active"
			if t, ok := tokens[name]; ok {
				tok = t.Owner
				if role, ok := roles[t.Owner]; ok {
					tok = role
				}
				if t.Expired {
					class, status = "crit", "EXPIRED"
				}
			}
			row.Worker, row.WorkerClass = servingRow.Status.Role, roleClass(servingRow.Status.Role)
			row.Token, row.Status, row.Class = tok, status, class
		} else {
			row.Worker, row.WorkerClass = "—", "dim"
			row.Token, row.Status, row.Class = "—", "not served", "dim"
		}
		if row.Disabled {
			row.Status, row.Class = "disabled", "warn"
			row.StatusTitle = "this scope is disabled: DHCP and DNS stopped, probing off; VLAN interface and VIP/VRRP stay up — enable to serve again"
		}
		scopes = append(scopes, row)
	}
	sort.Slice(scopes, func(i, j int) bool { return scopes[i].Name < scopes[j].Name })
	return scopes
}

func handleScopes(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		nodes := nodesIncludingSelf(cfg)
		rows := fetchAllStatus(cfg, nodes)
		tokens := fetchArbiterTokens(cfg, rows)
		iotSet := iotScopeSet(rows)
		roles := roleByNodeID(rows)

		configScopes := map[string]config.ScopeConfig{}
		if c, _, err := firstReachableConfig(nodesIncludingSelf(cfg)); err == nil {
			configScopes = c.Scopes
		}

		pendingDeletes := map[string]bool{}
		if cand, exists, _, err := firstReachableCandidate(nodesIncludingSelf(cfg)); err == nil && exists {
			for name := range configScopes {
				if _, stillPresent := cand.Scopes[name]; !stillPresent {
					pendingDeletes[name] = true
				}
			}
		}

		scopes := buildScopeRows(rows, configScopes, tokens, roles, iotSet, pendingDeletes)
		populateScopePoolUsage(scopes, nodes)

		if len(cfg.ProbeHosts) > 0 {
			populateScopeProbeCells(scopes, cfg, tokens)
		}

		totalPages := (len(scopes) + scopesPerPage - 1) / scopesPerPage
		if totalPages == 0 {
			totalPages = 1
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 {
			page = 1
		}
		if page > totalPages {
			page = totalPages
		}
		start := (page - 1) * scopesPerPage
		end := start + scopesPerPage
		if end > len(scopes) {
			end = len(scopes)
		}

		data := scopesPageData{
			Rows:          scopes[start:end],
			Total:         len(scopes),
			Page:          page,
			TotalPages:    totalPages,
			PrevPage:      page - 1,
			NextPage:      page + 1,
			HasProbeHosts: len(cfg.ProbeHosts) > 0,
		}
		renderTemplate(w, scopesTmpl, data, "scopes")
	}
}

// scopeSubnetCIDR returns the network CIDR for a scope's VIP.
func scopeSubnetCIDR(vip string) string {
	_, ipnet, err := net.ParseCIDR(vip)
	if err != nil {
		return vip
	}
	return ipnet.String()
}

// populateScopePoolUsage fills in each row's PoolUsed/PoolUsagePct in
// place.
func populateScopePoolUsage(scopes []scopeRow, nodes []NodeConfig) {
	type job struct {
		idx  int
		node NodeConfig
	}
	byName := make(map[string]NodeConfig, len(nodes))
	for _, n := range nodes {
		byName[n.Name] = n
	}
	var jobs []job
	for i := range scopes {
		if n, ok := byName[scopes[i].Worker]; ok {
			jobs = append(jobs, job{idx: i, node: n})
		}
	}
	if len(jobs) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			leases, err := fetchDnsmasqLeases(j.node, scopes[j.idx].Name)
			if err != nil {
				return
			}
			scopes[j.idx].PoolUsed = len(leases)
			if scopes[j.idx].PoolSize > 0 {
				scopes[j.idx].PoolUsagePct = scopes[j.idx].PoolUsed * 100 / scopes[j.idx].PoolSize
				scopes[j.idx].PoolClass = poolUsageClass(scopes[j.idx].PoolUsagePct)
			}
		}(j)
	}
	wg.Wait()
}

// populateScopeProbeCells fills in each row's ProbeCells in place.
func populateScopeProbeCells(scopes []scopeRow, cfg *WebConfig, tokens map[string]tokenInfo) {
	type job struct {
		idx  int
		node NodeConfig
	}
	var jobs []job
	for i := range scopes {
		for _, h := range cfg.ProbeHosts {
			jobs = append(jobs, job{idx: i, node: h})
		}
	}
	if len(jobs) == 0 {
		return
	}

	ownerUptime := ownerDaemonUptime(cfg)
	now := time.Now()

	results := make([]probeFetch, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func(i int, j job) {
			defer wg.Done()
			pr, err := fetchProbe(j.node, scopes[j.idx].Name)
			results[i] = probeFetch{scope: scopes[j.idx].Name, worker: j.node.Name, pr: pr, err: err}
		}(i, j)
	}
	wg.Wait()

	for i, j := range jobs {
		res := results[i]
		var stale bool
		if tok, ok := tokens[res.scope]; ok {
			uptimeSec, hasUptime := ownerUptime[tok.Owner]
			probedAt, _ := time.Parse(time.RFC3339, res.pr.ProbedAt)
			stale = probeStale(probedAt, uptimeSec, hasUptime, now)
		}
		if scopes[j.idx].Disabled {
			scopes[j.idx].ProbeCells = append(scopes[j.idx].ProbeCells, scopeDisabledCell(res.scope, j.node.Name))
			continue
		}
		dnsText, dnsClass, dhcpText, dhcpClass, note := probeCellDisplay(now, res.pr, res.err, true, cachedMismatch(res.scope, j.node.Name), stale)
		scopes[j.idx].ProbeCells = append(scopes[j.idx].ProbeCells, probeCellData{
			Scope: res.scope, Worker: j.node.Name,
			DNSText: dnsText, DNSClass: dnsClass, DHCPText: dhcpText, DHCPClass: dhcpClass, Note: note,
		})
	}
}

// freeVLANIDsForEdit mirrors scope_wizard.go's freeVLANIDs/usedVLANIDsSet
// exactly, but for editing an EXISTING scope in place.
func freeVLANIDsForEdit(scopes map[string]config.ScopeConfig, self string) []string {
	selfVLANID := scopes[self].VLANID
	selfParent := scopes[self].Parent
	used := make(map[int]bool, len(scopes))
	for name, sc := range scopes {
		if name == self || sc.Parent != selfParent {
			continue
		}
		used[sc.VLANID] = true
	}
	free := freeVLANIDs(used)
	if selfVLANID == 1 {
		free = append([]string{"1"}, free...)
	}
	return free
}

// otherScopeSubnetsAttr renders every OTHER scope's own vip CIDR as a
// compact "name|cidr,name|cidr" data-attribute value.
func otherScopeSubnetsAttr(scopes map[string]config.ScopeConfig, exclude string) string {
	names := make([]string, 0, len(scopes))
	for name := range scopes {
		if name == exclude {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	var parts []string
	for _, name := range names {
		vip := scopes[name].VIP
		if vip == "" {
			continue
		}
		parts = append(parts, name+"|"+vip)
	}
	return strings.Join(parts, ",")
}

// subnetOverlapScriptHTML backs the vip field's live "subnet already in
// use" check.
const subnetOverlapScriptHTML = `<script>
function ipToInt(ip){
  var p = ip.split('.');
  if(p.length!==4) return null;
  var out = 0;
  for(var i=0;i<4;i++){
    var n = Number(p[i]);
    if(isNaN(n) || n<0 || n>255) return null;
    out = out*256 + n;
  }
  return out;
}
function networkBase(ipInt, prefix){
  if(prefix<0 || prefix>32) return null;
  var hostBits = 32-prefix;
  var divisor = Math.pow(2, hostBits);
  return Math.floor(ipInt/divisor)*divisor;
}
function subnetsOverlapJS(aIp, aPrefix, bIp, bPrefix){
  var minPrefix = Math.min(aPrefix, bPrefix);
  var aBase = networkBase(aIp, minPrefix), bBase = networkBase(bIp, minPrefix);
  return aBase !== null && aBase === bBase;
}
function checkVIPSubnetOverlap(input){
  var msgEl = document.getElementById(input.getAttribute('data-msg-id'));
  if(!msgEl) return;
  msgEl.textContent = '';
  var m = input.value.trim().match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/);
  if(!m) return;
  var ipInt = ipToInt(m[1]);
  var prefix = parseInt(m[2], 10);
  if(ipInt===null) return;
  var raw = input.getAttribute('data-other-subnets');
  if(!raw) return;
  var items = raw.split(',');
  for(var i=0;i<items.length;i++){
    var parts = items[i].split('|');
    if(parts.length!==2) continue;
    var cm = parts[1].match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/);
    if(!cm) continue;
    var oIp = ipToInt(cm[1]), oPrefix = parseInt(cm[2], 10);
    if(oIp===null) continue;
    if(subnetsOverlapJS(ipInt, prefix, oIp, oPrefix)){
      msgEl.textContent = 'subnet already in use in scope ' + parts[0];
      return;
    }
  }
}
</script>`

const scopeColorPickerStyleHTML = `<style>
.swatch{display:inline-block;width:.85rem;height:.85rem;border-radius:3px;margin:1px;
cursor:pointer;border:1px solid rgba(0,0,0,.25);vertical-align:middle}
</style>`

const scopeColorPickerScriptHTML = `<script>
function setColor(inputId, hex){
  document.getElementById(inputId).value = hex;
}
</script>`

const scopeTitleStyleHTML = `<style>
.scope-title{position:sticky;top:var(--nav-h);z-index:15;background:var(--bg);
padding:.3rem 0}
#scope-edit-form input.field-invalid{outline:2px solid var(--crit)}
</style>`

const scopeEditAutoFillScriptHTML = `<script>
function autoScopeVIP(vipInput){
  var suffix = vipInput.getAttribute('data-vip-suffix');
  if(!suffix) return;
  var m = vipInput.value.trim().match(/^(\d{1,3}\.\d{1,3}\.\d{1,3})\.0\/(\d{1,2})$/);
  if(!m) return;
  vipInput.value = m[1] + '.' + suffix + '/' + m[2];
}
function scopeFillFromSuffix(vipInput, targetId, suffix){
  var el = document.getElementById(targetId);
  if(!el || !suffix || el.value.trim() !== '') return;
  var m = vipInput.value.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}/);
  if(!m) return;
  el.value = m[1] + '.' + suffix;
}
function autoScopeGateway(vipInput){
  scopeFillFromSuffix(vipInput, 'edit_gateway', vipInput.getAttribute('data-gw-suffix'));
}
function autoScopeDHCPRange(vipInput){
  scopeFillFromSuffix(vipInput, 'edit_dhcp_start', vipInput.getAttribute('data-dhcp-start-suffix'));
  scopeFillFromSuffix(vipInput, 'edit_dhcp_end', vipInput.getAttribute('data-dhcp-end-suffix'));
}
document.addEventListener('DOMContentLoaded', function(){
  document.querySelectorAll('#scope-edit-form input[pattern]').forEach(function(el){
    el.addEventListener('input', function(){
      el.classList.toggle('field-invalid', el.value !== '' && !el.checkValidity());
    });
  });
});
</script>`

var scopeDetailTmpl = template.Must(template.New("scope-detail").Parse(`<!doctype html>
<title>dnshived-web — scope {{.Scope}}</title>
` + styleHTML + scopeColorPickerStyleHTML + scopeTitleStyleHTML + subnetOverlapScriptHTML + scopeEditAutoFillScriptHTML + navHTML + `
<h1 class="scope-title">Scope: {{.Scope}}</h1>
` + pendingBannerHTML + `
<p><a href="/scopes">&larr; back to scopes</a></p>
{{if .NotFound}}
<p class="crit">No reachable node knows this scope.</p>
{{else if .FetchError}}
<p class="crit">Cannot fetch authority: {{.FetchError}}</p>
{{else}}
<p><strong class="{{.ServingClass}}">{{.ServingText}}</strong> — queried from <strong>{{.TargetNode}}</strong> (every "this node" below refers to it)</p>
<h2>Configuration{{if .Pending}} <span class="warn">(pending — not yet committed)</span>{{end}}</h2>
{{if .ConfigOK}}
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>VIP</th><td>{{.VIP}}</td></tr>
<tr><th>Gateway</th><td>{{.Gateway}}</td></tr>
<tr><th>DHCP pool</th><td>{{.DHCPStart}} &ndash; {{.DHCPEnd}}</td></tr>
<tr><th>Pool usage</th><td>{{.PoolUsed}} / {{.PoolSize}} ({{.PoolUsagePct}}%)</td></tr>
{{if .EditScope.DNSMasqDisabled}}<tr><th>Status</th><td class="warn">DISABLED — DHCP and DNS stopped for this scope (not relayed on any node), probing off; VLAN interface and VIP/VRRP stay up</td></tr>{{end}}
</table>
{{else}}
<p class="crit">Cannot fetch scope config{{if .ConfigError}}: {{.ConfigError}}{{end}}</p>
{{end}}
{{if .ConfigOK}}
<h3>Edit</h3>
<form id="scope-edit-form" method="post" action="/scopes/{{.Scope}}/config" onsubmit="return confirm('This will stage this scope\'s settings as a pending change on every configured node — nothing is applied until you commit from Pending changes. Continue?')">
<table border="1" cellpadding="4" cellspacing="0">
<tr><td>name<br><small class="dim">renaming tears down and rebuilds this scope's own interface/dnsmasq unit on commit (same cost as any other scope add/remove) — the VIP/DHCP pool themselves are untouched</small></td><td><input name="new_name" value="{{.Scope}}"></td></tr>
<tr><td>parent</td><td>
  <select name="parent">
    {{$cur := .EditScope.Parent}}
    {{range .PlatformWorkers}}
    <option value="{{.}}" {{if eq . $cur}}selected{{end}}>{{.}}</option>
    {{end}}
  </select>
</td></tr>
<tr><td>vlan_id<br><small class="dim">only IDs not already used by another scope are offered — this scope's own current ID always stays selectable. Type to search. "0 — untagged" serves directly on the parent interface itself, with no VLAN sub-interface.</small></td><td>
  <select name="vlan_id" class="js-combo">
    {{$curvl := printf "%d" .EditScope.VLANID}}{{range .VLANIDOptions}}<option value="{{.}}" {{if eq . $curvl}}selected{{end}}>{{if eq . "0"}}0 — untagged (bind directly to parent){{else}}{{.}}{{end}}</option>{{end}}
  </select>
</td></tr>
<tr><td>vip<br><small class="dim">typing a subnet already used by another scope is flagged live, and blocked at commit. Typing a bare network (e.g. 192.168.12.0/24) auto-fills gateway/dhcp_start/dhcp_end below from your configured <a href="/scopes/options">scope defaults</a> — only fields left empty are ever filled in, an already-set value is never overwritten.</small></td><td><input id="edit_vip" name="vip" value="{{.EditScope.VIP}}" pattern="{{.IPCIDRPattern}}" title="IPv4 with prefix, e.g. 192.168.105.2/24" data-vip-suffix="{{.VIPSuffix}}" data-gw-suffix="{{.GatewaySuffix}}" data-dhcp-start-suffix="{{.DHCPStartSuffix}}" data-dhcp-end-suffix="{{.DHCPEndSuffix}}" data-other-subnets="{{.OtherSubnetsAttr}}" data-msg-id="edit_vip_msg" oninput="autoScopeVIP(this);autoScopeGateway(this);autoScopeDHCPRange(this);checkVIPSubnetOverlap(this)"> <span id="edit_vip_msg" class="crit"></span></td></tr>
<tr><td>node_ip<br><small class="dim">each worker's own fixed address on this VLAN — required for VRRP; pre-filled from the derived/Cluster Settings default, edit if this worker needs a different one</small></td><td>
{{range .WorkerNodeIPs}}{{.Worker}}: <input name="node_ip_{{.Worker}}" value="{{.Value}}" pattern="{{$.IPCIDRPattern}}"><br>{{end}}
{{if .ProbeHostNodeIP}}<span class="dim">{{.ProbeHostName}} (probe host, informational only): {{.ProbeHostNodeIP}}</span>{{end}}
</td></tr>
<tr><td>dhcp_range start</td><td><input id="edit_dhcp_start" name="dhcp_start" value="{{index .EditScope.DHCPRange 0}}" pattern="{{.IPPattern}}" title="IPv4 address, e.g. 192.168.100.100"></td></tr>
<tr><td>dhcp_range end</td><td><input id="edit_dhcp_end" name="dhcp_end" value="{{index .EditScope.DHCPRange 1}}" pattern="{{.IPPattern}}" title="IPv4 address, e.g. 192.168.100.200"></td></tr>
<tr><td>gateway<br><small class="dim">a comma-separated list is accepted for multiple failover alternatives to the same route</small></td><td><input id="edit_gateway" name="gateway" value="{{.EditScope.Gateway}}" pattern="{{.GatewayPattern}}" title="IPv4 address, e.g. 192.168.100.1, or a comma-separated list"></td></tr>
<tr><td><span class="info-ico" title="DHCP option 6 — the DNS server(s) clients are told to use. dnshived (default) means dnsmasq's own built-in self-advertisement, no override needed. Other lets you point clients at a different resolver, or list several separated by commas.">&#9432;</span> DNS server for clients<br>{{.ClientDNSTemplatePicker}}</td><td>
<label><input type="radio" name="client_dns_choice" value="dnshived" {{if not .ClientDNSServerText}}checked{{end}} onclick="document.getElementById('edit_client_dns_server').disabled=true"> dnshived (default)</label>
&nbsp;&nbsp;
<label><input type="radio" id="edit_client_dns_server_other" name="client_dns_choice" value="other" {{if .ClientDNSServerText}}checked{{end}} onclick="document.getElementById('edit_client_dns_server').disabled=false"> other</label>
<br><input id="edit_client_dns_server" name="client_dns_server" value="{{.ClientDNSServerText}}" placeholder="e.g. 172.17.42.1 or 172.17.42.1,172.17.42.2" {{if not .ClientDNSServerText}}disabled{{end}}>
</td></tr>
<tr><td>vrrp_id</td><td><input name="vrrp_id" value="{{.EditScope.VRRPID}}"></td></tr>
<tr><td>preferred core</td><td>
  <select name="preferred_worker">
    <option value="core-1" {{if eq .EditScope.PreferredWorker "core-1"}}selected{{end}}>core-1</option>
    <option value="core-2" {{if eq .EditScope.PreferredWorker "core-2"}}selected{{end}}>core-2</option>
    <option value="core-3" {{if eq .EditScope.PreferredWorker "core-3"}}selected{{end}}>core-3</option>
  </select>
</td></tr>
<tr><td>advert_int_ms</td><td><input name="advert_int_ms" value="{{.EditScope.AdvertIntMS}}"> (0/blank = default 1000ms)</td></tr>
<tr><td>vrrp_version</td><td><input name="vrrp_version" value="{{.EditScope.VRRPVersion}}"> (0/blank = default v2; sub-second advert_int_ms requires 3)</td></tr>
<tr><td>dns_records<br><small>text mode, one per line — see <a href="/config/scopes">the scope editor</a> for the full format reference</small><br>{{.DNSTemplatePicker}}</td>
<td><textarea name="dns_records" id="scope_dns_records" rows="4" cols="40">{{.DNSRecordsText}}</textarea></td></tr>
<tr><td>dhcp_options<br><small>raw dnsmasq dhcp-option values, one per line — blank = use the cluster default</small><br>{{.DHCPTemplatePicker}}</td>
<td><textarea name="dhcp_options" id="scope_dhcp_options" rows="3" cols="40">{{.DHCPOptionsText}}</textarea></td></tr>
<tr><td>color tag</td><td>
  <input type="color" name="color" id="color_{{.Scope}}" value="{{if .EditScope.Color}}{{.EditScope.Color}}{{else}}` + scopeColorUnset + `{{end}}">
  {{range .ColorPalette}}<span class="swatch" style="background:{{.}}" onclick="setColor('color_{{$.Scope}}','{{.}}')" title="{{.}}"></span>{{end}}
  <span class="dim">(cosmetic grouping tag only, shown in the bulk scope table; reusable across scopes)</span>
</td></tr>
{{if .HasProbeHost}}
<tr><td>probing</td><td>
  <label><input type="checkbox" name="probe_enabled" {{if not .EditScope.ProbeDisabled}}checked{{end}}> external DHCP/DNS probing enabled for this scope</label>
  <span class="dim">(new scopes are probed by default; uncheck to opt this one out)</span>
</td></tr>
{{end}}
</table>
<p><input type="submit" value="Stage as pending change"></p>
</form>
<form method="post" action="/scopes/{{.Scope}}/toggle-disabled" style="display:inline" onsubmit="return confirm('This will stage a pending change on every configured node ({{if .EditScope.DNSMasqDisabled}}enable{{else}}disable{{end}} scope {{.Scope}}) — nothing is applied until you commit from Pending changes. {{if not .EditScope.DNSMasqDisabled}}DHCP, DNS and probing stop for this scope; the VLAN interface and VIP/VRRP stay up.{{end}} Continue?')">
<button type="submit" class="{{if .EditScope.DNSMasqDisabled}}btn-success{{else}}btn-warn{{end}}">{{if .EditScope.DNSMasqDisabled}}Enable this scope{{else}}Disable this scope (DHCP + DNS + probing off, VLAN/VIP stay up){{end}}</button>
</form>
<form method="post" action="/scopes/{{.Scope}}/move" style="display:inline" onsubmit="return confirm('Stage a move of scope {{.Scope}} to the parent and VLAN chosen here? The VIP, node IPs and DHCP pool stay the same. On commit every node rebuilds its VLAN sub-interface, so this scope is interrupted briefly.')">
<select name="parent" class="js-combo" title="the trunk interface the scope's VLAN sub-interface is created on">{{$curp := .EditScope.Parent}}{{range .PlatformWorkers}}<option value="{{.}}" {{if eq . $curp}}selected{{end}}>{{.}}</option>{{end}}</select>
<input type="number" name="vlan_id" min="0" max="4094" value="{{.EditScope.VLANID}}" required title="VLAN ID on the chosen parent (0 = untagged)">
<button type="submit">Move scope to this parent and VLAN</button>
</form>
<form method="post" action="/scopes/{{.Scope}}/rebalance" style="display:inline" onsubmit="return confirm('Approve a rebalance to the preferred core ({{.EditScope.PreferredWorker}}) for scope {{.Scope}}? This stages the approval as a pending change on every configured node — nothing moves until you commit from Pending changes, and even then only once {{.EditScope.PreferredWorker}} is confirmed alive and stable. Continue?')" title="a scope never moves back to its preferred core automatically while a different node is already serving it correctly — this explicitly approves doing so now">
<button type="submit">Rebalance to preferred ({{.EditScope.PreferredWorker}}) now</button>
</form>
<form method="post" action="/scopes/{{.Scope}}/delete" style="display:inline" onsubmit="return confirm('Really delete scope {{.Scope}}? This stages its removal as a pending change on every configured node — nothing is torn down until you commit from Pending changes, and the interface/dnsmasq unit only actually stop on the next daemon restart. Continue?')">
<button type="submit" class="btn-danger">Delete this scope</button>
</form>
<p class="dim">dnsmasq process on {{.TargetNode}}: running as <strong class="{{if eq .DnsmasqRunningAs "root"}}warn{{end}}">{{.DnsmasqRunningAs}}</strong>{{if .DnsmasqPID}}, PID {{.DnsmasqPID}}{{end}} —
<a href="/daemons/{{.TargetNode}}/{{.DnsmasqRestartUnit}}/restart/confirm">Restart dnsmasq for this scope</a>
<span title="dnsmasq has no live config reload (SIGHUP) — only a genuine restart is possible, which briefly interrupts DHCP/DNS for this scope on this node">(no reload — see tooltip)</span></p>
{{if .RenderedConfig}}
<details><summary class="dim">Debug: this scope's own contribution to the shared central DHCP/DNS config</summary>
<pre style="margin:.5rem 0;padding:.5rem;background:var(--panel);border:1px solid var(--border);overflow-x:auto">{{.RenderedConfig}}</pre>
</details>
{{end}}
{{end}}
<h2>Authority</h2>
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>Check</th><th>Pass</th><th>Detail</th></tr>
{{range .Check.Checks}}
<tr>
  <td>{{.Name}}</td>
  <td class="{{if .Pass}}ok{{else}}crit{{end}}">{{if .Pass}}yes{{else}}no{{end}}</td>
  <td>{{.Detail}}</td>
</tr>
{{end}}
</table>
<p>Decision: <strong class="{{.DecisionClass}}">{{.Check.Decision}}</strong></p>
{{if .Check.PrimaryReason}}
<p>Reason: <span class="warn">{{.Check.PrimaryReason}}</span> ({{.Check.Reason}})</p>
{{else}}
<p>Reason: {{.Check.Reason}}</p>
{{end}}
<h2>Leases ({{len .Leases}})</h2>
{{if .Leases}}
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>MAC</th><th>IP</th><th>Hostname</th><th>Expiry</th><th></th></tr>
{{range .Leases}}
<tr>
  <td>{{.MAC}}</td>
  <td>{{.IP}}</td>
  <td>{{.HostnameDisplay}}</td>
  <td{{if .Static}} class="dim"{{end}}>{{.Expiry}}</td>
  <td>{{if not .Static}}
  <form method="post" action="/scopes/{{$.Scope}}/reservations" style="display:inline">
  <input type="hidden" name="mac" value="{{.MAC}}">
  <input type="text" name="ip" value="{{.IP}}" size="15">
  <input type="text" name="hostname" value="{{.Hostname}}" size="12" placeholder="hostname">
  <button type="submit">Make static</button>
  </form>
  <form method="post" action="/scopes/{{$.Scope}}/leases/release" style="display:inline" onsubmit="return confirm('Release lease {{.IP}} ({{.MAC}})? The client will need to re-request an address.')">
  <input type="hidden" name="mac" value="{{.MAC}}">
  <input type="hidden" name="ip" value="{{.IP}}">
  <button type="submit">Release</button>
  </form>
  {{end}}</td>
</tr>
{{end}}
</table>
{{else}}
<p class="dim">(no active leases on {{.TargetNode}})</p>
{{end}}
<h2>Static reservations ({{len .EditScope.Reservations}})</h2>
{{if .EditScope.Reservations}}
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>MAC</th><th>IP</th><th>Hostname</th><th></th></tr>
{{range .EditScope.Reservations}}
<tr>
  <td>{{.MAC}}</td>
  <td>{{.IP}}</td>
  <td>{{if .Hostname}}{{.Hostname}}{{else}}—{{end}}</td>
  <td>
  <form method="post" action="/scopes/{{$.Scope}}/reservations/delete" style="display:inline" onsubmit="return confirm('Remove reservation {{.MAC}} from {{$.Scope}}? Stages the removal as a pending change on every configured node.')">
  <input type="hidden" name="mac" value="{{.MAC}}">
  <button type="submit">Delete</button>
  </form>
  </td>
</tr>
{{end}}
</table>
{{else}}
<p class="dim">(no static reservations for this scope)</p>
{{end}}
<h2>dnsmasq log (last {{len .DnsmasqLog}} line(s) from {{.TargetNode}})</h2>
{{if .DnsmasqLog}}
<pre>{{range .DnsmasqLog}}{{.}}
{{end}}</pre>
{{else}}
<p class="dim">(no per-scope log — DHCP/DNS for this scope is served by
the shared central dnsmasq instance since the "relay everywhere"
cutover, which has no per-scope log file of its own; see {{.TargetNode}}'s
own Daemons page for the shared instance's real activity)</p>
{{end}}
{{end}}
` + scopeColorPickerScriptHTML))

func renderScopePreview(scopeName string, sc config.ScopeConfig, defaultDHCPOptions []string) string {
	cluster := config.Cluster{
		Scopes:             map[string]config.ScopeConfig{scopeName: sc},
		DefaultDHCPOptions: defaultDHCPOptions,
	}
	var b strings.Builder
	if dhcp, err := dhcpcentralrender.RenderScopePreview(cluster, scopeName); err == nil && dhcp != "" {
		b.WriteString("# DHCP — this scope's own contribution to the shared central DHCP config\n")
		b.WriteString(dhcp)
	}
	if dns, err := dnscentralrender.RenderScopePreview(sc); err == nil && dns != "" {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString("# DNS — this scope's own contribution to the shared dnsmasq.central config\n")
		b.WriteString(dns)
	}
	return b.String()
}

type scopeDetailData struct {
	Scope         string
	NotFound      bool
	FetchError    string
	Check         authorityCheck
	ServingText   string
	ServingClass  string
	DecisionClass string
	// TargetNode names which node this page's checks were actually evaluated
	// on.
	TargetNode         string
	DnsmasqLog         []string
	DnsmasqPID         int
	DnsmasqRunningAs   string
	DnsmasqRestartUnit string
	// RenderedConfig previews this scope's own real contribution to the shared
	// central DHCP/DNS instances (via renderScopePreview).
	RenderedConfig string

	// Config* fields are this scope's basic definition.
	ConfigOK     bool
	ConfigError  string
	VIP          string
	Gateway      string
	DHCPStart    string
	DHCPEnd      string
	PoolSize     int
	PoolUsed     int
	PoolUsagePct int
	Leases       []leaseRow

	EditScope       config.ScopeConfig
	PlatformWorkers []string
	// VLANIDOptions is every VLAN ID not already claimed by ANOTHER scope
	// (this scope's own current ID always stays selectable).
	VLANIDOptions                                            []string
	OtherSubnetsAttr                                         string
	VIPSuffix, GatewaySuffix, DHCPStartSuffix, DHCPEndSuffix string
	// IPPattern/IPCIDRPattern back this form's pattern= syntax checks.
	IPPattern, IPCIDRPattern string
	// GatewayPattern — see scopesFormData's identical field (config.go) for
	// why this is separate from IPPattern.
	GatewayPattern          string
	DHCPTemplatePicker      template.HTML
	DNSTemplatePicker       template.HTML
	ClientDNSServerText     string
	ClientDNSTemplatePicker template.HTML
	ColorPalette            []string
	DNSRecordsText          string
	DHCPOptionsText         string
	// HasProbeHost gates the probing checkbox entirely.
	HasProbeHost  bool
	WorkerNodeIPs []workerNodeIPRow
	// ProbeHostNodeIP is the SAME suggested-default math applied to a
	// configured probe host's own mgmt address.
	ProbeHostNodeIP string
	ProbeHostName   string
	// Pending is true when this page's Configuration/Edit sections came from
	// an existing candidate rather than live config.
	Pending bool
}

// leaseRow is one DHCP lease, formatted for display.
type leaseRow struct {
	MAC             string
	IP              string
	Hostname        string
	HostnameDisplay string
	Expiry          string
	Static          bool
}

// dnsmasqLogLines is a small, useful-at-a-glance window on real recent
// activity without turning the scope detail page into a full log viewer.
const dnsmasqLogLines = 20

type workerNodeIPRow struct {
	Worker string
	Value  string
}

// resolveDisplayedNodeIP picks what to show in one worker's own node_ip
// field on a scope's detail page.
func resolveDisplayedNodeIP(sc config.ScopeConfig, workerName, workerAddr string, suffixes map[string]string, onDiskValue string) string {
	switch {
	case sc.NodeIPOverrides[workerName] != "":
		return sc.NodeIPOverrides[workerName]
	case suffixes[workerName] != "" && sc.VIP != "":
		return nodeIPFromVIPAndOctet(sc.VIP, suffixes[workerName])
	case onDiskValue != "":
		return onDiskValue
	case sc.VIP != "":
		return deriveNodeIP(workerAddr, sc.VIP)
	}
	return ""
}

// nodeIPOverridesToPersist decides which submitted per-node node_ip form
// values become stored NodeIPOverrides.
func nodeIPOverridesToPersist(existing, submitted, derived map[string]string) map[string]string {
	out := make(map[string]string)
	for name, v := range submitted {
		if v == "" {
			continue
		}
		if existing[name] != "" || v != derived[name] {
			out[name] = v
		}
	}
	return out
}

// perNodeScopeNodeIPs fetches each real node's OWN current NodeIP for one
// scope.
func perNodeScopeNodeIPs(nodes []NodeConfig, scope string) map[string]string {
	out := make(map[string]string)
	for _, n := range nodes {
		if cand, exists, err := fetchCandidate(n); err == nil && exists {
			if sc, ok := cand.Scopes[scope]; ok {
				out[n.Name] = sc.NodeIP
				continue
			}
		}
		if live, err := fetchConfig(n); err == nil {
			if sc, ok := live.Scopes[scope]; ok {
				out[n.Name] = sc.NodeIP
			}
		}
	}
	return out
}

// findScopeTargetNode resolves which node a scope's checks/actions should
// be evaluated/performed against.
func findScopeTargetNode(rows []statusRow, scope string) *NodeConfig {
	for _, row := range rows {
		if row.FetchError != "" || !isCoreRole(row.Status.Role) {
			continue
		}
		for _, sc := range row.Status.Serving {
			if sc == scope {
				n := row.Node
				return &n
			}
		}
	}
	for _, row := range rows {
		if row.FetchError == "" && isCoreRole(row.Status.Role) {
			n := row.Node
			return &n
		}
	}
	return nil
}

func handleScopeDetail(ref *configRef, store *TemplateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		scope := r.PathValue("name")
		rows := fetchAllStatus(cfg, nodesIncludingSelf(cfg))
		target := findScopeTargetNode(rows, scope)

		data := scopeDetailData{Scope: scope, HasProbeHost: len(cfg.ProbeHosts) > 0, IPPattern: ipPattern, IPCIDRPattern: ipCIDRPattern, GatewayPattern: ipGatewayPattern}
		if target == nil {
			data.NotFound = true
			renderTemplate(w, scopeDetailTmpl, data, "scope-detail")
			return
		}

		ac, err := fetchAuthority(*target, scope)
		if err != nil {
			data.FetchError = err.Error()
			renderTemplate(w, scopeDetailTmpl, data, "scope-detail")
			return
		}

		data.Check = ac
		data.TargetNode = target.Name
		data.DnsmasqLog, _ = fetchDnsmasqLog(*target, scope, dnsmasqLogLines)

		data.DnsmasqRestartUnit = "dnshived-dnsmasq@" + scope + ".service"
		if daemons, err := fetchDaemons(*target); err == nil {
			for _, d := range daemons.Daemons {
				if d.Unit == data.DnsmasqRestartUnit {
					data.DnsmasqPID = d.PID
					data.DnsmasqRunningAs = runningAsText(d.PID, d.User)
					break
				}
			}
		}

		c, _, isPending, err := currentEditableConfig(nodesIncludingSelf(cfg))
		data.Pending = isPending
		if err != nil {
			data.ConfigError = err.Error()
		} else if sc, ok := c.Scopes[scope]; !ok {
			data.ConfigError = "not present in cluster config (renamed or removed?)"
		} else {
			data.ConfigOK = true
			data.VIP = sc.VIP
			data.Gateway = sc.Gateway
			data.DHCPStart, data.DHCPEnd = sc.DHCPRange[0], sc.DHCPRange[1]
			if size, err := dhcplease.PoolSize(sc.DHCPRange[0], sc.DHCPRange[1]); err == nil {
				data.PoolSize = size
			}
			data.EditScope = sc
			data.ColorPalette = scopeColorPalette
			data.DNSRecordsText = formatDNSRecordLines(sc.DNSRecords)
			data.DHCPOptionsText = strings.Join(sc.DHCPOptions, "\n")
			data.ClientDNSServerText = sc.ClientDNSServer
			data.VLANIDOptions = freeVLANIDsForEdit(c.Scopes, scope)
			data.OtherSubnetsAttr = otherScopeSubnetsAttr(c.Scopes, scope)
			if c.Platform != nil {
				data.PlatformWorkers = c.Platform.Workers
			}
			data.RenderedConfig = renderScopePreview(scope, sc, c.DefaultDHCPOptions)
			data.DHCPTemplatePicker = wizardTemplateButtonsHTML(TemplateKindDHCP, "scope_dhcp_options", buildTemplateRows(store.ByKind(TemplateKindDHCP)))
			data.DNSTemplatePicker = wizardTemplateButtonsHTML(TemplateKindDNS, "scope_dns_records", buildTemplateRows(store.ByKind(TemplateKindDNS)))
			data.ClientDNSTemplatePicker = wizardTemplateReplaceButtonsHTML("edit_client_dns_server", buildTemplateRows(store.ByKind(TemplateKindClientDNS)))

			var suffixes map[string]string
			if c.ScopeDefaults != nil {
				suffixes = c.ScopeDefaults.NodeIPSuffixes
				data.VIPSuffix = c.ScopeDefaults.VIPSuffix
				data.GatewaySuffix = c.ScopeDefaults.GatewaySuffix
				data.DHCPStartSuffix = c.ScopeDefaults.DHCPStartSuffix
				data.DHCPEndSuffix = c.ScopeDefaults.DHCPEndSuffix
			}
			allScopeNodes := nodesIncludingSelf(cfg)
			perNode := perNodeScopeNodeIPs(allScopeNodes, scope)
			for _, n := range allScopeNodes {
				val := resolveDisplayedNodeIP(sc, n.Name, n.Addr, suffixes, perNode[n.Name])
				data.WorkerNodeIPs = append(data.WorkerNodeIPs, workerNodeIPRow{Worker: n.Name, Value: val})
			}
			if len(cfg.ProbeHosts) > 0 && sc.VIP != "" {
				ph := cfg.ProbeHosts[0]
				data.ProbeHostName = ph.Name
				data.ProbeHostNodeIP = nodeIPFromVIPAndOctet(sc.VIP, nodeAddrLastOctet(ph.Addr))
			}
		}

		leases, _ := fetchDnsmasqLeases(*target, scope)
		data.PoolUsed = len(leases)
		if data.PoolSize > 0 {
			data.PoolUsagePct = data.PoolUsed * 100 / data.PoolSize
		}
		for _, l := range leases {
			row := leaseRow{MAC: l.MAC, IP: l.IP, Hostname: l.Hostname, HostnameDisplay: l.Hostname, Static: l.NeverExpires}
			if row.HostnameDisplay == "" {
				row.HostnameDisplay = "—"
			}
			if l.NeverExpires {
				row.Expiry = "static"
			} else {
				row.Expiry = l.Expiry.Local().Format("2006-01-02 15:04:05")
			}
			data.Leases = append(data.Leases, row)
		}

		if ac.Serving {
			data.ServingText, data.ServingClass = "SERVING", "ok"
		} else {
			data.ServingText, data.ServingClass = "STOPPED", "dim"
		}
		data.DecisionClass = "warn"
		if ac.Decision == "SERVE" {
			data.DecisionClass = "ok"
		}
		renderTemplate(w, scopeDetailTmpl, data, "scope-detail")
	}
}

// upsertReservation adds a new reservation or updates an existing one
// (matched by MAC).
func upsertReservation(reservations []config.Reservation, res config.Reservation) []config.Reservation {
	for i, r := range reservations {
		if r.MAC == res.MAC {
			reservations[i] = res
			return reservations
		}
	}
	return append(reservations, res)
}

// promoteLeaseFormHandler (POST /scopes/{name}/reservations) is the "make
// static" action from the scope detail page's lease table.
func promoteLeaseFormHandler(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		scope := r.PathValue("name")
		mac := r.FormValue("mac")
		ip := r.FormValue("ip")
		hostname := r.FormValue("hostname")
		if mac == "" || ip == "" {
			http.Redirect(w, r, "/scopes/"+scope, http.StatusSeeOther)
			return
		}

		c, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "fetch current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		sc, ok := c.Scopes[scope]
		if !ok {
			http.Error(w, "scope not present in cluster config: "+scope, http.StatusNotFound)
			return
		}

		newScopes := make(map[string]config.ScopeConfig, len(c.Scopes))
		for name, s := range c.Scopes {
			newScopes[name] = s
		}
		sc.Reservations = upsertReservation(append([]config.Reservation{}, sc.Reservations...),
			config.Reservation{MAC: mac, IP: ip, Hostname: hostname})
		newScopes[scope] = sc

		payload := clusterPushPayloadFrom(c)
		payload.Scopes = newScopes

		user, _ := userFromContext(r)
		pushCandidateAndRenderResult(w, cfg, payload, user, "/scopes/"+scope, "back to scope")
	}
}

func releaseLeaseFormHandler(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		scope := r.PathValue("name")
		mac := r.FormValue("mac")
		ip := r.FormValue("ip")
		if mac == "" || ip == "" {
			http.Redirect(w, r, "/scopes/"+scope, http.StatusSeeOther)
			return
		}

		rows := fetchAllStatus(cfg, nodesIncludingSelf(cfg))
		target := findScopeTargetNode(rows, scope)
		if target == nil {
			http.Error(w, "no reachable node currently serves this scope", http.StatusBadGateway)
			return
		}
		if err := releaseLease(*target, scope, mac, ip); err != nil {
			http.Error(w, "release lease: "+err.Error(), http.StatusBadGateway)
			return
		}
		http.Redirect(w, r, "/scopes/"+scope, http.StatusSeeOther)
	}
}

func deleteReservationFormHandler(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		scope := r.PathValue("name")
		mac := r.FormValue("mac")
		if mac == "" {
			http.Redirect(w, r, "/scopes/"+scope, http.StatusSeeOther)
			return
		}

		c, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "fetch current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		sc, ok := c.Scopes[scope]
		if !ok {
			http.Error(w, "scope not present in cluster config: "+scope, http.StatusNotFound)
			return
		}

		newScopes := make(map[string]config.ScopeConfig, len(c.Scopes))
		for name, s := range c.Scopes {
			newScopes[name] = s
		}
		kept := make([]config.Reservation, 0, len(sc.Reservations))
		for _, res := range sc.Reservations {
			if res.MAC != mac {
				kept = append(kept, res)
			}
		}
		sc.Reservations = kept
		newScopes[scope] = sc

		payload := clusterPushPayloadFrom(c)
		payload.Scopes = newScopes

		user, _ := userFromContext(r)
		pushCandidateAndRenderResult(w, cfg, payload, user, "/scopes/"+scope, "back to scope")
	}
}

// parseScopeEditForm builds a config.ScopeConfig from the scope detail
// page's own edit form.
func parseScopeEditForm(r *http.Request) (config.ScopeConfig, error) {
	f := r.PostForm
	vlanID, _ := strconv.Atoi(first(f["vlan_id"]))
	vrrpID, _ := strconv.Atoi(first(f["vrrp_id"]))
	advertMS, _ := strconv.Atoi(first(f["advert_int_ms"]))
	vrrpVersion, _ := strconv.Atoi(first(f["vrrp_version"]))
	dnsRecords, err := parseDNSRecordLines(first(f["dns_records"]))
	if err != nil {
		return config.ScopeConfig{}, fmt.Errorf("dns_records: %w", err)
	}
	return config.ScopeConfig{
		Parent:          first(f["parent"]),
		VLANID:          vlanID,
		VIP:             first(f["vip"]),
		NodeIP:          first(f["node_ip"]),
		DHCPRange:       [2]string{first(f["dhcp_start"]), first(f["dhcp_end"])},
		Gateway:         first(f["gateway"]),
		VRRPID:          vrrpID,
		PreferredWorker: first(f["preferred_worker"]),
		AdvertIntMS:     advertMS,
		VRRPVersion:     vrrpVersion,
		Color:           parseScopeColor(first(f["color"])),
		DNSRecords:      dnsRecords,
		DHCPOptions:     splitLines(first(f["dhcp_options"])),
		ProbeDisabled:   first(f["probe_enabled"]) != "on",
		ClientDNSServer: clientDNSServerFromForm(f),
	}, nil
}

// clientDNSServerFromForm resolves parseScopeEditForm's own
// client_dns_choice/client_dns_server pair.
func clientDNSServerFromForm(f map[string][]string) string {
	if first(f["client_dns_choice"]) == "dnshived" {
		return ""
	}
	return first(f["client_dns_server"])
}

// handleScopeConfigPost (POST /scopes/{name}/config) edits one scope's
// basic definition from its own detail page.
func handleScopeConfigPost(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		scope := r.PathValue("name")
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}

		c, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "fetch current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		if _, ok := c.Scopes[scope]; !ok {
			http.Error(w, "scope not present in cluster config: "+scope, http.StatusNotFound)
			return
		}

		newScopes := make(map[string]config.ScopeConfig, len(c.Scopes))
		for name, sc := range c.Scopes {
			newScopes[name] = sc
		}
		edited, err := parseScopeEditForm(r)
		if err != nil {
			http.Error(w, "bad input: "+err.Error(), http.StatusBadRequest)
			return
		}
		edited.Reservations = c.Scopes[scope].Reservations

		targetName := scope
		if newName := strings.TrimSpace(first(r.PostForm["new_name"])); newName != "" && newName != scope {
			if !scopeRenamePattern.MatchString(newName) {
				http.Error(w, "invalid scope name: must match "+scopeRenamePattern.String(), http.StatusBadRequest)
				return
			}
			if _, exists := c.Scopes[newName]; exists {
				http.Error(w, "a scope named \""+newName+"\" already exists", http.StatusBadRequest)
				return
			}
			targetName = newName
			delete(newScopes, scope)
		}
		formNodes := nodesIncludingSelf(cfg)
		perNodeOnDisk := perNodeScopeNodeIPs(formNodes, scope)
		var suffixes map[string]string
		if c.ScopeDefaults != nil {
			suffixes = c.ScopeDefaults.NodeIPSuffixes
		}
		submitted := make(map[string]string)
		derived := make(map[string]string)
		noOverride := edited
		noOverride.NodeIPOverrides = nil
		for _, n := range formNodes {
			if v := first(r.PostForm[fmt.Sprintf("node_ip_%s", n.Name)]); v != "" {
				submitted[n.Name] = v
			}
			derived[n.Name] = resolveDisplayedNodeIP(noOverride, n.Name, n.Addr, suffixes, perNodeOnDisk[n.Name])
		}
		if overrides := nodeIPOverridesToPersist(c.Scopes[scope].NodeIPOverrides, submitted, derived); len(overrides) > 0 {
			edited.NodeIPOverrides = overrides
		}
		newScopes[targetName] = edited

		payload := clusterPushPayloadFrom(c)
		payload.Scopes = newScopes

		user, _ := userFromContext(r)
		pushCandidateAndRenderResult(w, cfg, payload, user, "/scopes/"+targetName, "back to scope")
	}
}

// handleScopeMove serves POST /scopes/{name}/move. It changes only the scope's parent trunk and VLAN ID;
// VIP, node IPs and the DHCP pool stay as they are.
func handleScopeMove(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		scope := r.PathValue("name")
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}

		c, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "fetch current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		sc, ok := c.Scopes[scope]
		if !ok {
			http.Error(w, "scope not present in cluster config: "+scope, http.StatusNotFound)
			return
		}

		parent := strings.TrimSpace(r.PostForm.Get("parent"))
		vlanID, err := strconv.Atoi(strings.TrimSpace(r.PostForm.Get("vlan_id")))
		if err != nil {
			http.Error(w, "vlan_id must be a number", http.StatusBadRequest)
			return
		}
		if err := validateScopeMove(c, scope, parent, vlanID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		moved := sc
		moved.Parent = parent
		moved.VLANID = vlanID
		newScopes := make(map[string]config.ScopeConfig, len(c.Scopes))
		for name, other := range c.Scopes {
			newScopes[name] = other
		}
		newScopes[scope] = moved

		payload := clusterPushPayloadFrom(c)
		payload.Scopes = newScopes

		user, _ := userFromContext(r)
		pushCandidateAndRenderResult(w, cfg, payload, user, "/scopes/"+scope, "back to scope")
	}
}

// validateScopeMove reports why scope cannot move to parent and vlanID under the cluster's current config.
func validateScopeMove(c config.Cluster, scope, parent string, vlanID int) error {
	sc, ok := c.Scopes[scope]
	if !ok {
		return fmt.Errorf("scope not present in cluster config: %s", scope)
	}
	if vlanID < 0 || vlanID > 4094 {
		return fmt.Errorf("vlan_id must be between 0 and 4094, got %d", vlanID)
	}
	known := false
	for _, w := range c.Platform.Workers {
		if w == parent {
			known = true
			break
		}
	}
	if !known {
		return fmt.Errorf("parent %q is not a trunk interface of this cluster", parent)
	}
	if parent == sc.Parent && vlanID == sc.VLANID {
		return fmt.Errorf("scope %s is already on %s, VLAN %d — nothing to move", scope, parent, vlanID)
	}
	for name, other := range c.Scopes {
		if name != scope && other.Parent == parent && other.VLANID == vlanID {
			return fmt.Errorf("VLAN %d on %s is already used by scope %s", vlanID, parent, name)
		}
	}
	return nil
}

// scopeRenamePattern mirrors internal/config's own (unexported)
// scopeNamePattern exactly.
var scopeRenamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func handleScopeDelete(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		scope := r.PathValue("name")

		c, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "fetch current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		if _, ok := c.Scopes[scope]; !ok {
			http.Error(w, "scope not present in cluster config: "+scope, http.StatusNotFound)
			return
		}

		newScopes := make(map[string]config.ScopeConfig, len(c.Scopes)-1)
		for name, sc := range c.Scopes {
			if name == scope {
				continue
			}
			newScopes[name] = sc
		}

		payload := clusterPushPayloadFrom(c)
		payload.Scopes = newScopes

		user, _ := userFromContext(r)
		back, backText := returnTargetOr(r, "/scopes", "back to scopes")
		pushCandidateAndRenderResult(w, cfg, payload, user, back, backText)
	}
}

// handleScopeDisableToggle serves POST /scopes/{name}/toggle-disabled.
func handleScopeDisableToggle(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		scope := r.PathValue("name")

		c, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "fetch current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		sc, ok := c.Scopes[scope]
		if !ok {
			http.Error(w, "scope not present in cluster config: "+scope, http.StatusNotFound)
			return
		}

		newScopes := make(map[string]config.ScopeConfig, len(c.Scopes))
		for name, s := range c.Scopes {
			newScopes[name] = s
		}
		disable := !sc.DNSMasqDisabled
		sc.DNSMasqDisabled = disable
		sc.ProbeDisabled = disable
		newScopes[scope] = sc

		payload := clusterPushPayloadFrom(c)
		payload.Scopes = newScopes

		user, _ := userFromContext(r)
		back, backText := returnTargetOr(r, "/scopes/"+scope, "back to scope")
		pushCandidateAndRenderResult(w, cfg, payload, user, back, backText)
	}
}

// handleScopeRebalance serves POST /scopes/{name}/rebalance.
func handleScopeRebalance(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		scope := r.PathValue("name")

		c, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "fetch current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		sc, ok := c.Scopes[scope]
		if !ok {
			http.Error(w, "scope not present in cluster config: "+scope, http.StatusNotFound)
			return
		}

		newScopes := make(map[string]config.ScopeConfig, len(c.Scopes))
		for name, s := range c.Scopes {
			newScopes[name] = s
		}
		sc.RebalanceApprovedAt = time.Now().Unix()
		newScopes[scope] = sc

		payload := clusterPushPayloadFrom(c)
		payload.Scopes = newScopes

		user, _ := userFromContext(r)
		back, backText := returnTargetOr(r, "/scopes/"+scope, "back to scope")
		pushCandidateAndRenderResult(w, cfg, payload, user, back, backText)
	}
}

// handleScopeRebalanceAll serves POST /scopes/rebalance-all.
func handleScopeRebalanceAll(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()

		c, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "fetch current config: "+err.Error(), http.StatusBadGateway)
			return
		}

		now := time.Now().Unix()
		newScopes := make(map[string]config.ScopeConfig, len(c.Scopes))
		for name, sc := range c.Scopes {
			sc.RebalanceApprovedAt = now
			newScopes[name] = sc
		}

		payload := clusterPushPayloadFrom(c)
		payload.Scopes = newScopes

		user, _ := userFromContext(r)
		pushCandidateAndRenderResult(w, cfg, payload, user, "/scopes", "back to scopes")
	}
}
