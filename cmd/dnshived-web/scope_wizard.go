// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strconv"
	"strings"

	"dnshived/internal/config"
)

type wizardData struct {
	Step int

	// Step 1 — identity/network.
	Name, Color     string
	Parent          string
	VIP, NodeIP     string
	PreferredWorker string
	// PreferredWorkerAutoLabel is whichever worker currently has fewer
	// configured scopes, computed fresh on every render.
	PreferredWorkerAutoLabel string
	Workers                  []string
	VLANID                   string
	VLANIDOptions            []string
	// Subnet is a dedicated "operator supplies the vlan and the subnet" entry
	// point.
	Subnet string
	// VRRPID backs the VRRP ID dropdown.
	VRRPID        string
	VRRPIDOptions []string
	// VIPSuffix is the cluster's preferred last octet for a new scope's own
	// VIP (Cluster Settings' "Scope VIP preference" section,
	// config.ScopeDefaults.VIPSuffix).
	VIPSuffix                string
	IPPattern, IPCIDRPattern string
	GatewayPattern           string
	// OtherSubnetsAttr feeds the vip field's live subnet-overlap check
	// (subnetOverlapScriptHTML, scopes.go).
	OtherSubnetsAttr string

	Gateway, DHCPStart, DHCPEnd string
	// GatewaySuffix/DHCPStartSuffix/DHCPEndSuffix back this step's own
	// suggested-default derivation from THIS scope's already-known VIP (set
	// back in Step 1).
	GatewaySuffix, DHCPStartSuffix, DHCPEndSuffix string
	DHCPOptionsText                               string
	DHCPTemplates                                 []templateRow

	// Step 3 — DNS options.
	DNSRecordsText       string
	GlobalDNSRecordsText string
	DNSTemplates         []templateRow

	ClientDNSServerText string
	ClientDNSTemplates  []templateRow

	// Step 4 — review.
	CheckErrors   []string
	CheckWarnings []string
	// RenderedPreview previews this scope's own real contribution to the
	// shared central DHCP/DNS config (via renderScopePreview).
	RenderedPreview string
}

// wizardVIPScriptHTML backs the vip field's "type a bare network, get a
// real address" shortcut.
const wizardVIPScriptHTML = `<script>
function autoVIPFromNetwork(input){
  var suffix = input.getAttribute('data-vip-suffix');
  if(!suffix) return;
  var m = input.value.trim().match(/^(\d{1,3}\.\d{1,3}\.\d{1,3})\.0\/24$/);
  if(!m) return;
  input.value = m[1] + '.' + suffix + '/24';
}
function autoVIPFromSubnet(input){
  var vipEl = document.getElementById('w_vip');
  if(!vipEl) return;
  var suffix = vipEl.getAttribute('data-vip-suffix');
  var m = input.value.trim().match(/^(\d{1,3}\.\d{1,3}\.\d{1,3})\.0\/24$/);
  if(!suffix || !m) return;
  vipEl.value = m[1] + '.' + suffix + '/24';
  if(typeof checkVIPSubnetOverlap === 'function') checkVIPSubnetOverlap(vipEl);
}
</script>`

func wizardTemplateButtonsHTML(kind TemplateKind, textareaID string, rows []templateRow) template.HTML {
	if len(rows) == 0 {
		return template.HTML(`<p class="dim">no templates yet — create one under <a href="/config/dns#templates">DHCP &amp; DNS &rarr; Templates</a>, or type directly below.</p>`)
	}
	var b strings.Builder
	keyFn := wizardCollisionKeyJS(kind)
	var body string
	if keyFn == "" {
		body = `var have=ta.value.split("\n").filter(function(l){return l!=='';});` +
			`var add=body.split("\n").filter(function(l){return l!=='';});` +
			`add.forEach(function(line){if(have.indexOf(line)===-1){have.push(line);}});ta.value=have.join("\n");`
	} else {
		body = `var have=ta.value.split("\n").filter(function(l){return l!=='';});` +
			`var add=body.split("\n").filter(function(l){return l!=='';});` +
			keyFn +
			`var haveKeys={};have.forEach(function(l){haveKeys[keyOf(l)]=l;});var conf=[];add.forEach(function(l){var k=keyOf(l);if(haveKeys[k]!==undefined&&haveKeys[k]!==l){conf.push(haveKeys[k]+"  -->  "+l);}});` +
			`if(conf.length>0&&!confirm("This adds "+conf.length+" line(s) that conflict with what's already here (both will be kept, nothing is removed):\n\n"+conf.join("\n")+"\n\nAdd anyway?"))return;` +
			`add.forEach(function(line){if(have.indexOf(line)===-1){have.push(line);}});ta.value=have.join("\n");`
	}
	b.WriteString(`<script>function wizInsert_` + textareaID + `(body){var ta=document.getElementById('` + textareaID + `');if(!ta)return;` + body + `}</script>`)
	for _, t := range rows {
		b.WriteString(`<details class="tpl-picker-item">`)
		b.WriteString(`<summary><span class="name-dot" style="background:` + template.HTMLEscapeString(t.Color) + `"></span>` + template.HTMLEscapeString(t.Name) + `</summary>`)
		b.WriteString(`<pre style="margin:.3rem 0;white-space:pre-wrap">` + template.HTMLEscapeString(t.Body) + `</pre>`)
		b.WriteString(`<button type="button" onclick="wizInsert_` + textareaID + `(` + template.HTMLEscapeString(templateJS(t.Body)) + `)">+ add to this scope</button>`)
		b.WriteString(`</details>`)
	}
	return template.HTML(b.String())
}

func wizardCollisionKeyJS(kind TemplateKind) string {
	switch kind {
	case TemplateKindDHCP:
		// "option:dns-server,8.8.8.8" -> "option:dns-server";
		// "252,http://..." -> "252" — everything up to the first comma.
		return `var keyOf=function(l){var i=l.indexOf(",");return i===-1?l:l.slice(0,i);};`
	case TemplateKindDNS:
		return `var keyOf=function(l){var p=l.split("|");if(p.length<2)return l;return p[0].trim().toLowerCase()+"|"+p[1].trim().toLowerCase().replace(/\.$/,"");};`
	default:
		return ""
	}
}

func wizardTemplateReplaceButtonsHTML(inputID string, rows []templateRow) template.HTML {
	if len(rows) == 0 {
		return template.HTML(`<p class="dim">no templates yet — create one under <a href="/config/dns#templates">DHCP &amp; DNS &rarr; Templates</a>, or type directly below.</p>`)
	}
	var b strings.Builder
	b.WriteString(`<script>function wizReplace_` + inputID + `(body){var el=document.getElementById('` + inputID + `');if(!el)return;` +
		`if(el.value&&el.value!==body&&!confirm('This replaces the current value ("'+el.value+'") with "'+body+'". Continue?'))return;` +
		`el.value=body;el.disabled=false;var other=document.getElementById('` + inputID + `_other');if(other)other.checked=true;}</script>`)
	for _, t := range rows {
		b.WriteString(`<details class="tpl-picker-item">`)
		b.WriteString(`<summary><span class="name-dot" style="background:` + template.HTMLEscapeString(t.Color) + `"></span>` + template.HTMLEscapeString(t.Name) + `</summary>`)
		b.WriteString(`<pre style="margin:.3rem 0;white-space:pre-wrap">` + template.HTMLEscapeString(t.Body) + `</pre>`)
		b.WriteString(`<button type="button" onclick="wizReplace_` + inputID + `(` + template.HTMLEscapeString(templateJS(t.Body)) + `)">+ use this</button>`)
		b.WriteString(`</details>`)
	}
	return template.HTML(b.String())
}

// templateJS renders a Go string as a JSON string literal.
func templateJS(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

var wizardTmpl = template.Must(template.New("wizard").Funcs(template.FuncMap{
	"dhcpButtons": func(id string, rows []templateRow) template.HTML {
		return wizardTemplateButtonsHTML(TemplateKindDHCP, id, rows)
	},
	"dnsButtons": func(id string, rows []templateRow) template.HTML {
		return wizardTemplateButtonsHTML(TemplateKindDNS, id, rows)
	},
	"clientDNSButtons": wizardTemplateReplaceButtonsHTML,
}).Parse(`<!doctype html>
<title>dnshived-web — add scope wizard</title>
` + styleHTML + wizardVIPScriptHTML + subnetOverlapScriptHTML + `
<h1>Add Scope — step {{.Step}} of 4</h1>
` + navHTML + `

{{if eq .Step 1}}
<form method="post" action="/scopes/wizard">
<input type="hidden" name="action" value="step2">
<button type="submit">Next &rarr;</button>
<h2>1. Identity &amp; network</h2>
<table>
<tr><td>name<br><small class="dim">unique scope ID (e.g. <code>rw-100</code> or <code>office</code>) — used in filenames, logs, and DNS/DHCP config</small></td><td><input name="name" value="{{.Name}}" required></td></tr>
<tr><td>color<br><small class="dim">UI only — tells scopes apart at a glance, no effect on DHCP/DNS behavior</small></td><td><input type="color" name="color" value="{{if .Color}}{{.Color}}{{else}}` + scopeColorUnset + `{{end}}"></td></tr>
<tr><td>parent interface<br><small class="dim">the trunk NIC this VLAN rides on (e.g. <code>ens19</code>) — must already exist on both workers</small></td><td><select name="parent">
{{$cur := .Parent}}{{range .Workers}}<option value="{{.}}" {{if eq . $cur}}selected{{end}}>{{.}}</option>{{end}}
</select></td></tr>
<tr><td>vlan_id<br><small class="dim">802.1Q VLAN tag — this scope's own sub-interface becomes e.g. <code>ens19.100</code>. Only IDs not already used by another scope are offered. Type to search. Choose "0 — untagged" to serve directly on the parent interface itself (e.g. the mgmt interface), with no VLAN sub-interface at all.</small></td><td><select name="vlan_id" class="js-combo">
{{$curl := .VLANID}}{{range .VLANIDOptions}}<option value="{{.}}" {{if eq . $curl}}selected{{end}}>{{if eq . "0"}}0 — untagged (bind directly to parent){{else}}{{.}}{{end}}</option>{{end}}
</select></td></tr>
<tr><td>subnet<br><small class="dim">start here: type this scope's network (e.g. <code>192.168.10.0/24</code>) and vip below fills in automatically from your configured <a href="/config">vip preference</a> — override vip directly if needed.</small></td><td><input id="w_subnet" name="subnet" value="{{.Subnet}}" pattern="{{.IPCIDRPattern}}" title="IPv4 network, e.g. 192.168.10.0/24" oninput="autoVIPFromSubnet(this)"></td></tr>
<tr><td>vrrp_id<br><small class="dim">VRRP router ID — must be unique among every scope sharing this VLAN's broadcast domain. Type to search.</small></td><td><select name="vrrp_id" class="js-combo">
{{$curv := .VRRPID}}{{range .VRRPIDOptions}}<option value="{{.}}" {{if eq . $curv}}selected{{end}}>{{.}}</option>{{end}}
</select></td></tr>
<tr><td>vip<br><small class="dim">the floating IP DHCP clients are told is their gateway/DNS server — moves between workers on failover. Auto-filled from the subnet field above when a VIP suffix is set under Scope Options; otherwise type the address here. A subnet already used by another scope is flagged live, and blocked at commit.</small></td><td><input id="w_vip" name="vip" value="{{.VIP}}" pattern="{{.IPCIDRPattern}}" title="IPv4 with prefix, e.g. 192.168.105.2/24" data-vip-suffix="{{.VIPSuffix}}" data-other-subnets="{{.OtherSubnetsAttr}}" data-msg-id="w_vip_msg" oninput="autoVIPFromNetwork(this);checkVIPSubnetOverlap(this)" required> <span id="w_vip_msg" class="crit"></span></td></tr>
<tr><td>node_ip<br><small class="dim">Each worker's own fixed address on this VLAN (e.g. core-1=.22, core-2=.23) — required for VRRP to actually work; auto-filled per worker when you submit if left blank here, but a scope with neither will never serve DHCP</small></td><td><input id="w_node_ip" name="node_ip" value="{{.NodeIP}}" pattern="{{.IPCIDRPattern}}" title="blank = auto-derived per node on submit"></td></tr>
<tr><td>preferred core<br><small class="dim">which core node normally serves this scope — another takes over automatically if it goes down</small></td><td><select name="preferred_worker">
<option value="auto" {{if eq .PreferredWorker "auto"}}selected{{end}}>auto (currently: {{.PreferredWorkerAutoLabel}})</option>
<option value="core-1" {{if eq .PreferredWorker "core-1"}}selected{{end}}>core-1</option>
<option value="core-2" {{if eq .PreferredWorker "core-2"}}selected{{end}}>core-2</option>
<option value="core-3" {{if eq .PreferredWorker "core-3"}}selected{{end}}>core-3</option>
</select> <span class="dim">— "auto" picks whichever core node currently has fewer configured scopes, resolved when you finish, not locked in now</span></td></tr>
</table>
<button type="submit">Next &rarr;</button>
</form>
{{end}}

{{if eq .Step 2}}
<form method="post" action="/scopes/wizard">
<input type="hidden" name="name" value="{{.Name}}"><input type="hidden" name="color" value="{{.Color}}">
<input type="hidden" name="parent" value="{{.Parent}}"><input type="hidden" name="vlan_id" value="{{.VLANID}}">
<input type="hidden" name="vrrp_id" value="{{.VRRPID}}"><input type="hidden" name="subnet" value="{{.Subnet}}"><input type="hidden" name="vip" value="{{.VIP}}">
<input type="hidden" name="node_ip" value="{{.NodeIP}}">
<input type="hidden" name="preferred_worker" value="{{.PreferredWorker}}">
<input type="hidden" name="dns_records" value="{{.DNSRecordsText}}">
<button type="submit" name="action" value="step1">&larr; Back</button>
<button type="submit" name="action" value="step3">Next &rarr;</button>
<h2>2. DHCP options</h2>
<table>
<tr><td>gateway<br><small class="dim">the real router address handed to clients — often the same as vip, but doesn't have to be. A comma-separated list is accepted for multiple failover alternatives to the same route.</small></td><td><input name="gateway" value="{{.Gateway}}" pattern="{{.GatewayPattern}}"></td></tr>
<tr><td>dhcp start<br><small class="dim">first address in the pool handed out to clients</small></td><td><input name="dhcp_start" value="{{.DHCPStart}}" pattern="{{.IPPattern}}" required></td></tr>
<tr><td>dhcp end<br><small class="dim">last address in the pool handed out to clients</small></td><td><input name="dhcp_end" value="{{.DHCPEnd}}" pattern="{{.IPPattern}}" required></td></tr>
</table>
<p class="dim">Pre-filled with the cluster's current default_dhcp_options —
edit freely; whatever's here when you finish becomes this scope's OWN
dhcp_options, replacing (not adding to) the default.</p>
{{dhcpButtons "w_dhcp_options" .DHCPTemplates}}
<textarea id="w_dhcp_options" name="dhcp_options" rows="6" cols="70">{{.DHCPOptionsText}}</textarea>
<p><input name="new_template_name" placeholder="name this as a new template">
<button type="submit" name="action" value="add_dhcp_template">+ save as template</button></p>
<button type="submit" name="action" value="step1">&larr; Back</button>
<button type="submit" name="action" value="step3">Next &rarr;</button>
</form>
{{end}}

{{if eq .Step 3}}
<form method="post" action="/scopes/wizard">
<input type="hidden" name="name" value="{{.Name}}"><input type="hidden" name="color" value="{{.Color}}">
<input type="hidden" name="parent" value="{{.Parent}}"><input type="hidden" name="vlan_id" value="{{.VLANID}}">
<input type="hidden" name="vrrp_id" value="{{.VRRPID}}"><input type="hidden" name="subnet" value="{{.Subnet}}"><input type="hidden" name="vip" value="{{.VIP}}">
<input type="hidden" name="node_ip" value="{{.NodeIP}}">
<input type="hidden" name="gateway" value="{{.Gateway}}"><input type="hidden" name="dhcp_start" value="{{.DHCPStart}}">
<input type="hidden" name="dhcp_end" value="{{.DHCPEnd}}">
<input type="hidden" name="preferred_worker" value="{{.PreferredWorker}}">
<input type="hidden" name="dhcp_options" value="{{.DHCPOptionsText}}">
<button type="submit" name="action" value="step2">&larr; Back</button>
<button type="submit" name="action" value="review">Next &rarr;</button>
<h2>3. DNS options</h2>
<p><span class="info-ico" title="DHCP option 6 — the DNS server(s) clients are told to use. dnshived (default) means dnsmasq's own built-in self-advertisement, no override needed. Other lets you point clients at a different resolver, or list several separated by commas.">&#9432;</span> DNS server for clients (option 6)</p>
<label><input type="radio" name="client_dns_choice" value="dnshived" {{if not .ClientDNSServerText}}checked{{end}} onclick="document.getElementById('w_client_dns_server').disabled=true"> dnshived (default)</label>
&nbsp;&nbsp;
<label><input type="radio" id="w_client_dns_server_other" name="client_dns_choice" value="other" {{if .ClientDNSServerText}}checked{{end}} onclick="document.getElementById('w_client_dns_server').disabled=false"> other</label>
<br>
<input id="w_client_dns_server" name="client_dns_server" value="{{.ClientDNSServerText}}" placeholder="e.g. 172.17.42.1 or 172.17.42.1,172.17.42.2" {{if not .ClientDNSServerText}}disabled{{end}}>
{{clientDNSButtons "w_client_dns_server" .ClientDNSTemplates}}
<p><input name="new_client_dns_template_name" placeholder="name this as a new template">
<button type="submit" name="action" value="add_client_dns_template">+ save as template</button></p>
{{if .GlobalDNSRecordsText}}
<p class="dim">Already applied to EVERY scope cluster-wide (global_dns_records —
edit under <a href="/config/dns">DHCP &amp; DNS</a>, not here):</p>
<pre style="margin:0 0 .8rem;white-space:pre-wrap">{{.GlobalDNSRecordsText}}</pre>
{{end}}
<p class="dim">Records below are ADDITIONAL, just for this scope.</p>
{{dnsButtons "w_dns_records" .DNSTemplates}}
<textarea id="w_dns_records" name="dns_records" rows="6" cols="70">{{.DNSRecordsText}}</textarea>
<p><input name="new_template_name" placeholder="name this as a new template">
<button type="submit" name="action" value="add_dns_template">+ save as template</button></p>
<button type="submit" name="action" value="step2">&larr; Back</button>
<button type="submit" name="action" value="review">Next &rarr;</button>
</form>
{{end}}

{{if eq .Step 4}}
<form method="post" action="/scopes/wizard">
<input type="hidden" name="name" value="{{.Name}}"><input type="hidden" name="color" value="{{.Color}}">
<input type="hidden" name="parent" value="{{.Parent}}"><input type="hidden" name="vlan_id" value="{{.VLANID}}">
<input type="hidden" name="vrrp_id" value="{{.VRRPID}}"><input type="hidden" name="subnet" value="{{.Subnet}}"><input type="hidden" name="vip" value="{{.VIP}}">
<input type="hidden" name="node_ip" value="{{.NodeIP}}">
<input type="hidden" name="gateway" value="{{.Gateway}}"><input type="hidden" name="dhcp_start" value="{{.DHCPStart}}">
<input type="hidden" name="dhcp_end" value="{{.DHCPEnd}}">
<input type="hidden" name="preferred_worker" value="{{.PreferredWorker}}">
<input type="hidden" name="dhcp_options" value="{{.DHCPOptionsText}}">
<input type="hidden" name="dns_records" value="{{.DNSRecordsText}}">
<input type="hidden" name="client_dns_server" value="{{.ClientDNSServerText}}">
<button type="submit" name="action" value="step3">&larr; Back</button>
{{if not .CheckErrors}}<button type="submit" name="action" value="submit">Create &mdash; submit to pending</button>{{end}}
<h2>4. Review</h2>
<table>
<tr><td>name</td><td><span class="name-dot" style="background:{{if .Color}}{{.Color}}{{else}}` + scopeColorUnset + `{{end}}"></span>{{.Name}}</td></tr>
<tr><td>parent / vlan_id / vrrp_id</td><td>{{.Parent}} / {{.VLANID}} / {{.VRRPID}}</td></tr>
<tr><td>vip / gateway / node_ip</td><td>{{.VIP}} / {{.Gateway}} / {{.NodeIP}}</td></tr>
<tr><td>dhcp range</td><td>{{.DHCPStart}} &ndash; {{.DHCPEnd}}</td></tr>
<tr><td>preferred core</td><td>{{if eq .PreferredWorker "auto"}}auto &rarr; {{.PreferredWorkerAutoLabel}}{{else}}{{.PreferredWorker}}{{end}}</td></tr>
<tr><td>dhcp_options</td><td><pre style="margin:0">{{.DHCPOptionsText}}</pre></td></tr>
<tr><td>DNS server for clients (option 6)</td><td>{{if .ClientDNSServerText}}{{.ClientDNSServerText}}{{else}}dnshived (default){{end}}</td></tr>
<tr><td>dns_records (this scope's own)</td><td><pre style="margin:0">{{.DNSRecordsText}}</pre></td></tr>
</table>
{{if .CheckErrors}}<p class="crit">Cannot create — fix first:</p><ul class="crit">{{range .CheckErrors}}<li>{{.}}</li>{{end}}</ul>{{end}}
{{if .CheckWarnings}}<p class="warn">Warnings:</p><ul class="warn">{{range .CheckWarnings}}<li>{{.}}</li>{{end}}</ul>{{end}}
{{if .RenderedPreview}}<p>What will actually be rendered (this scope's own contribution to the shared central DHCP/DNS config):</p>
<pre style="margin:0 0 1rem;padding:.5rem;background:var(--panel);border:1px solid var(--border);overflow-x:auto">{{.RenderedPreview}}</pre>{{end}}
<button type="submit" name="action" value="step3">&larr; Back</button>
{{if not .CheckErrors}}<button type="submit" name="action" value="submit">Create &mdash; submit to pending</button>{{end}}
</form>
{{end}}
`))

// wizardFieldsFromForm rebuilds a wizardData from whatever the previous
// step submitted.
func wizardFieldsFromForm(f map[string][]string) wizardData {
	return wizardData{
		Name: first(f["name"]), Color: parseScopeColor(first(f["color"])),
		Parent: first(f["parent"]), VLANID: first(f["vlan_id"]), VRRPID: first(f["vrrp_id"]),
		Subnet: first(f["subnet"]),
		VIP:    first(f["vip"]), Gateway: first(f["gateway"]), NodeIP: first(f["node_ip"]),
		DHCPStart: first(f["dhcp_start"]), DHCPEnd: first(f["dhcp_end"]),
		PreferredWorker:     first(f["preferred_worker"]),
		DHCPOptionsText:     first(f["dhcp_options"]),
		DNSRecordsText:      first(f["dns_records"]),
		ClientDNSServerText: first(f["client_dns_server"]),
	}
}

// usedVLANIDsSet is freeVLANIDs'/nextFreeVLANID's own source data as a
// lookup set, scoped to a single parent trunk interface.
func usedVLANIDsSet(c config.Cluster, parent string) map[int]bool {
	used := make(map[int]bool, len(c.Scopes))
	for _, sc := range c.Scopes {
		if sc.Parent == parent {
			used[sc.VLANID] = true
		}
	}
	return used
}

// usedVRRPIDsSet is usedVRRPIDsCSV's own source data as a lookup set
// (config.go) — freeVRRPIDs' input.
func usedVRRPIDsSet(c config.Cluster) map[int]bool {
	used := make(map[int]bool, len(c.Scopes)+1)
	if c.MgmtVIP != nil {
		used[c.MgmtVIP.VRRPID] = true
	}
	for _, sc := range c.Scopes {
		used[sc.VRRPID] = true
	}
	return used
}

// freeVRRPIDs returns every VRRP ID 1-255 not already claimed, as strings
// ready for the wizard's own real <select> dropdown.
func freeVRRPIDs(used map[int]bool) []string {
	var free []string
	for id := 1; id <= 255; id++ {
		if !used[id] {
			free = append(free, strconv.Itoa(id))
		}
	}
	return free
}

func freeVLANIDs(used map[int]bool) []string {
	free := make([]string, 0, 4094)
	if !used[0] {
		free = append(free, "0")
	}
	for id := 2; id <= 4094; id++ {
		if !used[id] {
			free = append(free, strconv.Itoa(id))
		}
	}
	return free
}

// bareIPFromVIPAndOctet is nodeIPFromVIPAndOctet's (config.go) bare-IP
// sibling — gateway/dhcp_start/dhcp_end are plain addresses, never CIDR,
// unlike node_ip.
func bareIPFromVIPAndOctet(vip, octet string) string {
	o, err := strconv.Atoi(octet)
	if err != nil || o < 0 || o > 255 {
		return ""
	}
	_, ipNet, err := net.ParseCIDR(vip)
	if err != nil {
		return ""
	}
	// Last-octet suffixes only make sense on a /24; any other prefix is
	// filled in by hand.
	if ones, bits := ipNet.Mask.Size(); ones != 24 || bits != 32 {
		return ""
	}
	base := ipNet.IP.To4()
	if base == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", base[0], base[1], base[2], o)
}

func handleScopeWizard(ref *configRef, store *TemplateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		c, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "could not read current config: "+err.Error(), http.StatusBadGateway)
			return
		}

		effectiveParent := r.PostFormValue("parent")
		if effectiveParent == "" && c.Platform != nil && len(c.Platform.Workers) > 0 {
			effectiveParent = c.Platform.Workers[0]
		}

		data := wizardData{
			Step: 1, IPPattern: ipPattern, IPCIDRPattern: ipCIDRPattern, GatewayPattern: ipGatewayPattern,
			VLANIDOptions:      freeVLANIDs(usedVLANIDsSet(c, effectiveParent)),
			OtherSubnetsAttr:   otherScopeSubnetsAttr(c.Scopes, ""),
			VRRPIDOptions:      freeVRRPIDs(usedVRRPIDsSet(c)),
			DHCPTemplates:      buildTemplateRows(store.ByKind(TemplateKindDHCP)),
			DNSTemplates:       buildTemplateRows(store.ByKind(TemplateKindDNS)),
			ClientDNSTemplates: buildTemplateRows(store.ByKind(TemplateKindClientDNS)),
		}
		if c.Platform != nil {
			data.Workers = c.Platform.Workers
		}
		var rows []scopeFormRow
		for name, sc := range c.Scopes {
			rows = append(rows, scopeFormRow{Name: name, ScopeConfig: sc})
		}
		data.PreferredWorker = "auto"
		data.PreferredWorkerAutoLabel = lessLoadedWorker(rows)
		data.GlobalDNSRecordsText = formatDNSRecordLines(c.GlobalDNSRecords)

		data.GatewaySuffix, data.DHCPStartSuffix, data.DHCPEndSuffix = "1", "100", "200"
		if c.ScopeDefaults != nil {
			if c.ScopeDefaults.GatewaySuffix != "" {
				data.GatewaySuffix = c.ScopeDefaults.GatewaySuffix
			}
			if c.ScopeDefaults.DHCPStartSuffix != "" {
				data.DHCPStartSuffix = c.ScopeDefaults.DHCPStartSuffix
			}
			if c.ScopeDefaults.DHCPEndSuffix != "" {
				data.DHCPEndSuffix = c.ScopeDefaults.DHCPEndSuffix
			}
			data.VIPSuffix = c.ScopeDefaults.VIPSuffix
		}

		if r.Method != http.MethodPost {
			if len(data.VLANIDOptions) > 0 {
				data.VLANID = data.VLANIDOptions[0]
			}
			if len(data.VRRPIDOptions) > 0 {
				data.VRRPID = data.VRRPIDOptions[0]
			}
			renderTemplate(w, wizardTmpl, data, "scope-wizard")
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		action := r.PostForm.Get("action")
		posted := wizardFieldsFromForm(r.PostForm)
		data.Name, data.Color = posted.Name, posted.Color
		data.Parent, data.VLANID, data.VRRPID = posted.Parent, posted.VLANID, posted.VRRPID
		data.Subnet = posted.Subnet
		data.VIP, data.NodeIP = posted.VIP, posted.NodeIP
		data.Gateway, data.DHCPStart, data.DHCPEnd = posted.Gateway, posted.DHCPStart, posted.DHCPEnd
		if posted.PreferredWorker != "" {
			data.PreferredWorker = posted.PreferredWorker
		}
		data.DHCPOptionsText, data.DNSRecordsText = posted.DHCPOptionsText, posted.DNSRecordsText
		if r.PostForm.Get("client_dns_choice") == "dnshived" {
			data.ClientDNSServerText = ""
		} else {
			data.ClientDNSServerText = posted.ClientDNSServerText
		}

		switch action {
		case "step1":
			data.Step = 1
		case "step2":
			data.Step = 2
			if _, seen := r.PostForm["gateway"]; !seen {
				if data.VIP != "" {
					data.Gateway = bareIPFromVIPAndOctet(data.VIP, data.GatewaySuffix)
					data.DHCPStart = bareIPFromVIPAndOctet(data.VIP, data.DHCPStartSuffix)
					data.DHCPEnd = bareIPFromVIPAndOctet(data.VIP, data.DHCPEndSuffix)
				}
			}
			if _, seen := r.PostForm["dhcp_options"]; !seen {
				data.DHCPOptionsText = strings.Join(c.DefaultDHCPOptions, "\n")
			}
		case "step3":
			data.Step = 3
		case "add_dhcp_template":
			name := strings.TrimSpace(r.PostForm.Get("new_template_name"))
			if name != "" && data.DHCPOptionsText != "" {
				if err := validateTemplateBody(TemplateKindDHCP, data.DHCPOptionsText); err == nil {
					store.Upsert("", name, scopeColorPalette[0], TemplateKindDHCP, data.DHCPOptionsText)
					store.Save(cfg.TemplatesFile)
					data.DHCPTemplates = buildTemplateRows(store.ByKind(TemplateKindDHCP))
				}
			}
			data.Step = 2
		case "add_client_dns_template":
			name := strings.TrimSpace(r.PostForm.Get("new_client_dns_template_name"))
			if name != "" && data.ClientDNSServerText != "" {
				if err := validateTemplateBody(TemplateKindClientDNS, data.ClientDNSServerText); err == nil {
					store.Upsert("", name, scopeColorPalette[1], TemplateKindClientDNS, data.ClientDNSServerText)
					store.Save(cfg.TemplatesFile)
					data.ClientDNSTemplates = buildTemplateRows(store.ByKind(TemplateKindClientDNS))
				}
			}
			data.Step = 3
		case "add_dns_template":
			name := strings.TrimSpace(r.PostForm.Get("new_template_name"))
			if name != "" && data.DNSRecordsText != "" {
				if err := validateTemplateBody(TemplateKindDNS, data.DNSRecordsText); err == nil {
					store.Upsert("", name, scopeColorPalette[2], TemplateKindDNS, data.DNSRecordsText)
					store.Save(cfg.TemplatesFile)
					data.DNSTemplates = buildTemplateRows(store.ByKind(TemplateKindDNS))
				}
			}
			data.Step = 3
		case "review", "submit":
			resolved := data
			if resolved.PreferredWorker == "auto" {
				resolved.PreferredWorker = data.PreferredWorkerAutoLabel
			}
			sc, dnsRecords, dnsErr := wizardBuildScope(resolved)
			if dnsErr != nil {
				data.Step = 3
				data.CheckErrors = []string{"dns_records: " + dnsErr.Error()}
				renderTemplate(w, wizardTmpl, data, "scope-wizard")
				return
			}
			candidate := make(map[string]config.ScopeConfig, len(c.Scopes)+1)
			for k, v := range c.Scopes {
				candidate[k] = v
			}
			candidate[data.Name] = sc
			checkCluster := c
			checkCluster.Scopes = candidate
			res := checkCluster.ValidateExtended()
			data.CheckErrors = filterFindingsForScope(res.Errors, data.Name)
			data.CheckWarnings = filterFindingsForScope(res.Warnings, data.Name)
			data.DNSRecordsText = formatDNSRecordLines(dnsRecords)
			if len(data.CheckErrors) == 0 {
				data.RenderedPreview = renderScopePreview(data.Name, sc, c.DefaultDHCPOptions)
			}

			if action == "review" || len(data.CheckErrors) > 0 {
				data.Step = 4
				renderTemplate(w, wizardTmpl, data, "scope-wizard")
				return
			}

			payload := clusterPushPayloadFrom(c)
			payload.Scopes = candidate
			user, _ := userFromContext(r)
			pushCandidateAndRenderResult(w, cfg, payload, user, "/scopes/wizard", "back to Add Scope wizard")
			return
		default:
			data.Step = 1
		}
		renderTemplate(w, wizardTmpl, data, "scope-wizard")
	}
}

func filterFindingsForScope(findings []string, scopeName string) []string {
	prefix := fmt.Sprintf("scope %q:", scopeName)
	var out []string
	for _, f := range findings {
		if strings.HasPrefix(f, prefix) {
			out = append(out, f)
		}
	}
	return out
}

// wizardBuildScope assembles the config.ScopeConfig the wizard is about to
// create from its accumulated field set.
func wizardBuildScope(d wizardData) (config.ScopeConfig, []config.DNSRecord, error) {
	dnsRecords, err := parseDNSRecordLines(d.DNSRecordsText)
	if err != nil {
		return config.ScopeConfig{}, nil, err
	}
	vlanID, _ := strconv.Atoi(d.VLANID)
	vrrpID, _ := strconv.Atoi(d.VRRPID)
	return config.ScopeConfig{
		Parent: d.Parent, VLANID: vlanID, VIP: d.VIP, NodeIP: d.NodeIP,
		DHCPRange: [2]string{d.DHCPStart, d.DHCPEnd}, Gateway: d.Gateway,
		VRRPID:          vrrpID,
		PreferredWorker: d.PreferredWorker,
		Color:           d.Color, DHCPOptions: splitLines(d.DHCPOptionsText), DNSRecords: dnsRecords,
		ClientDNSServer: d.ClientDNSServerText,
	}, dnsRecords, nil
}
