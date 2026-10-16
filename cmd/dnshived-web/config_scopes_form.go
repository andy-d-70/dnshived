// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import "html/template"

const scopeEditorStyleHTML = `<style>
.scope-search{width:100%;max-width:32rem;margin:0 0 .8rem;font-size:1rem}
.scope-table-wrap{overflow-x:auto;margin:0 0 1rem}
#scope-table{white-space:nowrap}
#scope-table td,#scope-table th{white-space:nowrap;vertical-align:top}
#scope-table input:not([type=checkbox]),#scope-table select{width:9rem}
#scope-table input.narrow{width:5rem}
#scope-table input.ip{width:9rem}
#scope-table textarea{width:11rem}
/* sticky header just below the sticky nav, z-index below the nav's own. */
#scope-table thead th{position:sticky;top:var(--nav-h);background:var(--panel);z-index:5}
/* shows a pattern= mismatch while typing; outline, so cell size never changes. */
#scope-table input.field-invalid{outline:2px solid var(--crit)}
.dns-copy-tool{background:var(--panel);border:1px solid var(--border);border-radius:8px;
padding:.6rem .8rem;margin:0 0 1rem}
</style>`

const vrrpSuggestScriptHTML = `<script>
function autoVRRPID(input){
  if(input.value.trim() !== '') return; // never clobber an already-typed/already-assigned value
  var used = {};
  (input.getAttribute('data-used-vrrp-ids') || '').split(',').forEach(function(s){
    var v = parseInt(s, 10);
    if(!isNaN(v)) used[v] = true;
  });
  document.querySelectorAll('input.vrrp-suggest').forEach(function(el){
    var v = parseInt(el.value, 10);
    if(!isNaN(v)) used[v] = true;
  });
  for(var id = 1; id <= 255; id++){
    if(!used[id]){ input.value = id; return; }
  }
}
document.addEventListener('DOMContentLoaded', function(){
  document.querySelectorAll('input.vrrp-suggest').forEach(autoVRRPID);
});
</script>`

const scopeEditorScriptHTML = `<script>
function filterScopes(){
  var q = document.getElementById('scope-search').value.toLowerCase();
  document.querySelectorAll('#scope-table tbody tr').forEach(function(tr){
    var hay = tr.getAttribute('data-search') || '';
    tr.style.display = hay.toLowerCase().indexOf(q) === -1 ? 'none' : '';
  });
}
function autoGateway(vipInput){
  var gw = document.getElementById(vipInput.getAttribute('data-gw-target'));
  var suffix = vipInput.getAttribute('data-gw-suffix');
  if(!gw || !suffix || gw.value.trim() !== '') return; // never clobber an already-typed value
  var m = vipInput.value.trim().match(/^(\d+\.\d+\.\d+)\.\d+\/24$/);
  if(!m) return; // suffixes only apply to a /24; other prefixes are typed by hand
  gw.value = m[1] + '.' + suffix;
}
// autoVIPFromNetwork turns a bare network address (last octet 0) into the
// VIP using the cluster's vip suffix; runs before autoGateway.
function autoVIPFromNetwork(vipInput){
  var suffix = vipInput.getAttribute('data-vip-suffix');
  if(!suffix) return;
  var m = vipInput.value.trim().match(/^(\d{1,3}\.\d{1,3}\.\d{1,3})\.0\/24$/);
  if(!m) return;
  vipInput.value = m[1] + '.' + suffix + '/24';
}
// syncNodeIPMask copies the VIP's /prefix onto a bare node_ip, never
// overwriting one that has its own.
function syncNodeIPMask(el, vipID, nodeIPID){
  var vip = document.getElementById(vipID);
  var nodeIP = document.getElementById(nodeIPID);
  if(!vip || !nodeIP) return;
  var m = vip.value.match(/\/(\d{1,2})$/);
  if(!m) return;
  if(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(nodeIP.value)){
    nodeIP.value = nodeIP.value + '/' + m[1];
  }
}
function copyDNSRecords(){
  var from = document.getElementById('dns-copy-from').value;
  var to = document.getElementById('dns-copy-to').value;
  var src = document.getElementById('dns_' + from);
  var dst = document.getElementById('dns_' + to);
  if(src && dst){ dst.value = src.value; }
}
// copyScopeAsNew copies a scope's non-identity settings into the new-scope
// row; VLAN, VIP, node IP, DHCP range, VRRP ID and DNS records are not
// copied.
function copyScopeAsNew(sourceName){
  var nameInput = document.querySelector('[name^="scope_name_new_"]');
  if(!nameInput) return;
  var suffix = nameInput.name.replace('scope_name_new_', '');
  ['parent', 'preferred', 'advert', 'vrrpver', 'dhcpopt'].forEach(function(field){
    var src = document.getElementById(field + '_' + sourceName);
    var dst = document.getElementById(field + '_new_' + suffix);
    if(src && dst){ dst.value = src.value; }
  });
  nameInput.focus();
  document.getElementById('new-scope-slot').scrollIntoView({block: 'center'});
}
// confirmScopesSave confirms every save, with a stronger warning listing
// scopes about to be deleted.
function confirmScopesSave(){
  var toDelete = [];
  document.querySelectorAll('input[name^="scope_delete_"]:checked').forEach(function(cb){
    toDelete.push(cb.name.replace('scope_delete_', ''));
  });
  if(toDelete.length > 0){
    return confirm('This will stage the DELETION of ' + toDelete.length + ' scope(s) (' + toDelete.join(', ') +
      ') as a pending change — their VLAN interface, DHCP gate, and dnsmasq unit are only actually torn down ' +
      'once you commit from Pending changes. Continue?');
  }
  return confirm('This will stage the whole scope set as a pending change on every configured node — nothing is applied until you commit it. Continue?');
}
// Live pattern= check while typing, via checkValidity() on every
// input[pattern].
document.addEventListener('DOMContentLoaded', function(){
  document.querySelectorAll('#scope-table input[pattern]').forEach(function(el){
    el.addEventListener('input', function(){
      el.classList.toggle('field-invalid', el.value !== '' && !el.checkValidity());
    });
  });
});
</script>`

// scopesConfigFormTmpl is the compact text-mode scope editor.
var scopesConfigFormTmpl = template.Must(template.New("config-scopes").Parse(`<!doctype html>
<title>dnshived-web — scope editor</title>
` + styleHTML + scopeEditorStyleHTML + `
<h1>Config editor — scopes</h1>
` + navHTML + pendingBannerHTML + `
<p><a href="/scopes/wizard">+ Add scope (guided wizard)</a> <span class="dim">— a step-by-step
alternative to the blank new-scope row at the bottom of the table below,
with reusable DHCP/DNS templates. Same result either way: a new scope
staged to <a href="/pending">pending changes</a>.</span></p>

<p>Snapshot from node: <strong>{{.SourceNode}}</strong>. Saving stages the
whole scope set as a PENDING change on every configured node — nothing is
applied until you commit it from <a href="/pending">pending changes</a>
(a NEW or REMOVED scope needs a daemon restart either way once committed —
see docs/SCOPE_LIFECYCLE.md). Cluster-wide settings (tokens, platform,
etc.) live on their own page: <a href="/config">edit cluster &rarr;</a>. DNS/
DHCP defaults live on another: <a href="/config/dns">edit DHCP &amp; DNS
&rarr;</a>. Each row's "edit &#8599;" link
opens that scope's own full detail page (live leases, VRRP/serving state,
dnsmasq log) in a new tab — this table stays for fast bulk edits across many
scopes at once.</p>

<input type="text" id="scope-search" class="scope-search" placeholder="search scopes… (name, VLAN, VIP, gateway, DNS entries — anything)" oninput="filterScopes()">

<div class="dns-copy-tool">
<strong>Copy DNS records</strong> from <select id="dns-copy-from" class="js-combo">{{range .ScopeNamesForCopy}}<option value="{{.}}">{{.}}</option>{{end}}</select>
to <select id="dns-copy-to" class="js-combo">{{range .ScopeNamesForCopy}}<option value="{{.}}">{{.}}</option>{{end}}</select>
<button type="button" onclick="copyDNSRecords()">Copy</button>
<span class="dim">(overwrites the destination scope's dns_records field below — review before saving)</span>
</div>

<form method="post" action="/config/scopes" onsubmit="return confirmScopesSave()">
<input type="hidden" name="__scope_names__" value="{{.ScopeNames}}">

<div class="scope-table-wrap">
<table border="1" cellpadding="4" id="scope-table">
<thead><tr>
<th>del</th><th>name</th><th>vlan_id</th><th>parent</th><th title="the floating IP DHCP clients are told is their gateway/DNS server — moves between workers on failover">vip</th><th title="each worker's own fixed address on this VLAN (e.g. core-1=.22, core-2=.23) — required for VRRP to actually work. A brand-new scope gets one derived automatically per worker when committed; an already-existing scope with none stays stuck in VRRP FAULT forever and never serves DHCP until one is set directly here">node_ip</th>
<th>dhcp start</th><th>dhcp end</th><th title="the real router address handed to clients — often the same as vip, but doesn't have to be">gateway</th><th title="VRRP router ID — must be unique among every scope sharing this VLAN's broadcast domain">vrrp_id</th>
<th title="which core node normally serves this scope — another takes over automatically if it goes down">preferred core</th><th>advert_ms</th><th>vrrp_ver</th><th>dns_records</th><th>dhcp_options</th>
</tr></thead>
<tbody>
{{$workers := .Workers}}
{{range .Scopes}}
<tr data-search="{{.Name}} {{.VLANID}} {{.Parent}} {{.VIP}} {{.NodeIP}} {{.Gateway}} {{.DNSRecordsText}}">
<td><input type="checkbox" name="scope_delete_{{.Name}}"></td>
<td>{{if .Color}}<span class="name-dot" style="background:{{.Color}}" title="color tag — change on the scope's own edit page"></span>{{end}}<strong>{{.Name}}</strong> <a href="/scopes/{{.Name}}" target="_blank" rel="noopener" title="full detail / leases / logs / color for {{.Name}}">edit &#8599;</a>
<button type="button" onclick="copyScopeAsNew('{{.Name}}')" title="copy this scope's non-identity settings (parent interface, preferred core, VRRP advert/version, DHCP options) into the new-scope row below — identity fields like VLAN/VIP/node IP/VRRP ID are never copied, since they must be unique">copy</button>
<input type="hidden" name="scope_color_{{.Name}}" value="{{if .Color}}{{.Color}}{{else}}` + scopeColorUnset + `{{end}}">
<input type="hidden" name="scope_probe_disabled_{{.Name}}" value="{{if .ProbeDisabled}}on{{end}}"></td>
<td><input class="narrow" type="number" min="0" max="4094" required name="scope_vlan_id_{{.Name}}" value="{{.VLANID}}" title="0 = untagged (bind directly to the parent interface, no VLAN sub-interface)"></td>
<td><select name="scope_parent_{{.Name}}" id="parent_{{.Name}}">
  {{$cur := .Parent}}
  {{range $workers}}<option value="{{.}}" {{if eq . $cur}}selected{{end}}>{{.}}</option>{{end}}
</select></td>
<td><input name="scope_vip_{{.Name}}" id="vip_{{.Name}}" value="{{.VIP}}" required
  pattern="{{$.IPCIDRPattern}}" title="IPv4 address with prefix, e.g. 192.168.100.1/24"
  data-gw-target="gw_{{.Name}}" data-gw-suffix="{{$.GatewaySuffix}}"
  oninput="autoGateway(this);syncNodeIPMask(this,'vip_{{.Name}}','node_ip_{{.Name}}')"></td>
<td><input name="scope_node_ip_{{.Name}}" id="node_ip_{{.Name}}" value="{{.NodeIP}}" pattern="{{$.IPCIDRPattern}}" title="IPv4 address with prefix, e.g. 192.168.100.22/24 (blank = none)"
  oninput="syncNodeIPMask(this,'vip_{{.Name}}','node_ip_{{.Name}}')"></td>
<td><input class="ip" name="scope_dhcp_start_{{.Name}}" value="{{index .DHCPRange 0}}" pattern="{{$.IPPattern}}" title="IPv4 address, e.g. 192.168.100.100"></td>
<td><input class="ip" name="scope_dhcp_end_{{.Name}}" value="{{index .DHCPRange 1}}" pattern="{{$.IPPattern}}" title="IPv4 address, e.g. 192.168.100.200"></td>
<td><input name="scope_gateway_{{.Name}}" id="gw_{{.Name}}" value="{{.Gateway}}" pattern="{{$.GatewayPattern}}" title="IPv4 address, e.g. 192.168.100.1, or a comma-separated list for failover alternatives"></td>
<td><input class="narrow" type="number" min="1" max="255" name="scope_vrrp_id_{{.Name}}" value="{{.VRRPID}}"></td>
<td><select name="scope_preferred_worker_{{.Name}}" id="preferred_{{.Name}}">
  <option value="core-1" {{if eq .PreferredWorker "core-1"}}selected{{end}}>core-1</option>
  <option value="core-2" {{if eq .PreferredWorker "core-2"}}selected{{end}}>core-2</option>
  <option value="core-3" {{if eq .PreferredWorker "core-3"}}selected{{end}}>core-3</option>
</select></td>
<td><input class="narrow" type="number" min="0" max="255000" name="scope_advert_int_ms_{{.Name}}" id="advert_{{.Name}}" value="{{.AdvertIntMS}}"></td>
<td><input class="narrow" type="number" min="0" max="3" name="scope_vrrp_version_{{.Name}}" id="vrrpver_{{.Name}}" value="{{.VRRPVersion}}"></td>
<td><textarea name="scope_dns_records_{{.Name}}" id="dns_{{.Name}}" rows="2">{{.DNSRecordsText}}</textarea></td>
<td><textarea name="scope_dhcp_options_{{.Name}}" id="dhcpopt_{{.Name}}" rows="2">{{.DHCPOptionsText}}</textarea></td>
</tr>
{{end}}

{{if .NewScopeSlots}}
<tr class="new-scope-header"><th>del</th><th>name</th><th>vlan_id</th><th>parent</th><th title="the floating IP DHCP clients are told is their gateway/DNS server — moves between workers on failover">vip</th><th title="each worker's own fixed address on this VLAN (e.g. core-1=.22, core-2=.23) — required for VRRP to actually work. A brand-new scope gets one derived automatically per worker when committed; an already-existing scope with none stays stuck in VRRP FAULT forever and never serves DHCP until one is set directly here">node_ip</th>
<th>dhcp start</th><th>dhcp end</th><th title="the real router address handed to clients — often the same as vip, but doesn't have to be">gateway</th><th title="VRRP router ID — must be unique among every scope sharing this VLAN's broadcast domain">vrrp_id</th>
<th title="which core node normally serves this scope — another takes over automatically if it goes down">preferred core</th><th>advert_ms</th><th>vrrp_ver</th><th>dns_records</th><th>dhcp_options</th></tr>
{{end}}
{{range .NewScopeSlots}}
<tr data-search="new scope slot {{.}}" id="new-scope-slot">
<td></td>
<td><input name="scope_name_new_{{.}}" placeholder="(blank = unused)"></td>
<td><input class="narrow" type="number" min="0" max="4094" name="scope_vlan_id_new_{{.}}" title="0 = untagged (bind directly to the parent interface, no VLAN sub-interface)"></td>
<td><select name="scope_parent_new_{{.}}" id="parent_new_{{.}}">
  <option value="">--</option>
  {{range $workers}}<option value="{{.}}">{{.}}</option>{{end}}
</select></td>
<td><input name="scope_vip_new_{{.}}" id="vip_new_{{.}}" pattern="{{$.IPCIDRPattern}}" title="IPv4 address with prefix, e.g. 192.168.100.1/24 — or type a bare network (192.168.100.0/24) to auto-fill from your configured vip preference"
  data-gw-target="gw_new_{{.}}" data-gw-suffix="{{$.GatewaySuffix}}" data-vip-suffix="{{$.VIPSuffix}}"
  oninput="autoVIPFromNetwork(this);autoGateway(this);syncNodeIPMask(this,'vip_new_{{.}}','node_ip_new_{{.}}')"></td>
<td><input name="scope_node_ip_new_{{.}}" id="node_ip_new_{{.}}" pattern="{{$.IPCIDRPattern}}" title="IPv4 address with prefix (blank = none)"
  oninput="syncNodeIPMask(this,'vip_new_{{.}}','node_ip_new_{{.}}')"></td>
<td><input class="ip" name="scope_dhcp_start_new_{{.}}" pattern="{{$.IPPattern}}" title="IPv4 address"></td>
<td><input class="ip" name="scope_dhcp_end_new_{{.}}" pattern="{{$.IPPattern}}" title="IPv4 address"></td>
<td><input name="scope_gateway_new_{{.}}" id="gw_new_{{.}}" pattern="{{$.GatewayPattern}}" title="IPv4 address, or a comma-separated list for failover alternatives"></td>
<td><input class="narrow vrrp-suggest" type="number" min="1" max="255" name="scope_vrrp_id_new_{{.}}" data-used-vrrp-ids="{{$.UsedVRRPIDs}}"></td>
<td><select name="scope_preferred_worker_new_{{.}}" id="preferred_new_{{.}}" title="defaults to whichever core node currently has fewer configured scopes">
  <option value="core-1" {{if eq $.PreferredWorkerDefault "core-1"}}selected{{end}}>core-1</option>
  <option value="core-2" {{if eq $.PreferredWorkerDefault "core-2"}}selected{{end}}>core-2</option>
  <option value="core-3" {{if eq $.PreferredWorkerDefault "core-3"}}selected{{end}}>core-3</option>
</select></td>
<td><input class="narrow" type="number" min="0" max="255000" name="scope_advert_int_ms_new_{{.}}" id="advert_new_{{.}}" value="{{if $.AdvertIntMS}}{{$.AdvertIntMS}}{{end}}"></td>
<td><input class="narrow" type="number" min="0" max="3" name="scope_vrrp_version_new_{{.}}" id="vrrpver_new_{{.}}" value="{{if $.VRRPVersion}}{{$.VRRPVersion}}{{end}}"></td>
<td><textarea name="scope_dns_records_new_{{.}}" id="dns_new_{{.}}" rows="2"></textarea></td>
<td><textarea name="scope_dhcp_options_new_{{.}}" id="dhcpopt_new_{{.}}" rows="2"></textarea></td>
</tr>
{{end}}
</tbody>
</table>
</div>

<p class="dim">To rename a scope: check "del" above and add it again as a new
scope below — renaming isn't supported directly. Typing into a new-scope
row's VIP field auto-fills that row's own empty gateway field from the
cluster's new-scope defaults (<a href="/config">edit &rarr;</a>).</p>

<p><input type="submit" value="Stage as pending change"></p>
</form>
` + scopeEditorScriptHTML + vrrpSuggestScriptHTML))
