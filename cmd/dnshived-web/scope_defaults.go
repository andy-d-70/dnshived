// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"dnshived/internal/config"
)

// scopeDefaultsFormTmpl renders "Scope VIP preference" and "New-scope
// defaults" under Scope general options.
var scopeDefaultsFormTmpl = template.Must(template.New("scope_defaults").Parse(`<!doctype html>
<title>dnshived-web — scope general options</title>
` + styleHTML + `
<h1>Scope — general options</h1>
` + navHTML + pendingBannerHTML + `
<p>Snapshot from node: <strong>{{.SourceNode}}</strong>. Saving stages a
PENDING change on every configured node — nothing is applied until you
commit it from <a href="/pending">pending changes</a>. Scope
DEFINITIONS live on their own page:
<a href="/config/scopes">edit scopes &rarr;</a>.</p>

<form method="post" action="/scopes/options" onsubmit="return confirm('This will stage these scope defaults as a pending change on every configured node — nothing is applied until you commit from Pending changes. Continue?')">

<h2>Scope VIP preference</h2>
<p class="dim">Set the last octet you want used by default — e.g. "50"
against a scope subnet of 192.168.105.0/24 suggests vip
192.168.105.50/24 in both the <a href="/scopes/wizard">Add Scope
wizard</a> and the bulk scope table's new-scope row. Only ever
pre-fills; you can always type a different address per scope. Checked
for valid syntax (a real 0-255 octet) on save — YOU are responsible
for making sure the resulting address is actually free and usable on
each scope's own VLAN, the same as any other address you type by
hand.</p>
<table border="1" cellpadding="4">
<tr><td>vip suffix</td><td><input type="number" min="0" max="255" name="scope_defaults_vip_suffix" value="{{.ScopeDefaultsVIPSuffix}}" size="10"></td></tr>
</table>

<h2>New-scope defaults</h2>
<p class="dim">Pre-fills the scope editor's "add new scope" row — never applied
to an existing scope, and only ever fills an EMPTY field there. Not read by the
daemon at all (see config.ScopeDefaults' own doc comment) — <strong>except default
upstream DNS below</strong>, which is genuinely read: it's the real upstream
forwarding list for the shared DNS relay, not just a form pre-fill.</p>
<table border="1" cellpadding="4">
<tr><td>gateway suffix<br><small>(e.g. "1" — with a new scope's VIP entered as
192.168.5.1/24, its gateway auto-fills as 192.168.5.1 unless you've already
typed one yourself)</small></td><td><input name="scope_defaults_gateway_suffix" value="{{.ScopeDefaultsGatewaySuffix}}" size="10"></td></tr>
<tr><td>node_ip suffix per node<br><small>Each worker's own fixed last octet on ANY VLAN scope (e.g. worker-a=22, worker-b=23) — required for VRRP to actually work, used automatically for every new scope going forward. A worker with no suffix set here still gets one auto-derived from its own management address (verified live), but setting it explicitly here gives you real control and makes it visible instead of implicit.</small><br>
{{range .ScopeDefaultsNodeIPSuffixes}}{{.Name}}: <input name="scope_defaults_node_ip_suffix_{{.Name}}" value="{{.Suffix}}" size="6"> {{end}}</td></tr>
<tr><td>dhcp range suffixes<br><small>(same wizard subnet field — start/end, e.g. "100"/"200")</small></td><td>
<input name="scope_defaults_dhcp_start_suffix" value="{{.ScopeDefaultsDHCPStartSuffix}}" size="10"> &ndash;
<input name="scope_defaults_dhcp_end_suffix" value="{{.ScopeDefaultsDHCPEndSuffix}}" size="10"></td></tr>
<tr><td>default upstream DNS (one per line)</td><td><textarea name="scope_defaults_upstream" rows="3" cols="20">{{.ScopeDefaultsUpstreamText}}</textarea></td></tr>
<tr><td>default advert_int_ms <span class="info-ico" title="how often keepalived sends VRRP advertisements for a scope's own VIP — lower means faster failover detection (a real bench: version 3 + 150ms advert_int ≈ 580ms clean handover) at the cost of more background traffic. Blank = daemon's own built-in default; safe to leave alone unless you have a specific failover-speed requirement.">ⓘ</span><br><small>(blank = daemon's own built-in default)</small></td><td><input type="number" min="0" max="255000" name="scope_defaults_advert_int_ms" value="{{if .ScopeDefaultsAdvertIntMS}}{{.ScopeDefaultsAdvertIntMS}}{{end}}" size="10"></td></tr>
<tr><td>default vrrp_version <span class="info-ico" title="the VRRP protocol version keepalived speaks for a scope's own VIP (2 or 3) — version 3 supports sub-second advertisement intervals, version 2 doesn't. Blank = daemon's own built-in default; safe to leave alone unless you have a specific failover-speed requirement.">ⓘ</span><br><small>(blank = daemon's own built-in default)</small></td><td><input type="number" min="0" max="3" name="scope_defaults_vrrp_version" value="{{if .ScopeDefaultsVRRPVersion}}{{.ScopeDefaultsVRRPVersion}}{{end}}" size="10"></td></tr>
</table>

<p><input type="submit" value="Stage as pending change"></p>
</form>
`))

func handleScopeDefaultsGet(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		c, node, isPending, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "could not read config from any node: "+err.Error(), http.StatusBadGateway)
			return
		}
		data := buildClusterFormData(c, node, nodesIncludingSelf(cfg))
		data.Pending = isPending
		renderTemplate(w, scopeDefaultsFormTmpl, data, "scope_defaults")
	}
}

// handleScopeDefaultsPost mirrors handleSecurityPost's own pattern
// exactly.
func handleScopeDefaultsPost(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		current, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "could not read current config: "+err.Error(), http.StatusBadGateway)
			return
		}

		f := r.PostForm
		var scopeDefaults *config.ScopeDefaults
		advertIntMS, _ := strconv.Atoi(f.Get("scope_defaults_advert_int_ms"))
		vrrpVersion, _ := strconv.Atoi(f.Get("scope_defaults_vrrp_version"))
		gatewaySuffix := strings.TrimSpace(f.Get("scope_defaults_gateway_suffix"))
		vipSuffix := strings.TrimSpace(f.Get("scope_defaults_vip_suffix"))
		dhcpStartSuffix := strings.TrimSpace(f.Get("scope_defaults_dhcp_start_suffix"))
		dhcpEndSuffix := strings.TrimSpace(f.Get("scope_defaults_dhcp_end_suffix"))
		upstream := splitLines(f.Get("scope_defaults_upstream"))
		nodeIPSuffixes := map[string]string{}
		for _, n := range nodesIncludingSelf(cfg) {
			if v := strings.TrimSpace(f.Get("scope_defaults_node_ip_suffix_" + n.Name)); v != "" {
				nodeIPSuffixes[n.Name] = v
			}
		}
		if gatewaySuffix != "" || vipSuffix != "" || len(nodeIPSuffixes) > 0 || dhcpStartSuffix != "" || dhcpEndSuffix != "" ||
			len(upstream) > 0 || advertIntMS > 0 || vrrpVersion > 0 {
			scopeDefaults = &config.ScopeDefaults{
				GatewaySuffix: gatewaySuffix, VIPSuffix: vipSuffix, NodeIPSuffixes: nodeIPSuffixes,
				DHCPStartSuffix: dhcpStartSuffix, DHCPEndSuffix: dhcpEndSuffix,
				Upstream: upstream, AdvertIntMS: advertIntMS, VRRPVersion: vrrpVersion,
			}
		}

		payload := clusterPushPayloadFrom(current)
		payload.Scopes = current.Scopes
		payload.ScopeDefaults = scopeDefaults

		user, _ := userFromContext(r)
		pushCandidateAndRenderResult(w, cfg, payload, user, "/scopes/options", "back to scope general options")
	}
}
