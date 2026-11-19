// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import "html/template"

var dhcpDNSConfigFormTmpl = template.Must(template.New("config-dhcp-dns").Parse(`<!doctype html>
<title>dnshived-web — {{.Title}}</title>
` + styleHTML + templateBuilderStyleHTML + `
` + navHTML + pendingBannerHTML + `
<h1>{{.Title}}</h1>

<p>Snapshot from node: <strong>{{.SourceNode}}</strong>. Any save below
stages a <a href="/pending">pending change</a> — nothing applies until
you commit it. Elsewhere: <a href="/hosts">hosts</a>, <a href="/config">cluster settings</a>,
<a href="/security">security</a>, <a href="/backup">maintenance</a>,
<a href="/config/scopes">scopes</a>, <a href="/scopes/options">scope
options</a>, <a href="/probes#tab-behavior">DNS probe checks</a>.</p>

{{if .ShowDNS}}<script>if(/^#(tab-)?(dhcp|dhcp-templates)$/.test(location.hash))location.replace("/config/dhcp"+location.hash);if(/^#(tab-)?domains$/.test(location.hash))location.replace("/config/domains");</script>{{end}}
<div class="tab-host"{{if .ShowDNS}} data-extra-tabs='[["Domains","/config/domains","DNS records &amp; checks"]]'{{end}}>
{{if .ShowDNS}}<section class="tab-pane" id="tab-dns" data-tab="DNS records &amp; checks" data-tab-order="2"{{if not .ShowDHCP}} data-tab-default{{end}}>
<h2 id="dns">DNS defaults</h2>
<form method="post" action="/config/dns" onsubmit="return confirm('This will stage these DNS defaults as a pending change on every configured node — nothing is applied until you commit from Pending changes. Continue?')">

<h3>Global DNS records</h3>
<p class="dim">Applies to every scope. One per line:
<code>TYPE|NAME|VALUE</code> (A/AAAA/CNAME/TXT/PTR),
<code>MX|NAME|TARGET|PRIORITY</code>,
<code>SRV|NAME|TARGET|PORT|PRIORITY|WEIGHT</code>,
<code>NAPTR|NAME|TARGET|ORDER|PRIORITY|FLAGS|SERVICE|REGEXP</code>,
<code>CAA|NAME|FLAGS|TAG|VALUE</code>,
<code>RAW|NAME|RR_TYPE|RR_DATA_HEX</code>. Optional trailing
<code>|ttl=N</code> (A/AAAA/CNAME only) and/or <code>|disabled</code>
(keeps the record, skips probing it). For anything with real structure
(multiple hosts, its own TTL), a local domain above usually fits
better. Named boilerplate lives under <a href="#templates">Templates</a>
— apply per-scope from that scope's page or the
<a href="/scopes/wizard">wizard</a>, not here.</p>
{{.GlobalDNSBuilder}}
<textarea name="global_dns_records" id="global_dns_records" rows="6" cols="70" data-line-list>{{.DNS.GlobalDNSRecordsText}}</textarea>

<p><input type="submit" value="Stage DNS defaults as pending change"></p>
</form>

<p class="dim">Default DNS probe checks moved to
<a href="/probes#tab-behavior">Probes &rarr;</a> — the checks that DRIVE
probing now live next to the probing RESULTS.</p>

</section>
{{end}}{{if .ShowDHCP}}<section class="tab-pane" id="tab-dhcp" data-tab="Default DHCP options" data-tab-order="1" data-tab-default>
<h2 id="dhcp">DHCP defaults</h2>
<form method="post" action="/config/dhcp" onsubmit="return confirm('This will stage this DHCP default as a pending change on every configured node — nothing is applied until you commit from Pending changes. Continue?')">

<h3>Default DHCP options</h3>
<p class="dim">Applied to every scope with none of its own (a scope's own
setting replaces this entirely, doesn't add to it). One raw
<code>dhcp-option=</code> value per line, e.g.
<code>option:domain-search,corp.local</code>,
<code>option:ntp-server,10.0.0.1</code>, or
<code>252,http://wpad.corp.local/wpad.dat</code> (WPAD has no symbolic
name in dnsmasq).</p>
{{.DefaultDHCPBuilder}}
<textarea name="default_dhcp_options" rows="4" cols="60" data-line-list>{{.DHCP.DefaultDHCPOptionsText}}</textarea>

<p><input type="submit" value="Stage DHCP default as pending change"></p>
</form>

<h3>Per-scope DHCP options</h3>
<p class="dim">Read-only — edit a scope's own dhcp_options from
<a href="/config/scopes">the bulk scope editor</a> or that scope's own
<a href="/scopes">detail page</a>.</p>
<div class="table-wrap"><table border="1" cellpadding="4" cellspacing="0">
<tr><th>Scope</th><th>VLAN</th><th>dhcp_options</th></tr>
{{range .DHCP.Scopes}}
<tr>
  <td><a href="/scopes/{{.Name}}">{{.Name}}</a></td>
  <td>{{.VLANID}}</td>
  <td>{{if .UsesDefault}}<span class="dim">(uses default above)</span>{{else}}<pre style="margin:0">{{.DHCPOptionsText}}</pre>{{end}}</td>
</tr>
{{end}}
</table></div>

</section>{{end}}
<section class="tab-pane" id="tab-templates" data-tab="Templates" data-tab-order="3">
<h2 id="templates">Templates</h2>
<p class="dim">Reusable, named sets of DHCP options or DNS records —
applied per scope from the <a href="/scopes/wizard">Add Scope
wizard</a>, or pasted by hand into any scope's own fields above. Deleting a
template never affects a scope that already applied it this way (its text was
copied in, not linked). To bundle several templates together and apply — and
keep — them across many scopes at once, see <a href="/optionsets">Option
sets</a>, <a href="/rollout">mass-rollout</a>, and <a href="/groups">scope
groups</a>.</p>

{{if .ShowDHCP}}<h3>DHCP option sets</h3>
<div class="table-wrap"><table data-stack><tr><th>name</th><th>preview</th><th></th></tr>
{{range .DHCPTemplates}}
<tr><td><span class="name-dot" style="background:{{.Color}}"></span>{{.Name}}</td>
<td class="dim"><pre style="margin:0;white-space:pre-wrap">{{.Body}}</pre></td>
<td style="width:3rem;text-align:center"><details class="row-menu"><summary aria-haspopup="menu" title="actions for {{.Name}}">&#9776;</summary>
<div class="row-menu-list" role="menu">
<a role="menuitem" href="{{.EditHref}}">Edit</a>
<form method="post" action="{{.DeleteHref}}" onsubmit="return confirm('Delete template {{.Name}}?')"><button type="submit" role="menuitem" class="danger">Delete…</button></form>
</div></details></td></tr>
{{else}}<tr><td colspan="3" class="dim">none yet</td></tr>{{end}}
</table></div>

{{end}}{{if .ShowDNS}}<h3>DNS record sets</h3>
<div class="table-wrap"><table data-stack><tr><th>name</th><th>preview</th><th></th></tr>
{{range .DNSTemplates}}
<tr><td><span class="name-dot" style="background:{{.Color}}"></span>{{.Name}}</td>
<td class="dim"><pre style="margin:0;white-space:pre-wrap">{{.Body}}</pre></td>
<td style="width:3rem;text-align:center"><details class="row-menu"><summary aria-haspopup="menu" title="actions for {{.Name}}">&#9776;</summary>
<div class="row-menu-list" role="menu">
<a role="menuitem" href="{{.EditHref}}">Edit</a>
<form method="post" action="{{.DeleteHref}}" onsubmit="return confirm('Delete template {{.Name}}?')"><button type="submit" role="menuitem" class="danger">Delete…</button></form>
</div></details></td></tr>
{{else}}<tr><td colspan="3" class="dim">none yet</td></tr>{{end}}
</table></div>

{{end}}{{if .ShowDHCP}}<h3>DNS server for clients</h3>
<p class="dim"><span class="info-ico" title="DHCP option 6 — the DNS server(s) clients are told to use. A single IP, or a comma-separated list.">&#9432;</span>
Named "dnshived vs. other" overrides — a single value, picking one
REPLACES a scope's own choice rather than adding to it (unlike the
sets above).</p>
<div class="table-wrap"><table data-stack><tr><th>name</th><th>preview</th><th></th></tr>
{{range .ClientDNSTemplates}}
<tr><td><span class="name-dot" style="background:{{.Color}}"></span>{{.Name}}</td>
<td class="dim">{{.Body}}</td>
<td style="width:3rem;text-align:center"><details class="row-menu"><summary aria-haspopup="menu" title="actions for {{.Name}}">&#9776;</summary>
<div class="row-menu-list" role="menu">
<a role="menuitem" href="{{.EditHref}}">Edit</a>
<form method="post" action="{{.DeleteHref}}" onsubmit="return confirm('Delete template {{.Name}}?')"><button type="submit" role="menuitem" class="danger">Delete…</button></form>
</div></details></td></tr>
{{else}}<tr><td colspan="3" class="dim">none yet</td></tr>{{end}}
</table></div>

{{end}}<p><a href="/templates/new">+ New template</a></p>
</section>
</div>
` + rowMenuScriptHTML + ``))
