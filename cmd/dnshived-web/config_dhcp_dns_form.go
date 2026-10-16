// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import "html/template"

var dhcpDNSConfigFormTmpl = template.Must(template.New("config-dhcp-dns").Parse(`<!doctype html>
<title>dnshived-web — DHCP &amp; DNS</title>
` + styleHTML + templateBuilderStyleHTML + `
<h1>DHCP &amp; DNS</h1>
` + navHTML + pendingBannerHTML + `
<p>Snapshot from node: <strong>{{.SourceNode}}</strong>. Any save below
stages a <a href="/pending">pending change</a> — nothing applies until
you commit it. Elsewhere: <a href="/config">cluster config</a>,
<a href="/security">security</a>, <a href="/backup">config management</a>,
<a href="/config/scopes">scopes</a>, <a href="/scopes/options">scope
options</a>, <a href="/probes#settings">DNS probe checks</a>.</p>

<h2 id="domains">Local domains &amp; hostnames</h2>
<p class="dim">Named DNS zones (e.g. <code>foo.lan</code>) — resolve
cluster-wide, same as Global DNS records below. TTL: per-domain default,
overridable per host. Bulk textarea = one record per line; the picker
above it fills a line for you. Fork a domain to start a new one as its
live-synced copy — every edit to the original pushes to its forks too,
until unlinked. Click a domain's own summary line below to edit it.</p>
{{range .LocalDomains}}
<details class="tpl-picker-item">
<summary>{{.Name}} <span class="dim">({{.RecordCount}} record(s), TTL {{if .TTL}}{{.TTL}}s{{else}}default{{end}}{{if .ForkedFrom}}, forked from {{.ForkedFrom}}{{end}})</span></summary>

<form method="post" action="{{.SaveHref}}" onsubmit="return confirm('This will stage this domain\'s records as a pending change on every configured node — nothing is applied until you commit from Pending changes. Continue?')">
<label>Domain TTL (seconds, blank/0 = dnsmasq default)<br><input type="number" name="ttl" min="0" value="{{.TTL}}"></label>
{{.Builder}}
<textarea name="records" id="{{.TextareaID}}" rows="6" cols="70">{{.RecordsText}}</textarea>
<p><input type="submit" value="Stage {{.Name}} as pending change"></p>
</form>

{{if .ForkedFrom}}
<form method="post" action="{{.UnlinkHref}}" style="display:inline" onsubmit="return confirm('Unlink {{.Name}} from {{.ForkedFrom}}? Its current records stay as-is, but future edits to {{.ForkedFrom}} will no longer be pushed here.')">
<button type="submit">unlink from {{.ForkedFrom}}</button>
</form>
{{else}}
<form method="post" action="{{.ForkHref}}" style="display:inline">
<input name="new_name" placeholder="fork as e.g. newdomain.tld" pattern="^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$" title="a valid domain name" required>
<button type="submit" title="creates a new domain starting as a copy of this one, and keeps it live-synced to every future edit here until unlinked">fork {{.Name}}</button>
</form>
{{end}}
<form method="post" action="{{.DeleteHref}}" style="display:inline" onsubmit="return confirm('Delete domain {{.Name}} and every host record under it?')">
<button type="submit">delete {{.Name}}</button>
</form>
</details>
{{else}}<p class="dim">no local domains yet</p>{{end}}

<h3>+ Add a domain</h3>
<form method="post" action="/config/domains/new">
<input name="name" placeholder="e.g. foo.lan" required pattern="^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$" title="a valid domain name, e.g. foo.lan">
<input type="number" name="ttl" min="0" placeholder="TTL seconds (optional)">
<button type="submit">+ add domain</button>
</form>

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
<textarea name="global_dns_records" id="global_dns_records" rows="6" cols="70">{{.DNS.GlobalDNSRecordsText}}</textarea>

<p><input type="submit" value="Stage DNS defaults as pending change"></p>
</form>

<p class="dim">Default DNS probe checks moved to
<a href="/probes#settings">Probes &rarr;</a> — the checks that DRIVE
probing now live next to the probing RESULTS.</p>

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
<textarea name="default_dhcp_options" rows="4" cols="60">{{.DHCP.DefaultDHCPOptionsText}}</textarea>

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

<h2 id="templates">Templates</h2>
<p class="dim">Reusable, named sets of DHCP options or DNS records —
applied per scope from the <a href="/scopes/wizard">Add Scope
wizard</a>, or pasted by hand into any scope's own fields above. Deleting a
template never affects a scope that already applied it this way (its text was
copied in, not linked). To bundle several templates together and apply — and
keep — them across many scopes at once, see <a href="/optionsets">Option
sets</a>, <a href="/rollout">mass-rollout</a>, and <a href="/groups">scope
groups</a>.</p>

<h3>DHCP option sets</h3>
<div class="table-wrap"><table><tr><th>name</th><th>preview</th><th></th></tr>
{{range .DHCPTemplates}}
<tr><td><span class="name-dot" style="background:{{.Color}}"></span>{{.Name}}</td>
<td class="dim"><pre style="margin:0;white-space:pre-wrap">{{.Body}}</pre></td>
<td><a href="{{.EditHref}}">edit</a>
<form method="post" action="{{.DeleteHref}}" style="display:inline" onsubmit="return confirm('Delete template {{.Name}}?')"><button type="submit">delete</button></form></td></tr>
{{else}}<tr><td colspan="3" class="dim">none yet</td></tr>{{end}}
</table></div>

<h3>DNS record sets</h3>
<div class="table-wrap"><table><tr><th>name</th><th>preview</th><th></th></tr>
{{range .DNSTemplates}}
<tr><td><span class="name-dot" style="background:{{.Color}}"></span>{{.Name}}</td>
<td class="dim"><pre style="margin:0;white-space:pre-wrap">{{.Body}}</pre></td>
<td><a href="{{.EditHref}}">edit</a>
<form method="post" action="{{.DeleteHref}}" style="display:inline" onsubmit="return confirm('Delete template {{.Name}}?')"><button type="submit">delete</button></form></td></tr>
{{else}}<tr><td colspan="3" class="dim">none yet</td></tr>{{end}}
</table></div>

<h3>DNS server for clients</h3>
<p class="dim"><span class="info-ico" title="DHCP option 6 — the DNS server(s) clients are told to use. A single IP, or a comma-separated list.">&#9432;</span>
Named "dnshived vs. other" overrides — a single value, picking one
REPLACES a scope's own choice rather than adding to it (unlike the
sets above).</p>
<div class="table-wrap"><table><tr><th>name</th><th>preview</th><th></th></tr>
{{range .ClientDNSTemplates}}
<tr><td><span class="name-dot" style="background:{{.Color}}"></span>{{.Name}}</td>
<td class="dim">{{.Body}}</td>
<td><a href="{{.EditHref}}">edit</a>
<form method="post" action="{{.DeleteHref}}" style="display:inline" onsubmit="return confirm('Delete template {{.Name}}?')"><button type="submit">delete</button></form></td></tr>
{{else}}<tr><td colspan="3" class="dim">none yet</td></tr>{{end}}
</table></div>

<p><a href="/templates/new">+ New template</a></p>
`))
