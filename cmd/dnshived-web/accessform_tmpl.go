// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import "html/template"

const accessPageStyle = `<style>
.acrow{display:flex;flex-wrap:nowrap;gap:.5rem;align-items:center;margin:.25rem 0}
.acrow .net{width:15rem;flex:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-variant-numeric:tabular-nums}
.acrow input[type=text]{flex:1 1 10rem;min-width:6rem}
.acrow select{flex:none}
.acrow label{flex:none;white-space:nowrap}
.acrow .sp{flex:0 0 7rem}
.achead{display:flex;gap:.5rem;font-weight:600;margin:.6rem 0 .2rem;color:var(--muted)}
.acadd{margin:.8rem 0;padding:.6rem;border:1px solid var(--border);border-radius:10px;background:var(--panel)}
.acnote{margin:.4rem 0;color:var(--muted)}
.acok{color:var(--ok)}.acbad{color:var(--crit)}.acwarn{color:var(--warn)}
</style>`

var accessPageTmpl = template.Must(template.New("access").Parse(`<!doctype html>
<title>dnshived-web — access list</title>
` + styleHTML + accessPageStyle + `
` + navHTML + `
<h1>Cluster settings</h1>
` + pendingBannerHTML + `
{{.Tabs}}
<p class="acnote">Who is allowed to be served by this cluster: DNS, DHCP and this web interface. Saving stages a PENDING change on every node; nothing applies until you commit it on <a href="/pending">pending changes</a>. Snapshot from node <strong>{{.SourceNode}}</strong>.</p>
{{.Sub}}
{{if .Notice}}<p class="acok">{{.Notice}}</p>{{end}}

{{if eq .Section "networks"}}
<h2>Who is served</h2>
<p class="acnote">A source that no entry allows gets no answer: not from DNS, not from DHCP, not from this web interface. The private networks are allowed by default. For every entry, DNS, DHCP and the web interface are allowed or denied on their own; the most specific entry decides, and on equal size deny wins. Whitelisted hosts are served before any entry.</p>
<form method="post" action="/config/access/save" class="acrow">
  <input type="hidden" name="op" value="mode"><input type="hidden" name="back" value="networks">
  <strong>Mode</strong>
  <label><input type="radio" name="mode" value="report" {{if not .Enforce}}checked{{end}}> Report only: nothing is dropped, sources that would be dropped are counted</label>
  <label><input type="radio" name="mode" value="enforce" {{if .Enforce}}checked{{end}}> Enforce: everything not allowed is dropped</label>
  <button type="submit" class="btn">Stage mode</button>
</form>
<p class="acnote">{{if .Active}}<span class="acok">Active:</span> every core runs a version that has the list; the relays and the web interface use it.{{else}}<span class="acwarn">Not active yet:</span> the list is stored but not used until every core runs version {{.Required}} or newer{{range .Blocking}} (waiting for {{.Name}}{{if .Version}}, {{.Version}}{{end}}){{end}}.{{end}}
 Always allowed, so the cluster cannot cut itself off: loopback, the node addresses and the VIPs.</p>
<p class="acnote">Your address: <strong>{{.YourAddr}}</strong> · web interface: {{.YourWeb}}</p>
{{range .NodeErrors}}<p class="acbad">{{.}}</p>{{end}}

<h2>Networks</h2>
<div class="achead"><span class="net">Network</span><span>On · note · DNS · DHCP · Web</span></div>
<form method="post" action="/config/access/save" class="acrow">
  <input type="hidden" name="op" value="private"><input type="hidden" name="back" value="networks">
  <span class="net" title="10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7">{{.Private.Net}}</span>
  <label><input type="checkbox" name="on" value="1" {{if .Private.On}}checked{{end}}> on</label>
  <input type="text" name="note" value="{{.Private.Note}}" aria-label="Note">
  <select name="dns" aria-label="DNS"><option value="allow" {{if eq .Private.DNS "allow"}}selected{{end}}>DNS allow</option><option value="deny" {{if eq .Private.DNS "deny"}}selected{{end}}>DNS deny</option></select>
  <select name="dhcp" aria-label="DHCP"><option value="allow" {{if eq .Private.DHCP "allow"}}selected{{end}}>DHCP allow</option><option value="deny" {{if eq .Private.DHCP "deny"}}selected{{end}}>DHCP deny</option></select>
  <select name="web" aria-label="Web"><option value="allow" {{if eq .Private.Web "allow"}}selected{{end}}>Web allow</option><option value="deny" {{if eq .Private.Web "deny"}}selected{{end}}>Web deny</option></select>
  <button type="submit" class="btn quiet sm">Stage</button>
</form>
{{template "pagerbar" .PagerTop}}
{{range .Lines}}
<form method="post" action="/config/access/save" class="acrow">
  <input type="hidden" name="op" value="entry-set"><input type="hidden" name="back" value="networks"><input type="hidden" name="net" value="{{.Net}}">
  <span class="net" title="{{.Net}}">{{.Net}}</span>
  <label><input type="checkbox" name="on" value="1" {{if .On}}checked{{end}}> on</label>
  <input type="text" name="note" value="{{.Note}}" aria-label="Note">
  <select name="dns" aria-label="DNS"><option value="allow" {{if eq .DNS "allow"}}selected{{end}}>DNS allow</option><option value="deny" {{if eq .DNS "deny"}}selected{{end}}>DNS deny</option></select>
  <select name="dhcp" aria-label="DHCP"><option value="allow" {{if eq .DHCP "allow"}}selected{{end}}>DHCP allow</option><option value="deny" {{if eq .DHCP "deny"}}selected{{end}}>DHCP deny</option></select>
  <select name="web" aria-label="Web"><option value="allow" {{if eq .Web "allow"}}selected{{end}}>Web allow</option><option value="deny" {{if eq .Web "deny"}}selected{{end}}>Web deny</option></select>
  <button type="submit" class="btn quiet sm">Stage</button>
  <button type="submit" class="btn quiet sm" name="op" value="entry-del" onclick="return confirm('Remove {{.Net}} from the list?')">Remove</button>
</form>
{{else}}<p class="acnote">No network added yet. Only the private networks are allowed.</p>{{end}}
{{template "pagerbar" .PagerBot}}
<form method="post" action="/config/access/save" class="acadd">
  <input type="hidden" name="op" value="entry-add"><input type="hidden" name="back" value="networks">
  <strong>Add a network</strong>
  <div class="acrow">
    <input type="text" name="net" placeholder="203.0.113.0/24" aria-label="Network" required>
    <input type="text" name="note" placeholder="note (optional)" aria-label="Note">
    <select name="dns" aria-label="DNS"><option value="allow">DNS allow</option><option value="deny">DNS deny</option></select>
    <select name="dhcp" aria-label="DHCP"><option value="allow">DHCP allow</option><option value="deny">DHCP deny</option></select>
    <select name="web" aria-label="Web"><option value="allow">Web allow</option><option value="deny">Web deny</option></select>
    <label title="Needed for a network that allows everyone or a very wide range"><input type="checkbox" name="confirm" value="1"> I understand</label>
    <button type="submit" class="btn">Add</button>
  </div>
</form>
{{end}}

{{if eq .Section "hosts"}}
<h2>Whitelisted hosts</h2>
<p class="acnote">Single hosts that are served no matter what: before any block and even outside the allowed networks. DNS and the web interface match the address; DHCP matches the MAC address (a DHCP client has no address yet).</p>
{{template "pagerbar" .PagerTop}}
<div class="achead"><span class="net">Address · MAC</span><span>Note · DNS · DHCP · Web</span></div>
{{range .Hosts}}
<form method="post" action="/config/access/save" class="acrow">
  <input type="hidden" name="op" value="host-set"><input type="hidden" name="back" value="hosts"><input type="hidden" name="key" value="{{.Key}}">
  <span class="net" title="{{.Addr}} {{.MAC}}">{{if .Addr}}{{.Addr}}{{else}}–{{end}} · {{if .MAC}}{{.MAC}}{{else}}–{{end}}</span>
  <input type="text" name="note" value="{{.Note}}" aria-label="Note">
  <label><input type="checkbox" name="hdns" value="1" {{if .DNS}}checked{{end}}> DNS</label>
  <label><input type="checkbox" name="hdhcp" value="1" {{if .DHCP}}checked{{end}}> DHCP</label>
  <label><input type="checkbox" name="hweb" value="1" {{if .Web}}checked{{end}}> Web</label>
  <button type="submit" class="btn quiet sm">Stage</button>
  <button type="submit" class="btn quiet sm" name="op" value="host-del">Remove</button>
</form>
{{else}}<p class="acnote">No whitelisted host yet.</p>{{end}}
{{template "pagerbar" .PagerBot}}
<form method="post" action="/config/access/save" class="acadd">
  <input type="hidden" name="op" value="host-add"><input type="hidden" name="back" value="hosts">
  <strong>Whitelist a host</strong>
  <div class="acrow">
    <input type="text" name="addr" placeholder="address (for DNS and web)" aria-label="Address">
    <input type="text" name="mac" placeholder="MAC (for DHCP)" aria-label="MAC">
    <input type="text" name="note" placeholder="note (optional)" aria-label="Note">
    <label><input type="checkbox" name="hdns" value="1" checked> DNS</label>
    <label><input type="checkbox" name="hdhcp" value="1"> DHCP</label>
    <label><input type="checkbox" name="hweb" value="1"> Web</label>
    <button type="submit" class="btn">Add</button>
  </div>
</form>
{{end}}

{{if eq .Section "report"}}
<h2>Would this be served?</h2>
<form method="get" action="/config/access/report" class="acrow">
  <input type="text" name="test" value="{{.TestAddr}}" placeholder="address or MAC, e.g. 203.0.113.9" aria-label="Address or MAC to test">
  <button type="submit" class="btn">Test</button>
</form>
{{range .Test}}<p class="acrow"><strong class="sp">{{.Service}}</strong> <span class="{{if eq .Verdict "served"}}acok{{else}}acbad{{end}}">{{.Verdict}}</span> <span class="acnote">{{.Why}}</span></p>{{end}}
<h2>{{if .Enforce}}Dropped{{else}}Would have been dropped{{end}} by the relays</h2>
<p class="acnote">What the DNS and DHCP relays refused (or would refuse in report mode) since they started, per node. The web interface on this node: {{.WebDropped}} connection(s) dropped.</p>
{{template "pagerbar" .PagerTop}}
{{if .Report}}
<table border="1" cellpadding="4">
<tr><th>Node</th><th>Service</th><th>Source</th><th>Count</th><th>Last</th></tr>
{{range .Report}}<tr><td>{{.Node}}</td><td>{{.Service}}</td><td>{{.Source}}</td><td>{{.Count}}</td><td>{{.Last}}</td></tr>{{end}}
</table>
{{else}}<p class="acnote">Nothing reported.</p>{{end}}
{{template "pagerbar" .PagerBot}}
{{range .NodeErrors}}<p class="acbad">{{.}}</p>{{end}}
{{end}}
` + pagerBarDefineHTML))
