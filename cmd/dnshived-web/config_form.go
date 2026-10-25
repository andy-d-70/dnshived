// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import "html/template"

// configFormTmpl is the cluster-wide settings editor; scopes have their
// own editor.
var configFormTmpl = template.Must(template.New("config").Parse(`<!doctype html>
<title>dnshived-web — config editor</title>
` + styleHTML + logModalScriptHTML + `
<h1>Config editor — cluster</h1>
` + navHTML + `
<div class="view-tabs"><span class="active">Settings</span><a href="/config/mail">Mail &rarr;</a><a href="/daemons">Daemons &rarr;</a></div>
` + pendingBannerHTML + `
<p>Snapshot from node: <strong>{{.SourceNode}}</strong>. Saving stages a
PENDING change on every configured node — nothing is applied until you
commit it from <a href="/pending">pending changes</a>. Scope definitions live on their
own page: <a href="/config/scopes">edit scopes &rarr;</a>. DNS/DHCP
defaults and the template library live on another:
<a href="/config/dns">edit DHCP &amp; DNS &rarr;</a>. To change your own
login password: <a href="/password">change password &rarr;</a>. Export/
import/backup moved to their own page:
<a href="/backup">config management &rarr;</a>. API tokens moved
to <a href="/security">security &rarr;</a>. Scope VIP preference and
new-scope defaults moved to
<a href="/scopes/options">scope — general options &rarr;</a>. Probe
hosts (add/remove/rename, parallel probing, probe-behavior settings)
moved to <a href="/probes#settings">probes &rarr;</a>.</p>

<form method="post" action="/config" onsubmit="return confirm('This will stage these cluster settings as a pending change on every configured node — nothing is applied until you commit from Pending changes. Continue?')">

<h2>Cluster-wide settings</h2>
<table border="1" cellpadding="4">
<tr><td>psk</td><td><input type="password" name="psk" value="" size="60" autocomplete="new-password" placeholder="unchanged — type a new PSK to replace it" title="The PSK is never sent to the browser. Leave blank to keep the current one."></td></tr>
<tr><td>trusted_hosts<br><small>(one IP per line — source-IP allowlist for the arbiter's token endpoints and /api/v1/ping; empty = allow any source)</small></td><td><textarea name="trusted_hosts" rows="4" cols="40">{{range .Cluster.TrustedHosts}}{{.}}
{{end}}</textarea></td></tr>
<tr><td>tls_cert</td><td><input name="tls_cert" value="{{.Cluster.TLSCert}}" size="60"></td></tr>
<tr><td>tls_key</td><td><input type="text" name="tls_key" value="{{.Cluster.TLSKey}}" size="60"> (a filesystem path, not the key material itself — not sensitive)</td></tr>
<tr><td>log_level <span class="info-ico" title="auto (default): info, plus debug detail for a subsystem for 5 minutes after it warns, and a summary of suppressed routine messages every 10 minutes. info: state changes (scope gained or lost, VRRP, DHCP gate, failover, config commits, nodes joining or leaving). warning: errors, failures, denials and refusals only. debug: every routine success (witness renewals, peer pings, probe results) — very verbose, for short troubleshooting.">ⓘ</span></td><td>
  <select name="log_level">
    <option value="" {{if eq .Cluster.LogLevel ""}}selected{{end}}>auto</option>
    <option value="debug" {{if eq .Cluster.LogLevel "debug"}}selected{{end}}>debug</option>
    <option value="info" {{if eq .Cluster.LogLevel "info"}}selected{{end}}>info</option>
    <option value="warning" {{if eq .Cluster.LogLevel "warning"}}selected{{end}}>warning</option>
  </select>
</td></tr>
</table>

<h2>Platform</h2>
<table border="1" cellpadding="4">
<tr><td>mgmt interface</td><td><input name="platform_mgmt" value="{{if .Cluster.Platform}}{{.Cluster.Platform.Mgmt}}{{end}}"></td></tr>
<tr><td>worker interfaces (one per line)</td><td><textarea name="platform_workers" rows="3" cols="30">{{if .Cluster.Platform}}{{range .Cluster.Platform.Workers}}{{.}}
{{end}}{{end}}</textarea></td></tr>
<tr><td>worker interface display names<br><small>(optional, cosmetic only — one per line, format <code>iface=Display Name</code>; blank = show the raw interface name)</small></td><td><textarea name="platform_worker_labels" rows="3" cols="30">{{if .Cluster.Platform}}{{range .Cluster.Platform.Workers}}{{$label := index $.Cluster.Platform.InterfaceLabels .}}{{if $label}}{{.}}={{$label}}
{{end}}{{end}}{{end}}</textarea></td></tr>
</table>

<h2>Management VIP (web UI access)</h2>
<table border="1" cellpadding="4">
<tr><td>vip</td><td><input name="mgmt_vip_vip" value="{{if .Cluster.MgmtVIP}}{{.Cluster.MgmtVIP.VIP}}{{end}}"></td></tr>
<tr><td>vrrp_id</td><td><input class="vrrp-suggest" name="mgmt_vip_vrrp_id" value="{{if .Cluster.MgmtVIP}}{{.Cluster.MgmtVIP.VRRPID}}{{end}}" data-used-vrrp-ids="{{.UsedVRRPIDs}}"> (blank = auto-suggests the next free ID on load; never touches an already-set value)</td></tr>
</table>

<h2 id="dns">Core DNS/DHCP addresses</h2>
<p class="dim">Loopback bind addresses for the two consolidated per-worker
"core" dnsmasq instances (0.9.7 DNS/DHCP consolidation prototype) —
dnsmasq.central (DNS) and central DHCP. Cluster-wide, identical on every
worker (unlike node_ip). Blank = use the built-in default
(127.0.0.42/127.0.0.21). Checked for valid syntax on save (a real IPv4
address in 127.0.0.0/8, not colliding with 127.0.0.1 or this host's own
systemd-resolved stub addresses, and the two must differ) — changing
either needs a daemon restart to take effect.</p>
<table border="1" cellpadding="4">
<tr><td>core_dns_address</td><td><input name="core_dns_address" value="{{.Cluster.CoreDNSAddress}}" size="20" placeholder="127.0.0.42"></td></tr>
<tr><td>core_dhcp_address</td><td><input name="core_dhcp_address" value="{{.Cluster.CoreDHCPAddress}}" size="20" placeholder="127.0.0.21"></td></tr>
<tr><td>core_dns_query_logging<br><small class="dim">real per-query logging for dnsmasq.central (DNS query volume is typically far higher than DHCP transaction volume — off by default). View the result on <a href="/logs#daemons">Logs → Daemon logs</a> once enabled.</small></td><td><input type="checkbox" name="core_dns_query_logging" value="1" {{if .Cluster.CoreDNSQueryLogging}}checked{{end}}></td></tr>
<tr><td>sanity_check_disabled<br><small class="dim">the "Configuration sane" reconciliation check (Overview) — verifies the live, running system against what's actually configured/intended, self-heals what it safely can (e.g. a relay socket left bound to a stale interface after a rename). On by default while this project actively hunts down drift causes; check this box to turn it off once satisfied — leave unchecked otherwise.</small></td><td><input type="checkbox" name="sanity_check_disabled" value="1" {{if .Cluster.SanityCheckDisabled}}checked{{end}}></td></tr>
</table>

<h2 id="dnsrelay-cache">DNS relay cache</h2>
<p class="dim">Response cache sizing for the standalone dnshived-dnsrelay
binary — previously only settable by hand-editing dnsrelay.json on each
worker separately, now a real cluster-wide setting pushed to both. Blank
or 0 = don't manage this field at all (whatever's already on each node —
a manual edit, or the binary's own built-in default of 5000
entries/no byte ceiling — stays exactly as it is). A configured value
here always overwrites whatever's currently on disk on the next apply.
Changing either needs a daemon restart, which then also restarts
dnshived-dnsrelay itself to actually pick up the new cache sizing (a
plain reload can't — see cache_max_bytes' own tooltip for why).</p>
<table border="1" cellpadding="4">
<tr><td>dnsrelay_cache_size<br><small class="dim">maximum number of cached responses across all shards.</small></td><td><input type="number" min="0" name="dnsrelay_cache_size" value="{{if .Cluster.DNSRelayCacheSize}}{{.Cluster.DNSRelayCacheSize}}{{end}}" size="10" placeholder="5000"></td></tr>
<tr><td>dnsrelay_cache_max_bytes<br><small class="dim" title="An optional second ceiling on top of cache_size's own entry count — bytes of cached response data, cluster-wide across all shards. 0/blank disables it (entry-count-only, today's default behavior). Applying a change always restarts dnshived-dnsrelay, never just a SIGHUP reload — its reload handler only re-reads allowed_interfaces/interface_acls/rewrites, never cache sizing.">byte ceiling on top of cache_size, in bytes.</small></td><td><input type="number" min="0" name="dnsrelay_cache_max_bytes" value="{{if .Cluster.DNSRelayCacheMaxBytes}}{{.Cluster.DNSRelayCacheMaxBytes}}{{end}}" size="10" placeholder="8388608"></td></tr>
</table>

<p><input type="submit" value="Stage as pending change"></p>
</form>

<h2>Cluster nodes</h2>
<div class="table-wrap"><table border="1" cellpadding="4">
<tr><th>Name</th><th>Display name</th><th>Address</th><th>Rename</th><th>Offboard</th></tr>
{{range .AllNodes}}
<tr>
  <td>{{.Name}}</td>
  <td>{{.DisplayName}}</td>
  <td>{{.Addr}}</td>
  <td><form method="post" action="/nodes/rename" style="display:inline">
    <input type="hidden" name="addr" value="{{.Addr}}">
    <input type="text" name="display_name" value="{{.DisplayName}}" placeholder="optional, blank = {{.Name}}">
    <button type="submit">Save</button>
  </form></td>
  <td><form method="post" action="/nodes/offboard" style="display:inline" onsubmit="return confirm('Stage offboarding {{.Name}} ({{.Addr}}) as a pending change? Nothing happens to {{.Name}} until you review and Commit it from Pending changes.')">
    <input type="hidden" name="role" value="{{.Name}}">
    <button type="submit">Offboard</button>
  </form></td>
</tr>
{{end}}
{{range .MissingRoles}}
<tr>
  <td class="dim">{{.}}</td>
  <td colspan="4" class="warn">not configured — offboarded or never onboarded. See "Discovered on the network" below to onboard or replace it.</td>
</tr>
{{end}}
</table></div>
<p class="dim">Display name is purely cosmetic — it's shown instead of
the real name above wherever this cluster's nodes are listed, but
never changes the real identity (routing, role-matching, etc. all keep
using the real name). Offboard, replace, and onboard-as-probe (below)
all now stage a pending node action instead of executing immediately —
review and commit (or discard) it from <a href="/pending">Pending
changes</a>, the same as every other config write in this package.
Core roles (worker-a/worker-b/arbiter) are fixed by this project's
architecture — there's no "add" for a role that isn't already one of
the three; a dead core node is replaced under its existing role
instead, from the discovered-node list below.</p>

<h2 id="discovered">Discovered on the network</h2>
<p class="dim">Fresh, unclaimed dnshived/dnshived-probe installs currently
broadcasting themselves on the mgmt segment (LAN autodiscovery, 0.9.8) —
saves typing an address by hand below. The join code itself is never
broadcast; read it off the candidate's own console/journal as always.
Onboarding or replacing here only STAGES the action — nothing is pushed
to the candidate node until you commit it from Pending changes. Two
separate actions, on purpose (2026-09-06): "Onboard as" only ever offers a
role/probe that's currently MISSING (nothing to disrupt); "Replace" only
ever offers one that's currently OCCUPIED (the old one is decommissioned/
dropped as part of the same job) — a role can never appear in both.
Real prechecks now run BEFORE any of that: click "Inspect" first — it
physically verifies (by discovery broadcast, not by trusting names) which
of this candidate's own interfaces line up with this cluster's own trunk
interfaces, and reports its OS. This can take several seconds per
interface; nothing is changed on the candidate by inspecting it.</p>
{{if .Discovered}}
<div class="table-wrap"><table border="1" cellpadding="4">
<tr><th>Hostname</th><th>Address</th><th>Version</th><th>Last seen</th><th>Inspect</th><th>Onboard as (missing)</th><th>Replace (occupied)</th></tr>
{{range .Discovered}}
<tr>
  <td>{{.Hostname}}</td>
  <td>{{.Addr}}</td>
  <td{{if and .Version $.ThisVersion (ne .Version $.ThisVersion)}} class="warn" title="this cluster is on {{$.ThisVersion}} — onboarding a different version may fail or behave unexpectedly. Go ahead at your own risk."{{end}}>{{.Version}}</td>
  <td>{{.LastSeen.Format "15:04:05"}}</td>
  <td><form method="post" action="/nodes/inspect" style="display:inline" onsubmit="return submitFormInModal(this, 'Inspecting {{.Addr}}')">
    <input type="hidden" name="addr" value="{{.Addr}}:{{.BootstrapPort}}">
    <button type="submit">Inspect</button>
  </form></td>
  <td>{{if $.OnboardTargets}}<form method="post" action="/nodes/replace" style="display:inline">
    <input type="hidden" name="addr" value="{{.Addr}}:{{.BootstrapPort}}">
    <select name="role">
      {{range $.OnboardTargets}}<option value="{{.}}">{{.}}</option>{{end}}
    </select>
    <input type="password" name="otp" placeholder="join code" size="12" autocomplete="off">
    <button type="submit">Onboard</button>
  </form>{{else}}<span class="dim">— everything already onboarded</span>{{end}}</td>
  <td>{{if $.ReplaceTargets}}<form method="post" action="/nodes/replace" style="display:inline">
    <input type="hidden" name="addr" value="{{.Addr}}:{{.BootstrapPort}}">
    <select name="role">
      {{range $.ReplaceTargets}}<option value="{{.}}">{{.}}</option>{{end}}
    </select>
    <input type="password" name="otp" placeholder="join code" size="12" autocomplete="off">
    <button type="submit">Replace</button>
  </form>{{else}}<span class="dim">—</span>{{end}}</td>
</tr>
{{end}}
</table></div>
{{else}}<p>None currently discovered.</p>{{end}}

<details><summary>Discovery not finding the candidate? Enter its address manually</summary>
<p class="dim">Fallback for a candidate that hasn't started broadcasting yet, or
whose broadcast can't reach this node for some other reason — still needs
to be reachable on the mgmt segment for a replacement to ever actually
work (VRRP itself requires the same broadcast domain), just not
necessarily already discovered.</p>
<form method="post" action="/nodes/replace">
<label>Role/probe:
<select name="role">
{{range .OnboardTargets}}<option value="{{.}}">{{.}} (missing — onboard)</option>{{end}}
{{range .ReplaceTargets}}<option value="{{.}}">{{.}} (occupied — replace)</option>{{end}}
</select>
</label><br>
<label>Address (host:port): <input type="text" name="addr" id="manual-inspect-addr" placeholder="192.0.2.22:9443"></label><br>
<label>Join code (read from the fresh node's own bootstrap console): <input type="password" name="otp" autocomplete="off"></label><br>
<button type="submit">Onboard / Replace</button>
</form>
<form method="post" action="/nodes/inspect" onsubmit="return submitFormInModal(this, 'Inspecting')">
<input type="hidden" name="addr" id="manual-inspect-addr-mirror" value="">
<button type="submit" onclick="document.getElementById('manual-inspect-addr-mirror').value=document.getElementById('manual-inspect-addr').value">Inspect this address</button>
</form>
</details>

<dialog id="log-modal">
<h3 id="log-modal-title" style="margin-top:0"></h3>
<div class="table-wrap"><pre id="log-modal-body" style="margin:0"></pre></div>
<form method="dialog"><button>Close</button></form>
</dialog>
`))
