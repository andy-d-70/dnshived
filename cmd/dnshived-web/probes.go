// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"dnshived/internal/config"
)

// probeClass classifies one worker's probe result for a scope — ported
// from dnshived-top's identical probeCell (ANSI colors replaced with CSS
// classes).
func probeClass(pr probeResult, have bool) (text, class string) {
	if !have {
		return "pending...", "dim"
	}
	if !pr.Enabled && pr.Reachable && pr.DHCP.Error == "" && pr.DNS.Error == "" {
		return "probe off", "dim"
	}
	if !pr.Reachable {
		return "no coverage", "dim"
	}

	dnsOK := pr.DNS.Error == "" && pr.DNS.Valid
	dnsUnknown := pr.DNS.Error != ""
	dhcpOK := pr.DHCP.Error == "" && pr.DHCP.Verdict == "ok"
	dhcpDual := pr.DHCP.Error == "" && pr.DHCP.Verdict == "dual_active"
	dhcpNoAnswer := pr.DHCP.Error == "" && pr.DHCP.Verdict == "no_answer"
	dhcpUnknown := pr.DHCP.Error != ""
	dnsPending, dhcpPending := pr.DNSPending, pr.DHCPPending

	dnsText := "DNS✖"
	if dnsPending {
		dnsText = "DNS…"
	} else if dnsUnknown {
		dnsText = "DNS?"
	} else if dnsOK {
		dnsText = "DNS✔"
	}
	dhcpText := "DHCP✖"
	switch {
	case dhcpPending:
		dhcpText = "DHCP…"
	case dhcpUnknown:
		dhcpText = "DHCP?"
	case dhcpOK:
		dhcpText = "DHCP✔"
	case dhcpDual:
		dhcpText = "DHCP✖DUAL"
	case dhcpNoAnswer:
		dhcpText = "DHCP-NONE"
	}
	text = dnsText + " " + dhcpText

	switch {
	case dhcpDual:
		return text, "crit" // dual-active — two servers answering
	case dhcpNoAnswer:
		return text, "crit"
	case dnsUnknown || dhcpUnknown:
		return text, "dim"
	case dnsPending || dhcpPending:
		if (dnsPending || dnsOK) && (dhcpPending || dhcpOK) {
			return text, "dim"
		}
		return text, "warn"
	case dnsOK && dhcpOK:
		return text, "ok"
	default:
		return text, "warn"
	}
}

// probeClassParts is probeClass's per-leg equivalent, used ONLY for the
// Probes-page grid cell.
func probeClassParts(pr probeResult, have bool, mismatch bool) (dnsText, dnsClass, dhcpText, dhcpClass string) {
	if !have {
		return "pending...", "dim", "", ""
	}
	if !pr.Enabled && pr.Reachable && pr.DHCP.Error == "" && pr.DNS.Error == "" {
		return "probe off", "dim", "", ""
	}
	if !pr.Reachable {
		return "no coverage", "dim", "", ""
	}

	dnsOK := pr.DNS.Error == "" && pr.DNS.Valid
	dnsUnknown := pr.DNS.Error != ""
	dhcpOK := pr.DHCP.Error == "" && pr.DHCP.Verdict == "ok"
	dhcpDual := pr.DHCP.Error == "" && pr.DHCP.Verdict == "dual_active"
	dhcpNoAnswer := pr.DHCP.Error == "" && pr.DHCP.Verdict == "no_answer"
	dhcpUnknown := pr.DHCP.Error != ""
	dnsPending, dhcpPending := pr.DNSPending, pr.DHCPPending

	switch {
	case dnsPending:
		dnsText, dnsClass = "DNS…", "warn"
	case dnsUnknown:
		dnsText, dnsClass = "DNS?", "dim"
	case dnsOK:
		dnsText, dnsClass = "DNS✔", "ok"
	default:
		dnsText, dnsClass = "DNS✖", "crit"
	}

	switch {
	case dhcpPending:
		dhcpText, dhcpClass = "DHCP…", "warn"
	case dhcpUnknown:
		dhcpText, dhcpClass = "DHCP?", "dim"
	case dhcpOK:
		dhcpText, dhcpClass = "DHCP✔", "ok"
		if mismatch {
			dhcpClass = "warn"
		}
	case dhcpDual:
		dhcpText, dhcpClass = "DHCP✖DUAL", "crit"
	case dhcpNoAnswer:
		dhcpText, dhcpClass = "DHCP-NONE", "crit"
	default:
		dhcpText, dhcpClass = "DHCP✖", "crit"
	}
	return
}

// probeReasonSuffix appends the actual diagnostic text behind a failure.
func probeReasonSuffix(pr probeResult, dnsOK bool) string {
	var parts []string
	switch {
	case !dnsOK && pr.DNS.Error != "":
		parts = append(parts, "DNS: "+pr.DNS.Error)
	case !dnsOK && pr.DNS.Reason != "":
		parts = append(parts, "DNS: "+pr.DNS.Reason)
	}
	switch {
	case pr.DHCP.Error != "":
		parts = append(parts, "DHCP: "+pr.DHCP.Error)
	case pr.DHCP.Reason != "":
		parts = append(parts, "DHCP: "+pr.DHCP.Reason)
	case pr.DHCP.Verdict == "dual_active" && len(pr.DHCP.Servers) > 0:
		parts = append(parts, fmt.Sprintf("DHCP: answered by %v", pr.DHCP.Servers))
	}
	if len(parts) == 0 {
		return ""
	}
	return "  [" + strings.Join(parts, "; ") + "]"
}

// probeCellDisplay renders one visible cell from a freshly-fetched
// probeResult.
func probeCellDisplay(now time.Time, pr probeResult, fetchErr error, queried bool, mismatch bool, stale bool) (dnsText, dnsClass, dhcpText, dhcpClass, note string) {
	if !queried {
		return "pending...", "dim", "", "", ""
	}
	if fetchErr != nil {
		return "pending...", "dim", "", "", fetchErr.Error()
	}
	if pr.Pending {
		return "pending...", "warn", "", "", "not yet probed"
	}
	if stale {
		return "pending...", "dim", "", "", "settling — reading predates the current owner's restart"
	}
	dnsText, dnsClass, dhcpText, dhcpClass = probeClassParts(pr, true, mismatch)
	if !pr.Enabled {
		return dnsText, dnsClass, dhcpText, dhcpClass, ""
	}
	if probedAt, err := time.Parse(time.RFC3339, pr.ProbedAt); err == nil {
		age := int(now.Sub(probedAt).Seconds())
		if age < 0 {
			age = 0
		}
		note = fmt.Sprintf("%ds ago", age)
	}
	if pr.DHCPPending {
		note = strings.TrimSpace(note + " DHCP not probed yet")
	}
	if pr.DNSPending {
		note = strings.TrimSpace(note + " DNS not probed yet")
	}
	if reason := probeReasonSuffix(pr, true); reason != "" {
		note = strings.TrimSpace(note + " " + strings.Trim(reason, " []"))
	} else if mismatch {
		note = strings.TrimSpace(note + " DHCP is being answered but no valid arbiter token authorizes this scope")
	}
	return dnsText, dnsClass, dhcpText, dhcpClass, note
}

// configuredScopeNames collects every distinct scope name across every
// reachable core node's ConfiguredScopes.
func configuredScopeNames(rows []statusRow) []string {
	var scopeNames []string
	seen := make(map[string]bool)
	for _, row := range rows {
		if row.FetchError != "" || !isCoreRole(row.Status.Role) {
			continue
		}
		for _, sc := range row.Status.ConfiguredScopes {
			if !seen[sc] {
				seen[sc] = true
				scopeNames = append(scopeNames, sc)
			}
		}
	}
	sort.Strings(scopeNames)
	return scopeNames
}

// servingScopeNames unions every reachable core node's own live Serving[]
// into a membership set.
func servingScopeNames(rows []statusRow) map[string]bool {
	serving := make(map[string]bool)
	for _, row := range rows {
		if row.FetchError != "" || !isCoreRole(row.Status.Role) {
			continue
		}
		for _, sc := range row.Status.Serving {
			serving[sc] = true
		}
	}
	return serving
}

// disabledScopeSet unions DisabledScopes across every reachable core node.
func disabledScopeSet(rows []statusRow) map[string]bool {
	set := make(map[string]bool)
	for _, row := range rows {
		if row.FetchError != "" || !isCoreRole(row.Status.Role) {
			continue
		}
		for _, sc := range row.Status.DisabledScopes {
			set[sc] = true
		}
	}
	return set
}

// scopeDisabledCell replaces a disabled scope's probe cell, so it never
// reads as a probe-only setting.
func scopeDisabledCell(scope, worker string) probeCellData {
	return probeCellData{Scope: scope, Worker: worker, DNSText: "scope disabled", DNSClass: "warn",
		Title: "DHCP and DNS stopped for this scope, probing off with it"}
}

// iotScopeSet unions IoTScopes across every reachable core node.
func iotScopeSet(rows []statusRow) map[string]bool {
	set := make(map[string]bool)
	for _, row := range rows {
		if row.FetchError != "" || !isCoreRole(row.Status.Role) {
			continue
		}
		for _, sc := range row.Status.IoTScopes {
			set[sc] = true
		}
	}
	return set
}

// scopeDisplayName appends a fixed "[IoT]" tag to a scope name when
// flagged.
func scopeDisplayName(name string, iot bool) string {
	if iot {
		return name + " [IoT]"
	}
	return name
}

type probeIssue struct {
	Scope, Worker       string
	DNSText, DNSClass   string
	DHCPText, DHCPClass string
	Detail              string
	// Rogue is true when Detail names an unrecognized DHCP server (see
	// unrecognizedServers/validateDHCPAnswer, cmd/dnshived-probe).
	Rogue bool
}

// ownerDaemonUptime fetches every node's own dnshived.service uptime
// (seconds), keyed by node_id.
func ownerDaemonUptime(cfg *WebConfig) map[string]int64 {
	uptime := make(map[string]int64)
	for _, res := range fetchAllDaemons(cfg, nodesIncludingSelf(cfg)) {
		if res.Err != nil {
			continue
		}
		for _, d := range res.Value.Daemons {
			if d.Unit == "dnshived.service" && d.Error == "" {
				uptime[res.Value.NodeID] = d.UptimeSec
			}
		}
	}
	return uptime
}

// probeSettleGraceSeconds extends probeStale past the owner's raw daemon
// uptime.
const probeSettleGraceSeconds = 20

func probeStale(probedAt time.Time, ownerUptimeSec int64, hasUptime bool, now time.Time) bool {
	if !hasUptime || probedAt.IsZero() {
		return false
	}
	ownerStartedAt := now.Add(-time.Duration(ownerUptimeSec) * time.Second)
	return probedAt.Before(ownerStartedAt.Add(probeSettleGraceSeconds * time.Second))
}

func checkProbeHostIssues(scopeNames []string, probeHosts []NodeConfig, tokens map[string]tokenInfo, ownerUptime map[string]int64, serving map[string]bool) (issues []probeIssue, mismatches map[string]bool, pendingCount int) {
	issues, mismatches, pendingCount, _ = checkProbeHostIssuesWithCoverage(scopeNames, probeHosts, tokens, ownerUptime, serving, nil)
	return issues, mismatches, pendingCount
}

// checkProbeHostIssuesWithCoverage is checkProbeHostIssues plus the
// coverage counts from the same fetch (no second round of requests).
func checkProbeHostIssuesWithCoverage(scopeNames []string, probeHosts []NodeConfig, tokens map[string]tokenInfo, ownerUptime map[string]int64, serving, disabled map[string]bool) (issues []probeIssue, mismatches map[string]bool, pendingCount int, cov probeCoverage) {
	results := fetchProbeResults(scopeNames, probeHosts)
	var active []probeFetch
	for _, res := range results {
		if !disabled[res.scope] {
			active = append(active, res)
		}
	}
	issues, mismatches, pendingCount = classifyProbeResults(active, tokens, ownerUptime, serving)
	issues = append(issues, manualProbeIssues(probeHosts)...)
	return issues, mismatches, pendingCount, probeCoverageOf(results, time.Now(), disabled)
}

// probeStaleAfter is how old a probe result may be before it counts as
// stale rather than fresh in the coverage line.
const probeStaleAfter = 6 * time.Minute

// probeCoverage says how many of the configured scopes are actually being
// probed, and why the rest are not.
type probeCoverage struct {
	Total         int // (scope, probe host) results considered
	Probed        int // enabled, reachable, fresh result
	ScopeDisabled int // the scope itself is disabled (deliberate)
	Disabled      int // only probing switched off for the scope (deliberate)
	NoCoverage    int // probe host has no VLAN interface for the scope
	Pending       int // no result yet (first sweep / cleared after a change)
	Stale         int // enabled result older than probeStaleAfter
	Unknown       int // probe host could not be asked
	Hosts         int // number of distinct probe hosts
}

// probeCoverageOf classifies every fetched probe result.
func probeCoverageOf(results []probeFetch, now time.Time, disabledScopes map[string]bool) probeCoverage {
	var c probeCoverage
	hosts := map[string]bool{}
	for _, res := range results {
		c.Total++
		hosts[res.worker] = true
		switch {
		case disabledScopes[res.scope]:
			c.ScopeDisabled++
		case res.err != nil:
			c.Unknown++
		case res.pr.anyPending():
			c.Pending++
		case !res.pr.Reachable:
			c.NoCoverage++
		case !res.pr.Enabled && res.pr.DHCP.Error == "" && res.pr.DNS.Error == "":
			c.Disabled++
		default:
			if at := res.pr.oldestProbedAt(); !at.IsZero() && now.Sub(at) > probeStaleAfter {
				c.Stale++
			} else {
				c.Probed++
			}
		}
	}
	c.Hosts = len(hosts)
	return c
}

func (c probeCoverage) text() string {
	if c.Total == 0 {
		return ""
	}
	unit := "scope(s)"
	if c.Hosts > 1 {
		unit = "probe check(s)"
	}
	var rest []string
	add := func(n int, what string) {
		if n > 0 {
			rest = append(rest, fmt.Sprintf("%d %s", n, what))
		}
	}
	add(c.ScopeDisabled, "not probed (scope disabled)")
	add(c.Disabled, "probe switched off")
	add(c.NoCoverage, "no VLAN coverage on the probe host")
	add(c.Pending, "pending first sweep")
	add(c.Stale, "stale (not refreshed for over "+probeStaleAfter.String()+")")
	add(c.Unknown, "probe host unreachable")
	out := fmt.Sprintf("probed %d of %d %s", c.Probed, c.Total, unit)
	if len(rest) > 0 {
		out += " — " + strings.Join(rest, ", ")
	}
	return out
}

// needsAttention is true for the not-probed reasons that are NOT a
// deliberate operator choice (a disabled scope or probe stays neutral).
func (c probeCoverage) needsAttention() bool {
	return c.NoCoverage > 0 || c.Pending > 0 || c.Stale > 0 || c.Unknown > 0
}

// probeSummaryWithCoverage is probeHealthSummary plus the coverage clause,
// so Overview's Probes row shows convergence, not just "all healthy".
func probeSummaryWithCoverage(issues []probeIssue, pending int, cov probeCoverage) (text, class string) {
	text, class = probeHealthSummary(issues, pending)
	ct := cov.text()
	if ct == "" {
		return text, class
	}
	if cov.needsAttention() && class == "ok" {
		class = "warn"
	}
	// The coverage clause already states the pending count, so the
	// "(N still pending first sweep)" wording is not repeated next to it.
	switch {
	case len(issues) > 0:
		text = text + " — " + ct
	case cov.needsAttention():
		text = "no issues found — " + ct
	default:
		text = "all healthy — " + ct
	}
	return text, class
}

// fetchProbeResults asks every probe host for every scope's result.
func fetchProbeResults(scopeNames []string, probeHosts []NodeConfig) []probeFetch {
	type job struct {
		scope, worker string
		node          NodeConfig
	}
	var jobs []job
	for _, sc := range scopeNames {
		for _, node := range probeHosts {
			jobs = append(jobs, job{scope: sc, worker: node.Name, node: node})
		}
	}
	results := make([]probeFetch, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func(i int, j job) {
			defer wg.Done()
			pr, err := fetchProbe(j.node, j.scope)
			results[i] = probeFetch{scope: j.scope, worker: j.worker, pr: pr, err: err}
		}(i, j)
	}
	wg.Wait()
	return results
}

// classifyProbeResults is checkProbeHostIssues' own classification logic,
// pulled out as a pure function (no I/O).
func classifyProbeResults(results []probeFetch, tokens map[string]tokenInfo, ownerUptime map[string]int64, serving map[string]bool) (issues []probeIssue, mismatches map[string]bool, pendingCount int) {
	mismatches = make(map[string]bool)
	now := time.Now()
	for _, res := range results {
		if res.err == nil && res.pr.anyPending() {
			pendingCount++
		}
		if res.err != nil || res.pr.Pending {
			continue // transport hiccup or not-yet-probed — not a confirmed failure
		}
		if tok, ok := tokens[res.scope]; ok {
			uptimeSec, hasUptime := ownerUptime[tok.Owner]
			probedAt := res.pr.oldestProbedAt()
			if probeStale(probedAt, uptimeSec, hasUptime, now) {
				continue
			}
		}
		if serving[res.scope] {
			_, class := probeClass(res.pr, true)
			if class == "crit" || class == "warn" {
				dnsText, dnsClass, dhcpText, dhcpClass := probeClassParts(res.pr, true, false)
				dnsOK := res.pr.DNS.Error == "" && res.pr.DNS.Valid
				detail := probeReasonSuffix(res.pr, dnsOK)
				issues = append(issues, probeIssue{
					Scope: res.scope, Worker: res.worker,
					DNSText: dnsText, DNSClass: dnsClass,
					DHCPText: dhcpText, DHCPClass: dhcpClass,
					Detail: detail,
					Rogue:  strings.Contains(detail, "ROGUE DHCP"),
				})
			}
		}

		dhcpAnswering := res.pr.DHCP.Error == "" && (res.pr.DHCP.Verdict == "ok" || res.pr.DHCP.Verdict == "dual_active")
		tok, hasToken := tokens[res.scope]
		tokenValid := hasToken && !tok.Expired
		if dhcpAnswering && !tokenValid {
			mismatches[res.scope+"|"+res.worker] = true
		}
	}
	sort.Slice(issues, func(i, j int) bool { return issues[i].Scope+issues[i].Worker < issues[j].Scope+issues[j].Worker })
	return issues, mismatches, pendingCount
}

// confirmProbeMismatches turns this tick's raw token-cross-check
// mismatches into confirmed issue lines, debounced against the PREVIOUS
// tick's mismatches (prev).
func confirmProbeMismatches(mismatches, prev map[string]bool) (lines []probeIssue, confirmed map[string]bool) {
	confirmed = make(map[string]bool)
	for key := range mismatches {
		if prev[key] {
			sc, w, _ := strings.Cut(key, "|")
			lines = append(lines, probeIssue{
				Scope: sc, Worker: w,
				DHCPText: "DHCP✔", DHCPClass: "warn",
				Detail: "no valid arbiter token authorizes this scope",
			})
			confirmed[key] = true
		}
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i].Scope+lines[i].Worker < lines[j].Scope+lines[j].Worker })
	return lines, confirmed
}

var (
	probeHealthMu          sync.Mutex
	probeMismatchPrev      map[string]bool
	confirmedMismatchCache map[string]bool
)

func debounceProbeMismatches(mismatches map[string]bool) []probeIssue {
	probeHealthMu.Lock()
	defer probeHealthMu.Unlock()
	lines, confirmed := confirmProbeMismatches(mismatches, probeMismatchPrev)
	probeMismatchPrev = mismatches
	confirmedMismatchCache = confirmed
	return lines
}

// probeHealthSummary computes Overview's probe-health text/CSS-class pair.
func sweptScopeCount(total, pending int) int {
	swept := total - pending
	if swept < 0 {
		return 0
	}
	return swept
}

// probeHostRowStatus computes Overview's probe-host row Class/Info pair.
func probeHostRowStatus(swept, total, pending int, settlingNow bool) (class, info string) {
	info = fmt.Sprintf("%d/%d scope(s) swept", swept, total)
	switch {
	case pending > 0:
		return "warn", info
	case settlingNow:
		return "warn", info + " (predates the cluster's current settling — not yet re-confirmed)"
	default:
		return "ok", info
	}
}

func probeHealthSummary(issues []probeIssue, pending int) (text, class string) {
	if len(issues) > 0 {
		return fmt.Sprintf("%d issue(s) — see below", len(issues)), "crit"
	}
	if pending > 0 {
		return fmt.Sprintf("no issues found (%d still pending first sweep)", pending), "warn"
	}
	return "all healthy", "ok"
}

func cachedMismatch(scope, probeHost string) bool {
	probeHealthMu.Lock()
	defer probeHealthMu.Unlock()
	return confirmedMismatchCache[scope+"|"+probeHost]
}

// probeRow is one scope's rendered cells.
type probeRow struct {
	Scope          string
	ProbeHostCells []probeCellData
}

// probeCellData holds DNS and DHCP as independently colored halves.
type probeCellData struct {
	Scope     string
	Worker    string
	DNSText   string
	DNSClass  string
	DHCPText  string
	DHCPClass string
	Note      string
	Title     string
}

// Auto-refresh is cheap: a page reload triggers no DHCP/DNS traffic.
const probeAutoRefreshSeconds = 20

// probeCellDefineHTML is the "probecell" named template.
const probeCellDefineHTML = `{{define "probecell"}}<span class="{{.DNSClass}}"{{if .Title}} title="{{.Title}}"{{end}}>{{.DNSText}}</span>{{if .DHCPText}} <span class="{{.DHCPClass}}">{{.DHCPText}}</span>{{end}}{{if .Note}} <span class="dim">({{.Note}})</span>{{end}} <a class="dim probe-detail" href="/probes/{{.Scope}}/{{.Worker}}">detail</a> <form class="probe-now-form" method="post" action="/probes/{{.Scope}}/{{.Worker}}/refresh" style="display:inline"><button type="submit" class="btn-sm">probe now</button></form>{{end}}`

// probePopupHTML is the dialog and the script that fill it with the probe
// detail; without JavaScript the "detail" link and "probe now" still open the
// full page.
const probePopupHTML = `<dialog id="probe-dialog" style="max-width:min(60rem,92vw);max-height:85vh;overflow:auto;border:1px solid var(--border);border-radius:10px;background:var(--panel);color:var(--text)">
<form method="dialog" style="text-align:right;margin:0"><button type="submit" class="btn-sm">Close</button></form>
<div id="probe-dialog-body"></div>
</dialog>
<script>
(function(){
var dlg=document.getElementById('probe-dialog');
if(!dlg||!dlg.showModal){return}
var body=document.getElementById('probe-dialog-body');
function show(html){body.innerHTML=html;if(!dlg.open){dlg.showModal()}}
function note(cls,text){var p=document.createElement('p');p.className=cls;p.textContent=text;body.replaceChildren(p);if(!dlg.open){dlg.showModal()}}
function load(url,opts,busy){
 note('dim',busy);
 fetch(url,opts).then(function(r){return r.text().then(function(t){if(!r.ok){throw new Error(r.status+' '+t.slice(0,200))}return t})}).then(show).catch(function(e){note('crit','Could not load the probe detail: '+e.message)})
}
function withFragment(u){return u+(u.indexOf('?')<0?'?':'&')+'fragment=1'}
document.addEventListener('click',function(e){
 var a=e.target.closest&&e.target.closest('a.probe-detail');
 if(a&&e.button===0&&!e.ctrlKey&&!e.metaKey&&!e.shiftKey){e.preventDefault();load(withFragment(a.href),{credentials:'same-origin'},'Loading the probe detail…')}
});
document.addEventListener('submit',function(e){
 var f=e.target;
 if(f.classList&&f.classList.contains('probe-now-form')){e.preventDefault();load(withFragment(f.action),{method:'POST',credentials:'same-origin'},'Probing now… this takes up to about 20 seconds')}
});
dlg.addEventListener('click',function(e){if(e.target===dlg){dlg.close()}});
})();
</script>`

const probeManagementHTML = `<section class="tab-pane" id="tab-hosts" data-tab="Probe hosts &amp; TLS" data-tab-order="3" data-tab-default>
<h2 id="settings">Probe hosts &amp; settings</h2>
<p class="dim">A probe host runs one DHCP check and one DNS check per physical
interface at a time, each interface on its own, and moves to the next scope as
soon as a DHCP server has offered a lease. Every scope is therefore checked
again within a few minutes however many interfaces carry scopes. DHCP and DNS
results are shown as soon as each is available: a part that has not run yet is
shown in orange as pending.</p>
{{if .NodeProbeHosts}}<div class="table-wrap"><table border="1" cellpadding="4">
<tr><th>Name</th><th>Display name</th><th>Address</th><th>State</th><th>Scopes</th><th>Rename</th><th></th></tr>
{{range .ProbeParallelRows}}
<tr>
  <td>{{.Name}}</td>
  <td>{{index $.ProbeHostDisplayNames .Addr}}</td>
  <td>{{.Addr}}</td>
  <td>{{if not .Reachable}}<span class="crit">unreachable{{if .Err}} — {{.Err}}{{end}}</span>
      {{else}}<span class="ok">running</span>{{end}}</td>
  <td>{{.ScopeCount}}</td>
  <td><form method="post" action="/nodes/rename" style="display:inline">
    <input type="hidden" name="addr" value="{{.Addr}}">
    <input type="text" name="display_name" value="{{index $.ProbeHostDisplayNames .Addr}}" placeholder="optional, blank = {{.Name}}">
    <button type="submit">Save</button>
  </form></td>
  <td><form method="post" action="/nodes/probe/remove" style="display:inline"><input type="hidden" name="addr" value="{{.Addr}}"><button type="submit">Remove</button></form></td>
</tr>
{{end}}
</table></div>
{{if .ProbeTLSStates}}<div class="table-wrap"><table border="1" cellpadding="4">
<tr><th>Probe host</th><th>TLS</th><th>Plain HTTP</th><th></th></tr>
{{range .ProbeTLSStates}}
<tr>
  <td>{{.Addr}}</td>
  <td>{{if .Pinned}}<span class="ok">pinned</span> <code>{{.Fingerprint}}</code>{{else}}<span class="warn" title="Traffic to this probe is not encrypted until its certificate is pinned. Use Pin now: the probe proves its certificate with its admin token; if it cannot, the fingerprint is shown to compare with the probe host's log.">not pinned</span>{{end}}</td>
  <td>{{if not .Pinned}}<span class="warn" title="The unencrypted port answers until the certificate is pinned and the port is closed.">open (unencrypted)</span>
      {{else if .Err}}<span class="dim" title="{{.Err}}">unknown</span>
      {{else if not .PlainKnown}}<span class="dim" title="This probe host does not report it; upgrade it.">unknown</span>
      {{else if .PlainOpen}}<span class="warn" title="The unencrypted port is still open although the certificate is pinned.">open</span>
      <form method="post" action="/probes/plain-http" style="display:inline"><input type="hidden" name="addr" value="{{.Addr}}"><input type="hidden" name="enabled" value="0"><button type="submit" title="The probe restarts once to close the port. Only this web UI and dnshived-top with the pinned fingerprint can reach it afterwards.">Close plain HTTP</button></form>
      {{else}}<span class="ok">closed</span>{{end}}</td>
  <td>{{if not .Pinned}}<form method="post" action="/probes/pin-now" style="display:inline"><input type="hidden" name="addr" value="{{.Addr}}"><button type="submit">Pin now</button></form>
      {{else}}{{if .PlainOpen}}<form method="post" action="/probes/unpin" style="display:inline"><input type="hidden" name="addr" value="{{.Addr}}"><button type="submit" class="btn-warn" title="go back to plain HTTP for this probe until it is pinned again">Unpin</button></form>{{end}}
      <details><summary class="dim">Replace the certificate</summary>
        <form method="post" action="/probes/tls/upload" onsubmit="return confirm('Replace the certificate of this probe host? The new fingerprint is pinned here at once; dnshived-top and dnshived-validate need the new fingerprint.')">
        <input type="hidden" name="addr" value="{{.Addr}}">
        <p class="dim">Certificate (PEM, the first one is the server certificate):<br><textarea name="cert_pem" rows="5" cols="70" required></textarea></p>
        <p class="dim">Private key (PEM, sent over the pinned connection and never shown again):<br><textarea name="key_pem" rows="5" cols="70" required autocomplete="off"></textarea></p>
        <button type="submit">Replace certificate</button></form></details>{{end}}</td>
</tr>
{{end}}
</table></div>{{end}}
{{else}}<p>None adopted.</p>{{end}}
{{if .NodeProbeHosts}}<p class="dim">A probe host is onboarded. To use a different one, remove this one first; the form to add a probe host then appears here.</p>{{else}}<form method="post" action="/nodes/probe/add">
<label>Address (host:port): <input type="text" name="addr" placeholder="192.0.2.43:9444"></label><br>
<label>Join code (read from the probe's own bootstrap console): <input type="password" name="otp" autocomplete="off"></label><br>
<p class="dim">Trunk coverage is derived automatically from the cluster's own configured worker interfaces — a probe host always covers every one of them, no separate entry needed here.</p>
<button type="submit">Add probe</button>
</form>{{end}}

</section>
<section class="tab-pane" id="tab-manual" data-tab="Manual probes" data-tab-order="2">
<h3 id="manual">Manual probes</h3>
<p class="dim">Watch an interface for DHCP servers, tagged or untagged, also where no scope is served.
A DISCOVER is sent and no lease is ever taken. Every DHCP server that answers is listed; click "ack" on one that belongs on
that segment (your router, for example) and it is known from then on. Any other server is a rogue. A segment where a scope is served
never accepts a second server.</p>
{{range .ManualProbeHosts}}
<h4>{{.Name}}</h4>
{{if .Err}}<p class="warn" title="The probe host did not answer GET /api/v1/watch; it may run an older version.">Manual probes not available: {{.Err}}</p>{{end}}
{{if .Rows}}<div class="table-wrap"><table border="1" cellpadding="4">
<tr><th>Name</th><th>Interface</th><th>VLAN</th><th>Result</th><th>DHCP servers seen</th><th>Probed</th><th></th></tr>
{{$addr := .Addr}}{{range .Rows}}{{$name := .Name}}<tr>
  <td>{{.Name}}</td><td>{{.Interface}}</td><td>{{.VLAN}}</td>
  <td><span class="{{.ResultClass}}"{{if .Title}} title="{{.Title}}"{{end}}>{{.ResultText}}</span></td>
  <td>{{range .Chips}}<span class="{{.Class}}" title="{{.Title}}">{{.Server}} <small>{{.Label}}</small></span>{{if .CanToggle}} <form method="post" action="/probes/manual/ack" style="display:inline"><input type="hidden" name="addr" value="{{$addr}}"><input type="hidden" name="name" value="{{$name}}"><input type="hidden" name="server" value="{{.Server}}"><input type="hidden" name="action" value="{{.Action}}"><button type="submit" class="btn-sm">{{.Action}}</button></form>{{end}}&nbsp; {{end}}{{if not .Served}}<form method="post" action="/probes/manual/ack" style="display:inline"><input type="hidden" name="addr" value="{{$addr}}"><input type="hidden" name="name" value="{{$name}}"><input type="hidden" name="action" value="ack"><input type="text" name="server" size="14" placeholder="add address" pattern="[0-9]{1,3}(\.[0-9]{1,3}){3}" required title="An IPv4 address to acknowledge as a known DHCP server on this segment, also one that is not answering now."> <button type="submit" class="btn-sm">add</button></form>{{end}}</td>
  <td class="dim">{{.Age}}</td>
  <td><form method="post" action="/probes/manual/remove" style="display:inline"><input type="hidden" name="addr" value="{{$addr}}"><input type="hidden" name="name" value="{{.Name}}"><button type="submit">Remove</button></form></td>
</tr>{{end}}
</table></div>{{end}}
{{if not .Err}}<form method="post" action="/probes/manual/add">
<input type="hidden" name="addr" value="{{.Addr}}">
<label>Name: <input type="text" name="name" size="14" pattern="[a-z0-9][a-z0-9_-]{0,31}" required title="lowercase letters, digits, - and _"></label>
<label>Interface: <input type="text" name="interface" list="manual-ifaces" size="10" required></label>
<label>VLAN (0 = untagged): <input type="number" name="vlan_id" min="0" max="4094" value="0" class="narrow"></label>
<button type="submit">Add manual probe</button>
</form>{{end}}
{{end}}
<datalist id="manual-ifaces">{{range .ManualIfaces}}<option value="{{.}}">{{end}}</datalist>

</section>
<section class="tab-pane" id="tab-history" data-tab="History" data-tab-order="4">
<h3 id="history">Probe history</h3>
<p class="dim">The probe host can keep what it finds: every result, or only failures (with a "recovered" line when a failing scope answers again), separately for DHCP and DNS. Manual probes follow the DHCP setting. Off by default. Each record is also written to the probe host's syslog (tag dnshived-probe-history) unless that is switched off here.
<a href="/probes/history">Open the history</a>.</p>
{{range .HistoryHosts}}
<h4>{{.Name}}</h4>
{{if .Err}}<p class="warn" title="The probe host did not answer GET /api/v1/history; it may run an older version.">History not available: {{.Err}}</p>{{else}}
<form method="post" action="/probes/history">
<input type="hidden" name="addr" value="{{.Addr}}">
<p>DHCP: <label><input type="radio" name="dhcp" value="none"{{if eq .Settings.DHCP "none"}} checked{{end}}> none</label> <label><input type="radio" name="dhcp" value="failures"{{if eq .Settings.DHCP "failures"}} checked{{end}}> failures only</label> <label><input type="radio" name="dhcp" value="all"{{if eq .Settings.DHCP "all"}} checked{{end}}> all</label></p>
<p>DNS: <label><input type="radio" name="dns" value="none"{{if eq .Settings.DNS "none"}} checked{{end}}> none</label> <label><input type="radio" name="dns" value="failures"{{if eq .Settings.DNS "failures"}} checked{{end}}> failures only</label> <label><input type="radio" name="dns" value="all"{{if eq .Settings.DNS "all"}} checked{{end}}> all</label> <span class="warn" title="DNS is probed for every scope every 20 seconds: with 100 scopes, all results are on the order of 100 MB a day. The size and age limits below bound it.">&#9888; "all" is a lot of data</span></p>
<p><label><input type="checkbox" name="syslog"{{if .Settings.Syslog}} checked{{end}}> also write every record to syslog</label></p>
<details><summary class="dim">Limits (defaults: 25 MB per file, 4 files, 7 days)</summary>
<p><label>largest file, MB: <input type="number" name="max_file_mb" min="1" max="1024" value="{{.Settings.MaxFileMB}}" class="narrow"></label>
<label>files kept: <input type="number" name="max_files" min="1" max="50" value="{{.Settings.MaxFiles}}" class="narrow"></label>
<label>days kept: <input type="number" name="max_age_days" min="1" max="365" value="{{.Settings.MaxAgeDays}}" class="narrow"></label></p></details>
<p><button type="submit">Save history settings</button> <span class="dim">now {{.Size}} on disk{{if .Dropped}}, {{.Dropped}} record(s) dropped because the disk could not keep up{{end}}; applies at once, no restart</span></p>
</form>{{end}}
{{end}}
</section>
<section class="tab-pane" id="tab-behavior" data-tab="Behavior" data-tab-order="5">
<h3>Probe behavior settings</h3>
<form method="post" action="/probes/settings" onsubmit="return confirm('This will stage these probe settings as a pending change on every configured node — nothing is applied until you commit from Pending changes. Continue?')">
<p class="dim">Generic (name, type) DNS queries a probe host runs against
every scope, in addition to any scope-specific/global records — one
<code>NAME|TYPE</code> pair per line. Blank = built-in default
(claude.ai./A).</p>
{{if .GlobalDNSNames}}<p><select id="dns_check_quick_add" multiple size="6">
{{range .GlobalDNSNames}}<option value="{{.Name}}|{{.Type}}">{{.Name}} ({{.Type}})</option>{{end}}
</select>
<button type="button" onclick="addSelectedDNSChecks()">+ add selected</button>
<span class="dim">— only <a href="/config/dns">global_dns_records</a> names
are offered: a scope-local name only resolves against that one scope's own
dnsmasq, but this check runs against every scope, so a local-only name
would spuriously fail everywhere else.</span></p>
<script>
function addSelectedDNSChecks(){
  var sel = document.getElementById('dns_check_quick_add');
  var ta = document.getElementById('default_dns_checks');
  if(!sel || !ta) return;
  var have = ta.value.split("\n");
  Array.prototype.forEach.call(sel.selectedOptions, function(o){
    if(o.value !== '' && have.indexOf(o.value) === -1){ have.push(o.value); }
  });
  ta.value = have.filter(function(l){ return l !== ''; }).join("\n");
}
</script>
{{end}}
<p><label>Default DNS probe checks:<br>
<textarea name="default_dns_checks" id="default_dns_checks" rows="3" cols="40">{{.DefaultDNSChecksText}}</textarea></label></p>
<p><label>probe_interval_ms: <input name="probe_interval_ms" value="{{.ProbeIntervalMS}}"> (0/blank = default 5000ms)</label></p>
<p><input type="submit" value="Stage probe settings as pending change"></p>
</form>
</section>`

var probesTmpl = template.Must(template.New("probes").Parse(`<!doctype html>
<meta http-equiv="refresh" content="` + fmt.Sprint(probeAutoRefreshSeconds) + `">
<title>dnshived-web — probes</title>
` + styleHTML + `
` + navHTML + pendingBannerHTML + `
<h1>Probes (DNS/DHCP)</h1>

<div class="tab-host">
` + probeManagementHTML + `
<section class="tab-pane" id="tab-results" data-tab="Results" data-tab-order="1" data-tab-default>
<h2 id="results">Results</h2>
<p>{{.Total}} scope(s), {{.ErrorCount}} error(s){{if .PendingCount}}, <span class="dim">{{.PendingCount}} pending</span>{{end}}{{if .CoverageText}} — <span class="dim">{{.CoverageText}}</span>{{end}} — page {{.Page}}/{{.TotalPages}}
{{if gt .Page 1}}<a href="/probes?page={{.PrevPage}}#results">prev</a>{{else}}<span class="dim">prev</span>{{end}}
{{if lt .Page .TotalPages}}<a href="/probes?page={{.NextPage}}#results">next</a>{{end}}
</p>
` + probeCellDefineHTML + `
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>Scope</th>{{range .ProbeHostNames}}<th>from {{.}}</th>{{end}}</tr>
{{range .Rows}}
<tr>
  <td>{{.Scope}}</td>
  {{range .ProbeHostCells}}<td>{{template "probecell" .}}</td>{{end}}
</tr>
{{end}}
</table>
{{if eq .Total 0}}<p class="dim">(no scopes configured)</p>{{end}}
<p class="dim">Ages are as of the probe host's own check, not when this page loaded.
Next auto-refresh: {{.NextRefreshAt}} (every ` + fmt.Sprint(probeAutoRefreshSeconds) + `s) —
<a href="?page={{.Page}}#results">refresh now</a>.</p>
</section>
</div>
` + probePopupHTML + `
`))

// noProbeHostTmpl is the page shown when zero probe hosts are configured.
var noProbeHostTmpl = template.Must(template.New("no-probe-host").Parse(`<!doctype html>
<title>dnshived-web — probes</title>
` + styleHTML + `
` + navHTML + pendingBannerHTML + `
<h1>Probes (DNS/DHCP)</h1>

<p class="dim">No probe host configured yet.</p>
<div class="tab-host">
` + probeManagementHTML + `
</div>
`))

type probesPageData struct {
	Rows         []probeRow
	Total        int
	ErrorCount   int
	PendingCount int
	// CoverageText is the same "probed N of M" convergence clause Overview
	// shows.
	CoverageText  string
	Page          int
	TotalPages    int
	PrevPage      int
	NextPage      int
	NextRefreshAt string
	// ProbeHostNames: configured external probe hosts' display names, in the
	// same order as each Row's ProbeHostCells.
	ProbeHostNames []string
	// Pending — see clusterFormData's identical field for why this is set by
	// the GET handler, not built inline here.
	Pending bool

	probeManagementData
}

type probeManagementData struct {
	NodeProbeHosts        []NodeConfig
	ProbeParallelRows     []probeParallelRow
	AllProbeHostsParallel bool
	ProbeHostDisplayNames map[string]string

	DefaultDNSChecksText string
	GlobalDNSNames       []dnsCheckOption
	ProbeIntervalMS      int

	ManualProbeHosts []manualProbeHost
	ManualIfaces     []string
	ProbeTLSStates   []probeTLSState
	HistoryHosts     []historyHostRow
}

// manualProbeHost is one probe host's manual probes as the page shows them.
type manualProbeHost struct {
	Name, Addr string
	Err        string
	Rows       []manualProbeRow
}

type manualProbeRow struct {
	Name, Interface         string
	VLAN                    string
	ResultText, ResultClass string
	Title, Age              string
	Chips                   []serverChip
	Served                  bool
}

// serverChip is one DHCP server beside a manual probe: known (acknowledged),
// unknown (answered but not acknowledged) or known but silent this time.
type serverChip struct {
	Server, Label, Class, Title, Action string
	CanToggle                           bool
}

// manualProbeRowOf turns one result into the table row; the same wording and
// colors are used wherever a manual probe is shown. served says a scope sits
// on this interface and VLAN: an unknown server there cannot be acknowledged.
func manualProbeRowOf(w watchResult, now time.Time, served bool) manualProbeRow {
	row := manualProbeRow{Name: w.Name, Interface: w.Interface, VLAN: "untagged", Served: served}
	if w.VLANID != 0 {
		row.VLAN = strconv.Itoa(w.VLANID)
	}
	switch {
	case w.Pending:
		row.ResultText, row.ResultClass = "pending…", "warn"
		row.Title = "This manual probe has not run yet."
	case w.Verdict == "rogue":
		row.ResultText, row.ResultClass = "ROGUE "+strings.Join(w.Unexpected, ", "), "crit"
		row.Title = "A DHCP server that is not acknowledged answered on this interface."
	case w.Verdict == "ok":
		row.ResultText, row.ResultClass = "only known servers", "ok"
	case w.Verdict == "clear":
		row.ResultText, row.ResultClass = "no DHCP server answered", "ok"
	default:
		row.ResultText, row.ResultClass = "error: "+w.Error, "warn"
		row.Title = "The probe could not run on this interface, so nothing is known about it."
	}
	if at, err := time.Parse(time.RFC3339, w.ProbedAt); err == nil && !w.Pending {
		row.Age = fmt.Sprintf("%ds ago", max(0, int(now.Sub(at).Seconds())))
	}
	known := make(map[string]bool, len(w.ExpectedServers))
	for _, e := range w.ExpectedServers {
		known[e] = true
	}
	seen := make(map[string]bool, len(w.Servers))
	for _, s := range w.Servers {
		seen[s] = true
		if known[s] {
			row.Chips = append(row.Chips, serverChip{Server: s, Label: "known", Class: "ok", Action: "unack", CanToggle: true,
				Title: "Acknowledged: this server is expected on this segment. Click to stop treating it as known."})
			continue
		}
		chip := serverChip{Server: s, Label: "unknown", Class: "crit", Action: "ack", CanToggle: !served,
			Title: "Answered but is not acknowledged. Acknowledge it if it belongs on this segment."}
		if served {
			chip.Title = "A scope is served on this interface and VLAN, so a second DHCP server here is never acceptable and cannot be acknowledged."
		}
		row.Chips = append(row.Chips, chip)
	}
	for _, e := range w.ExpectedServers {
		if !seen[e] {
			row.Chips = append(row.Chips, serverChip{Server: e, Label: "known, silent", Class: "dim", Action: "unack", CanToggle: true,
				Title: "Acknowledged but did not answer this time. Click to remove it from the known servers."})
		}
	}
	return row
}

// manualProbeIssues lists every manual probe that found a rogue server, in
// the shape the probe issue list uses.
func manualProbeIssues(probeHosts []NodeConfig) []probeIssue {
	var out []probeIssue
	for _, host := range probeHosts {
		results, err := fetchWatch(host)
		if err != nil {
			continue
		}
		for _, w := range results {
			if w.Verdict != "rogue" {
				continue
			}
			where := w.Interface + " (untagged)"
			if w.VLANID != 0 {
				where = fmt.Sprintf("%s VLAN %d", w.Interface, w.VLANID)
			}
			out = append(out, probeIssue{
				Scope: "manual probe " + w.Name, Worker: host.Name,
				DHCPText: "DHCP✖ROGUE", DHCPClass: "crit",
				Detail: fmt.Sprintf("ROGUE DHCP on %s: unlisted server(s) %s answered", where, strings.Join(w.Unexpected, ", ")),
				Rogue:  true,
			})
		}
	}
	return out
}

// buildProbeManagementData fetches everything probeManagementData needs.
func buildProbeManagementData(c config.Cluster, node NodeConfig, probeHosts []NodeConfig) probeManagementData {
	dns := buildDNSConfigFormData(c, node)
	rows := fetchProbeParallelRows(probeHosts)
	return probeManagementData{
		NodeProbeHosts:        probeHosts,
		ProbeParallelRows:     rows,
		AllProbeHostsParallel: allProbeHostsParallel(rows),
		ProbeHostDisplayNames: probeHostDisplayNames(probeHosts),
		DefaultDNSChecksText:  dns.DefaultDNSChecksText,
		GlobalDNSNames:        dns.GlobalDNSNames,
		ProbeIntervalMS:       c.ProbeIntervalMS,
		ManualProbeHosts:      buildManualProbeHosts(probeHosts, c.Scopes),
		ManualIfaces:          manualInterfaceChoices(c),
		ProbeTLSStates:        buildProbeTLSStates(probeHosts),
		HistoryHosts:          buildHistoryHostRows(probeHosts),
	}
}

// scopeServed reports whether any scope sits on this interface and VLAN.
func scopeServed(scopes map[string]config.ScopeConfig, iface string, vlan int) bool {
	for _, sc := range scopes {
		if sc.Parent == iface && sc.VLANID == vlan {
			return true
		}
	}
	return false
}

func buildManualProbeHosts(probeHosts []NodeConfig, scopes map[string]config.ScopeConfig) []manualProbeHost {
	now := time.Now()
	out := make([]manualProbeHost, 0, len(probeHosts))
	for _, h := range probeHosts {
		mh := manualProbeHost{Name: h.Name, Addr: h.Addr}
		results, err := fetchWatch(h)
		if err != nil {
			mh.Err = err.Error()
		}
		for _, w := range results {
			mh.Rows = append(mh.Rows, manualProbeRowOf(w, now, scopeServed(scopes, w.Interface, w.VLANID)))
		}
		out = append(out, mh)
	}
	return out
}

// manualInterfaceChoices is every interface of the cluster, serving or not.
func manualInterfaceChoices(c config.Cluster) []string {
	if c.Platform == nil {
		return nil
	}
	out := append([]string(nil), c.Platform.Workers...)
	if c.Platform.Mgmt != "" {
		out = append(out, c.Platform.Mgmt)
	}
	return out
}

type probeFetch struct {
	scope, worker string
	pr            probeResult
	err           error
}

// noProbeHostPageData backs noProbeHostTmpl.
type noProbeHostPageData struct {
	Pending bool
	probeManagementData
}

func handleProbes(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		c, node, isPending, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "could not read config from any node: "+err.Error(), http.StatusBadGateway)
			return
		}
		mgmt := buildProbeManagementData(c, node, cfg.ProbeHosts)

		if len(cfg.ProbeHosts) == 0 {
			renderTemplate(w, noProbeHostTmpl, noProbeHostPageData{Pending: isPending, probeManagementData: mgmt}, "probes")
			return
		}

		statusRows := fetchAllStatus(cfg, nodesIncludingSelf(cfg))
		scopeNames := configuredScopeNames(statusRows)
		iotSet := iotScopeSet(statusRows)
		disabledSet := disabledScopeSet(statusRows)
		tokens := fetchArbiterTokens(cfg, statusRows)
		ownerUptime := ownerDaemonUptime(cfg)

		// Fetch every (scope, probe host) pair concurrently.
		type job struct {
			scope, worker string
			node          NodeConfig
		}
		var jobs []job
		for _, sc := range scopeNames {
			for _, node := range cfg.ProbeHosts {
				jobs = append(jobs, job{scope: sc, worker: node.Name, node: node})
			}
		}

		results := make([]probeFetch, len(jobs))
		var wg sync.WaitGroup
		for i, j := range jobs {
			wg.Add(1)
			go func(i int, j job) {
				defer wg.Done()
				pr, err := fetchProbe(j.node, j.scope)
				results[i] = probeFetch{scope: j.scope, worker: j.worker, pr: pr, err: err}
			}(i, j)
		}
		wg.Wait()

		fetched := make(map[string]map[string]probeFetch, len(scopeNames))
		for _, res := range results {
			if fetched[res.scope] == nil {
				fetched[res.scope] = make(map[string]probeFetch)
			}
			fetched[res.scope][res.worker] = res
		}

		serving := servingScopeNames(statusRows)
		var activeResults []probeFetch
		for _, res := range results {
			if !disabledSet[res.scope] {
				activeResults = append(activeResults, res)
			}
		}
		errIssues, mismatches, pendingCount := classifyProbeResults(activeResults, tokens, ownerUptime, serving)
		errIssues = append(errIssues, manualProbeIssues(cfg.ProbeHosts)...)
		confirmedLines := debounceProbeMismatches(mismatches)
		errorCount := len(errIssues) + len(confirmedLines)

		probeHostNames := probeHostDisplayNamesList(cfg.ProbeHosts)

		renderNow := time.Now()
		var probeRows []probeRow
		for _, sc := range scopeNames {
			pr := probeRow{Scope: scopeDisplayName(sc, iotSet[sc])}
			tok, hasToken := tokens[sc]
			for _, h := range cfg.ProbeHosts {
				res, ok := fetched[sc][h.Name]
				var stale bool
				if hasToken {
					uptimeSec, hasUptime := ownerUptime[tok.Owner]
					probedAt := res.pr.oldestProbedAt()
					stale = probeStale(probedAt, uptimeSec, hasUptime, renderNow)
				}
				if disabledSet[sc] {
					pr.ProbeHostCells = append(pr.ProbeHostCells, scopeDisabledCell(sc, h.Name))
					continue
				}
				dnsText, dnsClass, dhcpText, dhcpClass, note := probeCellDisplay(renderNow, res.pr, res.err, ok, cachedMismatch(sc, h.Name), stale)
				pr.ProbeHostCells = append(pr.ProbeHostCells, probeCellData{
					Scope: sc, Worker: h.Name,
					DNSText: dnsText, DNSClass: dnsClass, DHCPText: dhcpText, DHCPClass: dhcpClass, Note: note,
				})
			}
			probeRows = append(probeRows, pr)
		}

		totalPages := (len(probeRows) + scopesPerPage - 1) / scopesPerPage
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
		if end > len(probeRows) {
			end = len(probeRows)
		}

		data := probesPageData{
			Rows:                probeRows[start:end],
			Total:               len(probeRows),
			ErrorCount:          errorCount,
			PendingCount:        pendingCount,
			CoverageText:        probeCoverageOf(results, renderNow, disabledSet).text(),
			Page:                page,
			TotalPages:          totalPages,
			PrevPage:            page - 1,
			NextPage:            page + 1,
			NextRefreshAt:       renderNow.Add(probeAutoRefreshSeconds * time.Second).Format("15:04:05"),
			ProbeHostNames:      probeHostNames,
			Pending:             isPending,
			probeManagementData: mgmt,
		}
		renderTemplate(w, probesTmpl, data, "probes")
	}
}

// probeDetailData is one (scope, probe host) pair's full raw probe result.
type probeDetailData struct {
	BackHref, BackText string
	Scope, Worker      string
	FetchError         string
	Pending            bool
	Enabled            bool
	Reachable          bool
	ProbedAt           string
	// ProbeDisabled/ProbeDisabledKnown carry the scope's ACTUAL probe_disabled
	// config field (fetched separately from the probe result itself).
	ProbeDisabled      bool
	ProbeDisabledKnown bool
	// CandidatePending is true when ProbeDisabled above came from a STAGED
	// candidate rather than live config (currentEditableConfig's own
	// isPending).
	CandidatePending bool
	// JustRefreshed is set only by handleProbeRefresh, on a successful
	// on-demand trigger.
	JustRefreshed bool
	QueueWaitMS   int64

	DHCPPending bool
	DNSPending  bool
	DHCPOfferMS int64

	DHCPVerdict string
	DHCPServers []string
	DHCPValid   bool
	DHCPReason  string
	DHCPError   string
	DHCPOffers  []probeDHCPOffer

	DNSAnswered  bool
	DNSValid     bool
	DNSReason    string
	DNSLatencyMS int64
	DNSError     string
	DNSChecks    []probeDNSCheck

	HistoryOff  bool
	HistoryErr  string
	HistoryRows []historyRow
}

// findProbeHost looks up worker by name among cfg.ProbeHosts.
func findProbeHost(cfg *WebConfig, worker string) *NodeConfig {
	for _, h := range cfg.ProbeHosts {
		if h.Name == worker {
			n := h
			return &n
		}
	}
	return nil
}

func formatProbedAt(raw string) string {
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil || t.IsZero() {
		return raw
	}
	return t.Local().Format("2006-01-02 15:04:05 MST")
}

// buildProbeDetailData converts one fetched (or freshly-triggered)
// probeResult into the detail page's render data.
func buildProbeDetailData(scope, worker string, pr probeResult, err error, probeDisabled, probeDisabledKnown, candidatePending bool) probeDetailData {
	data := probeDetailData{
		Scope: scope, Worker: worker,
		Pending: pr.Pending, Enabled: pr.Enabled, Reachable: pr.Reachable, ProbedAt: formatProbedAt(pr.ProbedAt),
		ProbeDisabled: probeDisabled, ProbeDisabledKnown: probeDisabledKnown, CandidatePending: candidatePending,
		DHCPPending: pr.DHCPPending, DNSPending: pr.DNSPending, DHCPOfferMS: pr.DHCP.OfferMS,
		DHCPVerdict: pr.DHCP.Verdict, DHCPServers: pr.DHCP.Servers,
		DHCPValid: pr.DHCP.Valid, DHCPReason: pr.DHCP.Reason, DHCPError: pr.DHCP.Error,
		DHCPOffers:  pr.DHCP.Offers,
		DNSAnswered: pr.DNS.Answered, DNSValid: pr.DNS.Valid, DNSReason: pr.DNS.Reason,
		DNSLatencyMS: pr.DNS.LatencyMS, DNSError: pr.DNS.Error,
		DNSChecks:   pr.DNSChecks,
		QueueWaitMS: pr.QueueWaitMS,
	}
	if err != nil {
		data.FetchError = err.Error()
	}
	return data
}

// fetchScopeProbeDisabled looks up one scope's current probe_disabled
// field via the same candidate-aware config fetch every edit form uses
// (currentEditableConfig).
func fetchScopeProbeDisabled(nodes []NodeConfig, scope string) (disabled bool, known bool, pending bool) {
	c, _, isPending, err := currentEditableConfig(nodes)
	if err != nil {
		return false, false, false
	}
	sc, ok := c.Scopes[scope]
	if !ok {
		return false, false, false
	}
	return sc.ProbeDisabled, true, isPending
}

// handleProbeDetail serves one (scope, probe host) pair's full raw probe
// result — linked from every cell on the Probes grid.
// probeDetailFragmentTmpl is the detail content without the page around it,
// for the popup on the scope list and the Probes page.
var probeDetailFragmentTmpl = template.Must(template.Must(probeDetailTmpl.Clone()).New("fragment").Parse(`<h2>Probe detail: {{.Scope}} <span class="dim">(from {{.Worker}})</span></h2>
<form class="probe-now-form" method="post" action="/probes/{{.Scope}}/{{.Worker}}/refresh"><button type="submit">Probe now</button>
<span class="dim">checks DHCP and DNS now; takes up to about 20 seconds</span></form>
{{template "probe-detail-body" .}}`))

func wantsFragment(r *http.Request) bool { return r.URL.Query().Get("fragment") == "1" }

func renderProbeDetail(w http.ResponseWriter, r *http.Request, data probeDetailData) {
	if wantsFragment(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := probeDetailFragmentTmpl.ExecuteTemplate(w, "fragment", data); err != nil {
			fmt.Fprintf(w, "<p class=\"crit\">render error: %v</p>", err)
		}
		return
	}
	data.BackHref, data.BackText = backTarget(r, "/probes", "back to Probes")
	renderTemplate(w, probeDetailTmpl, data, "probe-detail")
}

func handleProbeDetail(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		scope := r.PathValue("scope")
		worker := r.PathValue("worker")

		node := findProbeHost(cfg, worker)
		if node == nil {
			http.NotFound(w, r)
			return
		}

		pr, err := fetchProbe(*node, scope)
		probeDisabled, known, pending := fetchScopeProbeDisabled(nodesIncludingSelf(cfg), scope)
		data := buildProbeDetailData(scope, worker, pr, err, probeDisabled, known, pending)
		attachScopeHistory(&data, *node)
		renderProbeDetail(w, r, data)
	}
}

// handleProbeToggle serves POST /probes/{scope}/toggle-probe.
func handleProbeSettingsPost(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		defaultChecks, err := parseDNSCheckLines(r.PostForm.Get("default_dns_checks"))
		if err != nil {
			http.Error(w, "bad input: "+err.Error(), http.StatusBadRequest)
			return
		}
		probeMS, _ := strconv.Atoi(r.PostForm.Get("probe_interval_ms"))

		current, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "could not read current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		payload := clusterPushPayloadFrom(current)
		payload.Scopes = current.Scopes
		payload.DefaultDNSChecks = defaultChecks
		payload.ProbeIntervalMS = probeMS

		user, _ := userFromContext(r)
		pushCandidateAndRenderResult(w, cfg, payload, user, "/probes#settings", "back to probes")
	}
}

func handleProbeToggle(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		scope := r.PathValue("scope")
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		worker := r.FormValue("worker")

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
		sc.ProbeDisabled = !sc.ProbeDisabled
		newScopes[scope] = sc

		payload := clusterPushPayloadFrom(c)
		payload.Scopes = newScopes

		user, _ := userFromContext(r)
		backLink := "/probes/" + scope + "/" + worker
		pushCandidateAndRenderResult(w, cfg, payload, user, backLink, "back to probe detail")
	}
}

// handleProbeRefresh serves POST /probes/{scope}/{worker}/refresh.
func handleProbeRefresh(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		scope := r.PathValue("scope")
		worker := r.PathValue("worker")

		node := findProbeHost(cfg, worker)
		if node == nil {
			http.NotFound(w, r)
			return
		}

		pr, err := triggerProbeNow(*node, scope)
		probeDisabled, known, pending := fetchScopeProbeDisabled(nodesIncludingSelf(cfg), scope)
		data := buildProbeDetailData(scope, worker, pr, err, probeDisabled, known, pending)
		data.JustRefreshed = err == nil && pr.Reachable
		attachScopeHistory(&data, *node)
		renderProbeDetail(w, r, data)
	}
}

var probeDetailTmpl = template.Must(template.New("probe-detail").Parse(`<!doctype html>
<title>dnshived-web — probe detail</title>
` + styleHTML + `
` + navHTML + `
<h1>Probe detail: {{.Scope}} (from {{.Worker}})</h1>

<p><a href="{{.BackHref}}">&larr; {{.BackText}}</a></p>
<form method="post" action="/probes/{{.Scope}}/{{.Worker}}/refresh">
<button type="submit">Probe now</button>
</form>
<p class="dim">A manual probe blocks for the real DHCP/DNS check duration (roughly 10-20 seconds) — the page will show the fresh result once it completes.</p>
{{template "probe-detail-body" .}}
{{define "probe-detail-body"}}
{{if .ProbeDisabledKnown}}
<form method="post" action="/probes/{{.Scope}}/toggle-probe" onsubmit="return confirm('This will stage a pending change on every configured node ({{if .ProbeDisabled}}enable{{else}}disable{{end}} probing for scope {{.Scope}}) — nothing is applied until you commit from Pending changes. Continue?')">
<input type="hidden" name="worker" value="{{.Worker}}">
<button type="submit">{{if .ProbeDisabled}}Enable probing for this scope{{else}}Disable probing for this scope{{end}}</button>
</form>
{{if .CandidatePending}}<p class="warn">This button reflects a PENDING candidate, not what's live yet — the DHCP/DNS results below still reflect the LIVE setting until you <a href="/pending">commit</a> it.</p>{{end}}
{{end}}
{{if .JustRefreshed}}<p class="ok"><strong>&#10003; Probe successful — results below are fresh as of just now.</strong></p>{{if .QueueWaitMS}}<p class="dim">Waited {{.QueueWaitMS}}ms for the background sweep to finish probing another scope first.</p>{{end}}{{end}}
{{if .FetchError}}<p class="crit">Fetch error: {{.FetchError}}</p>{{end}}
{{if .Pending}}<p class="dim">Pending — this probe host hasn't completed its first sweep for this scope yet.</p>{{end}}
{{if not .Enabled}}{{if not .Reachable}}<p class="dim">Unreachable — this probe host has no VLAN sub-interface for this scope at all, so nothing was actually attempted (see docs/COOKBOOK.md, "Extend probe-host VLAN coverage").</p>{{else}}<p class="dim">Disabled (live) — this scope currently has probing turned off (probe_disabled).</p>{{end}}{{end}}
{{if .ProbedAt}}<p class="dim">Probed at: {{.ProbedAt}}</p>{{end}}

<h2>DHCP</h2>
{{if .DHCPPending}}<p class="warn" title="The DHCP probe runs one scope after another on each interface; this scope has not had its turn yet.">Pending &mdash; the DHCP probe has not run for this scope yet.</p>
{{else}}
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>Verdict</th><th>Valid</th><th>Reason</th><th>Error</th></tr>
<tr><td>{{.DHCPVerdict}}</td><td>{{.DHCPValid}}</td><td>{{.DHCPReason}}</td><td>{{.DHCPError}}</td></tr>
</table>
{{if .DHCPOfferMS}}<p class="dim">First offer after {{.DHCPOfferMS}} ms.</p>{{end}}
{{if .DHCPOffers}}
<p>Offers received:</p>
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>Server</th><th>Offered IP</th></tr>
{{range .DHCPOffers}}<tr><td>{{.ServerID}}</td><td>{{.OfferedIP}}</td></tr>{{end}}
</table>
{{else}}<p class="dim">(no offers received)</p>{{end}}
{{end}}

<h2>DNS</h2>
{{if .DNSPending}}<p class="warn" title="The DNS probe runs one scope after another on each interface; this scope has not had its turn yet.">Pending &mdash; the DNS probe has not run for this scope yet.</p>
{{else}}
<p>Summary: answered={{.DNSAnswered}} valid={{.DNSValid}} latency={{.DNSLatencyMS}}ms{{if .DNSError}} error={{.DNSError}}{{end}}{{if .DNSReason}} — {{.DNSReason}}{{end}}</p>
{{if .DNSChecks}}
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>Name</th><th>Type</th><th>Against</th><th>Answered</th><th>Latency</th><th>Expected</th><th>Got</th><th>Valid</th><th>Reason</th><th>Skipped</th><th>Error</th></tr>
{{range .DNSChecks}}<tr>
  <td>{{.Name}}</td><td>{{.Type}}</td><td>{{.Against}}</td><td>{{.Answered}}</td>
  <td>{{.LatencyMS}}ms</td><td>{{.Expected}}</td><td>{{.Got}}</td>
  <td class="{{if .Skipped}}dim{{else if .Valid}}ok{{else}}warn{{end}}">{{if .Skipped}}n/a{{else}}{{.Valid}}{{end}}</td>
  <td>{{.Reason}}</td>
  <td>{{.Skipped}}</td><td>{{.Error}}</td>
</tr>{{end}}
</table>
{{else}}<p class="dim">(no per-record DNS checks)</p>{{end}}
{{end}}

<h2>Recent history</h2>
{{if .HistoryErr}}<p class="dim">History is not available from this probe host: {{.HistoryErr}}</p>
{{else if .HistoryOff}}<p class="dim">History is off for this probe host. <a href="/probes#history">Switch it on</a>.</p>
{{else if .HistoryRows}}<table border="1" cellpadding="4" cellspacing="0">
<tr><th>Time</th><th>Check</th><th>Result</th><th>Detail</th></tr>
{{range .HistoryRows}}<tr><td style="white-space:nowrap">{{.Time}}</td><td>{{.Leg}}</td><td class="{{.Class}}">{{.Outcome}}{{if .Failing}} <span class="dim">after {{.Failing}}</span>{{end}}</td><td>{{.Detail}}{{if .Flags}} <span class="dim">({{.Flags}})</span>{{end}}</td></tr>{{end}}
</table>
<p><a href="/probes/history?scope={{.Scope}}&amp;range=7d">full history of this scope</a></p>
{{else}}<p class="dim">(nothing recorded yet)</p>{{end}}
{{end}}
`))

// parseExpectedServers reads one IPv4 address per line or separated by
// commas or spaces.
func parseExpectedServers(raw string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t' }) {
		out = append(out, f)
	}
	return out
}

func probeHostByAddr(cfg *WebConfig, addr string) (NodeConfig, bool) {
	for _, h := range cfg.ProbeHosts {
		if h.Addr == addr {
			return h, true
		}
	}
	return NodeConfig{}, false
}

// handleManualProbeAdd adds one manual probe to a probe host.
func handleManualProbeAdd(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		host, ok := probeHostByAddr(cfg, r.FormValue("addr"))
		if !ok {
			http.Error(w, "unknown probe host", http.StatusBadRequest)
			return
		}
		vlan, err := strconv.Atoi(strings.TrimSpace(r.FormValue("vlan_id")))
		if r.FormValue("vlan_id") == "" {
			vlan, err = 0, nil
		}
		if err != nil {
			http.Error(w, "vlan_id must be a number (0 = untagged)", http.StatusBadRequest)
			return
		}
		current, err := fetchWatch(host)
		if err != nil {
			http.Error(w, "could not read the probe host's manual probes: "+err.Error(), http.StatusBadGateway)
			return
		}
		list := make([]manualProbeDef, 0, len(current)+1)
		for _, c := range current {
			list = append(list, c.def())
		}
		list = append(list, manualProbeDef{
			Name: strings.TrimSpace(r.FormValue("name")), Interface: strings.TrimSpace(r.FormValue("interface")),
			VLANID: vlan, ExpectedServers: parseExpectedServers(r.FormValue("expected_servers")),
		})
		user, _ := userFromContext(r)
		err = pushProbeHostManualProbes(host, list)
		summary := fmt.Sprintf("manual probe %q added on %s", list[len(list)-1].Name, host.Name)
		if err != nil {
			summary = fmt.Sprintf("manual probe %q on %s FAILED: %v", list[len(list)-1].Name, host.Name, err)
		}
		pushAudit(host, user.Name, "probe.manual_add", summary)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "/probes#manual", http.StatusSeeOther)
	}
}

// handleManualProbeRemove removes one manual probe from a probe host.
func handleManualProbeRemove(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		host, ok := probeHostByAddr(cfg, r.FormValue("addr"))
		if !ok {
			http.Error(w, "unknown probe host", http.StatusBadRequest)
			return
		}
		name := r.FormValue("name")
		current, err := fetchWatch(host)
		if err != nil {
			http.Error(w, "could not read the probe host's manual probes: "+err.Error(), http.StatusBadGateway)
			return
		}
		list := make([]manualProbeDef, 0, len(current))
		for _, c := range current {
			if c.Name != name {
				list = append(list, c.def())
			}
		}
		user, _ := userFromContext(r)
		err = pushProbeHostManualProbes(host, list)
		summary := fmt.Sprintf("manual probe %q removed from %s", name, host.Name)
		if err != nil {
			summary = fmt.Sprintf("removing manual probe %q from %s FAILED: %v", name, host.Name, err)
		}
		pushAudit(host, user.Name, "probe.manual_remove", summary)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		http.Redirect(w, r, "/probes#manual", http.StatusSeeOther)
	}
}

// handleManualProbeAck acknowledges or un-acknowledges one DHCP server on a
// manual probe, by editing that probe's expected_servers.
func handleManualProbeAck(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		host, ok := probeHostByAddr(cfg, r.FormValue("addr"))
		if !ok {
			http.Error(w, "unknown probe host", http.StatusBadRequest)
			return
		}
		name, server, action := r.FormValue("name"), strings.TrimSpace(r.FormValue("server")), r.FormValue("action")
		if action != "ack" && action != "unack" {
			http.Error(w, "action must be ack or unack", http.StatusBadRequest)
			return
		}
		if ip := net.ParseIP(server); ip == nil || ip.To4() == nil {
			http.Error(w, "server must be an IPv4 address", http.StatusBadRequest)
			return
		}
		current, err := fetchWatch(host)
		if err != nil {
			http.Error(w, "could not read the probe host's manual probes: "+err.Error(), http.StatusBadGateway)
			return
		}
		if action == "ack" {
			c, _, _, cerr := currentEditableConfig(nodesIncludingSelf(cfg))
			if cerr != nil {
				http.Error(w, "fetch current config: "+cerr.Error(), http.StatusBadGateway)
				return
			}
			for _, w0 := range current {
				if w0.Name == name && scopeServed(c.Scopes, w0.Interface, w0.VLANID) {
					http.Error(w, "a scope is served on this interface and VLAN: a second DHCP server here cannot be acknowledged", http.StatusConflict)
					return
				}
			}
		}
		list, found := editExpected(current, name, server, action == "ack")
		if !found {
			http.Error(w, "unknown manual probe", http.StatusNotFound)
			return
		}
		user, _ := userFromContext(r)
		err = pushProbeHostManualProbes(host, list)
		summary := fmt.Sprintf("manual probe %q: server %s %sed on %s", name, server, action, host.Name)
		if err != nil {
			summary = fmt.Sprintf("manual probe %q: %s of %s on %s FAILED: %v", name, action, server, host.Name, err)
		}
		pushAudit(host, user.Name, "probe.manual_"+action, summary)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "/probes#manual", http.StatusSeeOther)
	}
}

// editExpected returns the whole manual probe list with server added to or
// removed from the named probe's expected servers.
func editExpected(current []watchResult, name, server string, add bool) ([]manualProbeDef, bool) {
	list := make([]manualProbeDef, 0, len(current))
	found := false
	for _, c := range current {
		d := c.def()
		if c.Name == name {
			found = true
			var kept []string
			for _, e := range d.ExpectedServers {
				if e != server {
					kept = append(kept, e)
				}
			}
			if add {
				kept = append(kept, server)
			}
			d.ExpectedServers = kept
		}
		list = append(list, d)
	}
	return list, found
}
