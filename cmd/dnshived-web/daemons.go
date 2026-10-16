// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"
)

// checkDaemonHealth fetches every node's daemon list and returns a
// human-readable line for each non-healthy unit (crit or warn per
// daemonClass).
func checkDaemonHealth(cfg *WebConfig, nodes []NodeConfig) []string {
	var issues []string
	for _, res := range fetchAllDaemons(cfg, nodes) {
		if res.Err != nil {
			continue // node unreachable — already surfaced by Overview's Workers table
		}
		for _, d := range res.Value.Daemons {
			if isDnsmasqScopeUnit(d.Unit) || isRelayClientEntry(d.Unit) {
				continue
			}
			text, class := daemonClass(d)
			if class == "crit" || class == "warn" {
				issues = append(issues, fmt.Sprintf("%s: %s is %s", res.Node.Name, d.Unit, text))
			}
		}
	}
	return issues
}

// daemonRow is one flattened (node, unit) line.
type daemonRow struct {
	Node string
	// NodeClass is the same worker-identity color topology.go's own
	// roleClass() uses everywhere else.
	NodeClass string
	Unit      string
	Text      string
	Class     string
	Uptime    string
	Version   string
	PID       int
	RunningAs string
	// RestartLabel is empty when this row has no restart action.
	RestartLabel string
	IsProbeHost  bool
	// DnsmasqDetail is set ONLY on the synthetic "dnsmasq" aggregate row.
	DnsmasqDetail []daemonRow

	// RelayDetail is set only on the synthetic "dhcp-relay" aggregate row.
	RelayDetail []daemonRow

	// Cache is set ONLY on the dnshived-dnsrelay.service row.
	Cache string
}

// restartLabel decides whether row (node, unit) gets a restart button at
// all, and what to call it.
func restartLabel(unit string, notFound bool, isProbeHost bool) string {
	if notFound {
		return ""
	}
	if isProbeHost {
		if unit == "dnshived-probe.service" {
			return "Restart"
		}
		return ""
	}
	switch {
	case unit == "dnshived.service", unit == "dnshived-keepalived-mgmt.service",
		unit == "dnshived-helper.service", unit == "dnshived-web.service",
		unit == "dnshived-relay.service", unit == "dnshived-dnsrelay.service":
		return "Restart"
	case unit == "dnshived-keepalived.service":
		return "Reload"
	case isDnsmasqScopeUnit(unit):
		return "Restart"
	default:
		return ""
	}
}

// isDnsmasqScopeUnit reports whether unit is one specific scope's own
// dnshived-dnsmasq@<scope>.service.
func isDnsmasqScopeUnit(unit string) bool {
	if unit == "dnshived-dnsmasq@core-dns.service" || unit == "dnshived-dnsmasq@core-dhcp.service" {
		return false
	}
	return strings.HasPrefix(unit, "dnshived-dnsmasq@") && strings.HasSuffix(unit, ".service")
}

func isRelayClientEntry(unit string) bool {
	return strings.HasPrefix(unit, "dhcp-relay: ")
}

func runningAsText(pid int, user string) string {
	if pid == 0 {
		return "—"
	}
	if user == "" {
		return "unknown"
	}
	return user
}

// daemonClass picks one unit's display text and CSS class — ported from
// dnshived-top's identical daemonCell (ANSI colors replaced with CSS
// classes).
func daemonClass(d daemonStatus) (text, class string) {
	if d.Error != "" {
		return "unknown", "dim"
	}
	if d.LoadState == "not-found" {
		return "not installed", "dim"
	}
	if d.TotalCount == 0 && d.ActiveState != "active" && (d.Unit == "dhcp-relay" || d.Unit == "dnshived-relay.service" || d.Unit == "dnshived-dnsrelay.service") {
		return "no scope eligible yet", "dim"
	}
	if d.TotalCount > 0 && (d.Unit == "dnsmasq" || d.Unit == "dhcp-relay") {
		text = fmt.Sprintf("%d/%d active", d.ActiveCount, d.TotalCount)
		if d.ActiveCount == d.TotalCount {
			return text, "ok"
		}
		return text, "crit"
	}
	text = d.ActiveState
	if d.SubState != "" && d.SubState != d.ActiveState {
		text = d.ActiveState + "/" + d.SubState
	}
	switch d.ActiveState {
	case "active":
		return text, "ok"
	case "activating", "reloading", "deactivating":
		return text, "warn"
	default:
		return text, "crit"
	}
}

// formatUptime renders a duration the way uptime/ps conventionally do —
// coarsest two units, dropping finer ones once the coarser one is nonzero.
func formatUptime(sec int64) string {
	if sec <= 0 {
		return "-"
	}
	d := time.Duration(sec) * time.Second
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, mins)
	case mins > 0:
		return fmt.Sprintf("%dm", mins)
	default:
		return fmt.Sprintf("%ds", sec)
	}
}

// formatCacheStats renders dnshived-dnsrelay's own cache stats
// (fetchDNSRelayStats) as one plain summary line for the Daemons table.
func formatCacheStats(s dnsRelayStatsResult) string {
	if !s.Available {
		return ""
	}
	entries := fmt.Sprintf("%d/%d entries", s.Entries, s.CacheSize)
	if s.CacheMaxBytes > 0 {
		return fmt.Sprintf("%.1f%% hit rate — %s, %s/%s", s.HitRatePct, entries, formatBytesIEC(s.BytesUsed), formatBytesIEC(int64(s.CacheMaxBytes)))
	}
	return fmt.Sprintf("%.1f%% hit rate — %s, %s", s.HitRatePct, entries, formatBytesIEC(s.BytesUsed))
}

// formatBytesIEC renders a byte count the conventional short way
// (KiB/MiB/GiB, 1024-based).
func formatBytesIEC(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

var daemonsTmpl = template.Must(template.New("daemons").Parse(`<!doctype html>
<title>dnshived-web — daemons</title>
` + styleHTML + `
<h1>Daemons</h1>
` + navHTML + `
<div class="view-tabs"><a href="/config">&larr; Cluster config</a><span class="active">Daemons</span></div>
<p>{{.Total}} unit(s)</p>
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>Node</th><th>Unit</th><th>State</th><th>Uptime</th><th>Version</th><th title="the ACTUAL live process's own user, not just what the unit is configured to run as">Running as</th><th title="the ACTUAL live process's own PID">PID</th><th></th></tr>
{{range .Rows}}
<tr>
  <td class="{{.NodeClass}}">{{.Node}}</td>
  <td>{{.Unit}}</td>
  <td class="{{.Class}}">{{.Text}}{{if .Cache}}<br><small class="dim">{{.Cache}}</small>{{end}}</td>
  <td>{{.Uptime}}</td>
  <td>{{.Version}}</td>
  <td class="{{if eq .RunningAs "root"}}warn{{end}}">{{.RunningAs}}</td>
  <td>{{if .PID}}{{.PID}}{{else}}—{{end}}</td>
  <td>{{if .RestartLabel}}<a href="/daemons/{{.Node}}/{{.Unit}}/restart/confirm">{{.RestartLabel}}</a>{{end}}</td>
</tr>
{{if .DnsmasqDetail}}
<tr><td colspan="8" style="padding:0">
<details>
<summary class="dim">{{len .DnsmasqDetail}} scope(s) — click to expand for each one's own PID/restart</summary>
<table border="1" cellpadding="4" cellspacing="0" style="margin:.3rem 0 .3rem 1.5rem">
{{range .DnsmasqDetail}}
<tr>
  <td>{{.Unit}}</td>
  <td class="{{.Class}}">{{.Text}}</td>
  <td>{{.Uptime}}</td>
  <td class="{{if eq .RunningAs "root"}}warn{{end}}">{{.RunningAs}}</td>
  <td>{{if .PID}}{{.PID}}{{else}}—{{end}}</td>
  <td>{{if .RestartLabel}}<a href="/daemons/{{.Node}}/{{.Unit}}/restart/confirm">{{.RestartLabel}}</a>{{end}}</td>
</tr>
{{end}}
</table>
</details>
</td></tr>
{{end}}
{{if .RelayDetail}}
<tr><td colspan="8" style="padding:0">
<details>
<summary class="dim">{{len .RelayDetail}} VLAN(s) relayed — click to expand</summary>
<table border="1" cellpadding="4" cellspacing="0" style="margin:.3rem 0 .3rem 1.5rem">
{{range .RelayDetail}}
<tr>
  <td>{{.Unit}}</td>
  <td class="{{.Class}}">{{.Text}}</td>
</tr>
{{end}}
</table>
</details>
</td></tr>
{{end}}
{{end}}
</table>
{{if eq .Total 0}}<p class="dim">(no daemon data available)</p>{{end}}
`))

type daemonsPageData struct {
	Rows  []daemonRow
	Total int
}

func handleDaemons(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		// nodesIncludingSelf, not cfg.Nodes: cfg.Nodes never lists this
		// instance's own node, whose daemons were missing here.
		nodes := nodesIncludingSelf(cfg)
		results := fetchAllDaemons(cfg, nodes)
		cacheStatsByNode := make(map[string]dnsRelayStatsResult, len(nodes))
		for _, res := range fetchAllNodes(nodes, fetchDNSRelayStats) {
			if res.Err == nil {
				cacheStatsByNode[res.Node.Name] = res.Value
			}
		}

		var rows []daemonRow
		for _, res := range results {
			if res.Err != nil {
				continue
			}
			aggIdx := -1
			relayAggIdx := -1
			for _, d := range res.Value.Daemons {
				if isDnsmasqScopeUnit(d.Unit) {
					if aggIdx < 0 {
						continue
					}
					text, class := daemonClass(d)
					rows[aggIdx].DnsmasqDetail = append(rows[aggIdx].DnsmasqDetail, daemonRow{
						Node: res.Node.Name, NodeClass: roleClass(res.Node.Name), Unit: d.Unit, Text: text, Class: class,
						Uptime: formatUptime(d.UptimeSec), Version: d.Version,
						PID: d.PID, RunningAs: runningAsText(d.PID, d.User),
						RestartLabel: restartLabel(d.Unit, d.LoadState == "not-found", false),
					})
					continue
				}
				if isRelayClientEntry(d.Unit) {
					if relayAggIdx < 0 {
						continue
					}
					text, class := daemonClass(d)
					rows[relayAggIdx].RelayDetail = append(rows[relayAggIdx].RelayDetail, daemonRow{
						Node: res.Node.Name, NodeClass: roleClass(res.Node.Name), Unit: d.Unit, Text: text, Class: class,
					})
					continue
				}
				text, class := daemonClass(d)
				row := daemonRow{
					Node: res.Node.Name, NodeClass: roleClass(res.Node.Name), Unit: d.Unit, Text: text, Class: class,
					Uptime: formatUptime(d.UptimeSec), Version: d.Version,
					PID: d.PID, RunningAs: runningAsText(d.PID, d.User),
					RestartLabel: restartLabel(d.Unit, d.LoadState == "not-found", false),
				}
				if d.Unit == "dnshived-dnsrelay.service" {
					row.Cache = formatCacheStats(cacheStatsByNode[res.Node.Name])
				}
				rows = append(rows, row)
				switch d.Unit {
				case "dnsmasq":
					aggIdx = len(rows) - 1
				case "dhcp-relay":
					relayAggIdx = len(rows) - 1
				}
			}
		}
		for _, res := range fetchAllNodes(cfg.ProbeHosts, fetchDaemons) {
			if res.Err != nil {
				continue
			}
			for _, d := range res.Value.Daemons {
				text, class := daemonClass(d)
				rows = append(rows, daemonRow{
					Node: res.Node.Name, NodeClass: "node-probe", Unit: d.Unit, Text: text, Class: class,
					Uptime: formatUptime(d.UptimeSec), Version: d.Version,
					PID: d.PID, RunningAs: runningAsText(d.PID, d.User),
					RestartLabel: restartLabel(d.Unit, d.LoadState == "not-found", true),
					IsProbeHost:  true,
				})
			}
		}

		data := daemonsPageData{
			Rows:  rows,
			Total: len(rows),
		}
		renderTemplate(w, daemonsTmpl, data, "daemons")
	}
}

// findNode looks up name among cfg.Nodes first, then cfg.ProbeHosts.
func findNode(cfg *WebConfig, name string) (node NodeConfig, isProbeHost bool, ok bool) {
	for _, n := range cfg.Nodes {
		if n.Name == name {
			return n, false, true
		}
	}
	for _, n := range cfg.ProbeHosts {
		if n.Name == name {
			return n, true, true
		}
	}
	if self, ok := selfNodeConfig(cfg); ok && self.Name == name {
		return self, false, true
	}
	return NodeConfig{}, false, false
}

type restartConfirmData struct {
	Node, Unit, Label string
}

var restartConfirmTmpl = template.Must(template.New("restart-confirm").Parse(`<!doctype html>
<title>dnshived-web — confirm restart</title>
` + styleHTML + `
<h1>Confirm: {{.Label}} {{.Unit}} on {{.Node}}</h1>
` + navHTML + `
<p><a href="/daemons">&larr; back to Daemons</a></p>
<p class="warn"><strong>This is a real action, not a preview.</strong> {{.Label}}ing {{.Unit}} briefly
interrupts whatever it's currently doing on {{.Node}} — for dnshived.service itself, this daemon's
own documented ~15-20s dead-daemon gate closure applies (any scope this node is currently serving
goes unserved on this node for that window, until it comes back up).</p>
<form method="post" action="/daemons/{{.Node}}/{{.Unit}}/restart">
<button type="submit">Yes, {{.Label}} it</button>
</form>
`))

// handleDaemonRestartConfirm serves the warning + confirmation form for
// one (node, unit) restart action.
func handleDaemonRestartConfirm(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		nodeName := r.PathValue("node")
		unit := r.PathValue("unit")

		_, isProbeHost, ok := findNode(cfg, nodeName)
		if !ok {
			http.NotFound(w, r)
			return
		}
		label := restartLabel(unit, false, isProbeHost)
		if label == "" {
			http.Error(w, "unit not restartable", http.StatusBadRequest)
			return
		}
		renderTemplate(w, restartConfirmTmpl, restartConfirmData{Node: nodeName, Unit: unit, Label: label}, "restart-confirm")
	}
}

// handleDaemonRestart serves the actual POST that triggers the restart.
func handleDaemonRestart(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		nodeName := r.PathValue("node")
		unit := r.PathValue("unit")

		node, isProbeHost, ok := findNode(cfg, nodeName)
		if !ok {
			http.NotFound(w, r)
			return
		}
		if restartLabel(unit, false, isProbeHost) == "" {
			http.Error(w, "unit not restartable", http.StatusBadRequest)
			return
		}

		_, err := restartUnit(node, unit, isProbeHost)

		user, _ := userFromContext(r)
		action := "daemon.restart"
		summary := fmt.Sprintf("restarted %s on %s", unit, nodeName)
		if err != nil {
			summary = fmt.Sprintf("restart %s on %s FAILED: %v", unit, nodeName, err)
		}
		pushAudit(node, user.Name, action, summary)

		http.Redirect(w, r, "/daemons", http.StatusSeeOther)
	}
}
