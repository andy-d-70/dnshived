// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
)

// logsEventLimit matches dnshived-top's own renderLogs cap — showing
// more than a screenful of merged events isn't more useful, just noisier.
const logsEventLimit = 25

const logsFetchPerNode = 50

// levelClass maps an event's Level to a CSS class.
func levelClass(level string) string {
	switch level {
	case "WARNING":
		return "warn"
	case "ERROR", "CRITICAL":
		return "crit"
	case "INFO":
		return "ok"
	default:
		return "dim"
	}
}

type logRow struct {
	Time string
	Node string
	// NodeClass is the same worker-identity color topology.go's own
	// roleClass() uses everywhere else.
	NodeClass string
	Level     string
	Class     string
	Prefix    string
	Message   string
}

var logsTmpl = template.Must(template.New("logs").Parse(`<!doctype html>
<title>dnshived-web — logs</title>
` + styleHTML + logModalScriptHTML + `
<h1>Logs</h1>
` + navHTML + `
<details><summary><h2 style="display:inline" id="logs">General logs</h2></summary>
<p>Node filter:
{{range .Filters}}
{{if eq . $.Current}}<strong>[{{.}}]</strong>{{else}}<a href="/logs?node={{.}}">{{.}}</a>{{end}}
{{end}}
</p>
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>Time</th><th>Node</th><th>Level</th><th>Prefix</th><th>Message</th></tr>
{{range .Rows}}
<tr>
  <td>{{.Time}}</td>
  <td class="{{.NodeClass}}">{{.Node}}</td>
  <td class="{{.Class}}">{{.Level}}</td>
  <td>{{.Prefix}}</td>
  <td>{{.Message}}</td>
</tr>
{{end}}
</table>
{{if not .Rows}}<p class="dim">(no events yet)</p>{{end}}
</details>

<details><summary><h2 style="display:inline" id="audit">Audit logs</h2></summary>
<p class="dim">Every node's own persisted, append-only config-change
trail — no merging/de-duplication across nodes. Raw text export (for
scripting/diffing): <a href="/audit" onclick="return showLogModal('Audit log (raw)', '/audit', this)">/audit &rarr;</a>.</p>
{{range .Audit}}
<h3 class="{{.NodeClass}}">{{.Node.Name}} <span class="dim">({{.Node.Addr}})</span></h3>
{{if .Err}}<p class="crit">unreachable: {{.Err}}</p>
{{else if .Body}}<div class="table-wrap"><pre style="margin:0">{{.Body}}</pre></div>
{{else}}<p class="dim">(no audit entries yet)</p>{{end}}
{{end}}
</details>

<details id="daemons"><summary><h2 style="display:inline">Daemon logs (incl. dnsmasq)</h2></summary>

<h3>dnsmasq (shared central instances)</h3>
<p class="dim">The shared central dnsmasq instances every scope's real
DHCP/DNS flows through since the "relay everywhere" cutover — links
open the real tail in a popup.</p>
{{range .DnsmasqLogNodes}}
<h4 class="{{.NodeClass}}">{{.Node}}</h4>
<ul>
<li><a href="/logs/dnsmasq/{{.Node}}/core-dhcp" onclick="return showLogModal('{{.Node}} — core-dhcp', '/logs/dnsmasq/{{.Node}}/core-dhcp', this)">core-dhcp</a> <span class="dim">(real DHCP transaction log — DISCOVER/OFFER/REQUEST/ACK. Shows every configured scope on this node, not just the ones it's currently serving — the shared instance is configured with every scope's own range regardless; dnshived-relay/the DHCP gate decide where a scope is actually served, not this log.)</span></li>
<li><a href="/logs/dnsmasq/{{.Node}}/core-dns" onclick="return showLogModal('{{.Node}} — core-dns', '/logs/dnsmasq/{{.Node}}/core-dns', this)">core-dns</a> <span class="dim">(off by default — <a href="/config#dns">enable under Cluster Settings</a> for real query content here)</span></li>
</ul>
{{end}}
{{if not .DnsmasqLogNodes}}<p class="dim">(no core nodes configured)</p>{{end}}

<h3>Node daemons (dnshived, dnshived-web, dnshived-helper, keepalived, relays)</h3>
<p class="dim">These log to the systemd journal only (no per-daemon log
file) — reading another node's journal needs root, so this goes
through the same privileged-helper path every other privileged
operation already uses. Links open the real tail in a popup.</p>
{{range .DaemonLogNodes}}
{{$node := .Node}}
<h4 class="{{.NodeClass}}">{{.Node}}</h4>
<ul>
{{range .Units}}<li><a href="/logs/daemon/{{$node}}/{{.Unit}}" onclick="return showLogModal('{{$node}} — {{.Label}}', '/logs/daemon/{{$node}}/{{.Unit}}', this)">{{.Label}}</a></li>
{{end}}
</ul>
{{end}}
{{if not .DaemonLogNodes}}<p class="dim">(no core nodes configured)</p>{{end}}

{{if .ProbeDaemonLogNodes}}
<h3>Probe host</h3>
{{range .ProbeDaemonLogNodes}}
{{$node := .Node}}
<h4 class="{{.NodeClass}}">{{.Node}}</h4>
<ul>
{{range .Units}}<li><a href="/logs/daemon/{{$node}}/{{.Unit}}" onclick="return showLogModal('{{$node}} — {{.Label}}', '/logs/daemon/{{$node}}/{{.Unit}}', this)">{{.Label}}</a></li>
{{end}}
</ul>
{{end}}
{{end}}
</details>

<dialog id="log-modal">
<h3 id="log-modal-title" style="margin-top:0"></h3>
<div class="table-wrap"><pre id="log-modal-body" style="margin:0"></pre></div>
<form method="dialog"><button>Close</button></form>
</dialog>
`))

type logsPageData struct {
	Rows    []logRow
	Filters []string
	Current string
	Audit   []auditSectionRow
	// DnsmasqLogNodes: one row per configured core node.
	DnsmasqLogNodes []daemonLogNodeRow
	DaemonLogNodes  []daemonLogNodeRow
	// ProbeDaemonLogNodes: same shape, for the adopted probe host.
	ProbeDaemonLogNodes []daemonLogNodeRow
}

// auditSectionRow adapts nodeAuditSection (audit.go) for template
// rendering.
type auditSectionRow struct {
	Node      NodeConfig
	NodeClass string
	Body      string
	Err       string
}

// daemonLogNodeRow is one node's own entry in the Daemon logs section.
type daemonLogNodeRow struct {
	Node      string
	NodeClass string
	Units     []daemonLogUnit
}

// daemonLogUnit is one systemd unit this node runs.
type daemonLogUnit struct {
	Label string
	Unit  string
}

// coreDaemonLogUnits/probeDaemonLogUnits are this project's own real unit
// sets per role.
var coreDaemonLogUnits = []daemonLogUnit{
	{"dnshived", "dnshived.service"},
	{"dnshived-web", "dnshived-web.service"},
	{"dnshived-helper", "dnshived-helper.service"},
	{"keepalived (mgmt VIP)", "dnshived-keepalived-mgmt.service"},
	{"keepalived (scopes)", "dnshived-keepalived.service"},
	{"dnshived-relay", "dnshived-relay.service"},
	{"dnshived-dnsrelay", "dnshived-dnsrelay.service"},
}

var probeDaemonLogUnits = []daemonLogUnit{
	{"dnshived-probe", "dnshived-probe.service"},
	{"dnshived-probe-helper", "dnshived-probe-helper.service"},
}

func handleLogs(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		filter := r.URL.Query().Get("node")
		if filter == "" {
			filter = "all"
		}
		nodes := nodesIncludingSelf(cfg)

		statusRows := fetchAllStatus(cfg, nodes)

		eventResults, ok := fetchAllEvents(cfg, nodes, logsFetchPerNode)
		if !ok {
			eventResults = fetchAllNodes(nodes, func(n NodeConfig) ([]event, error) {
				return fetchEvents(n, logsFetchPerNode)
			})
		}

		type taggedEvent struct {
			e     event
			label string
		}
		var all []taggedEvent
		for i, res := range eventResults {
			if res.Err != nil {
				continue
			}
			nodeRole := statusRows[i].Status.Role
			for _, e := range res.Value {
				if filter == "all" || nodeRole == filter {
					all = append(all, taggedEvent{e, nodeRole})
				}
			}
		}
		if len(cfg.ProbeHosts) > 0 {
			probeEventResults := fetchAllNodes(cfg.ProbeHosts, func(n NodeConfig) ([]event, error) {
				return fetchEvents(n, logsFetchPerNode)
			})
			for _, res := range probeEventResults {
				if res.Err != nil {
					continue
				}
				name := "probe"
				for _, e := range res.Value {
					if filter == "all" || name == filter {
						all = append(all, taggedEvent{e, name})
					}
				}
			}
		}
		sort.Slice(all, func(i, j int) bool { return all[i].e.Timestamp.After(all[j].e.Timestamp) })

		var rows []logRow
		for _, t := range all {
			if len(rows) >= logsEventLimit {
				break
			}
			rows = append(rows, logRow{
				Time:      t.e.Timestamp.Local().Format("01-02 15:04:05"),
				Node:      t.label,
				NodeClass: roleClass(t.label),
				Level:     t.e.Level,
				Class:     levelClass(t.e.Level),
				Prefix:    t.e.Prefix,
				Message:   t.e.Message,
			})
		}

		filters := []string{"all", "core-1", "core-2", "core-3"}
		if len(cfg.ProbeHosts) > 0 {
			filters = append(filters, "probe")
		}

		var audit []auditSectionRow
		for _, sec := range fetchNodeAuditSections(nodes) {
			row := auditSectionRow{Node: sec.Node, NodeClass: roleClass(sec.Node.Name), Body: sec.Body}
			if sec.Err != nil {
				row.Err = sec.Err.Error()
			}
			audit = append(audit, row)
		}

		var dnsmasqLogNodes []daemonLogNodeRow
		for _, n := range nodes {
			if isCoreRole(n.Name) {
				dnsmasqLogNodes = append(dnsmasqLogNodes, daemonLogNodeRow{Node: n.Name, NodeClass: roleClass(n.Name)})
			}
		}

		var daemonLogNodes []daemonLogNodeRow
		for _, n := range nodes {
			daemonLogNodes = append(daemonLogNodes, daemonLogNodeRow{Node: n.Name, NodeClass: roleClass(n.Name), Units: coreDaemonLogUnits})
		}
		var probeDaemonLogNodes []daemonLogNodeRow
		for _, n := range cfg.ProbeHosts {
			probeDaemonLogNodes = append(probeDaemonLogNodes, daemonLogNodeRow{Node: n.Name, NodeClass: roleClass(n.Name), Units: probeDaemonLogUnits})
		}

		data := logsPageData{
			Rows:                rows,
			Filters:             filters,
			Current:             filter,
			Audit:               audit,
			DnsmasqLogNodes:     dnsmasqLogNodes,
			DaemonLogNodes:      daemonLogNodes,
			ProbeDaemonLogNodes: probeDaemonLogNodes,
		}
		renderTemplate(w, logsTmpl, data, "logs")
	}
}

// dnsmasqLogViewLines is the tail size for the raw log-view page.
const dnsmasqLogViewLines = 200

// handleDnsmasqLogView serves the raw tail of one core node's own dnsmasq
// log as plain text.
func handleDnsmasqLogView(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		nodeName := r.PathValue("node")
		scope := r.PathValue("scope")

		node, isProbeHost, ok := findNode(cfg, nodeName)
		if !ok || isProbeHost {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		lines, note, err := fetchDnsmasqLogFull(node, scope, dnsmasqLogViewLines)
		if err != nil {
			fmt.Fprintf(w, "unreachable: %v\n", err)
			return
		}
		if note != "" {
			fmt.Fprintln(w, note)
		}
		if len(lines) == 0 {
			if note == "" {
				fmt.Fprintln(w, "(no log lines yet)")
			}
			return
		}
		fmt.Fprintln(w, strings.Join(lines, "\n"))
	}
}

// handleDaemonLogView serves the raw tail of one node's own daemon unit's
// systemd journal as plain text.
func handleDaemonLogView(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		nodeName := r.PathValue("node")
		unit := r.PathValue("unit")

		node, _, ok := findNode(cfg, nodeName)
		if !ok {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		lines, err := fetchDaemonLog(node, unit, dnsmasqLogViewLines)
		if err != nil {
			fmt.Fprintf(w, "unreachable: %v\n", err)
			return
		}
		if len(lines) == 0 {
			fmt.Fprintln(w, "(no log lines yet)")
			return
		}
		fmt.Fprintln(w, strings.Join(lines, "\n"))
	}
}
