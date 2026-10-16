// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"sync"
	"time"

	"dnshived/internal/config"
	"dnshived/internal/nftgate"
)

type topologyVLAN struct {
	ScopeName       string
	VLANID          int
	IfaceName       string // e.g. "ens19.104"
	NodeIP          string
	VIP             string
	VRRPID          int
	PreferredWorker string
	DnsmasqUnit     string
	Badge           string
	BadgeClass      string
	Color           string

	// Probe result fields — only ever populated on a probe host's own branch
	// (a cluster node's VLAN entry has no probe vantage point of its own).
	DNSText   string
	DNSClass  string
	DHCPText  string
	DHCPClass string
	ProbedAt  string
}

type topologyInterface struct {
	Name  string
	Label string
	VLANs []topologyVLAN
}

// interfaceLabel resolves an operator-chosen display name for a real
// interface, falling back to the raw kernel name when none is set.
func interfaceLabel(labels map[string]string, ifname string) string {
	if l := labels[ifname]; l != "" {
		return l
	}
	return ifname
}

// topologyNode is one node's whole tree branch, as rendered on the page.
type topologyNode struct {
	Name        string
	RoleClass   string // "node-core-1"/"node-core-2"/"node-core-3"/"node-probe"
	RoleLabel   string
	FetchError  string
	IsProbeHost bool
	MgmtIface   string
	MgmtVIP     string
	Interfaces  []topologyInterface
	// Note is a one-line explanation shown in place of an empty Interfaces
	// list.
	Note string
}

// roleClass maps a node's self-reported role (or "probe" for a probe host)
// to its CSS color class.
func roleClass(role string) string {
	switch role {
	case config.RoleCore1:
		return "node-core-1"
	case config.RoleCore2:
		return "node-core-2"
	case config.RoleCore3:
		return "node-core-3"
	default:
		return "node-probe"
	}
}

// scopeDnsmasqUnit mirrors internal/agent's own systemd unit naming for a
// scope's dnsmasq instance (dnshived-dnsmasq@<scope>.service).
func scopeDnsmasqUnit(scope string) string {
	return "dnshived-dnsmasq@" + scope + ".service"
}

// buildTopologyNode assembles one cluster node's tree branch from its own
// concurrently-fetched status (Role, Serving) and full config (Platform,
// Scopes, MgmtVIP).
func buildTopologyNode(node NodeConfig, st nodeStatus, statErr error, c config.Cluster, cfgErr error) topologyNode {
	tn := topologyNode{
		Name:      node.Name,
		RoleLabel: st.Role,
	}
	if statErr != nil {
		tn.FetchError = statErr.Error()
		tn.RoleClass = roleClass("")
		return tn
	}
	tn.RoleClass = roleClass(st.Role)
	if cfgErr != nil {
		tn.FetchError = cfgErr.Error()
		return tn
	}

	if c.Platform != nil {
		tn.MgmtIface = c.Platform.Mgmt
	}

	if c.MgmtVIP != nil {
		tn.MgmtVIP = c.MgmtVIP.VIP
	}

	servingSet := make(map[string]bool, len(st.Serving))
	for _, s := range st.Serving {
		servingSet[s] = true
	}

	byParent := make(map[string][]topologyVLAN)
	for name, sc := range c.Scopes {
		badge, badgeClass := "standby", "dim"
		if servingSet[name] {
			badge, badgeClass = "serving", "ok"
		}
		byParent[sc.Parent] = append(byParent[sc.Parent], topologyVLAN{
			ScopeName:       name,
			VLANID:          sc.VLANID,
			IfaceName:       nftgate.InterfaceName(sc.Parent, sc.VLANID),
			NodeIP:          sc.NodeIP,
			VIP:             sc.VIP,
			VRRPID:          sc.VRRPID,
			PreferredWorker: sc.PreferredWorker,
			DnsmasqUnit:     scopeDnsmasqUnit(name),
			Badge:           badge,
			BadgeClass:      badgeClass,
			Color:           sc.Color,
		})
	}

	var ifaceNames []string
	var labels map[string]string
	if c.Platform != nil {
		ifaceNames = c.Platform.Workers
		labels = c.Platform.InterfaceLabels
	}
	for _, ifname := range ifaceNames {
		vlans := byParent[ifname]
		sort.Slice(vlans, func(i, j int) bool { return vlans[i].VLANID < vlans[j].VLANID })
		tn.Interfaces = append(tn.Interfaces, topologyInterface{Name: ifname, Label: interfaceLabel(labels, ifname), VLANs: vlans})
		delete(byParent, ifname)
	}
	// Any scope whose parent isn't in Platform.Workers (stale config, manual
	// edit) still needs to be visible somewhere rather than silently dropped
	// from the tree.
	var strayNames []string
	for ifname := range byParent {
		strayNames = append(strayNames, ifname)
	}
	sort.Strings(strayNames)
	for _, ifname := range strayNames {
		vlans := byParent[ifname]
		sort.Slice(vlans, func(i, j int) bool { return vlans[i].VLANID < vlans[j].VLANID })
		tn.Interfaces = append(tn.Interfaces, topologyInterface{Name: ifname, Label: ifname, VLANs: vlans})
	}

	return tn
}

// topologyEndpoint is one node's (worker or probe host) view of a single
// scope, as shown inside a combined-view scope card.
type topologyEndpoint struct {
	NodeName   string
	RoleClass  string
	RoleLabel  string
	IsProbe    bool
	Badge      string
	BadgeClass string
	DNSText    string
	DNSClass   string
	DHCPText   string
	DHCPClass  string
	ProbedAt   string
	ProbedAgo  string
}

type topologyScopeCombined struct {
	ScopeName       string
	VLANID          int
	IfaceName       string
	VIP             string
	VRRPID          int
	PreferredWorker string
	DnsmasqUnit     string
	ServingLabel    string
	ServingClass    string
	ChipClass       string
	HasError        bool
	ErrorReason     string
	Endpoints       []topologyEndpoint
	Color           string
}

type topologyInterfaceCombined struct {
	Name   string
	Label  string
	Scopes []topologyScopeCombined
}

// topologyRailNode is one entry in the combined view's left-hand node
// rail.
type topologyRailNode struct {
	Name      string
	RoleClass string
	RoleLabel string
}

type topologyPageData struct {
	Nodes       []topologyNode
	RailNodes   []topologyRailNode
	Combined    []topologyInterfaceCombined
	TotalScopes int
	ErrorScopes int
	// ErrorScopeList names each erroring scope, linking to its own chip's
	// existing #pop-<name> popup anchor.
	ErrorScopeList []topologyErrorScope
	HealthyClass   string
}

// topologyErrorScope is one erroring scope's name + reason, for the
// combined-view summary banner's own "which one?" list.
type topologyErrorScope struct {
	Name   string
	Reason string
}

// summarizeCombined counts total scopes and scopes with HasError set, and
// names each erroring one (sorted, for a stable order).
func summarizeCombined(combined []topologyInterfaceCombined) (total, errs int, errList []topologyErrorScope) {
	for _, iface := range combined {
		for _, sc := range iface.Scopes {
			total++
			if sc.HasError {
				errs++
				errList = append(errList, topologyErrorScope{Name: sc.ScopeName, Reason: sc.ErrorReason})
			}
		}
	}
	sort.Slice(errList, func(i, j int) bool { return errList[i].Name < errList[j].Name })
	return total, errs, errList
}

func buildTopologyRail(nodes []topologyNode) []topologyRailNode {
	var rail []topologyRailNode
	for _, n := range nodes {
		if n.FetchError != "" {
			continue
		}
		rail = append(rail, topologyRailNode{Name: n.Name, RoleClass: n.RoleClass, RoleLabel: n.RoleLabel})
	}
	sort.SliceStable(rail, func(i, j int) bool {
		ri, rj := endpointRank(rail[i].RoleLabel, rail[i].RoleLabel == "probe"), endpointRank(rail[j].RoleLabel, rail[j].RoleLabel == "probe")
		if ri != rj {
			return ri < rj
		}
		return rail[i].Name < rail[j].Name
	})
	return rail
}

// buildTopologyPageData assembles the combined tree, its node rail, and
// the at-a-glance error summary from one already-built per-node node list.
func buildTopologyPageData(nodes []topologyNode) topologyPageData {
	combined := buildCombinedTopology(nodes)
	total, errs, errList := summarizeCombined(combined)
	healthyClass := "ok"
	if errs > 0 {
		healthyClass = "crit"
	}
	return topologyPageData{
		Nodes:          nodes,
		RailNodes:      buildTopologyRail(nodes),
		Combined:       combined,
		TotalScopes:    total,
		ErrorScopes:    errs,
		ErrorScopeList: errList,
		HealthyClass:   healthyClass,
	}
}

// endpointRank orders a combined scope card's endpoints core-1, then
// core-2, then core-3, then probe host(s) (alphabetically by name).
func endpointRank(roleLabel string, isProbe bool) int {
	switch {
	case isProbe:
		return 3
	case roleLabel == config.RoleCore1:
		return 0
	case roleLabel == config.RoleCore2:
		return 1
	case roleLabel == config.RoleCore3:
		return 2
	default:
		return 4
	}
}

func formatProbeAge(raw string) string {
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil || t.IsZero() {
		return ""
	}
	return formatDuration(time.Since(t)) + " ago"
}

func appendErrorReason(existing, next string) string {
	if existing == "" {
		return next
	}
	return existing + "; " + next
}

func buildCombinedTopology(nodes []topologyNode) []topologyInterfaceCombined {
	byIface := make(map[string]map[string]*topologyScopeCombined)
	ifaceLabels := make(map[string]string)
	var ifaceOrder []string

	for _, n := range nodes {
		if n.FetchError != "" {
			continue
		}
		for _, iface := range n.Interfaces {
			scopeMap, ok := byIface[iface.Name]
			if !ok {
				scopeMap = make(map[string]*topologyScopeCombined)
				byIface[iface.Name] = scopeMap
				ifaceLabels[iface.Name] = iface.Label
				ifaceOrder = append(ifaceOrder, iface.Name)
			}
			for _, v := range iface.VLANs {
				sc, ok := scopeMap[v.ScopeName]
				if !ok {
					sc = &topologyScopeCombined{
						ScopeName:       v.ScopeName,
						VLANID:          v.VLANID,
						IfaceName:       v.IfaceName,
						VIP:             v.VIP,
						VRRPID:          v.VRRPID,
						PreferredWorker: v.PreferredWorker,
						DnsmasqUnit:     v.DnsmasqUnit,
						Color:           v.Color,
					}
					scopeMap[v.ScopeName] = sc
				}
				sc.Endpoints = append(sc.Endpoints, topologyEndpoint{
					NodeName:   n.Name,
					RoleClass:  n.RoleClass,
					RoleLabel:  n.RoleLabel,
					IsProbe:    n.IsProbeHost,
					Badge:      v.Badge,
					BadgeClass: v.BadgeClass,
					DNSText:    v.DNSText,
					DNSClass:   v.DNSClass,
					DHCPText:   v.DHCPText,
					DHCPClass:  v.DHCPClass,
					ProbedAt:   v.ProbedAt,
					ProbedAgo:  formatProbeAge(v.ProbedAt),
				})
			}
		}
	}

	sort.Strings(ifaceOrder)
	result := make([]topologyInterfaceCombined, 0, len(ifaceOrder))
	for _, ifname := range ifaceOrder {
		scopeMap := byIface[ifname]
		scopes := make([]topologyScopeCombined, 0, len(scopeMap))
		for _, sc := range scopeMap {
			sort.Slice(sc.Endpoints, func(i, j int) bool {
				ri, rj := endpointRank(sc.Endpoints[i].RoleLabel, sc.Endpoints[i].IsProbe), endpointRank(sc.Endpoints[j].RoleLabel, sc.Endpoints[j].IsProbe)
				if ri != rj {
					return ri < rj
				}
				return sc.Endpoints[i].NodeName < sc.Endpoints[j].NodeName
			})
			sc.ServingLabel, sc.ServingClass, sc.ChipClass = "no node serving", "crit", "serve-none"
			for _, ep := range sc.Endpoints {
				if !ep.IsProbe && ep.BadgeClass == "ok" {
					sc.ServingLabel, sc.ServingClass = ep.NodeName, "ok"
					switch ep.RoleLabel {
					case config.RoleCore1:
						sc.ChipClass = "serve-1"
					case config.RoleCore2:
						sc.ChipClass = "serve-2"
					case config.RoleCore3:
						sc.ChipClass = "serve-3"
					}
					break
				}
			}
			if sc.ServingClass == "crit" {
				sc.HasError = true
				sc.ErrorReason = "no core node is serving this scope"
			}
			for _, ep := range sc.Endpoints {
				if ep.DHCPClass == "crit" {
					sc.HasError = true
					sc.ErrorReason = appendErrorReason(sc.ErrorReason, ep.NodeName+": "+ep.DHCPText)
				}
				if ep.DNSClass == "crit" {
					sc.HasError = true
					sc.ErrorReason = appendErrorReason(sc.ErrorReason, ep.NodeName+": "+ep.DNSText)
				}
			}
			scopes = append(scopes, *sc)
		}
		sort.Slice(scopes, func(i, j int) bool { return scopes[i].VLANID < scopes[j].VLANID })
		result = append(result, topologyInterfaceCombined{Name: ifname, Label: ifaceLabels[ifname], Scopes: scopes})
	}
	return result
}

// probeStatusInfo mirrors the subset of a probe host's own GET
// /api/v1/status this file needs.
type probeStatusInfo struct {
	TrunkParent string `json:"trunk_parent"`
}

func fetchProbeStatus(node NodeConfig) (probeStatusInfo, error) {
	var s probeStatusInfo
	status, err := doGet(httpClient, node, "/api/v1/status", &s)
	if err != nil {
		return s, err
	}
	if status != http.StatusOK {
		return s, fmt.Errorf("status %d", status)
	}
	return s, nil
}

func buildProbeTopologyNode(node NodeConfig, trunkParent string, statErr error, scopes map[string]config.ScopeConfig, results map[string]probeResult, fetched map[string]bool, labels map[string]string) topologyNode {
	tn := topologyNode{
		Name:        node.Name,
		RoleLabel:   "probe",
		RoleClass:   roleClass("probe"),
		IsProbeHost: true,
	}
	if statErr != nil {
		tn.FetchError = statErr.Error()
		return tn
	}
	if trunkParent == "" {
		tn.FetchError = "probe host reported no trunk_parent"
		return tn
	}

	byParent := make(map[string][]topologyVLAN)
	for name, sc := range scopes {
		parent := sc.Parent
		if parent == "" {
			parent = trunkParent
		}
		pr := results[name]
		have := fetched[name]

		badge, badgeClass := "not trunked", "dim"
		if have && pr.Reachable {
			badge, badgeClass = "trunked", "ok"
		}
		dnsText, dnsClass, dhcpText, dhcpClass := probeClassParts(pr, have, false)
		if sc.DNSMasqDisabled {
			dnsText, dnsClass, dhcpText, dhcpClass = "scope disabled", "warn", "", ""
		}

		byParent[parent] = append(byParent[parent], topologyVLAN{
			ScopeName:       name,
			VLANID:          sc.VLANID,
			IfaceName:       nftgate.InterfaceName(parent, sc.VLANID),
			VIP:             sc.VIP,
			VRRPID:          sc.VRRPID,
			PreferredWorker: sc.PreferredWorker,
			Badge:           badge,
			BadgeClass:      badgeClass,
			DNSText:         dnsText,
			DNSClass:        dnsClass,
			DHCPText:        dhcpText,
			DHCPClass:       dhcpClass,
			ProbedAt:        formatProbedAt(pr.ProbedAt),
		})
	}

	var parentNames []string
	for p := range byParent {
		parentNames = append(parentNames, p)
	}
	sort.Strings(parentNames)
	for _, p := range parentNames {
		vlans := byParent[p]
		sort.Slice(vlans, func(i, j int) bool { return vlans[i].VLANID < vlans[j].VLANID })
		tn.Interfaces = append(tn.Interfaces, topologyInterface{Name: p, Label: interfaceLabel(labels, p), VLANs: vlans})
	}
	return tn
}

func buildTopology(cfg *WebConfig) topologyPageData {
	type nodeConfigFetch struct {
		cluster config.Cluster
		err     error
	}
	// nodesIncludingSelf, not cfg.Nodes: cfg.Nodes never lists this instance's
	// own node.
	coreNodes := nodesIncludingSelf(cfg)
	statusResults := fetchAllNodes(coreNodes, fetchStatus)
	configResults := fetchAllNodes(coreNodes, func(n NodeConfig) (nodeConfigFetch, error) {
		c, err := fetchConfig(n)
		return nodeConfigFetch{cluster: c, err: err}, nil
	})

	nodes := make([]topologyNode, 0, len(coreNodes)+len(cfg.ProbeHosts))
	var clusterScopes map[string]config.ScopeConfig
	var interfaceLabels map[string]string
	for i, n := range coreNodes {
		cf := configResults[i].Value
		nodes = append(nodes, buildTopologyNode(n, statusResults[i].Value, statusResults[i].Err, cf.cluster, cf.err))
		if cf.err == nil && clusterScopes == nil {
			clusterScopes = cf.cluster.Scopes
			if cf.cluster.Platform != nil {
				interfaceLabels = cf.cluster.Platform.InterfaceLabels
			}
		}
	}

	if len(cfg.ProbeHosts) == 0 {
		return buildTopologyPageData(nodes)
	}
	probeStatusResults := fetchAllNodes(cfg.ProbeHosts, fetchProbeStatus)

	type reachJob struct {
		probeIdx int
		scope    string
	}
	var jobs []reachJob
	for i := range cfg.ProbeHosts {
		for name := range clusterScopes {
			jobs = append(jobs, reachJob{probeIdx: i, scope: name})
		}
	}
	results := make([]map[string]probeResult, len(cfg.ProbeHosts))
	fetchedOK := make([]map[string]bool, len(cfg.ProbeHosts))
	for i := range results {
		results[i] = make(map[string]probeResult)
		fetchedOK[i] = make(map[string]bool)
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func(j reachJob) {
			defer wg.Done()
			pr, err := fetchProbe(cfg.ProbeHosts[j.probeIdx], j.scope)
			if err != nil {
				return
			}
			mu.Lock()
			results[j.probeIdx][j.scope] = pr
			fetchedOK[j.probeIdx][j.scope] = true
			mu.Unlock()
		}(j)
	}
	wg.Wait()

	for i, n := range cfg.ProbeHosts {
		nodes = append(nodes, buildProbeTopologyNode(n, probeStatusResults[i].Value.TrunkParent, probeStatusResults[i].Err, clusterScopes, results[i], fetchedOK[i], interfaceLabels))
	}
	return buildTopologyPageData(nodes)
}

const topologyStyleHTML = `<style>
#topo-combined{position:absolute;opacity:0;pointer-events:none}
.topo-toggle-row{margin:0 0 1.1rem}
.topo-toggle-row label{cursor:pointer}
.split-view,.combined-view{display:none}
#topo-combined:checked ~ .combined-view{display:block}
#topo-combined:not(:checked) ~ .split-view{display:block}
.topo-wrap{display:grid;grid-template-columns:180px 1fr;gap:0 1.6rem;align-items:start}
/* sticky just below the sticky nav. */
.topo-rail{display:flex;flex-direction:column;gap:.6rem;position:sticky;top:calc(var(--nav-h) + 1rem)}
.rail-node{display:flex;align-items:center;gap:.5rem;padding:.5rem .7rem;background:var(--panel);
border:1px solid var(--border);border-left:4px solid currentColor;border-radius:6px;font-size:.88rem}
.rail-node .dot{display:inline-block;width:.55rem;height:.55rem;border-radius:50%;
background:currentColor;flex:none}
.topo-canvas{display:flex;flex-direction:column;gap:1.4rem;min-width:0}
.iface-branch{position:relative;padding-left:1.2rem}
.iface-branch::before{content:"";position:absolute;top:1.7rem;bottom:.1rem;left:0;width:2px;
background:var(--border)}
.iface-label{font-weight:600;font-size:.8rem;color:var(--muted);text-transform:uppercase;
letter-spacing:.04em;margin:0 0 .55rem}
.scope-row{display:flex;flex-wrap:wrap;gap:.7rem}
.scope-chip{position:relative;display:block;border:1px solid var(--border);border-left:4px solid var(--border);
border-radius:8px;background:var(--panel);padding:.5rem .7rem .5rem .6rem;min-width:9.5rem;color:var(--text)}
.scope-chip:hover{border-color:var(--accent);text-decoration:none}
.scope-chip::before{content:"";position:absolute;top:50%;left:-1.2rem;width:1.2rem;height:2px;
background:var(--border)}
.scope-chip.serve-1{border-left-color:var(--core-1);background:var(--tint-1)}
.scope-chip.serve-2{border-left-color:var(--core-2);background:var(--tint-2)}
.scope-chip.serve-3{border-left-color:var(--core-3);background:var(--tint-3)}
.scope-chip.serve-none{border-left-color:var(--crit);background:var(--tint-crit)}
.scope-chip.has-error{outline:2px solid var(--crit);outline-offset:-1px}
.scope-chip .chip-name{font-weight:600}
.scope-chip .chip-vlan{font-size:.78rem}
.scope-chip .chip-err{float:right;color:var(--crit);font-weight:700;font-size:.95rem;line-height:1}
.mini-eps{display:flex;gap:.3rem;margin-top:.45rem}
.mini-ep{display:inline-block;width:1.1rem;height:.3rem;border-radius:2px;background:currentColor}
.topo-summary{display:flex;align-items:center;gap:.6rem;background:var(--panel);border:1px solid var(--border);
border-radius:8px;padding:.6rem .9rem;margin:0 0 1.1rem;font-size:.95rem}
.topo-summary strong{font-size:1.1rem}
.topo-summary .sep{color:var(--border)}
.popup{display:none;position:fixed;inset:0;background:rgba(15,18,22,.45);z-index:50;
align-items:center;justify-content:center;padding:1rem}
.popup:target{display:flex}
.popup-inner{background:var(--panel);border-radius:10px;padding:1rem 1.3rem;max-width:360px;
width:100%;box-shadow:0 10px 30px rgba(0,0,0,.28);position:relative}
.popup-inner h3{margin:0 0 .3rem;font-size:1.02rem}
.popup-close{position:absolute;top:.4rem;right:.6rem;font-size:1.15rem;color:var(--muted);line-height:1}
.popup-inner ul{margin:.5rem 0 0;padding-left:1.15rem}
</style>`

var topologyTmpl = template.Must(template.New("topology").Parse(`<!doctype html>
<title>dnshived-web — topology</title>
` + styleHTML + topologyStyleHTML + `
<h1>Topology</h1>
` + navHTML + `
<div class="view-tabs"><a href="/scopes">&larr; List view</a><span class="active">Topology view</span></div>
<p class="dim">Physical wiring: interface &rarr; VLAN &rarr; IP &rarr; VRRP &rarr; dnsmasq. Combined
view groups every scope with its worker(s) and probe status in one card; split view shows each
node's own full tree.</p>

<input type="checkbox" id="topo-combined" checked>
<p class="topo-toggle-row"><label for="topo-combined"><strong>Combined view</strong> (uncheck for the per-node split view)</label></p>

<div class="combined-view">
{{if not .Combined}}<p class="dim">(no data)</p>{{end}}
<p class="topo-summary"><strong class="{{.HealthyClass}}">{{.TotalScopes}} scope(s)</strong>
<span class="sep">&mdash;</span>
{{if .ErrorScopes}}<span class="crit">{{.ErrorScopes}} need(s) attention:
{{range $i, $e := .ErrorScopeList}}{{if $i}}, {{end}}<a href="#pop-{{$e.Name}}" title="{{$e.Reason}}">{{$e.Name}}</a>{{end}}</span>{{else}}<span class="ok">all healthy</span>{{end}}
<span class="sep">&mdash;</span> <span class="dim">chip color = which worker is serving; a red outline flags a real problem (no server, probe error)</span></p>
<div class="topo-wrap">
<aside class="topo-rail">
{{range .RailNodes}}
<div class="rail-node {{.RoleClass}}"><span class="dot"></span>{{.Name}} <span class="dim">({{.RoleLabel}})</span></div>
{{end}}
</aside>
<div class="topo-canvas">
{{range .Combined}}
<div class="iface-branch">
<p class="iface-label">{{.Label}}{{if ne .Label .Name}} <span class="dim">({{.Name}})</span>{{end}}</p>
<div class="scope-row">
{{range .Scopes}}
<a href="#pop-{{.ScopeName}}" class="scope-chip {{.ChipClass}}{{if .HasError}} has-error{{end}}"{{if .Color}} style="border-top:3px solid {{.Color}}"{{end}}{{if .ErrorReason}} title="{{.ErrorReason}}"{{end}}>
{{if .HasError}}<span class="chip-err">&#9888;</span>{{end}}
<span class="chip-name">{{.ScopeName}}</span> <span class="dim chip-vlan">VLAN {{.VLANID}}</span><br>
<span class="{{.ServingClass}} chip-vlan">[{{.ServingLabel}}]</span>
<span class="mini-eps">
{{range .Endpoints}}<span class="mini-ep {{.RoleClass}}"{{if eq .BadgeClass "dim"}} style="opacity:.3"{{end}} title="{{.NodeName}}: {{.Badge}}"></span>{{end}}
</span>
</a>
<div class="popup" id="pop-{{.ScopeName}}">
<div class="popup-inner">
<a href="#" class="popup-close">&times;</a>
<h3>{{.ScopeName}} <span class="dim">(VLAN {{.VLANID}})</span></h3>
<p class="dim">{{.IfaceName}} &mdash; VIP {{.VIP}}{{if .VRRPID}}, VRRP id {{.VRRPID}} (preferred {{.PreferredWorker}}){{end}}</p>
{{if .DnsmasqUnit}}<p class="dim">{{.DnsmasqUnit}}</p>{{end}}
<ul>
{{range .Endpoints}}
<li><strong class="{{.RoleClass}}">{{.NodeName}}</strong>{{if .IsProbe}} <span class="dim">(probe)</span>{{end}}
&mdash; <span class="{{.BadgeClass}}">{{.Badge}}</span>
{{if .DHCPText}}<br><span class="{{.DNSClass}}">{{.DNSText}}</span> <span class="{{.DHCPClass}}">{{.DHCPText}}</span>{{if .ProbedAgo}} <span class="dim">({{.ProbedAgo}})</span>{{end}}{{end}}</li>
{{end}}
</ul>
</div>
</div>
{{end}}
</div>
</div>
{{end}}
</div>
</div>
</div>

<div class="split-view">
{{range .Nodes}}
<details open>
<summary class="{{.RoleClass}}"><strong>{{.Name}}</strong> ({{if .RoleLabel}}{{.RoleLabel}}{{else}}unknown{{end}})</summary>
{{if .FetchError}}
<p class="crit">unreachable: {{.FetchError}}</p>
{{else}}
<ul>
{{if .MgmtIface}}<li>mgmt: {{.MgmtIface}}{{if .MgmtVIP}} &mdash; VIP {{.MgmtVIP}}{{end}}</li>{{end}}
{{if .Note}}<li class="dim">{{.Note}}</li>{{end}}
{{range .Interfaces}}
<li><details>
<summary>{{.Label}}{{if ne .Label .Name}} ({{.Name}}){{end}} ({{len .VLANs}} scope(s))</summary>
<ul>
{{range .VLANs}}
<li><details>
<summary>VLAN {{.VLANID}} &mdash; {{.ScopeName}} <span class="{{.BadgeClass}}">[{{.Badge}}]</span></summary>
<ul>
<li>interface: {{.IfaceName}}</li>
{{if .NodeIP}}<li>node IP: {{.NodeIP}}</li>{{end}}
<li>VIP: {{.VIP}}</li>
{{if .VRRPID}}<li>VRRP id: {{.VRRPID}} (preferred: {{.PreferredWorker}})</li>{{end}}
{{if .DnsmasqUnit}}<li>{{.DnsmasqUnit}}</li>{{end}}
{{if .DHCPText}}<li>probe result: <span class="{{.DNSClass}}">{{.DNSText}}</span> <span class="{{.DHCPClass}}">{{.DHCPText}}</span>{{if .ProbedAt}} &mdash; probed at {{.ProbedAt}}{{end}}</li>{{end}}
</ul>
</details></li>
{{end}}
</ul>
</details></li>
{{end}}
</ul>
{{end}}
</details>
{{end}}
</div>
`))

func handleTopology(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		renderTemplate(w, topologyTmpl, buildTopology(cfg), "topology")
	}
}
