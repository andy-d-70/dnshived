// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"dnshived/internal/config"
	"dnshived/internal/discovery"
	"dnshived/internal/webauth"
)

// newScopeSlots is how many blank "add a new scope" rows the form renders
// at the bottom, alongside every existing scope.
const newScopeSlots = 1

// newTokenSlots is the same fixed-blank-slots pattern applied to
// api_tokens.
const newTokenSlots = 5

// configPushPayload mirrors cmd/dnshived's configUpdate JSON shape exactly
// (field-for-field).
type configPushPayload struct {
	PSK                   string                        `json:"psk"`
	TrustedHosts          []string                      `json:"trusted_hosts"`
	TLSCert               string                        `json:"tls_cert"`
	TLSKey                string                        `json:"tls_key"`
	APITokens             []config.APIToken             `json:"api_tokens"`
	LogLevel              string                        `json:"log_level"`
	HelperSocket          string                        `json:"helper_socket"`
	Platform              *config.Platform              `json:"platform"`
	Scopes                map[string]config.ScopeConfig `json:"scopes"`
	ProbeIntervalMS       int                           `json:"probe_interval_ms"`
	MgmtVIP               *config.MgmtVIPConfig         `json:"mgmt_vip"`
	DefaultDNSChecks      []config.DNSCheck             `json:"default_dns_checks"`
	GlobalDNSRecords      []config.DNSRecord            `json:"global_dns_records"`
	LocalDomains          []config.LocalDomain          `json:"local_domains"`
	ScopeDefaults         *config.ScopeDefaults         `json:"scope_defaults"`
	DefaultDHCPOptions    []string                      `json:"default_dhcp_options"`
	CoreDNSAddress        string                        `json:"core_dns_address"`
	CoreDHCPAddress       string                        `json:"core_dhcp_address"`
	CoreDNSQueryLogging   bool                          `json:"core_dns_query_logging"`
	DNSRelayCacheSize     int                           `json:"dnsrelay_cache_size"`
	DNSRelayCacheMaxBytes int                           `json:"dnsrelay_cache_max_bytes"`
	SanityCheckDisabled   bool                          `json:"sanity_check_disabled"`

	BackupEnabled          bool   `json:"backup_enabled"`
	BackupIntervalHours    int    `json:"backup_interval_hours"`
	BackupRetentionCount   int    `json:"backup_retention_count"`
	BackupPassword         string `json:"backup_password"`
	BackupReplicateToPeers bool   `json:"backup_replicate_to_peers"`
}

// fetchConfig reads the full current config from one node's GET
// /api/v1/config (admin-gated on the daemon side — this returns PSK and
// token values in cleartext).
func fetchConfig(node NodeConfig) (config.Cluster, error) {
	return fetchConfigWithClient(httpClient, node)
}

// fetchConfigDirect is fetchConfig via directHTTPClient — bypasses the
// shared reachability belief cache.
func fetchConfigDirect(node NodeConfig) (config.Cluster, error) {
	return fetchConfigWithClient(directHTTPClient, node)
}

func fetchConfigWithClient(cl *http.Client, node NodeConfig) (config.Cluster, error) {
	var c config.Cluster
	req, err := http.NewRequest(http.MethodGet, node.baseURL()+"/api/v1/config", nil)
	if err != nil {
		return c, err
	}
	if node.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+node.AdminToken)
	}
	resp, err := cl.Do(req)
	if err != nil {
		return c, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return c, fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return c, err
	}
	return c, nil
}

// firstReachableConfig fetches from the first node that answers — the
// form's baseline snapshot.
func firstReachableConfig(nodes []NodeConfig) (config.Cluster, NodeConfig, error) {
	var lastErr error
	for _, n := range nodes {
		c, err := fetchConfig(n)
		if err == nil {
			return c, n, nil
		}
		lastErr = err
	}
	return config.Cluster{}, NodeConfig{}, fmt.Errorf("no node reachable, last error: %w", lastErr)
}

func handleConfigGet(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		c, node, isPending, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "could not read config from any node: "+err.Error(), http.StatusBadGateway)
			return
		}
		allNodes := nodesIncludingSelf(cfg)
		data := buildClusterFormData(c, node, allNodes)
		data.Pending = isPending
		data.AllNodes = allNodes
		data.MissingRoles = missingCoreRolesExcludingSelf(cfg)
		data.OnboardTargets, data.ReplaceTargets = onboardAndReplaceTargets(allNodes, cfg.ProbeHosts)
		data.Discovered = withoutMembers(fetchDiscoveredNodes(node), allNodes, cfg.ProbeHosts)
		data.ThisVersion = version
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := configFormTmpl.Execute(w, data); err != nil {
			log.Printf("[ERROR] render config form: %v", err)
		}
	}
}

// withoutMembers drops candidates that already joined; their last
// bootstrap announcement stays in the listener until it ages out.
func withoutMembers(cands []discovery.Candidate, groups ...[]NodeConfig) []discovery.Candidate {
	member := map[string]bool{}
	for _, g := range groups {
		for _, n := range g {
			member[hostOnly(n.Addr)] = true
		}
	}
	out := cands[:0:0]
	for _, c := range cands {
		if !member[hostOnly(c.Addr)] {
			out = append(out, c)
		}
	}
	return out
}

func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func fetchProbeParallelRows(hosts []NodeConfig) []probeParallelRow {
	rows := make([]probeParallelRow, 0, len(hosts))
	for _, res := range fetchAllNodes(hosts, fetchNodeSnapshot) {
		row := probeParallelRow{Name: res.Node.Name, Addr: res.Node.Addr}
		if res.Err != nil {
			row.Err = res.Err.Error()
		} else {
			row.Reachable = true
			row.Enabled = res.Value.Status.ParallelProbing
			row.ScopeCount = len(res.Value.Status.ConfiguredScopes)
		}
		rows = append(rows, row)
	}
	return rows
}

// allProbeHostsParallel reports whether every REACHABLE row already has
// parallel_probing enabled.
func allProbeHostsParallel(rows []probeParallelRow) bool {
	sawReachable := false
	for _, r := range rows {
		if !r.Reachable {
			continue
		}
		sawReachable = true
		if !r.Enabled {
			return false
		}
	}
	return sawReachable
}

func handleScopesConfigGet(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		c, node, isPending, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "could not read config from any node: "+err.Error(), http.StatusBadGateway)
			return
		}
		data := buildScopesFormData(c, node)
		data.Pending = isPending
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := scopesConfigFormTmpl.Execute(w, data); err != nil {
			log.Printf("[ERROR] render scopes config form: %v", err)
		}
	}
}

// scopesExport is the "scopes" export mode's shape — cluster_id plus the
// raw scopes map, nothing else.
type scopesExport struct {
	ClusterID  string                        `json:"cluster_id"`
	SourceNode string                        `json:"source_node"`
	Scopes     map[string]config.ScopeConfig `json:"scopes"`
}

// clusterOnlyExport is the "cluster" export mode's shape: config.Cluster
// with Scopes explicitly cleared.
func clusterOnlyExport(c config.Cluster) config.Cluster {
	c.Scopes = nil
	return c
}

// exportFilename builds a descriptive, collision-resistant download
// filename.
func exportFilename(clusterID, mode string) string {
	if clusterID == "" {
		clusterID = "cluster"
	}
	return fmt.Sprintf("dnshived-%s-%s-%s.json", clusterID, mode, time.Now().UTC().Format("20060102-150405"))
}

// handleConfigExport serves GET /config/export?mode=all|cluster|scopes.
func handleConfigExport(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		mode := r.URL.Query().Get("mode")
		if mode == "" {
			mode = "all"
		}
		if mode != "all" && mode != "cluster" && mode != "scopes" {
			http.Error(w, "unknown mode — want all, cluster, or scopes", http.StatusBadRequest)
			return
		}

		c, node, err := firstReachableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "could not read config from any node: "+err.Error(), http.StatusBadGateway)
			return
		}

		var body interface{}
		switch mode {
		case "all":
			body = c
		case "cluster":
			body = clusterOnlyExport(c)
		case "scopes":
			body = scopesExport{ClusterID: c.ClusterID, SourceNode: node.Name, Scopes: c.Scopes}
		}

		data, err := json.MarshalIndent(body, "", "    ")
		if err != nil {
			http.Error(w, "encode export: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=\""+exportFilename(c.ClusterID, mode)+"\"")
		w.Write(data)
	}
}

// handleConfigPost saves the cluster-settings form.
func handleConfigPost(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}

		payload, err := parseClusterConfigForm(r, cfg.Nodes)
		if err != nil {
			http.Error(w, "bad input: "+err.Error(), http.StatusBadRequest)
			return
		}
		current, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "could not read current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		payload.Scopes = current.Scopes
		if payload.Platform != nil && current.Platform != nil {
			payload.Platform.WorkerOverrides = current.Platform.WorkerOverrides
			payload.Platform.MgmtOverrides = current.Platform.MgmtOverrides
		}
		if payload.PSK == "" {
			payload.PSK = current.PSK
		}
		payload.DefaultDNSChecks = current.DefaultDNSChecks
		payload.GlobalDNSRecords = current.GlobalDNSRecords
		payload.LocalDomains = current.LocalDomains
		payload.DefaultDHCPOptions = current.DefaultDHCPOptions
		payload.APITokens = current.APITokens
		payload.ScopeDefaults = current.ScopeDefaults
		payload.ProbeIntervalMS = current.ProbeIntervalMS
		payload.HelperSocket = current.HelperSocket
		payload.BackupEnabled = current.BackupEnabled
		payload.BackupIntervalHours = current.BackupIntervalHours
		payload.BackupRetentionCount = current.BackupRetentionCount
		payload.BackupPassword = current.BackupPassword
		payload.BackupReplicateToPeers = current.BackupReplicateToPeers

		user, _ := userFromContext(r)
		pushCandidateAndRenderResult(w, cfg, payload, user, "/config", "back to editor")
	}
}

// handleProbeParallelPost applies the probe-parallelization toggle to
// every registered probe host.
func handleProbeParallelPost(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		enabled := r.FormValue("probe_parallel_enabled") == "on"
		user, _ := userFromContext(r)

		for _, node := range cfg.ProbeHosts {
			err := pushProbeHostParallelProbing(node, enabled)
			summary := fmt.Sprintf("parallel_probing -> %v on %s", enabled, node.Name)
			if err != nil {
				summary = fmt.Sprintf("parallel_probing -> %v on %s FAILED: %v", enabled, node.Name, err)
			}
			pushAudit(node, user.Name, "probe.parallel_probing", summary)
		}

		http.Redirect(w, r, "/probes#settings", http.StatusSeeOther)
	}
}

// handleScopesConfigPost saves the scope editor form.
func handleScopesConfigPost(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}

		scopes, err := parseScopeSlots(r.PostForm)
		if err != nil {
			http.Error(w, "bad input: "+err.Error(), http.StatusBadRequest)
			return
		}
		current, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "could not read current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		payload := clusterPushPayloadFrom(current)
		payload.Scopes = scopes

		user, _ := userFromContext(r)
		pushCandidateAndRenderResult(w, cfg, payload, user, "/config/scopes", "back to scope editor")
	}
}

func handleDHCPDNSConfigGet(ref *configRef, store *TemplateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		c, node, isPending, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "could not read config from any node: "+err.Error(), http.StatusBadGateway)
			return
		}
		existing := collectExistingDNSRecords(c)
		data := dhcpDNSConfigFormData{
			SourceNode:         node.Name,
			Pending:            isPending,
			DNS:                buildDNSConfigFormData(c, node),
			DHCP:               buildDHCPConfigFormData(c, node),
			LocalDomains:       buildLocalDomainRows(c.LocalDomains, existing),
			GlobalDNSBuilder:   dnsRecordBuilderHTML("global_dns_records", existing),
			DefaultDHCPBuilder: dhcpOptionBuilderHTML("default_dhcp_options"),
			DHCPTemplates:      buildTemplateRows(store.ByKind(TemplateKindDHCP)),
			DNSTemplates:       buildTemplateRows(store.ByKind(TemplateKindDNS)),
			ClientDNSTemplates: buildTemplateRows(store.ByKind(TemplateKindClientDNS)),
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := dhcpDNSConfigFormTmpl.Execute(w, data); err != nil {
			log.Printf("[ERROR] render dhcp/dns config form: %v", err)
		}
	}
}

// handleDNSConfigPost saves the DNS-defaults section of the merged DHCP &
// DNS page.
func handleDNSConfigPost(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}

		globalRecords, err := parseDNSRecordLines(r.PostForm.Get("global_dns_records"))
		if err != nil {
			http.Error(w, "bad input: "+err.Error(), http.StatusBadRequest)
			return
		}

		current, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "could not read current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		payload := clusterPushPayloadFrom(current)
		payload.Scopes = current.Scopes
		payload.GlobalDNSRecords = globalRecords

		user, _ := userFromContext(r)
		pushCandidateAndRenderResult(w, cfg, payload, user, "/config/dns#dns", "back to DHCP & DNS")
	}
}

// handleDHCPConfigPost saves the DHCP-defaults section of the merged DHCP
// & DNS page.
func handleDHCPConfigPost(ref *configRef) http.HandlerFunc {
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
		payload := clusterPushPayloadFrom(current)
		payload.Scopes = current.Scopes
		payload.DefaultDHCPOptions = splitLines(r.PostForm.Get("default_dhcp_options"))

		user, _ := userFromContext(r)
		pushCandidateAndRenderResult(w, cfg, payload, user, "/config/dns#dhcp", "back to DHCP & DNS")
	}
}

type configCheckResponse struct {
	OK       bool     `json:"ok"`
	Errors   []string `json:"errors"`
	Warnings []string `json:"warnings"`
	// RestartNeeded is the daemon's own answer.
	RestartNeeded bool `json:"restart_needed"`
}

// nodeSaveResult is one node's outcome from pushConfigAndRenderResult.
type nodeSaveResult struct {
	Node            NodeConfig
	Unreachable     bool
	CheckOK         bool
	CheckErrors     []string
	CheckWarnings   []string
	RawStatus       int
	RawBody         string
	ReloadOK        bool
	ReloadSkipped   bool // config check failed, or the node was unreachable — never attempted
	ReloadErr       string
	ReloadNotNeeded bool
	restartNeeded   bool
}

func saveWatchdogHTML(target string) string {
	return `<script>(function(){var t="` + template.JSEscapeString(target) + `",started=0;
function done(){return !!document.getElementById("save-done")}
function poll(){if(done())return;if(Date.now()-started>60000){location.href=t;return}
fetch(t,{mode:"no-cors",cache:"no-store",credentials:"omit"}).then(function(){location.href=t},function(){setTimeout(poll,2000)})}
function stalled(){if(started||done())return;started=Date.now();setTimeout(poll,2000)}
window.addEventListener("load",function(){if(!done())stalled()});setTimeout(stalled,25000)})();</script>
`
}

func postSaveURL(cfg *WebConfig, newMgmtVIP *config.MgmtVIPConfig) string {
	newHost := vipHostOf(newMgmtVIP)
	if newHost == cfg.VIPHost {
		return "/"
	}
	_, port, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil {
		port = "8443"
	}
	if newHost == "" {
		nodes := nodesIncludingSelf(cfg)
		if len(nodes) == 0 {
			return "/"
		}
		h, _, err := net.SplitHostPort(nodes[0].Addr)
		if err != nil {
			h = nodes[0].Addr
		}
		newHost = h
	}
	return "https://" + net.JoinHostPort(newHost, port) + "/"
}

func vipHostOf(m *config.MgmtVIPConfig) string {
	if m == nil || m.VIP == "" {
		return ""
	}
	if ip, _, err := net.ParseCIDR(m.VIP); err == nil {
		return ip.String()
	}
	return m.VIP
}

const saveDoneMarkerHTML = `<span id="save-done" hidden></span>
`

// pushConfigAndRenderResult is the shared concurrent push-to-every-node +
// per-node audit entry + result-page rendering logic.
func pushConfigAndRenderResult(w http.ResponseWriter, cfg *WebConfig, payload configPushPayload, user webauth.User, backLink, backText string, onFullSuccess func()) {
	if cfg.CoordinatorNode != nil {
		pushConfigViaCoordinator(w, cfg, payload, user, backLink, backText, onFullSuccess)
		return
	}
	pushConfigDirectFanout(w, cfg, payload, user, backLink, backText, onFullSuccess)
}

func pushConfigDirectFanout(w http.ResponseWriter, cfg *WebConfig, payload configPushPayload, user webauth.User, backLink, backText string, onFullSuccess func()) {
	if _, err := json.Marshal(payload); err != nil {
		http.Error(w, "encode: "+err.Error(), http.StatusInternalServerError)
		return
	}

	nodes := nodesIncludingSelf(cfg)

	if err := checkNodeIPCollisions(payload, nodes); err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<!doctype html><title>dnshived-web — save result</title>\n"+styleHTML+navHTML+"\n")
		fmt.Fprintf(w, "<h1 class=\"crit\">Refused — would create a duplicate node_ip</h1>\n<p>%s</p>\n<p><a href=\"%s\">%s</a></p>\n",
			template.HTMLEscapeString(err.Error()), backLink, backText)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, "<!doctype html><title>dnshived-web — save result</title>\n"+styleHTML+"\n<h1>Saving…</h1>\n"+saveWatchdogHTML(postSaveURL(cfg, payload.MgmtVIP)))
	defer fmt.Fprint(w, saveDoneMarkerHTML)
	flusher, canFlush := w.(http.Flusher)
	flush := func() {
		if canFlush {
			flusher.Flush()
		}
	}
	for _, n := range nodes {
		fmt.Fprintf(w, "<p id=\"log-%s\">pushing to %s…</p>\n", template.HTMLEscapeString(n.Name), template.HTMLEscapeString(n.Name))
	}
	flush()

	// pushProgress is one live-log line.
	type pushProgress struct {
		node NodeConfig
		line string
	}
	progress := make(chan pushProgress)

	// Pushed to every node concurrently — bounds total latency to the single
	// slowest node instead of their sum.
	results := make([]nodeSaveResult, len(nodes))
	var wg sync.WaitGroup
	for i, n := range nodes {
		wg.Add(1)
		go func(i int, n NodeConfig) {
			defer wg.Done()
			res := nodeSaveResult{Node: n, ReloadSkipped: true}

			body, err := json.Marshal(payloadForNode(payload, n))
			if err != nil {
				res.Unreachable = true
				res.RawBody = err.Error()
				results[i] = res
				progress <- pushProgress{n, fmt.Sprintf(`pushing to %s… <span class="crit">encode: %s</span>`, template.HTMLEscapeString(n.Name), template.HTMLEscapeString(err.Error()))}
				return
			}

			status, respBody, err := pushConfig(n, body)
			res.RawStatus = status
			if err != nil {
				res.Unreachable = true
				res.RawBody = err.Error()
				results[i] = res
				progress <- pushProgress{n, fmt.Sprintf(`pushing to %s… <span class="crit">unreachable: %s</span>`, template.HTMLEscapeString(n.Name), template.HTMLEscapeString(err.Error()))}
				return
			}

			var check configCheckResponse
			if jsonErr := json.Unmarshal(respBody, &check); jsonErr != nil {
				res.RawBody = string(respBody)
				results[i] = res
				progress <- pushProgress{n, fmt.Sprintf(`pushing to %s… <span class="warn">unexpected response</span>`, template.HTMLEscapeString(n.Name))}
				return
			}
			res.CheckErrors, res.CheckWarnings = check.Errors, check.Warnings
			res.CheckOK = status == http.StatusOK && check.OK

			if res.CheckOK {
				progress <- pushProgress{n, fmt.Sprintf(`pushing to %s… <span class="ok">done</span>`, template.HTMLEscapeString(n.Name))}
				if !check.RestartNeeded {
					res.ReloadNotNeeded = true
					progress <- pushProgress{n, fmt.Sprintf(`%s… <span class="ok">no restart needed</span>`, template.HTMLEscapeString(n.Name))}
				} else {
					res.restartNeeded = true
				}
			} else {
				progress <- pushProgress{n, fmt.Sprintf(`pushing to %s… <span class="crit">rejected — see below</span>`, template.HTMLEscapeString(n.Name))}
			}
			results[i] = res

			// Best-effort audit entry — only for a node that WON'T restart (nothing
			// more will happen to it).
			if !res.restartNeeded {
				summary := "pushed config update via dnshived-web"
				if !res.CheckOK {
					summary += " — REJECTED by config check"
				} else if res.ReloadNotNeeded {
					summary += " (no restart needed)"
				}
				pushAudit(n, user.Name, "config.save", summary)
			}
		}(i, n)
	}
	go func() {
		wg.Wait()
		close(progress)
	}()
	for p := range progress {
		fmt.Fprintf(w, "<p>%s</p>\n", p.line)
		flush()
	}

	for i, n := range nodes {
		if !results[i].restartNeeded {
			continue
		}
		res := results[i]
		fmt.Fprintf(w, "<p>restarting %s…</p>\n", template.HTMLEscapeString(n.Name))
		flush()
		if _, reloadErr := restartUnit(n, "dnshived.service", false); reloadErr != nil {
			res.ReloadErr = reloadErr.Error()
			fmt.Fprintf(w, "<p>restarting %s… <span class=\"crit\">FAILED: %s</span></p>\n", template.HTMLEscapeString(n.Name), template.HTMLEscapeString(reloadErr.Error()))
		} else if waitErr := waitNodeStable(n, restartWaitTimeout); waitErr != nil {
			res.ReloadErr = "restarted, but did not confirm STABLE: " + waitErr.Error()
			fmt.Fprintf(w, "<p>restarting %s… <span class=\"warn\">restarted, but did not confirm STABLE: %s</span></p>\n", template.HTMLEscapeString(n.Name), template.HTMLEscapeString(waitErr.Error()))
		} else {
			res.ReloadOK = true
			fmt.Fprintf(w, "<p>restarting %s… <span class=\"ok\">done</span></p>\n", template.HTMLEscapeString(n.Name))
		}
		res.ReloadSkipped = false
		results[i] = res
		flush()

		summary := "pushed config update via dnshived-web"
		if !res.ReloadOK {
			summary += " — saved, but reload failed"
		}
		pushAudit(n, user.Name, "config.save", summary)
	}

	allOK := true
	anyRestarted := false
	for _, res := range results {
		if res.Unreachable || !res.CheckOK || (!res.ReloadOK && !res.ReloadNotNeeded) {
			allOK = false
		}
		if res.ReloadOK {
			anyRestarted = true
		}
	}
	if allOK && onFullSuccess != nil {
		onFullSuccess()
	}

	if allOK {
		if !anyRestarted {
			fmt.Fprintf(w, "<h1 class=\"ok\">Saved on all %d node(s) — no restart needed</h1>\n", len(nodes))
		} else {
			fmt.Fprintf(w, "<h1 class=\"ok\">Saved and reloaded on all %d node(s)</h1>\n", len(nodes))
		}
	} else {
		fmt.Fprintf(w, "<h1 class=\"crit\">Partial or full failure — no rollback attempted</h1>\n")
		fmt.Fprintf(w, "<p>Config changes that DID pass their check and reload are still in place on those nodes. "+
			"Check the per-node results below, fix the problem, and re-submit.</p>\n")
	}
	fmt.Fprintf(w, "<p><a href=\"%s\">%s</a></p>\n", backLink, backText)
	fmt.Fprintf(w, "<table border=\"1\" cellpadding=\"4\"><tr><th>Node</th><th>Config check</th><th>Reload</th></tr>\n")
	for _, res := range results {
		checkCell := `<span class="ok">OK</span>`
		switch {
		case res.Unreachable:
			checkCell = fmt.Sprintf(`<span class="crit">unreachable: %s</span>`, template.HTMLEscapeString(res.RawBody))
		case len(res.CheckErrors) > 0:
			var b strings.Builder
			b.WriteString(`<span class="crit">rejected:</span><ul>`)
			for _, e := range res.CheckErrors {
				fmt.Fprintf(&b, "<li>%s</li>", template.HTMLEscapeString(e))
			}
			b.WriteString("</ul>")
			checkCell = b.String()
		case res.RawBody != "":
			checkCell = fmt.Sprintf(`<span class="warn">unexpected response (status %d): %s</span>`, res.RawStatus, template.HTMLEscapeString(res.RawBody))
		}
		if len(res.CheckWarnings) > 0 {
			var b strings.Builder
			b.WriteString(checkCell + `<br><span class="warn">warnings:</span><ul>`)
			for _, wtext := range res.CheckWarnings {
				fmt.Fprintf(&b, "<li>%s</li>", template.HTMLEscapeString(wtext))
			}
			b.WriteString("</ul>")
			checkCell = b.String()
		}

		reloadCell := `<span class="dim">not attempted (config check failed or node unreachable)</span>`
		switch {
		case res.ReloadNotNeeded:
			reloadCell = `<span class="ok">saved — no restart needed</span>`
		case !res.ReloadSkipped:
			if res.ReloadOK {
				reloadCell = `<span class="ok">reloaded</span>`
			} else {
				reloadCell = fmt.Sprintf(`<span class="crit">FAILED: %s</span> — config is saved on this node but NOT yet applied; restart dnshived.service manually from the Daemons tab`, template.HTMLEscapeString(res.ReloadErr))
			}
		}

		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n", res.Node.Name, checkCell, reloadCell)
	}
	fmt.Fprintf(w, "</table>\n<p><a href=\"%s\">%s</a></p>\n", backLink, backText)
}

// coordinatorConfigResponse mirrors internal/coordplane's own POST
// /api/v1/coord/config response shape.
type coordinatorConfigResponse struct {
	Coordinator string                           `json:"coordinator"`
	Overall     string                           `json:"overall"`
	Results     map[string]coordinatorPeerResult `json:"results"`
	// Frozen/Reason only populated on a 423 response — a worker standing in
	// for the arbiter, not a real push result at all.
	Frozen bool   `json:"frozen"`
	Reason string `json:"reason"`
}

type coordinatorPeerResult struct {
	OK       bool            `json:"ok"`
	Status   int             `json:"status"`
	Checksum string          `json:"checksum"`
	Body     json.RawMessage `json:"body"`
	Error    string          `json:"error"`
}

func pushConfigViaCoordinator(w http.ResponseWriter, cfg *WebConfig, payload configPushPayload, user webauth.User, backLink, backText string, onFullSuccess func()) {
	if _, err := json.Marshal(payload); err != nil {
		http.Error(w, "encode: "+err.Error(), http.StatusInternalServerError)
		return
	}
	nodes := nodesIncludingSelf(cfg)
	if err := checkNodeIPCollisions(payload, nodes); err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<!doctype html><title>dnshived-web — save result</title>\n"+styleHTML+navHTML+"\n")
		fmt.Fprintf(w, "<h1 class=\"crit\">Refused — would create a duplicate node_ip</h1>\n<p>%s</p>\n<p><a href=\"%s\">%s</a></p>\n",
			template.HTMLEscapeString(err.Error()), backLink, backText)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, "<!doctype html><title>dnshived-web — save result</title>\n"+styleHTML+"\n<h1>Saving…</h1>\n"+saveWatchdogHTML(postSaveURL(cfg, payload.MgmtVIP)))
	defer fmt.Fprint(w, saveDoneMarkerHTML)
	flusher, canFlush := w.(http.Flusher)
	flush := func() {
		if canFlush {
			flusher.Flush()
		}
	}
	fmt.Fprintf(w, "<p id=\"log-coordinator\">pushing to coordinator (%s) <span class=\"loading-dots\"><span>.</span><span>.</span><span>.</span></span></p>\n"+
		"<p class=\"dim\">this can take several seconds for changes affecting central DHCP (relay push is staggered across peers)</p>\n",
		template.HTMLEscapeString(cfg.CoordinatorNode.Addr))
	flush()

	documents := make(map[string]json.RawMessage, len(nodes))
	for _, n := range nodes {
		body, err := json.Marshal(payloadForNode(payload, n))
		if err != nil {
			fmt.Fprintf(w, "<h1 class=\"crit\">Encode failed for %s</h1>\n<p>%s</p>\n<p><a href=\"%s\">%s</a></p>\n",
				template.HTMLEscapeString(n.Name), template.HTMLEscapeString(err.Error()), backLink, backText)
			return
		}
		documents[n.Addr] = body
	}
	reqBody, err := json.Marshal(map[string]interface{}{"documents": documents})
	if err != nil {
		fmt.Fprintf(w, "<h1 class=\"crit\">Encode failed</h1>\n<p>%s</p>\n<p><a href=\"%s\">%s</a></p>\n",
			template.HTMLEscapeString(err.Error()), backLink, backText)
		return
	}

	req, err := http.NewRequest(http.MethodPost, cfg.CoordinatorNode.baseURL()+"/api/v1/coord/config", bytes.NewReader(reqBody))
	if err == nil {
		req.Header.Set("Content-Type", "application/json")
		if cfg.CoordinatorNode.AdminToken != "" {
			req.Header.Set("Authorization", "Bearer "+cfg.CoordinatorNode.AdminToken)
		}
	}
	var resp *http.Response
	if err == nil {
		resp, err = coordinatorPushClient.Do(req)
	}
	if err != nil {
		fmt.Fprintf(w, "<p id=\"log-coordinator\">pushing to coordinator… <span class=\"crit\">unreachable: %s</span></p>\n", template.HTMLEscapeString(err.Error()))
		fmt.Fprintf(w, "<h1 class=\"crit\">Coordinator unreachable — nothing pushed</h1>\n<p><a href=\"%s\">%s</a></p>\n", backLink, backText)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(w, "<p id=\"log-coordinator\">pushing to coordinator… <span class=\"warn\">unexpected response</span></p>\n")
		fmt.Fprintf(w, "<h1 class=\"crit\">Could not read coordinator response (status %d): %s</h1>\n<p><a href=\"%s\">%s</a></p>\n",
			resp.StatusCode, template.HTMLEscapeString(err.Error()), backLink, backText)
		return
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusLocked {
		fmt.Fprintf(w, "<p id=\"log-coordinator\">pushing to coordinator… <span class=\"crit\">rejected</span></p>\n")
		fmt.Fprintf(w, "<h1 class=\"crit\">Coordinator refused this push (status %d)</h1>\n<p>%s</p>\n<p>Nothing was pushed to any node.</p>\n<p><a href=\"%s\">%s</a></p>\n",
			resp.StatusCode, template.HTMLEscapeString(string(respBody)), backLink, backText)
		return
	}

	var result coordinatorConfigResponse
	if jsonErr := json.Unmarshal(respBody, &result); jsonErr != nil {
		fmt.Fprintf(w, "<p id=\"log-coordinator\">pushing to coordinator… <span class=\"warn\">unexpected response</span></p>\n")
		fmt.Fprintf(w, "<h1 class=\"crit\">Unexpected coordinator response (status %d)</h1>\n<p><a href=\"%s\">%s</a></p>\n", resp.StatusCode, backLink, backText)
		return
	}

	if resp.StatusCode == http.StatusLocked || result.Frozen {
		fmt.Fprintf(w, "<p id=\"log-coordinator\">pushing to coordinator… <span class=\"crit\">frozen</span></p>\n")
		fmt.Fprintf(w, "<h1 class=\"crit\">Coordinator refused — older build still enforcing the arbiter-only freeze</h1>\n<p>%s</p>\n<p>Nothing was pushed to any node. "+
			"Upgrade this node to a build that supports worker-coordinated writes, or wait for the arbiter to come back.</p>\n<p><a href=\"%s\">%s</a></p>\n",
			template.HTMLEscapeString(result.Reason), backLink, backText)
		return
	}

	fmt.Fprintf(w, "<p id=\"log-coordinator\">pushing to coordinator… <span class=\"ok\">done</span> (coordinator: %s)</p>\n", template.HTMLEscapeString(result.Coordinator))
	flush()

	allOK := result.Overall == "ok"
	anyRestarted := false

	type renderedResult struct {
		node          NodeConfig
		unreachable   bool
		checkOK       bool
		checkErrors   []string
		checkWarnings []string
		rawBody       string
		reloadOK      bool
		reloadSkipped bool
		reloadErr     string
		reloadNeeded  bool
	}
	rendered := make([]renderedResult, 0, len(nodes))
	for _, n := range nodes {
		peerRes, ok := result.Results[n.Addr]
		rr := renderedResult{node: n, reloadSkipped: true}
		if !ok {
			rr.unreachable = true
			rr.rawBody = "coordinator reported no result for this node"
			rendered = append(rendered, rr)
			continue
		}
		if peerRes.Error != "" {
			rr.unreachable = true
			rr.rawBody = peerRes.Error
			rendered = append(rendered, rr)
			continue
		}
		var check configCheckResponse
		if jsonErr := json.Unmarshal(peerRes.Body, &check); jsonErr != nil {
			rr.rawBody = string(peerRes.Body)
			rendered = append(rendered, rr)
			continue
		}
		rr.checkErrors, rr.checkWarnings = check.Errors, check.Warnings
		rr.checkOK = peerRes.OK && check.OK
		rr.reloadNeeded = check.RestartNeeded
		rendered = append(rendered, rr)
	}

	for i := range rendered {
		rr := &rendered[i]
		if !rr.checkOK {
			continue
		}
		if !rr.reloadNeeded {
			rr.reloadOK = true
			continue
		}
		if _, reloadErr := restartUnit(rr.node, "dnshived.service", false); reloadErr != nil {
			rr.reloadErr = reloadErr.Error()
		} else if waitErr := waitNodeStable(rr.node, restartWaitTimeout); waitErr != nil {
			rr.reloadErr = "restarted, but did not confirm STABLE: " + waitErr.Error()
			anyRestarted = true
		} else {
			rr.reloadOK = true
			anyRestarted = true
		}
		rr.reloadSkipped = false
	}

	for i := range rendered {
		rr := rendered[i]
		summary := "pushed config update via dnshived-web (coordination plane)"
		if !rr.checkOK {
			summary += " — REJECTED by config check"
			allOK = false
		} else if rr.reloadSkipped && rr.reloadNeeded {
			summary += " (no restart needed)"
		} else if rr.reloadErr != "" {
			summary += " — saved, but reload failed"
			allOK = false
		}
		if rr.unreachable {
			allOK = false
		}
		pushAudit(rr.node, user.Name, "config.save", summary)
	}

	if allOK && onFullSuccess != nil {
		onFullSuccess()
	}

	if allOK {
		if !anyRestarted {
			fmt.Fprintf(w, "<h1 class=\"ok\">Saved on all %d node(s) — no restart needed</h1>\n", len(nodes))
		} else {
			fmt.Fprintf(w, "<h1 class=\"ok\">Saved and reloaded on all %d node(s)</h1>\n", len(nodes))
		}
	} else {
		fmt.Fprintf(w, "<h1 class=\"crit\">Partial or full failure — no rollback attempted</h1>\n")
		fmt.Fprintf(w, "<p>Config changes that DID pass their check and reload are still in place on those nodes. "+
			"Check the per-node results below, fix the problem, and re-submit.</p>\n")
		if result.Overall == "partial" {
			fmt.Fprintf(w, "<p>Coordinator reported <code>overall: partial</code> — see the per-node checksums below; "+
				"a node whose applied config doesn't checksum-match the rest is a real drift, not just a display glitch.</p>\n")
		}
	}
	fmt.Fprintf(w, "<p><a href=\"%s\">%s</a></p>\n", backLink, backText)
	fmt.Fprintf(w, "<table border=\"1\" cellpadding=\"4\"><tr><th>Node</th><th>Config check</th><th>Reload</th></tr>\n")
	for _, rr := range rendered {
		checkCell := `<span class="ok">OK</span>`
		switch {
		case rr.unreachable:
			checkCell = fmt.Sprintf(`<span class="crit">unreachable: %s</span>`, template.HTMLEscapeString(rr.rawBody))
		case len(rr.checkErrors) > 0:
			var b strings.Builder
			b.WriteString(`<span class="crit">rejected:</span><ul>`)
			for _, e := range rr.checkErrors {
				fmt.Fprintf(&b, "<li>%s</li>", template.HTMLEscapeString(e))
			}
			b.WriteString("</ul>")
			checkCell = b.String()
		case rr.rawBody != "":
			checkCell = fmt.Sprintf(`<span class="warn">unexpected response: %s</span>`, template.HTMLEscapeString(rr.rawBody))
		}
		if len(rr.checkWarnings) > 0 {
			var b strings.Builder
			b.WriteString(checkCell + `<br><span class="warn">warnings:</span><ul>`)
			for _, wtext := range rr.checkWarnings {
				fmt.Fprintf(&b, "<li>%s</li>", template.HTMLEscapeString(wtext))
			}
			b.WriteString("</ul>")
			checkCell = b.String()
		}

		reloadCell := `<span class="dim">not attempted (config check failed or node unreachable)</span>`
		switch {
		case rr.checkOK && !rr.reloadNeeded:
			reloadCell = `<span class="ok">saved — no restart needed</span>`
		case !rr.reloadSkipped:
			if rr.reloadOK {
				reloadCell = `<span class="ok">reloaded</span>`
			} else {
				reloadCell = fmt.Sprintf(`<span class="crit">FAILED: %s</span> — config is saved on this node but NOT yet applied; restart dnshived.service manually from the Daemons tab`, template.HTMLEscapeString(rr.reloadErr))
			}
		}

		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n", rr.node.Name, checkCell, reloadCell)
	}
	fmt.Fprintf(w, "</table>\n<p><a href=\"%s\">%s</a></p>\n", backLink, backText)
}

// parseClusterConfigForm builds a configPushPayload from the CLUSTER
// settings form's posted values.
func parseClusterConfigForm(r *http.Request, nodes []NodeConfig) (configPushPayload, error) {
	f := r.PostForm
	var platform *config.Platform
	if mgmt := strings.TrimSpace(f.Get("platform_mgmt")); mgmt != "" {
		platform = &config.Platform{
			Mgmt:            mgmt,
			Workers:         splitLines(f.Get("platform_workers")),
			InterfaceLabels: parseInterfaceLabels(f.Get("platform_worker_labels")),
		}
	}

	var mgmtVIP *config.MgmtVIPConfig
	if vip := strings.TrimSpace(f.Get("mgmt_vip_vip")); vip != "" {
		vrrpID, _ := strconv.Atoi(f.Get("mgmt_vip_vrrp_id"))
		if vrrpID == 0 {
			vrrpID = 60
		}
		mgmtVIP = &config.MgmtVIPConfig{VIP: vip, VRRPID: vrrpID}
	}

	dnsRelayCacheSize, _ := strconv.Atoi(strings.TrimSpace(f.Get("dnsrelay_cache_size")))
	dnsRelayCacheMaxBytes, _ := strconv.Atoi(strings.TrimSpace(f.Get("dnsrelay_cache_max_bytes")))

	return configPushPayload{
		PSK:                   f.Get("psk"),
		TrustedHosts:          splitLines(f.Get("trusted_hosts")),
		TLSCert:               f.Get("tls_cert"),
		TLSKey:                f.Get("tls_key"),
		LogLevel:              f.Get("log_level"),
		Platform:              platform,
		MgmtVIP:               mgmtVIP,
		CoreDNSAddress:        strings.TrimSpace(f.Get("core_dns_address")),
		CoreDHCPAddress:       strings.TrimSpace(f.Get("core_dhcp_address")),
		CoreDNSQueryLogging:   f.Get("core_dns_query_logging") != "",
		DNSRelayCacheSize:     dnsRelayCacheSize,
		DNSRelayCacheMaxBytes: dnsRelayCacheMaxBytes,
		SanityCheckDisabled:   f.Get("sanity_check_disabled") != "",
	}, nil
}

// clusterPushPayloadFrom carries every cluster-wide field of an
// already-loaded config.Cluster into a configPushPayload UNEDITED.
func clusterPushPayloadFrom(c config.Cluster) configPushPayload {
	return configPushPayload{
		PSK: c.PSK, TrustedHosts: c.TrustedHosts,
		TLSCert: c.TLSCert, TLSKey: c.TLSKey, APITokens: c.APITokens,
		LogLevel: c.LogLevel, HelperSocket: c.HelperSocket, Platform: c.Platform,
		ProbeIntervalMS: c.ProbeIntervalMS, MgmtVIP: c.MgmtVIP,
		DefaultDNSChecks: c.DefaultDNSChecks, GlobalDNSRecords: c.GlobalDNSRecords,
		LocalDomains:  c.LocalDomains,
		ScopeDefaults: c.ScopeDefaults, DefaultDHCPOptions: c.DefaultDHCPOptions,
		CoreDNSAddress: c.CoreDNSAddress, CoreDHCPAddress: c.CoreDHCPAddress,
		CoreDNSQueryLogging:   c.CoreDNSQueryLogging,
		DNSRelayCacheSize:     c.DNSRelayCacheSize,
		DNSRelayCacheMaxBytes: c.DNSRelayCacheMaxBytes,
		SanityCheckDisabled:   c.SanityCheckDisabled,
		BackupEnabled:         c.BackupEnabled, BackupIntervalHours: c.BackupIntervalHours,
		BackupRetentionCount: c.BackupRetentionCount, BackupPassword: c.BackupPassword,
		BackupReplicateToPeers: c.BackupReplicateToPeers,
	}
}

// payloadForNode returns p with a per-node node_ip filled in for any scope
// whose NodeIP is still empty — everything else is untouched.
func payloadForNode(p configPushPayload, n NodeConfig) configPushPayload {
	if len(p.Scopes) == 0 {
		return p
	}
	var explicitSuffix string
	if p.ScopeDefaults != nil {
		explicitSuffix = p.ScopeDefaults.NodeIPSuffixes[n.Name]
	}
	scopes := make(map[string]config.ScopeConfig, len(p.Scopes))
	for name, sc := range p.Scopes {
		if v, ok := sc.NodeIPOverrides[n.Name]; ok && v != "" {
			sc.NodeIP = v
			scopes[name] = sc
			continue
		}
		switch {
		case explicitSuffix != "" && sc.VIP != "":
			if derived := nodeIPFromVIPAndOctet(sc.VIP, explicitSuffix); derived != "" {
				sc.NodeIP = derived
			}
		case sc.VIP != "":
			if derived := deriveNodeIP(n.Addr, sc.VIP); derived != "" {
				sc.NodeIP = derived
			}
		}
		scopes[name] = sc
	}
	p.Scopes = scopes
	return p
}

func checkNodeIPCollisions(payload configPushPayload, nodes []NodeConfig) error {
	type seenAt struct {
		worker, nodeIP string
	}
	perScope := make(map[string][]seenAt)
	for _, n := range nodes {
		resolved := payloadForNode(payload, n)
		for scope, sc := range resolved.Scopes {
			if sc.NodeIP == "" {
				continue
			}
			perScope[scope] = append(perScope[scope], seenAt{n.Name, sc.NodeIP})
		}
	}
	scopeNames := make([]string, 0, len(perScope))
	for name := range perScope {
		scopeNames = append(scopeNames, name)
	}
	sort.Strings(scopeNames)
	for _, scope := range scopeNames {
		entries := perScope[scope]
		for i := 0; i < len(entries); i++ {
			for j := i + 1; j < len(entries); j++ {
				if entries[i].nodeIP == entries[j].nodeIP {
					return fmt.Errorf("scope %q: %s and %s would both get node_ip %s — refusing to push (would create a real duplicate-address condition); set distinct values via the scope's own node_ip fields or Cluster Settings' node_ip suffixes",
						scope, entries[i].worker, entries[j].worker, entries[i].nodeIP)
				}
			}
		}
	}
	return nil
}

// nodeIPFromVIPAndOctet combines a VIP's own subnet base+prefix with a
// given last-octet string into a full node_ip CIDR value.
func nodeIPFromVIPAndOctet(vip, octet string) string {
	o, err := strconv.Atoi(octet)
	if err != nil || o < 0 || o > 255 {
		return ""
	}
	_, ipNet, err := net.ParseCIDR(vip)
	if err != nil {
		return ""
	}
	base := ipNet.IP.To4()
	if base == nil {
		return ""
	}
	ones, _ := ipNet.Mask.Size()
	return fmt.Sprintf("%d.%d.%d.%d/%d", base[0], base[1], base[2], o, ones)
}

func deriveNodeIP(nodeAddr, vip string) string {
	octet := nodeAddrLastOctet(nodeAddr)
	if octet == "" {
		return ""
	}
	return nodeIPFromVIPAndOctet(vip, octet)
}

// nodeAddrLastOctet extracts just the last IPv4 octet from a node's own
// host:port Addr, as a string.
func nodeAddrLastOctet(nodeAddr string) string {
	host, _, err := net.SplitHostPort(nodeAddr)
	if err != nil {
		host = nodeAddr
	}
	nodeIP := net.ParseIP(host)
	if nodeIP == nil {
		return ""
	}
	nodeIP4 := nodeIP.To4()
	if nodeIP4 == nil {
		return ""
	}
	return strconv.Itoa(int(nodeIP4[3]))
}

// parseDNSCheckLines parses the cluster form's default_dns_checks
// textarea.
func parseDNSCheckLines(s string) ([]config.DNSCheck, error) {
	var checks []config.DNSCheck
	for _, line := range splitLines(s) {
		name, typ, ok := strings.Cut(line, "|")
		if !ok {
			return nil, fmt.Errorf("%q: expected NAME|TYPE", line)
		}
		checks = append(checks, config.DNSCheck{Name: strings.TrimSpace(name), Type: strings.ToUpper(strings.TrimSpace(typ))})
	}
	return checks, nil
}

// formatDNSCheckLines is parseDNSCheckLines' inverse, for the form's
// initial textarea value.
func formatDNSCheckLines(checks []config.DNSCheck) string {
	lines := make([]string, len(checks))
	for i, c := range checks {
		lines[i] = c.Name + "|" + c.Type
	}
	return strings.Join(lines, "\n")
}

// withoutSecrets returns c with every secret blanked, for page data: the
// PSK, API token values and the backup password never reach the browser.
func withoutSecrets(c config.Cluster) config.Cluster {
	c.PSK = maskedSecret(c.PSK)
	c.BackupPassword = maskedSecret(c.BackupPassword)
	tokens := make([]config.APIToken, len(c.APITokens))
	for i, t := range c.APITokens {
		t.Token = maskedSecret(t.Token)
		tokens[i] = t
	}
	c.APITokens = tokens
	return c
}

// maskedSecret keeps only whether a secret is set.
func maskedSecret(s string) string {
	if s == "" {
		return ""
	}
	return "set"
}

// parseTokenSlots reads back as many token_* rows as were actually
// rendered; a row with a name but a blank token keeps the current token
// of that name (token values are never rendered).
func parseTokenSlots(f map[string][]string, current []config.APIToken) []config.APIToken {
	rowCount, _ := strconv.Atoi(first(f["__token_row_count__"]))
	if rowCount <= 0 {
		rowCount = newTokenSlots
	}
	var tokens []config.APIToken
	for i := 0; i < rowCount; i++ {
		name := strings.TrimSpace(first(f["token_name_"+strconv.Itoa(i)]))
		token := strings.TrimSpace(first(f["token_value_"+strconv.Itoa(i)]))
		if name != "" && token == "" {
			for j, ct := range current {
				if ct.Name == name && ct.Token != "" {
					token = ct.Token
					current = append(append([]config.APIToken(nil), current[:j]...), current[j+1:]...)
					break
				}
			}
		}
		if name == "" || token == "" {
			continue // blank slot — not every slot needs to be filled
		}
		tokens = append(tokens, config.APIToken{
			Name:    name,
			Token:   token,
			Role:    first(f["token_role_"+strconv.Itoa(i)]),
			Expires: strings.TrimSpace(first(f["token_expires_"+strconv.Itoa(i)])),
		})
	}
	return tokens
}

func parseScopeSlots(f map[string][]string) (map[string]config.ScopeConfig, error) {
	scopes := make(map[string]config.ScopeConfig)
	names := first(f["__scope_names__"])
	for _, name := range strings.Split(names, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if first(f["scope_delete_"+name]) == "on" {
			continue // deleted — simply not carried forward
		}
		vlanID, _ := strconv.Atoi(first(f["scope_vlan_id_"+name]))
		vrrpID, _ := strconv.Atoi(first(f["scope_vrrp_id_"+name]))
		advertMS, _ := strconv.Atoi(first(f["scope_advert_int_ms_"+name]))
		vrrpVersion, _ := strconv.Atoi(first(f["scope_vrrp_version_"+name]))
		dnsRecords, err := parseDNSRecordLines(first(f["scope_dns_records_"+name]))
		if err != nil {
			return nil, fmt.Errorf("scope %q: dns_records: %w", name, err)
		}
		scopes[name] = config.ScopeConfig{
			Parent:          first(f["scope_parent_"+name]),
			VLANID:          vlanID,
			VIP:             first(f["scope_vip_"+name]),
			NodeIP:          first(f["scope_node_ip_"+name]),
			DHCPRange:       [2]string{first(f["scope_dhcp_start_"+name]), first(f["scope_dhcp_end_"+name])},
			Gateway:         first(f["scope_gateway_"+name]),
			VRRPID:          vrrpID,
			PreferredWorker: first(f["scope_preferred_worker_"+name]),
			AdvertIntMS:     advertMS,
			VRRPVersion:     vrrpVersion,
			DNSRecords:      dnsRecords,
			Color:           parseScopeColor(first(f["scope_color_"+name])),
			DHCPOptions:     splitLines(first(f["scope_dhcp_options_"+name])),
			ProbeDisabled:   first(f["scope_probe_disabled_"+name]) == "on",
		}
	}
	// New-scope slots.
	for i := 0; i < newScopeSlots; i++ {
		suffix := "new_" + strconv.Itoa(i)
		name := strings.TrimSpace(first(f["scope_name_"+suffix]))
		if name == "" {
			continue // unused slot
		}
		vlanID, _ := strconv.Atoi(first(f["scope_vlan_id_"+suffix]))
		vrrpID, _ := strconv.Atoi(first(f["scope_vrrp_id_"+suffix]))
		advertMS, _ := strconv.Atoi(first(f["scope_advert_int_ms_"+suffix]))
		vrrpVersion, _ := strconv.Atoi(first(f["scope_vrrp_version_"+suffix]))
		dnsRecords, err := parseDNSRecordLines(first(f["scope_dns_records_"+suffix]))
		if err != nil {
			return nil, fmt.Errorf("new scope %q: dns_records: %w", name, err)
		}
		scopes[name] = config.ScopeConfig{
			Parent:          first(f["scope_parent_"+suffix]),
			VLANID:          vlanID,
			VIP:             first(f["scope_vip_"+suffix]),
			NodeIP:          first(f["scope_node_ip_"+suffix]),
			DHCPRange:       [2]string{first(f["scope_dhcp_start_"+suffix]), first(f["scope_dhcp_end_"+suffix])},
			Gateway:         first(f["scope_gateway_"+suffix]),
			VRRPID:          vrrpID,
			PreferredWorker: first(f["scope_preferred_worker_"+suffix]),
			AdvertIntMS:     advertMS,
			VRRPVersion:     vrrpVersion,
			DNSRecords:      dnsRecords,
			Color:           parseScopeColor(first(f["scope_color_"+suffix])),
			DHCPOptions:     splitLines(first(f["scope_dhcp_options_"+suffix])),
		}
	}
	return scopes, nil
}

// parseScopeColor normalizes the scope editor's native <input
// type="color"> submission.
func parseScopeColor(raw string) string {
	if strings.EqualFold(raw, scopeColorUnset) {
		return ""
	}
	return raw
}

func first(vals []string) string {
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// parseInterfaceLabels parses the config form's "worker interface display
// names" textarea.
func parseInterfaceLabels(s string) map[string]string {
	var labels map[string]string
	for _, line := range splitLines(s) {
		iface, label, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		iface, label = strings.TrimSpace(iface), strings.TrimSpace(label)
		if iface == "" || label == "" {
			continue
		}
		if labels == nil {
			labels = make(map[string]string)
		}
		labels[iface] = label
	}
	return labels
}

// --- form rendering ---

type scopeFormRow struct {
	Name string
	config.ScopeConfig
	DNSRecordsText  string
	DHCPOptionsText string // strings.Join(ScopeConfig.DHCPOptions, "\n")
}

type nodeIPSuffixRow struct {
	Name   string
	Suffix string
}

type tokenFormRow struct {
	Index int
	config.APIToken
	HasToken bool
}

// clusterFormData backs the cluster settings page (handleConfigGet).
type clusterFormData struct {
	SourceNode string
	Cluster    config.Cluster
	// Tokens is always fixed-length (existing tokens + newTokenSlots blanks)
	// — see buildClusterFormData.
	Tokens                       []tokenFormRow
	TokenRowCount                int
	ScopeDefaultsGatewaySuffix   string
	ScopeDefaultsVIPSuffix       string
	ScopeDefaultsNodeIPSuffixes  []nodeIPSuffixRow
	ScopeDefaultsDHCPStartSuffix string
	ScopeDefaultsDHCPEndSuffix   string
	ScopeDefaultsUpstreamText    string
	ScopeDefaultsAdvertIntMS     int
	ScopeDefaultsVRRPVersion     int
	// UsedVRRPIDs is every vrrp_id already claimed by a scope or the mgmt VIP
	// itself, comma-joined ascending — see usedVRRPIDsCSV.
	UsedVRRPIDs string
	// Pending is true when this form's baseline came from an existing
	// candidate rather than live config (currentEditableConfig's own
	// isPending).
	Pending bool

	// AllNodes backs the Cluster nodes section's rename/replace forms.
	AllNodes []NodeConfig

	MissingRoles []string

	OnboardTargets []string
	ReplaceTargets []string

	// Discovered is the LAN-autodiscovery listener's live view.
	Discovered []discovery.Candidate

	ThisVersion string
}

type probeParallelRow struct {
	Name, Addr string
	Enabled    bool
	ScopeCount int
	Reachable  bool
	Err        string
}

type dnsConfigFormData struct {
	SourceNode           string
	DefaultDNSChecksText string
	GlobalDNSRecordsText string
	GlobalDNSNames       []dnsCheckOption
	// Pending: see clusterFormData.Pending.
	Pending bool
}

// dnsCheckOption is one selectable (name, type) pair for the quick-add
// dropdown above.
type dnsCheckOption struct {
	Name, Type string
}

func buildDNSConfigFormData(c config.Cluster, node NodeConfig) dnsConfigFormData {
	seen := make(map[string]bool)
	var opts []dnsCheckOption
	for _, r := range c.GlobalDNSRecords {
		key := r.Name + "|" + r.Type
		if seen[key] {
			continue
		}
		seen[key] = true
		opts = append(opts, dnsCheckOption{Name: r.Name, Type: r.Type})
	}
	sort.Slice(opts, func(i, j int) bool {
		if opts[i].Name != opts[j].Name {
			return opts[i].Name < opts[j].Name
		}
		return opts[i].Type < opts[j].Type
	})
	return dnsConfigFormData{
		SourceNode:           node.Name,
		DefaultDNSChecksText: formatDNSCheckLines(c.DefaultDNSChecks),
		GlobalDNSRecordsText: formatDNSRecordLines(c.GlobalDNSRecords),
		GlobalDNSNames:       opts,
	}
}

// dhcpScopeRow is one scope's own dhcp_options, read-only, for the
// DHCP-options page's summary table.
type dhcpScopeRow struct {
	Name            string
	VLANID          int
	DHCPOptionsText string
	// UsesDefault is true when this scope has no dhcp_options of its own.
	UsesDefault bool
}

type dhcpConfigFormData struct {
	SourceNode string
	// DefaultDHCPOptionsText is the cluster-wide fallback DHCP options
	// textarea's initial value, one raw dnsmasq --dhcp-option value per line.
	DefaultDHCPOptionsText string
	// Scopes is sorted by VLANID, like the scope editor.
	Scopes []dhcpScopeRow
	// Pending: see clusterFormData.Pending.
	Pending bool
}

func buildDHCPConfigFormData(c config.Cluster, node NodeConfig) dhcpConfigFormData {
	data := dhcpConfigFormData{
		SourceNode:             node.Name,
		DefaultDHCPOptionsText: strings.Join(c.DefaultDHCPOptions, "\n"),
	}
	for name, sc := range c.Scopes {
		data.Scopes = append(data.Scopes, dhcpScopeRow{
			Name: name, VLANID: sc.VLANID,
			DHCPOptionsText: strings.Join(sc.DHCPOptions, "\n"),
			UsesDefault:     len(sc.DHCPOptions) == 0,
		})
	}
	sort.Slice(data.Scopes, func(i, j int) bool { return data.Scopes[i].VLANID < data.Scopes[j].VLANID })
	return data
}

type dhcpDNSConfigFormData struct {
	SourceNode string
	// Pending: see clusterFormData.Pending.
	Pending bool

	DNS  dnsConfigFormData
	DHCP dhcpConfigFormData

	LocalDomains       []localDomainFormRow
	GlobalDNSBuilder   template.HTML
	DefaultDHCPBuilder template.HTML

	DHCPTemplates      []templateRow
	DNSTemplates       []templateRow
	ClientDNSTemplates []templateRow
}

func buildClusterFormData(c config.Cluster, node NodeConfig, allNodes []NodeConfig) clusterFormData {
	numTokenRows := len(c.APITokens) + newTokenSlots
	tokens := make([]tokenFormRow, numTokenRows)
	for i := range tokens {
		tokens[i].Index = i
		if i < len(c.APITokens) {
			tokens[i].APIToken = c.APITokens[i]
			tokens[i].HasToken = c.APITokens[i].Token != ""
			tokens[i].Token = ""
		}
	}
	c = withoutSecrets(c)

	data := clusterFormData{
		SourceNode:    node.Name,
		Cluster:       c,
		Tokens:        tokens,
		TokenRowCount: numTokenRows,
		UsedVRRPIDs:   usedVRRPIDsCSV(c),
	}
	var nodeIPSuffixes map[string]string
	if c.ScopeDefaults != nil {
		data.ScopeDefaultsGatewaySuffix = c.ScopeDefaults.GatewaySuffix
		data.ScopeDefaultsVIPSuffix = c.ScopeDefaults.VIPSuffix
		nodeIPSuffixes = c.ScopeDefaults.NodeIPSuffixes
		data.ScopeDefaultsDHCPStartSuffix = c.ScopeDefaults.DHCPStartSuffix
		data.ScopeDefaultsDHCPEndSuffix = c.ScopeDefaults.DHCPEndSuffix
		data.ScopeDefaultsUpstreamText = strings.Join(c.ScopeDefaults.Upstream, "\n")
		data.ScopeDefaultsAdvertIntMS = c.ScopeDefaults.AdvertIntMS
		data.ScopeDefaultsVRRPVersion = c.ScopeDefaults.VRRPVersion
	}
	for _, n := range allNodes {
		suffix := nodeIPSuffixes[n.Name]
		if suffix == "" {
			suffix = nodeAddrLastOctet(n.Addr)
		}
		data.ScopeDefaultsNodeIPSuffixes = append(data.ScopeDefaultsNodeIPSuffixes, nodeIPSuffixRow{
			Name: n.Name, Suffix: suffix,
		})
	}
	return data
}

// usedVRRPIDsCSV returns every vrrp_id already claimed by a scope or the
// mgmt VIP, comma-joined ascending.
func usedVRRPIDsCSV(c config.Cluster) string {
	ids := make([]int, 0, len(c.Scopes)+1)
	if c.MgmtVIP != nil {
		ids = append(ids, c.MgmtVIP.VRRPID)
	}
	for _, sc := range c.Scopes {
		ids = append(ids, sc.VRRPID)
	}
	sort.Ints(ids)
	strs := make([]string, len(ids))
	for i, id := range ids {
		strs[i] = strconv.Itoa(id)
	}
	return strings.Join(strs, ",")
}

type scopesFormData struct {
	SourceNode string
	// Workers backs the parent-interface <select> in every row — needs only
	// the interface list, not the rest of Cluster.
	Workers           []string
	Scopes            []scopeFormRow
	ScopeNames        string // comma-joined, for the hidden __scope_names__ field
	ScopeNamesForCopy []string
	NewScopeSlots     []int
	GatewaySuffix     string
	// VIPSuffix is the cluster's preferred last octet for a new scope's own
	// VIP (Cluster Settings' new "Scope VIP preference" section,
	// config.ScopeDefaults.VIPSuffix).
	VIPSuffix string
	// AdvertIntMS/VRRPVersion pre-fill the new-scope row's own VRRP tuning
	// fields — same ScopeDefaults-sourced pre-fill as GatewaySuffix above.
	AdvertIntMS int
	VRRPVersion int
	// PreferredWorkerDefault is which core role (core-1/core-2/core-3) the
	// new-scope-slot's preferred_worker <select> should default to.
	PreferredWorkerDefault string
	IPPattern              string
	IPCIDRPattern          string
	// GatewayPattern backs the Gateway field's pattern= check.
	GatewayPattern string
	// UsedVRRPIDs is every vrrp_id already claimed by a scope or the mgmt VIP,
	// comma-joined ascending — see usedVRRPIDsCSV.
	UsedVRRPIDs string
	// Pending: see clusterFormData.Pending.
	Pending bool
}

const (
	ipPattern     = `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`
	ipCIDRPattern = ipPattern + `(/\d{1,2})?`
	// ipGatewayPattern backs ScopeConfig.Gateway's own pattern= syntax check.
	ipGatewayPattern = ipPattern + `(\s*,\s*` + ipPattern + `)*`
)

var scopeColorPalette = []string{
	"#e6194b", "#800000", // red, dark red
	"#4363d8", "#000075", // blue, navy
	"#3cb44b", "#006400", // green, dark green
	"#911eb4", "#4b0082", // purple, indigo
	"#000000", "#ffffff", // black, white
}

// scopeColorUnset is the color picker's "nothing chosen yet" sentinel.
const scopeColorUnset = "#c0c0c0"

func buildScopesFormData(c config.Cluster, node NodeConfig) scopesFormData {
	names := make([]string, 0, len(c.Scopes))
	for name := range c.Scopes {
		names = append(names, name)
	}
	sort.Strings(names)

	rows := make([]scopeFormRow, 0, len(names))
	for _, name := range names {
		sc := c.Scopes[name]
		rows = append(rows, scopeFormRow{
			Name: name, ScopeConfig: sc,
			DNSRecordsText:  formatDNSRecordLines(sc.DNSRecords),
			DHCPOptionsText: strings.Join(sc.DHCPOptions, "\n"),
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].VLANID < rows[j].VLANID })

	copyNames := make([]string, len(names))
	copy(copyNames, names)

	newScopeIdx := make([]int, newScopeSlots)
	for i := range newScopeIdx {
		newScopeIdx[i] = i
	}

	var workers []string
	if c.Platform != nil {
		workers = c.Platform.Workers
	}

	data := scopesFormData{
		SourceNode:             node.Name,
		Workers:                workers,
		Scopes:                 rows,
		ScopeNames:             strings.Join(names, ","),
		ScopeNamesForCopy:      copyNames,
		NewScopeSlots:          newScopeIdx,
		IPPattern:              ipPattern,
		IPCIDRPattern:          ipCIDRPattern,
		GatewayPattern:         ipGatewayPattern,
		UsedVRRPIDs:            usedVRRPIDsCSV(c),
		PreferredWorkerDefault: lessLoadedWorker(rows),
	}
	if c.ScopeDefaults != nil {
		data.GatewaySuffix = c.ScopeDefaults.GatewaySuffix
		data.VIPSuffix = c.ScopeDefaults.VIPSuffix
		data.AdvertIntMS = c.ScopeDefaults.AdvertIntMS
		data.VRRPVersion = c.ScopeDefaults.VRRPVersion
	}
	return data
}

// lessLoadedWorker returns whichever of core-1/core-2/core-3 currently has
// fewer configured scopes — see scopesFormData.
func lessLoadedWorker(rows []scopeFormRow) string {
	counts := map[string]int{}
	for _, r := range rows {
		counts[r.PreferredWorker]++
	}
	best := config.RoleCore1
	for _, role := range []string{config.RoleCore2, config.RoleCore3} {
		if counts[role] < counts[best] {
			best = role
		}
	}
	return best
}
