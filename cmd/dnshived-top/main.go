// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// dnshived-top — interactive cluster monitoring console.
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"dnshived/internal/clientrc"
	"time"
	"unicode/utf8"
	"unsafe"
)

var version = "0.9.7-dev"

// --- API types ---

type nodeStatus struct {
	NodeID           string            `json:"node_id"`
	Role             string            `json:"role"`
	ClusterID        string            `json:"cluster_id"`
	State            string            `json:"state"`
	Epoch            uint64            `json:"epoch"`
	Generation       uint64            `json:"generation"`
	Incarnation      uint64            `json:"incarnation"`
	Healthy          bool              `json:"healthy"`
	Serving          []string          `json:"serving"`
	Watermark        map[string]uint64 `json:"watermark"`
	Version          string            `json:"version"`
	ServerTime       string            `json:"server_time"`
	PeersVisible     []string          `json:"peers_visible"`
	PeersUnreachable []string          `json:"peers_unreachable"`
	// FallbackPeers: primary (mgmt) addr -> scope-VLAN fallback addr for every
	// peer this node sees down over mgmt but alive over the fallback path
	// (mgmt-only loss).
	FallbackPeers    map[string]string `json:"fallback_peers"`
	ConfiguredScopes []string          `json:"configured_scopes"`
	ScopesHash       string            `json:"scopes_hash"`
	PlaneWarnings    []string          `json:"plane_warnings"`
	// IoTScopes is the subset of ConfiguredScopes with dhcp_iot_defaults set.
	IoTScopes []string `json:"iot_scopes"`
	// DisabledScopes is the subset of ConfiguredScopes with dnsmasq_disabled set.
	DisabledScopes []string `json:"disabled_scopes"`
	StateSince     string   `json:"state_since"`
	// Paths: this node's own view of every
	// alternate (worker-trunk) path to every other core role.
	Paths []nodePathStatus `json:"paths,omitempty"`
}

// nodePathStatus mirrors internal/cluster.FallbackStatus's own JSON shape.
type nodePathStatus struct {
	Role      string `json:"role"`
	Parent    string `json:"parent"`
	Addr      string `json:"addr"`
	Reachable bool   `json:"reachable"`
	LastError string `json:"last_error,omitempty"`
	Score     int    `json:"score"`
}

// probeResult mirrors an external probe host's GET /api/v1/probe/<scope>
// response shape (cmd/dnshived-probe's own API — see cmd/dnshived-probe/
// api.go).
type probeResult struct {
	Scope   string `json:"scope"`
	Pending bool   `json:"pending"`
	// Enabled is false when a scope opted out of probing (e.g. the record-
	// level config.DNSRecord.ProbeDisabled).
	Enabled  bool   `json:"enabled"`
	ProbedAt string `json:"probed_at"`
	DHCP     struct {
		Verdict string   `json:"verdict"`
		Servers []string `json:"servers"`
		Error   string   `json:"error"`
		Valid   bool     `json:"valid"`
		Reason  string   `json:"reason,omitempty"`
	} `json:"dhcp"`
	DNS struct {
		Answered  bool   `json:"answered"`
		LatencyMS int64  `json:"latency_ms"`
		Error     string `json:"error"`
	} `json:"dns"`
}

// daemonStatus mirrors GET /api/v1/daemons's per-unit entry shape.
type daemonStatus struct {
	Unit        string `json:"unit"`
	LoadState   string `json:"load_state"`
	ActiveState string `json:"active_state"`
	SubState    string `json:"sub_state"`
	UptimeSec   int64  `json:"uptime_seconds"`
	Version     string `json:"version"`
	Error       string `json:"error"`
	PID         int    `json:"pid"`
	User        string `json:"user"`
	ActiveCount int    `json:"active_count"`
	TotalCount  int    `json:"total_count"`
}

type daemonsResponse struct {
	NodeID  string         `json:"node_id"`
	Daemons []daemonStatus `json:"daemons"`
}

type clusterView struct {
	SelfAddr string      `json:"self_addr"`
	Peers    []peerState `json:"peers"`
}

type peerState struct {
	Addr string `json:"addr"`
}

type tokenInfo struct {
	Owner     string `json:"owner"`
	ExpiresAt string `json:"expires_at"`
	Expired   bool   `json:"expired"`
}

type systemInfo struct {
	LoadAvg1   float64 `json:"load_avg_1"`
	LoadAvg5   float64 `json:"load_avg_5"`
	MemTotalMB int64   `json:"memory_total_mb"`
	MemUsedMB  int64   `json:"memory_used_mb"`
	MemPct     int     `json:"memory_used_pct"`
	UptimeSec  int64   `json:"uptime_seconds"`
}

type event struct {
	Timestamp time.Time `json:"ts"`
	Level     string    `json:"level"`
	Prefix    string    `json:"prefix"`
	Message   string    `json:"message"`
	NodeID    string    `json:"node_id"`
}

type nodeData struct {
	Addr      string
	Status    *nodeStatus
	System    *systemInfo
	Events    []event
	Daemons   []daemonStatus
	Reachable bool
	Error     string
	// ViaFallback: this node's mgmt path is down but its data was fetched over
	// its scope-VLAN fallback address.
	ViaFallback bool
}

// --- HTTP client ---

var (
	scheme   = "http"
	apiToken = ""
	client   = &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:      10,
			MaxConnsPerHost:   2,
			IdleConnTimeout:   30 * time.Second,
			DisableKeepAlives: false,
		},
	}
	probeClient = &http.Client{Timeout: 5 * time.Second}
)

func fetchJSON(url string, v interface{}) error {
	return fetchJSONWith(client, url, v)
}

func fetchJSONWith(cl *http.Client, url string, v interface{}) error {
	req, _ := http.NewRequest("GET", url, nil)
	if apiToken != "" {
		req.Header.Set("Authorization", "Bearer "+apiToken)
	}
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(v)
}

// --- Data collection ---

// clusterSnapshotResponse mirrors GET /api/v1/cluster/snapshot's wire
// shape (cmd/dnshived's own cluster_snapshot.go).
type clusterSnapshotResponse struct {
	Self   snapshotNode            `json:"self"`
	Peers  map[string]snapshotNode `json:"peers"`
	Tokens map[string]tokenInfo    `json:"tokens"`
}

// snapshotNode is one node's raw, still-encoded bundle within a
// clusterSnapshotResponse.
type snapshotNode struct {
	Status  json.RawMessage `json:"status,omitempty"`
	System  json.RawMessage `json:"system,omitempty"`
	Events  json.RawMessage `json:"events,omitempty"`
	Daemons json.RawMessage `json:"daemons,omitempty"`
	Error   string          `json:"error,omitempty"`
	// Via is "fallback" when the daemon fetched this node over its scope-VLAN
	// fallback address because its mgmt path is down.
	Via     string `json:"via,omitempty"`
	ViaAddr string `json:"via_addr,omitempty"`
}

// decodeSnapshotNode turns one snapshotNode's raw bundles into the SAME
// nodeData shape collectAll's own per-node fetch already builds.
func decodeSnapshotNode(addr string, sn snapshotNode) nodeData {
	nd := nodeData{Addr: addr, ViaFallback: sn.Via == "fallback"}
	if sn.Error != "" {
		nd.Error = sn.Error
		return nd
	}
	var st nodeStatus
	if err := json.Unmarshal(sn.Status, &st); err != nil {
		nd.Error = err.Error()
		return nd
	}
	nd.Status = &st
	nd.Reachable = true
	if len(sn.System) > 0 {
		var si systemInfo
		if json.Unmarshal(sn.System, &si) == nil {
			nd.System = &si
		}
	}
	if len(sn.Events) > 0 {
		var evts []event
		if json.Unmarshal(sn.Events, &evts) == nil {
			nd.Events = evts
		}
	}
	if len(sn.Daemons) > 0 {
		var dr daemonsResponse
		if json.Unmarshal(sn.Daemons, &dr) == nil {
			nd.Daemons = dr.Daemons
		}
	}
	return nd
}

// collectFromSnapshot is the "single address, one TCP port" alternative to
// collectAll's own multi-round-trip fan-out.
func collectFromSnapshot(entryAddr string) (nodes []nodeData, tokens map[string]tokenInfo, warnings []string, ok bool) {
	var resp clusterSnapshotResponse
	if err := fetchJSON(scheme+"://"+entryAddr+"/api/v1/cluster/snapshot", &resp); err != nil {
		return nil, nil, nil, false
	}
	if len(resp.Self.Status) == 0 && resp.Self.Error == "" {
		return nil, nil, nil, false
	}

	nodes = append(nodes, decodeSnapshotNode(entryAddr, resp.Self))
	for addr, sn := range resp.Peers {
		nodes = append(nodes, decodeSnapshotNode(addr, sn))
	}
	sort.Slice(nodes, func(i, j int) bool {
		return roleOrder(nodes[i].role()) < roleOrder(nodes[j].role())
	})

	tokens = resp.Tokens
	warnings = checkCoherence(nodes, tokens)
	return nodes, tokens, warnings, true
}

// fetchNodeData builds one node's data.
func fetchNodeData(addr, dialAddr string) nodeData {
	nd := nodeData{Addr: addr}

	var st nodeStatus
	if err := fetchJSON(scheme+"://"+dialAddr+"/api/v1/status", &st); err != nil {
		nd.Error = err.Error()
		return nd
	}
	nd.Status = &st
	nd.Reachable = true

	var si systemInfo
	if err := fetchJSON(scheme+"://"+dialAddr+"/api/v1/system", &si); err == nil {
		nd.System = &si
	}

	var evts []event
	if err := fetchJSON(scheme+"://"+dialAddr+"/api/v1/events?n=50", &evts); err == nil {
		nd.Events = evts
	}

	var dr daemonsResponse
	if err := fetchJSON(scheme+"://"+dialAddr+"/api/v1/daemons", &dr); err == nil {
		nd.Daemons = dr.Daemons
	}
	return nd
}

var (
	knownNodesMu sync.Mutex
	knownNodes   = map[string]bool{}
)

func rememberNodes(nodes []nodeData) {
	knownNodesMu.Lock()
	defer knownNodesMu.Unlock()
	for _, n := range nodes {
		if n.Addr != "" {
			knownNodes[n.Addr] = true
		}
	}
}

// knownNodesExcept lists remembered node addresses not among exclude, in a
// stable order.
func knownNodesExcept(exclude []string) []string {
	skip := make(map[string]bool, len(exclude))
	for _, e := range exclude {
		skip[e] = true
	}
	knownNodesMu.Lock()
	defer knownNodesMu.Unlock()
	var out []string
	for a := range knownNodes {
		if !skip[a] {
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out
}

// collectAll queries all cluster nodes.
func collectAll(entryAddrs []string) ([]nodeData, map[string]tokenInfo, []string) {
	if len(entryAddrs) == 1 {
		if nodes, tokens, warnings, ok := collectFromSnapshot(entryAddrs[0]); ok {
			rememberNodes(nodes)
			return nodes, tokens, warnings
		}
		// The one configured entry failed (typically the node whose mgmt interface
		// just went down, or the VIP mid-move).
		for _, alt := range knownNodesExcept(entryAddrs) {
			if nodes, tokens, warnings, ok := collectFromSnapshot(alt); ok {
				rememberNodes(nodes)
				return nodes, tokens, warnings
			}
		}
	}
	// Discover full topology from any responding entry address (falling back
	// to any node seen before when none of the entries answer).
	var cv clusterView
	discovered := false
	for _, ea := range append(append([]string{}, entryAddrs...), knownNodesExcept(entryAddrs)...) {
		if err := fetchJSON(scheme+"://"+ea+"/api/v1/cluster", &cv); err == nil {
			discovered = true
			break
		}
	}
	if !discovered {
		// No entry address responded. Try each as a standalone node.
		nodes := make([]nodeData, len(entryAddrs))
		for i, ea := range entryAddrs {
			nodes[i] = nodeData{Addr: ea, Error: "unreachable"}
		}
		return nodes, nil, []string{"no cluster node reachable"}
	}

	// Build unique address set from discovery + explicit entries.
	addrSet := make(map[string]bool)
	addrSet[cv.SelfAddr] = true
	for _, p := range cv.Peers {
		addrSet[p.Addr] = true
	}
	for _, ea := range entryAddrs {
		addrSet[ea] = true
	}
	addrs := make([]string, 0, len(addrSet))
	for a := range addrSet {
		addrs = append(addrs, a)
	}

	// Query all nodes in parallel.
	nodes := make([]nodeData, len(addrs))
	var wg sync.WaitGroup
	for i, addr := range addrs {
		wg.Add(1)
		go func(idx int, a string) {
			defer wg.Done()
			nodes[idx] = fetchNodeData(a, a)
		}(i, addr)
	}
	wg.Wait()

	routes := map[string]string{}
	for _, nd := range nodes {
		if nd.Reachable && nd.Status != nil {
			for primary, fb := range nd.Status.FallbackPeers {
				routes[primary] = fb
			}
		}
	}
	for i := range nodes {
		if nodes[i].Reachable {
			continue
		}
		if fb, ok := routes[nodes[i].Addr]; ok && fb != "" {
			if via := fetchNodeData(nodes[i].Addr, fb); via.Reachable {
				via.ViaFallback = true
				nodes[i] = via
			}
		}
	}
	rememberNodes(nodes)

	sort.Slice(nodes, func(i, j int) bool {
		return roleOrder(nodes[i].role()) < roleOrder(nodes[j].role())
	})

	tokens := make(map[string]tokenInfo)
	var preferredAddr, fallbackAddr string
	for _, n := range nodes {
		if !n.Reachable {
			continue
		}
		if n.role() == "core-3" {
			preferredAddr = n.Addr
			continue
		}
		if fallbackAddr == "" {
			fallbackAddr = n.Addr
		}
	}
	for _, addr := range []string{preferredAddr, fallbackAddr} {
		if addr == "" {
			continue
		}
		if err := fetchJSON(scheme+"://"+addr+"/api/v1/token/status", &tokens); err == nil {
			break
		}
	}

	// Coherence cross-check.
	warnings := checkCoherence(nodes, tokens)

	return nodes, tokens, warnings
}

// scopeNamesFromNodes unions ConfiguredScopes across every reachable core
// node.
func scopeNamesFromNodes(nodes []nodeData) []string {
	seen := make(map[string]bool)
	var names []string
	for _, n := range nodes {
		if !n.Reachable || !isCoreRole(n.role()) {
			continue
		}
		for _, sc := range n.Status.ConfiguredScopes {
			if !seen[sc] {
				seen[sc] = true
				names = append(names, sc)
			}
		}
	}
	return names
}

// servingScopeNamesFromNodes unions every reachable core node's own live
// Status.Serving into a membership set.
func servingScopeNamesFromNodes(nodes []nodeData) map[string]bool {
	serving := make(map[string]bool)
	for _, n := range nodes {
		if !n.Reachable || !isCoreRole(n.role()) {
			continue
		}
		for _, sc := range n.Status.Serving {
			serving[sc] = true
		}
	}
	return serving
}

// disabledScopeSet unions DisabledScopes across every reachable core node.
func disabledScopeSet(nodes []nodeData) map[string]bool {
	set := make(map[string]bool)
	for _, n := range nodes {
		if !n.Reachable || !isCoreRole(n.role()) {
			continue
		}
		for _, sc := range n.Status.DisabledScopes {
			set[sc] = true
		}
	}
	return set
}

// withoutDisabledScopes drops disabled scopes from per-host probe results.
func withoutDisabledScopes(results map[string]map[string]probeResult, disabled map[string]bool) map[string]map[string]probeResult {
	if len(disabled) == 0 {
		return results
	}
	out := make(map[string]map[string]probeResult, len(results))
	for addr, byScope := range results {
		m := make(map[string]probeResult, len(byScope))
		for sc, pr := range byScope {
			if !disabled[sc] {
				m[sc] = pr
			}
		}
		out[addr] = m
	}
	return out
}

// iotScopeSet unions IoTScopes across every reachable core node, mirroring
// scopeNamesFromNodes' own union.
func iotScopeSet(nodes []nodeData) map[string]bool {
	set := make(map[string]bool)
	for _, n := range nodes {
		if !n.Reachable || !isCoreRole(n.role()) {
			continue
		}
		for _, sc := range n.Status.IoTScopes {
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

// collectProbeHosts polls GET /api/v1/status on every configured external
// probe host.
func collectProbeHosts(addrs []string) (map[string]nodeStatus, map[string]string, map[string][]daemonStatus, map[string]systemInfo) {
	statuses := make(map[string]nodeStatus)
	errs := make(map[string]string)
	daemons := make(map[string][]daemonStatus)
	systems := make(map[string]systemInfo)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, addr := range addrs {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			var st nodeStatus
			err := fetchJSONWith(probeClient, "http://"+addr+"/api/v1/status", &st)
			if err != nil {
				mu.Lock()
				errs[addr] = err.Error()
				mu.Unlock()
				return
			}
			var dr daemonsResponse
			var sys systemInfo
			daemonErr := fetchJSONWith(probeClient, "http://"+addr+"/api/v1/daemons", &dr)
			sysErr := fetchJSONWith(probeClient, "http://"+addr+"/api/v1/system", &sys)
			mu.Lock()
			defer mu.Unlock()
			statuses[addr] = st
			if daemonErr == nil {
				daemons[addr] = dr.Daemons
			}
			if sysErr == nil {
				systems[addr] = sys
			}
		}(addr)
	}
	wg.Wait()
	return statuses, errs, daemons, systems
}

// collectProbeHostResults polls GET /api/v1/probe/<scope> on every
// configured external probe host for every known scope.
func collectProbeHostResults(addrs, scopes []string) map[string]map[string]probeResult {
	results := make(map[string]map[string]probeResult)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, addr := range addrs {
		mu.Lock()
		results[addr] = make(map[string]probeResult)
		mu.Unlock()
		for _, scope := range scopes {
			wg.Add(1)
			go func(addr, scope string) {
				defer wg.Done()
				var pr probeResult
				if err := fetchJSONWith(probeClient, "http://"+addr+"/api/v1/probe/"+scope, &pr); err != nil {
					pr.Scope = scope
					pr.DHCP.Error = err.Error()
					pr.DNS.Error = err.Error()
				}
				mu.Lock()
				results[addr][scope] = pr
				mu.Unlock()
			}(addr, scope)
		}
	}
	wg.Wait()
	return results
}

// collectProbeHostEvents polls GET /api/v1/events on every configured
// external probe host.
func collectProbeHostEvents(addrs []string) map[string][]event {
	results := make(map[string][]event, len(addrs))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, addr := range addrs {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			var evts []event
			fetchJSONWith(probeClient, "http://"+addr+"/api/v1/events?n=50", &evts)
			mu.Lock()
			results[addr] = evts
			mu.Unlock()
		}(addr)
	}
	wg.Wait()
	return results
}

// scopesMismatch compares scopes_hash across every real core role.
func scopesMismatch(nodes []nodeData) bool {
	hashes := make(map[string]bool)
	for _, n := range nodes {
		if n.Reachable && n.Status.ScopesHash != "" && isCoreRole(n.Status.Role) {
			hashes[n.Status.ScopesHash] = true
		}
	}
	return len(hashes) > 1
}

// versionMismatchWarning groups reachable nodes by role for each distinct
// version, returning "" when everyone agrees.
func versionMismatchWarning(nodes []nodeData) string {
	byVersion := make(map[string][]string) // version -> roles running it
	for _, n := range nodes {
		if n.Reachable {
			byVersion[n.Status.Version] = append(byVersion[n.Status.Version], n.role())
		}
	}
	if len(byVersion) <= 1 {
		return ""
	}
	versions := make([]string, 0, len(byVersion))
	for v := range byVersion {
		versions = append(versions, v)
	}
	sort.Strings(versions)
	var parts []string
	for _, v := range versions {
		roles := byVersion[v]
		sort.Strings(roles)
		parts = append(parts, fmt.Sprintf("%s: %s", v, strings.Join(roles, ",")))
	}
	return fmt.Sprintf("VERSION MISMATCH: %s", strings.Join(parts, "; "))
}

// checkCoherence cross-validates what each node claims against arbiter
// tokens and peer state.
func checkCoherence(nodes []nodeData, tokens map[string]tokenInfo) []string {
	var warnings []string

	// Build serving map: scope → list of roles claiming to serve it.
	servingMap := make(map[string][]string)
	for _, n := range nodes {
		if !n.Reachable || !isCoreRole(n.Status.Role) {
			continue
		}
		for _, sc := range n.Status.Serving {
			servingMap[sc] = append(servingMap[sc], n.Status.Role)
		}
	}

	// Check 1: dual-active — more than one core node serving the same scope.
	for sc, workers := range servingMap {
		if len(workers) > 1 {
			warnings = append(warnings, fmt.Sprintf("DUAL-ACTIVE: scope %s served by %s", sc, strings.Join(workers, " AND ")))
		}
	}

	// Check 2: serving without token — worker serves but arbiter has no matching token.
	for sc, workers := range servingMap {
		tok, hasTok := tokens[sc]
		if !hasTok {
			warnings = append(warnings, fmt.Sprintf("NO TOKEN: scope %s served by %s but no arbiter token exists", sc, workers[0]))
			continue
		}
		// Check token owner matches the serving worker's node_id.
		for _, n := range nodes {
			if !n.Reachable || n.Status.Role != workers[0] {
				continue
			}
			if tok.Owner != n.Status.NodeID {
				warnings = append(warnings, fmt.Sprintf("TOKEN MISMATCH: scope %s served by %s but token owned by %s", sc, n.Status.NodeID, tok.Owner))
			}
		}
	}

	// Check 3: token exists but nobody serves — orphan token.
	for sc, tok := range tokens {
		if _, served := servingMap[sc]; !served && !tok.Expired {
			warnings = append(warnings, fmt.Sprintf("UNSERVED: scope %s has active token (%s) but no core node is serving it", sc, tok.Owner))
		}
	}

	if w := versionMismatchWarning(nodes); w != "" {
		warnings = append(warnings, w)
	}

	// Check 5: epoch divergence — every core node should agree on epoch when
	// stable.
	epochsByValue := make(map[uint64][]string)
	allStable := true
	for _, n := range nodes {
		if n.Reachable && isCoreRole(n.Status.Role) {
			epochsByValue[n.Status.Epoch] = append(epochsByValue[n.Status.Epoch], n.Status.Role)
			if n.Status.State != "STABLE" {
				allStable = false
			}
		}
	}
	if allStable && len(epochsByValue) > 1 {
		var parts []string
		for epoch, roles := range epochsByValue {
			parts = append(parts, fmt.Sprintf("%s=%d", strings.Join(roles, "+"), epoch))
		}
		sort.Strings(parts)
		warnings = append(warnings, fmt.Sprintf("EPOCH DIVERGENCE: %s", strings.Join(parts, " vs ")))
	}

	// Check 6: clock skew — compare each node's server_time against local time.
	for _, n := range nodes {
		if !n.Reachable || n.Status.ServerTime == "" {
			continue
		}
		serverT, err := time.Parse(time.RFC3339, n.Status.ServerTime)
		if err != nil {
			continue
		}
		skew := time.Since(serverT)
		if skew < 0 {
			skew = -skew
		}
		if skew > 5*time.Second {
			warnings = append(warnings, fmt.Sprintf("CLOCK SKEW: %s is %.1fs off from this host", n.Status.NodeID, skew.Seconds()))
		}
	}

	// Check 7: partition — two nodes that BOTH answer -top, but one reports
	// the other unreachable on every path.
	seenPair := map[string]bool{}
	cannotSee := func(from, to nodeData) bool {
		for _, peer := range from.Status.PeersUnreachable {
			if peer == to.Addr {
				return from.Status.FallbackPeers[peer] == ""
			}
		}
		return false
	}
	for _, n := range nodes {
		if !n.Reachable || len(n.Status.PeersUnreachable) == 0 {
			continue
		}
		for _, other := range nodes {
			if !other.Reachable || other.Addr == n.Addr || !cannotSee(n, other) {
				continue
			}
			ids := []string{n.Status.NodeID, other.Status.NodeID}
			sort.Strings(ids)
			key := ids[0] + "|" + ids[1]
			if seenPair[key] {
				continue
			}
			seenPair[key] = true
			if cannotSee(other, n) {
				warnings = append(warnings, fmt.Sprintf("PARTITION: %s and %s cannot see each other (mgmt path down, no working fallback path confirmed; both answer this view)", ids[0], ids[1]))
			} else {
				warnings = append(warnings, fmt.Sprintf("PARTITION: %s cannot see %s, but %s can see it (both answer this view)", n.Status.NodeID, other.Status.NodeID, other.Status.NodeID))
			}
		}
	}

	for _, n := range nodes {
		if !n.Reachable {
			continue
		}
		for _, pw := range n.Status.PlaneWarnings {
			warnings = append(warnings, fmt.Sprintf("PLANE (%s): %s", n.role(), pw))
		}
	}

	return warnings
}

func (n nodeData) role() string {
	if n.Status != nil {
		return n.Status.Role
	}
	return ""
}

// isCoreRole reports whether role is one of the 3 real core roles.
func isCoreRole(role string) bool {
	switch role {
	case "core-1", "core-2", "core-3":
		return true
	default:
		return false
	}
}

// roleOrder gives the fixed display order for this project's three core
// roles.
func roleOrder(role string) int {
	switch role {
	case "core-1":
		return 0
	case "core-2":
		return 1
	case "core-3":
		return 2
	default:
		return 99
	}
}

// --- Terminal control ---

func clearScreen() { fmt.Print("\033[H\033[2J") }

func setRawMode() {
	exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "1", "-echo").Run()
}

func restoreMode() {
	exec.Command("stty", "-F", "/dev/tty", "sane").Run()
}

// Synthetic key codes outside the single-byte (0-255) range, for keys that
// arrive as multi-byte CSI escape sequences (see readKey).
const (
	keyPgUp = 0x100 + iota
	keyPgDn
	keyLeft
	keyRight
	keyUp
	keyDown
)

func readKey(ch chan int) {
	f, err := os.Open("/dev/tty")
	if err != nil {
		return
	}
	defer f.Close()
	fd := f.Fd()
	buf := make([]byte, 1)
	for {
		n, err := f.Read(buf)
		if err != nil || n == 0 {
			return
		}
		b := buf[0]
		if b != 27 {
			ch <- int(b)
			continue
		}

		// Possible start of a CSI escape sequence.
		time.Sleep(10 * time.Millisecond)
		if availableBytes(fd) < 2 {
			ch <- 27
			continue
		}
		head := make([]byte, 2)
		if _, err := io.ReadFull(f, head); err != nil {
			ch <- 27
			continue
		}
		if head[0] != '[' {
			continue // not a CSI sequence this UI recognizes at all
		}
		switch head[1] {
		case 'A':
			ch <- keyUp
			continue
		case 'B':
			ch <- keyDown
			continue
		case 'C':
			ch <- keyRight
			continue
		case 'D':
			ch <- keyLeft
			continue
		}
		time.Sleep(10 * time.Millisecond)
		if availableBytes(fd) < 1 {
			continue
		}
		tail := make([]byte, 1)
		if _, err := io.ReadFull(f, tail); err != nil {
			continue
		}
		switch {
		case head[1] == '5' && tail[0] == '~':
			ch <- keyPgUp
		case head[1] == '6' && tail[0] == '~':
			ch <- keyPgDn
			// else: unrecognized sequence, ignore silently.
		}
	}
}

const fionread = 0x541B

// availableBytes reports how many bytes can be read from fd without
// blocking (FIONREAD).
func availableBytes(fd uintptr) int {
	var n int
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, fionread, uintptr(unsafe.Pointer(&n)))
	if errno != 0 {
		return 0
	}
	return n
}

// --- Colors ---

// Bright (9x) ANSI variants throughout.
const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cDim    = "\033[2m"
	cGreen  = "\033[92m" // healthy/active/pass
	cYellow = "\033[93m" // attention needed — degraded, not critical
	cRed    = "\033[91m" // critical/down/fail — a real, deliberate red
	cCyan   = "\033[96m" // info/accent (tab highlight, etc.)
	cWhite  = "\033[97m" // neutral
	cNodeA  = "\033[31m" // core-1 identity marker (plain red)
	cNodeB  = "\033[34m" // core-2 identity marker (plain blue)
	cNodeC  = "\033[37m" // core-3 identity marker (plain white)
)

// bodyHeight is the fixed content height every view pads to, so the footer
// (menu) lands on the same row across refreshes and across view switches.
const bodyHeight = 24

func stateIcon(state string, reachable bool) string {
	if !reachable {
		return cRed + "✖" + cReset
	}
	if state == "STABLE" {
		return cGreen + "✔" + cReset
	}
	return cYellow + "⚠" + cReset
}

func nodeIdentityColor(role string) string {
	switch role {
	case "core-1":
		return cNodeA
	case "core-2":
		return cNodeB
	case "core-3":
		return cNodeC
	default:
		return cCyan
	}
}

// roleByNodeID builds a NodeID → Role lookup from the current node
// snapshot.
func roleByNodeID(nodes []nodeData) map[string]string {
	m := make(map[string]string, len(nodes))
	for _, n := range nodes {
		if n.Status != nil {
			m[n.Status.NodeID] = n.Status.Role
		}
	}
	return m
}

// levelColor maps an event's Level to the same traffic-light severity
// color in both Events and Logs.
func levelColor(level string) string {
	switch level {
	case "WARNING":
		return cYellow
	case "ERROR", "CRITICAL":
		return cRed
	case "INFO":
		return cCyan
	default:
		return cDim
	}
}

// stateColor implements the traffic-light convention: green=STABLE,
// yellow=any other reachable state (degraded/settling/etc.), red=down.
func stateColor(state string) string {
	switch state {
	case "STABLE":
		return cGreen
	case "UNREACHABLE":
		return cRed
	default:
		return cYellow
	}
}

// --- Rendering ---

type appState struct {
	view          int
	scopePage     int
	probePage     int    // separate from scopePage — Probes scrolls independently of Scopes
	daemonPage    int    // separate again — Daemons scrolls independently of Probes/Scopes
	logFilter     string // "all", "core-1", "core-2", "core-3"
	nodes         []nodeData
	tokens        map[string]tokenInfo
	coherence     []string // coherence warnings
	lastUpdate    time.Time
	selectedScope string   // non-empty → show authority drilldown
	entryAddrs    []string // multiple entry addresses

	// probeIssues: the crit/warn lines actually rendered on Overview, plus
	// confirmed/debounced token-mismatch lines.
	probeIssues []probeIssue
	// probeHostMismatchPrev holds the raw (undebounced) mismatch set from the
	// last probe-host sweep, kept only to debounce the NEXT one.
	probeHostMismatchPrev        map[string]bool
	probeHostConfirmedMismatches map[string]bool

	// settlingSince: when the cluster first entered "STABLE, but not every
	// configured scope is serving yet" (see bannerText's settlingTimeout).
	settlingSince time.Time

	// probeHostAddrs are the optional external dnshived-probe hosts (-probe-addr).
	probeHostAddrs []string
	// probeHostNames: addr -> operator-assigned friendly name (-probe-name
	// flag), positionally matched against probeHostAddrs.
	probeHostNames   map[string]string
	probeHosts       map[string]nodeStatus     // addr -> decoded /api/v1/status
	probeHostErrors  map[string]string         // addr -> fetch error, if any
	probeHostDaemons map[string][]daemonStatus // addr -> its own GET /api/v1/daemons
	probeHostSystem  map[string]systemInfo     // addr -> its own GET /api/v1/system

	// probeHostResults: addr -> scope -> its own GET /api/v1/probe/<scope>
	// result.
	probeHostResults map[string]map[string]probeResult

	// probeHostEvents: addr -> its own GET /api/v1/events.
	probeHostEvents map[string][]event
}

func renderHeader(s *appState) {
	clusterID := "unknown"
	ver := ""
	for _, n := range s.nodes {
		if n.Status != nil {
			clusterID = n.Status.ClusterID
			if ver == "" {
				ver = n.Status.Version
			}
		}
	}

	fmt.Printf("%sdnshived-top%s", cBold, cReset)
	now := time.Now().Format("15:04:05 MST")
	padding := 50 - len(clusterID) - len(ver) - len(now)
	if padding < 1 {
		padding = 1
	}
	fmt.Printf("%s%s • %s • %s\n", strings.Repeat(" ", padding), clusterID, ver, now)

	// Banner
	fmt.Println("═══════════════════════════════════════════════════════════")

	stable, reachable, total := 0, 0, len(s.nodes)
	configuredScopes := make(map[string]bool)
	servingScopes := make(map[string]bool)
	for _, n := range s.nodes {
		if n.Reachable {
			reachable++
			if n.Status.State == "STABLE" {
				stable++
			}
			if isCoreRole(n.Status.Role) {
				for _, sc := range n.Status.ConfiguredScopes {
					configuredScopes[sc] = true
				}
				for _, sc := range n.Status.Serving {
					servingScopes[sc] = true
				}
			}
		}
	}
	settlingNow := stable == total && len(configuredScopes) > 0 && len(servingScopes) < len(configuredScopes)
	if settlingNow {
		if s.settlingSince.IsZero() {
			s.settlingSince = time.Now()
		}
	} else {
		s.settlingSince = time.Time{}
	}
	var settlingElapsed time.Duration
	if !s.settlingSince.IsZero() {
		settlingElapsed = time.Since(s.settlingSince)
	}

	text, color := bannerText(stable, reachable, total, len(configuredScopes), len(servingScopes), settlingElapsed)
	fmt.Printf("  %s%s%s\n", color, text, cReset)

	fmt.Println("═══════════════════════════════════════════════════════════")
}

// settlingTimeout bounds how long bannerText will call the cluster GETTING
// THERE before treating it as actually stuck.
const settlingTimeout = 90 * time.Second

// bannerText picks the top banner's text and color.
func bannerText(stable, reachable, total, configuredCount, servingCount int, settlingElapsed time.Duration) (text, color string) {
	settlingScopes := configuredCount > 0 && servingCount < configuredCount

	switch {
	case stable == total && settlingScopes && settlingElapsed > settlingTimeout:
		return fmt.Sprintf("✖  NOT CONVERGING — stable but scopes still not serving after %ds", int(settlingElapsed.Seconds())), cRed
	case stable == total && settlingScopes:
		return "⏳ GETTING THERE — cluster stable, scopes still starting", cYellow
	case stable == total:
		return "✔  PRODUCTION ACTIVE", cGreen
	case reachable < total:
		return "✖  NODE DOWN", cRed
	default:
		return "⚠  DEGRADED", cYellow
	}
}

func renderTabs(view int) {
	tabs := []string{"Overview", "Scopes", "Probes", "Daemons", "Logs"}
	for i, t := range tabs {
		if i+1 == view {
			fmt.Printf("  %s[%d] %s%s", cBold+cCyan, i+1, t, cReset)
		} else {
			fmt.Printf("  %s[%d] %s%s", cDim, i+1, t, cReset)
		}
	}
	fmt.Printf("  %s[q] quit%s\n\n", cDim, cReset)
}

func renderOverview(s *appState) {
	stable, reachable := 0, 0
	totalServing := 0
	configuredScopes := make(map[string]bool)
	disabledScopes := disabledScopeSet(s.nodes)
	var warnings []string
	for _, n := range s.nodes {
		if n.Reachable {
			reachable++
			if n.Status.State == "STABLE" {
				stable++
			}
			if isCoreRole(n.Status.Role) {
				for _, sc := range n.Status.Serving {
					if !disabledScopes[sc] {
						totalServing++
					}
				}
				for _, sc := range n.Status.ConfiguredScopes {
					if !disabledScopes[sc] {
						configuredScopes[sc] = true
					}
				}
			}
		} else {
			warnings = append(warnings, n.Addr+" unreachable")
		}
	}

	lines := 0

	// Cluster health summary.
	overallState := "STABLE"
	if stable != len(s.nodes) {
		overallState = "DEGRADED"
	}
	fmt.Printf("  %sCluster%s\n", cBold, cReset)
	fmt.Printf("  ──────────────────────────────────────\n")
	fmt.Printf("  State:       %s%s%s\n", stateColor(overallState), overallState, cReset)
	if overallState == "STABLE" {
		if since, ok := clusterStableSince(s.nodes); ok {
			fmt.Printf("  Stable since:%s%s%s (%s ago)\n", cDim, since.Local().Format("15:04:05"), cReset, formatDuration(time.Since(since)))
		}
	}

	// Node IDs — internal/protocol reference only, not a primary display
	// field.
	var idParts []string
	for _, n := range s.nodes {
		if n.Reachable {
			idParts = append(idParts, n.role()+"="+n.Status.NodeID)
		}
	}
	fmt.Printf("  %sNode IDs:    %s%s\n", cDim, strings.Join(idParts, "  "), cReset)

	tokenHealth := "healthy"
	expiredCount := 0
	activeCount := 0
	for _, t := range s.tokens {
		if t.Expired {
			expiredCount++
		} else {
			activeCount++
		}
	}
	if expiredCount > 0 {
		tokenHealth = fmt.Sprintf("%d expired", expiredCount)
	}
	fmt.Printf("  Witness:     %s\n", tokenHealth)
	servingColor := cGreen
	if len(configuredScopes) > 0 && totalServing < len(configuredScopes) {
		servingColor = cYellow
	}
	disabledNote := ""
	if len(disabledScopes) > 0 {
		disabledNote = fmt.Sprintf(", %s%d disabled%s", cYellow, len(disabledScopes), cReset)
	}
	fmt.Printf("  Serving:     %s%d of %d scope(s)%s%s\n", servingColor, totalServing, len(configuredScopes), cReset, disabledNote)
	if len(warnings) > 0 {
		fmt.Printf("  Warnings:    %s%d%s\n", cYellow, len(warnings), cReset)
	} else {
		fmt.Printf("  Warnings:    none\n")
	}
	probeIssues := s.probeIssues
	if len(probeIssues) > 0 {
		fmt.Printf("  Probes:      %s%d issue(s) — see below%s\n", cRed, len(probeIssues), cReset)
	} else {
		fmt.Printf("  Probes:      all healthy\n")
	}
	if scopesMismatch(s.nodes) {
		fmt.Printf("  Config:      %sscopes_hash differs between nodes — not identical%s\n", cRed, cReset)
	} else {
		fmt.Printf("  Config:      OK\n")
	}
	pathTotal, pathDown, pathMinScore := 0, 0, 101
	for _, n := range s.nodes {
		if !n.Reachable {
			continue
		}
		for _, p := range n.Status.Paths {
			pathTotal++
			if !p.Reachable {
				pathDown++
			}
			if p.Score < pathMinScore {
				pathMinScore = p.Score
			}
		}
	}
	if pathTotal > 0 {
		if pathDown > 0 {
			fmt.Printf("  Paths:       %s%d/%d down%s %s(min trust %d%%)%s\n", cYellow, pathDown, pathTotal, cReset, cDim, pathMinScore, cReset)
		} else {
			fmt.Printf("  Paths:       %sall reachable (%d)%s %s(min trust %d%%)%s\n", cGreen, pathTotal, cReset, cDim, pathMinScore, cReset)
		}
		lines++
	}
	lines += 9

	// Cluster nodes — show counts, not scope lists.
	fmt.Printf("\n  %sCluster nodes%s\n", cBold, cReset)
	fmt.Printf("  ──────────────────────────────────────\n")
	lines += 3
	for _, n := range s.nodes {
		if !n.Reachable {
			fmt.Printf("  %s %-10s %-22s %sDOWN%s\n",
				stateIcon("", false), "", n.Addr, cRed, cReset)
			lines++
			continue
		}
		active, off := 0, 0
		for _, sc := range n.Status.Serving {
			if disabledScopes[sc] {
				off++
			} else {
				active++
			}
		}
		info := fmt.Sprintf("%d scope(s)", active)
		if off > 0 {
			info += fmt.Sprintf(", %d disabled", off)
		}
		sysStr := ""
		if n.System != nil {
			sysStr = fmt.Sprintf(" %sload %.2f  mem %d%%%s",
				cDim, n.System.LoadAvg1, n.System.MemPct, cReset)
		}
		mode := ""
		if n.ViaFallback {
			mode += cYellow + " [mgmt path down — via fallback]" + cReset
		}
		fmt.Printf("  %s %-10s %-22s %-14s%s%s\n",
			stateIcon(n.Status.State, true), n.Status.Role, n.Addr,
			info, sysStr, mode)
		lines++
	}

	if len(s.probeHostAddrs) > 0 {
		fmt.Printf("  ──────────────────────────────────────\n")
		lines++
		for _, addr := range s.probeHostAddrs {
			name := probeHostLabel(s, addr)
			if _, bad := s.probeHostErrors[addr]; bad {
				fmt.Printf("  %s %-10s %-22s %sDOWN%s\n", stateIcon("", false), name, addr, cRed, cReset)
				lines++
				continue
			}
			st, ok := s.probeHosts[addr]
			if !ok {
				fmt.Printf("  %s %-10s %-22s %swaiting for first sweep...%s\n",
					stateIcon("", false), name, addr, cDim, cReset)
				lines++
				continue
			}
			sysStr := ""
			if sys, ok := s.probeHostSystem[addr]; ok {
				sysStr = fmt.Sprintf(" %sload %.2f  mem %d%%%s", cDim, sys.LoadAvg1, sys.MemPct, cReset)
			}
			fmt.Printf("  %s %-10s %-22s %sRUNNING%s  %-14s%s\n",
				stateIcon("STABLE", true), name, addr, cGreen, cReset,
				fmt.Sprintf("%d scope(s)", len(st.ConfiguredScopes)), sysStr)
			lines++
		}
	}

	// Tokens — summary only, not per-scope list.
	fmt.Printf("\n  %sTokens%s: %d active, %d expired\n", cBold, cReset, activeCount, expiredCount)
	lines += 2

	if len(probeIssues) > 0 {
		fmt.Printf("\n  %sProbe issues%s\n", cBold, cReset)
		fmt.Printf("  ──────────────────────────────────────\n")
		shown := 0
		for _, iss := range probeIssues {
			if shown >= 3 {
				fmt.Printf("  %s... and %d more%s\n", cDim, len(probeIssues)-3, cReset)
				lines++
				break
			}
			fmt.Printf("  %s✖ %s%s\n", iss.Color, iss.Text, cReset)
			shown++
			lines++
		}
		lines += 2
	}

	if len(s.coherence) > 0 {
		fmt.Printf("\n  %sCoherence%s\n", cBold, cReset)
		fmt.Printf("  ──────────────────────────────────────\n")
		shown := 0
		for _, c := range s.coherence {
			if shown >= 3 {
				fmt.Printf("  %s... and %d more%s\n", cDim, len(s.coherence)-3, cReset)
				lines++
				break
			}
			fmt.Printf("  %s✖ %s%s\n", cRed, c, cReset)
			shown++
			lines++
		}
		lines += 2
	}

	// Pad to fixed content height so every view's footer lands on the
	// same row — see bodyHeight.
	for lines < bodyHeight {
		fmt.Println()
		lines++
	}
}

func renderScopes(s *appState) {
	// If a scope is selected, show authority drilldown.
	if s.selectedScope != "" {
		renderAuthority(s)
		return
	}

	type scopeInfo struct {
		name   string
		worker string
		token  string
		status string
	}
	var scopes []scopeInfo
	iotSet := iotScopeSet(s.nodes)
	disabledSet := disabledScopeSet(s.nodes)
	roles := roleByNodeID(s.nodes)

	for _, n := range s.nodes {
		if !n.Reachable || !isCoreRole(n.Status.Role) {
			continue
		}
		for _, sc := range n.Status.Serving {
			tok := "—"
			status := cGreen + "active" + cReset
			if t, ok := s.tokens[sc]; ok {
				tok = t.Owner
				if role, ok := roles[t.Owner]; ok {
					tok = role
				}
				if t.Expired {
					status = cRed + "EXPIRED" + cReset
				}
			}
			if disabledSet[sc] {
				status = cYellow + "disabled" + cReset
			}
			scopes = append(scopes, scopeInfo{name: scopeDisplayName(sc, iotSet[sc]), worker: n.Status.Role, token: tok, status: status})
		}
	}
	sort.Slice(scopes, func(i, j int) bool { return scopes[i].name < scopes[j].name })

	perPage := 15
	totalPages := (len(scopes) + perPage - 1) / perPage
	if totalPages == 0 {
		totalPages = 1
	}
	if s.scopePage >= totalPages {
		s.scopePage = totalPages - 1
	}

	start := s.scopePage * perPage
	end := start + perPage
	if end > len(scopes) {
		end = len(scopes)
	}

	fmt.Printf("  Scopes (%d total)  %spage %d/%d  [n]ext [p]rev  [Enter scope name]%s\n\n",
		len(scopes), cDim, s.scopePage+1, totalPages, cReset)

	fmt.Printf("  %-16s %-12s %-18s %s\n",
		cDim+"scope", "worker", "token owner", "status"+cReset)
	fmt.Printf("  %s\n", strings.Repeat("─", 54))

	for _, sc := range scopes[start:end] {
		fmt.Printf("  %-16s %-12s %-18s %s\n", sc.name, sc.worker, sc.token, sc.status)
	}

	if len(scopes) == 0 {
		fmt.Printf("  %s(no scopes currently served)%s\n", cDim, cReset)
	}

	// Pad to fixed content height.
	shown := end - start
	if shown < 0 {
		shown = 0
	}
	for i := shown; i < bodyHeight; i++ {
		fmt.Println()
	}
}

func renderAuthority(s *appState) {
	fmt.Printf("  %s← [Esc] back to scopes%s\n\n", cDim, cReset)

	type checkResult struct {
		Name   string `json:"name"`
		Pass   bool   `json:"pass"`
		Detail string `json:"detail"`
	}
	type authCheck struct {
		Scope         string        `json:"scope"`
		Allowed       bool          `json:"allowed"`
		Serving       bool          `json:"serving"`
		Decision      string        `json:"decision"`
		Reason        string        `json:"reason"`
		PrimaryReason string        `json:"primary_reason"`
		EvaluatedAt   string        `json:"evaluated_at"`
		Checks        []checkResult `json:"checks"`
	}

	// Find which node serves this scope.
	targetAddr, targetRole := "", ""
	for _, n := range s.nodes {
		if !n.Reachable || !isCoreRole(n.Status.Role) {
			continue
		}
		for _, sc := range n.Status.Serving {
			if sc == s.selectedScope {
				targetAddr, targetRole = n.Addr, n.Status.Role
				break
			}
		}
		if targetAddr != "" {
			break
		}
	}
	if targetAddr == "" {
		for _, n := range s.nodes {
			if n.Reachable && isCoreRole(n.Status.Role) {
				targetAddr, targetRole = n.Addr, n.Status.Role
				break
			}
		}
	}

	if targetAddr == "" {
		fmt.Printf("  %sNo reachable worker to query%s\n", cYellow, cReset)
		return
	}

	var ac authCheck
	err := fetchJSON(scheme+"://"+targetAddr+"/api/v1/authority/"+s.selectedScope, &ac)
	if err != nil {
		fmt.Printf("  %sCannot fetch authority: %v%s\n", cYellow, err, cReset)
		return
	}

	serving := cGreen + "SERVING" + cReset
	if !ac.Serving {
		serving = cDim + "STOPPED" + cReset
	}

	fmt.Printf("  %sScope: %s%s                    %s\n", cBold, s.selectedScope, cReset, serving)
	fmt.Printf("  %sQueried from: %s%s (every \"this node\" below refers to it)\n", cDim, targetRole, cReset)
	fmt.Printf("  ─────────────────────────────────────────\n")

	for _, c := range ac.Checks {
		icon := cGreen + "✔" + cReset
		if !c.Pass {
			icon = cRed + "✖" + cReset
		}
		fmt.Printf("  %s %-14s %s\n", icon, c.Name, c.Detail)
	}

	fmt.Printf("  ─────────────────────────────────────────\n")
	decColor := cGreen
	if ac.Decision != "SERVE" {
		decColor = cYellow
	}
	fmt.Printf("  Decision: %s%s%s\n", decColor+cBold, ac.Decision, cReset)
	if ac.PrimaryReason != "" {
		fmt.Printf("  Reason:   %s%s%s (%s)\n", cYellow, ac.PrimaryReason, cReset, ac.Reason)
	} else {
		fmt.Printf("  Reason:   %s\n", ac.Reason)
	}
}

// probeCell classifies one probe result as a single text and color.
func probeCell(pr probeResult, have bool) (text, color string) {
	if !have {
		return "pending...", cDim
	}
	if !pr.Enabled && pr.DHCP.Error == "" && pr.DNS.Error == "" {
		return "probe off", cDim
	}

	dnsOK := pr.DNS.Error == "" && pr.DNS.Answered
	dnsUnknown := pr.DNS.Error != ""
	dhcpOK := pr.DHCP.Error == "" && pr.DHCP.Verdict == "ok"
	dhcpDual := pr.DHCP.Error == "" && pr.DHCP.Verdict == "dual_active"
	dhcpNoAnswer := pr.DHCP.Error == "" && pr.DHCP.Verdict == "no_answer"
	dhcpUnknown := pr.DHCP.Error != ""

	dnsText := "DNS✖"
	if dnsUnknown {
		dnsText = "DNS?"
	} else if dnsOK {
		dnsText = "DNS✔"
	}
	dhcpText := "DHCP✖"
	switch {
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
		return text, cRed // dual-active — two servers answering
	case dhcpNoAnswer:
		return text, cRed
	case dnsUnknown || dhcpUnknown:
		return text, cDim
	case dnsOK && dhcpOK:
		return text, cGreen
	default:
		return text, cYellow
	}
}

// probeCellParts is probeCell's per-leg equivalent, used ONLY for the
// Probes-tab grid cell.
func probeCellParts(pr probeResult, have bool, mismatch bool) (dnsText, dnsColor, dhcpText, dhcpColor string) {
	if !have {
		return "pending...", cDim, "", ""
	}
	if !pr.Enabled && pr.DHCP.Error == "" && pr.DNS.Error == "" {
		return "probe off", cDim, "", ""
	}

	dnsOK := pr.DNS.Error == "" && pr.DNS.Answered
	dnsUnknown := pr.DNS.Error != ""
	dhcpOK := pr.DHCP.Error == "" && pr.DHCP.Verdict == "ok"
	dhcpDual := pr.DHCP.Error == "" && pr.DHCP.Verdict == "dual_active"
	dhcpNoAnswer := pr.DHCP.Error == "" && pr.DHCP.Verdict == "no_answer"
	dhcpUnknown := pr.DHCP.Error != ""

	switch {
	case dnsUnknown:
		dnsText, dnsColor = "DNS?", cDim
	case dnsOK:
		dnsText, dnsColor = "DNS✔", cGreen
	default:
		dnsText, dnsColor = "DNS✖", cRed
	}

	switch {
	case dhcpUnknown:
		dhcpText, dhcpColor = "DHCP?", cDim
	case dhcpOK:
		dhcpText, dhcpColor = "DHCP✔", cGreen
		if mismatch {
			dhcpColor = cYellow
		}
	case dhcpDual:
		dhcpText, dhcpColor = "DHCP✖DUAL", cRed
	case dhcpNoAnswer:
		dhcpText, dhcpColor = "DHCP-NONE", cRed
	default:
		dhcpText, dhcpColor = "DHCP✖", cRed
	}
	return
}

// renderProbeCell composes probeCellParts' two independently-colored legs
// into one fixed-width cell string, ready to drop straight into a %s verb.
func renderProbeCell(pr probeResult, have bool, width int, mismatch bool) string {
	dnsText, dnsColor, dhcpText, dhcpColor := probeCellParts(pr, have, mismatch)
	plain := dnsText
	colored := dnsColor + dnsText + cReset
	if dhcpText != "" {
		plain += " " + dhcpText
		colored += " " + dhcpColor + dhcpText + cReset
	}
	if pad := width - utf8.RuneCountInString(plain); pad > 0 {
		colored += strings.Repeat(" ", pad)
	}
	return colored
}

func probeIssueText(pr probeResult) string {
	full, _ := probeCell(pr, true)
	dnsOK := pr.DNS.Error == "" && pr.DNS.Answered
	text := full
	if dnsOK {
		// DNS is fine — the DHCP half is everything after the first space.
		if idx := strings.IndexByte(full, ' '); idx >= 0 {
			text = full[idx+1:]
		}
	}
	return text + probeReasonSuffix(pr, dnsOK)
}

// probeReasonSuffix appends the actual diagnostic text behind a failure.
func probeReasonSuffix(pr probeResult, dnsOK bool) string {
	var parts []string
	if !dnsOK && pr.DNS.Error != "" {
		parts = append(parts, "DNS: "+pr.DNS.Error)
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

type probeIssue struct {
	Text  string
	Color string
}

// ownerDaemonUptime fetches every node's own dnshived.service uptime
// (seconds), keyed by node_id.
func ownerDaemonUptime(nodes []nodeData) map[string]int64 {
	uptime := make(map[string]int64)
	for _, n := range nodes {
		if !n.Reachable || n.Status == nil {
			continue
		}
		for _, d := range n.Daemons {
			if d.Unit == "dnshived.service" && d.Error == "" {
				uptime[n.Status.NodeID] = d.UptimeSec
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

func checkProbeHostIssues(probeHostResults map[string]map[string]probeResult, addrs []string, names map[string]string, tokens map[string]tokenInfo, ownerUptime map[string]int64, serving map[string]bool) (issues []probeIssue, mismatches map[string]bool) {
	mismatches = make(map[string]bool)
	now := time.Now()
	for _, addr := range addrs {
		var scopes []string
		for sc := range probeHostResults[addr] {
			scopes = append(scopes, sc)
		}
		sort.Strings(scopes)
		label := names[addr]
		if label == "" {
			label = probeHostShortLabel(addr)
		}
		for _, sc := range scopes {
			pr := probeHostResults[addr][sc]
			if tok, ok := tokens[sc]; ok {
				uptimeSec, hasUptime := ownerUptime[tok.Owner]
				probedAt, _ := time.Parse(time.RFC3339, pr.ProbedAt)
				if probeStale(probedAt, uptimeSec, hasUptime, now) {
					continue // predates the current owner's daemon restart
				}
			}
			_, color := probeCell(pr, true)
			if serving[sc] && (color == cRed || color == cYellow) {
				issues = append(issues, probeIssue{
					Text:  fmt.Sprintf("%s (from %s): %s", sc, label, probeIssueText(pr)),
					Color: color,
				})
			}

			if color != cDim {
				dhcpAnswering := pr.DHCP.Error == "" && (pr.DHCP.Verdict == "ok" || pr.DHCP.Verdict == "dual_active")
				tok, hasToken := tokens[sc]
				tokenValid := hasToken && !tok.Expired
				if dhcpAnswering && !tokenValid {
					mismatches[sc+"|"+label] = true
				}
			}
		}
	}
	return issues, mismatches
}

func confirmProbeMismatches(mismatches, prev map[string]bool) (lines []probeIssue, confirmed map[string]bool) {
	confirmed = make(map[string]bool)
	for key := range mismatches {
		if prev[key] {
			sc, w, _ := strings.Cut(key, "|")
			lines = append(lines, probeIssue{
				Text:  fmt.Sprintf("%s (from %s): DHCP is being answered but no valid arbiter token authorizes this scope", sc, w),
				Color: cYellow,
			})
			confirmed[key] = true
		}
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i].Text < lines[j].Text })
	return lines, confirmed
}

// probeAge renders a dim "(Ns ago)" suffix for a probe cell, parsed from
// the result's own server-set ProbedAt.
func probeAge(pr probeResult, have bool) string {
	if !have || !pr.Enabled || pr.ProbedAt == "" {
		return ""
	}
	probedAt, err := time.Parse(time.RFC3339, pr.ProbedAt)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%ds ago", int(time.Since(probedAt).Seconds()))
}

// probeAgeDisplay renders probeAge's plain text as a fixed-width, colored
// field.
func probeAgeDisplay(pr probeResult, have bool) string {
	age := probeAge(pr, have)
	if age != "" {
		age = "(" + age + ")"
	}
	return fmt.Sprintf("%s%-11s%s", cDim, age, cReset)
}

// renderProbes is entirely external-probe-host-driven.
func renderProbes(s *appState) {
	if len(s.probeHostAddrs) == 0 {
		fmt.Printf("  %sNo probe host configured.%s\n", cDim, cReset)
		for i := 1; i < bodyHeight; i++ {
			fmt.Println()
		}
		return
	}

	var scopeNames []string
	seen := make(map[string]bool)
	for _, n := range s.nodes {
		if !n.Reachable || !isCoreRole(n.Status.Role) {
			continue
		}
		for _, sc := range n.Status.ConfiguredScopes {
			if !seen[sc] {
				seen[sc] = true
				scopeNames = append(scopeNames, sc)
			}
		}
	}
	sort.Strings(scopeNames)

	perPage := 15
	totalPages := (len(scopeNames) + perPage - 1) / perPage
	if totalPages == 0 {
		totalPages = 1
	}
	if s.probePage >= totalPages {
		s.probePage = totalPages - 1
	}
	start := s.probePage * perPage
	end := start + perPage
	if end > len(scopeNames) {
		end = len(scopeNames)
	}

	fmt.Printf("  Probes (%d scope(s), %d error(s))  %spage %d/%d  [PgDn/PgUp] scroll%s\n\n",
		len(scopeNames), len(s.probeIssues), cDim, s.probePage+1, totalPages, cReset)
	const (
		textWidth = 20
		ageWidth  = 11
		colWidth  = textWidth + 1 + ageWidth
	)
	header := fmt.Sprintf("  %s%-16s", cDim, "scope")
	ruleWidth := 16
	for _, addr := range s.probeHostAddrs {
		header += fmt.Sprintf(" %-*s", colWidth, "from "+probeHostLabel(s, addr))
		ruleWidth += 1 + colWidth
	}
	fmt.Println(header + cReset)
	fmt.Printf("  %s\n", strings.Repeat("─", ruleWidth))

	iotSet := iotScopeSet(s.nodes)
	disabledSet := disabledScopeSet(s.nodes)
	ownerUptime := ownerDaemonUptime(s.nodes)
	renderNow := time.Now()
	lines := 3
	for _, sc := range scopeNames[start:end] {
		row := fmt.Sprintf("  %-16s", scopeDisplayName(sc, iotSet[sc]))
		for _, addr := range s.probeHostAddrs {
			if disabledSet[sc] {
				row += " " + cYellow + "scope disabled" + cReset + strings.Repeat(" ", textWidth-len("scope disabled")+1+ageWidth)
				continue
			}
			result, have := s.probeHostResults[addr][sc]
			label := probeHostLabel(s, addr)
			mismatch := s.probeHostConfirmedMismatches[sc+"|"+label]
			if have {
				if tok, ok := s.tokens[sc]; ok {
					uptimeSec, hasUptime := ownerUptime[tok.Owner]
					probedAt, _ := time.Parse(time.RFC3339, result.ProbedAt)
					if probeStale(probedAt, uptimeSec, hasUptime, renderNow) {
						result, have = probeResult{}, false
					}
				}
			}
			row += fmt.Sprintf(" %s %s", renderProbeCell(result, have, textWidth, mismatch), probeAgeDisplay(result, have))
		}
		fmt.Println(row)
		lines++
	}
	if len(scopeNames) == 0 {
		fmt.Printf("  %s(no scopes configured)%s\n", cDim, cReset)
		lines++
	}

	for i := lines; i < bodyHeight; i++ {
		fmt.Println()
	}
}

func probeHostShortLabel(addr string) string {
	if i := strings.LastIndex(addr, ":"); i > 0 {
		return addr[:i]
	}
	return addr
}

// probeHostLabel prefers an operator-assigned name (-probe-name) over the
// bare address.
func probeHostLabel(s *appState, addr string) string {
	if name := s.probeHostNames[addr]; name != "" {
		return name
	}
	return probeHostShortLabel(addr)
}

// daemonCell picks one unit's display text and color.
func daemonCell(d daemonStatus) (text, color string) {
	if d.Error != "" {
		return "unknown", cDim
	}
	if d.LoadState == "not-found" {
		return "not installed", cDim
	}
	if d.TotalCount == 0 && d.ActiveState != "active" && (d.Unit == "dhcp-relay" || d.Unit == "dnshived-relay.service" || d.Unit == "dnshived-dnsrelay.service") {
		return "no scope eligible yet", cDim
	}
	if d.TotalCount > 0 && (d.Unit == "dnsmasq" || d.Unit == "dhcp-relay") {
		text = fmt.Sprintf("%d/%d active", d.ActiveCount, d.TotalCount)
		if d.ActiveCount == d.TotalCount {
			return text, cGreen
		}
		return text, cRed
	}
	text = d.ActiveState
	if d.SubState != "" && d.SubState != d.ActiveState {
		text = d.ActiveState + "/" + d.SubState
	}
	switch d.ActiveState {
	case "active":
		return text, cGreen
	case "activating", "reloading", "deactivating":
		return text, cYellow
	default:
		return text, cRed
	}
}

// runningAsText mirrors cmd/dnshived-web's own identical helper.
func runningAsText(pid int64, user string) string {
	if pid == 0 {
		return "—"
	}
	if user == "" {
		return "unknown"
	}
	return user
}

// isDnsmasqScopeUnit mirrors cmd/dnshived-web's own identical helper —
// reports whether unit is one specific scope's own
// dnshived-dnsmasq@<scope>.service.
func isDnsmasqScopeUnit(unit string) bool {
	if unit == "dnshived-dnsmasq@core-dns.service" || unit == "dnshived-dnsmasq@core-dhcp.service" {
		// Reserved instance names under the same @template a real scope's
		// own dnsmasq uses — see cmd/dnshived-web's identical exclusion.
		return false
	}
	return strings.HasPrefix(unit, "dnshived-dnsmasq@") && strings.HasSuffix(unit, ".service")
}

// isRelayClientEntry mirrors cmd/dnshived-web's own identical helper.
func isRelayClientEntry(unit string) bool {
	return strings.HasPrefix(unit, "dhcp-relay: ")
}

// formatUptime renders a duration the way `uptime`/`ps` conventionally do.
func clusterStableSince(nodes []nodeData) (time.Time, bool) {
	var latest time.Time
	for _, n := range nodes {
		if !n.Reachable {
			return time.Time{}, false
		}
		t, err := time.Parse(time.RFC3339, n.Status.StateSince)
		if err != nil {
			return time.Time{}, false
		}
		if t.After(latest) {
			latest = t
		}
	}
	if latest.IsZero() {
		return time.Time{}, false
	}
	return latest, true
}

// formatDuration renders elapsed time precise to the second (HH:MM:SS, or
// "Nd HH:MM:SS" past 24h).
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	total := int64(d.Seconds())
	days := total / 86400
	hours := (total % 86400) / 3600
	mins := (total % 3600) / 60
	secs := total % 60
	if days > 0 {
		return fmt.Sprintf("%dd %02d:%02d:%02d", days, hours, mins, secs)
	}
	return fmt.Sprintf("%02d:%02d:%02d", hours, mins, secs)
}

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

// daemonRow is one flattened (node, unit) line for the Daemons view's
// table.
type daemonRow struct {
	Node      string
	Unit      string
	Text      string
	Color     string
	Uptime    int64
	Version   string
	PID       int64
	RunningAs string
}

func renderDaemons(s *appState) {
	var rows []daemonRow
	for _, n := range s.nodes {
		if !n.Reachable {
			continue
		}
		for _, d := range n.Daemons {
			if isDnsmasqScopeUnit(d.Unit) || isRelayClientEntry(d.Unit) {
				continue
			}
			text, color := daemonCell(d)
			rows = append(rows, daemonRow{
				Node: n.role(), Unit: d.Unit, Text: text, Color: color,
				Uptime: d.UptimeSec, Version: d.Version,
				PID: int64(d.PID), RunningAs: runningAsText(int64(d.PID), d.User),
			})
		}
	}
	for _, addr := range s.probeHostAddrs {
		label := probeHostLabel(s, addr)
		for _, d := range s.probeHostDaemons[addr] {
			text, color := daemonCell(d)
			rows = append(rows, daemonRow{
				Node: label, Unit: d.Unit, Text: text, Color: color,
				Uptime: d.UptimeSec, Version: d.Version,
				PID: int64(d.PID), RunningAs: runningAsText(int64(d.PID), d.User),
			})
		}
	}

	const daemonsPerPage = 30
	perPage := daemonsPerPage
	totalPages := (len(rows) + perPage - 1) / perPage
	if totalPages == 0 {
		totalPages = 1
	}
	if s.daemonPage >= totalPages {
		s.daemonPage = totalPages - 1
	}
	start := s.daemonPage * perPage
	end := start + perPage
	if end > len(rows) {
		end = len(rows)
	}

	fmt.Printf("  Daemons (%d unit(s))  %spage %d/%d  [PgDn/PgUp] scroll%s\n\n",
		len(rows), cDim, s.daemonPage+1, totalPages, cReset)
	fmt.Printf("  %s%-18s %-38s %-16s %-8s %-24s %-12s %-8s%s\n",
		cDim, "node", "unit", "state", "uptime", "version", "running as", "pid", cReset)
	fmt.Printf("  %s\n", strings.Repeat("─", 130))

	lines := 3
	for _, r := range rows[start:end] {
		pidText := "—"
		if r.PID != 0 {
			pidText = strconv.FormatInt(r.PID, 10)
		}
		runningAsColor := cReset
		if r.RunningAs == "root" {
			runningAsColor = cYellow
		}
		fmt.Printf("  %s%-18s%s %-38s %s%-16s%s %-8s %-24s %s%-12s%s %-8s\n",
			nodeIdentityColor(r.Node), r.Node, cReset, r.Unit, r.Color, r.Text, cReset,
			formatUptime(r.Uptime), r.Version, runningAsColor, r.RunningAs, cReset, pidText)
		lines++
	}
	if len(rows) == 0 {
		fmt.Printf("  %s(no daemon data yet)%s\n", cDim, cReset)
		lines++
	}

	for i := lines; i < bodyHeight; i++ {
		fmt.Println()
	}
}

type logLine struct {
	event
	Label string
	Role  string // for filtering: a real node's role, or a probe host's short label
}

// logFilterOptions is the Logs page's node filter, cycled by the
// Left/Right arrow keys (see the keyLeft/keyRight case in the run loop).
var logFilterOptions = []string{"all", "core-1", "core-2", "core-3"}

// cycleLogFilter returns the next (forward=true) or previous
// (forward=false) entry in logFilterOptions after current, wrapping around
// at either end.
func cycleLogFilter(current string, forward bool) string {
	idx := 0
	for i, f := range logFilterOptions {
		if f == current {
			idx = i
			break
		}
	}
	if forward {
		idx = (idx + 1) % len(logFilterOptions)
	} else {
		idx = (idx - 1 + len(logFilterOptions)) % len(logFilterOptions)
	}
	return logFilterOptions[idx]
}

func renderLogs(s *appState) {
	fmt.Printf("  Node filter: ")
	for _, f := range logFilterOptions {
		if f == s.logFilter {
			fmt.Printf(" %s[%s]%s", cBold+cCyan, f, cReset)
		} else {
			fmt.Printf(" %s%s%s", cDim, f, cReset)
		}
	}
	fmt.Printf("  %s[a]All  [←→]Cycle filter%s\n\n", cDim, cReset)

	roles := roleByNodeID(s.nodes)

	var all []logLine
	for _, n := range s.nodes {
		for _, e := range n.Events {
			role := roles[e.NodeID]
			if role == "" {
				role = e.NodeID // fallback: role couldn't be resolved (e.g. node currently unreachable)
			}
			if s.logFilter == "all" || role == s.logFilter {
				all = append(all, logLine{event: e, Label: role, Role: role})
			}
		}
	}
	for _, addr := range s.probeHostAddrs {
		label := probeHostLabel(s, addr)
		for _, e := range s.probeHostEvents[addr] {
			if s.logFilter == "all" || label == s.logFilter {
				all = append(all, logLine{event: e, Label: label, Role: label})
			}
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Timestamp.After(all[j].Timestamp) })

	shown := 0
	for _, l := range all {
		if shown >= 25 {
			break
		}
		ts := l.Timestamp.Local().Format("01-02 15:04:05")
		fmt.Printf("  %s%s%s %s[%-9s]%s %s[%s]%s %s\n",
			cDim, ts, cReset,
			nodeIdentityColor(l.Label), l.Label, cReset,
			levelColor(l.Level), l.Prefix, cReset,
			l.Message)
		shown++
	}
	if shown == 0 {
		fmt.Printf("  %s(no events yet)%s\n", cDim, cReset)
	}

	// Pad to fixed content height.
	for i := shown; i < bodyHeight; i++ {
		fmt.Println()
	}
}

func renderFooter(s *appState) {
	fmt.Println()
	switch {
	case s.view == 2 && s.selectedScope != "":
		fmt.Printf("  %s[Esc]Back  [q]Quit%s\n", cDim, cReset)
	case s.view == 2:
		fmt.Printf("  %s[1-5]Views  [n]Next  [p]Prev  [o]Office  [d]Dante  [w]Cycle scope  [q]Quit%s\n", cDim, cReset)
	case s.view == 3:
		fmt.Printf("  %s[1-5]Views  [PgDn/PgUp]Scroll  [q]Quit%s\n", cDim, cReset)
	case s.view == 4:
		fmt.Printf("  %s[1-5]Views  [PgDn/PgUp]Scroll  [q]Quit%s\n", cDim, cReset)
	case s.view == 5:
		fmt.Printf("  %s[1-5]Views  [←→]Filter node  [q]Quit%s\n", cDim, cReset)
	default:
		fmt.Printf("  %s[1-5]Views  [q]Quit%s\n", cDim, cReset)
	}
}

func render(s *appState) {
	clearScreen()
	renderHeader(s)
	renderTabs(s.view)

	switch s.view {
	case 1:
		renderOverview(s)
	case 2:
		renderScopes(s)
	case 3:
		renderProbes(s)
	case 4:
		renderDaemons(s)
	case 5:
		renderLogs(s)
	}

	renderFooter(s)
}

// --- Main ---

func main() {
	rc, rcErr := clientrc.Load()
	if rcErr != nil {
		fmt.Fprintln(os.Stderr, rcErr)
		os.Exit(2)
	}
	addrDefault := "127.0.0.1:9443"
	if rc.Addr != "" {
		addrDefault = rc.Addr
	}

	addr := flag.String("addr", addrDefault, "address(es) of cluster nodes (comma-separated)")
	probeAddr := flag.String("probe-addr", rc.ProbeAddr, "address(es) of external dnshived-probe hosts, comma-separated (0.9.7, optional)")
	probeName := flag.String("probe-name", rc.ProbeName, "friendly name(s) for external probe hosts, comma-separated, matching -probe-addr order (0.9.7, optional — falls back to address when unset)")
	useTLS := flag.Bool("tls", rc.TLS, "use HTTPS")
	tlsSkipVerify := flag.Bool("tls-skip-verify", rc.TLSSkipVerify, "skip TLS verification")
	tokenFile := flag.String("token-file", "", "path to bearer token file")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()

	if *showVersion {
		fmt.Println("dnshived-top", version)
		os.Exit(0)
	}

	if *useTLS || *tlsSkipVerify {
		scheme = "https"
		if *tlsSkipVerify {
			client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
	}
	if *tokenFile != "" {
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading token file: %v\n", err)
			os.Exit(2)
		}
		apiToken = strings.TrimSpace(string(data))
	} else if t := os.Getenv("DNSHIVED_TOKEN"); t != "" {
		apiToken = t
	} else if rc.Token != "" {
		apiToken = rc.Token
	}

	// Parse comma-separated addresses.
	var entryAddrs []string
	for _, a := range strings.Split(*addr, ",") {
		if a = strings.TrimSpace(a); a != "" {
			entryAddrs = append(entryAddrs, a)
		}
	}

	var probeHostAddrs []string
	if *probeAddr != "" {
		for _, a := range strings.Split(*probeAddr, ",") {
			if a = strings.TrimSpace(a); a != "" {
				probeHostAddrs = append(probeHostAddrs, a)
			}
		}
	}
	probeHostNames := make(map[string]string, len(probeHostAddrs))
	if *probeName != "" {
		names := strings.Split(*probeName, ",")
		for i, a := range probeHostAddrs {
			if i < len(names) {
				if n := strings.TrimSpace(names[i]); n != "" {
					probeHostNames[a] = n
				}
			}
		}
	}

	// Terminal setup.
	setRawMode()
	defer restoreMode()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	keyCh := make(chan int, 10)
	go readKey(keyCh)

	state := &appState{view: 1, logFilter: "all", entryAddrs: entryAddrs, probeHostAddrs: probeHostAddrs, probeHostNames: probeHostNames}

	// Initial fetch.
	state.nodes, state.tokens, state.coherence = collectAll(entryAddrs)
	state.lastUpdate = time.Now()
	render(state)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	probeTicker := time.NewTicker(20 * time.Second)
	defer probeTicker.Stop()

	type probeHostSweep struct {
		Statuses map[string]nodeStatus
		Errors   map[string]string
		Daemons  map[string][]daemonStatus
		Systems  map[string]systemInfo
	}
	probeHostCh := make(chan probeHostSweep, 1)
	if len(state.probeHostAddrs) > 0 {
		go func(addrs []string) {
			st, errs, daemons, systems := collectProbeHosts(addrs)
			probeHostCh <- probeHostSweep{st, errs, daemons, systems}
		}(state.probeHostAddrs)
	}

	probeHostResultsCh := make(chan map[string]map[string]probeResult, 1)
	if len(state.probeHostAddrs) > 0 {
		go func(addrs, scopes []string) {
			probeHostResultsCh <- collectProbeHostResults(addrs, scopes)
		}(state.probeHostAddrs, scopeNamesFromNodes(state.nodes))
	}

	probeHostEventsCh := make(chan map[string][]event, 1)
	if len(state.probeHostAddrs) > 0 {
		go func(addrs []string) {
			probeHostEventsCh <- collectProbeHostEvents(addrs)
		}(state.probeHostAddrs)
	}

	displayTicker := time.NewTicker(1 * time.Second)
	defer displayTicker.Stop()

	for {
		select {
		case <-ticker.C:
			state.nodes, state.tokens, state.coherence = collectAll(entryAddrs)
			state.lastUpdate = time.Now()
			render(state)

		case <-probeTicker.C:
			if len(state.probeHostAddrs) > 0 {
				go func(addrs []string) {
					st, errs, daemons, systems := collectProbeHosts(addrs)
					probeHostCh <- probeHostSweep{st, errs, daemons, systems}
				}(state.probeHostAddrs)
				go func(addrs, scopes []string) {
					probeHostResultsCh <- collectProbeHostResults(addrs, scopes)
				}(state.probeHostAddrs, scopeNamesFromNodes(state.nodes))
				go func(addrs []string) {
					probeHostEventsCh <- collectProbeHostEvents(addrs)
				}(state.probeHostAddrs)
			}

		case sweep := <-probeHostCh:
			state.probeHosts = sweep.Statuses
			state.probeHostErrors = sweep.Errors
			state.probeHostDaemons = sweep.Daemons
			state.probeHostSystem = sweep.Systems
			if state.view == 3 || state.view == 1 || state.view == 4 {
				render(state)
			}

		case hostEvents := <-probeHostEventsCh:
			state.probeHostEvents = hostEvents
			if state.view == 5 {
				render(state)
			}

		case results := <-probeHostResultsCh:
			state.probeHostResults = results
			issues, mismatches := checkProbeHostIssues(withoutDisabledScopes(state.probeHostResults, disabledScopeSet(state.nodes)), state.probeHostAddrs, state.probeHostNames, state.tokens, ownerDaemonUptime(state.nodes), servingScopeNamesFromNodes(state.nodes))
			confirmedLines, confirmedKeys := confirmProbeMismatches(mismatches, state.probeHostMismatchPrev)
			issues = append(issues, confirmedLines...)
			sort.Slice(issues, func(i, j int) bool { return issues[i].Text < issues[j].Text })
			state.probeIssues = issues
			state.probeHostMismatchPrev = mismatches
			state.probeHostConfirmedMismatches = confirmedKeys
			if state.view == 1 || state.view == 3 {
				render(state)
			}

		case <-displayTicker.C:
			if state.view == 3 {
				render(state)
			}

		case key := <-keyCh:
			switch key {
			case 'q', 'Q':
				clearScreen()
				return
			case '1':
				state.view = 1
				state.selectedScope = ""
			case '2':
				state.view = 2
				state.selectedScope = ""
			case '3':
				state.view = 3
				state.selectedScope = ""
			case '4':
				state.view = 4
				state.selectedScope = ""
			case '5':
				state.view = 5
				state.selectedScope = ""
			case 'n', 'N':
				state.scopePage++
			case 'p', 'P':
				if state.scopePage > 0 {
					state.scopePage--
				}
			case keyPgDn:
				if state.view == 4 {
					state.daemonPage++
				} else {
					state.probePage++
				}
			case keyPgUp:
				if state.view == 4 {
					if state.daemonPage > 0 {
						state.daemonPage--
					}
				} else if state.probePage > 0 {
					state.probePage--
				}
			case 'a', 'A':
				state.logFilter = "all"
			case keyLeft, keyRight:
				if state.view == 5 {
					state.logFilter = cycleLogFilter(state.logFilter, key == keyRight)
				}
			case 27: // Escape
				state.selectedScope = ""
			case 'w': // cycle through scopes for drilldown
				state.view = 2
				allScopes := []string{}
				for _, n := range state.nodes {
					if n.Reachable && isCoreRole(n.Status.Role) {
						allScopes = append(allScopes, n.Status.Serving...)
					}
				}
				if len(allScopes) == 0 {
					break
				}
				if state.selectedScope == "" {
					state.selectedScope = allScopes[0]
				} else {
					// Find current and advance
					found := false
					for i, s := range allScopes {
						if s == state.selectedScope {
							state.selectedScope = allScopes[(i+1)%len(allScopes)]
							found = true
							break
						}
					}
					if !found {
						state.selectedScope = allScopes[0]
					}
				}
			}
			render(state)

		case <-sigCh:
			clearScreen()
			return
		}
	}
}
