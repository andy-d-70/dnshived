// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// dnshived-validate — Invariant Validation Framework
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"dnshived/internal/cliguard"
	"dnshived/internal/probepin"
)

var version = "0.9.7-dev"

// --- Cluster state types ---

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
	PlaneWarnings    []string          `json:"plane_warnings"`
	ConfiguredScopes []string          `json:"configured_scopes"`
	ScopesHash       string            `json:"scopes_hash"`
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

// ClusterSnapshot is the complete observed state at one point in time.
type ClusterSnapshot struct {
	Timestamp   time.Time            `json:"timestamp"`
	SampleIndex int64                `json:"sample_index"`
	Nodes       []NodeSnapshot       `json:"nodes"`
	Tokens      map[string]tokenInfo `json:"tokens,omitempty"`
}

// NodeSnapshot is one node's state at snapshot time.
type NodeSnapshot struct {
	Addr          string            `json:"addr"`
	NodeID        string            `json:"node_id"`
	Role          string            `json:"role"`
	State         string            `json:"state"`
	Epoch         uint64            `json:"epoch"`
	Generation    uint64            `json:"generation"`
	Incarnation   uint64            `json:"incarnation"`
	Watermark     map[string]uint64 `json:"watermark,omitempty"`
	Serving       []string          `json:"serving"`
	Reachable     bool              `json:"reachable"`
	Error         string            `json:"error,omitempty"`
	PlaneWarnings []string          `json:"plane_warnings,omitempty"`
	// ConfiguredScopes mirrors /api/v1/status's own field of the same name.
	ConfiguredScopes []string `json:"configured_scopes,omitempty"`
}

// --- Invariant interface ---

// Invariant is a safety property that must hold at every observed state.
type Invariant interface {
	Name() string
	Evaluate(snap ClusterSnapshot) error
}

// Violation records a broken invariant with the full cluster state.
type Violation struct {
	Invariant string          `json:"invariant"`
	Error     string          `json:"error"`
	Snapshot  ClusterSnapshot `json:"snapshot"`
}

// --- Invariant implementations ---

// MutualExclusion: for every scope, at most one node may be serving it.
type MutualExclusion struct{}

func (MutualExclusion) Name() string { return "mutual_exclusion" }

func (MutualExclusion) Evaluate(snap ClusterSnapshot) error {
	scopeOwners := make(map[string][]string) // scope → list of serving node IDs
	for _, n := range snap.Nodes {
		if !n.Reachable {
			continue
		}
		for _, scope := range n.Serving {
			scopeOwners[scope] = append(scopeOwners[scope], n.NodeID)
		}
	}
	for scope, owners := range scopeOwners {
		if len(owners) > 1 {
			return fmt.Errorf("scope %q served by %d nodes simultaneously: %s",
				scope, len(owners), strings.Join(owners, ", "))
		}
	}
	return nil
}

// AuthorityMatching: a serving worker's scope must be backed by an
// unexpired arbiter token naming that worker as owner.
type AuthorityMatching struct{}

func (AuthorityMatching) Name() string { return "authority_matching" }

func (AuthorityMatching) Evaluate(snap ClusterSnapshot) error {
	if snap.Tokens == nil {
		return nil // no token data available (every fetch attempt failed) — can't check
	}
	for _, n := range snap.Nodes {
		if !n.Reachable || !isCoreRole(n.Role) {
			continue
		}
		for _, scope := range n.Serving {
			tok, exists := snap.Tokens[scope]
			if !exists {
				return fmt.Errorf("node %s serves scope %q but arbiter has no token for it",
					n.NodeID, scope)
			}
			if tok.Owner != n.NodeID {
				return fmt.Errorf("node %s serves scope %q but arbiter token names %q as owner",
					n.NodeID, scope, tok.Owner)
			}
			if tok.Expired {
				return fmt.Errorf("node %s serves scope %q but arbiter token is expired",
					n.NodeID, scope)
			}
		}
	}
	return nil
}

// FencedNodeNeverServes: a node with state != STABLE must not serve any
// scope.
type FencedNodeNeverServes struct{}

func (FencedNodeNeverServes) Name() string { return "fenced_node_never_serves" }

func (FencedNodeNeverServes) Evaluate(snap ClusterSnapshot) error {
	for _, n := range snap.Nodes {
		if !n.Reachable {
			continue
		}
		if n.State != "STABLE" && len(n.Serving) > 0 {
			return fmt.Errorf("node %s in state %s is serving %v — fenced nodes must not serve",
				n.NodeID, n.State, n.Serving)
		}
	}
	return nil
}

type PlaneIntact struct{}

func (PlaneIntact) Name() string { return "plane_intact" }

func (PlaneIntact) Evaluate(snap ClusterSnapshot) error {
	for _, n := range snap.Nodes {
		if !n.Reachable || len(n.PlaneWarnings) == 0 {
			continue
		}
		return fmt.Errorf("node %s: network plane drift detected: %s",
			n.NodeID, strings.Join(n.PlaneWarnings, "; "))
	}
	return nil
}

// dhcpProbeAPIResult mirrors GET /api/v1/probe/<scope>'s response shape.
type dhcpProbeAPIResult struct {
	Scope   string `json:"scope"`
	Pending bool   `json:"pending"`
	DHCP    struct {
		Verdict string   `json:"verdict"`
		Servers []string `json:"servers"`
		Error   string   `json:"error"`
	} `json:"dhcp"`
}

// DHCPDualActive: real, ground-truth DHCP dual-active detection, read from
// the probe hosts (the only nodes that serve /api/v1/probe/<scope>).
type DHCPDualActive struct {
	mu      sync.Mutex
	lastBad map[string]string // "scope@probe base URL" -> distinct server-ids seen
	running atomic.Bool
	probes  []string
}

// dhcpProbeFanoutLimit bounds concurrent (scope, worker) probe goroutines
// within a single probeOnce round.
const dhcpProbeFanoutLimit = 10

const dhcpDualActiveInterval = 20 * time.Second

func NewDHCPDualActive(entryAddr string, probes []string) *DHCPDualActive {
	d := &DHCPDualActive{lastBad: make(map[string]string), probes: probes}
	go func() {
		d.probeOnce(entryAddr)
		ticker := time.NewTicker(dhcpDualActiveInterval)
		defer ticker.Stop()
		for range ticker.C {
			d.probeOnce(entryAddr)
		}
	}()
	return d
}

func (d *DHCPDualActive) Name() string { return "dhcp_dual_active" }

func (d *DHCPDualActive) Evaluate(snap ClusterSnapshot) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.lastBad) == 0 {
		return nil
	}
	details := make([]string, 0, len(d.lastBad))
	for key, detail := range d.lastBad {
		details = append(details, fmt.Sprintf("%s (%s)", key, detail))
	}
	sort.Strings(details)
	return fmt.Errorf("real DHCP dual-active detected: %s", strings.Join(details, "; "))
}

func (d *DHCPDualActive) probeOnce(entryAddr string) {
	if !d.running.CompareAndSwap(false, true) {
		return
	}
	defer d.running.Store(false)

	var cv clusterView
	if err := fetchJSON(scheme+"://"+entryAddr+"/api/v1/cluster", &cv); err != nil {
		return
	}
	addrs := []string{cv.SelfAddr}
	for _, p := range cv.Peers {
		addrs = append(addrs, p.Addr)
	}

	scopeSet := make(map[string]bool)
	for _, addr := range addrs {
		var st nodeStatus
		if err := fetchJSON(scheme+"://"+addr+"/api/v1/status", &st); err != nil {
			continue
		}
		if !isCoreRole(st.Role) {
			continue
		}
		for _, sc := range st.ConfiguredScopes {
			scopeSet[sc] = true
		}
	}

	current := make(map[string]string)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, dhcpProbeFanoutLimit)
	for scope := range scopeSet {
		for _, probe := range d.probes {
			wg.Add(1)
			sem <- struct{}{}
			go func(scope, probe string) {
				defer wg.Done()
				defer func() { <-sem }()
				var pr dhcpProbeAPIResult
				if err := fetchJSONWith(dhcpProbeClient, probe+"/api/v1/probe/"+scope, &pr); err != nil {
					return
				}
				if !pr.Pending && pr.DHCP.Verdict == "dual_active" {
					mu.Lock()
					current[scope+"@"+probe] = fmt.Sprintf("servers=%v", pr.DHCP.Servers)
					mu.Unlock()
				}
			}(scope, probe)
		}
	}
	wg.Wait()

	d.mu.Lock()
	d.lastBad = current
	d.mu.Unlock()
}

type NodeIPCoherence struct {
	mu      sync.Mutex
	lastBad map[string]string // scope name -> violation detail
	running atomic.Bool
}

// nodeIPCoherenceInterval doesn't need DHCPDualActive's 20s realtime-
// probe cadence.
const nodeIPCoherenceInterval = 30 * time.Second

// probeConfigScope mirrors the subset of GET /api/v1/probe-config's
// per-scope fields this invariant needs (cmd/dnshived/main.go).
type probeConfigScope struct {
	VIP    string `json:"vip"`
	NodeIP string `json:"node_ip"`
}

type probeConfigResp struct {
	Scopes map[string]probeConfigScope `json:"scopes"`
}

func NewNodeIPCoherence(entryAddr string) *NodeIPCoherence {
	n := &NodeIPCoherence{lastBad: make(map[string]string)}
	go func() {
		n.checkOnce(entryAddr)
		ticker := time.NewTicker(nodeIPCoherenceInterval)
		defer ticker.Stop()
		for range ticker.C {
			n.checkOnce(entryAddr)
		}
	}()
	return n
}

func (n *NodeIPCoherence) Name() string { return "node_ip_coherence" }

func (n *NodeIPCoherence) Evaluate(snap ClusterSnapshot) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.lastBad) == 0 {
		return nil
	}
	details := make([]string, 0, len(n.lastBad))
	for scope, detail := range n.lastBad {
		details = append(details, fmt.Sprintf("%s: %s", scope, detail))
	}
	sort.Strings(details)
	return fmt.Errorf("node_ip/VIP coherence violated: %s", strings.Join(details, "; "))
}

func (n *NodeIPCoherence) checkOnce(entryAddr string) {
	if !n.running.CompareAndSwap(false, true) {
		return
	}
	defer n.running.Store(false)

	addrs, err := discoverClusterAddrs(entryAddr)
	if err != nil {
		return
	}

	// scope name -> worker addr -> that worker's own reported scope data.
	byScope := make(map[string]map[string]probeConfigScope)
	for _, addr := range addrs {
		var st nodeStatus
		if err := fetchJSON(scheme+"://"+addr+"/api/v1/status", &st); err != nil {
			continue
		}
		if !isCoreRole(st.Role) {
			continue
		}
		var pc probeConfigResp
		if err := fetchJSON(scheme+"://"+addr+"/api/v1/probe-config", &pc); err != nil {
			continue
		}
		for name, sc := range pc.Scopes {
			if byScope[name] == nil {
				byScope[name] = make(map[string]probeConfigScope)
			}
			byScope[name][addr] = sc
		}
	}

	current := make(map[string]string)
	for scope, byAddr := range byScope {
		if detail := checkScopeIPCoherence(byAddr); detail != "" {
			current[scope] = detail
		}
	}

	n.mu.Lock()
	n.lastBad = current
	n.mu.Unlock()
}

// checkScopeIPCoherence is the pure core of the invariant.
func checkScopeIPCoherence(byAddr map[string]probeConfigScope) string {
	if len(byAddr) == 0 {
		return ""
	}

	addrs := make([]string, 0, len(byAddr))
	for addr := range byAddr {
		addrs = append(addrs, addr)
	}
	sort.Strings(addrs)

	vip := byAddr[addrs[0]].VIP
	vipIP, vipNet, err := net.ParseCIDR(vip)
	if err != nil {
		return fmt.Sprintf("VIP %q does not parse as a CIDR address", vip)
	}

	type entry struct {
		label string
		ip    net.IP
	}
	entries := []entry{{"VIP", vipIP}}
	for _, addr := range addrs {
		nodeIP := byAddr[addr].NodeIP
		ip, _, err := net.ParseCIDR(nodeIP)
		if err != nil {
			return fmt.Sprintf("node_ip %q on %s does not parse as a CIDR address", nodeIP, addr)
		}
		if !vipNet.Contains(ip) {
			return fmt.Sprintf("node_ip %s on %s is outside the VIP's own subnet %s", ip, addr, vipNet)
		}
		entries = append(entries, entry{addr, ip})
	}

	seen := make(map[string]string) // ip string -> first label that used it
	for _, e := range entries {
		s := e.ip.String()
		if prior, dup := seen[s]; dup {
			return fmt.Sprintf("duplicate address %s used by both %s and %s", s, prior, e.label)
		}
		seen[s] = e.label
	}
	return ""
}

func groupByField(label string, addrs []string, fetch func(addr string) (value string, ok bool)) string {
	groups := make(map[string][]string) // value -> addrs
	for _, addr := range addrs {
		v, ok := fetch(addr)
		if !ok {
			continue
		}
		groups[v] = append(groups[v], addr)
	}
	if len(groups) <= 1 {
		return ""
	}
	var parts []string
	for v, addrList := range groups {
		sort.Strings(addrList)
		parts = append(parts, fmt.Sprintf("%s: %s", v, strings.Join(addrList, ",")))
	}
	sort.Strings(parts)
	return fmt.Sprintf("%s mismatch across cluster: %s", label, strings.Join(parts, "; "))
}

// heartbeatLine renders the periodic "still checking, here's the current
// state" summary — pure so it's directly testable without driving the
// whole run() loop.
func heartbeatLine(sample int64, total int, stillViolated []string) string {
	if len(stillViolated) == 0 {
		return fmt.Sprintf("[sample %d] %d invariant(s) checked, all healthy", sample, total)
	}
	sort.Strings(stillViolated)
	return fmt.Sprintf("[sample %d] %d invariant(s) checked, %d still violated: %s",
		sample, total, len(stillViolated), strings.Join(stillViolated, ", "))
}

// discoverClusterAddrs asks entryAddr for its own view of cluster
// membership (self + peers).
func discoverClusterAddrs(entryAddr string) ([]string, error) {
	var cv clusterView
	if err := fetchJSON(scheme+"://"+entryAddr+"/api/v1/cluster", &cv); err != nil {
		return nil, err
	}
	addrs := []string{cv.SelfAddr}
	for _, p := range cv.Peers {
		addrs = append(addrs, p.Addr)
	}
	sort.Strings(addrs)
	return addrs, nil
}

// VersionCoherence: every node in the cluster must report the same
// dnshived version.
type VersionCoherence struct {
	mu      sync.Mutex
	lastBad string
	running atomic.Bool
}

const versionCoherenceInterval = 30 * time.Second

func NewVersionCoherence(entryAddr string) *VersionCoherence {
	v := &VersionCoherence{}
	go func() {
		v.checkOnce(entryAddr)
		ticker := time.NewTicker(versionCoherenceInterval)
		defer ticker.Stop()
		for range ticker.C {
			v.checkOnce(entryAddr)
		}
	}()
	return v
}

func (v *VersionCoherence) Name() string { return "version_coherence" }

func (v *VersionCoherence) Evaluate(snap ClusterSnapshot) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.lastBad == "" {
		return nil
	}
	return fmt.Errorf("%s", v.lastBad)
}

func (v *VersionCoherence) checkOnce(entryAddr string) {
	if !v.running.CompareAndSwap(false, true) {
		return
	}
	defer v.running.Store(false)

	addrs, err := discoverClusterAddrs(entryAddr)
	if err != nil {
		return
	}
	bad := groupByField("version", addrs, func(addr string) (string, bool) {
		var st nodeStatus
		if err := fetchJSON(scheme+"://"+addr+"/api/v1/status", &st); err != nil {
			return "", false
		}
		return st.Version, true
	})

	v.mu.Lock()
	v.lastBad = bad
	v.mu.Unlock()
}

// ScopesHashCoherence: every node must agree on the cluster-wide parts of
// scope config (Cluster.ScopesHash() — excludes NodeIP, which is
// legitimately per-node).
type ScopesHashCoherence struct {
	mu      sync.Mutex
	lastBad string
	running atomic.Bool
}

const scopesHashCoherenceInterval = 30 * time.Second

func NewScopesHashCoherence(entryAddr string) *ScopesHashCoherence {
	s := &ScopesHashCoherence{}
	go func() {
		s.checkOnce(entryAddr)
		ticker := time.NewTicker(scopesHashCoherenceInterval)
		defer ticker.Stop()
		for range ticker.C {
			s.checkOnce(entryAddr)
		}
	}()
	return s
}

func (s *ScopesHashCoherence) Name() string { return "scopes_hash_coherence" }

func (s *ScopesHashCoherence) Evaluate(snap ClusterSnapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastBad == "" {
		return nil
	}
	return fmt.Errorf("%s", s.lastBad)
}

func (s *ScopesHashCoherence) checkOnce(entryAddr string) {
	if !s.running.CompareAndSwap(false, true) {
		return
	}
	defer s.running.Store(false)

	addrs, err := discoverClusterAddrs(entryAddr)
	if err != nil {
		return
	}
	bad := groupByField("scopes_hash", addrs, func(addr string) (string, bool) {
		var st nodeStatus
		if err := fetchJSON(scheme+"://"+addr+"/api/v1/status", &st); err != nil {
			return "", false
		}
		return st.ScopesHash, true
	})

	s.mu.Lock()
	s.lastBad = bad
	s.mu.Unlock()
}

// MonotonicProgress: for any successive snapshots, a stable node's epoch
// and generation must never decrease.
type MonotonicProgress struct {
	mu   sync.Mutex
	prev map[string]nodeProgress // keyed by node_id
}

type nodeProgress struct {
	Epoch       uint64
	Generation  uint64
	Incarnation uint64
}

func NewMonotonicProgress() *MonotonicProgress {
	return &MonotonicProgress{prev: make(map[string]nodeProgress)}
}

func (m *MonotonicProgress) Name() string { return "monotonic_progress" }

func (m *MonotonicProgress) Evaluate(snap ClusterSnapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, n := range snap.Nodes {
		if !n.Reachable || n.State != "STABLE" {
			continue
		}
		prev, exists := m.prev[n.NodeID]
		if exists && n.Incarnation == prev.Incarnation {
			// Same incarnation — epoch and generation must not decrease.
			if n.Epoch < prev.Epoch {
				return fmt.Errorf("node %s epoch retrogressed: %d → %d (incarnation %d)",
					n.NodeID, prev.Epoch, n.Epoch, n.Incarnation)
			}
			if n.Epoch == prev.Epoch && n.Generation < prev.Generation {
				return fmt.Errorf("node %s generation retrogressed: %d → %d (epoch %d, incarnation %d)",
					n.NodeID, prev.Generation, n.Generation, n.Epoch, n.Incarnation)
			}
		}
		// New incarnation or first observation — record and move on.
		m.prev[n.NodeID] = nodeProgress{
			Epoch:       n.Epoch,
			Generation:  n.Generation,
			Incarnation: n.Incarnation,
		}
	}
	return nil
}

// PreferredWorkerConvergence: after the cluster has been fully STABLE for
// longer than the settling window, scopes must be served by their
// preferred workers.
type PreferredWorkerConvergence struct {
	mu           sync.Mutex
	stableSince  time.Time
	settleWindow time.Duration
	// preferredMap maps scope name → expected serving role.
	preferredMap map[string]string
}

func NewPreferredWorkerConvergence(settleWindow time.Duration, preferredMap map[string]string) *PreferredWorkerConvergence {
	return &PreferredWorkerConvergence{
		settleWindow: settleWindow,
		preferredMap: preferredMap,
	}
}

func (p *PreferredWorkerConvergence) Name() string { return "preferred_worker_convergence" }

func (p *PreferredWorkerConvergence) Evaluate(snap ClusterSnapshot) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if all reachable nodes are STABLE.
	allStable := true
	reachable := 0
	for _, n := range snap.Nodes {
		if !n.Reachable {
			allStable = false
			break
		}
		reachable++
		if n.State != "STABLE" {
			allStable = false
		}
	}

	if !allStable || reachable < 3 {
		p.stableSince = time.Time{} // reset
		return nil
	}

	if p.stableSince.IsZero() {
		p.stableSince = snap.Timestamp
		return nil
	}

	// Only assert after the settling window.
	if snap.Timestamp.Sub(p.stableSince) <= p.settleWindow {
		return nil
	}

	// Build serving map: role → scopes.
	roleServing := make(map[string][]string)
	stillConfigured := make(map[string]bool)
	for _, n := range snap.Nodes {
		if !n.Reachable {
			continue
		}
		roleServing[n.Role] = n.Serving
		for _, sc := range n.ConfiguredScopes {
			stillConfigured[sc] = true
		}
	}

	// Check each scope is on its preferred worker.
	for scope, expectedRole := range p.preferredMap {
		if !stillConfigured[scope] {
			continue
		}
		scopes, ok := roleServing[expectedRole]
		if !ok {
			return fmt.Errorf("scope %q expected on %s but role not reachable", scope, expectedRole)
		}
		found := false
		for _, s := range scopes {
			if s == scope {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("scope %q not on preferred worker %s after %v of stability",
				scope, expectedRole, snap.Timestamp.Sub(p.stableSince).Round(time.Second))
		}
	}
	return nil
}

// --- HTTP client ---

var (
	scheme   = "http"
	apiToken = ""
)

// discoverPreferredMap queries the cluster and builds the
// scope→preferred_worker map from what each worker is currently serving.
func discoverPreferredMap(entryAddr string) map[string]string {
	result := make(map[string]string)

	// Discover all nodes.
	var cv clusterView
	if err := fetchJSON(scheme+"://"+entryAddr+"/api/v1/cluster", &cv); err != nil {
		return result
	}

	addrs := []string{cv.SelfAddr}
	for _, p := range cv.Peers {
		addrs = append(addrs, p.Addr)
	}

	// Query each node's serving list and role.
	for _, addr := range addrs {
		var st nodeStatus
		if err := fetchJSON(scheme+"://"+addr+"/api/v1/status", &st); err != nil {
			continue
		}
		if !isCoreRole(st.Role) {
			continue
		}
		for _, scope := range st.Serving {
			result[scope] = st.Role
		}
	}

	return result
}

var client = &http.Client{
	Timeout: 2 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:      10,
		MaxConnsPerHost:   2,
		IdleConnTimeout:   30 * time.Second,
		DisableKeepAlives: false,
	},
}

var dhcpProbeClient = &http.Client{Timeout: 18 * time.Second}

const defaultWebConfigPath = "/etc/dnshived/web.json"

// probeTargets returns each probe host's base URL, from the -probe-addr
// list or else the web UI's own probe_hosts.
func probeTargets(flagVal, webConfigPath string) []string {
	return probeTargetsPinned(flagVal, webConfigPath, nil)
}

// probeTargetsPinned is probeTargets with -probe-pin: a pinned address is reached over HTTPS, and a pin
// without a -probe-addr entry adds that probe too.
func probeTargetsPinned(flagVal, webConfigPath string, flagPins map[string]string) []string {
	var out []string
	for _, a := range strings.Split(flagVal, ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if _, pinned := flagPins[a]; pinned {
			a = "https://" + a
		} else if !strings.Contains(a, "://") {
			a = "http://" + a
		}
		out = append(out, strings.TrimSuffix(a, "/"))
	}
	pinnedAddrs := make([]string, 0, len(flagPins))
	for addr := range flagPins {
		pinnedAddrs = append(pinnedAddrs, addr)
	}
	sort.Strings(pinnedAddrs)
	for _, addr := range pinnedAddrs {
		if !slices.Contains(out, "https://"+addr) {
			out = append(out, "https://"+addr)
		}
	}
	if len(out) > 0 {
		return out
	}
	for _, h := range loadWebProbeHosts(webConfigPath) {
		if h.Addr == "" {
			continue
		}
		if h.TLSFingerprint != "" {
			out = append(out, "https://"+tlsAddrOf(h.Addr, h.TLSPort))
			continue
		}
		sch := "http"
		if h.TLS {
			sch = "https"
		}
		out = append(out, sch+"://"+h.Addr)
	}
	return out
}

// webProbeHost is one entry of the web UI's probe_hosts.
type webProbeHost struct {
	Addr           string `json:"addr"`
	TLS            bool   `json:"tls"`
	TLSPort        string `json:"tls_port"`
	TLSFingerprint string `json:"tls_fingerprint"`
}

func loadWebProbeHosts(webConfigPath string) []webProbeHost {
	data, err := os.ReadFile(webConfigPath)
	if err != nil {
		return nil
	}
	var wc struct {
		ProbeHosts []webProbeHost `json:"probe_hosts"`
	}
	if json.Unmarshal(data, &wc) != nil {
		return nil
	}
	return wc.ProbeHosts
}

// webProbePins maps each pinned probe host in the web UI's config to its TLS address and fingerprint.
func webProbePins(webConfigPath string) map[string]string {
	pins := make(map[string]string)
	for _, h := range loadWebProbeHosts(webConfigPath) {
		if h.Addr != "" && h.TLSFingerprint != "" {
			pins[tlsAddrOf(h.Addr, h.TLSPort)] = h.TLSFingerprint
		}
	}
	return pins
}

// tlsAddrOf is addr's host with port.
func tlsAddrOf(addr, port string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return net.JoinHostPort(host, port)
}

// probePinFlag is -probe-pin: host:port=sha256:<fingerprint>, repeatable.
type probePinFlag map[string]string

func (p probePinFlag) String() string { return "" }

func (p probePinFlag) Set(v string) error {
	addr, fp, err := probepin.ParsePin(v)
	if err != nil {
		return err
	}
	p[addr] = fp
	return nil
}

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

// --- Snapshot collection ---

func collectSnapshot(entryAddr string, sampleIndex int64) ClusterSnapshot {
	snap := ClusterSnapshot{
		Timestamp:   time.Now().UTC(),
		SampleIndex: sampleIndex,
	}

	// Discover topology.
	var cv clusterView
	if err := fetchJSON(scheme+"://"+entryAddr+"/api/v1/cluster", &cv); err != nil {
		snap.Nodes = append(snap.Nodes, NodeSnapshot{
			Addr: entryAddr, Reachable: false, Error: err.Error(),
		})
		return snap
	}

	addrs := []string{cv.SelfAddr}
	for _, p := range cv.Peers {
		addrs = append(addrs, p.Addr)
	}

	// Fetch all nodes in parallel.
	type result struct {
		addr   string
		status *nodeStatus
		err    error
	}
	results := make([]result, len(addrs))
	var wg sync.WaitGroup
	for i, addr := range addrs {
		wg.Add(1)
		go func(idx int, a string) {
			defer wg.Done()
			var st nodeStatus
			err := fetchJSON(scheme+"://"+a+"/api/v1/status", &st)
			results[idx] = result{addr: a, status: &st, err: err}
		}(i, addr)
	}
	wg.Wait()

	for _, r := range results {
		if r.err != nil {
			snap.Nodes = append(snap.Nodes, NodeSnapshot{
				Addr: r.addr, Reachable: false, Error: r.err.Error(),
			})
			continue
		}
		snap.Nodes = append(snap.Nodes, NodeSnapshot{
			Addr:             r.addr,
			NodeID:           r.status.NodeID,
			Role:             r.status.Role,
			State:            r.status.State,
			Epoch:            r.status.Epoch,
			Generation:       r.status.Generation,
			Incarnation:      r.status.Incarnation,
			Watermark:        r.status.Watermark,
			Serving:          r.status.Serving,
			Reachable:        true,
			PlaneWarnings:    r.status.PlaneWarnings,
			ConfiguredScopes: r.status.ConfiguredScopes,
		})
	}

	// Sort by role.
	sort.Slice(snap.Nodes, func(i, j int) bool {
		return roleOrder(snap.Nodes[i].Role) < roleOrder(snap.Nodes[j].Role)
	})

	// Fetch tokens from a reachable core node.
	var preferredAddr, fallbackAddr string
	for _, n := range snap.Nodes {
		if !n.Reachable || !isCoreRole(n.Role) {
			continue
		}
		if n.Role == "core-3" {
			preferredAddr = n.Addr
		} else if fallbackAddr == "" {
			fallbackAddr = n.Addr
		}
	}
	for _, addr := range []string{preferredAddr, fallbackAddr} {
		if addr == "" {
			continue
		}
		tokens := make(map[string]tokenInfo)
		if err := fetchJSON(scheme+"://"+addr+"/api/v1/token/status", &tokens); err == nil {
			snap.Tokens = tokens
			break
		}
	}

	return snap
}

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

// isCoreRole reports whether role is one of the 3 real core roles.
func isCoreRole(role string) bool {
	switch role {
	case "core-1", "core-2", "core-3":
		return true
	default:
		return false
	}
}

// --- Monitor ---

// dumpViolation writes one violation's full snapshot to its own file.
func dumpViolation(v Violation, outDir string) string {
	os.MkdirAll(outDir, 0o755)
	filename := fmt.Sprintf("violation-%s-sample%d-%d.json",
		v.Invariant, v.Snapshot.SampleIndex, v.Snapshot.Timestamp.UnixNano())
	path := filepath.Join(outDir, filename)
	data, _ := json.MarshalIndent(v, "", "  ")
	os.WriteFile(path, data, 0o600)
	return path
}

func main() {
	log.SetOutput(os.Stdout)

	addr := flag.String("addr", "127.0.0.1:9443", "address of any cluster node")
	duration := flag.Duration("duration", 60*time.Second, "how long to monitor (0 = until Ctrl-C)")
	interval := flag.Duration("interval", 500*time.Millisecond, "polling interval")
	outDir := flag.String("out", "./violations", "directory for violation snapshots")
	useTLS := flag.Bool("tls", false, "use HTTPS")
	tlsSkipVerify := flag.Bool("tls-skip-verify", false, "skip TLS certificate verification")
	tokenFile := flag.String("token-file", "", "path to file containing API bearer token")
	probeAddrs := flag.String("probe-addr", "", "comma-separated probe host addresses (host:port, plain HTTP unless given as https://...); default: probe_hosts from "+defaultWebConfigPath)
	probePins := probePinFlag{}
	flag.Var(probePins, "probe-pin", "pin a probe host's TLS API: host:port=sha256:<fingerprint> (repeatable; the probe's log shows the fingerprint)")
	showVersion := flag.Bool("version", false, "print version")
	cliguard.Parse("dnshived-validate", false)

	if *showVersion {
		fmt.Println("dnshived-validate", version)
		os.Exit(0)
	}

	// Configure TLS and auth.
	if *useTLS || *tlsSkipVerify {
		scheme = "https"
		if *tlsSkipVerify {
			tlsCfg := &tls.Config{InsecureSkipVerify: true}
			if tr, ok := client.Transport.(*http.Transport); ok {
				tr.TLSClientConfig = tlsCfg
				dhcpProbeClient.Transport = tr.Clone()
			} else {
				fmt.Fprintln(os.Stderr, "warning: -tls-skip-verify has no effect — client.Transport is not *http.Transport")
			}
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
	}

	// Register invariants.
	// Discover preferred_worker map from cluster state at startup.
	fmt.Println("  Discovering scope ownership from cluster...")
	preferredMap := discoverPreferredMap(*addr)
	if len(preferredMap) == 0 {
		fmt.Println("  ⚠ Could not discover scopes — preferred_worker_convergence will be skipped")
	} else {
		fmt.Printf("  Discovered %d scopes\n", len(preferredMap))
	}

	pins := webProbePins(defaultWebConfigPath)
	for addr, fp := range probePins {
		pins[addr] = fp
	}
	if len(pins) > 0 {
		next := dhcpProbeClient.Transport
		if next == nil {
			next = http.DefaultTransport
		}
		router := &probepin.Router{Next: next}
		router.SetPins(pins)
		dhcpProbeClient.Transport = router
	}
	probes := probeTargetsPinned(*probeAddrs, defaultWebConfigPath, probePins)
	if len(probes) == 0 {
		fmt.Println("  ⚠ No probe host known (-probe-addr, or probe_hosts in " + defaultWebConfigPath + ") — dhcp_dual_active will be skipped")
	} else {
		fmt.Printf("  Probe hosts: %s\n", strings.Join(probes, ", "))
	}

	invariants := []Invariant{
		MutualExclusion{},
		AuthorityMatching{},
		FencedNodeNeverServes{},
		PlaneIntact{},
		NewMonotonicProgress(),
		NewNodeIPCoherence(*addr),
		NewVersionCoherence(*addr),
		NewScopesHashCoherence(*addr),
	}
	if len(probes) > 0 {
		invariants = append(invariants, NewDHCPDualActive(*addr, probes))
	}
	if len(preferredMap) > 0 {
		invariants = append(invariants, NewPreferredWorkerConvergence(30*time.Second, preferredMap))
	}

	fmt.Println("═══════════════════════════════════════════════════")
	fmt.Println("  dnshived Invariant Validation Framework")
	fmt.Printf("  Version  : %s\n", version)
	fmt.Printf("  Target   : %s\n", *addr)
	fmt.Printf("  Interval : %s\n", *interval)
	if *duration > 0 {
		fmt.Printf("  Duration : %s\n", *duration)
	} else {
		fmt.Printf("  Duration : until Ctrl-C\n")
	}
	fmt.Printf("  Invariants:\n")
	for _, inv := range invariants {
		fmt.Printf("    ✔ %s\n", inv.Name())
	}
	fmt.Println("═══════════════════════════════════════════════════")
	fmt.Println()

	// Verify initial connectivity.
	snap := collectSnapshot(*addr, 0)
	reachable := 0
	for _, n := range snap.Nodes {
		if n.Reachable {
			reachable++
		}
	}
	if reachable == 0 {
		fmt.Fprintf(os.Stderr, "FATAL: cannot reach any node at %s\n", *addr)
		os.Exit(2)
	}
	fmt.Printf("  Initial contact: %d node(s) reachable. Monitoring...\n\n", reachable)

	// Set up timer and signal handling.
	var deadline <-chan time.Time
	if *duration > 0 {
		deadline = time.After(*duration)
	}
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	// violationListCap bounds the in-memory violations slice, kept only for
	// the end-of-run itemized listing.
	const violationListCap = 1000

	var (
		samples        int64
		violationCount int64
		violations     []Violation
	)

	violated := make(map[string]bool, len(invariants))
	lastHeartbeat := time.Now()
	const heartbeatInterval = 30 * time.Second

	for {
		select {
		case <-ticker.C:
			samples++
			snap := collectSnapshot(*addr, samples)

			for _, inv := range invariants {
				name := inv.Name()
				if err := inv.Evaluate(snap); err != nil {
					v := Violation{
						Invariant: name,
						Error:     err.Error(),
						Snapshot:  snap,
					}
					violationCount++
					if len(violations) < violationListCap {
						violations = append(violations, v)
					}
					path := dumpViolation(v, *outDir)
					log.Printf("[VALIDATE:VIOLATION] #%d [sample %d] %s: %s (snapshot: %s)",
						violationCount, samples, name, err, path)
					violated[name] = true
				} else if violated[name] {
					log.Printf("[VALIDATE:RESOLVED] [sample %d] %s — back to healthy", samples, name)
					violated[name] = false
				}
			}

			if time.Since(lastHeartbeat) >= heartbeatInterval {
				var stillViolated []string
				for _, inv := range invariants {
					if violated[inv.Name()] {
						stillViolated = append(stillViolated, inv.Name())
					}
				}
				log.Printf("[VALIDATE:HEARTBEAT] %s", heartbeatLine(samples, len(invariants), stillViolated))
				lastHeartbeat = time.Now()
			}

			// Progress indicator every 100 samples.
			if samples%100 == 0 {
				fmt.Printf("  … %d samples, %d violations\n", samples, violationCount)
			}

		case <-deadline:
			goto done

		case <-sigCh:
			fmt.Println("\n  Interrupted.")
			goto done
		}
	}

done:
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════")
	fmt.Printf("  Samples    : %d\n", samples)
	fmt.Printf("  Duration   : %s\n", time.Duration(samples)*(*interval))
	fmt.Printf("  Violations : %d\n", violationCount)
	if violationCount == 0 {
		fmt.Println("  Result     : ✔ ALL INVARIANTS HELD")
	} else {
		fmt.Println("  Result     : ✖ INVARIANTS VIOLATED")
		for i, v := range violations {
			fmt.Printf("    %d. [%s] %s\n", i+1, v.Invariant, v.Error)
		}
		if violationCount > int64(len(violations)) {
			fmt.Printf("    … and %d more (see %s for every snapshot)\n", violationCount-int64(len(violations)), *outDir)
		}
	}
	fmt.Println("═══════════════════════════════════════════════════")

	if violationCount > 0 {
		os.Exit(1)
	}
}
