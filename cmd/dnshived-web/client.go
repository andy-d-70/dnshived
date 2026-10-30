// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dnshived/internal/discovery"
	"dnshived/internal/tlspin"
)

// errNodeBelievedOffline is the synthetic error fetchAllNodes returns for
// a node the shared reachability cache already believes is dead
// (reachability.go).
var errNodeBelievedOffline = errors.New("node offline (per cluster peer reachability)")

var rawClusterTransport = &http.Transport{TLSClientConfig: tlspin.Config()}

// clusterTransport wraps the raw transport above with the
// shared node-reachability belief (reachability.go).
var clusterTransport http.RoundTripper = reachabilityRoundTripper{inner: probePinTransport}

type reachabilityRoundTripper struct {
	inner http.RoundTripper
}

func (rt reachabilityRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	addr := req.URL.Host
	if reachability.isDead(addr) {
		fb := reachability.fallbackFor(addr)
		if fb == "" {
			return nil, errNodeBelievedOffline
		}
		rerouted := req.Clone(req.Context())
		rerouted.URL.Host = fb
		rerouted.Host = fb
		return rt.inner.RoundTrip(rerouted)
	}
	resp, err := rt.inner.RoundTrip(req)
	if err != nil {
		if countsAsDead(err) {
			reachability.markDead(addr)
		}
		return resp, err
	}
	reachability.markAlive(addr)
	return resp, nil
}

// nodeStatus mirrors the subset of /api/v1/status's fields this UI needs.
type nodeStatus struct {
	NodeID      string            `json:"node_id"`
	Hostname    string            `json:"hostname"`
	Role        string            `json:"role"`
	ClusterID   string            `json:"cluster_id"`
	State       string            `json:"state"`
	Epoch       uint64            `json:"epoch"`
	Generation  uint64            `json:"generation"`
	Incarnation uint64            `json:"incarnation"`
	Healthy     bool              `json:"healthy"`
	Serving     []string          `json:"serving"`
	Watermark   map[string]uint64 `json:"watermark"`
	Version     string            `json:"version"`
	ServerTime  string            `json:"server_time"`
	ScopesHash  string            `json:"scopes_hash"`
	// ConfigHash mirrors Cluster.ConfigDocumentHash().
	ConfigHash       string            `json:"config_hash"`
	PeersVisible     []string          `json:"peers_visible"`
	PeersUnreachable []string          `json:"peers_unreachable"`
	FallbackPeers    map[string]string `json:"fallback_peers"`
	ConfiguredScopes []string          `json:"configured_scopes"`
	// IoTScopes is the subset of ConfiguredScopes with dhcp_iot_defaults set.
	IoTScopes []string `json:"iot_scopes"`
	// DisabledScopes is the subset of ConfiguredScopes with dnsmasq_disabled set.
	DisabledScopes []string `json:"disabled_scopes"`
	PlaneWarnings  []string `json:"plane_warnings"`
	StateSince     string   `json:"state_since"`
	// MgmtVIPState / HoldsMgmtVIP: this node's own last-sampled VRRP
	// state for the separate management-VIP keepalived instance.
	MgmtVIPState string `json:"mgmt_vip_state,omitempty"`
	HoldsMgmtVIP bool   `json:"holds_mgmt_vip,omitempty"`
	// Paths: this node's own view of every
	// alternate (worker-trunk) path to every other core role.
	Paths    []nodePathStatus   `json:"paths,omitempty"`
	Topology []nodeTopoSighting `json:"topology,omitempty"`
	// TopologyTrunks: trunk interfaces the node beacons on, so a trunk that
	// hears no peer at all can be flagged (see trunkPathWarnings).
	TopologyTrunks []string `json:"topology_trunks,omitempty"`
	// ScopePaths: this node's own live
	// per-scope beacon state.
	ScopePaths []nodeScopeBeaconStatus `json:"scope_paths,omitempty"`
	// ParallelProbing is only ever set by a probe host's own GET
	// /api/v1/status (cmd/dnshived-probe).
	ParallelProbing bool `json:"parallel_probing,omitempty"`
}

// nodePathStatus mirrors internal/cluster.FallbackStatus's own JSON shape.
type nodePathStatus struct {
	Role      string `json:"role"`
	Parent    string `json:"parent"`
	Addr      string `json:"addr"`
	Reachable bool   `json:"reachable"`
	LastError string `json:"last_error,omitempty"`
	// Score (0-100, higher = more trusted) — see internal/cluster.
	Score int `json:"score"`
}

// nodeTopoSighting mirrors internal/topobeacon.Sighting's own JSON shape.
type nodeTopoSighting struct {
	MyIface   string    `json:"my_iface"`
	MyKind    string    `json:"my_kind"`
	PeerRole  string    `json:"peer_role"`
	PeerIface string    `json:"peer_iface"`
	PeerKind  string    `json:"peer_kind"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int64     `json:"count"`
}

// nodeScopeBeaconStatus mirrors internal/topobeacon.ScopeStatus's own JSON
// shape.
type nodeScopeBeaconStatus struct {
	Scope             string    `json:"scope"`
	PeerRole          string    `json:"peer_role"`
	Reachable         bool      `json:"reachable"`
	ConsecutiveMisses int       `json:"consecutive_misses"`
	LastChecked       time.Time `json:"last_checked"`
	Parent            string    `json:"parent,omitempty"`
	VLANID            int       `json:"vlan_id,omitempty"`
}

// probeResult mirrors an external probe host's GET /api/v1/probe/<scope>
// response shape (cmd/dnshived-probe's own API).
type probeResult struct {
	Scope    string `json:"scope"`
	ProbedAt string `json:"probed_at"`
	// Pending is true before a probe host's own sweep ticker has completed its
	// first tick (e.g. right after a restart).
	Pending bool `json:"pending"`
	// Enabled is false when a scope opted out of probing (e.g. the record-
	// level config.DNSRecord.ProbeDisabled).
	Enabled   bool `json:"enabled"`
	Reachable bool `json:"reachable"`
	DHCP      struct {
		Verdict string   `json:"verdict"`
		Servers []string `json:"servers"`
		Error   string   `json:"error"`
		Valid   bool     `json:"valid"`
		Reason  string   `json:"reason,omitempty"`
		// Offers is the actual offered lease IP per responding server.
		Offers []probeDHCPOffer `json:"offers,omitempty"`
	} `json:"dhcp"`
	DNS struct {
		Answered  bool   `json:"answered"`
		LatencyMS int64  `json:"latency_ms"`
		Error     string `json:"error"`
		Valid     bool   `json:"valid"`
		Reason    string `json:"reason,omitempty"`
	} `json:"dns"`
	// DNSChecks is the full per-record detail (name/type/expected/got) behind
	// the single-check DNS summary above.
	DNSChecks []probeDNSCheck `json:"dns_checks,omitempty"`
	// QueueWaitMS is only ever set by a "probe now" on-demand trigger, never
	// the regular sweep.
	QueueWaitMS int64 `json:"queue_wait_ms,omitempty"`
}

// probeDHCPOffer mirrors cmd/dnshived-probe.DHCPOfferDetail.
type probeDHCPOffer struct {
	ServerID  string `json:"server_id"`
	OfferedIP string `json:"offered_ip"`
}

// probeDNSCheck mirrors cmd/dnshived-probe.DNSCheckResult.
type probeDNSCheck struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Against   string `json:"against"`
	Answered  bool   `json:"answered"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	Error     string `json:"error,omitempty"`
	Skipped   string `json:"skipped,omitempty"`
	Expected  string `json:"expected,omitempty"`
	Got       string `json:"got,omitempty"`
	Valid     bool   `json:"valid,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// daemonStatus mirrors GET /api/v1/daemons's per-unit entry shape (see
// internal/daemonstatus and cmd/dnshived/main.go).
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

// event mirrors one GET /api/v1/events entry (internal/eventlog.Event).
type event struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"ts"`
	Level     string    `json:"level"`
	Prefix    string    `json:"prefix"`
	Message   string    `json:"message"`
	NodeID    string    `json:"node_id"`
}

// systemInfo mirrors GET /api/v1/system's response shape
// (internal/sysinfo.Info).
type systemInfo struct {
	LoadAvg1  float64 `json:"load_avg_1"`
	LoadAvg5  float64 `json:"load_avg_5"`
	MemPct    int     `json:"memory_used_pct"`
	UptimeSec int64   `json:"uptime_seconds"`
	OS        string  `json:"os,omitempty"`
}

// tokenInfo mirrors one entry of GET /api/v1/token/status (arbiter only).
type tokenInfo struct {
	Owner     string `json:"owner"`
	ExpiresAt string `json:"expires_at"`
	Expired   bool   `json:"expired"`
}

// authorityCheck mirrors GET /api/v1/authority/<scope>'s response shape
// (internal/agent.AuthorityCheck).
type authorityCheck struct {
	Scope         string `json:"scope"`
	Allowed       bool   `json:"allowed"`
	Serving       bool   `json:"serving"`
	Decision      string `json:"decision"`
	Reason        string `json:"reason"`
	PrimaryReason string `json:"primary_reason"`
	EvaluatedAt   string `json:"evaluated_at"`
	Checks        []struct {
		Name   string `json:"name"`
		Pass   bool   `json:"pass"`
		Detail string `json:"detail"`
	} `json:"checks"`
}

var httpClient = &http.Client{Timeout: 5 * time.Second, Transport: clusterTransport}

// clusterSnapshotHTTPClient is fetchClusterSnapshot's own dedicated
// client, needing a real margin over the plain httpClient's 5s.
var clusterSnapshotHTTPClient = &http.Client{Timeout: 10 * time.Second, Transport: clusterTransport}

// coordinatorPushClient is pushConfigViaCoordinator's own dedicated
// client.
var coordinatorPushClient = &http.Client{Timeout: 30 * time.Second, Transport: clusterTransport}

// directHTTPClient bypasses the shared reachability belief cache entirely
// (the pin router, not the reachability-wrapped one httpClient uses).
var directHTTPClient = &http.Client{Timeout: 5 * time.Second, Transport: probePinTransport}

func doGet(cl *http.Client, node NodeConfig, path string, v interface{}) (status int, err error) {
	req, err := http.NewRequest(http.MethodGet, node.baseURL()+path, nil)
	if err != nil {
		return 0, err
	}
	if node.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+node.AdminToken)
	}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, err
	}
	if err := json.Unmarshal(body, v); err != nil {
		snippet := strings.TrimSpace(string(body))
		if len(snippet) > 60 {
			snippet = snippet[:60] + "…"
		}
		return resp.StatusCode, fmt.Errorf("HTTP %s, not a JSON answer (%s: %q)", resp.Status, resp.Header.Get("Content-Type"), snippet)
	}
	return resp.StatusCode, nil
}

func fetchDiscoveredNodes(node NodeConfig) []discovery.Candidate {
	var candidates []discovery.Candidate
	if _, err := doGet(httpClient, node, "/api/v1/discovered-nodes", &candidates); err != nil {
		return nil
	}
	return candidates
}

// clusterSnapshotResponse/clusterSnapshotNode mirror GET
// /api/v1/cluster/snapshot's wire shape (cmd/dnshived's own
// cluster_snapshot.go).
type clusterSnapshotResponse struct {
	Self  clusterSnapshotNode            `json:"self"`
	Peers map[string]clusterSnapshotNode `json:"peers"`
	// Tokens is GET /api/v1/token/status's own response, fetched server-side
	// from self's own loopback address.
	Tokens json.RawMessage `json:"tokens,omitempty"`
}

type clusterSnapshotNode struct {
	Status  json.RawMessage `json:"status,omitempty"`
	System  json.RawMessage `json:"system,omitempty"`
	Events  json.RawMessage `json:"events,omitempty"`
	Daemons json.RawMessage `json:"daemons,omitempty"`
	Error   string          `json:"error,omitempty"`
	// Via is "fallback" when the daemon fetched this node's bundle over its
	// scope-VLAN fallback address because its mgmt path is down.
	Via string `json:"via,omitempty"`
}

// fetchClusterSnapshot calls GET /api/v1/cluster/snapshot on entry.
// While someone uses the UI, refreshSnapshotLoop keeps the cached copy
// younger than snapshotRefreshAfter, so a page never waits for the cores;
// pages accept a copy up to snapshotMaxServeAge old in that case.
const (
	clusterSnapshotCacheTTL = 3 * time.Second
	snapshotRefreshAfter    = 4 * time.Second
	snapshotMaxServeAge     = 6 * time.Second
	uiActiveWindow          = 2 * time.Minute
)

var (
	clusterSnapshotCacheMu   sync.Mutex
	clusterSnapshotCacheAt   time.Time
	clusterSnapshotCacheAddr string
	clusterSnapshotCacheResp clusterSnapshotResponse
	clusterSnapshotCacheOK   bool

	lastUIActivity atomic.Int64
)

// noteUIActivity marks that an operator is using the UI right now.
func noteUIActivity() { lastUIActivity.Store(time.Now().UnixNano()) }

func uiActive() bool {
	return time.Since(time.Unix(0, lastUIActivity.Load())) < uiActiveWindow
}

func fetchClusterSnapshot(entry NodeConfig) (clusterSnapshotResponse, bool) {
	maxAge := clusterSnapshotCacheTTL
	if uiActive() {
		maxAge = snapshotMaxServeAge
	}
	clusterSnapshotCacheMu.Lock()
	if clusterSnapshotCacheAddr == entry.Addr && time.Since(clusterSnapshotCacheAt) < maxAge {
		resp, ok := clusterSnapshotCacheResp, clusterSnapshotCacheOK
		clusterSnapshotCacheMu.Unlock()
		return resp, ok
	}
	clusterSnapshotCacheMu.Unlock()
	return fetchClusterSnapshotFresh(entry)
}

func fetchClusterSnapshotFresh(entry NodeConfig) (clusterSnapshotResponse, bool) {
	var resp clusterSnapshotResponse
	status, err := doGet(clusterSnapshotHTTPClient, entry, "/api/v1/cluster/snapshot", &resp)
	ok := err == nil && status == http.StatusOK
	if ok && len(resp.Self.Status) == 0 && resp.Self.Error == "" {
		ok = false
	}
	if !ok {
		resp = clusterSnapshotResponse{}
	}

	clusterSnapshotCacheMu.Lock()
	clusterSnapshotCacheAddr = entry.Addr
	clusterSnapshotCacheAt = time.Now()
	clusterSnapshotCacheResp = resp
	clusterSnapshotCacheOK = ok
	clusterSnapshotCacheMu.Unlock()

	return resp, ok
}

// refreshSnapshotLoop refreshes the cluster snapshot in the background
// while the UI is in use, and does nothing while it is idle.
func refreshSnapshotLoop(ref *configRef) {
	for range time.Tick(500 * time.Millisecond) {
		if !uiActive() {
			continue
		}
		self, ok := selfNodeConfig(ref.Load())
		if !ok {
			continue
		}
		clusterSnapshotCacheMu.Lock()
		age := time.Since(clusterSnapshotCacheAt)
		same := clusterSnapshotCacheAddr == self.Addr
		clusterSnapshotCacheMu.Unlock()
		if !same || age >= snapshotRefreshAfter {
			fetchClusterSnapshotFresh(self)
		}
	}
}

func resolveClusterSnapshot(cfg *WebConfig, nodes []NodeConfig) (byAddr map[string]clusterSnapshotNode, snap clusterSnapshotResponse, ok bool) {
	self, ok := selfNodeConfig(cfg)
	if !ok {
		return nil, clusterSnapshotResponse{}, false
	}
	snap, ok = fetchClusterSnapshot(self)
	if !ok {
		return nil, clusterSnapshotResponse{}, false
	}
	byAddr = make(map[string]clusterSnapshotNode, 1+len(snap.Peers))
	byAddr[self.Addr] = snap.Self
	for addr, sn := range snap.Peers {
		byAddr[addr] = sn
	}
	for _, n := range nodes {
		if _, found := byAddr[n.Addr]; !found {
			return nil, clusterSnapshotResponse{}, false
		}
	}
	return byAddr, snap, true
}

// fetchAllDaemons is every core-node daemon-list fetch's shared tiered
// call (checkDaemonHealth, handleDaemons' core-node half,
// ownerDaemonUptime).
func fetchAllDaemons(cfg *WebConfig, nodes []NodeConfig) []nodeResult[daemonsResponse] {
	if results, ok := fetchAllDaemonsViaSnapshot(cfg, nodes); ok {
		return results
	}
	return fetchAllNodes(nodes, fetchDaemons)
}

func fetchAllDaemonsViaSnapshot(cfg *WebConfig, nodes []NodeConfig) ([]nodeResult[daemonsResponse], bool) {
	byAddr, _, ok := resolveClusterSnapshot(cfg, nodes)
	if !ok {
		return nil, false
	}
	fetchedAt := time.Now()
	results := make([]nodeResult[daemonsResponse], len(nodes))
	for i, n := range nodes {
		sn := byAddr[n.Addr]
		res := nodeResult[daemonsResponse]{Node: n, FetchedAt: fetchedAt}
		switch {
		case sn.Error != "":
			res.Err = errors.New(sn.Error)
		case len(sn.Daemons) == 0:
			res.Err = errors.New("daemons not available in cluster snapshot")
		default:
			var dr daemonsResponse
			if err := json.Unmarshal(sn.Daemons, &dr); err != nil {
				res.Err = err
			} else {
				res.Value = dr
			}
		}
		results[i] = res
	}
	return results, true
}

// fetchAllEvents is Logs' shared tiered call for core nodes.
func fetchAllEvents(cfg *WebConfig, nodes []NodeConfig, n int) ([]nodeResult[[]event], bool) {
	byAddr, _, ok := resolveClusterSnapshot(cfg, nodes)
	if !ok || n != logsFetchPerNode {
		return nil, false
	}
	fetchedAt := time.Now()
	results := make([]nodeResult[[]event], len(nodes))
	for i, node := range nodes {
		sn := byAddr[node.Addr]
		res := nodeResult[[]event]{Node: node, FetchedAt: fetchedAt}
		switch {
		case sn.Error != "":
			res.Err = errors.New(sn.Error)
		case len(sn.Events) == 0:
		default:
			var evts []event
			if err := json.Unmarshal(sn.Events, &evts); err != nil {
				res.Err = err
			} else {
				res.Value = evts
			}
		}
		results[i] = res
	}
	return results, true
}

// releaseLease calls POST /api/v1/leases/<scope>/release on node.
func releaseLease(node NodeConfig, scope, mac, ip string) error {
	form := url.Values{"mac": {mac}, "ip": {ip}}
	req, err := http.NewRequest(http.MethodPost, node.baseURL()+"/api/v1/leases/"+url.PathEscape(scope)+"/release", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if node.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+node.AdminToken)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("release lease: node returned status %d", resp.StatusCode)
	}
	return nil
}

// refreshProbeClient is a dedicated, longer-timeout client for
// triggerProbeNow only.
var refreshProbeClient = &http.Client{Timeout: 30 * time.Second, Transport: clusterTransport}

// triggerProbeNow calls POST /api/v1/probe/<scope>/refresh on node.
func triggerProbeNow(node NodeConfig, scope string) (probeResult, error) {
	var pr probeResult
	req, err := http.NewRequest(http.MethodPost, node.baseURL()+"/api/v1/probe/"+url.PathEscape(scope)+"/refresh", nil)
	if err != nil {
		return pr, err
	}
	if node.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+node.AdminToken)
	}
	resp, err := refreshProbeClient.Do(req)
	if err != nil {
		return pr, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return pr, fmt.Errorf("a probe for this scope is already running — try again shortly")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return pr, fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return pr, err
	}
	return pr, nil
}

// restartUnitPath returns the downstream restart endpoint for node.
func restartUnitPath(unit string, isProbeHost bool) string {
	if isProbeHost {
		return "/api/v1/restart"
	}
	return "/api/v1/daemons/" + url.PathEscape(unit) + "/restart"
}

func restartUnit(node NodeConfig, unit string, isProbeHost bool) (throttled bool, err error) {
	req, err := http.NewRequest(http.MethodPost, node.baseURL()+restartUnitPath(unit, isProbeHost), nil)
	if err != nil {
		return false, err
	}
	if node.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+node.AdminToken)
	}
	resp, err := refreshProbeClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}
	var result struct {
		Throttled bool `json:"throttled"`
	}
	json.NewDecoder(resp.Body).Decode(&result) // best-effort — a 202 self-restart body may never fully arrive
	return result.Throttled, nil
}

// restartWaitTimeout bounds how long waitNodeStable will poll a
// just-restarted node before giving up and reporting it as a real,
// explicit warning.
const restartWaitTimeout = 60 * time.Second

func waitNodeStable(node NodeConfig, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if st, err := fetchStatus(node); err == nil && st.State == "STABLE" {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("did not reach STABLE within %s", timeout)
		}
		time.Sleep(2 * time.Second)
	}
}

func pushProbeHostParallelProbing(node NodeConfig, enabled bool) error {
	body, err := json.Marshal(map[string]bool{"parallel_probing": enabled})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, node.baseURL()+"/api/v1/config", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if node.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+node.AdminToken)
	}
	resp, err := refreshProbeClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// probeClusterNodePatch mirrors cmd/dnshived-probe's own ClusterNode wire
// shape ({name,addr,tls}).
type probeClusterNodePatch struct {
	Name string `json:"name"`
	Addr string `json:"addr"`
	TLS  bool   `json:"tls"`
}

func pushProbeHostClusterNodes(probe NodeConfig, nodes []probeClusterNodePatch) error {
	body, err := json.Marshal(map[string]interface{}{"cluster_nodes": nodes})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, probe.baseURL()+"/api/v1/config", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if probe.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+probe.AdminToken)
	}
	resp, err := refreshProbeClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func fetchStatus(node NodeConfig) (nodeStatus, error) {
	var s nodeStatus
	status, err := doGet(httpClient, node, "/api/v1/status", &s)
	if err != nil {
		return s, err
	}
	if status != http.StatusOK {
		return s, fmt.Errorf("status %d", status)
	}
	return s, nil
}

// fetchDaemons calls GET /api/v1/daemons — no server-side rate limit
// (local systemctl query only), safe to poll on every page load.
func fetchDaemons(node NodeConfig) (daemonsResponse, error) {
	var d daemonsResponse
	status, err := doGet(httpClient, node, "/api/v1/daemons", &d)
	if err != nil {
		return d, err
	}
	if status != http.StatusOK {
		return d, fmt.Errorf("status %d", status)
	}
	return d, nil
}

// dnsRelayStatsResult mirrors cmd/dnshived's own dnsRelayStatsResponse
// wire shape.
type dnsRelayStatsResult struct {
	Available     bool    `json:"available"`
	Entries       int     `json:"entries,omitempty"`
	CacheSize     int     `json:"cache_size,omitempty"`
	CacheMaxBytes int     `json:"cache_max_bytes,omitempty"`
	BytesUsed     int64   `json:"bytes_used,omitempty"`
	Hits          uint64  `json:"hits,omitempty"`
	Misses        uint64  `json:"misses,omitempty"`
	HitRatePct    float64 `json:"hit_rate_pct,omitempty"`
	UpdatedAt     string  `json:"updated_at,omitempty"`
}

// fetchDNSRelayStats calls GET /api/v1/dnsrelay-stats.
func fetchDNSRelayStats(node NodeConfig) (dnsRelayStatsResult, error) {
	var s dnsRelayStatsResult
	status, err := doGet(httpClient, node, "/api/v1/dnsrelay-stats", &s)
	if err != nil {
		return s, err
	}
	if status != http.StatusOK {
		return s, fmt.Errorf("status %d", status)
	}
	return s, nil
}

// fetchEvents calls GET /api/v1/events?n=<n> — no server-side rate
// limit.
func fetchEvents(node NodeConfig, n int) ([]event, error) {
	var evts []event
	status, err := doGet(httpClient, node, fmt.Sprintf("/api/v1/events?n=%d", n), &evts)
	if err != nil {
		return evts, err
	}
	if status != http.StatusOK {
		return evts, fmt.Errorf("status %d", status)
	}
	return evts, nil
}

// fetchDnsmasqLog calls GET /api/v1/dnsmasq-log/<scope>?n=<n> on a core
// node.
func fetchDnsmasqLog(node NodeConfig, scope string, n int) ([]string, error) {
	lines, _, err := fetchDnsmasqLogFull(node, scope, n)
	return lines, err
}

// fetchDnsmasqLogFull is fetchDnsmasqLog's full-response counterpart.
func fetchDnsmasqLogFull(node NodeConfig, scope string, n int) (lines []string, note string, err error) {
	var out struct {
		Lines []string `json:"lines"`
		Note  string   `json:"note,omitempty"`
	}
	status, err := doGet(httpClient, node, fmt.Sprintf("/api/v1/dnsmasq-log/%s?n=%d", url.PathEscape(scope), n), &out)
	if err != nil {
		return nil, "", err
	}
	if status != http.StatusOK {
		return nil, "", fmt.Errorf("status %d", status)
	}
	return out.Lines, out.Note, nil
}

// fetchDaemonLog calls GET /api/v1/daemon-log/<unit>?n=<n>.
func fetchDaemonLog(node NodeConfig, unit string, n int) ([]string, error) {
	var out struct {
		Lines []string `json:"lines"`
	}
	status, err := doGet(httpClient, node, fmt.Sprintf("/api/v1/daemon-log/%s?n=%d", url.PathEscape(unit), n), &out)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("status %d", status)
	}
	return out.Lines, nil
}

// dnsmasqLease mirrors GET /api/v1/leases/{scope}'s per-entry shape
// (internal/dhcplease.Lease on the daemon side).
type dnsmasqLease struct {
	Expiry       time.Time `json:"expiry"`
	NeverExpires bool      `json:"never_expires"`
	MAC          string    `json:"mac"`
	IP           string    `json:"ip"`
	Hostname     string    `json:"hostname,omitempty"`
	ClientID     string    `json:"client_id,omitempty"`
}

// fetchDnsmasqLeases calls GET /api/v1/leases/<scope> on a core node.
func fetchDnsmasqLeases(node NodeConfig, scope string) ([]dnsmasqLease, error) {
	var out struct {
		Leases []dnsmasqLease `json:"leases"`
	}
	status, err := doGet(httpClient, node, "/api/v1/leases/"+url.PathEscape(scope), &out)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("status %d", status)
	}
	return out.Leases, nil
}

// fetchProbe calls GET /api/v1/probe/<scope> on an external probe host.
func fetchProbe(node NodeConfig, scope string) (probeResult, error) {
	var pr probeResult
	_, err := doGet(httpClient, node, "/api/v1/probe/"+url.PathEscape(scope), &pr)
	if err != nil {
		return pr, err
	}
	return pr, nil
}

// fetchSystem calls GET /api/v1/system — no server-side rate limit.
func fetchSystem(node NodeConfig) (systemInfo, error) {
	var si systemInfo
	status, err := doGet(httpClient, node, "/api/v1/system", &si)
	if err != nil {
		return si, err
	}
	if status != http.StatusOK {
		return si, fmt.Errorf("status %d", status)
	}
	return si, nil
}

// fetchTokenStatus calls GET /api/v1/token/status.
func fetchTokenStatus(node NodeConfig) (map[string]tokenInfo, error) {
	tokens := make(map[string]tokenInfo)
	status, err := doGet(httpClient, node, "/api/v1/token/status", &tokens)
	if err != nil {
		return tokens, err
	}
	if status != http.StatusOK {
		return tokens, fmt.Errorf("status %d", status)
	}
	return tokens, nil
}

// fetchAuthority calls GET /api/v1/authority/<scope> — no server-side
// rate limit (pure computation over cached state).
func fetchAuthority(node NodeConfig, scope string) (authorityCheck, error) {
	var ac authorityCheck
	status, err := doGet(httpClient, node, "/api/v1/authority/"+url.PathEscape(scope), &ac)
	if err != nil {
		return ac, err
	}
	if status != http.StatusOK {
		return ac, fmt.Errorf("status %d", status)
	}
	return ac, nil
}

// nodeResult pairs one node with a concurrently-fetched value (or the
// error from fetching it).
type nodeResult[T any] struct {
	Node  NodeConfig
	Value T
	Err   error
	// FetchedAt is the local wall-clock moment THIS node's own fetch returned
	// — captured per-goroutine, not once after the whole batch joins.
	FetchedAt time.Time
}

// fetchAllNodes polls every node concurrently, one goroutine per node
// writing its own preallocated index (no mutex needed).
func fetchAllNodes[T any](nodes []NodeConfig, fetch func(NodeConfig) (T, error)) []nodeResult[T] {
	results := make([]nodeResult[T], len(nodes))
	var wg sync.WaitGroup
	for i, n := range nodes {
		wg.Add(1)
		go func(i int, n NodeConfig) {
			defer wg.Done()
			if reachability.isDead(n.Addr) && !reachability.viaFallback(n.Addr) {
				var zero T
				results[i] = nodeResult[T]{
					Node:      n,
					Value:     zero,
					Err:       errNodeBelievedOffline,
					FetchedAt: time.Now(),
				}
				return
			}
			v, err := fetch(n)
			results[i] = nodeResult[T]{Node: n, Value: v, Err: err, FetchedAt: time.Now()}
		}(i, n)
	}
	wg.Wait()
	return results
}

func pushConfig(node NodeConfig, payload []byte) (status int, respBody []byte, err error) {
	req, err := http.NewRequest(http.MethodPost, node.baseURL()+"/api/v1/config", bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if node.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+node.AdminToken)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBody, err = io.ReadAll(resp.Body)
	return resp.StatusCode, respBody, err
}

// pushAudit records one audit entry on one node via POST /api/v1/audit.
func pushAudit(node NodeConfig, actor, action, summary string) error {
	payload, err := json.Marshal(map[string]string{
		"actor": actor, "action": action, "summary": summary,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, node.baseURL()+"/api/v1/audit", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if node.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+node.AdminToken)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}
