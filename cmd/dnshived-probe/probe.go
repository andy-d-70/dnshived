// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"dnshived/internal/config"
	"dnshived/internal/dhcpprobe"
	"dnshived/internal/dnsprobe"
	"dnshived/internal/eventlog"
)

// DHCPOfferDetail is one real DHCPOFFER's server-id paired with the lease
// IP it actually offered.
type DHCPOfferDetail struct {
	ServerID  string `json:"server_id"`
	OfferedIP string `json:"offered_ip"`
}

// DNSCheckResult is one (name, type) query's outcome — either from a
// scope's own config.DNSRecords or from the cluster-wide
// config.EffectiveDefaultDNSChecks().
type DNSCheckResult struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Against   string `json:"against"` // which worker's address this was queried against
	Answered  bool   `json:"answered"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	Error     string `json:"error,omitempty"`
	Skipped   string `json:"skipped,omitempty"` // reason, e.g. "type FOO not supported"
	Expected  string `json:"expected,omitempty"`
	Got       string `json:"got,omitempty"`
	Valid     bool   `json:"valid,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// dnsRcodeName renders a raw DNS RCODE (RFC 1035/2136 §2.3) as the short
// mnemonic operators actually recognize.
func dnsRcodeName(rcode int) string {
	switch rcode {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", rcode)
	}
}

// ScopeProbeResult is one scope's full probe outcome.
type ScopeProbeResult struct {
	Scope string `json:"scope"`

	// Enabled is always true for a stored result.
	Enabled bool `json:"enabled"`

	DHCP struct {
		Verdict string   `json:"verdict"`
		Servers []string `json:"servers"`
		Error   string   `json:"error"`
		// Valid cross-checks DHCP.Servers against the arbiter's live token holder
		// (GET /api/v1/token/status), not the scope's static preferred_worker.
		Valid  bool   `json:"valid"`
		Reason string `json:"reason,omitempty"` // why Valid is false, or empty when Valid or unknown
		// Offers is every DHCPOFFER actually received, paired with what each
		// server offered.
		Offers []DHCPOfferDetail `json:"offers,omitempty"`
	} `json:"dhcp"`

	// DNS mirrors the single default-check shape existing tools already decode
	// (agent.DNSProbeSummary).
	DNS struct {
		Answered  bool   `json:"answered"`
		LatencyMS int64  `json:"latency_ms"`
		Error     string `json:"error"`
		Valid     bool   `json:"valid"`
		Reason    string `json:"reason,omitempty"`
	} `json:"dns"`

	DNSChecks []DNSCheckResult `json:"dns_checks"`

	Reachable bool      `json:"reachable"` // false if this host has no local interface for the scope's VLAN
	ProbedAt  time.Time `json:"probed_at"`

	// QueueWaitMS is only ever set by probeScopeNow (the on-demand "probe now"
	// trigger).
	QueueWaitMS int64 `json:"queue_wait_ms,omitempty"`
}

type resultStore struct {
	mu      sync.Mutex
	results map[string]ScopeProbeResult
}

func newResultStore() *resultStore {
	return &resultStore{results: make(map[string]ScopeProbeResult)}
}

func (s *resultStore) set(scope string, r ScopeProbeResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results[scope] = r
}

func (s *resultStore) get(scope string) (ScopeProbeResult, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.results[scope]
	return r, ok
}

// delete drops just scope's own stored result, reverting it to "pending"
// on the next GET /api/v1/probe/<scope>.
func (s *resultStore) delete(scope string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.results, scope)
}

func (s *resultStore) prune(keep map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name := range s.results {
		if !keep[name] {
			delete(s.results, name)
		}
	}
}

func (s *resultStore) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results = make(map[string]ScopeProbeResult)
}

func (s *resultStore) all() map[string]ScopeProbeResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]ScopeProbeResult, len(s.results))
	for k, v := range s.results {
		out[k] = v
	}
	return out
}

func isOwnershipOnlyFailure(r ScopeProbeResult) bool {
	return r.Reachable && r.Enabled && r.DHCP.Verdict == string(dhcpprobe.VerdictOK) && !r.DHCP.Valid
}

type ownershipDebounce struct {
	mu     sync.Mutex
	streak map[string]int
}

func newOwnershipDebounce() *ownershipDebounce {
	return &ownershipDebounce{streak: make(map[string]int)}
}

// recordFailure increments and returns scope's own consecutive-
// ownership-failure count.
func (d *ownershipDebounce) recordFailure(scope string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.streak[scope]++
	return d.streak[scope]
}

// reset clears scope's streak.
func (d *ownershipDebounce) reset(scope string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.streak, scope)
}

// clear drops every scope's streak.
func (d *ownershipDebounce) clear() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.streak = make(map[string]int)
}

// settleOwnershipResult is the single decision point both runProbeSweep
// and probeScopeNow route every freshly-computed result through before
// it's ever published.
func settleOwnershipResult(store *resultStore, debounce *ownershipDebounce, tracker *probeLogTracker, events *eventlog.Ring, scope string, result ScopeProbeResult) bool {
	if !isOwnershipOnlyFailure(result) {
		debounce.reset(scope)
		tracker.check(events, scope, result)
		store.set(scope, result)
		return true
	}
	if debounce.recordFailure(scope) < 2 {
		store.delete(scope)
		return false
	}
	tracker.check(events, scope, result)
	store.set(scope, result)
	return true
}

// probeLogTracker records WHY a probe failed, not just the current tick's
// snapshot.
type probeLogTracker struct {
	mu      sync.Mutex
	dhcp    map[string]string // scope -> last signature ("" = ok/unreachable)
	dns     map[string]string // "scope|name|type|against" -> last signature
	persist *probeFailureLog
}

func newProbeLogTracker(persist *probeFailureLog) *probeLogTracker {
	return &probeLogTracker{dhcp: map[string]string{}, dns: map[string]string{}, persist: persist}
}

// prune mirrors resultStore.prune.
func (t *probeLogTracker) prune(keep map[string]bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for scope := range t.dhcp {
		if !keep[scope] {
			delete(t.dhcp, scope)
		}
	}
	for key := range t.dns {
		scope, _, _ := strings.Cut(key, "|")
		if !keep[scope] {
			delete(t.dns, key)
		}
	}
}

func dhcpFailureSignature(r ScopeProbeResult) string {
	if !r.Enabled {
		return ""
	}
	switch {
	case r.DHCP.Error != "":
		return "transport error: " + r.DHCP.Error
	case r.DHCP.Verdict != "ok":
		if r.DHCP.Reason != "" {
			return r.DHCP.Reason
		}
		return "verdict: " + r.DHCP.Verdict
	case !r.DHCP.Valid:
		if r.DHCP.Reason != "" {
			return r.DHCP.Reason
		}
		return "invalid, no reason given"
	}
	return ""
}

// dnsCheckFailureSignature is dhcpFailureSignature's DNS equivalent, one
// per (name, type, against) check.
func dnsCheckFailureSignature(c DNSCheckResult) string {
	if c.Skipped != "" {
		return ""
	}
	if c.Error != "" {
		return "transport error: " + c.Error
	}
	if !c.Answered {
		return "no answer"
	}
	return ""
}

// check logs an edge-triggered transition for scope's DHCP leg and every
// one of its DNS checks, comparing against the LAST call's signatures.
func (t *probeLogTracker) check(events *eventlog.Ring, scope string, result ScopeProbeResult) {
	t.mu.Lock()
	defer t.mu.Unlock()

	sig := dhcpFailureSignature(result)
	prev := t.dhcp[scope] // zero value "" for a never-seen scope
	if sig != prev {
		var level, prefix, message string
		if sig == "" {
			level, prefix = "INFO", "PROBE:DHCP_OK"
			message = fmt.Sprintf("%s: DHCP recovered — resolved (was: %s)", scope, prev)
		} else {
			level, prefix = "WARNING", "PROBE:DHCP_FAIL"
			message = fmt.Sprintf("%s: %s", scope, sig)
		}
		events.Add(level, prefix, message)
		if err := t.persist.append(level, prefix, message); err != nil {
			log.Printf("[PROBE:EVENTLOG] persist failed: %v", err)
		}
	}
	t.dhcp[scope] = sig

	for _, c := range result.DNSChecks {
		key := scope + "|" + c.Name + "|" + c.Type + "|" + c.Against
		csig := dnsCheckFailureSignature(c)
		cprev := t.dns[key]
		if csig != cprev {
			label := fmt.Sprintf("%s (%s %s vs %s)", scope, c.Name, c.Type, c.Against)
			var level, prefix, message string
			if csig == "" {
				level, prefix = "INFO", "PROBE:DNS_OK"
				message = label + ": DNS recovered — resolved (was: " + cprev + ")"
			} else {
				level, prefix = "WARNING", "PROBE:DNS_FAIL"
				message = label + ": " + csig
			}
			events.Add(level, prefix, message)
			if err := t.persist.append(level, prefix, message); err != nil {
				log.Printf("[PROBE:EVENTLOG] persist failed: %v", err)
			}
		}
		t.dns[key] = csig
	}
}

type incarnationTracker struct {
	mu   sync.Mutex
	seen map[string]uint64 // node_id -> last-seen incarnation
}

func newIncarnationTracker() *incarnationTracker {
	return &incarnationTracker{seen: make(map[string]uint64)}
}

func (t *incarnationTracker) restarted(byNodeID map[string]probeConfigResponse) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	changed := false
	for nodeID, resp := range byNodeID {
		if prev, known := t.seen[nodeID]; known && prev != resp.Incarnation {
			changed = true
		}
		t.seen[nodeID] = resp.Incarnation
	}
	return changed
}

// refreshScopeSet is the lightweight, metadata-only half of a probe sweep.
func refreshScopeSet(cfg *ProbeConfig, store *resultStore, tracker *probeLogTracker) {
	refreshScopeSetTracking(cfg, store, tracker, newScopeSigTracker())
}

// scopeSig is the part of a scope's config that decides what its probe
// result means: which interface it probes on and whether probing is
// switched off.
type scopeSig struct {
	parent   string
	vlanID   int
	disabled bool
}

type scopeSigTracker struct {
	mu   sync.Mutex
	last map[string]scopeSig
}

func newScopeSigTracker() *scopeSigTracker {
	return &scopeSigTracker{last: map[string]scopeSig{}}
}

// changed records the current signatures and returns the scopes whose
// signature differs from the previous observation.
func (t *scopeSigTracker) changed(byNodeID map[string]probeConfigResponse) []string {
	ids := make([]string, 0, len(byNodeID))
	for id := range byNodeID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	cur := map[string]scopeSig{}
	for _, id := range ids {
		for name, sc := range byNodeID[id].Scopes {
			if _, seen := cur[name]; !seen {
				cur[name] = scopeSig{parent: sc.Parent, vlanID: sc.VLANID, disabled: sc.ProbeDisabled}
			}
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	var changed []string
	for name, sig := range cur {
		if prev, ok := t.last[name]; ok && prev != sig {
			changed = append(changed, name)
		}
	}
	t.last = cur
	sort.Strings(changed)
	return changed
}

func refreshScopeSetTracking(cfg *ProbeConfig, store *resultStore, tracker *probeLogTracker, sigs *scopeSigTracker) []string {
	byNodeID, _, err := fetchAllScopes(cfg)
	if err != nil {
		log.Printf("[PROBE:FETCH] %v", err)
		return nil
	}
	scopeNames := mergedScopeNames(byNodeID)
	keep := make(map[string]bool, len(scopeNames))
	for _, name := range scopeNames {
		keep[name] = true
	}
	store.prune(keep)
	tracker.prune(keep)
	changed := sigs.changed(byNodeID)
	for _, name := range changed {
		store.delete(name)
		log.Printf("[PROBE:CONFIG] scope %s: probe-relevant config changed — stored result cleared, re-probing now", name)
	}
	return changed
}

// runProbeSweep is this binary's equivalent of Agent.RunProbes: one full
// pass over every scope the cluster knows about, on the caller's ticker.
func runProbeSweep(cfg *ProbeConfig, store *resultStore, tracker *probeLogTracker, events *eventlog.Ring, incarnations *incarnationTracker, debounce *ownershipDebounce) {
	byNodeID, defaultChecks, err := fetchAllScopes(cfg)
	if err != nil {
		log.Printf("[PROBE:FETCH] %v", err)
		return
	}

	if incarnations.restarted(byNodeID) {
		log.Printf("[PROBE:INVALIDATE] a monitored cluster node restarted — clearing all stored results, forcing a fresh sweep")
		store.clear()
		debounce.clear()
	}

	if changed := reconcileVLANInterfaces(cfg, byNodeID); len(changed) > 0 {
		log.Printf("[PROBE:VLAN] %v", changed)
	}
	if removed := reconcileOrphanVLANs(cfg, desiredVLANs(byNodeID, cfg.trunkParents())); len(removed) > 0 {
		log.Printf("[PROBE:VLAN] %v", removed)
	}

	tokens := fetchTokens(cfg)

	scopeNames := mergedScopeNames(byNodeID)
	keep := make(map[string]bool, len(scopeNames))
	for _, name := range scopeNames {
		keep[name] = true
	}
	store.prune(keep)
	tracker.prune(keep)

	probeAndRecord := func(name string) {
		result := probeOneScope(cfg, name, byNodeID, defaultChecks, tokens, false)
		settleOwnershipResult(store, debounce, tracker, events, name, result)
	}

	if cfg.Parallel() {
		var wg sync.WaitGroup
		for _, name := range scopeNames {
			wg.Add(1)
			go func(name string) {
				defer wg.Done()
				probeAndRecord(name)
			}(name)
		}
		wg.Wait()
	} else {
		for _, name := range scopeNames {
			probeAndRecord(name)
		}
	}
}

// probeScopeNow runs an immediate, single-scope probe outside the regular
// sweep ticker.
func probeScopeNow(cfg *ProbeConfig, store *resultStore, tracker *probeLogTracker, events *eventlog.Ring, debounce *ownershipDebounce, scope string) (result ScopeProbeResult, published bool, err error) {
	byNodeID, defaultChecks, err := fetchAllScopes(cfg)
	if err != nil {
		return ScopeProbeResult{}, false, fmt.Errorf("fetch cluster scopes: %w", err)
	}
	known := false
	for _, name := range mergedScopeNames(byNodeID) {
		if name == scope {
			known = true
			break
		}
	}
	if !known {
		return ScopeProbeResult{}, false, fmt.Errorf("unknown scope %q", scope)
	}
	tokens := fetchTokens(cfg)

	probeStart := time.Now()
	result = probeOneScope(cfg, scope, byNodeID, defaultChecks, tokens, true)
	elapsed := time.Since(probeStart)

	if result.Reachable {
		expectedFloor := time.Duration(cfg.dhcpWaitMS()) * time.Millisecond
		result.QueueWaitMS = queueWaitMS(elapsed, expectedFloor)
	}

	published = settleOwnershipResult(store, debounce, tracker, events, scope, result)
	return result, published, nil
}

// queueWaitMS reports how much of elapsed sat beyond expectedFloor (the
// configured DHCP wait), clamped to zero.
func queueWaitMS(elapsed, expectedFloor time.Duration) int64 {
	if wait := elapsed - expectedFloor; wait > 0 {
		return wait.Milliseconds()
	}
	return 0
}

// fetchAllScopes polls every configured cluster node for its own view of
// GET /api/v1/probe-config, keyed by that node's own node_id.
func fetchAllScopes(cfg *ProbeConfig) (map[string]probeConfigResponse, []config.DNSCheck, error) {
	type fetchResult struct {
		resp probeConfigResponse
		err  error
	}
	results := make([]fetchResult, len(cfg.ClusterNodes))
	var wg sync.WaitGroup
	for i, n := range cfg.ClusterNodes {
		wg.Add(1)
		go func(i int, n ClusterNode) {
			defer wg.Done()
			resp, err := fetchProbeConfig(n, cfg.ClusterToken)
			results[i] = fetchResult{resp: resp, err: err}
		}(i, n)
	}
	wg.Wait()

	byNodeID := make(map[string]probeConfigResponse)
	var defaultChecks []config.DNSCheck
	var lastErr error
	for _, r := range results {
		if r.err != nil {
			lastErr = r.err
			log.Printf("[PROBE:FETCH] %v", r.err)
			continue
		}
		byNodeID[r.resp.NodeID] = r.resp
		if len(r.resp.DefaultDNSChecks) > 0 {
			defaultChecks = r.resp.DefaultDNSChecks
		}
	}
	if len(byNodeID) == 0 {
		return nil, nil, fmt.Errorf("no cluster node answered probe-config: %w", lastErr)
	}
	return byNodeID, defaultChecks, nil
}

func fetchTokens(cfg *ProbeConfig) map[string]tokenInfo {
	nodes := make([]ClusterNode, 0, len(cfg.ClusterNodes))
	for _, n := range cfg.ClusterNodes {
		if n.Name == "core-3" {
			nodes = append([]ClusterNode{n}, nodes...)
		} else {
			nodes = append(nodes, n)
		}
	}
	for _, n := range nodes {
		tokens, err := fetchTokenStatus(n, cfg.ClusterToken)
		if err == nil {
			return tokens
		}
		log.Printf("[PROBE:TOKEN] %v", err)
	}
	return map[string]tokenInfo{}
}

func mergedScopeNames(byNodeID map[string]probeConfigResponse) []string {
	seen := make(map[string]bool)
	var names []string
	for _, resp := range byNodeID {
		for name := range resp.Scopes {
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	return names
}

// isCoreRole reports whether role is one of the 3 real core roles.
func isCoreRole(role string) bool {
	switch role {
	case config.RoleCore1, config.RoleCore2, config.RoleCore3:
		return true
	default:
		return false
	}
}

// ifaceExistsFn checks whether a named interface exists on this host.
var ifaceExistsFn = func(name string) (*net.Interface, error) { return net.InterfaceByName(name) }

func clusterConvergence(cfg *ProbeConfig) (converged bool, served, total int) {
	type fetchResult struct {
		resp remoteStatus
		err  error
	}
	results := make([]fetchResult, len(cfg.ClusterNodes))
	var wg sync.WaitGroup
	for i, n := range cfg.ClusterNodes {
		wg.Add(1)
		go func(i int, n ClusterNode) {
			defer wg.Done()
			resp, err := fetchStatus(n, cfg.ClusterToken)
			results[i] = fetchResult{resp: resp, err: err}
		}(i, n)
	}
	wg.Wait()

	configuredSet := make(map[string]bool)
	servingSet := make(map[string]bool)
	anySucceeded := false
	for _, r := range results {
		if r.err != nil {
			continue
		}
		anySucceeded = true
		for _, s := range r.resp.ConfiguredScopes {
			configuredSet[s] = true
		}
		for _, s := range r.resp.Serving {
			servingSet[s] = true
		}
	}
	total = len(configuredSet)
	for s := range configuredSet {
		if servingSet[s] {
			served++
		}
	}
	if len(cfg.ClusterNodes) > 0 && !anySucceeded {
		return false, served, total
	}
	return served >= total, served, total
}

// waitForConvergence blocks until every configured scope has a real
// server, or a bounded max wait elapses.
func waitForConvergence(cfg *ProbeConfig) {
	deadline := time.Now().Add(convergenceMaxWait)
	for {
		converged, served, total := clusterConvergence(cfg)
		if total == 0 || converged {
			log.Printf("[PROBE:INIT] cluster converged (%d/%d scope(s) served) — starting regular probing", served, total)
			return
		}
		if time.Now().After(deadline) {
			log.Printf("[PROBE:INIT] WARNING: cluster still not fully converged after %s (%d/%d scope(s) served) — starting regular probing anyway", convergenceMaxWait, served, total)
			return
		}
		log.Printf("[PROBE:INIT] waiting for cluster convergence before probing: %d/%d scope(s) served", served, total)
		time.Sleep(convergencePollInterval)
	}
}

const (
	convergencePollInterval = 5 * time.Second
	convergenceMaxWait      = 5 * time.Minute
)

func probeDHCPOptions(iface string) dhcpprobe.Options {
	opts := dhcpprobe.DefaultOptions()
	ifi, err := net.InterfaceByName(iface)
	if err != nil || len(ifi.HardwareAddr) != 6 {
		return opts
	}
	opts.MAC = ifi.HardwareAddr
	return opts
}

// probeOneScope runs the full DHCP + DNS check set for one scope.
func probeOneScope(cfg *ProbeConfig, name string, byNodeID map[string]probeConfigResponse, defaultChecks []config.DNSCheck, tokens map[string]tokenInfo, priority bool) ScopeProbeResult {
	result := ScopeProbeResult{Scope: name, ProbedAt: time.Now()}

	var vlanID int
	var parent string
	var dnsRecords []config.DNSRecord
	var probeDisabled bool
	for _, resp := range byNodeID {
		if sc, ok := resp.Scopes[name]; ok {
			vlanID = sc.VLANID
			parent = sc.Parent
			dnsRecords = sc.DNSRecords
			probeDisabled = sc.ProbeDisabled
			break
		}
	}
	if parent == "" {
		parent = cfg.TrunkParent
	}

	iface := realIfaceName(parent, vlanID)
	if _, err := ifaceExistsFn(iface); err != nil {
		result.Reachable = false
		return result
	}
	result.Reachable = true

	if probeDisabled {
		return result
	}
	result.Enabled = true

	probeScheduler.Submit(parent, priority, func() {
		dhcpResult, err := dhcpprobe.ProbeWithOptions(iface, time.Duration(cfg.dhcpWaitMS())*time.Millisecond, probeDHCPOptions(iface))
		if err != nil {
			result.DHCP.Error = err.Error()
		} else {
			result.DHCP.Verdict = string(dhcpResult.Verdict)
			result.DHCP.Servers = dhcpResult.Servers
			result.DHCP.Valid, result.DHCP.Reason = validateDHCPAnswer(name, dhcpResult, byNodeID, tokens)
			result.DHCP.Offers = dhcpOffersToDetails(dhcpResult.Offers)
		}

		if len(defaultChecks) == 0 {
			defaultChecks = []config.DNSCheck{{Name: config.DefaultDNSCheckName, Type: config.DefaultDNSCheckType}}
		}

		for _, resp := range byNodeID {
			if !isCoreRole(resp.Role) {
				continue
			}
			sc, ok := resp.Scopes[name]
			if !ok || sc.NodeIP == "" {
				continue
			}
			addr, err := netip.ParsePrefix(sc.NodeIP)
			target := sc.NodeIP
			if err == nil {
				target = addr.Addr().String()
			}

			hasUpstream := resp.ClusterHasUpstream
			for _, chk := range defaultChecks {
				result.DNSChecks = append(result.DNSChecks, runOneDNSCheck(target, chk.Name, chk.Type, nil, hasUpstream))
			}
			for _, rec := range dnsRecords {
				if rec.ProbeDisabled {
					continue
				}
				result.DNSChecks = append(result.DNSChecks, runOneDNSCheck(target, rec.Name, rec.Type, &rec, hasUpstream))
			}
		}

		for _, c := range result.DNSChecks {
			if c.Skipped != "" {
				continue
			}
			result.DNS.Answered = c.Answered
			result.DNS.LatencyMS = c.LatencyMS
			result.DNS.Error = c.Error
			result.DNS.Valid = c.Valid
			result.DNS.Reason = c.Reason
			break
		}
	})

	return result
}

// dnsProbeFn is runOneDNSCheck's actual query call.
var dnsProbeFn = dnsprobe.Probe

// runOneDNSCheck runs a single (name, type) query against target.
func runOneDNSCheck(target, name, qtype string, expected *config.DNSRecord, hasUpstream bool) DNSCheckResult {
	r := DNSCheckResult{Name: name, Type: qtype, Against: target}
	queryType := qtype
	if strings.EqualFold(qtype, "RAW") && expected != nil {
		queryType = strconv.Itoa(expected.RRType)
	}
	res, err := dnsProbeFn(target, name, queryType, 5*time.Second)
	if err != nil {
		if strings.Contains(err.Error(), "unsupported query type") {
			r.Skipped = err.Error()
			return r
		}
		r.Error = err.Error()
		return r
	}
	r.Got = res.Data
	rcodeOK := res.Answered && res.RCode == 0
	if expected != nil {
		want, werr := expectedDNSData(*expected)
		if werr != nil {
			r.Error = werr.Error()
		} else {
			r.Expected = want
			r.Valid = rcodeOK && dnsDataMatches(qtype, want, res.Data)
		}
	} else {
		r.Valid = rcodeOK
	}
	if res.Answered && res.RCode != 0 {
		switch {
		case expected == nil && !hasUpstream && res.RCode == 5:
			r.Reason = "no upstream DNS configured for this cluster (set one under Scope Options) — dnsmasq has nowhere to forward an external name"
		default:
			r.Reason = "rcode: " + dnsRcodeName(res.RCode)
		}
	}
	r.Answered = res.Answered
	r.LatencyMS = res.Latency.Milliseconds()
	return r
}

func expectedDNSData(rec config.DNSRecord) (string, error) {
	switch strings.ToUpper(rec.Type) {
	case "A", "AAAA":
		ip := net.ParseIP(rec.Value)
		if ip == nil {
			return "", fmt.Errorf("configured value %q is not a valid IP address", rec.Value)
		}
		return ip.String(), nil
	case "CNAME", "PTR":
		return dnsNameForm(rec.Value), nil
	case "TXT":
		return rec.Value, nil
	case "SRV":
		return fmt.Sprintf("%d %d %d %s", rec.Priority, rec.Weight, rec.Port, dnsNameForm(rec.Target)), nil
	case "MX":
		return fmt.Sprintf("%d %s", rec.Priority, dnsNameForm(rec.Target)), nil
	case "NAPTR":
		return fmt.Sprintf("%d %d %s|%s|%s %s", rec.NAPTROrder, rec.Priority, rec.NAPTRFlags, rec.NAPTRService, rec.NAPTRRegexp, dnsNameForm(rec.Target)), nil
	case "CAA":
		return fmt.Sprintf("%d %s %s", rec.CAAFlags, rec.CAATag, rec.Value), nil
	case "RAW":
		if rec.RRDataHex == "" {
			return "", nil
		}
		raw, err := hex.DecodeString(rec.RRDataHex)
		if err != nil {
			return "", fmt.Errorf("configured rr_data_hex %q is not valid hex: %w", rec.RRDataHex, err)
		}
		return hex.EncodeToString(raw), nil
	default:
		return "", fmt.Errorf("don't know how to validate type %s", rec.Type)
	}
}

// dnsNameForm normalizes a DNS name to always end in a trailing dot.
func dnsNameForm(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

// dnsDataMatches compares an expected value against what was actually
// returned.
func dnsDataMatches(qtype, want, got string) bool {
	switch strings.ToUpper(qtype) {
	case "CNAME", "PTR":
		return strings.EqualFold(want, got)
	case "SRV":
		// Only the trailing target name is case-insensitive; priority/
		// weight/port are plain decimal numbers, compared exact.
		wantFields := strings.SplitN(want, " ", 4)
		gotFields := strings.SplitN(got, " ", 4)
		if len(wantFields) != 4 || len(gotFields) != 4 {
			return want == got
		}
		return wantFields[0] == gotFields[0] && wantFields[1] == gotFields[1] &&
			wantFields[2] == gotFields[2] && strings.EqualFold(wantFields[3], gotFields[3])
	case "MX":
		// Only the trailing exchange name is case-insensitive; preference
		// is a plain decimal number, compared exact.
		wantFields := strings.SplitN(want, " ", 2)
		gotFields := strings.SplitN(got, " ", 2)
		if len(wantFields) != 2 || len(gotFields) != 2 {
			return want == got
		}
		return wantFields[0] == gotFields[0] && strings.EqualFold(wantFields[1], gotFields[1])
	case "NAPTR":
		// "<order> <preference> <flags>|<service>|<regexp> <replacement>" —
		// only the trailing replacement name is case-insensitive.
		wantFields := strings.SplitN(want, " ", 4)
		gotFields := strings.SplitN(got, " ", 4)
		if len(wantFields) != 4 || len(gotFields) != 4 {
			return want == got
		}
		return wantFields[0] == gotFields[0] && wantFields[1] == gotFields[1] &&
			wantFields[2] == gotFields[2] && strings.EqualFold(wantFields[3], gotFields[3])
	case "RAW":
		// Hex digits, case-insensitive.
		return strings.EqualFold(want, got)
	default:
		return want == got
	}
}

// validateDHCPAnswer compares the DHCPOFFER's server-identifier(s) against
// the arbiter's LIVE token holder for this scope.
func dhcpOffersToDetails(offers []dhcpprobe.Offer) []DHCPOfferDetail {
	var details []DHCPOfferDetail
	for _, o := range offers {
		details = append(details, DHCPOfferDetail{
			ServerID:  o.ServerID.String(),
			OfferedIP: o.YourIP.String(),
		})
	}
	return details
}

// legitimateScopeServers returns the bare node_ip of every core node that
// has this scope configured at all — not just the current arbiter token
// owner.
func legitimateScopeServers(scope string, byNodeID map[string]probeConfigResponse) map[string]bool {
	out := make(map[string]bool)
	for _, node := range byNodeID {
		sc, ok := node.Scopes[scope]
		if !ok {
			continue
		}
		// The relay puts the scope's VIP into option 54, so the VIP is
		// a legitimate server identifier too, not just each NodeIP.
		for _, cidr := range []string{sc.NodeIP, sc.VIP} {
			if cidr == "" {
				continue
			}
			ip := cidr
			if addr, err := netip.ParsePrefix(cidr); err == nil {
				ip = addr.Addr().String()
			}
			out[ip] = true
		}
	}
	return out
}

// unrecognizedServers returns the subset of servers not present in legit,
// preserving order.
func unrecognizedServers(servers []string, legit map[string]bool) []string {
	if len(legit) == 0 {
		return nil
	}
	var out []string
	for _, s := range servers {
		if legit[s] {
			continue
		}
		if ip := net.ParseIP(s); ip != nil && ip.IsLoopback() {
			continue
		}
		out = append(out, s)
	}
	return out
}

func validateDHCPAnswer(scope string, dhcpResult dhcpprobe.Result, byNodeID map[string]probeConfigResponse, tokens map[string]tokenInfo) (bool, string) {
	legit := legitimateScopeServers(scope, byNodeID)
	if dhcpResult.Verdict == dhcpprobe.VerdictDualActive {
		if rogue := unrecognizedServers(dhcpResult.Servers, legit); len(rogue) > 0 {
			return false, fmt.Sprintf("ROGUE DHCP: unrecognized server(s) %v among responders %v", rogue, dhcpResult.Servers)
		}
		return false, fmt.Sprintf("dual-active: more than one server answered %v", dhcpResult.Servers)
	}
	if dhcpResult.Verdict == dhcpprobe.VerdictNoAnswer {
		return false, "no answer"
	}
	if rogue := unrecognizedServers(dhcpResult.Servers, legit); len(rogue) > 0 {
		return false, fmt.Sprintf("ROGUE DHCP: unrecognized server %v answered (expected one of %v)", rogue, legit)
	}
	tok, ok := tokens[scope]
	if !ok {
		return false, "no arbiter token exists for this scope"
	}
	if tok.Expired {
		return false, "arbiter token for this scope is expired"
	}
	owner, ok := byNodeID[tok.Owner]
	if !ok {
		return false, "arbiter token owner " + tok.Owner + " did not answer probe-config"
	}
	sc, ok := owner.Scopes[scope]
	if !ok || sc.NodeIP == "" {
		return false, "token owner has no node_ip for this scope"
	}
	ownerAddr, err := netip.ParsePrefix(sc.NodeIP)
	ownerIP := sc.NodeIP
	if err == nil {
		ownerIP = ownerAddr.Addr().String()
	}
	for _, o := range dhcpResult.Offers {
		if o.GIAddr != nil && !o.GIAddr.IsUnspecified() && o.GIAddr.String() == ownerIP {
			return true, ""
		}
	}
	for _, s := range dhcpResult.Servers {
		if s == ownerIP {
			return true, ""
		}
	}
	return false, fmt.Sprintf("answered by %v (relay %v), expected token owner %s (%s)", dhcpResult.Servers, giaddrsOf(dhcpResult.Offers), tok.Owner, ownerIP)
}

// giaddrsOf returns the distinct, non-empty GIAddr values across offers,
// for validateDHCPAnswer's own failure-reason string.
func giaddrsOf(offers []dhcpprobe.Offer) []string {
	seen := make(map[string]bool)
	var out []string
	for _, o := range offers {
		if o.GIAddr == nil || o.GIAddr.IsUnspecified() {
			continue
		}
		s := o.GIAddr.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
