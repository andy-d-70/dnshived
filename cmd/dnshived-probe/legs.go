// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"dnshived/internal/config"
	"dnshived/internal/dhcpprobe"
)

type probeLeg int

const (
	legDHCP probeLeg = iota
	legDNS
)

const (
	dhcpFirstWait   = 9 * time.Second
	dhcpWaitFloor   = 3500 * time.Millisecond
	dhcpWaitCap     = 9 * time.Second
	dhcpRetryWait   = 10 * time.Second
	dhcpSuspectWait = 9 * time.Second
	dhcpOfferGrace  = 400 * time.Millisecond
	dnsQueryTimeout = 2 * time.Second
)

var dhcpProbeFn = dhcpprobe.ProbeWithOptions

type scopeProbeTarget struct {
	name          string
	parent        string
	iface         string
	vlanID        int
	dnsRecords    []config.DNSRecord
	probeDisabled bool
}

func sortedNodeIDs(byNodeID map[string]probeConfigResponse) []string {
	ids := make([]string, 0, len(byNodeID))
	for id := range byNodeID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func resolveScopeTarget(cfg *ProbeConfig, name string, byNodeID map[string]probeConfigResponse) scopeProbeTarget {
	t := scopeProbeTarget{name: name}
	for _, id := range sortedNodeIDs(byNodeID) {
		if sc, ok := byNodeID[id].Scopes[name]; ok {
			t.vlanID = sc.VLANID
			t.parent = sc.Parent
			t.dnsRecords = sc.DNSRecords
			t.probeDisabled = sc.ProbeDisabled
			break
		}
	}
	if t.parent == "" {
		t.parent = cfg.TrunkParent
	}
	t.iface = realIfaceName(t.parent, t.vlanID)
	return t
}

// base returns the result for a scope with nothing to probe (no interface,
// probing off) and whether the two legs have to run.
func (t scopeProbeTarget) base() (ScopeProbeResult, bool) {
	r := ScopeProbeResult{Scope: t.name, ProbedAt: time.Now()}
	if _, err := ifaceExistsFn(t.iface); err != nil {
		return r, false
	}
	r.Reachable = true
	if t.probeDisabled {
		return r, false
	}
	r.Enabled = true
	return r, true
}

type dhcpHint struct {
	latency time.Duration
	silent  bool
}

func dhcpWaitFor(cfg *ProbeConfig, prev time.Duration) time.Duration {
	if cfg.DHCPWaitMS > 0 {
		return time.Duration(cfg.DHCPWaitMS) * time.Millisecond
	}
	if prev <= 0 {
		return dhcpFirstWait
	}
	w := 2*prev + 500*time.Millisecond
	return min(max(w, dhcpWaitFloor), dhcpWaitCap)
}

// dhcpOptions picks the client MAC: the interface's own, except on the
// management interface, where a derived one keeps the probe from claiming
// the host's own address with a DHCP server there.
func dhcpOptions(cfg *ProbeConfig, t scopeProbeTarget) dhcpprobe.Options {
	o := probeDHCPOptions(t.iface)
	if cfg.MgmtInterface != "" && t.parent == cfg.MgmtInterface {
		o.MAC = stableMAC("scope|" + t.name)
	}
	return o
}

func firstOfferOptions(cfg *ProbeConfig, t scopeProbeTarget) dhcpprobe.Options {
	o := dhcpOptions(cfg, t)
	o.StopOnFirstOffer = true
	o.FirstOfferGrace = dhcpOfferGrace
	return o
}

// runDHCPLeg runs the DHCP half of a scope probe. A first answer that is
// invalid or from several servers is probed again over the full window, so
// a rogue server is listed with every other server that answers.
func runDHCPLeg(cfg *ProbeConfig, t scopeProbeTarget, byNodeID map[string]probeConfigResponse, tokens map[string]tokenInfo, hint dhcpHint) (ScopeProbeResult, dhcpHint) {
	r := ScopeProbeResult{Scope: t.name, Reachable: true, Enabled: true, DNSPending: true}
	dr, err := dhcpProbeFn(t.iface, dhcpWaitFor(cfg, hint.latency), firstOfferOptions(cfg, t))
	if err == nil && len(dr.Offers) == 0 && !hint.silent && cfg.DHCPWaitMS <= 0 {
		dr, err = dhcpProbeFn(t.iface, dhcpRetryWait, firstOfferOptions(cfg, t))
		r.Flags = append(r.Flags, "retried")
	}
	var next dhcpHint
	if err != nil {
		r.DHCP.Error = err.Error()
	} else {
		valid, reason := validateDHCPAnswer(t.name, dr, byNodeID, tokens)
		suspect := dr.Verdict == dhcpprobe.VerdictDualActive ||
			len(unrecognizedServers(dr.Servers, legitimateScopeServers(t.name, byNodeID))) > 0
		if len(dr.Offers) > 0 && suspect {
			full, ferr := dhcpProbeFn(t.iface, dhcpSuspectWait, dhcpOptions(cfg, t))
			r.Flags = append(r.Flags, "full_window")
			if ferr == nil && len(full.Offers) >= len(dr.Offers) {
				dr = full
				valid, reason = validateDHCPAnswer(t.name, dr, byNodeID, tokens)
			}
		}
		r.DHCP.Verdict = string(dr.Verdict)
		r.DHCP.Servers = dr.Servers
		r.DHCP.Valid, r.DHCP.Reason = valid, reason
		r.DHCP.Offers = dhcpOffersToDetails(dr.Offers)
		if len(dr.Offers) > 0 {
			next.latency = dr.Offers[0].At
			r.DHCP.OfferMS = dr.Offers[0].At.Milliseconds()
		} else {
			next.silent = true
		}
	}
	r.ProbedAt = time.Now()
	return r, next
}

// runDNSLeg queries every core's address for the default checks and the
// scope's own records, the cores in parallel.
func runDNSLeg(t scopeProbeTarget, byNodeID map[string]probeConfigResponse, defaultChecks []config.DNSCheck) ScopeProbeResult {
	r := ScopeProbeResult{Scope: t.name, Reachable: true, Enabled: true, DHCPPending: true}
	checks := defaultChecks
	if len(checks) == 0 {
		checks = []config.DNSCheck{{Name: config.DefaultDNSCheckName, Type: config.DefaultDNSCheckType}}
	}

	var ids []string
	for _, id := range sortedNodeIDs(byNodeID) {
		resp := byNodeID[id]
		if !isCoreRole(resp.Role) {
			continue
		}
		if sc, ok := resp.Scopes[t.name]; ok && sc.NodeIP != "" {
			ids = append(ids, id)
		}
	}
	perNode := make([][]DNSCheckResult, len(ids))
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			perNode[i] = dnsChecksForNode(byNodeID[id], t, checks)
		}(i, id)
	}
	wg.Wait()
	for _, part := range perNode {
		r.DNSChecks = append(r.DNSChecks, part...)
	}

	for _, c := range r.DNSChecks {
		if c.Skipped != "" {
			continue
		}
		r.DNS.Answered = c.Answered
		r.DNS.LatencyMS = c.LatencyMS
		r.DNS.Error = c.Error
		r.DNS.Valid = c.Valid
		r.DNS.Reason = c.Reason
		break
	}
	r.ProbedAt = time.Now()
	return r
}

func dnsChecksForNode(resp probeConfigResponse, t scopeProbeTarget, checks []config.DNSCheck) []DNSCheckResult {
	sc := resp.Scopes[t.name]
	target := sc.NodeIP
	if pfx, err := netip.ParsePrefix(sc.NodeIP); err == nil {
		target = pfx.Addr().String()
	}
	var out []DNSCheckResult
	for _, chk := range checks {
		out = append(out, runOneDNSCheck(target, chk.Name, chk.Type, nil, resp.ClusterHasUpstream))
	}
	for _, rec := range t.dnsRecords {
		if rec.ProbeDisabled {
			continue
		}
		out = append(out, runOneDNSCheck(target, rec.Name, rec.Type, &rec, resp.ClusterHasUpstream))
	}
	return out
}

func combineLegs(base, dl, nl ScopeProbeResult) ScopeProbeResult {
	out := base
	out.DHCP = dl.DHCP
	out.DHCPProbedAt = dl.ProbedAt
	out.DNS = nl.DNS
	out.DNSChecks = nl.DNSChecks
	out.DNSProbedAt = nl.ProbedAt
	out.ProbedAt = laterOf(dl.ProbedAt, nl.ProbedAt)
	return out
}

func firstSet(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	return a
}

func laterOf(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// mergeLeg folds one freshly probed leg into the stored record. A scope
// with no interface or with probing off carries no legs at all.
func mergeLeg(old ScopeProbeResult, have bool, leg probeLeg, fresh ScopeProbeResult) ScopeProbeResult {
	if !fresh.Reachable || !fresh.Enabled {
		fresh.DHCPPending, fresh.DNSPending = false, false
		fresh.DHCPProbedAt, fresh.DNSProbedAt = fresh.ProbedAt, fresh.ProbedAt
		return fresh
	}
	out := old
	if !have || !old.Reachable || !old.Enabled {
		out = ScopeProbeResult{DHCPPending: true, DNSPending: true}
	}
	out.Scope = fresh.Scope
	out.Reachable, out.Enabled = true, true
	if fresh.QueueWaitMS > 0 {
		out.QueueWaitMS = fresh.QueueWaitMS
	}
	switch leg {
	case legDHCP:
		out.DHCP = fresh.DHCP
		out.DHCPProbedAt = firstSet(fresh.DHCPProbedAt, fresh.ProbedAt)
		out.DHCPPending = false
	case legDNS:
		out.DNS = fresh.DNS
		out.DNSChecks = fresh.DNSChecks
		out.DNSProbedAt = firstSet(fresh.DNSProbedAt, fresh.ProbedAt)
		out.DNSPending = false
	}
	out.ProbedAt = laterOf(out.DHCPProbedAt, out.DNSProbedAt)
	return out
}
