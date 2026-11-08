// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"dnshived/internal/config"
	"dnshived/internal/eventlog"
)

const (
	maxRunnerParents = 32
	runnerIdleWait   = 2 * time.Second
	planMaxAgeSlack  = 30 * time.Second
)

// probePlan is one immutable snapshot of what to probe, rebuilt on every
// configuration refresh and read by the runners.
type probePlan struct {
	fetchedAt     time.Time
	epoch         uint64
	byNodeID      map[string]probeConfigResponse
	defaultChecks []config.DNSCheck
	tokens        map[string]tokenInfo
	targets       map[string]scopeProbeTarget
	byParent      map[string][]string
	manual        map[string]ManualProbe
	dhcpNames     map[string][]string
}

type runnerKey struct {
	leg    probeLeg
	parent string
}

func (k runnerKey) label() string {
	if k.leg == legDNS {
		return "dns " + k.parent
	}
	return "dhcp " + k.parent
}

// probeRunners owns one DHCP runner and one DNS runner per physical
// interface that carries scopes.
type probeRunners struct {
	cfg      *ProbeConfig
	store    *resultStore
	tracker  *probeLogTracker
	events   *eventlog.Ring
	debounce *ownershipDebounce
	ctx      context.Context

	plan  atomic.Pointer[probePlan]
	epoch atomic.Uint64

	wg      sync.WaitGroup
	mu      sync.Mutex
	running map[runnerKey]context.CancelFunc
}

func newProbeRunners(ctx context.Context, cfg *ProbeConfig, store *resultStore, tracker *probeLogTracker, events *eventlog.Ring, debounce *ownershipDebounce) *probeRunners {
	return &probeRunners{
		cfg: cfg, store: store, tracker: tracker, events: events, debounce: debounce, ctx: ctx,
		running: make(map[runnerKey]context.CancelFunc),
	}
}

func (r *probeRunners) parentAllowed(parent string) bool {
	allowed := r.cfg.servingParents()
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if a == parent {
			return true
		}
	}
	return false
}

func buildProbePlan(cfg *ProbeConfig, byNodeID map[string]probeConfigResponse, defaultChecks []config.DNSCheck, tokens map[string]tokenInfo, epoch uint64) *probePlan {
	p := &probePlan{
		fetchedAt: time.Now(), epoch: epoch, byNodeID: byNodeID, defaultChecks: defaultChecks, tokens: tokens,
		targets: make(map[string]scopeProbeTarget), byParent: make(map[string][]string),
		manual: make(map[string]ManualProbe), dhcpNames: make(map[string][]string),
	}
	for _, name := range mergedScopeNames(byNodeID) {
		t := resolveScopeTarget(cfg, name, byNodeID)
		p.targets[name] = t
		p.byParent[t.parent] = append(p.byParent[t.parent], name)
		p.dhcpNames[t.parent] = append(p.dhcpNames[t.parent], name)
	}
	for _, m := range cfg.manualProbeList() {
		p.manual[m.key()] = m
		p.dhcpNames[m.Interface] = append(p.dhcpNames[m.Interface], m.key())
	}
	return p
}

// apply installs a new plan and starts or stops runners to match it. A scope
// on an interface this host does not serve is published as having no
// coverage instead of getting a runner.
func (r *probeRunners) apply(p *probePlan) {
	r.plan.Store(p)
	want := make(map[runnerKey]bool)
	served := 0
	parents := make(map[string]bool, len(p.dhcpNames))
	for parent := range p.dhcpNames {
		parents[parent] = true
	}
	for parent := range parents {
		if !r.parentAllowed(parent) || served >= maxRunnerParents {
			for _, name := range p.byParent[parent] {
				unreachable := ScopeProbeResult{Scope: name, ProbedAt: time.Now()}
				r.store.setLeg(legDHCP, name, unreachable)
				r.store.setLeg(legDNS, name, unreachable)
			}
			for _, name := range p.dhcpNames[parent] {
				if m, ok := p.manual[name]; ok {
					watchResults.set(WatchResult{Name: m.Name, Interface: m.Interface, VLANID: m.VLANID, Verdict: "error",
						Error: "interface " + m.Interface + " is not one this probe host serves", ProbedAt: time.Now()})
				}
			}
			continue
		}
		served++
		want[runnerKey{legDHCP, parent}] = true
		want[runnerKey{legDNS, parent}] = true
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for k, cancel := range r.running {
		if !want[k] {
			cancel()
			delete(r.running, k)
			log.Printf("[PROBE:RUNNER] stopped %s runner: no scope left on this interface", k.label())
		}
	}
	for k := range want {
		if _, ok := r.running[k]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(r.ctx)
		r.running[k] = cancel
		log.Printf("[PROBE:RUNNER] started %s runner", k.label())
		r.wg.Add(1)
		go r.loop(ctx, k)
	}
}

func (r *probeRunners) stop() {
	r.mu.Lock()
	for k, cancel := range r.running {
		cancel()
		delete(r.running, k)
	}
	r.mu.Unlock()
	r.wg.Wait()
}

func (r *probeRunners) runnerCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.running)
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// nextDue picks the scope that has waited longest since its last attempt
// (never-attempted first) and the time it is due again.
func nextDue(names []string, attempted map[string]time.Time, interval time.Duration) (string, time.Time) {
	var pick string
	var pickAt time.Time
	for i, name := range names {
		at := attempted[name]
		if i == 0 || at.Before(pickAt) {
			pick, pickAt = name, at
		}
	}
	if pick == "" || pickAt.IsZero() {
		return pick, time.Time{}
	}
	return pick, pickAt.Add(interval)
}

func (r *probeRunners) loop(ctx context.Context, key runnerKey) {
	defer r.wg.Done()
	interval := time.Duration(r.cfg.probeInterval()) * time.Millisecond
	attempted := make(map[string]time.Time)
	hints := make(map[string]dhcpHint)
	var epoch uint64
	var cycleStart time.Time
	cycleN := 0
	for ctx.Err() == nil {
		p := r.plan.Load()
		if p == nil || time.Since(p.fetchedAt) > 3*interval+planMaxAgeSlack {
			sleepCtx(ctx, runnerIdleWait)
			continue
		}
		if p.epoch != epoch {
			epoch = p.epoch
			attempted = make(map[string]time.Time)
			hints = make(map[string]dhcpHint)
			cycleN = 0
		}
		names := p.byParent[key.parent]
		if key.leg == legDHCP {
			names = p.dhcpNames[key.parent]
		}
		name, due := nextDue(names, attempted, interval)
		if name == "" {
			sleepCtx(ctx, runnerIdleWait)
			continue
		}
		if wait := time.Until(due); wait > 0 {
			sleepCtx(ctx, min(wait, runnerIdleWait))
			continue
		}
		if cycleN == 0 {
			cycleStart = time.Now()
		}
		attempted[name] = time.Now()
		r.runOne(key, p, name, hints)
		cycleN++
		if cycleN >= len(names) {
			log.Printf("[PROBE:CYCLE] %s: %d scope(s) in %s", key.label(), cycleN, time.Since(cycleStart).Round(time.Millisecond))
			cycleN = 0
		}
	}
}

func (r *probeRunners) runOne(key runnerKey, p *probePlan, name string, hints map[string]dhcpHint) {
	if m, ok := p.manual[name]; ok {
		var res WatchResult
		probeScheduler.Submit(m.Interface, false, func() { res = runWatchProbe(m) })
		if res.Name != "" {
			r.publishWatch(res)
		}
		return
	}
	t, ok := p.targets[name]
	if !ok {
		return
	}
	base, run := t.base()
	if !run {
		r.publish(key.leg, name, t, base)
		return
	}
	var res ScopeProbeResult
	switch key.leg {
	case legDHCP:
		probeScheduler.Submit(t.parent, false, func() {
			var next dhcpHint
			res, next = runDHCPLeg(r.cfg, t, p.byNodeID, p.tokens, hints[name])
			hints[name] = next
		})
	case legDNS:
		dnsScheduler.Submit(t.parent, false, func() {
			res = runDNSLeg(t, p.byNodeID, p.defaultChecks)
		})
	}
	if res.Scope == "" {
		return
	}
	r.publish(key.leg, name, t, res)
}

// publishWatch records a manual probe's result and logs an edge-triggered
// event when a rogue server appears or goes away.
func (r *probeRunners) publishWatch(res WatchResult) {
	r.tracker.checkWatch(r.events, res)
	watchResults.set(res)
	recordWatch(res)
}

func (r *probeRunners) publish(leg probeLeg, name string, t scopeProbeTarget, res ScopeProbeResult) {
	if leg == legDHCP {
		res.DNSPending = true
		var flags []string
		if !settleOwnershipResult(r.store, r.debounce, r.tracker, r.events, name, res) {
			flags = append(flags, "held_by_debounce")
		}
		recordScopeLeg("dhcp", name, t, res, flags)
		return
	}
	res.DHCPPending = true
	settleDNSResult(r.store, r.tracker, r.events, name, res)
	recordScopeLeg("dns", name, t, res, nil)
}

// refreshProbePlan rebuilds the plan from the cluster's current view and
// hands it to the runners. It does no probing itself.
func refreshProbePlan(cfg *ProbeConfig, rn *probeRunners, incarnations *incarnationTracker) {
	byNodeID, defaultChecks, err := fetchAllScopes(cfg)
	if err != nil {
		log.Printf("[PROBE:FETCH] %v", err)
		return
	}

	if incarnations.restarted(byNodeID) {
		log.Printf("[PROBE:INVALIDATE] a monitored cluster node restarted — clearing all stored results, forcing a fresh sweep")
		rn.store.clear()
		rn.debounce.clear()
		rn.epoch.Add(1)
	}

	if changed := reconcileVLANInterfaces(cfg, byNodeID); len(changed) > 0 {
		log.Printf("[PROBE:VLAN] %v", changed)
	}
	if removed := reconcileOrphanVLANs(cfg, desiredWithWatch(cfg, byNodeID)); len(removed) > 0 {
		log.Printf("[PROBE:VLAN] %v", removed)
	}

	tokens := fetchTokens(cfg)

	scopeNames := mergedScopeNames(byNodeID)
	keep := make(map[string]bool, len(scopeNames))
	for _, name := range scopeNames {
		keep[name] = true
	}
	rn.store.prune(keep)
	rn.tracker.prune(keep)
	manualKeep := make(map[string]bool)
	for _, m := range cfg.manualProbeList() {
		manualKeep[m.Name] = true
	}
	watchResults.prune(manualKeep)

	rn.apply(buildProbePlan(cfg, byNodeID, defaultChecks, tokens, rn.epoch.Load()))
}
