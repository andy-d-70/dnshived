// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"

	"dnshived/internal/repldoc"
	"dnshived/internal/secretindex"
)

// The probe-host list follows the same rule as the users document: once every core offers the secret index, a
// change of a probe host is ordered by the cores (first wins, a later one from the same version is refused), and
// a sibling's list is taken host by host, only where it holds what the index names.

const probeHostsIndexPart = "probe_hosts"

// probeHostsShared is the running instance's probe-host document; nil in tests that do not set it.
var probeHostsShared *probeHostsDoc

func probeHostItems(hosts []NodeConfig) (map[string][]byte, error) {
	out := make(map[string][]byte, len(hosts))
	for _, h := range hosts {
		raw, err := json.Marshal(h)
		if err != nil {
			return nil, fmt.Errorf("probe host %s: %w", h.Addr, err)
		}
		out[h.Addr] = raw
	}
	return out, nil
}

// probeHostsFrom builds the list from items, in the order of order, then new hosts by address.
func probeHostsFrom(items map[string][]byte, order []NodeConfig) ([]NodeConfig, error) {
	var keys []string
	for _, h := range order {
		keys = append(keys, h.Addr)
	}
	var out []NodeConfig
	for _, addr := range ordered(keys, items) {
		var h NodeConfig
		if err := json.Unmarshal(items[addr], &h); err != nil || h.Addr != addr {
			return nil, fmt.Errorf("probe host item %q does not hold that host", addr)
		}
		out = append(out, h)
	}
	return out, nil
}

func ordered(order []string, have map[string][]byte) []string {
	seen := map[string]bool{}
	var out, rest []string
	for _, k := range order {
		if _, ok := have[k]; ok && !seen[k] {
			out = append(out, k)
			seen[k] = true
		}
	}
	for k := range have {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	return append(out, rest...)
}

func (d *probeHostsDoc) strictOn() bool { return d != nil && d.strict != nil && d.strict.active() }

func (d *probeHostsDoc) pendingPath() string { return d.cfgPath + ".probehosts.pending" }

// saveProbeHostsChange saves next (a change of old) to web.json and makes it live. When strict mode is on and the
// probe-host list changed, the change is first ordered by the cores; a refusal leaves everything as it was.
func saveProbeHostsChange(cfgPath string, ref *configRef, old, next *WebConfig) error {
	d := probeHostsShared
	if !d.strictOn() {
		if err := saveWebConfig(cfgPath, next); err != nil {
			return err
		}
		ref.Store(next)
		return nil
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	before, err := probeHostItems(old.ProbeHosts)
	if err != nil {
		return err
	}
	after, err := probeHostItems(next.ProbeHosts)
	if err != nil {
		return err
	}
	changed := len(secretindex.Changed(before, after)) > 0
	if changed {
		applied, err := orderChange(d.strict, d.pendingPath(), probeHostsIndexPart, d.self(), before, after)
		var ce *secretindex.ConflictError
		if errors.As(err, &ce) {
			msg := fmt.Sprintf("refused a change of probe host %s on %s: it was changed by %s at %s", ce.Key, d.self(), ce.Entry.By, ce.Entry.At)
			log.Printf("[REPL] %s", msg)
			go auditAll(ref.Load(), "system", "probehosts.rejected", msg)
			return fmt.Errorf("not saved: probe host %s was changed on %s at %s since this page was loaded; reload and enter the change again if it is still needed", ce.Key, ce.Entry.By, ce.Entry.At)
		}
		if !applied {
			return err
		}
		d.stampLocked(next)
	}
	if err := saveWebConfig(cfgPath, next); err != nil {
		return err
	}
	ref.Store(next)
	if changed && d.push != nil {
		go d.push()
	}
	return nil
}

func (d *probeHostsDoc) stampLocked(next *WebConfig) {
	next.ProbeHostsVersion++
	next.ProbeHostsUpdatedAt, next.ProbeHostsOrigin = stampNow(), d.self()
	next.ProbeHostsHash = probeHostsHash(next.ProbeHosts)
}

// pullFromSiblings answers a sibling's direct probe-host change in strict mode: the list is fetched through the
// ordered comparison instead of being applied as sent.
func (d *probeHostsDoc) pullFromSiblings() bool {
	if !d.strictOn() {
		return false
	}
	if d.sync != nil {
		go d.sync()
	}
	return true
}

// strictAdopt takes a sibling's newer list host by host: only what the index names.
func (d *probeHostsDoc) strictAdopt(in probeHostsWire, from string) (adopted, spread bool, err error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	cfg := d.ref.Load()
	localStamp := repldoc.Meta{Version: cfg.ProbeHostsVersion, UpdatedAt: cfg.ProbeHostsUpdatedAt, Origin: cfg.ProbeHostsOrigin}
	if !repldoc.Newer(in.Meta, localStamp) {
		return false, false, nil
	}
	tree, err := d.strict.getIndex()
	if err != nil {
		return false, false, fmt.Errorf("probe-host list from %s not taken yet: the cores' change order cannot be read: %w", from, err)
	}
	idx, err := secretindex.Parse(tree, probeHostsIndexPart)
	if err != nil {
		return false, false, err
	}
	local, err := probeHostItems(cfg.ProbeHosts)
	if err != nil {
		return false, false, err
	}
	incoming, err := probeHostItems(in.ProbeHosts)
	if err != nil {
		return false, false, invalidDocError{err.Error()}
	}
	out, refused, missing := secretindex.Reconcile(idx, local, incoming, nil)
	hosts, err := probeHostsFrom(out, in.ProbeHosts)
	if err != nil {
		return false, false, invalidDocError{err.Error()}
	}
	next := *cfg
	next.ProbeHosts = hosts
	next.ProbeHostsVersion, next.ProbeHostsUpdatedAt, next.ProbeHostsOrigin = in.Version, in.UpdatedAt, in.Origin
	next.ProbeHostsHash = probeHostsHash(hosts)
	if len(refused) > 0 {
		d.stampLocked(&next)
		log.Printf("[REPL] probe hosts from %s not taken (the cores ordered another version): %v", from, refused)
	}
	for _, k := range missing {
		log.Printf("[REPL] the cores name a version of probe host %s that no instance holds; following %s's copy", k, from)
	}
	if err := d.publish(cfg, &next); err != nil {
		return false, false, err
	}
	return true, len(refused) > 0, nil
}

// settle applies, resends or drops a pending probe-host change; it runs after every comparison.
func (d *probeHostsDoc) settle() {
	if !d.strictOn() {
		return
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	p, outcome, err := settlePendingChange(d.strict, d.pendingPath())
	if err != nil {
		log.Printf("[REPL] probe hosts: %v", err)
	}
	switch outcome {
	case settleApply:
		cfg := d.ref.Load()
		cur, err := probeHostItems(cfg.ProbeHosts)
		if err != nil {
			return
		}
		p.applyItems(cur)
		hosts, err := probeHostsFrom(cur, cfg.ProbeHosts)
		if err != nil {
			log.Printf("[REPL] confirmed probe-host change not applied: %v", err)
			return
		}
		next := *cfg
		next.ProbeHosts = hosts
		d.stampLocked(&next)
		if err := d.publish(cfg, &next); err != nil {
			log.Printf("[REPL] confirmed probe-host change: %v", err)
			return
		}
		_ = os.Remove(d.pendingPath())
		log.Printf("[REPL] applied a probe-host change the cores confirmed after it was sent")
		if d.push != nil {
			go d.push()
		}
	case settleDropped:
		msg := fmt.Sprintf("dropped a probe-host change on %s that the cores refused: someone else changed it first", d.self())
		log.Printf("[REPL] %s", msg)
		go auditAll(d.ref.Load(), "system", "probehosts.rejected", msg)
	}
}
