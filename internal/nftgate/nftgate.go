// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package nftgate manages the per-scope DHCP packet-filter gate via
// nftables.
package nftgate

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Table and Chain name the single table+chain every scope's gate rule
// lives in, distinguished by its `iif <iface>` match.
const (
	Table = "dnshived"
	Chain = "dhcp_gate"
)

// validIfaceName matches the safe character set for a Linux network
// interface name.
var validIfaceName = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)

// CheckIfaceName validates iface against validIfaceName's safe character
// set.
func CheckIfaceName(iface string) error {
	if !validIfaceName.MatchString(iface) {
		return fmt.Errorf("invalid interface name %q — refusing to build an nft/ip command from it", iface)
	}
	return nil
}

// InterfaceName returns a scope's real network interface name from its own
// Parent+VLANID.
func InterfaceName(parent string, vlanID int) string {
	if vlanID == 0 {
		return parent
	}
	return fmt.Sprintf("%s.%d", parent, vlanID)
}

// EnsureChain creates the table+chain the gate lives in.
func EnsureChain() error {
	if err := run("nft", "add", "table", "inet", Table); err != nil {
		return fmt.Errorf("create table: %w", err)
	}
	if err := run("nft", "add", "chain", "inet", Table, Chain,
		"{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}"); err != nil {
		return fmt.Errorf("create chain: %w", err)
	}
	return nil
}

// EnsureClosed adds the drop rule for iface if it isn't already present.
func EnsureClosed(iface string) error {
	if err := CheckIfaceName(iface); err != nil {
		return err
	}
	rules, err := listRulesCached()
	if err != nil {
		return fmt.Errorf("check gate state: %w", err)
	}
	if _, found := rules[iface]; found {
		return nil
	}
	if err := run("nft", "add", "rule", "inet", Table, Chain,
		"iif", iface, "udp", "dport", "67", "drop"); err != nil {
		return err
	}
	invalidateCache()
	return nil
}

// Close ensures iface's gate is closed (drop rule present).
func Close(iface string) error {
	return EnsureClosed(iface)
}

// Open ensures iface's gate is open (drop rule absent).
func Open(iface string) error {
	if err := CheckIfaceName(iface); err != nil {
		return err
	}
	rules, err := listRulesCached()
	if err != nil {
		return fmt.Errorf("check gate state: %w", err)
	}
	handle, found := rules[iface]
	if !found {
		return nil
	}
	if err := run("nft", "delete", "rule", "inet", Table, Chain,
		"handle", fmt.Sprintf("%d", handle)); err != nil {
		return err
	}
	invalidateCache()
	return nil
}

// RemoveRule drops any gate rule for iface without regard to open/closed
// semantics.
func RemoveRule(iface string) error {
	if err := CheckIfaceName(iface); err != nil {
		return err
	}
	handle, found, err := ruleHandle(iface)
	if err != nil || !found {
		return nil
	}
	return run("nft", "delete", "rule", "inet", Table, Chain,
		"handle", fmt.Sprintf("%d", handle))
}

// IsClosed reports whether iface's gate is currently closed (drop rule
// present).
func IsClosed(iface string) (bool, error) {
	if err := CheckIfaceName(iface); err != nil {
		return false, err
	}
	_, found, err := ruleHandle(iface)
	if err != nil {
		return false, fmt.Errorf("check gate state: %w", err)
	}
	return found, nil
}

// Dump returns every interface currently gated closed (drop rule present)
// in the whole chain, in one fresh round trip.
func Dump() (map[string]bool, error) {
	rules, err := listRulesFreshFn()
	if err != nil {
		return nil, err
	}
	closed := make(map[string]bool, len(rules))
	for iface := range rules {
		closed[iface] = true
	}
	return closed, nil
}

// --- nftables JSON parsing ---

type listResult struct {
	Nftables []entry `json:"nftables"`
}

type entry struct {
	Rule *rule `json:"rule,omitempty"`
}

type rule struct {
	Handle int    `json:"handle"`
	Expr   []expr `json:"expr"`
}

type expr struct {
	Match *match `json:"match,omitempty"`
}

type match struct {
	Left  matchLeft       `json:"left"`
	Right json.RawMessage `json:"right"`
}

type matchLeft struct {
	Meta *meta `json:"meta,omitempty"`
}

type meta struct {
	Key string `json:"key"`
}

// ruleHandle returns the handle of the gate-closing rule for iface, if one
// exists in the chain.
func ruleHandle(iface string) (handle int, found bool, err error) {
	rules, err := listRulesFresh()
	if err != nil {
		return 0, false, err
	}
	handle, found = rules[iface]
	return handle, found, nil
}

// listRulesFresh lists the whole gate chain in one nft call and returns
// every currently-closed interface's rule handle, keyed by iface.
func listRulesFresh() (map[string]int, error) {
	out, err := exec.Command("nft", "-j", "list", "chain", "inet", Table, Chain).Output()
	if err != nil {
		return nil, fmt.Errorf("nft list chain: %w", err)
	}

	var result listResult
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("parse nft output: %w", err)
	}
	return rulesFromListResult(result), nil
}

// rulesFromListResult extracts {iface: rule handle} for every drop rule in
// a parsed `nft -j list chain` response.
func rulesFromListResult(result listResult) map[string]int {
	rules := make(map[string]int)
	for _, e := range result.Nftables {
		if e.Rule == nil {
			continue
		}
		for _, ex := range e.Rule.Expr {
			if ex.Match == nil || ex.Match.Left.Meta == nil || ex.Match.Left.Meta.Key != "iif" {
				continue
			}
			var right string
			if err := json.Unmarshal(ex.Match.Right, &right); err != nil {
				continue
			}
			rules[right] = e.Rule.Handle
		}
	}
	return rules
}

// cacheTTL bounds how long listRulesCached reuses one nft listing across
// repeated Close/Open calls.
const cacheTTL = 2 * time.Second

var (
	cacheMu     sync.Mutex
	cachedRules map[string]int
	cachedAt    time.Time

	// inFlight/inFlightErr back listRulesCached's own single-flight dedup.
	inFlight    chan struct{}
	inFlightErr error
)

// listRulesFreshFn is listRulesCached's actual data source.
var listRulesFreshFn = listRulesFresh

// listRulesCached returns listRulesFreshFn's result, reusing a recent
// listing within cacheTTL instead of a fresh nft call.
func listRulesCached() (map[string]int, error) {
	cacheMu.Lock()
	if cachedRules != nil && time.Since(cachedAt) < cacheTTL {
		rules := cachedRules
		cacheMu.Unlock()
		return rules, nil
	}
	if inFlight != nil {
		ch := inFlight
		cacheMu.Unlock()
		<-ch
		cacheMu.Lock()
		rules, err := cachedRules, inFlightErr
		cacheMu.Unlock()
		return rules, err
	}
	ch := make(chan struct{})
	inFlight = ch
	cacheMu.Unlock()

	rules, err := listRulesFreshFn()

	cacheMu.Lock()
	if err == nil {
		cachedRules = rules
		cachedAt = time.Now()
	}
	inFlightErr = err
	inFlight = nil
	cacheMu.Unlock()
	close(ch)

	return rules, err
}

// invalidateCache is called after any successful mutating nft call
// (Close/Open's add/delete), so the next read never sees a stale pre-write
// snapshot.
func invalidateCache() {
	cacheMu.Lock()
	cachedAt = time.Time{}
	cacheMu.Unlock()
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %s (%w)", name, args, strings.TrimSpace(string(out)), err)
	}
	return nil
}
