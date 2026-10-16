// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"

	"dnshived/internal/config"
)

// knownScope is the minimal information needed to tear a scope's
// infrastructure back down after it's disappeared from config.
type knownScope struct {
	Parent string `json:"parent"`
	VLANID int    `json:"vlan_id"`
}

// knownScopesPath is where each node persists, across restarts, the set of
// scopes it last actually constructed.
func knownScopesPath(dataDir string) string {
	return filepath.Join(dataDir, "known-scopes.json")
}

// loadKnownScopes reads the persisted set.
func loadKnownScopes(dataDir string) map[string]knownScope {
	data, err := os.ReadFile(knownScopesPath(dataDir))
	if err != nil {
		return nil
	}
	var known map[string]knownScope
	if err := json.Unmarshal(data, &known); err != nil {
		log.Printf("[AGENT:WARN] known-scopes file corrupt, ignoring: %v", err)
		return nil
	}
	return known
}

// saveKnownScopes atomically overwrites the persisted set with exactly
// today's configured scopes.
func saveKnownScopes(dataDir string, scopes map[string]config.ScopeConfig) error {
	known := make(map[string]knownScope, len(scopes))
	for name, sc := range scopes {
		known[name] = knownScope{Parent: sc.Parent, VLANID: sc.VLANID}
	}
	data, err := json.MarshalIndent(known, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal known scopes: %w", err)
	}
	return atomicWriteFile(knownScopesPath(dataDir), data, 0o640)
}

// isUnsafeScopeName reports whether name is unsafe to use directly in a
// filesystem path (os.Remove(filepath.Join(a.dataDir, ...))).
func isUnsafeScopeName(name string) bool {
	return filepath.Base(name) != name || name == "." || name == ".."
}

// removedScopes is the pure diff at the heart of decommissioning: any
// scope name that was known-constructed but is absent from the current
// config.
func removedScopes(known map[string]knownScope, current map[string]config.ScopeConfig) []string {
	var removed []string
	for name, ks := range known {
		cur, stillConfigured := current[name]
		if !stillConfigured || cur.Parent != ks.Parent || cur.VLANID != ks.VLANID {
			removed = append(removed, name)
		}
	}
	sort.Strings(removed)
	return removed
}

func (a *Agent) DecommissionRemovedScopes() (removed []string, saveErr error) {
	currentScopes := a.allScopes()
	known := loadKnownScopes(a.dataDir)
	removed = removedScopes(known, currentScopes)

	for _, name := range removed {
		if isUnsafeScopeName(name) {
			log.Printf("[AGENT:WARN] known-scopes entry %q looks unsafe — skipping teardown for it", name)
			continue
		}

		ks := known[name]
		sc := config.ScopeConfig{Parent: ks.Parent, VLANID: ks.VLANID}
		reason := "no longer in config"
		if cur, stillConfigured := currentScopes[name]; stillConfigured {
			reason = fmt.Sprintf("moved from %s.%d to %s.%d", ks.Parent, ks.VLANID, cur.Parent, cur.VLANID)
		}
		log.Printf("[AGENT:DECOMMISSION] scope %s %s — tearing down %s.%d and its dnsmasq unit",
			name, reason, ks.Parent, ks.VLANID)
		a.deleteInterface(name, sc)
		if err := a.stopDnsmasqUnit(name); err != nil {
			log.Printf("[AGENT:WARN] scope %s: stop dnsmasq: %v", name, err)
		}
		os.Remove(filepath.Join(a.dataDir, "dnsmasq-"+name+".conf"))
		os.Remove(filepath.Join(a.dataDir, "reservations-"+name+".conf"))
		os.Remove(filepath.Join(a.dataDir, "leases-"+name))
	}

	if err := saveKnownScopes(a.dataDir, currentScopes); err != nil {
		log.Printf("[AGENT:WARN] save known scopes: %v", err)
		saveErr = err
	}

	return removed, saveErr
}
