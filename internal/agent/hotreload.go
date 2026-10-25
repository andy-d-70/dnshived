// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"dnshived/internal/loglevel"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"dnshived/internal/config"
)

// HotReloadScopes updates the running agent's in-memory scope definitions
// from a freshly-committed config, WITHOUT restarting the process.
func (a *Agent) HotReloadScopes(newScopes map[string]config.ScopeConfig) []string {
	a.constructMu.Lock()
	defer a.constructMu.Unlock()

	if newScopes == nil {
		newScopes = map[string]config.ScopeConfig{}
	}
	old := a.allScopes()
	type teardown struct {
		name string
		sc   config.ScopeConfig
	}
	var report []string
	var toTearDown []teardown
	var toDemote []string

	for name, oldSC := range old {
		newSC, stillConfigured := newScopes[name]
		switch {
		case !stillConfigured:
			toTearDown = append(toTearDown, teardown{name, oldSC})
			toDemote = append(toDemote, name)
			report = append(report, fmt.Sprintf("%s: removed", name))
		case oldSC.Parent != newSC.Parent || oldSC.VLANID != newSC.VLANID || oldSC.NodeIP != newSC.NodeIP:
			toTearDown = append(toTearDown, teardown{name, oldSC})
			toDemote = append(toDemote, name)
			report = append(report, fmt.Sprintf("%s: physical definition changed (%s.%d/%s -> %s.%d/%s) — rebuilding",
				name, oldSC.Parent, oldSC.VLANID, oldSC.NodeIP, newSC.Parent, newSC.VLANID, newSC.NodeIP))
		case !reflect.DeepEqual(oldSC, newSC):
			report = append(report, fmt.Sprintf("%s: updated (no interface rebuild needed)", name))
		}
	}
	for name := range newScopes {
		if _, existed := old[name]; !existed {
			toDemote = append(toDemote, name)
			report = append(report, fmt.Sprintf("%s: added", name))
		}
	}

	if len(toDemote) > 0 {
		a.mu.Lock()
		for _, name := range toDemote {
			delete(a.ready, name)
			delete(a.serving, name)
			delete(a.antiFlap, name)
			delete(a.vrrpPriority, name)
		}
		a.mu.Unlock()
	}

	for _, t := range toTearDown {
		loglevel.Infof("[AGENT:HOT_RELOAD] tearing down %s.%d for scope %s", t.sc.Parent, t.sc.VLANID, t.name)
		a.deleteInterface(t.name, t.sc)
		if err := a.stopDnsmasqUnit(t.name); err != nil {
			loglevel.Warnf("[AGENT:WARN] hot-reload scope %s: stop dnsmasq: %v", t.name, err)
		}
		os.Remove(filepath.Join(a.dataDir, "dnsmasq-"+t.name+".conf"))
		os.Remove(filepath.Join(a.dataDir, "reservations-"+t.name+".conf"))
		os.Remove(filepath.Join(a.dataDir, "leases-"+t.name))
	}

	a.publishScopes(newScopes)

	if err := saveKnownScopes(a.dataDir, newScopes); err != nil {
		loglevel.Warnf("[AGENT:WARN] hot-reload: save known scopes: %v", err)
	}

	go a.TriggerOrphanCheck("HOT_RELOAD_CHECK")

	if len(report) == 0 {
		loglevel.Infof("[AGENT:HOT_RELOAD] no scope changes to apply")
		return report
	}
	for _, line := range report {
		loglevel.Infof("[AGENT:HOT_RELOAD] %s", line)
	}
	return report
}

// publishScopes atomically swaps in a fresh copy of newScopes as the
// agent's current scope set.
func (a *Agent) publishScopes(newScopes map[string]config.ScopeConfig) {
	cp := make(map[string]config.ScopeConfig, len(newScopes))
	for k, v := range newScopes {
		cp[k] = v
	}
	a.scopes.Store(&cp)
}
