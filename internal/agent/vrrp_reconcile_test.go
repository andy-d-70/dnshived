// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dnshived/internal/config"
)

func TestReconcileVRRPPriorities_ArbiterRoleStillCommits(t *testing.T) {
	a := &Agent{
		role:    config.RoleCore3,
		dataDir: t.TempDir(),
	}
	scopes := map[string]config.ScopeConfig{"office": {VLANID: 104, PreferredWorker: "core-1"}}
	a.scopes.Store(&scopes)
	last := map[string]int{}
	constructed := map[string]bool{"office": true}

	_, ok := a.reconcileVRRPPriorities(nil, last, constructed, time.Now())
	if ok {
		t.Error("ok = true, want false (arbiter role must now attempt real render/reload work, same as any other core role)")
	}
}

// TestReconcileVRRPPriorities_WorkerRoleStillCommits is a light control
// pin.
func TestReconcileVRRPPriorities_WorkerRoleStillCommits(t *testing.T) {
	a := &Agent{
		role:    config.RoleCore1,
		dataDir: t.TempDir(),
	}
	scopes := map[string]config.ScopeConfig{"office": {VLANID: 104, PreferredWorker: "core-1"}}
	a.scopes.Store(&scopes)
	last := map[string]int{}
	constructed := map[string]bool{"office": true}

	_, ok := a.reconcileVRRPPriorities(nil, last, constructed, time.Now())
	if ok {
		t.Error("ok = true, want false — a worker with no real helper/keepalived process must fail (and retry), not silently no-op")
	}
}

func TestReconcileVRRPPriorities_ExcludesNotYetConstructedScope(t *testing.T) {
	a := &Agent{
		role:    config.RoleCore1,
		dataDir: t.TempDir(),
		ready:   map[string]time.Time{"office": time.Now()},
	}
	scopes := map[string]config.ScopeConfig{
		"office":       {VLANID: 104, Parent: "ens19", PreferredWorker: "core-1"},
		"just-hotload": {VLANID: 999, Parent: "ens19", PreferredWorker: "core-1"},
	}
	a.scopes.Store(&scopes)
	last := map[string]int{}
	constructed := map[string]bool{"office": true}

	a.reconcileVRRPPriorities(nil, last, constructed, time.Now())

	data, err := os.ReadFile(filepath.Join(a.dataDir, "keepalived.conf"))
	if err != nil {
		t.Fatalf("read rendered keepalived.conf: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, "DNSHIVED_office") {
		t.Errorf("rendered config missing the real, ready scope's own vrrp_instance; got:\n%s", text)
	}
	if strings.Contains(text, "DNSHIVED_just-hotload") {
		t.Errorf("rendered config includes a NOT-yet-constructed scope's vrrp_instance -- "+
			"this is exactly what crash-loops keepalived on a real cluster; got:\n%s", text)
	}
}
