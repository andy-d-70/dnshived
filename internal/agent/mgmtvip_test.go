// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dnshived/internal/config"
)

func TestRenderMgmtVIPConfig_NoopWhenNil(t *testing.T) {
	dir := t.TempDir()
	platform := &config.Platform{Mgmt: "eth0"}
	a := &Agent{dataDir: dir, role: config.RoleCore1}

	if err := a.RenderMgmtVIPConfig(nil, platform); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "keepalived-mgmt.conf")); !os.IsNotExist(err) {
		t.Error("expected no file written when mgmtVIP is nil")
	}
}

// TestCachedMgmtVIPState_EmptyBeforeAnyRefresh confirms the cache starts
// empty (never a stale/fabricated value) before RefreshMgmtVIPStateCache
// has ever run.
func TestCachedMgmtVIPState_EmptyBeforeAnyRefresh(t *testing.T) {
	a := &Agent{role: config.RoleCore1}
	if got := a.CachedMgmtVIPState(); got != "" {
		t.Errorf("CachedMgmtVIPState() = %q before any refresh, want empty", got)
	}
}

// TestCachedMgmtVIPState_ReadsWhateverWasCached proves the getter actually
// reads back what the mutex-guarded cache field holds.
func TestCachedMgmtVIPState_ReadsWhateverWasCached(t *testing.T) {
	a := &Agent{role: config.RoleCore1}
	a.mgmtVIPStateMu.Lock()
	a.mgmtVIPStateCached = "MASTER"
	a.mgmtVIPStateMu.Unlock()

	if got := a.CachedMgmtVIPState(); got != "MASTER" {
		t.Errorf("CachedMgmtVIPState() = %q, want %q", got, "MASTER")
	}
}

func TestRefreshMgmtVIPStateCache_ClearsStaleValueOnError(t *testing.T) {
	a := &Agent{role: config.RoleCore1}
	a.mgmtVIPStateMu.Lock()
	a.mgmtVIPStateCached = "MASTER" // simulate a stale prior value
	a.mgmtVIPStateMu.Unlock()

	a.RefreshMgmtVIPStateCache()

	if got := a.CachedMgmtVIPState(); got != "" {
		t.Errorf("CachedMgmtVIPState() = %q after a failed refresh, want empty (not the stale prior value)", got)
	}
}

func TestRenderMgmtVIPConfig_NoopWithoutPlatform(t *testing.T) {
	dir := t.TempDir()
	vip := &config.MgmtVIPConfig{VIP: "192.168.0.100/24", VRRPID: 200}
	a := &Agent{dataDir: dir, role: config.RoleCore1}

	if err := a.RenderMgmtVIPConfig(vip, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "keepalived-mgmt.conf")); !os.IsNotExist(err) {
		t.Error("expected no file written when platform is nil")
	}
}

// TestRenderMgmtVIPConfig_Core3GetsPreferredPriority checks core-3 gets
// the preferred mgmt VIP priority.
func TestRenderMgmtVIPConfig_Core3GetsPreferredPriority(t *testing.T) {
	dir := t.TempDir()
	vip := &config.MgmtVIPConfig{VIP: "192.168.0.100/24", VRRPID: 200}
	platform := &config.Platform{Mgmt: "eth0"}
	a := &Agent{dataDir: dir, role: config.RoleCore3}

	if err := a.RenderMgmtVIPConfig(vip, platform); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "keepalived-mgmt.conf"))
	if err != nil {
		t.Fatalf("expected a rendered file on core-3, not a no-op: %v", err)
	}
	if !strings.Contains(string(data), "priority 110") {
		t.Errorf("expected priority 110 (highest, preferred) for core-3, got:\n%s", data)
	}
}

func TestRenderMgmtVIPConfig_Core1GetsMiddlePriority(t *testing.T) {
	dir := t.TempDir()
	vip := &config.MgmtVIPConfig{VIP: "192.168.0.100/24", VRRPID: 200}
	platform := &config.Platform{Mgmt: "eth0"}
	a := &Agent{dataDir: dir, role: config.RoleCore1}

	if err := a.RenderMgmtVIPConfig(vip, platform); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "keepalived-mgmt.conf"))
	if err != nil {
		t.Fatalf("expected a rendered file: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "priority 100") {
		t.Errorf("expected priority 100 for core-1 (first fallback, below core-3), got:\n%s", content)
	}
	if !strings.Contains(content, "interface eth0") {
		t.Errorf("expected the raw platform.mgmt interface (eth0), not a VLAN sub-interface, got:\n%s", content)
	}
	if !strings.Contains(content, "virtual_router_id 200") {
		t.Errorf("expected virtual_router_id 200, got:\n%s", content)
	}
	if !strings.Contains(content, "nopreempt") {
		t.Errorf("expected nopreempt so a later-onboarded/recovered higher-priority node can't take the VIP away from whoever already holds it, got:\n%s", content)
	}
	if strings.Contains(content, "version 3") {
		t.Errorf("mgmt VIP must stay VRRPv2 (no version 3) — got:\n%s", content)
	}
}

func TestRenderMgmtVIPConfig_Core2GetsLowestPriority(t *testing.T) {
	dir := t.TempDir()
	vip := &config.MgmtVIPConfig{VIP: "192.168.0.100/24", VRRPID: 200}
	platform := &config.Platform{Mgmt: "eth0"}
	a := &Agent{dataDir: dir, role: config.RoleCore2}

	if err := a.RenderMgmtVIPConfig(vip, platform); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "keepalived-mgmt.conf"))
	if err != nil {
		t.Fatalf("expected a rendered file: %v", err)
	}
	if !strings.Contains(string(data), "priority 90") {
		t.Errorf("expected priority 90 (lowest, second fallback) for core-2, got:\n%s", data)
	}
}

func TestRenderMgmtVIPConfig_RemovalDecommissionsStaleFile(t *testing.T) {
	dir := t.TempDir()
	vip := &config.MgmtVIPConfig{VIP: "192.168.0.100/24", VRRPID: 200}
	platform := &config.Platform{Mgmt: "eth0"}
	a := &Agent{dataDir: dir, role: config.RoleCore1}

	if err := a.RenderMgmtVIPConfig(vip, platform); err != nil {
		t.Fatalf("initial render: %v", err)
	}
	path := filepath.Join(dir, "keepalived-mgmt.conf")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected file to exist after initial render: %v", err)
	}

	if err := a.RenderMgmtVIPConfig(nil, platform); err != nil {
		t.Fatalf("decommission call: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("expected keepalived-mgmt.conf to be removed once mgmtVIP is no longer configured")
	}
}

func TestRenderMgmtVIPConfig_DecommissionNoopWhenNothingRendered(t *testing.T) {
	dir := t.TempDir()
	a := &Agent{dataDir: dir, role: config.RoleCore1}

	if err := a.RenderMgmtVIPConfig(nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
