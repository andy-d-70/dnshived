// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"testing"

	"dnshived/internal/config"
)

func TestLoadCandidateConfig_MissingIsNotAnError(t *testing.T) {
	dataDir := t.TempDir()
	cand, exists, err := loadCandidateConfig(dataDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if exists || cand != nil {
		t.Errorf("exists = %v, cand = %+v, want false/nil for a missing candidate", exists, cand)
	}
}

func TestApplyCandidateUpdate_SavesSeparatelyFromLiveConfig(t *testing.T) {
	cfgPath := writeBaseConfig(t)
	dataDir := t.TempDir()

	upd := configUpdate{
		PSK: testPSK, Platform: testPlatform(),
		Scopes: map[string]config.ScopeConfig{
			"office": {
				Parent: "ens19", VLANID: 100, VIP: "192.168.100.1/24",
				DHCPRange: [2]string{"192.168.100.100", "192.168.100.200"},
				Gateway:   "192.168.100.1",
				VRRPID:    51, PreferredWorker: config.RoleCore1,
			},
		},
	}

	status, body := applyCandidateUpdate(dataDir, cfgPath, upd)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %+v", status, http.StatusOK, body)
	}

	// The LIVE config must be completely untouched — this is the whole
	// point of a staged candidate.
	live, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("reload live: %v", err)
	}
	if live.HasScopes() {
		t.Error("live config gained scopes from a candidate-only save — candidate must never touch cfgPath")
	}

	cand, exists, err := loadCandidateConfig(dataDir)
	if err != nil {
		t.Fatalf("load candidate: %v", err)
	}
	if !exists {
		t.Fatal("candidate not found after applyCandidateUpdate")
	}
	if _, ok := cand.Scopes["office"]; !ok {
		t.Error("candidate missing the staged scope")
	}
}

// TestApplyCandidateUpdate_PreservesLiveNodeIP mirrors
// TestApplyConfigUpdate_PreservesExistingScopeNodeIP.
func TestApplyCandidateUpdate_AcceptsNodeIPChange(t *testing.T) {
	cfgPath := writeBaseConfig(t)
	dataDir := t.TempDir()

	seedLive := configUpdate{
		PSK: testPSK, Platform: testPlatform(),
		Scopes: map[string]config.ScopeConfig{
			"office": {
				Parent: "ens19", VLANID: 100, VIP: "192.168.100.1/24",
				NodeIP:    "192.168.100.23/24",
				DHCPRange: [2]string{"192.168.100.100", "192.168.100.200"},
				Gateway:   "192.168.100.1",
				VRRPID:    51, PreferredWorker: config.RoleCore1,
			},
		},
	}
	if status, body := applyConfigUpdate(cfgPath, seedLive, nil, nil, nil); status != http.StatusOK {
		t.Fatalf("seed live status = %d, want %d, body = %+v", status, http.StatusOK, body)
	}

	edit := configUpdate{
		PSK: testPSK, Platform: testPlatform(),
		Scopes: map[string]config.ScopeConfig{
			"office": {
				Parent: "ens19", VLANID: 100, VIP: "192.168.100.1/24",
				NodeIP:    "192.168.100.22/24", // a genuine, intentional change
				DHCPRange: [2]string{"192.168.100.150", "192.168.100.250"},
				Gateway:   "192.168.100.1",
				VRRPID:    51, PreferredWorker: config.RoleCore1,
			},
		},
	}
	status, body := applyCandidateUpdate(dataDir, cfgPath, edit)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %+v", status, http.StatusOK, body)
	}

	cand, _, err := loadCandidateConfig(dataDir)
	if err != nil {
		t.Fatalf("load candidate: %v", err)
	}
	sc, ok := cand.Scopes["office"]
	if !ok {
		t.Fatal("scope 'office' missing from candidate")
	}
	if sc.NodeIP != "192.168.100.22/24" {
		t.Errorf("NodeIP = %q, want the staged new value %q — NodeIP must no longer be frozen", sc.NodeIP, "192.168.100.22/24")
	}
	if sc.DHCPRange != [2]string{"192.168.100.150", "192.168.100.250"} {
		t.Errorf("DHCPRange = %v, want the candidate push's new value to still apply", sc.DHCPRange)
	}
}

func TestApplyCandidateUpdate_ValidationFailureNotSaved(t *testing.T) {
	cfgPath := writeBaseConfig(t)
	dataDir := t.TempDir()

	bad := configUpdate{}
	status, body := applyCandidateUpdate(dataDir, cfgPath, bad)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body = %+v", status, http.StatusBadRequest, body)
	}
	if _, exists, _ := loadCandidateConfig(dataDir); exists {
		t.Error("candidate saved despite a validation failure")
	}
}

func TestDiscardCandidateConfig_MissingIsNotAnError(t *testing.T) {
	if err := discardCandidateConfig(t.TempDir()); err != nil {
		t.Errorf("discard of a never-created candidate: %v", err)
	}
}

func TestDiscardCandidateConfig_RemovesFile(t *testing.T) {
	cfgPath := writeBaseConfig(t)
	dataDir := t.TempDir()
	upd := configUpdate{PSK: testPSK, Platform: testPlatform()}
	if status, body := applyCandidateUpdate(dataDir, cfgPath, upd); status != http.StatusOK {
		t.Fatalf("seed candidate status = %d, body = %+v", status, body)
	}

	if err := discardCandidateConfig(dataDir); err != nil {
		t.Fatalf("discard: %v", err)
	}
	if _, exists, _ := loadCandidateConfig(dataDir); exists {
		t.Error("candidate still present after discard")
	}
}

// TestDiscardCandidateScope_RevertsToLiveValue pins the per-scope revert
// path.
func TestDiscardCandidateScope_RevertsToLiveValue(t *testing.T) {
	cfgPath := writeBaseConfig(t)
	dataDir := t.TempDir()

	seedLive := configUpdate{
		PSK: testPSK, Platform: testPlatform(),
		Scopes: map[string]config.ScopeConfig{
			"office": {Parent: "ens19", VLANID: 100, VIP: "192.168.100.1/24", Gateway: "192.168.100.1", VRRPID: 50, PreferredWorker: config.RoleCore1},
		},
	}
	if status, _ := applyConfigUpdate(cfgPath, seedLive, nil, nil, nil); status != http.StatusOK {
		t.Fatalf("seed live failed")
	}

	candUpd := configUpdate{
		PSK: testPSK, Platform: testPlatform(),
		Scopes: map[string]config.ScopeConfig{
			"office": {Parent: "ens19", VLANID: 200, VIP: "192.168.200.1/24", Gateway: "192.168.200.1", VRRPID: 50, PreferredWorker: config.RoleCore1}, // edited
			"guest":  {Parent: "ens19", VLANID: 300, VIP: "192.168.201.1/24", Gateway: "192.168.201.1", VRRPID: 51, PreferredWorker: config.RoleCore1}, // untouched, should survive
		},
	}
	if status, body := applyCandidateUpdate(dataDir, cfgPath, candUpd); status != http.StatusOK {
		t.Fatalf("seed candidate status = %d, body = %+v", status, body)
	}

	if err := discardCandidateScope(dataDir, cfgPath, "office"); err != nil {
		t.Fatalf("discard scope: %v", err)
	}

	cand, exists, err := loadCandidateConfig(dataDir)
	if err != nil || !exists {
		t.Fatalf("candidate missing after per-scope revert: exists=%v err=%v", exists, err)
	}
	if cand.Scopes["office"].VLANID != 100 {
		t.Errorf("office.VLANID = %d, want 100 (reverted to live)", cand.Scopes["office"].VLANID)
	}
	if cand.Scopes["guest"].VLANID != 300 {
		t.Errorf("guest.VLANID = %d, want 300 (unrelated pending change untouched)", cand.Scopes["guest"].VLANID)
	}
}

func TestDiscardCandidateScope_RevertsWhenCandidateScopesMapIsNil(t *testing.T) {
	cfgPath := writeBaseConfig(t)
	dataDir := t.TempDir()

	seedLive := configUpdate{
		PSK: testPSK, Platform: testPlatform(),
		Scopes: map[string]config.ScopeConfig{
			"office": {Parent: "ens19", VLANID: 100, VIP: "192.168.100.1/24", Gateway: "192.168.100.1", VRRPID: 50, PreferredWorker: config.RoleCore1},
		},
	}
	if status, _ := applyConfigUpdate(cfgPath, seedLive, nil, nil, nil); status != http.StatusOK {
		t.Fatalf("seed live failed")
	}

	// Stage a candidate deleting the cluster's only scope — Scopes
	// ends up empty, which omitempty drops from the saved JSON.
	candUpd := configUpdate{
		PSK: testPSK, Platform: testPlatform(),
		Scopes: map[string]config.ScopeConfig{},
	}
	if status, body := applyCandidateUpdate(dataDir, cfgPath, candUpd); status != http.StatusOK {
		t.Fatalf("seed candidate status = %d, body = %+v", status, body)
	}

	preCand, exists, err := loadCandidateConfig(dataDir)
	if err != nil || !exists {
		t.Fatalf("candidate missing before revert: exists=%v err=%v", exists, err)
	}
	if preCand.Scopes != nil {
		t.Fatalf("test precondition not met: candidate.Scopes is non-nil (%v) — this test needs the omitempty-produced nil-map shape", preCand.Scopes)
	}

	if err := discardCandidateScope(dataDir, cfgPath, "office"); err != nil {
		t.Fatalf("discard scope: %v", err)
	}

	cand, exists, err := loadCandidateConfig(dataDir)
	if err != nil || !exists {
		t.Fatalf("candidate missing after per-scope revert: exists=%v err=%v", exists, err)
	}
	if cand.Scopes["office"].VLANID != 100 {
		t.Errorf("office.VLANID = %d, want 100 (reverted to live)", cand.Scopes["office"].VLANID)
	}
}

func TestDiscardCandidateScope_NewScopeIsRemovedEntirely(t *testing.T) {
	cfgPath := writeBaseConfig(t)
	dataDir := t.TempDir()

	candUpd := configUpdate{
		PSK: testPSK, Platform: testPlatform(),
		Scopes: map[string]config.ScopeConfig{
			"brand-new": {Parent: "ens19", VLANID: 100, VIP: "192.168.100.1/24", Gateway: "192.168.100.1", VRRPID: 50, PreferredWorker: config.RoleCore1},
		},
	}
	if status, body := applyCandidateUpdate(dataDir, cfgPath, candUpd); status != http.StatusOK {
		t.Fatalf("seed candidate status = %d, body = %+v", status, body)
	}

	if err := discardCandidateScope(dataDir, cfgPath, "brand-new"); err != nil {
		t.Fatalf("discard scope: %v", err)
	}

	cand, _, err := loadCandidateConfig(dataDir)
	if err != nil {
		t.Fatalf("load candidate: %v", err)
	}
	if _, ok := cand.Scopes["brand-new"]; ok {
		t.Error("pending new scope still present after revert — should have been dropped entirely")
	}
}

func TestDiscardCandidateScope_NoCandidateIsANoOp(t *testing.T) {
	cfgPath := writeBaseConfig(t)
	dataDir := t.TempDir()
	if err := discardCandidateScope(dataDir, cfgPath, "anything"); err != nil {
		t.Errorf("discard scope with no candidate at all: %v", err)
	}
}
