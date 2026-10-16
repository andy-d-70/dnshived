// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeProbeConfigFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "probe.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

const baseProbeConfigJSON = `{
	"listen_addr": ":9444",
	"trunk_parent": "ens19",
	"cluster_token": "tok",
	"cluster_nodes": [{"name": "core-1", "addr": "192.168.0.22:9443"}]
}`

func TestLoadProbeConfig_LocalOctetZeroSkipsVLANValidation(t *testing.T) {
	path := writeProbeConfigFile(t, baseProbeConfigJSON)
	cfg, err := loadProbeConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.LocalOctet != 0 {
		t.Errorf("LocalOctet = %d, want 0 (unset)", cfg.LocalOctet)
	}
}

func TestLoadProbeConfig_LocalOctetRequiresHelperSocket(t *testing.T) {
	path := writeProbeConfigFile(t, `{
		"listen_addr": ":9444",
		"trunk_parent": "ens19",
		"cluster_token": "tok",
		"cluster_nodes": [{"name": "core-1", "addr": "192.168.0.22:9443"}],
		"local_octet": 42,
		"known_vlans_path": "/var/lib/probe/known-vlans.json"
	}`)
	if _, err := loadProbeConfig(path); err == nil {
		t.Fatal("expected an error when local_octet is set without probe_helper_socket")
	}
}

func TestLoadProbeConfig_LocalOctetRequiresKnownVLANsPath(t *testing.T) {
	path := writeProbeConfigFile(t, `{
		"listen_addr": ":9444",
		"trunk_parent": "ens19",
		"cluster_token": "tok",
		"cluster_nodes": [{"name": "core-1", "addr": "192.168.0.22:9443"}],
		"local_octet": 42,
		"probe_helper_socket": "/run/dnshived/probe-helper.sock"
	}`)
	if _, err := loadProbeConfig(path); err == nil {
		t.Fatal("expected an error when local_octet is set without known_vlans_path")
	}
}

func TestLoadProbeConfig_LocalOctetOutOfRangeRejected(t *testing.T) {
	path := writeProbeConfigFile(t, `{
		"listen_addr": ":9444",
		"trunk_parent": "ens19",
		"cluster_token": "tok",
		"cluster_nodes": [{"name": "core-1", "addr": "192.168.0.22:9443"}],
		"local_octet": 300,
		"probe_helper_socket": "/run/dnshived/probe-helper.sock",
		"known_vlans_path": "/var/lib/probe/known-vlans.json"
	}`)
	if _, err := loadProbeConfig(path); err == nil {
		t.Fatal("expected an error for local_octet out of range")
	}
}

func TestLoadProbeConfig_LocalOctetValidCombinationAccepted(t *testing.T) {
	path := writeProbeConfigFile(t, `{
		"listen_addr": ":9444",
		"trunk_parent": "ens19",
		"cluster_token": "tok",
		"cluster_nodes": [{"name": "core-1", "addr": "192.168.0.22:9443"}],
		"local_octet": 42,
		"trunk_parents": ["ens19", "ens20"],
		"probe_helper_socket": "/run/dnshived/probe-helper.sock",
		"known_vlans_path": "/var/lib/probe/known-vlans.json"
	}`)
	cfg, err := loadProbeConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.LocalOctet != 42 {
		t.Errorf("LocalOctet = %d, want 42", cfg.LocalOctet)
	}
}

func TestProbeConfig_TrunkParentsFallsBackToTrunkParent(t *testing.T) {
	cfg := &ProbeConfig{TrunkParent: "ens19"}
	got := cfg.trunkParents()
	if len(got) != 1 || got[0] != "ens19" {
		t.Errorf("trunkParents() = %v, want [ens19]", got)
	}
}

func TestProbeConfig_TrunkParentsExplicitOverridesFallback(t *testing.T) {
	cfg := &ProbeConfig{TrunkParent: "ens19", TrunkParents: []string{"ens19", "ens20"}}
	got := cfg.trunkParents()
	if len(got) != 2 {
		t.Errorf("trunkParents() = %v, want [ens19 ens20]", got)
	}
}

func TestProbeConfig_KnownVLANsPathFallsBackToDefault(t *testing.T) {
	cfg := &ProbeConfig{}
	if got := cfg.knownVLANsPath(); got == "" {
		t.Error("knownVLANsPath() should never return empty")
	}
}

func TestProbeConfig_KnownVLANsPathExplicitOverridesDefault(t *testing.T) {
	cfg := &ProbeConfig{KnownVLANsPath: "/custom/path.json"}
	if got := cfg.knownVLANsPath(); got != "/custom/path.json" {
		t.Errorf("knownVLANsPath() = %q, want /custom/path.json", got)
	}
}

func TestLoadProbeConfig_ParallelProbingDefaultsFalse(t *testing.T) {
	path := writeProbeConfigFile(t, baseProbeConfigJSON)
	cfg, err := loadProbeConfig(path)
	if err != nil {
		t.Fatalf("loadProbeConfig: %v", err)
	}
	if cfg.ParallelProbing {
		t.Error("ParallelProbing = true, want false when the field is absent from probe.json")
	}
}

func TestLoadProbeConfig_ParallelProbingExplicitTrueParses(t *testing.T) {
	path := writeProbeConfigFile(t, `{
		"listen_addr": ":9444",
		"trunk_parent": "ens19",
		"cluster_token": "tok",
		"cluster_nodes": [{"name": "core-1", "addr": "192.168.0.22:9443"}],
		"parallel_probing": true
	}`)
	cfg, err := loadProbeConfig(path)
	if err != nil {
		t.Fatalf("loadProbeConfig: %v", err)
	}
	if !cfg.ParallelProbing {
		t.Error("ParallelProbing = false, want true")
	}
}
