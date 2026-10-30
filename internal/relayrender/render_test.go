// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package relayrender

import (
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"dnshived/internal/config"
	"dnshived/internal/dhcprelay"
)

func testCluster() config.Cluster {
	return config.Cluster{
		Platform: &config.Platform{Workers: []string{"ens19", "ens20"}},
		Scopes: map[string]config.ScopeConfig{
			"office": {
				Parent: "ens19",
				VLANID: 42,
				NodeIP: "192.168.10.22/24",
			},
			"av-dante": {
				Parent: "ens20",
				VLANID: 100,
				NodeIP: "172.16.100.22/24",
			},
			"no-node-ip-yet": {
				Parent: "ens19",
				VLANID: 200,
			},
		},
	}
}

func TestRenderRelayConfig_OneEntryPerScopeWithNodeIP(t *testing.T) {
	cfg, err := RenderRelayConfig(testCluster(), "")
	if err != nil {
		t.Fatalf("RenderRelayConfig: %v", err)
	}
	if len(cfg.ClientInterfaces) != 2 {
		t.Fatalf("ClientInterfaces = %d, want 2 (the scope with no node_ip must be skipped)", len(cfg.ClientInterfaces))
	}

	byName := make(map[string]string)
	for _, ci := range cfg.ClientInterfaces {
		byName[ci.Name] = ci.GIAddr
	}
	if got := byName["ens19.42"]; got != "192.168.10.22" {
		t.Errorf("ens19.42 giaddr = %q, want 192.168.10.22 (CIDR suffix must be stripped)", got)
	}
	if got := byName["ens20.100"]; got != "172.16.100.22" {
		t.Errorf("ens20.100 giaddr = %q, want 172.16.100.22", got)
	}
	if _, present := byName["ens19.200"]; present {
		t.Error("scope with no node_ip should not have produced a client interface")
	}
}

func TestRenderRelayConfig_ServerIdentifierIsScopeVIP(t *testing.T) {
	cluster := config.Cluster{
		Platform: &config.Platform{Workers: []string{"ens19"}},
		Scopes: map[string]config.ScopeConfig{
			"office": {
				Parent: "ens19",
				VLANID: 42,
				NodeIP: "192.168.10.22/24",
				VIP:    "192.168.10.1/24",
			},
		},
	}
	cfg, err := RenderRelayConfig(cluster, "")
	if err != nil {
		t.Fatalf("RenderRelayConfig: %v", err)
	}
	if len(cfg.ClientInterfaces) != 1 {
		t.Fatalf("ClientInterfaces = %d, want 1", len(cfg.ClientInterfaces))
	}
	ci := cfg.ClientInterfaces[0]
	if ci.ServerIdentifier != "192.168.10.1" {
		t.Errorf("ServerIdentifier = %q, want the scope's VIP 192.168.10.1 (CIDR suffix stripped)", ci.ServerIdentifier)
	}
	if ci.GIAddr != "192.168.10.22" {
		t.Errorf("GIAddr = %q, want this node's own node_ip 192.168.10.22, unchanged by the VIP addition", ci.GIAddr)
	}
}

// TestRenderRelayConfig_NoVIPRendersEmptyServerIdentifier confirms a scope
// with no VIP yet renders an empty ServerIdentifier.
func TestRenderRelayConfig_NoVIPRendersEmptyServerIdentifier(t *testing.T) {
	cfg, err := RenderRelayConfig(testCluster(), "")
	if err != nil {
		t.Fatalf("RenderRelayConfig: %v", err)
	}
	for _, ci := range cfg.ClientInterfaces {
		if ci.ServerIdentifier != "" {
			t.Errorf("%s: ServerIdentifier = %q, want empty (testCluster's scopes have no VIP)", ci.Name, ci.ServerIdentifier)
		}
	}
}

func TestRenderRelayConfig_ServerInterfaceIsAlwaysLo(t *testing.T) {
	cfg, err := RenderRelayConfig(testCluster(), "")
	if err != nil {
		t.Fatalf("RenderRelayConfig: %v", err)
	}
	if cfg.ServerInterface != "lo" {
		t.Errorf("ServerInterface = %q, want %q", cfg.ServerInterface, "lo")
	}
}

func TestRenderRelayConfig_DefaultServerAddrUsedWhenEmpty(t *testing.T) {
	cfg, err := RenderRelayConfig(testCluster(), "")
	if err != nil {
		t.Fatalf("RenderRelayConfig: %v", err)
	}
	if cfg.ServerAddr != DefaultServerAddr {
		t.Errorf("ServerAddr = %q, want default %q", cfg.ServerAddr, DefaultServerAddr)
	}
}

func TestRenderRelayConfig_ExplicitServerAddrHonored(t *testing.T) {
	cfg, err := RenderRelayConfig(testCluster(), "127.0.0.21:6767")
	if err != nil {
		t.Fatalf("RenderRelayConfig: %v", err)
	}
	if cfg.ServerAddr != "127.0.0.21:6767" {
		t.Errorf("ServerAddr = %q, want the explicit override", cfg.ServerAddr)
	}
}

func TestRenderRelayConfig_DeterministicOrder(t *testing.T) {
	c := testCluster()
	cfg1, err := RenderRelayConfig(c, "")
	if err != nil {
		t.Fatalf("RenderRelayConfig: %v", err)
	}
	cfg2, err := RenderRelayConfig(c, "")
	if err != nil {
		t.Fatalf("RenderRelayConfig: %v", err)
	}
	if len(cfg1.ClientInterfaces) != len(cfg2.ClientInterfaces) {
		t.Fatal("length differs between renders")
	}
	for i := range cfg1.ClientInterfaces {
		if cfg1.ClientInterfaces[i] != cfg2.ClientInterfaces[i] {
			t.Errorf("entry %d differs between renders: %+v vs %+v", i, cfg1.ClientInterfaces[i], cfg2.ClientInterfaces[i])
		}
	}
	// Sorted by scope name ("av-dante" < "office" alphabetically) --
	// pins down the actual order, not just that it's stable.
	if cfg1.ClientInterfaces[0].Name != "ens20.100" {
		t.Errorf("first entry = %q, want ens20.100 (av-dante sorts before office)", cfg1.ClientInterfaces[0].Name)
	}
}

func TestRenderRelayConfig_NoScopeHasNodeIP_Errors(t *testing.T) {
	c := config.Cluster{
		Scopes: map[string]config.ScopeConfig{
			"office": {Parent: "ens19", VLANID: 42},
		},
	}
	if _, err := RenderRelayConfig(c, ""); err == nil {
		t.Error("RenderRelayConfig = nil error, want an error when no scope has a node_ip")
	}
}

func TestRenderRelayConfig_EveryScopeRoutesToSharedDefault(t *testing.T) {
	cfg, err := RenderRelayConfig(testCluster(), "")
	if err != nil {
		t.Fatalf("RenderRelayConfig: %v", err)
	}
	for _, ci := range cfg.ClientInterfaces {
		if ci.ServerAddr != "" {
			t.Errorf("%s has a per-interface ServerAddr override (%q), want empty -- every scope must route to the single shared instance", ci.Name, ci.ServerAddr)
		}
	}
}

func TestWriteRelayConfig_RoundTripsThroughLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.json")

	if err := WriteRelayConfig(path, testCluster(), ""); err != nil {
		t.Fatalf("WriteRelayConfig: %v", err)
	}

	loaded, err := dhcprelay.LoadConfig(path)
	if err != nil {
		t.Fatalf("dhcprelay.LoadConfig: %v", err)
	}
	if len(loaded.ClientInterfaces) != 2 {
		t.Errorf("loaded ClientInterfaces = %d, want 2", len(loaded.ClientInterfaces))
	}
	if loaded.ServerAddr != DefaultServerAddr {
		t.Errorf("loaded ServerAddr = %q, want %q", loaded.ServerAddr, DefaultServerAddr)
	}
}

func TestWriteRelayConfig_PreservesRateLimitAcrossRerender(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.json")

	if err := WriteRelayConfig(path, testCluster(), ""); err != nil {
		t.Fatalf("first WriteRelayConfig: %v", err)
	}

	// Simulate an operator hand-tuning the just-rendered file.
	loaded, err := dhcprelay.LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig after first render: %v", err)
	}
	loaded.RateLimit = 500
	loaded.RateBurst = 1000
	for i, ci := range loaded.ClientInterfaces {
		if ci.Name == "ens19.42" { // "office"
			loaded.ClientInterfaces[i].RateLimit = 20
			loaded.ClientInterfaces[i].RateBurst = 40
		}
	}
	data, err := json.MarshalIndent(loaded, "", "  ")
	if err != nil {
		t.Fatalf("marshal hand-tuned config: %v", err)
	}
	if err := os.WriteFile(path, data, 0640); err != nil {
		t.Fatalf("write hand-tuned config: %v", err)
	}

	// Re-render — the SAME cluster, nothing scope-related changed.
	if err := WriteRelayConfig(path, testCluster(), ""); err != nil {
		t.Fatalf("second WriteRelayConfig: %v", err)
	}

	reloaded, err := dhcprelay.LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig after re-render: %v", err)
	}
	if reloaded.RateLimit != 500 || reloaded.RateBurst != 1000 {
		t.Errorf("cluster-wide rate limit = %d/%d, want 500/1000 (should survive re-render)", reloaded.RateLimit, reloaded.RateBurst)
	}
	var found bool
	for _, ci := range reloaded.ClientInterfaces {
		if ci.Name == "ens19.42" {
			found = true
			if ci.RateLimit != 20 || ci.RateBurst != 40 {
				t.Errorf("ens19.42 rate limit = %d/%d, want 20/40 (should survive re-render)", ci.RateLimit, ci.RateBurst)
			}
		}
	}
	if !found {
		t.Fatal("ens19.42 (office) missing from re-rendered ClientInterfaces")
	}
}

// TestWriteRelayConfig_NoExistingFileStartsFresh confirms a first-ever
// render (no prior file to preserve anything from) still succeeds cleanly.
func TestWriteRelayConfig_NoExistingFileStartsFresh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.json")

	if err := WriteRelayConfig(path, testCluster(), ""); err != nil {
		t.Fatalf("WriteRelayConfig with no prior file: %v", err)
	}
	loaded, err := dhcprelay.LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if loaded.RateLimit != 0 || loaded.RateBurst != 0 {
		t.Errorf("rate limit = %d/%d, want 0/0 (unset) on a genuinely fresh render", loaded.RateLimit, loaded.RateBurst)
	}
}

func TestWriteRelayConfig_GroupOwnedByRelayGroup(t *testing.T) {
	g, err := user.LookupGroup(relayGroup)
	if err != nil {
		t.Skipf("no %q group on this host, skipping: %v", relayGroup, err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.json")

	if err := WriteRelayConfig(path, testCluster(), ""); err != nil {
		t.Fatalf("WriteRelayConfig: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("could not read raw stat_t for gid check")
	}
	wantGid, _ := strconv.Atoi(g.Gid)
	if int(stat.Gid) != wantGid {
		t.Errorf("relay.json group gid = %d, want %d (%s) — the relay process (Group=%s) must be able to read its own config", stat.Gid, wantGid, relayGroup, relayGroup)
	}
}

func TestWriteRelayConfig_PreservesOptionalLimitsAcrossRerender(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.json")
	if err := WriteRelayConfig(path, testCluster(), ""); err != nil {
		t.Fatalf("first WriteRelayConfig: %v", err)
	}
	loaded, err := dhcprelay.LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if loaded.PendingPerVLAN != 0 || loaded.ClientRateLimit != 0 || loaded.ClientRateBurst != 0 {
		t.Fatalf("a fresh render must leave the optional limits at their defaults (0): %+v", loaded)
	}
	loaded.PendingPerVLAN, loaded.ClientRateLimit, loaded.ClientRateBurst = 500, -1, 7
	data, _ := json.MarshalIndent(loaded, "", "  ")
	if err := os.WriteFile(path, data, 0640); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := WriteRelayConfig(path, testCluster(), ""); err != nil {
		t.Fatalf("second WriteRelayConfig: %v", err)
	}
	reloaded, err := dhcprelay.LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig after re-render: %v", err)
	}
	if reloaded.PendingPerVLAN != 500 || reloaded.ClientRateLimit != -1 || reloaded.ClientRateBurst != 7 {
		t.Errorf("optional limits lost on re-render: %d %d %d", reloaded.PendingPerVLAN, reloaded.ClientRateLimit, reloaded.ClientRateBurst)
	}
}

func TestLoadConfig_OldRelayJSONWithoutOptionalLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.json")
	old := `{"client_interfaces":[{"name":"ens19.42","giaddr":"10.42.0.22"}],"server_addr":"127.0.0.21:67","server_interface":"lo","rate_limit":50}`
	if err := os.WriteFile(path, []byte(old), 0640); err != nil {
		t.Fatal(err)
	}
	cfg, err := dhcprelay.LoadConfig(path)
	if err != nil {
		t.Fatalf("relay.json from an older release no longer loads: %v", err)
	}
	if cfg.RateLimit != 50 || cfg.PendingPerVLAN != 0 {
		t.Errorf("old fields changed meaning: %+v", cfg)
	}
}

// TestRender_CarriesNodeIDAndCoreCount covers F2: the gate needs this node's ID (tokens name their owner) and the
// number of cores (quorum is the majority of them).
func TestRender_CarriesNodeIDAndCoreCount(t *testing.T) {
	c := testCluster()
	c.NodeID = "core-1-701bf1ca87ae"
	c.Peers = []string{"192.168.0.52:9443", "192.168.0.26:9443"}
	cfg, err := RenderRelayConfig(c, "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NodeID != "core-1-701bf1ca87ae" || cfg.CoreCount != 3 {
		t.Fatalf("node_id=%q core_count=%d, want the node ID and 3", cfg.NodeID, cfg.CoreCount)
	}
}
