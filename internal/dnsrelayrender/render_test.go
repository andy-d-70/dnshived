// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsrelayrender

import (
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"dnshived/internal/config"
	"dnshived/internal/dnscentralrender"
)

func testCluster() config.Cluster {
	return config.Cluster{
		Scopes: map[string]config.ScopeConfig{
			"office": {
				Parent: "ens19",
				VLANID: 42,
			},
			"av-dante": {
				Parent: "ens20",
				VLANID: 100,
			},
			"paused": {
				Parent:          "ens19",
				VLANID:          77,
				DNSMasqDisabled: true,
			},
		},
	}
}

func TestRenderRelayConfig_OneInterfacePerEligibleScope(t *testing.T) {
	cfg, err := RenderRelayConfig(testCluster())
	if err != nil {
		t.Fatalf("RenderRelayConfig: %v", err)
	}
	if len(cfg.AllowedInterfaces) != 2 {
		t.Fatalf("AllowedInterfaces = %v, want exactly 2 (the DNSMasqDisabled scope must be excluded)", cfg.AllowedInterfaces)
	}
	want := map[string]bool{"ens19.42": true, "ens20.100": true}
	for _, ifn := range cfg.AllowedInterfaces {
		if !want[ifn] {
			t.Errorf("unexpected interface %q", ifn)
		}
		delete(want, ifn)
	}
	if len(want) != 0 {
		t.Errorf("missing expected interfaces: %v", want)
	}
}

func TestRenderRelayConfig_DeterministicOrder(t *testing.T) {
	c := testCluster()
	cfg1, err := RenderRelayConfig(c)
	if err != nil {
		t.Fatalf("RenderRelayConfig: %v", err)
	}
	cfg2, err := RenderRelayConfig(c)
	if err != nil {
		t.Fatalf("RenderRelayConfig: %v", err)
	}
	for i := range cfg1.AllowedInterfaces {
		if cfg1.AllowedInterfaces[i] != cfg2.AllowedInterfaces[i] {
			t.Fatalf("entry %d differs between renders: %q vs %q", i, cfg1.AllowedInterfaces[i], cfg2.AllowedInterfaces[i])
		}
	}
	// Sorted by scope name ("av-dante" < "office" alphabetically) --
	// pins down the actual order, not just that it's stable.
	if cfg1.AllowedInterfaces[0] != "ens20.100" {
		t.Errorf("first entry = %q, want ens20.100 (av-dante sorts before office)", cfg1.AllowedInterfaces[0])
	}
}

func TestRenderRelayConfig_UpstreamDefaultsToDnsCentralAddress(t *testing.T) {
	cfg, err := RenderRelayConfig(testCluster())
	if err != nil {
		t.Fatalf("RenderRelayConfig: %v", err)
	}
	if len(cfg.Upstreams) != 1 || cfg.Upstreams[0] != dnscentralrender.DefaultAddress {
		t.Errorf("Upstreams = %v, want [%q]", cfg.Upstreams, dnscentralrender.DefaultAddress)
	}
}

func TestRenderRelayConfig_HonorsExplicitCoreDNSAddress(t *testing.T) {
	c := testCluster()
	c.CoreDNSAddress = "127.0.0.99"
	cfg, err := RenderRelayConfig(c)
	if err != nil {
		t.Fatalf("RenderRelayConfig: %v", err)
	}
	if cfg.Upstreams[0] != "127.0.0.99" {
		t.Errorf("Upstreams[0] = %q, want the explicit override %q", cfg.Upstreams[0], "127.0.0.99")
	}
}

func TestRenderRelayConfig_NoEligibleScopeErrors(t *testing.T) {
	c := config.Cluster{
		Scopes: map[string]config.ScopeConfig{
			"paused": {Parent: "ens19", VLANID: 1, DNSMasqDisabled: true},
		},
	}
	if _, err := RenderRelayConfig(c); err == nil {
		t.Error("RenderRelayConfig = nil error, want an error when no scope is eligible")
	}
}

func TestWriteRelayConfig_CreatesFileMatchingDnshivedDnsrelaySchema(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsrelay.json")

	if err := WriteRelayConfig(path, testCluster()); err != nil {
		t.Fatalf("WriteRelayConfig: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	var written map[string]any
	if err := json.Unmarshal(data, &written); err != nil {
		t.Fatalf("written file is not valid JSON: %v", err)
	}
	if _, ok := written["upstreams"]; !ok {
		t.Error("written file has no \"upstreams\" field")
	}
	if _, ok := written["allowed_interfaces"]; !ok {
		t.Error("written file has no \"allowed_interfaces\" field")
	}
}

func TestWriteRelayConfig_PreservesUnrelatedExistingFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsrelay.json")
	existing := `{
		"upstreams": ["127.0.0.1"],
		"allowed_interfaces": ["stale.99"],
		"rate_limit": 42,
		"interface_acls": {"ens19.42": {"rate_limit": 7}},
		"rewrites": [{"match": "keep.me", "answer": "9.9.9.9"}]
	}`
	if err := os.WriteFile(path, []byte(existing), 0644); err != nil {
		t.Fatalf("seed existing file: %v", err)
	}

	if err := WriteRelayConfig(path, testCluster()); err != nil {
		t.Fatalf("WriteRelayConfig: %v", err)
	}

	data, _ := os.ReadFile(path)
	var written map[string]any
	if err := json.Unmarshal(data, &written); err != nil {
		t.Fatalf("written file is not valid JSON: %v", err)
	}
	if written["rate_limit"] != float64(42) {
		t.Errorf("rate_limit = %v, want preserved 42", written["rate_limit"])
	}
	if _, ok := written["interface_acls"]; !ok {
		t.Error("interface_acls was dropped by the re-render")
	}
	if _, ok := written["rewrites"]; !ok {
		t.Error("rewrites was dropped by the re-render")
	}
	// The two cluster-derived fields, meanwhile, must actually be the
	// NEW render, not the stale seeded values.
	ifaces, _ := written["allowed_interfaces"].([]any)
	if len(ifaces) != 2 {
		t.Errorf("allowed_interfaces = %v, want the freshly-rendered 2 entries, not the stale seed", written["allowed_interfaces"])
	}
}

func TestWriteRelayConfig_MissingFileStartsFresh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist-yet.json")
	if err := WriteRelayConfig(path, testCluster()); err != nil {
		t.Fatalf("WriteRelayConfig: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected the file to now exist: %v", err)
	}
}

func TestWriteRelayConfig_GroupOwnedByDnshived(t *testing.T) {
	g, err := user.LookupGroup("dnshived")
	if err != nil {
		t.Skipf("no \"dnshived\" group on this host, skipping: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsrelay.json")

	if err := WriteRelayConfig(path, testCluster()); err != nil {
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
		t.Errorf("dnsrelay.json group gid = %d, want %d (dnshived)", stat.Gid, wantGid)
	}
}

func TestRenderRelayConfig_CacheFieldsFollowCluster(t *testing.T) {
	c := testCluster()
	cfg, err := RenderRelayConfig(c)
	if err != nil {
		t.Fatalf("RenderRelayConfig: %v", err)
	}
	if cfg.CacheSize != 0 || cfg.CacheMaxBytes != 0 {
		t.Errorf("CacheSize/CacheMaxBytes = %d/%d, want 0/0 when the cluster never configured either", cfg.CacheSize, cfg.CacheMaxBytes)
	}

	c.DNSRelayCacheSize = 12000
	c.DNSRelayCacheMaxBytes = 8388608
	cfg, err = RenderRelayConfig(c)
	if err != nil {
		t.Fatalf("RenderRelayConfig: %v", err)
	}
	if cfg.CacheSize != 12000 || cfg.CacheMaxBytes != 8388608 {
		t.Errorf("CacheSize/CacheMaxBytes = %d/%d, want the configured 12000/8388608", cfg.CacheSize, cfg.CacheMaxBytes)
	}
}

func TestWriteRelayConfig_UnconfiguredCachePreservesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsrelay.json")
	existing := `{"upstreams": ["127.0.0.1"], "allowed_interfaces": ["stale.99"], "cache_size": 9999, "cache_max_bytes": 555}`
	if err := os.WriteFile(path, []byte(existing), 0644); err != nil {
		t.Fatalf("seed existing file: %v", err)
	}

	if err := WriteRelayConfig(path, testCluster()); err != nil { // testCluster() sets neither DNSRelayCacheSize nor DNSRelayCacheMaxBytes
		t.Fatalf("WriteRelayConfig: %v", err)
	}

	data, _ := os.ReadFile(path)
	var written map[string]any
	if err := json.Unmarshal(data, &written); err != nil {
		t.Fatalf("written file is not valid JSON: %v", err)
	}
	if written["cache_size"] != float64(9999) {
		t.Errorf("cache_size = %v, want the preserved manual value 9999", written["cache_size"])
	}
	if written["cache_max_bytes"] != float64(555) {
		t.Errorf("cache_max_bytes = %v, want the preserved manual value 555", written["cache_max_bytes"])
	}
}

func TestWriteRelayConfig_ConfiguredCacheOverwritesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsrelay.json")
	existing := `{"upstreams": ["127.0.0.1"], "allowed_interfaces": ["stale.99"], "cache_size": 9999, "cache_max_bytes": 555}`
	if err := os.WriteFile(path, []byte(existing), 0644); err != nil {
		t.Fatalf("seed existing file: %v", err)
	}

	c := testCluster()
	c.DNSRelayCacheSize = 3000
	c.DNSRelayCacheMaxBytes = 4194304
	if err := WriteRelayConfig(path, c); err != nil {
		t.Fatalf("WriteRelayConfig: %v", err)
	}

	data, _ := os.ReadFile(path)
	var written map[string]any
	if err := json.Unmarshal(data, &written); err != nil {
		t.Fatalf("written file is not valid JSON: %v", err)
	}
	if written["cache_size"] != float64(3000) {
		t.Errorf("cache_size = %v, want the freshly-configured 3000", written["cache_size"])
	}
	if written["cache_max_bytes"] != float64(4194304) {
		t.Errorf("cache_max_bytes = %v, want the freshly-configured 4194304", written["cache_max_bytes"])
	}
}
