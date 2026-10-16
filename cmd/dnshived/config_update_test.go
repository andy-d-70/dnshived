// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"dnshived/internal/agent"
	"dnshived/internal/auth"
	"dnshived/internal/config"
)

const testPSK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"

func testPlatform() *config.Platform {
	return &config.Platform{Mgmt: "eth0", Workers: []string{"ens19"}}
}

// writeBaseConfig writes a minimal valid worker config to a temp file and
// returns its path — the seed applyConfigUpdate tests load, mutate, and
// re-save.
func writeBaseConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cluster.json")
	base := &config.Cluster{
		SchemaVersion: 2,
		ClusterID:     "test-cluster",
		NodeID:        "worker-a-node",
		Role:          config.RoleCore1,
		ControlAddr:   "10.0.0.1:9443",
		DataDir:       "/var/lib/dnshived",
		BindAddr:      ":9443",
		Peers:         []string{"10.0.0.2:9443"},
		PSK:           testPSK,
		Platform:      testPlatform(),
	}
	if err := config.Save(path, base); err != nil {
		t.Fatalf("seed config.Save: %v", err)
	}
	return path
}

func TestApplyConfigUpdate_Success(t *testing.T) {
	path := writeBaseConfig(t)

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

	status, body := applyConfigUpdate(path, upd, nil, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %+v", status, http.StatusOK, body)
	}

	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload after update: %v", err)
	}
	if !reloaded.HasScopes() {
		t.Error("scopes not persisted after applyConfigUpdate")
	}
}

func TestApplyConfigUpdate_PersistsNewDNSDefaultsFields(t *testing.T) {
	path := writeBaseConfig(t)

	upd := configUpdate{
		PSK: testPSK, Platform: testPlatform(),
		DefaultDNSChecks:   []config.DNSCheck{{Name: "example.com.", Type: "A"}},
		GlobalDNSRecords:   []config.DNSRecord{{Name: "fileserver.lan", Type: "A", Value: "10.0.0.50"}},
		ScopeDefaults:      &config.ScopeDefaults{GatewaySuffix: "1", Upstream: []string{"1.1.1.1", "8.8.8.8"}},
		DefaultDHCPOptions: []string{"option:ntp-server,10.0.0.1"},
		CoreDNSAddress:     "127.0.0.142",
		CoreDHCPAddress:    "127.0.0.121",
	}

	status, body := applyConfigUpdate(path, upd, nil, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %+v", status, http.StatusOK, body)
	}

	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload after update: %v", err)
	}
	if len(reloaded.DefaultDNSChecks) != 1 || reloaded.DefaultDNSChecks[0].Name != "example.com." {
		t.Errorf("DefaultDNSChecks not persisted: %+v", reloaded.DefaultDNSChecks)
	}
	if len(reloaded.GlobalDNSRecords) != 1 || reloaded.GlobalDNSRecords[0].Name != "fileserver.lan" {
		t.Errorf("GlobalDNSRecords not persisted: %+v", reloaded.GlobalDNSRecords)
	}
	if reloaded.ScopeDefaults == nil || reloaded.ScopeDefaults.GatewaySuffix != "1" {
		t.Errorf("ScopeDefaults not persisted: %+v", reloaded.ScopeDefaults)
	}
	if len(reloaded.DefaultDHCPOptions) != 1 || reloaded.DefaultDHCPOptions[0] != "option:ntp-server,10.0.0.1" {
		t.Errorf("DefaultDHCPOptions not persisted: %+v", reloaded.DefaultDHCPOptions)
	}
	if reloaded.CoreDNSAddress != "127.0.0.142" {
		t.Errorf("CoreDNSAddress not persisted: %q", reloaded.CoreDNSAddress)
	}
	if reloaded.CoreDHCPAddress != "127.0.0.121" {
		t.Errorf("CoreDHCPAddress not persisted: %q", reloaded.CoreDHCPAddress)
	}
}

// TestApplyConfigUpdate_PersistsBackupFields is the backup-fields
// counterpart of the DNS-defaults test above.
func TestApplyConfigUpdate_PersistsBackupFields(t *testing.T) {
	path := writeBaseConfig(t)

	upd := configUpdate{
		PSK: testPSK, Platform: testPlatform(),
		BackupEnabled:          true,
		BackupIntervalHours:    12,
		BackupRetentionCount:   7,
		BackupPassword:         "correct horse battery staple",
		BackupReplicateToPeers: true,
	}

	status, body := applyConfigUpdate(path, upd, nil, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %+v", status, http.StatusOK, body)
	}

	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload after update: %v", err)
	}
	if !reloaded.BackupEnabled {
		t.Error("BackupEnabled not persisted")
	}
	if reloaded.BackupIntervalHours != 12 {
		t.Errorf("BackupIntervalHours = %d, want 12", reloaded.BackupIntervalHours)
	}
	if reloaded.BackupRetentionCount != 7 {
		t.Errorf("BackupRetentionCount = %d, want 7", reloaded.BackupRetentionCount)
	}
	if reloaded.BackupPassword != "correct horse battery staple" {
		t.Errorf("BackupPassword not persisted: %q", reloaded.BackupPassword)
	}
	if !reloaded.BackupReplicateToPeers {
		t.Error("BackupReplicateToPeers not persisted")
	}
}

func TestClusterIdentityFieldsChanged_BackupOnlyChangeNeedsNoRestart(t *testing.T) {
	c := &config.Cluster{BackupEnabled: false}
	upd := configUpdate{BackupEnabled: true, BackupIntervalHours: 24, BackupRetentionCount: 14, BackupPassword: "x", BackupReplicateToPeers: true}

	if clusterIdentityFieldsChanged(c, upd) {
		t.Error("clusterIdentityFieldsChanged() = true for a backup-fields-only change, want false")
	}
}

func TestClusterIdentityFieldsChanged_CoreAddressOnlyChangeDoesNotNeedRestart(t *testing.T) {
	c := &config.Cluster{CoreDNSAddress: "127.0.0.42", CoreDHCPAddress: "127.0.0.21"}
	upd := configUpdate{CoreDNSAddress: "127.0.0.99", CoreDHCPAddress: "127.0.0.21"}

	if clusterIdentityFieldsChanged(c, upd) {
		t.Error("clusterIdentityFieldsChanged() = true for a CoreDNSAddress-only change, want false (live-applied via SetCoreDNSAddress)")
	}
}

func TestClusterIdentityFieldsChanged_SameCoreAddressesNoChange(t *testing.T) {
	c := &config.Cluster{CoreDNSAddress: "127.0.0.42", CoreDHCPAddress: "127.0.0.21"}
	upd := configUpdate{CoreDNSAddress: "127.0.0.42", CoreDHCPAddress: "127.0.0.21"}

	if clusterIdentityFieldsChanged(c, upd) {
		t.Error("clusterIdentityFieldsChanged() = true with identical core addresses, want false")
	}
}

func TestClusterIdentityFieldsChanged_ScopeDefaultsUpstreamChangeDoesNotNeedRestart(t *testing.T) {
	c := &config.Cluster{ScopeDefaults: &config.ScopeDefaults{Upstream: []string{"1.1.1.1"}}}
	upd := configUpdate{ScopeDefaults: &config.ScopeDefaults{Upstream: []string{"8.8.8.8"}}}

	if clusterIdentityFieldsChanged(c, upd) {
		t.Error("clusterIdentityFieldsChanged() = true for a ScopeDefaults.Upstream change, want false (live-applied via SetCentralDNSUpstream)")
	}
}

func TestApplyConfigUpdate_PreservesPeers(t *testing.T) {
	path := writeBaseConfig(t)
	before, err := config.Load(path)
	if err != nil {
		t.Fatalf("load before: %v", err)
	}

	status, _ := applyConfigUpdate(path, configUpdate{PSK: testPSK, Platform: testPlatform()}, nil, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}

	after, err := config.Load(path)
	if err != nil {
		t.Fatalf("load after: %v", err)
	}
	if len(after.Peers) != len(before.Peers) {
		t.Errorf("Peers = %v after update, want unchanged from %v", after.Peers, before.Peers)
	}
}

func TestApplyConfigUpdate_PreservesNodeIdentity(t *testing.T) {
	path := writeBaseConfig(t)
	before, err := config.Load(path)
	if err != nil {
		t.Fatalf("load before: %v", err)
	}

	status, _ := applyConfigUpdate(path, configUpdate{PSK: testPSK, Platform: testPlatform()}, nil, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}

	after, err := config.Load(path)
	if err != nil {
		t.Fatalf("load after: %v", err)
	}
	if after.NodeID != before.NodeID || after.Role != before.Role ||
		after.ControlAddr != before.ControlAddr || after.DataDir != before.DataDir ||
		after.BindAddr != before.BindAddr || after.SchemaVersion != before.SchemaVersion {
		t.Errorf("node-identity fields changed: before=%+v after=%+v", before, after)
	}
}

func TestApplyConfigUpdate_AcceptsNodeIPChangeOnExistingScope(t *testing.T) {
	path := writeBaseConfig(t)

	seed := configUpdate{
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
	if status, body := applyConfigUpdate(path, seed, nil, nil, nil); status != http.StatusOK {
		t.Fatalf("seed status = %d, want %d, body = %+v", status, http.StatusOK, body)
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
	status, body := applyConfigUpdate(path, edit, nil, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %+v", status, http.StatusOK, body)
	}

	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	sc, ok := reloaded.Scopes["office"]
	if !ok {
		t.Fatal("scope 'office' missing after update")
	}
	if sc.NodeIP != "192.168.100.22/24" {
		t.Errorf("NodeIP = %q, want the new pushed value %q — NodeIP must no longer be frozen", sc.NodeIP, "192.168.100.22/24")
	}
	if sc.DHCPRange != [2]string{"192.168.100.150", "192.168.100.250"} {
		t.Errorf("DHCPRange = %v, want the new push's value to apply", sc.DHCPRange)
	}
}

func TestApplyConfigUpdate_NewScopeAcceptsProvidedNodeIP(t *testing.T) {
	path := writeBaseConfig(t)

	upd := configUpdate{
		PSK: testPSK, Platform: testPlatform(),
		Scopes: map[string]config.ScopeConfig{
			"brand-new": {
				Parent: "ens19", VLANID: 101, VIP: "192.168.101.1/24",
				NodeIP:    "192.168.101.23/24",
				DHCPRange: [2]string{"192.168.101.100", "192.168.101.200"},
				Gateway:   "192.168.101.1",
				VRRPID:    52, PreferredWorker: config.RoleCore1,
			},
		},
	}
	status, body := applyConfigUpdate(path, upd, nil, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %+v", status, http.StatusOK, body)
	}

	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	sc, ok := reloaded.Scopes["brand-new"]
	if !ok {
		t.Fatal("new scope missing after update")
	}
	if sc.NodeIP != "192.168.101.23/24" {
		t.Errorf("NodeIP = %q, want the provided value for a genuinely new scope", sc.NodeIP)
	}
}

// TestApplyConfigUpdate_ValidationFailureNotSaved confirms an invalid push
// is rejected AND leaves the on-disk file untouched.
func TestApplyConfigUpdate_ValidationFailureNotSaved(t *testing.T) {
	path := writeBaseConfig(t)
	beforeBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read before: %v", err)
	}

	upd := configUpdate{
		PSK: testPSK, Platform: testPlatform(),
		Scopes: map[string]config.ScopeConfig{
			"bad": {
				Parent: "ens19", VLANID: 99999, VIP: "x", // out of range
				DHCPRange: [2]string{"a", "b"}, Gateway: "g",
				VRRPID: 51, PreferredWorker: config.RoleCore1,
			},
		},
	}

	status, body := applyConfigUpdate(path, upd, nil, nil, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body = %+v", status, http.StatusBadRequest, body)
	}

	result, ok := body.(config.ValidationResult)
	if !ok || len(result.Errors) == 0 {
		t.Errorf("body = %+v, want a ValidationResult with errors", body)
	}

	afterBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if string(afterBytes) != string(beforeBytes) {
		t.Error("on-disk file changed despite a validation failure — must not be written")
	}
}

func TestApplyConfigUpdate_LoadFailure(t *testing.T) {
	status, body := applyConfigUpdate(filepath.Join(t.TempDir(), "does-not-exist.json"), configUpdate{}, nil, nil, nil)
	if status != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d, body = %+v", status, http.StatusInternalServerError, body)
	}
}

func boolPtr(b bool) *bool { return &b }

// TestApplyConfigUpdate_ScopeOnlyChangeReportsNoRestartNeeded checks a
// scope-only change needs no restart.
func TestApplyConfigUpdate_ScopeOnlyChangeReportsNoRestartNeeded(t *testing.T) {
	path := writeBaseConfig(t)

	// Seed with a real scope first (writeBaseConfig's own base has none).
	seed := configUpdate{PSK: testPSK, Platform: testPlatform(), Scopes: map[string]config.ScopeConfig{
		"office": {Parent: "ens19", VLANID: 100, VRRPID: 51, PreferredWorker: config.RoleCore1},
	}}
	if status, body := applyConfigUpdate(path, seed, nil, nil, nil); status != http.StatusOK {
		t.Fatalf("seed status = %d, body = %+v", status, body)
	}

	upd := seed
	upd.Scopes = map[string]config.ScopeConfig{
		"office": {Parent: "ens19", VLANID: 101, VRRPID: 51, PreferredWorker: config.RoleCore1},
	}
	status, body := applyConfigUpdate(path, upd, nil, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %+v", status, http.StatusOK, body)
	}
	resp, ok := body.(map[string]interface{})
	if !ok {
		t.Fatalf("body = %#v, want a map", body)
	}
	if restartNeeded, _ := resp["restart_needed"].(bool); restartNeeded {
		t.Error("restart_needed = true, want false for a scope-only VLAN change")
	}
}

// TestApplyConfigUpdate_ClusterFieldChangeReportsRestartNeeded is the
// control case.
func TestApplyConfigUpdate_ClusterFieldChangeReportsRestartNeeded(t *testing.T) {
	path := writeBaseConfig(t)
	upd := configUpdate{PSK: "a-new-psk-value"}

	status, body := applyConfigUpdate(path, upd, nil, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %+v", status, http.StatusOK, body)
	}
	resp := body.(map[string]interface{})
	if restartNeeded, _ := resp["restart_needed"].(bool); !restartNeeded {
		t.Error("restart_needed = false, want true for a PSK change")
	}
}

func TestApplyConfigUpdate_NilEngineIsSafe(t *testing.T) {
	path := writeBaseConfig(t)
	upd := configUpdate{PSK: testPSK, Platform: testPlatform()}
	if status, body := applyConfigUpdate(path, upd, nil, nil, nil); status != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %+v", status, http.StatusOK, body)
	}
}

func TestClusterIdentityFieldsChanged_GracefulFields(t *testing.T) {
	tests := []struct {
		name string
		c    *config.Cluster
		upd  configUpdate
	}{
		{"log_level", &config.Cluster{LogLevel: "info"}, configUpdate{LogLevel: "debug"}},
		{"trusted_hosts", &config.Cluster{TrustedHosts: []string{"10.0.0.1"}}, configUpdate{TrustedHosts: []string{"10.0.0.2"}}},
		{"helper_socket", &config.Cluster{HelperSocket: "/run/old.sock"}, configUpdate{HelperSocket: "/run/new.sock"}},
		{"probe_interval_ms", &config.Cluster{ProbeIntervalMS: 1000}, configUpdate{ProbeIntervalMS: 2000}},
		{"mgmt_vip", &config.Cluster{}, configUpdate{MgmtVIP: &config.MgmtVIPConfig{VIP: "192.168.0.230/24", VRRPID: 60}}},
		{"default_dns_checks", &config.Cluster{}, configUpdate{DefaultDNSChecks: []config.DNSCheck{{Name: "x", Type: "A"}}}},
		{"global_dns_records", &config.Cluster{}, configUpdate{GlobalDNSRecords: []config.DNSRecord{{Name: "a.test.", Type: "A", Value: "1.2.3.4"}}}},
		{"local_domains", &config.Cluster{}, configUpdate{LocalDomains: []config.LocalDomain{{Name: "test.local"}}}},
		{"default_dhcp_options", &config.Cluster{}, configUpdate{DefaultDHCPOptions: []string{"option:ntp-server,1.2.3.4"}}},
		{"core_dns_address", &config.Cluster{CoreDNSAddress: "127.0.0.42"}, configUpdate{CoreDNSAddress: "127.0.0.99"}},
		{"core_dhcp_address", &config.Cluster{CoreDHCPAddress: "127.0.0.21"}, configUpdate{CoreDHCPAddress: "127.0.0.88"}},
		{"core_dns_query_logging", &config.Cluster{CoreDNSQueryLogging: false}, configUpdate{CoreDNSQueryLogging: true}},
		{"dnsrelay_cache_size", &config.Cluster{DNSRelayCacheSize: 0}, configUpdate{DNSRelayCacheSize: 500}},
		{"dnsrelay_cache_max_bytes", &config.Cluster{DNSRelayCacheMaxBytes: 0}, configUpdate{DNSRelayCacheMaxBytes: 1000}},
		{"sanity_check_disabled", &config.Cluster{SanityCheckDisabled: false}, configUpdate{SanityCheckDisabled: true}},
		{"api_tokens", &config.Cluster{}, configUpdate{APITokens: []config.APIToken{{Name: "x", Token: "y", Role: "admin"}}}},
		{"scope_defaults_upstream", &config.Cluster{ScopeDefaults: &config.ScopeDefaults{Upstream: []string{"1.1.1.1"}}}, configUpdate{ScopeDefaults: &config.ScopeDefaults{Upstream: []string{"8.8.8.8"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if clusterIdentityFieldsChanged(tt.c, tt.upd) {
				t.Errorf("clusterIdentityFieldsChanged() = true for a %s-only change, want false (live-applied now, not a restart-forcing field)", tt.name)
			}
		})
	}
}

func TestClusterIdentityFieldsChanged_RestartStillRequiredFields(t *testing.T) {
	tests := []struct {
		name string
		c    *config.Cluster
		upd  configUpdate
	}{
		{"psk", &config.Cluster{PSK: "old-psk"}, configUpdate{PSK: "new-psk"}},
		{"tls_cert", &config.Cluster{TLSCert: "/old/cert.pem"}, configUpdate{TLSCert: "/new/cert.pem"}},
		{"tls_key", &config.Cluster{TLSKey: "/old/key.pem"}, configUpdate{TLSKey: "/new/key.pem"}},
		{"platform", &config.Cluster{Platform: &config.Platform{Mgmt: "eth0"}}, configUpdate{Platform: &config.Platform{Mgmt: "eth1"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !clusterIdentityFieldsChanged(tt.c, tt.upd) {
				t.Errorf("clusterIdentityFieldsChanged() = false for a %s-only change, want true (still a real restart-requiring field)", tt.name)
			}
		})
	}
}

func TestApplyConfigUpdate_GracefulFieldsLiveApplyToRealAgent(t *testing.T) {
	path := writeBaseConfig(t)
	ag := agent.New(config.RoleCore1, "test-node", 1, "", t.TempDir(), nil, nil)
	authMw := auth.New(nil)

	upd := configUpdate{
		PSK: testPSK, Platform: testPlatform(),
		LogLevel:  "debug",
		APITokens: []config.APIToken{{Name: "automation", Token: "tok-123", Role: "admin"}},
	}
	status, body := applyConfigUpdate(path, upd, ag, nil, authMw)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %+v", status, http.StatusOK, body)
	}
	resp := body.(map[string]interface{})
	if restartNeeded, _ := resp["restart_needed"].(bool); restartNeeded {
		t.Fatal("restart_needed = true, want false — LogLevel/APITokens together must not force a restart")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer tok-123")
	rr := httptest.NewRecorder()
	authMw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("request with the newly-saved API token: status = %d, want 200 — SetTokens was not actually called live", rr.Code)
	}
}
