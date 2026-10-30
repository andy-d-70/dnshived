// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package config

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testPSK is a fixture-only value; validate() requires a non-empty psk
// (see TestPSKRequired).
const testPSK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"

// helper: write JSON to a temp file, return the path.
func writeConfig(t *testing.T, v interface{}) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "cluster.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// validBase returns a minimal valid schema-v2 worker config.
func validBase() map[string]interface{} {
	return map[string]interface{}{
		"schema_version": 2,
		"cluster_id":     "test",
		"node_id":        "node1",
		"role":           "core-1",
		"control_addr":   "10.0.0.1:9443",
		"peers":          []string{"10.0.0.2:9443", "10.0.0.3:9443"},
		"psk":            testPSK,
		"platform": map[string]interface{}{
			"mgmt":    "eth0",
			"workers": []string{"eth1"},
		},
		"scopes": map[string]interface{}{
			"office": map[string]interface{}{
				"parent":           "eth1",
				"vlan_id":          100,
				"vip":              "192.168.100.1/24",
				"dhcp_range":       []string{"192.168.100.100", "192.168.100.200"},
				"gateway":          "192.168.100.1",
				"upstream":         []string{"1.1.1.1"},
				"vrrp_id":          51,
				"preferred_worker": "core-1",
			},
		},
	}
}

func TestValidConfig(t *testing.T) {
	cfg := validBase()
	path := writeConfig(t, cfg)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("valid config should load: %v", err)
	}
	if c.ClusterID != "test" {
		t.Errorf("cluster_id = %q, want %q", c.ClusterID, "test")
	}
	if !c.HasScopes() {
		t.Error("should have scopes")
	}
}

func TestMissingClusterID(t *testing.T) {
	cfg := validBase()
	delete(cfg, "cluster_id")
	path := writeConfig(t, cfg)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing cluster_id")
	}
}

func TestMissingNodeID(t *testing.T) {
	cfg := validBase()
	delete(cfg, "node_id")
	path := writeConfig(t, cfg)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing node_id")
	}
}

func TestInvalidRole(t *testing.T) {
	cfg := validBase()
	cfg["role"] = "leader"
	path := writeConfig(t, cfg)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid role")
	}
}

func TestMissingControlAddr(t *testing.T) {
	cfg := validBase()
	delete(cfg, "control_addr")
	path := writeConfig(t, cfg)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing control_addr")
	}
}

func TestSchemaVersionTooNew(t *testing.T) {
	cfg := validBase()
	cfg["schema_version"] = 99
	path := writeConfig(t, cfg)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for schema_version too new")
	}
}

func TestDuplicateVLANID(t *testing.T) {
	cfg := validBase()
	scopes := cfg["scopes"].(map[string]interface{})
	scopes["dante"] = map[string]interface{}{
		"parent":           "eth1",
		"vlan_id":          100, // same as office
		"vip":              "10.200.0.1/24",
		"dhcp_range":       []string{"10.200.0.100", "10.200.0.200"},
		"gateway":          "10.200.0.1",
		"upstream":         []string{"1.1.1.1"},
		"vrrp_id":          52,
		"preferred_worker": "core-2",
	}
	path := writeConfig(t, cfg)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for duplicate vlan_id")
	}
}

func TestSameVLANIDDifferentParent_NoConflict(t *testing.T) {
	cfg := validBase()
	platform := cfg["platform"].(map[string]interface{})
	platform["workers"] = []string{"eth1", "eth2"}
	scopes := cfg["scopes"].(map[string]interface{})
	scopes["dante"] = map[string]interface{}{
		"parent":           "eth2", // different parent than office (eth1)
		"vlan_id":          100,    // same as office
		"vip":              "10.200.0.1/24",
		"dhcp_range":       []string{"10.200.0.100", "10.200.0.200"},
		"gateway":          "10.200.0.1",
		"upstream":         []string{"1.1.1.1"},
		"vrrp_id":          52,
		"preferred_worker": "core-2",
	}
	path := writeConfig(t, cfg)
	if _, err := Load(path); err != nil {
		t.Fatalf("expected no error for same vlan_id on a different parent trunk, got: %v", err)
	}
}

func TestDuplicateVRRPID(t *testing.T) {
	cfg := validBase()
	scopes := cfg["scopes"].(map[string]interface{})
	scopes["dante"] = map[string]interface{}{
		"parent":           "eth1",
		"vlan_id":          200,
		"vip":              "10.200.0.1/24",
		"dhcp_range":       []string{"10.200.0.100", "10.200.0.200"},
		"gateway":          "10.200.0.1",
		"upstream":         []string{"1.1.1.1"},
		"vrrp_id":          51, // same as office
		"preferred_worker": "core-2",
	}
	path := writeConfig(t, cfg)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for duplicate vrrp_id")
	}
}

func TestVLANIDOutOfRange(t *testing.T) {
	tests := []struct {
		name   string
		vlanID int
	}{
		{"negative", -1},
		{"too_high", 4095},
		{"reserved_native_vlan_one", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBase()
			scopes := cfg["scopes"].(map[string]interface{})
			scope := scopes["office"].(map[string]interface{})
			scope["vlan_id"] = tt.vlanID
			path := writeConfig(t, cfg)
			_, err := Load(path)
			if err == nil {
				t.Fatalf("expected error for vlan_id %d", tt.vlanID)
			}
		})
	}
}

func TestVLANIDZeroIsValidUntagged(t *testing.T) {
	cfg := validBase()
	scopes := cfg["scopes"].(map[string]interface{})
	scope := scopes["office"].(map[string]interface{})
	scope["vlan_id"] = 0
	path := writeConfig(t, cfg)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("vlan_id 0 (untagged) should load cleanly: %v", err)
	}
	if got := c.Scopes["office"].VLANID; got != 0 {
		t.Errorf("VLANID = %d, want 0", got)
	}
}

func TestVRRPIDOutOfRange(t *testing.T) {
	tests := []struct {
		name   string
		vrrpID int
	}{
		{"zero", 0},
		{"too_high", 256},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBase()
			scopes := cfg["scopes"].(map[string]interface{})
			scope := scopes["office"].(map[string]interface{})
			scope["vrrp_id"] = tt.vrrpID
			path := writeConfig(t, cfg)
			_, err := Load(path)
			if err == nil {
				t.Fatalf("expected error for vrrp_id %d", tt.vrrpID)
			}
		})
	}
}

func TestInvalidPreferredWorker(t *testing.T) {
	cfg := validBase()
	scopes := cfg["scopes"].(map[string]interface{})
	scope := scopes["office"].(map[string]interface{})
	scope["preferred_worker"] = "worker-c"
	path := writeConfig(t, cfg)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid preferred_worker")
	}
}

func TestScopeOnMgmtInterface(t *testing.T) {
	cfg := validBase()
	scopes := cfg["scopes"].(map[string]interface{})
	scope := scopes["office"].(map[string]interface{})
	scope["parent"] = "eth0" // mgmt interface
	path := writeConfig(t, cfg)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for scope on mgmt interface")
	}
}

func TestScopeOnUnknownInterface(t *testing.T) {
	cfg := validBase()
	scopes := cfg["scopes"].(map[string]interface{})
	scope := scopes["office"].(map[string]interface{})
	scope["parent"] = "eth99" // not in workers list
	path := writeConfig(t, cfg)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for scope on unknown interface")
	}
}

func TestScopeNameRejectsPathTraversalCharacters(t *testing.T) {
	for _, bad := range []string{"../../etc/cron.d/x", "a/b", "a b", "a.b"} {
		cfg := validBase()
		scopes := cfg["scopes"].(map[string]interface{})
		scope := scopes["office"].(map[string]interface{})
		delete(scopes, "office")
		scopes[bad] = scope
		path := writeConfig(t, cfg)
		if _, err := Load(path); err == nil {
			t.Errorf("scope name %q: expected error, got none", bad)
		}
	}
}

// setScopeDNSRecords is a small test helper — every DNSRecord validation
// test below only differs in this one field.
func setScopeDNSRecords(cfg map[string]interface{}, records []map[string]interface{}) {
	scopes := cfg["scopes"].(map[string]interface{})
	scope := scopes["office"].(map[string]interface{})
	scope["dns_records"] = records
}

// TestGlobalDNSRecords_ValidRecordAccepted confirms a valid
// Cluster.GlobalDNSRecords entry loads.
func TestGlobalDNSRecords_ValidRecordAccepted(t *testing.T) {
	cfg := validBase()
	cfg["global_dns_records"] = []map[string]interface{}{
		{"name": "fileserver.lan", "type": "A", "value": "10.0.0.50"},
	}
	path := writeConfig(t, cfg)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("valid global_dns_records entry should load: %v", err)
	}
	if len(c.GlobalDNSRecords) != 1 || c.GlobalDNSRecords[0].Name != "fileserver.lan" {
		t.Errorf("GlobalDNSRecords = %+v, want one fileserver.lan record", c.GlobalDNSRecords)
	}
}

// TestGlobalDNSRecords_InvalidRecordRejected confirms the shared
// validateDNSRecords injection checks apply here too.
func TestGlobalDNSRecords_InvalidRecordRejected(t *testing.T) {
	cfg := validBase()
	cfg["global_dns_records"] = []map[string]interface{}{
		{"name": "evil\nlisten-address=0.0.0.0", "type": "A", "value": "10.0.0.50"},
	}
	path := writeConfig(t, cfg)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error: global_dns_records name contains a newline")
	}
}

func TestReservations_ValidEntryAccepted(t *testing.T) {
	cfg := validBase()
	scopes := cfg["scopes"].(map[string]interface{})
	office := scopes["office"].(map[string]interface{})
	office["reservations"] = []map[string]interface{}{
		{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.100.50", "hostname": "printer"},
	}
	path := writeConfig(t, cfg)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("valid reservation should load: %v", err)
	}
	res := c.Scopes["office"].Reservations
	if len(res) != 1 || res[0].MAC != "aa:bb:cc:dd:ee:ff" || res[0].IP != "192.168.100.50" || res[0].Hostname != "printer" {
		t.Errorf("Reservations = %+v, want the one submitted entry", res)
	}
}

func TestReservations_InvalidMACRejected(t *testing.T) {
	cfg := validBase()
	scopes := cfg["scopes"].(map[string]interface{})
	office := scopes["office"].(map[string]interface{})
	office["reservations"] = []map[string]interface{}{
		{"mac": "not-a-mac", "ip": "192.168.100.50"},
	}
	path := writeConfig(t, cfg)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error: malformed MAC address")
	}
}

func TestReservations_InvalidIPRejected(t *testing.T) {
	cfg := validBase()
	scopes := cfg["scopes"].(map[string]interface{})
	office := scopes["office"].(map[string]interface{})
	office["reservations"] = []map[string]interface{}{
		{"mac": "aa:bb:cc:dd:ee:ff", "ip": "not-an-ip"},
	}
	path := writeConfig(t, cfg)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error: malformed IP address")
	}
}

// TestReservations_HostnameRejectsInjectionChars confirms the same
// line-oriented-file injection protection the old per-node
// reservations.go's hostnameRe gave.
func TestReservations_HostnameRejectsInjectionChars(t *testing.T) {
	cfg := validBase()
	scopes := cfg["scopes"].(map[string]interface{})
	office := scopes["office"].(map[string]interface{})
	office["reservations"] = []map[string]interface{}{
		{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.100.50", "hostname": "evil\nlisten-address=0.0.0.0"},
	}
	path := writeConfig(t, cfg)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error: hostname contains a newline")
	}
}

// TestReservations_DuplicateMACInSameScopeRejected confirms a scope can't
// reserve the same MAC twice.
func TestReservations_DuplicateMACInSameScopeRejected(t *testing.T) {
	cfg := validBase()
	scopes := cfg["scopes"].(map[string]interface{})
	office := scopes["office"].(map[string]interface{})
	office["reservations"] = []map[string]interface{}{
		{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.100.50"},
		{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.100.51"},
	}
	path := writeConfig(t, cfg)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error: same MAC reserved twice in one scope")
	}
}

func TestDNSRecord_AllSixTypesValid(t *testing.T) {
	cfg := validBase()
	setScopeDNSRecords(cfg, []map[string]interface{}{
		{"name": "nas.office.lan", "type": "A", "value": "192.168.100.50"},
		{"name": "nas6.office.lan", "type": "AAAA", "value": "fe80::1"},
		{"name": "printer.office.lan", "type": "CNAME", "value": "nas.office.lan"},
		{"name": "_info.office.lan", "type": "TXT", "value": "a note"},
		{"name": "_dante._udp.office.lan", "type": "SRV", "target": "nas.office.lan", "port": 4440, "priority": 10, "weight": 20},
		{"name": "50.100.168.192.in-addr.arpa", "type": "PTR", "value": "nas.office.lan"},
	})
	path := writeConfig(t, cfg)
	if _, err := Load(path); err != nil {
		t.Fatalf("expected all 6 record types to be valid, got: %v", err)
	}
}

func TestDNSRecord_PTRRejectsLineBreakAndComma(t *testing.T) {
	for _, bad := range []string{"evil\nlisten-address=0.0.0.0", "a,b"} {
		cfg := validBase()
		setScopeDNSRecords(cfg, []map[string]interface{}{
			{"name": "50.100.168.192.in-addr.arpa", "type": "PTR", "value": bad},
		})
		path := writeConfig(t, cfg)
		if _, err := Load(path); err == nil {
			t.Errorf("PTR value %q: expected an error, got none", bad)
		}
	}
}

func TestDNSRecord_NameRejectsLineBreakAndComma(t *testing.T) {
	for _, bad := range []string{"evil\nlisten-address=0.0.0.0", "evil\r\ndhcp-range=set:x", "a,b"} {
		cfg := validBase()
		setScopeDNSRecords(cfg, []map[string]interface{}{
			{"name": bad, "type": "A", "value": "192.168.100.50"},
		})
		path := writeConfig(t, cfg)
		if _, err := Load(path); err == nil {
			t.Errorf("name %q: expected an error, got none", bad)
		}
	}
}

func TestDNSRecord_ARecordRejectsInvalidIP(t *testing.T) {
	for _, bad := range []string{"not-an-ip", "192.168.1.999", "192.168.1.1,evil=1"} {
		cfg := validBase()
		setScopeDNSRecords(cfg, []map[string]interface{}{
			{"name": "nas.office.lan", "type": "A", "value": bad},
		})
		path := writeConfig(t, cfg)
		if _, err := Load(path); err == nil {
			t.Errorf("A record value %q: expected an error, got none", bad)
		}
	}
}

func TestDNSRecord_CNAMERejectsLineBreakAndComma(t *testing.T) {
	for _, bad := range []string{"evil\nlisten-address=0.0.0.0", "a,b"} {
		cfg := validBase()
		setScopeDNSRecords(cfg, []map[string]interface{}{
			{"name": "printer.office.lan", "type": "CNAME", "value": bad},
		})
		path := writeConfig(t, cfg)
		if _, err := Load(path); err == nil {
			t.Errorf("CNAME value %q: expected an error, got none", bad)
		}
	}
}

// TestDNSRecord_TXTAllowsCommaRejectsLineBreak confirms TXT's free-text
// value is only rejected for the genuine injection vector (a newline), not
// over-restricted.
func TestDNSRecord_TXTAllowsCommaRejectsLineBreak(t *testing.T) {
	cfg := validBase()
	setScopeDNSRecords(cfg, []map[string]interface{}{
		{"name": "_info.office.lan", "type": "TXT", "value": "key1=a,key2=b"},
	})
	path := writeConfig(t, cfg)
	if _, err := Load(path); err != nil {
		t.Errorf("expected a comma in TXT value to be valid, got: %v", err)
	}

	cfg2 := validBase()
	setScopeDNSRecords(cfg2, []map[string]interface{}{
		{"name": "_info.office.lan", "type": "TXT", "value": "evil\nlisten-address=0.0.0.0"},
	})
	path2 := writeConfig(t, cfg2)
	if _, err := Load(path2); err == nil {
		t.Error("expected a newline in TXT value to be rejected")
	}
}

func TestDNSRecord_SRVTargetRejectsLineBreakAndComma(t *testing.T) {
	for _, bad := range []string{"evil\nlisten-address=0.0.0.0", "a,b"} {
		cfg := validBase()
		setScopeDNSRecords(cfg, []map[string]interface{}{
			{"name": "_dante._udp.office.lan", "type": "SRV", "target": bad, "port": 4440},
		})
		path := writeConfig(t, cfg)
		if _, err := Load(path); err == nil {
			t.Errorf("SRV target %q: expected an error, got none", bad)
		}
	}
}

func TestDHCPOptions_ValidValuesAccepted(t *testing.T) {
	cfg := validBase()
	scopes := cfg["scopes"].(map[string]interface{})
	scopes["office"].(map[string]interface{})["dhcp_options"] = []string{"option:domain-search,corp.local", "option:ntp-server,10.0.0.1"}
	cfg["default_dhcp_options"] = []string{"252,http://wpad.corp.local/wpad.dat"}
	path := writeConfig(t, cfg)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("valid dhcp_options should load: %v", err)
	}
	if len(c.Scopes["office"].DHCPOptions) != 2 {
		t.Errorf("scope DHCPOptions = %+v, want 2 entries", c.Scopes["office"].DHCPOptions)
	}
	if len(c.DefaultDHCPOptions) != 1 || c.DefaultDHCPOptions[0] != "252,http://wpad.corp.local/wpad.dat" {
		t.Errorf("DefaultDHCPOptions = %+v", c.DefaultDHCPOptions)
	}
}

func TestDHCPOptions_NewlineRejected(t *testing.T) {
	cfg := validBase()
	scopes := cfg["scopes"].(map[string]interface{})
	scopes["office"].(map[string]interface{})["dhcp_options"] = []string{"option:domain-search,corp.local\nlisten-address=0.0.0.0"}
	path := writeConfig(t, cfg)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error: dhcp_options entry contains a newline")
	}
}

func TestDHCPOptions_DefaultNewlineRejected(t *testing.T) {
	cfg := validBase()
	cfg["default_dhcp_options"] = []string{"evil\nlisten-address=0.0.0.0"}
	path := writeConfig(t, cfg)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error: default_dhcp_options entry contains a newline")
	}
}

func TestScopeColor_ValidHexAccepted(t *testing.T) {
	cfg := validBase()
	scopes := cfg["scopes"].(map[string]interface{})
	scopes["office"].(map[string]interface{})["color"] = "#f58231"
	path := writeConfig(t, cfg)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("valid color should load: %v", err)
	}
	if c.Scopes["office"].Color != "#f58231" {
		t.Errorf("Color = %q, want #f58231", c.Scopes["office"].Color)
	}
}

func TestScopeColor_EmptyIsValid(t *testing.T) {
	cfg := validBase() // no color set at all
	path := writeConfig(t, cfg)
	if _, err := Load(path); err != nil {
		t.Fatalf("no color set should load fine: %v", err)
	}
}

func TestScopeColor_InvalidRejected(t *testing.T) {
	for _, bad := range []string{"red", "#fff", "#gggggg", "f58231"} {
		cfg := validBase()
		scopes := cfg["scopes"].(map[string]interface{})
		scopes["office"].(map[string]interface{})["color"] = bad
		path := writeConfig(t, cfg)
		if _, err := Load(path); err == nil {
			t.Errorf("color %q: expected an error, got none", bad)
		}
	}
}

func TestDNSRecord_AllTenTypesValid(t *testing.T) {
	cfg := validBase()
	setScopeDNSRecords(cfg, []map[string]interface{}{
		{"name": "nas.office.lan", "type": "A", "value": "192.168.100.50"},
		{"name": "nas6.office.lan", "type": "AAAA", "value": "fe80::1"},
		{"name": "printer.office.lan", "type": "CNAME", "value": "nas.office.lan"},
		{"name": "_info.office.lan", "type": "TXT", "value": "a note"},
		{"name": "_dante._udp.office.lan", "type": "SRV", "target": "nas.office.lan", "port": 4440, "priority": 10, "weight": 20},
		{"name": "50.100.168.192.in-addr.arpa", "type": "PTR", "value": "nas.office.lan"},
		{"name": "office.lan", "type": "MX", "target": "mail.office.lan", "priority": 10},
		{"name": "_sip._udp.office.lan", "type": "NAPTR", "target": "_sip._udp.office.lan",
			"naptr_order": 100, "priority": 10, "naptr_flags": "S", "naptr_service": "SIP+D2U", "naptr_regexp": ""},
		{"name": "office.lan", "type": "CAA", "caa_flags": 0, "caa_tag": "issue", "value": "letsencrypt.org"},
		{"name": "raw.office.lan", "type": "RAW", "rr_type": 65280, "rr_data_hex": "68656c6c6f"},
	})
	path := writeConfig(t, cfg)
	if _, err := Load(path); err != nil {
		t.Fatalf("expected all 10 record types to be valid, got: %v", err)
	}
}

func TestDNSRecord_MXRequiresTargetRejectsLineBreakAndComma(t *testing.T) {
	cfg := validBase()
	setScopeDNSRecords(cfg, []map[string]interface{}{
		{"name": "office.lan", "type": "MX", "target": "", "priority": 10},
	})
	path := writeConfig(t, cfg)
	if _, err := Load(path); err == nil {
		t.Error("MX with empty target: expected an error, got none")
	}

	for _, bad := range []string{"evil\nlisten-address=0.0.0.0", "a,b"} {
		cfg := validBase()
		setScopeDNSRecords(cfg, []map[string]interface{}{
			{"name": "office.lan", "type": "MX", "target": bad, "priority": 10},
		})
		path := writeConfig(t, cfg)
		if _, err := Load(path); err == nil {
			t.Errorf("MX target %q: expected an error, got none", bad)
		}
	}
}

func TestDNSRecord_MXAllowsZeroPriority(t *testing.T) {
	cfg := validBase()
	setScopeDNSRecords(cfg, []map[string]interface{}{
		{"name": "office.lan", "type": "MX", "target": "mail.office.lan", "priority": 0},
	})
	path := writeConfig(t, cfg)
	if _, err := Load(path); err != nil {
		t.Errorf("expected priority 0 to be valid for MX, got: %v", err)
	}
}

func TestDNSRecord_NAPTRRequiresTargetRejectsLineBreakAndComma(t *testing.T) {
	cfg := validBase()
	setScopeDNSRecords(cfg, []map[string]interface{}{
		{"name": "_sip._udp.office.lan", "type": "NAPTR", "target": "", "naptr_order": 100, "priority": 10},
	})
	path := writeConfig(t, cfg)
	if _, err := Load(path); err == nil {
		t.Error("NAPTR with empty target: expected an error, got none")
	}

	for _, field := range []string{"target", "naptr_flags", "naptr_service", "naptr_regexp"} {
		for _, bad := range []string{"evil\nlisten-address=0.0.0.0", "a,b"} {
			cfg := validBase()
			rec := map[string]interface{}{
				"name": "_sip._udp.office.lan", "type": "NAPTR", "target": "_sip._udp.office.lan",
				"naptr_order": 100, "priority": 10, "naptr_flags": "S", "naptr_service": "SIP+D2U", "naptr_regexp": "",
			}
			rec[field] = bad
			setScopeDNSRecords(cfg, []map[string]interface{}{rec})
			path := writeConfig(t, cfg)
			if _, err := Load(path); err == nil {
				t.Errorf("NAPTR %s %q: expected an error, got none", field, bad)
			}
		}
	}
}

func TestDNSRecord_CAARequiresTagAndValueRejectsLineBreakAndComma(t *testing.T) {
	for _, rec := range []map[string]interface{}{
		{"name": "office.lan", "type": "CAA", "caa_tag": "", "value": "letsencrypt.org"},
		{"name": "office.lan", "type": "CAA", "caa_tag": "issue", "value": ""},
	} {
		cfg := validBase()
		setScopeDNSRecords(cfg, []map[string]interface{}{rec})
		path := writeConfig(t, cfg)
		if _, err := Load(path); err == nil {
			t.Errorf("CAA record %+v: expected an error, got none", rec)
		}
	}

	for _, bad := range []string{"evil\nlisten-address=0.0.0.0", "a,b"} {
		cfg := validBase()
		setScopeDNSRecords(cfg, []map[string]interface{}{
			{"name": "office.lan", "type": "CAA", "caa_tag": bad, "value": "letsencrypt.org"},
		})
		path := writeConfig(t, cfg)
		if _, err := Load(path); err == nil {
			t.Errorf("CAA caa_tag %q: expected an error, got none", bad)
		}

		cfg2 := validBase()
		setScopeDNSRecords(cfg2, []map[string]interface{}{
			{"name": "office.lan", "type": "CAA", "caa_tag": "issue", "value": bad},
		})
		path2 := writeConfig(t, cfg2)
		if _, err := Load(path2); err == nil {
			t.Errorf("CAA value %q: expected an error, got none", bad)
		}
	}
}

func TestDNSRecord_RAWRequiresPositiveRRTypeValidHex(t *testing.T) {
	cfg := validBase()
	setScopeDNSRecords(cfg, []map[string]interface{}{
		{"name": "raw.office.lan", "type": "RAW", "rr_type": 0},
	})
	path := writeConfig(t, cfg)
	if _, err := Load(path); err == nil {
		t.Error("RAW with rr_type 0: expected an error, got none")
	}

	cfg2 := validBase()
	setScopeDNSRecords(cfg2, []map[string]interface{}{
		{"name": "raw.office.lan", "type": "RAW", "rr_type": 65280, "rr_data_hex": "not-hex"},
	})
	path2 := writeConfig(t, cfg2)
	if _, err := Load(path2); err == nil {
		t.Error("RAW with invalid rr_data_hex: expected an error, got none")
	}

	cfg3 := validBase()
	setScopeDNSRecords(cfg3, []map[string]interface{}{
		{"name": "raw.office.lan", "type": "RAW", "rr_type": 65280},
	})
	path3 := writeConfig(t, cfg3)
	if _, err := Load(path3); err != nil {
		t.Errorf("RAW with no rr_data_hex: expected valid (dnsmasq allows a bare type), got: %v", err)
	}
}

func TestScopesWithoutPlatform(t *testing.T) {
	cfg := validBase()
	delete(cfg, "platform")
	path := writeConfig(t, cfg)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error: scopes configured without platform")
	}
}

// TestNoScopesNoPlatformIsValid covers a freshly founded cluster whose
// wizard network step was skipped: no trunks known, nothing to build.
func TestNoScopesNoPlatformIsValid(t *testing.T) {
	cfg := validBase()
	delete(cfg, "platform")
	delete(cfg, "scopes")
	path := writeConfig(t, cfg)
	if _, err := Load(path); err != nil {
		t.Fatalf("zero scopes without platform should load: %v", err)
	}
}

// TestPSKRequired: an empty psk skips the witness protocol entirely
// (WitnessRequired is psk != "") and lets a forged token verify, so
// validate() refuses it.
func TestPSKRequired(t *testing.T) {
	cfg := validBase()
	delete(cfg, "psk")
	path := writeConfig(t, cfg)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error: no psk must be refused")
	}
}

func TestPSKRequired_Core3(t *testing.T) {
	cfg := validBase()
	cfg["role"] = "core-3"
	delete(cfg, "psk")
	delete(cfg, "platform")
	delete(cfg, "scopes")
	path := writeConfig(t, cfg)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error: core-3 with no psk must be refused")
	}
}

// TestWithoutScopesIsValid: a running cluster before any scope exists,
// scopes added incrementally afterward.
func TestWithoutScopesIsValid(t *testing.T) {
	cfg := validBase()
	delete(cfg, "scopes")
	path := writeConfig(t, cfg)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("zero scopes should be valid: %v", err)
	}
	if c.HasScopes() {
		t.Error("HasScopes() = true, want false")
	}
}

// TestInterfaceLabels_ValidWorkerKeyAccepted confirms an operator-chosen
// display name for a real Platform.Workers entry loads cleanly.
func TestInterfaceLabels_ValidWorkerKeyAccepted(t *testing.T) {
	cfg := validBase()
	cfg["platform"].(map[string]interface{})["interface_labels"] = map[string]interface{}{"eth1": "Interface Office"}
	path := writeConfig(t, cfg)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("valid interface_labels entry should load: %v", err)
	}
	if c.Platform.InterfaceLabels["eth1"] != "Interface Office" {
		t.Errorf("InterfaceLabels[eth1] = %q, want %q", c.Platform.InterfaceLabels["eth1"], "Interface Office")
	}
}

func TestInterfaceLabels_UnknownKeyRejected(t *testing.T) {
	cfg := validBase()
	cfg["platform"].(map[string]interface{})["interface_labels"] = map[string]interface{}{"eth9": "Ghost"}
	path := writeConfig(t, cfg)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error: interface_labels key not in platform.workers")
	}
}

// TestInterfaceLabels_MgmtKeyRejected confirms the mgmt interface can't be
// labeled through this field either.
func TestInterfaceLabels_MgmtKeyRejected(t *testing.T) {
	cfg := validBase()
	cfg["platform"].(map[string]interface{})["interface_labels"] = map[string]interface{}{"eth0": "Mgmt"}
	path := writeConfig(t, cfg)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error: interface_labels key is the mgmt interface, not a worker")
	}
}

func TestArbiterNoPlatformRequired(t *testing.T) {
	cfg := validBase()
	cfg["role"] = "core-3"
	delete(cfg, "platform")
	delete(cfg, "scopes")
	path := writeConfig(t, cfg)
	_, err := Load(path)
	if err != nil {
		t.Fatalf("arbiter should not require platform/scopes: %v", err)
	}
}

func TestLegacyDryRunKeyFlaggedAndNotSaved(t *testing.T) {
	cfg := validBase()
	cfg["dry_run"] = true
	path := writeConfig(t, cfg)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !c.LegacyDryRun {
		t.Fatal("LegacyDryRun = false, want true for a file carrying dry_run")
	}
	if err := Save(path, c); err != nil {
		t.Fatalf("save: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(data), "dry_run") {
		t.Error("saved config still contains dry_run")
	}
	c2, err := Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if c2.LegacyDryRun {
		t.Error("LegacyDryRun = true after save, want false")
	}
}

func TestScopeNames(t *testing.T) {
	cfg := validBase()
	scopes := cfg["scopes"].(map[string]interface{})
	scopes["dante"] = map[string]interface{}{
		"parent":           "eth1",
		"vlan_id":          200,
		"vip":              "10.200.0.1/24",
		"dhcp_range":       []string{"10.200.0.100", "10.200.0.200"},
		"gateway":          "10.200.0.1",
		"upstream":         []string{"1.1.1.1"},
		"vrrp_id":          52,
		"preferred_worker": "core-2",
	}
	path := writeConfig(t, cfg)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	names := c.ScopeNames()
	if len(names) != 2 || names[0] != "dante" || names[1] != "office" {
		t.Errorf("ScopeNames() = %v, want [dante office]", names)
	}
}

// TestIoTScopeNames pins that only scopes with dhcp_iot_defaults set are
// returned, sorted.
func TestIoTScopeNames(t *testing.T) {
	cfg := validBase()
	scopes := cfg["scopes"].(map[string]interface{})
	scopes["dante"] = map[string]interface{}{
		"parent":            "eth1",
		"vlan_id":           200,
		"vip":               "10.200.0.1/24",
		"dhcp_range":        []string{"10.200.0.100", "10.200.0.200"},
		"gateway":           "10.200.0.1",
		"upstream":          []string{"1.1.1.1"},
		"vrrp_id":           52,
		"preferred_worker":  "core-2",
		"dhcp_iot_defaults": true,
	}
	path := writeConfig(t, cfg)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	names := c.IoTScopeNames()
	if len(names) != 1 || names[0] != "dante" {
		t.Errorf("IoTScopeNames() = %v, want [dante]", names)
	}
}

func TestPSKField(t *testing.T) {
	cfg := validBase()
	cfg["psk"] = "my-secret-key"
	path := writeConfig(t, cfg)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.PSK != "my-secret-key" {
		t.Errorf("PSK = %q, want %q", c.PSK, "my-secret-key")
	}
}

func TestListenAddr(t *testing.T) {
	tests := []struct {
		name     string
		bind     string
		control  string
		expected string
	}{
		{"bind_addr set", ":8080", "10.0.0.1:9443", ":8080"},
		{"bind_addr empty", "", "10.0.0.1:9443", ":9443"},
		{"no port", "", "10.0.0.1", ":9443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Cluster{BindAddr: tt.bind, ControlAddr: tt.control}
			if got := c.ListenAddr(); got != tt.expected {
				t.Errorf("ListenAddr() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestMgmtVIPValid(t *testing.T) {
	cfg := validBase()
	cfg["mgmt_vip"] = map[string]interface{}{
		"vip":     "192.0.2.100/24",
		"vrrp_id": 200,
	}
	path := writeConfig(t, cfg)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("valid mgmt_vip should load: %v", err)
	}
	if c.MgmtVIP == nil || c.MgmtVIP.VIP != "192.0.2.100/24" {
		t.Errorf("MgmtVIP = %+v, want VIP=192.0.2.100/24", c.MgmtVIP)
	}
}

func TestMgmtVIPMissingVIP(t *testing.T) {
	cfg := validBase()
	cfg["mgmt_vip"] = map[string]interface{}{"vrrp_id": 200}
	path := writeConfig(t, cfg)
	if _, err := Load(path); err == nil {
		t.Error("expected error for mgmt_vip with no vip")
	}
}

func TestMgmtVIPOutOfRange(t *testing.T) {
	cfg := validBase()
	cfg["mgmt_vip"] = map[string]interface{}{"vip": "192.0.2.100/24", "vrrp_id": 256}
	path := writeConfig(t, cfg)
	if _, err := Load(path); err == nil {
		t.Error("expected error for mgmt_vip vrrp_id out of range")
	}
}

// TestMgmtVIPCollidesWithScope pins that the mgmt VIP's vrrp_id is checked
// against the SAME uniqueness map scope-vs-scope collisions use.
func TestMgmtVIPCollidesWithScope(t *testing.T) {
	cfg := validBase()
	// office already uses vrrp_id 51 in validBase().
	cfg["mgmt_vip"] = map[string]interface{}{"vip": "192.0.2.100/24", "vrrp_id": 51}
	path := writeConfig(t, cfg)
	if _, err := Load(path); err == nil {
		t.Error("expected error for mgmt_vip vrrp_id colliding with a scope's vrrp_id")
	}
}

func TestMgmtVIPAddressCollidesWithScopeVIP(t *testing.T) {
	cfg := validBase()
	office := cfg["scopes"].(map[string]interface{})["office"].(map[string]interface{})
	cfg["mgmt_vip"] = map[string]interface{}{"vip": office["vip"], "vrrp_id": 200}
	path := writeConfig(t, cfg)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "already used by mgmt_vip") {
		t.Errorf("expected a scope VIP equal to the mgmt VIP to be rejected, got %v", err)
	}
}

// TestDHCPLeaseTime_AcceptsValidDurations pins the exact set of formats
// dnsmasq itself accepts for a dhcp-range's lease time.
func TestDHCPLeaseTime_AcceptsValidDurations(t *testing.T) {
	for _, valid := range []string{"12h", "24h", "7d", "30m", "3600", "infinite"} {
		cfg := validBase()
		cfg["scopes"].(map[string]interface{})["office"].(map[string]interface{})["dhcp_lease_time"] = valid
		path := writeConfig(t, cfg)
		if _, err := Load(path); err != nil {
			t.Errorf("dhcp_lease_time %q should be valid, got error: %v", valid, err)
		}
	}
}

func TestDHCPLeaseTime_RejectsInvalidFormat(t *testing.T) {
	for _, invalid := range []string{"12hh", "1.5h", "forever", "-5h", "12 h"} {
		cfg := validBase()
		cfg["scopes"].(map[string]interface{})["office"].(map[string]interface{})["dhcp_lease_time"] = invalid
		path := writeConfig(t, cfg)
		if _, err := Load(path); err == nil {
			t.Errorf("dhcp_lease_time %q should be rejected as invalid", invalid)
		}
	}
}

func TestSaveRoundTrip(t *testing.T) {
	cfg := validBase()
	path := writeConfig(t, cfg)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	c.PSK = "super-secret-psk"
	c.APITokens = []APIToken{{Name: "op", Token: "tok123", Role: "admin"}}
	if err := Save(path, c); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("reload after Save: %v", err)
	}
	if reloaded.PSK != "super-secret-psk" {
		t.Errorf("PSK = %q after round trip, want preserved", reloaded.PSK)
	}
	if len(reloaded.APITokens) != 1 || reloaded.APITokens[0].Token != "tok123" {
		t.Errorf("APITokens = %+v after round trip, want preserved", reloaded.APITokens)
	}
	if !reloaded.HasScopes() {
		t.Error("scopes lost after round trip")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat saved file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("saved file mode = %v, want 0600 (PSK/tokens are cleartext secrets)", info.Mode().Perm())
	}
}

func TestScopesHash_DeterministicAndSensitiveToChange(t *testing.T) {
	cfg := validBase()
	path := writeConfig(t, cfg)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	h1 := c.ScopesHash()
	h2 := c.ScopesHash()
	if h1 != h2 {
		t.Errorf("ScopesHash() not deterministic: %q vs %q", h1, h2)
	}
	if h1 == "" {
		t.Error("ScopesHash() returned empty string for a config with scopes")
	}

	// Mutate a scope's field and confirm the hash changes.
	sc := c.Scopes["office"]
	sc.VLANID = 200
	c.Scopes["office"] = sc
	if h3 := c.ScopesHash(); h3 == h1 {
		t.Error("ScopesHash() unchanged after a scope field changed")
	}
}

func TestScopesHash_MatchesAcrossIdenticalConfigs(t *testing.T) {
	cfgA := validBase()
	cfgB := validBase() // separately constructed, same content
	pathA := writeConfig(t, cfgA)
	pathB := writeConfig(t, cfgB)
	a, _ := Load(pathA)
	b, _ := Load(pathB)

	if a.ScopesHash() != b.ScopesHash() {
		t.Error("ScopesHash() differs for two independently-loaded, identically-scoped configs — cross-node comparison would be useless")
	}
}

func TestScopesHash_IgnoresNodeIP(t *testing.T) {
	cfgA := validBase()
	cfgB := validBase()

	officeA := cfgA["scopes"].(map[string]interface{})["office"].(map[string]interface{})
	officeA["node_ip"] = "192.168.100.22/24"

	officeB := cfgB["scopes"].(map[string]interface{})["office"].(map[string]interface{})
	officeB["node_ip"] = "192.168.100.23/24"

	pathA := writeConfig(t, cfgA)
	pathB := writeConfig(t, cfgB)
	a, err := Load(pathA)
	if err != nil {
		t.Fatalf("load a: %v", err)
	}
	b, err := Load(pathB)
	if err != nil {
		t.Fatalf("load b: %v", err)
	}

	if a.ScopesHash() != b.ScopesHash() {
		t.Error("ScopesHash() differs solely due to NodeIP — NodeIP is legitimately per-node, so a healthy 2-worker cluster would always report a false config mismatch")
	}
}

func TestConfigDocumentHash_DeterministicAndSensitiveToChange(t *testing.T) {
	cfg := validBase()
	path := writeConfig(t, cfg)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	h1 := c.ConfigDocumentHash()
	h2 := c.ConfigDocumentHash()
	if h1 != h2 {
		t.Errorf("ConfigDocumentHash() not deterministic: %q vs %q", h1, h2)
	}
	if h1 == "" {
		t.Error("ConfigDocumentHash() returned empty string")
	}

	c.LogLevel = "debug"
	if h3 := c.ConfigDocumentHash(); h3 == h1 {
		t.Error("ConfigDocumentHash() unchanged after LogLevel changed")
	}
}

func TestConfigDocumentHash_IgnoresNodeIdentityFields(t *testing.T) {
	cfgA := validBase()
	cfgB := validBase()
	cfgA["node_id"] = "node1"
	cfgA["role"] = "core-1"
	cfgA["control_addr"] = "10.0.0.1:9443"
	cfgA["peers"] = []string{"10.0.0.2:9443"}
	cfgB["node_id"] = "node2"
	cfgB["role"] = "core-2"
	cfgB["control_addr"] = "10.0.0.2:9443"
	cfgB["peers"] = []string{"10.0.0.1:9443"}

	pathA := writeConfig(t, cfgA)
	pathB := writeConfig(t, cfgB)
	a, err := Load(pathA)
	if err != nil {
		t.Fatalf("load a: %v", err)
	}
	b, err := Load(pathB)
	if err != nil {
		t.Fatalf("load b: %v", err)
	}

	if a.ConfigDocumentHash() != b.ConfigDocumentHash() {
		t.Error("ConfigDocumentHash() differs solely due to node-identity fields (node_id/role/control_addr/peers) — these are per-node by design and were never part of a push, so every healthy node would falsely report a mismatch")
	}
}

func TestConfigDocumentHash_IgnoresNodeIP(t *testing.T) {
	cfgA := validBase()
	cfgB := validBase()

	officeA := cfgA["scopes"].(map[string]interface{})["office"].(map[string]interface{})
	officeA["node_ip"] = "192.168.100.22/24"

	officeB := cfgB["scopes"].(map[string]interface{})["office"].(map[string]interface{})
	officeB["node_ip"] = "192.168.100.23/24"

	pathA := writeConfig(t, cfgA)
	pathB := writeConfig(t, cfgB)
	a, err := Load(pathA)
	if err != nil {
		t.Fatalf("load a: %v", err)
	}
	b, err := Load(pathB)
	if err != nil {
		t.Fatalf("load b: %v", err)
	}

	if a.ConfigDocumentHash() != b.ConfigDocumentHash() {
		t.Error("ConfigDocumentHash() differs solely due to NodeIP — NodeIP is legitimately per-node, same reasoning as ScopesHash")
	}
}

func TestConfigDocumentHash_DiffersFromScopesHash(t *testing.T) {
	cfg := validBase()
	path := writeConfig(t, cfg)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if c.ConfigDocumentHash() == c.ScopesHash() {
		t.Error("ConfigDocumentHash() and ScopesHash() coincidentally equal — not itself a bug, but suspicious enough to flag; expected them to differ for a config with non-empty non-Scopes fields")
	}
}

func TestDHCPOptionOverridesClientDNS(t *testing.T) {
	cases := []struct {
		name string
		opts []string
		want bool
	}{
		{"empty", nil, false},
		{"unrelated option", []string{"3,192.168.1.1"}, false},
		{"numeric option 6", []string{"6,8.8.8.8"}, true},
		{"named option:dns-server", []string{"option:dns-server,8.8.8.8"}, true},
		{"named option6:dns-server (IPv6 form)", []string{"option6:dns-server,[2001:4860:4860::8888]"}, true},
		{"case-insensitive + surrounding whitespace", []string{"  OPTION:DNS-SERVER,8.8.8.8"}, true},
		{"option 60 must not match option 6's prefix", []string{"60,foo"}, false},
		{"match among several unrelated entries", []string{"3,192.168.1.1", "119,example.com", "6,8.8.8.8"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := dhcpOptionOverridesClientDNS(tc.opts); got != tc.want {
				t.Errorf("dhcpOptionOverridesClientDNS(%v) = %v, want %v", tc.opts, got, tc.want)
			}
		})
	}
}

func TestDNSClientMismatch_WarnsOnScopeOwnRecords(t *testing.T) {
	c := &Cluster{
		Scopes: map[string]ScopeConfig{
			"office": {
				DNSRecords:  []DNSRecord{{Name: "printer.local", Type: "A", Value: "192.168.100.50"}},
				DHCPOptions: []string{"6,8.8.8.8"},
			},
		},
	}
	res := c.ValidateExtended()
	wantSubstr := `scope "office": defines local DNS name(s) but its DNS server for clients (option 6) is set away`
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, wantSubstr) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a local-DNS-vs-client-DNS mismatch warning for scope %q, got: %v", "office", res.Warnings)
	}
}

func TestDNSClientMismatch_WarnsViaClientDNSServerField(t *testing.T) {
	c := &Cluster{
		Scopes: map[string]ScopeConfig{
			"office": {
				DNSRecords:      []DNSRecord{{Name: "printer.local", Type: "A", Value: "192.168.100.50"}},
				ClientDNSServer: "8.8.8.8",
			},
		},
	}
	res := c.ValidateExtended()
	wantSubstr := `scope "office": defines local DNS name(s) but its DNS server for clients (option 6) is set away`
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, wantSubstr) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a local-DNS-vs-client-DNS mismatch warning via ClientDNSServer, got: %v", res.Warnings)
	}
}

func TestDNSClientMismatch_WarnsViaGlobalRecordsAndDefaultOptions(t *testing.T) {
	c := &Cluster{
		GlobalDNSRecords:   []DNSRecord{{Name: "ntp.local", Type: "A", Value: "192.0.2.10"}},
		DefaultDHCPOptions: []string{"option:dns-server,1.1.1.1"},
		Scopes: map[string]ScopeConfig{
			"av-dante": {},
		},
	}
	res := c.ValidateExtended()
	wantSubstr := `scope "av-dante": defines local DNS name(s)`
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, wantSubstr) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a local-DNS-vs-client-DNS mismatch warning via GlobalDNSRecords+DefaultDHCPOptions, got: %v", res.Warnings)
	}
}

func TestDNSClientMismatch_NoWarningForLegitimateDHCPOnlyScope(t *testing.T) {
	c := &Cluster{
		Scopes: map[string]ScopeConfig{
			"dhcp-only": {DHCPOptions: []string{"6,8.8.8.8"}},
		},
	}
	res := c.ValidateExtended()
	for _, w := range res.Warnings {
		if strings.Contains(w, "defines local DNS name(s)") {
			t.Errorf("a scope with no DNS records must never trigger the local-DNS-vs-client-DNS warning, got: %v", res.Warnings)
		}
	}
}

// TestDNSClientMismatch_NoWarningWithoutOverride covers the common case: a
// scope with local DNS records and no dhcp_options override at all.
func TestDNSClientMismatch_NoWarningWithoutOverride(t *testing.T) {
	c := &Cluster{
		Scopes: map[string]ScopeConfig{
			"office": {DNSRecords: []DNSRecord{{Name: "printer.local", Type: "A", Value: "192.168.100.50"}}},
		},
	}
	res := c.ValidateExtended()
	for _, w := range res.Warnings {
		if strings.Contains(w, "defines local DNS name(s)") {
			t.Errorf("a scope with no dhcp_options override must never trigger the local-DNS-vs-client-DNS warning, got: %v", res.Warnings)
		}
	}
}

func TestVIPEqualsGateway_Warns(t *testing.T) {
	c := &Cluster{Scopes: map[string]ScopeConfig{
		"office": {VIP: "192.168.100.1/24", Gateway: "192.168.100.1"},
	}}
	res := c.ValidateExtended()
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, `scope "office": vip and gateway are the same address`) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a vip-equals-gateway warning, got: %v", res.Warnings)
	}
}

func TestVIPDiffersFromGateway_NoWarning(t *testing.T) {
	c := &Cluster{Scopes: map[string]ScopeConfig{
		"office": {VIP: "192.168.100.2/24", Gateway: "192.168.100.1"},
	}}
	res := c.ValidateExtended()
	for _, w := range res.Warnings {
		if strings.Contains(w, "vip and gateway are the same address") {
			t.Errorf("vip != gateway must not trigger the warning, got: %v", res.Warnings)
		}
	}
}

func TestIPRangesOverlap(t *testing.T) {
	cases := []struct {
		name         string
		aStart, aEnd string
		bStart, bEnd string
		want         bool
	}{
		{"identical ranges", "192.168.1.100", "192.168.1.200", "192.168.1.100", "192.168.1.200", true},
		{"partial overlap", "192.168.1.100", "192.168.1.200", "192.168.1.150", "192.168.1.250", true},
		{"one contains the other", "192.168.1.50", "192.168.1.250", "192.168.1.100", "192.168.1.200", true},
		{"adjacent, touching at one address", "192.168.1.100", "192.168.1.200", "192.168.1.200", "192.168.1.250", true},
		{"disjoint", "192.168.1.100", "192.168.1.200", "192.168.1.201", "192.168.1.250", false},
		{"different subnets entirely", "192.168.1.100", "192.168.1.200", "10.0.0.100", "10.0.0.200", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			aStart, aEnd, aOK := parseIPRange([2]string{tc.aStart, tc.aEnd})
			bStart, bEnd, bOK := parseIPRange([2]string{tc.bStart, tc.bEnd})
			if !aOK || !bOK {
				t.Fatalf("parseIPRange failed to parse a valid test range")
			}
			if got := ipRangesOverlap(aStart, aEnd, bStart, bEnd); got != tc.want {
				t.Errorf("ipRangesOverlap(%s-%s, %s-%s) = %v, want %v", tc.aStart, tc.aEnd, tc.bStart, tc.bEnd, got, tc.want)
			}
		})
	}
}

func TestOverlappingVIPSubnets_ErrorsBlocking(t *testing.T) {
	c := &Cluster{Scopes: map[string]ScopeConfig{
		"test2": {VIP: "192.168.10.254/23"},
		"test6": {VIP: "192.168.10.254/24"},
	}}
	res := c.ValidateExtended()
	found := false
	for _, e := range res.Errors {
		if strings.Contains(e, "vip subnets overlap") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a vip-subnet-overlap error, got: %v", res.Errors)
	}
}

func TestOverlappingVIPSubnets_SameSizeAlsoErrors(t *testing.T) {
	c := &Cluster{Scopes: map[string]ScopeConfig{
		"a": {VIP: "192.168.20.1/24"},
		"b": {VIP: "192.168.20.200/24"},
	}}
	res := c.ValidateExtended()
	found := false
	for _, e := range res.Errors {
		if strings.Contains(e, "vip subnets overlap") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a vip-subnet-overlap error for two scopes on the identical /24, got: %v", res.Errors)
	}
}

func TestDisjointVIPSubnets_NoOverlapError(t *testing.T) {
	c := &Cluster{Scopes: map[string]ScopeConfig{
		"a": {VIP: "192.168.20.1/24"},
		"b": {VIP: "192.168.21.1/24"},
	}}
	res := c.ValidateExtended()
	for _, e := range res.Errors {
		if strings.Contains(e, "vip subnets overlap") {
			t.Errorf("disjoint /24s must not error, got: %v", res.Errors)
		}
	}
}

func TestOverlappingDHCPRanges_WarnsOncePerPairNotBlocking(t *testing.T) {
	c := &Cluster{Scopes: map[string]ScopeConfig{
		"rw-100": {DHCPRange: [2]string{"192.168.1.100", "192.168.1.200"}},
		"rw-101": {DHCPRange: [2]string{"192.168.1.150", "192.168.1.250"}},
		"rw-102": {DHCPRange: [2]string{"10.0.0.100", "10.0.0.200"}}, // disjoint from both
	}}
	res := c.ValidateExtended()
	count := 0
	for _, w := range res.Warnings {
		if strings.Contains(w, "dhcp_range overlaps") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 overlap warning (one pair), got %d: %v", count, res.Warnings)
	}
}

func TestNodeIPInsideDHCPRange_Warns(t *testing.T) {
	c := &Cluster{Scopes: map[string]ScopeConfig{
		"office": {
			VIP:       "192.168.100.1/24",
			NodeIP:    "192.168.100.150/24",
			DHCPRange: [2]string{"192.168.100.100", "192.168.100.200"},
		},
	}}
	res := c.ValidateExtended()
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, `scope "office": node_ip 192.168.100.150/24 falls inside this scope's own dhcp_range`) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a node_ip-inside-dhcp_range warning, got: %v", res.Warnings)
	}
}

func TestNodeIPOutsideDHCPRange_NoWarning(t *testing.T) {
	c := &Cluster{Scopes: map[string]ScopeConfig{
		"office": {
			VIP:       "192.168.100.1/24",
			NodeIP:    "192.168.100.22/24",
			DHCPRange: [2]string{"192.168.100.100", "192.168.100.200"},
		},
	}}
	res := c.ValidateExtended()
	for _, w := range res.Warnings {
		if strings.Contains(w, "falls inside this scope's own dhcp_range") {
			t.Errorf("node_ip outside dhcp_range must not warn, got: %v", res.Warnings)
		}
	}
}

func TestNodeIPSuffixesDuplicateValue_Errors(t *testing.T) {
	c := &Cluster{ScopeDefaults: &ScopeDefaults{
		NodeIPSuffixes: map[string]string{"core-1": "22", "core-2": "22"},
	}}
	res := c.ValidateExtended()
	found := false
	for _, e := range res.Errors {
		if strings.Contains(e, `"core-1" and "core-2" both use suffix "22"`) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a NodeIPSuffixes duplicate-value error, got: %v", res.Errors)
	}
}

func TestNodeIPSuffixesDistinctValues_NoError(t *testing.T) {
	c := &Cluster{ScopeDefaults: &ScopeDefaults{
		NodeIPSuffixes: map[string]string{"core-1": "22", "core-2": "23"},
	}}
	res := c.ValidateExtended()
	for _, e := range res.Errors {
		if strings.Contains(e, "node_ip_suffixes") {
			t.Errorf("distinct suffixes must not error, got: %v", res.Errors)
		}
	}
}

func TestVIPSuffixSyntaxCheck_Errors(t *testing.T) {
	cases := []struct {
		name    string
		suffix  string
		wantErr bool
	}{
		{"empty — nothing configured", "", false},
		{"valid low", "0", false},
		{"valid high", "255", false},
		{"valid mid", "50", false},
		{"too high", "256", true},
		{"negative", "-1", true},
		{"not a number", "abc", true},
		{"full IP instead of a bare octet", "192.168.1.50", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Cluster{ScopeDefaults: &ScopeDefaults{VIPSuffix: tc.suffix}}
			res := c.ValidateExtended()
			found := false
			for _, e := range res.Errors {
				if strings.Contains(e, "vip_suffix") {
					found = true
				}
			}
			if found != tc.wantErr {
				t.Errorf("VIPSuffix %q: got error=%v, want %v (errors: %v)", tc.suffix, found, tc.wantErr, res.Errors)
			}
		})
	}
}

func TestBackupEnabledRequiresPassword_Errors(t *testing.T) {
	cases := []struct {
		name    string
		enabled bool
		pw      string
		wantErr bool
	}{
		{"disabled, no password — fine", false, "", false},
		{"disabled, has password anyway — fine", false, "x", false},
		{"enabled, no password — blocked", true, "", true},
		{"enabled, has password — fine", true, "x", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Cluster{BackupEnabled: tc.enabled, BackupPassword: tc.pw}
			res := c.ValidateExtended()
			found := false
			for _, e := range res.Errors {
				if strings.Contains(e, "backup_password") {
					found = true
				}
			}
			if found != tc.wantErr {
				t.Errorf("BackupEnabled=%v/pw=%q: got error=%v, want %v (errors: %v)", tc.enabled, tc.pw, found, tc.wantErr, res.Errors)
			}
		})
	}
}

func TestCoreAddressSyntaxCheck_Errors(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"empty — nothing configured, use built-in default", "", false},
		{"valid loopback alias", "127.0.0.99", false},
		{"not an IP at all", "not-an-ip", true},
		{"a real routable address, not loopback", "192.168.1.50", true},
		{"127.0.0.1 itself — reserved", "127.0.0.1", true},
		{"systemd-resolved's own .53", "127.0.0.53", true},
		{"systemd-resolved's own .54", "127.0.0.54", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Cluster{CoreDNSAddress: tc.addr}
			res := c.ValidateExtended()
			found := false
			for _, e := range res.Errors {
				if strings.Contains(e, "core_dns_address") {
					found = true
				}
			}
			if found != tc.wantErr {
				t.Errorf("CoreDNSAddress %q: got error=%v, want %v (errors: %v)", tc.addr, found, tc.wantErr, res.Errors)
			}
		})
	}
}

func TestCoreAddresses_MustNotBeIdentical(t *testing.T) {
	c := &Cluster{CoreDNSAddress: "127.0.0.42", CoreDHCPAddress: "127.0.0.42"}
	res := c.ValidateExtended()
	found := false
	for _, e := range res.Errors {
		if strings.Contains(e, "core_dns_address") && strings.Contains(e, "core_dhcp_address") {
			found = true
		}
	}
	if !found {
		t.Errorf("identical CoreDNSAddress/CoreDHCPAddress should be a hard error, got: %v", res.Errors)
	}
}

func TestCoreAddresses_DistinctValuesNoError(t *testing.T) {
	c := &Cluster{CoreDNSAddress: "127.0.0.42", CoreDHCPAddress: "127.0.0.21"}
	res := c.ValidateExtended()
	for _, e := range res.Errors {
		if strings.Contains(e, "core_d") {
			t.Errorf("distinct, valid core addresses should not error, got: %v", res.Errors)
		}
	}
}

func TestNonOverlappingDHCPRanges_NoWarning(t *testing.T) {
	c := &Cluster{Scopes: map[string]ScopeConfig{
		"rw-100": {DHCPRange: [2]string{"192.168.1.100", "192.168.1.200"}},
		"rw-101": {DHCPRange: [2]string{"192.168.2.100", "192.168.2.200"}},
	}}
	res := c.ValidateExtended()
	for _, w := range res.Warnings {
		if strings.Contains(w, "dhcp_range overlaps") {
			t.Errorf("non-overlapping ranges must not warn, got: %v", res.Warnings)
		}
	}
}

func TestTrustedHosts_RejectsMalformedIP(t *testing.T) {
	c := &Cluster{TrustedHosts: []string{"192.0.2.22", "not-an-ip"}}
	res := c.ValidateExtended()
	found := false
	for _, e := range res.Errors {
		if e == `trusted_hosts: "not-an-ip" is not a valid IP address` {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an error for the malformed entry, got: %v", res.Errors)
	}
}

func TestTrustedHosts_EmptyWarns(t *testing.T) {
	cfg := validBase()
	cfg["psk"] = testPSK
	path := writeConfig(t, cfg)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	res := c.ValidateExtended()
	wantWarning := "trusted_hosts is empty — the arbiter's token endpoints and /api/v1/ping accept requests from any source address"
	found := false
	for _, w := range res.Warnings {
		if w == wantWarning {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the empty-trusted_hosts warning, got: %v", res.Warnings)
	}

}

func TestTrustedHosts_PopulatedAndValidHasNoWarningOrError(t *testing.T) {
	cfg := validBase()
	cfg["psk"] = testPSK
	cfg["trusted_hosts"] = []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	path := writeConfig(t, cfg)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	res := c.ValidateExtended()
	if len(res.Errors) != 0 {
		t.Errorf("expected no errors, got: %v", res.Errors)
	}
	for _, w := range res.Warnings {
		if w == "trusted_hosts is empty — the arbiter's token endpoints and /api/v1/ping accept requests from any source address" {
			t.Error("populated trusted_hosts must not trigger the empty-list warning")
		}
	}
}

func TestSaveRejectsInvalidConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cluster.json")
	c := &Cluster{} // missing cluster_id, node_id, role, control_addr
	if err := Save(path, c); err == nil {
		t.Fatal("expected Save to reject an invalid config")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("Save must not write anything when validation fails")
	}
}

func TestIsNetworkOrBroadcastAddress(t *testing.T) {
	_, ipNet, err := net.ParseCIDR("192.168.4.0/24")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cases := []struct {
		ip   string
		want bool
	}{
		{"192.168.4.0", true},   // network address
		{"192.168.4.255", true}, // broadcast address
		{"192.168.4.1", false},
		{"192.168.4.254", false},
	}
	for _, c := range cases {
		got := isNetworkOrBroadcastAddress(net.ParseIP(c.ip), ipNet)
		if got != c.want {
			t.Errorf("isNetworkOrBroadcastAddress(%s, 192.168.4.0/24) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestValidateScopeAddressing_VIPIsNetworkAddressIsAnError(t *testing.T) {
	errs, _ := validateScopeAddressing("rw-netaddr", ScopeConfig{VIP: "192.168.4.0/24"})
	found := false
	for _, e := range errs {
		if strings.Contains(e, "network/broadcast address") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a network/broadcast-address error for vip 192.168.4.0/24, got: %v", errs)
	}
}

func TestValidateScopeAddressing_VIPIsBroadcastAddressIsAnError(t *testing.T) {
	errs, _ := validateScopeAddressing("rw-bcast", ScopeConfig{VIP: "192.168.4.255/24"})
	found := false
	for _, e := range errs {
		if strings.Contains(e, "network/broadcast address") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a network/broadcast-address error for vip 192.168.4.255/24, got: %v", errs)
	}
}

func TestValidateScopeAddressing_GatewayIsNetworkAddressIsAnError(t *testing.T) {
	errs, _ := validateScopeAddressing("rw-gw-netaddr", ScopeConfig{VIP: "192.168.4.1/24", Gateway: "192.168.4.0"})
	found := false
	for _, e := range errs {
		if strings.Contains(e, "network/broadcast address") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a network/broadcast-address error for gateway 192.168.4.0, got: %v", errs)
	}
}

func TestValidateScopeAddressing_NodeIPIsBroadcastAddressIsAnError(t *testing.T) {
	errs, _ := validateScopeAddressing("rw-nodeip-bcast", ScopeConfig{NodeIP: "192.168.4.255/24"})
	found := false
	for _, e := range errs {
		if strings.Contains(e, "network/broadcast address") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a network/broadcast-address error for node_ip 192.168.4.255/24, got: %v", errs)
	}
}

func TestValidateScopeAddressing_DHCPRangeIsNetworkAddressIsAnError(t *testing.T) {
	errs, _ := validateScopeAddressing("rw-dhcp-netaddr", ScopeConfig{
		VIP: "192.168.4.1/24", Gateway: "192.168.4.1", DHCPRange: [2]string{"192.168.4.0", "192.168.4.200"},
	})
	found := false
	for _, e := range errs {
		if strings.Contains(e, "dhcp_range start") && strings.Contains(e, "network/broadcast address") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a network/broadcast-address error for dhcp_range start 192.168.4.0, got: %v", errs)
	}
}

func TestValidateScopeAddressing_ImplausiblyWidePrefixIsAnError(t *testing.T) {
	errs, _ := validateScopeAddressing("rw-bad", ScopeConfig{VIP: "192.168.32.2/2"})
	found := false
	for _, e := range errs {
		if strings.Contains(e, "implausibly wide prefix") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an implausibly-wide-prefix error for a /2 VIP, got: %v", errs)
	}
}

// TestValidateScopeAddressing_GatewayOutsideVIPSubnetIsAnError pins the
// gateway/VIP subnet coherence check.
func TestValidateScopeAddressing_GatewayOutsideVIPSubnetIsAnError(t *testing.T) {
	errs, _ := validateScopeAddressing("rw-gw", ScopeConfig{VIP: "192.168.100.1/24", Gateway: "10.0.0.1"})
	found := false
	for _, e := range errs {
		if strings.Contains(e, "outside vip's own subnet") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a gateway-outside-subnet error, got: %v", errs)
	}
}

func TestValidateScopeAddressing_MultiGatewayAllInsideSubnetIsClean(t *testing.T) {
	errs, _ := validateScopeAddressing("rw-multi-gw", ScopeConfig{
		VIP: "192.168.100.1/24", Gateway: "192.168.100.2,192.168.100.3",
	})
	if len(errs) != 0 {
		t.Errorf("expected a clean multi-gateway list, got: %v", errs)
	}
}

func TestValidateScopeAddressing_MultiGatewayOneOutsideSubnetIsAnError(t *testing.T) {
	errs, _ := validateScopeAddressing("rw-multi-gw-bad", ScopeConfig{
		VIP: "192.168.100.1/24", Gateway: "192.168.100.2,10.0.0.1",
	})
	found := false
	for _, e := range errs {
		if strings.Contains(e, "10.0.0.1") && strings.Contains(e, "outside vip's own subnet") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a gateway-outside-subnet error naming 10.0.0.1, got: %v", errs)
	}
}

func TestValidateScopeAddressing_MultiGatewayMalformedEntryIsAnError(t *testing.T) {
	errs, _ := validateScopeAddressing("rw-multi-gw-typo", ScopeConfig{
		VIP: "192.168.100.1/24", Gateway: "192.168.100.2, not-an-ip",
	})
	found := false
	for _, e := range errs {
		if strings.Contains(e, "not-an-ip") && strings.Contains(e, "not a valid IP address") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a malformed-gateway error naming not-an-ip, got: %v", errs)
	}
}

func TestValidateExtended_VIPEqualsOneOfMultipleGatewaysStillWarns(t *testing.T) {
	c := Cluster{Scopes: map[string]ScopeConfig{
		"rw-1": {VIP: "192.168.100.1/24", Gateway: "192.168.100.2,192.168.100.1"},
	}}
	res := c.ValidateExtended()
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "vip and gateway are the same address") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the vip-equals-gateway warning for the matching list entry, got: %v", res.Warnings)
	}
}

func TestValidateScopeAddressing_DHCPRangeWithNoGatewayIsAnError(t *testing.T) {
	errs, _ := validateScopeAddressing("rw-nogw", ScopeConfig{
		VIP: "192.168.100.1/24", DHCPRange: [2]string{"192.168.100.100", "192.168.100.200"},
	})
	found := false
	for _, e := range errs {
		if strings.Contains(e, "dhcp_range is set but gateway is empty") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a dhcp_range-without-gateway error, got: %v", errs)
	}
}

// TestValidateScopeAddressing_DHCPRangeWithGatewayNoError confirms the
// error above doesn't fire once gateway is actually set (the normal,
// healthy case).
func TestValidateScopeAddressing_DHCPRangeWithGatewayNoError(t *testing.T) {
	errs, _ := validateScopeAddressing("rw-ok", ScopeConfig{
		VIP: "192.168.100.1/24", Gateway: "192.168.100.1",
		DHCPRange: [2]string{"192.168.100.100", "192.168.100.200"},
	})
	for _, e := range errs {
		if strings.Contains(e, "dhcp_range is set but gateway is empty") {
			t.Errorf("gateway is set — must not error, got: %v", errs)
		}
	}
}

func TestValidateScopeAddressing_EmptyDHCPRangeNoGatewayErrorEither(t *testing.T) {
	errs, _ := validateScopeAddressing("rw-nodhcp", ScopeConfig{VIP: "192.168.100.1/24"})
	for _, e := range errs {
		if strings.Contains(e, "dhcp_range is set but gateway is empty") {
			t.Errorf("no dhcp_range at all — must not error, got: %v", errs)
		}
	}
}

func TestValidateScopeAddressing_MissingNodeIPIsAWarning(t *testing.T) {
	errs, warns := validateScopeAddressing("rw-nonode", ScopeConfig{VIP: "192.168.100.1/24", Gateway: "192.168.100.1"})
	if len(errs) != 0 {
		t.Errorf("missing node_ip must never be a hard Error, got: %v", errs)
	}
	found := false
	for _, w := range warns {
		if strings.Contains(w, "node_ip is not set") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a missing-node_ip warning, got: %v", warns)
	}
}

func TestValidateScopeAddressing_PresentNodeIPNoWarning(t *testing.T) {
	_, warns := validateScopeAddressing("rw-ok", ScopeConfig{
		VIP: "192.168.100.1/24", Gateway: "192.168.100.1", NodeIP: "192.168.100.22/24",
	})
	for _, w := range warns {
		if strings.Contains(w, "node_ip is not set") {
			t.Errorf("node_ip is set — must not warn, got: %v", warns)
		}
	}
}

// TestValidateScopeAddressing_NodeIPOverridesAloneNoWarning: node_ip
// overrides alone satisfy the node_ip check.
func TestValidateScopeAddressing_NodeIPOverridesAloneNoWarning(t *testing.T) {
	_, warns := validateScopeAddressing("rw-ok", ScopeConfig{
		VIP: "192.168.100.1/24", Gateway: "192.168.100.1",
		NodeIPOverrides: map[string]string{"core-1": "192.168.100.22/24", "core-2": "192.168.100.23/24"},
	})
	for _, w := range warns {
		if strings.Contains(w, "node_ip is not set") {
			t.Errorf("node_ip_overrides alone covers this scope — must not warn, got: %v", warns)
		}
	}
}

func TestPlatform_ResolveParent(t *testing.T) {
	p := &Platform{
		Mgmt:    "eth0",
		Workers: []string{"ens19", "ens20"},
		WorkerOverrides: map[string]map[string]string{
			"core-2": {"ens19": "eth1", "ens20": "eth2"},
		},
	}
	if got := p.ResolveParent("core-2", "ens19"); got != "eth1" {
		t.Errorf("ResolveParent(core-2, ens19) = %q, want eth1", got)
	}
	if got := p.ResolveParent("core-2", "ens20"); got != "eth2" {
		t.Errorf("ResolveParent(core-2, ens20) = %q, want eth2", got)
	}
	if got := p.ResolveParent("core-1", "ens19"); got != "ens19" {
		t.Errorf("ResolveParent(core-1, ens19) = %q, want ens19 (no override)", got)
	}
	// core-2 has overrides, but not for THIS canonical name -- falls
	// through to the canonical name unchanged, not a zero-value/panic.
	if got := p.ResolveParent("core-2", "ens99"); got != "ens99" {
		t.Errorf("ResolveParent(core-2, ens99) = %q, want ens99 (unmapped canonical)", got)
	}
}

func TestPlatform_ResolveParent_NilReceiverSafe(t *testing.T) {
	var p *Platform
	if got := p.ResolveParent("core-2", "ens19"); got != "ens19" {
		t.Errorf("nil Platform: ResolveParent(core-2, ens19) = %q, want ens19", got)
	}
}

func TestDisabledScopeNames(t *testing.T) {
	c := &Cluster{Scopes: map[string]ScopeConfig{
		"b":  {DNSMasqDisabled: true},
		"a":  {DNSMasqDisabled: true},
		"on": {ProbeDisabled: true},
	}}
	names := c.DisabledScopeNames()
	if len(names) != 2 || names[0] != "a" || names[1] != "b" {
		t.Errorf("DisabledScopeNames() = %v, want [a b]", names)
	}
}

func TestNodeIPSuffixesOutOfRange_Errors(t *testing.T) {
	for _, bad := range []string{"0", "255", "x", "22.1"} {
		c := &Cluster{ScopeDefaults: &ScopeDefaults{NodeIPSuffixes: map[string]string{"core-1": bad}}}
		res := c.ValidateExtended()
		found := false
		for _, e := range res.Errors {
			if strings.Contains(e, "must be a host number from 1 to 254") {
				found = true
			}
		}
		if !found {
			t.Errorf("suffix %q: expected a range error, got: %v", bad, res.Errors)
		}
	}
}
