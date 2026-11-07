// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package config

import "testing"

func hashFixture() Cluster {
	return Cluster{
		ClusterID: "c", PSK: "psk", LogLevel: "info", TrustedHosts: []string{"a"},
		Scopes:         map[string]ScopeConfig{"x": {Parent: "e", VLANID: 5, VIP: "10.0.0.1/24", NodeIP: "10.0.0.2/24", VRRPID: 3}},
		CoreDNSAddress: "127.0.0.1",
	}
}

// The original hash must keep its value: nodes of different versions
// compare it. If this fails, documentV1 was changed.
func TestConfigDocumentHash_KeepsItsValue(t *testing.T) {
	c := hashFixture()
	if got := c.ConfigDocumentHash(); got != "dd032def78d7" {
		t.Errorf("ConfigDocumentHash = %s, want dd032def78d7", got)
	}
}

func TestConfigDocumentHashV2_CoversTheSixSettings(t *testing.T) {
	base := hashFixture()
	v1, v2 := base.ConfigDocumentHash(), base.ConfigDocumentHashV2()
	if v2 == "" || v2 == v1 {
		t.Fatalf("v2 = %q, v1 = %q", v2, v1)
	}
	mutations := map[string]func(*Cluster){
		"sanity_check_disabled":     func(c *Cluster) { c.SanityCheckDisabled = true },
		"backup_enabled":            func(c *Cluster) { c.BackupEnabled = true },
		"backup_interval_hours":     func(c *Cluster) { c.BackupIntervalHours = 6 },
		"backup_retention_count":    func(c *Cluster) { c.BackupRetentionCount = 3 },
		"backup_password":           func(c *Cluster) { c.BackupPassword = "x" },
		"backup_replicate_to_peers": func(c *Cluster) { c.BackupReplicateToPeers = true },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			c := hashFixture()
			mutate(&c)
			if c.ConfigDocumentHash() != v1 {
				t.Error("the original hash changed; it must not cover this setting")
			}
			if c.ConfigDocumentHashV2() == v2 {
				t.Error("v2 does not notice the change")
			}
		})
	}
}

func TestConfigDocumentHashes_IgnoreNodeLocalAndMetadataFields(t *testing.T) {
	base := hashFixture()
	v1, v2 := base.ConfigDocumentHash(), base.ConfigDocumentHashV2()
	c := hashFixture()
	c.NodeID, c.Role, c.ControlAddr, c.Peers = "n", RoleCore2, "192.0.2.2:9443", []string{"p"}
	c.ConfigRevision, c.ConfigRevisionAt, c.ConfigRevisionOrigin = 9, "t", "core-2"
	c.MembershipEpoch, c.OutageRulesActive = 3, true
	sc := c.Scopes["x"]
	sc.NodeIP = "10.0.0.99/24"
	c.Scopes = map[string]ScopeConfig{"x": sc}
	if c.ConfigDocumentHash() != v1 || c.ConfigDocumentHashV2() != v2 {
		t.Error("a node-local or metadata field changed a hash")
	}
}

func TestHashedKeys(t *testing.T) {
	v1, v2 := HashedKeys()
	if len(v1) != 21 || len(v2) != 27 {
		t.Errorf("v1 has %d keys, v2 has %d, want 21 and 27", len(v1), len(v2))
	}
	set := map[string]bool{}
	for _, k := range v2 {
		set[k] = true
	}
	for _, k := range v1 {
		if !set[k] {
			t.Errorf("v2 lacks v1 key %s", k)
		}
	}
	for _, k := range []string{"scopes", "psk", "sanity_check_disabled", "backup_password"} {
		if !set[k] {
			t.Errorf("v2 lacks %s", k)
		}
	}
}
