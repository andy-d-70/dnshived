// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package cfgjournal

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"dnshived/internal/config"
)

const validCluster = `{"schema_version":2,"cluster_id":"test","node_id":"node1","role":"core-1","control_addr":"10.0.0.1:9443",
"peers":["10.0.0.2:9443","10.0.0.3:9443"],"psk":"x","platform":{"mgmt":"eth0","workers":["eth1"]},
"scopes":{"office":{"parent":"eth1","vlan_id":100,"vip":"192.168.100.1/24","dhcp_range":["192.168.100.100","192.168.100.200"],
"gateway":"192.168.100.1","upstream":["1.1.1.1"],"vrrp_id":51,"preferred_worker":"core-1"}}}`

func coreConfig(t *testing.T, node, psk, nodeIP string, split bool) *ConfigDoc {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cluster.json")
	var c config.Cluster
	if err := json.Unmarshal([]byte(validCluster), &c); err != nil {
		t.Fatal(err)
	}
	c.NodeID, c.Role, c.PSK = node, node, psk
	sc := c.Scopes["office"]
	sc.NodeIP = nodeIP
	c.Scopes["office"] = sc
	c.ConfigRevision = 40
	if err := config.Save(path, &c); err != nil {
		t.Fatal(err)
	}
	if split {
		if _, err := config.MigrateToSplit(path); err != nil {
			t.Fatal(err)
		}
	}
	return &ConfigDoc{Name: "cluster", Path: path}
}

func TestConfigDoc_EveryCoreGetsTheChangeAndKeepsItsOwnFields(t *testing.T) {
	s := newStore(t)
	cores := []*ConfigDoc{
		coreConfig(t, "core-1", "secret-1", "192.168.100.22/24", false),
		coreConfig(t, "core-2", "secret-2", "192.168.100.23/24", true),
	}
	live, _ := config.Load(cores[0].Path)
	cand := *live
	cand.LogLevel = "debug"
	lab := live.Scopes["office"]
	lab.VLANID, lab.VIP, lab.Gateway, lab.VRRPID, lab.NodeIP = 30, "192.168.30.1/24", "192.168.30.1", 52, ""
	lab.DHCPRange = [2]string{"192.168.30.100", "192.168.30.200"}
	cand.Scopes = map[string]config.ScopeConfig{"office": live.Scopes["office"], "lab": lab}
	cand.PSK = "must-not-travel"
	lt, _ := Replicated(live)
	ct, _ := Replicated(&cand)
	es, err := FromChange("cluster", lt, ct, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range es {
		if e.Path == "psk" {
			t.Fatal("a secret must never become a journal entry")
		}
	}
	rev, err := New(s.Commit).Append(Meta{Author: "ann"}, es)
	if err != nil {
		t.Fatal(err)
	}
	for i, d := range cores {
		if _, got, err := Replay(s.View(), d); err != nil || got != rev {
			t.Fatalf("core %d: replay %d %v", i, got, err)
		}
		c, err := config.Load(d.Path)
		if err != nil {
			t.Fatal(err)
		}
		if c.LogLevel != "debug" || c.Scopes["lab"].VLANID != 30 || c.ConfigRevision != 41 {
			t.Errorf("core %d: change not applied: %s %+v rev %d", i, c.LogLevel, c.Scopes["lab"], c.ConfigRevision)
		}
		wantPSK, wantIP := []string{"secret-1", "secret-2"}[i], []string{"192.168.100.22/24", "192.168.100.23/24"}[i]
		if c.PSK != wantPSK || c.Scopes["office"].NodeIP != wantIP || c.NodeID != []string{"core-1", "core-2"}[i] {
			t.Errorf("core %d lost its own fields: psk %q node_ip %q node %q", i, c.PSK, c.Scopes["office"].NodeIP, c.NodeID)
		}
		if _, at, _, err := d.Load(); err != nil || at != rev {
			t.Errorf("core %d: stamp %d %v", i, at, err)
		}
	}
}

func TestConfigDoc_AChangeOutsideTheJournalIsDetectedButOwnFieldsAreNot(t *testing.T) {
	s := newStore(t)
	d := coreConfig(t, "core-1", "secret-1", "192.168.100.22/24", false)
	live, _ := config.Load(d.Path)
	cand := *live
	cand.LogLevel = "warn"
	lt, _ := Replicated(live)
	ct, _ := Replicated(&cand)
	es, _ := FromChange("cluster", lt, ct, 0)
	if _, err := New(s.Commit).Append(Meta{}, es); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Replay(s.View(), d); err != nil {
		t.Fatal(err)
	}
	c, _ := config.Load(d.Path)
	c.PSK, c.NodeID = "rotated", "renamed"
	if err := config.Save(d.Path, c); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := d.Load(); err != nil {
		t.Fatalf("own fields may change outside the journal: %v", err)
	}
	c.LogLevel = "error"
	if err := config.Save(d.Path, c); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := d.Load(); !errors.Is(err, ErrOutside) {
		t.Fatalf("a cluster-wide change outside the journal must be detected: %v", err)
	}
}

func TestWithOwnFields_TakesOnlyOwnFields(t *testing.T) {
	d := coreConfig(t, "core-1", "old", "192.168.100.22/24", false)
	dst, _ := config.Load(d.Path)
	src, _ := config.Load(d.Path)
	src.PSK, src.TrustedHosts, src.LogLevel = "new", []string{"10.0.0.9"}, "trace"
	sc := src.Scopes["office"]
	sc.NodeIP = "192.168.100.99/24"
	src.Scopes["office"] = sc
	got, err := WithOwnFields(dst, src)
	if err != nil {
		t.Fatal(err)
	}
	if got.PSK != "new" || len(got.TrustedHosts) != 1 || got.Scopes["office"].NodeIP != "192.168.100.99/24" {
		t.Fatalf("own fields not taken: %+v", got)
	}
	if got.LogLevel != dst.LogLevel {
		t.Fatal("a replicated field must not be taken from src")
	}
}
