// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const extraFixture = `{
  "cluster_id": "c1",
  "node_id": "n1",
  "role": "core-1",
  "control_addr": "192.0.2.1:9443",
  "dry_run": true,
  "psk": "0123456789abcdef0123456789abcdef",
  "templates": {"t1": {"name": "office"}},
  "history_limit": 30,
  "platform": {"mgmt": "eth0", "workers": ["eth1"]},
  "scopes": {
    "office": {
      "parent": "eth1",
      "vlan_id": 10,
      "vrrp_id": 10,
      "preferred_worker": "core-1",
      "vip": "192.0.2.10/24",
      "dhcp_range": ["192.0.2.50", "192.0.2.90"],
      "gateway": "192.0.2.1",
      "network_ref": "net-1"
    }
  }
}`

func TestSaveKeepsUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	if err := os.WriteFile(path, []byte(extraFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !c.LegacyDryRun {
		t.Error("LegacyDryRun not set")
	}
	c.LogLevel = "debug"
	sc := c.Scopes["office"]
	sc.Gateway = "192.0.2.2"
	c.Scopes["office"] = sc
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"templates", "history_limit"} {
		if _, ok := top[k]; !ok {
			t.Errorf("top-level key %q lost", k)
		}
	}
	if _, ok := top["dry_run"]; ok {
		t.Error("dry_run was written back")
	}
	if string(top["history_limit"]) != "30" {
		t.Errorf("history_limit = %s", top["history_limit"])
	}
	var scopes map[string]map[string]json.RawMessage
	if err := json.Unmarshal(top["scopes"], &scopes); err != nil {
		t.Fatal(err)
	}
	if string(scopes["office"]["network_ref"]) != `"net-1"` {
		t.Errorf("scope key network_ref = %s", scopes["office"]["network_ref"])
	}
	if string(scopes["office"]["gateway"]) != `"192.0.2.2"` {
		t.Errorf("edit not saved: gateway = %s", scopes["office"]["gateway"])
	}
	back, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if back.LegacyDryRun {
		t.Error("dry_run still present after save")
	}
	if len(back.Extra) != 2 || len(back.Scopes["office"].Extra) != 1 {
		t.Errorf("extras after round trip: %d top, %d scope", len(back.Extra), len(back.Scopes["office"].Extra))
	}
}

func TestExtraNeverShadowsKnownKeys(t *testing.T) {
	c := Cluster{ClusterID: "c1", Extra: map[string]json.RawMessage{
		"cluster_id": json.RawMessage(`"evil"`),
		"Role":       json.RawMessage(`"evil"`),
		"x_new":      json.RawMessage(`1`),
	}}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if m["cluster_id"] != "c1" || m["x_new"] != float64(1) {
		t.Errorf("unexpected output %s", data)
	}
	if _, ok := m["Role"]; ok {
		t.Errorf("case-variant of a known key written: %s", data)
	}
}

func TestExtraCaseInsensitiveKnownKeyIsNotExtra(t *testing.T) {
	var c Cluster
	if err := json.Unmarshal([]byte(`{"Cluster_ID":"c1","other":2}`), &c); err != nil {
		t.Fatal(err)
	}
	if c.ClusterID != "c1" {
		t.Errorf("ClusterID = %q", c.ClusterID)
	}
	if len(c.Extra) != 1 || c.Extra["other"] == nil {
		t.Errorf("Extra = %v", c.Extra)
	}
}

func TestMarshalWithoutExtraIsUnchanged(t *testing.T) {
	c := Cluster{ClusterID: "c1"}
	got, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(clusterPlain(c))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("got %s want %s", got, want)
	}
}

func TestUnmarshalRejectsBadJSON(t *testing.T) {
	var c Cluster
	if err := json.Unmarshal([]byte(`{"cluster_id": 5}`), &c); err == nil {
		t.Error("wrong type accepted")
	}
}

func TestUnmarshalMergesIntoExistingValue(t *testing.T) {
	c := Cluster{ClusterID: "c1", LogLevel: "debug", Extra: map[string]json.RawMessage{"old": json.RawMessage(`1`)}}
	if err := json.Unmarshal([]byte(`{"role":"core-2","fresh":2}`), &c); err != nil {
		t.Fatal(err)
	}
	if c.ClusterID != "c1" || c.LogLevel != "debug" || c.Role != "core-2" {
		t.Errorf("existing fields not merged: %+v", c)
	}
	if string(c.Extra["old"]) != "1" || string(c.Extra["fresh"]) != "2" {
		t.Errorf("Extra = %v", c.Extra)
	}
	sc := ScopeConfig{Parent: "eth1", VLANID: 5}
	if err := json.Unmarshal([]byte(`{"gateway":"192.0.2.1"}`), &sc); err != nil {
		t.Fatal(err)
	}
	if sc.Parent != "eth1" || sc.VLANID != 5 || sc.Gateway != "192.0.2.1" {
		t.Errorf("scope not merged: %+v", sc)
	}
}
