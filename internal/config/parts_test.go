// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func splitFixture() *Cluster {
	raw, _ := json.Marshal(validBase())
	var c Cluster
	if err := json.Unmarshal(raw, &c); err != nil {
		panic(err)
	}
	office := c.Scopes["office"]
	office.NodeIP = "192.168.100.22/24"
	office.Reservations = []Reservation{{MAC: "aa:bb:cc:00:00:01", IP: "192.168.100.50", Hostname: "nas"}}
	c.Scopes["office"] = office
	lab := office
	lab.VLANID = 101
	lab.VIP = "192.168.101.1/24"
	lab.NodeIP = "192.168.101.22/24"
	lab.DHCPRange = [2]string{"192.168.101.100", "192.168.101.200"}
	lab.Gateway = "192.168.101.1"
	lab.VRRPID = 52
	lab.Reservations = nil
	c.Scopes["lab"] = lab
	c.LocalDomains = []LocalDomain{
		{Name: "office.lan", Records: []LocalDomainHost{{Host: "nas", Type: "A", Value: "192.168.100.50"}}},
		{Name: "av.lan", TTL: 60, Records: []LocalDomainHost{{Host: "cam", Type: "A", Value: "192.168.100.60"}}},
	}
	c.GlobalDNSRecords = []DNSRecord{{Name: "g.lan.", Type: "A", Value: "192.168.100.8"}}
	c.ConfigRevision = 7
	return &c
}

func marshalDoc(t *testing.T, c *Cluster) string {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSplitAssemble_RoundTripKeepsEverything(t *testing.T) {
	c := splitFixture()
	m, files, err := c.Split()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Assemble(m, func(p string) ([]byte, error) {
		b, ok := files[p]
		if !ok {
			return nil, os.ErrNotExist
		}
		return b, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if marshalDoc(t, got) != marshalDoc(t, c) {
		t.Errorf("round trip differs:\n got %s\nwant %s", marshalDoc(t, got), marshalDoc(t, c))
	}
	g1, g2 := got.ConfigDocumentHashes()
	w1, w2 := c.ConfigDocumentHashes()
	if g1 != w1 || g2 != w2 {
		t.Errorf("config hashes differ after the round trip")
	}
}

func TestManifestHash_FollowsEveryKindOfData(t *testing.T) {
	base := splitFixture()
	m0, _, _ := base.Split()
	h0 := m0.Hash()
	tests := []struct {
		name   string
		change func(c *Cluster)
		differ bool
	}{
		{"reservation", func(c *Cluster) {
			sc := c.Scopes["office"]
			sc.Reservations = append(append([]Reservation(nil), sc.Reservations...), Reservation{MAC: "aa:bb:cc:00:00:02", IP: "192.168.100.51", Hostname: "x"})
			c.Scopes["office"] = sc
		}, true},
		{"domain record", func(c *Cluster) {
			c.LocalDomains = append([]LocalDomain(nil), c.LocalDomains...)
			c.LocalDomains[1].Records = []LocalDomainHost{{Host: "cam", Type: "A", Value: "192.168.100.61"}}
		}, true},
		{"domain ttl", func(c *Cluster) {
			c.LocalDomains = append([]LocalDomain(nil), c.LocalDomains...)
			c.LocalDomains[0].TTL = 5
		}, true},
		{"global record", func(c *Cluster) {
			c.GlobalDNSRecords = []DNSRecord{{Name: "q.lan.", Type: "A", Value: "192.168.100.9"}}
		}, true},
		{"backup setting", func(c *Cluster) { c.BackupEnabled = true }, true},
		{"new domain", func(c *Cluster) {
			c.LocalDomains = append(append([]LocalDomain(nil), c.LocalDomains...), LocalDomain{Name: "new.lan"})
		}, true},
		{"node address", func(c *Cluster) {
			sc := c.Scopes["office"]
			sc.NodeIP = "192.168.100.99/24"
			c.Scopes["office"] = sc
		}, false},
		{"revision", func(c *Cluster) { c.ConfigRevision = 99 }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := splitFixture()
			tt.change(c)
			m, _, err := c.Split()
			if err != nil {
				t.Fatal(err)
			}
			if (m.Hash() != h0) != tt.differ {
				t.Errorf("manifest hash changed = %v, want %v", m.Hash() != h0, tt.differ)
			}
		})
	}
}

func TestSplit_ChangesOnlyTheTouchedPart(t *testing.T) {
	c := splitFixture()
	m0, _, _ := c.Split()
	c.LocalDomains = append([]LocalDomain(nil), c.LocalDomains...)
	c.LocalDomains[1].TTL = 11
	m1, _, _ := c.Split()
	changed := 0
	for i := range m0.Parts {
		if m0.Parts[i].Hash != m1.Parts[i].Hash {
			changed++
			if m0.Parts[i].Kind != PartDomain || m0.Parts[i].Name != "av.lan" {
				t.Errorf("unexpected part changed: %+v", m0.Parts[i])
			}
		}
	}
	if changed != 1 {
		t.Errorf("%d parts changed, want 1", changed)
	}
}

func TestSaveLoadSplit_RoundTripAndLoadFallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	c := splitFixture()
	if err := SaveSplit(SplitDir(path), c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load must fall back to the split directory: %v", err)
	}
	if marshalDoc(t, got) != marshalDoc(t, c) {
		t.Error("loaded split config differs from the saved one")
	}
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	c.PSK = "other"
	if err := SaveSplit(SplitDir(path), c); err != nil {
		t.Fatal(err)
	}
	single, err := Load(path)
	if err != nil || single.PSK != testPSK {
		t.Errorf("the single file must stay authoritative while it exists (err %v)", err)
	}
}

func TestSaveSplit_RemovesPartsOfDeletedObjects(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "c.d")
	c := splitFixture()
	if err := SaveSplit(dir, c); err != nil {
		t.Fatal(err)
	}
	c.LocalDomains = c.LocalDomains[:1]
	delete(c.Scopes, "lab")
	if err := SaveSplit(dir, c); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"domains/av.lan.json", "scopes/lab.json"} {
		if _, err := os.Stat(filepath.Join(dir, p)); err == nil {
			t.Errorf("%s is still there", p)
		}
	}
	if _, err := LoadSplit(dir); err != nil {
		t.Fatal(err)
	}
}

func TestLoadSplit_RejectsTamperedAndUnsafeParts(t *testing.T) {
	setup := func(t *testing.T) string {
		dir := filepath.Join(t.TempDir(), "c.d")
		if err := SaveSplit(dir, splitFixture()); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	t.Run("changed part", func(t *testing.T) {
		dir := setup(t)
		p := filepath.Join(dir, "domains", "av.lan.json")
		b, _ := os.ReadFile(p)
		os.WriteFile(p, []byte(strings.Replace(string(b), "192.168.100.60", "192.168.100.66", 1)), 0o600)
		if _, err := LoadSplit(dir); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Errorf("err = %v, want a manifest mismatch", err)
		}
	})
	t.Run("missing part", func(t *testing.T) {
		dir := setup(t)
		os.Remove(filepath.Join(dir, "scopes", "lab.json"))
		if _, err := LoadSplit(dir); err == nil {
			t.Error("a missing part must fail")
		}
	})
	t.Run("path traversal name", func(t *testing.T) {
		dir := setup(t)
		raw, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
		bad := strings.Replace(string(raw), `"name": "lab"`, `"name": "../../x"`, 1)
		os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(bad), 0o600)
		if _, err := LoadSplit(dir); err == nil || !strings.Contains(err.Error(), "not a valid scope name") {
			t.Errorf("err = %v, want a rejected name", err)
		}
	})
	t.Run("future format", func(t *testing.T) {
		dir := setup(t)
		raw, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
		os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(strings.Replace(string(raw), `"format": 1`, `"format": 99`, 1)), 0o600)
		if _, err := LoadSplit(dir); err == nil {
			t.Error("an unknown format must fail")
		}
	})
	t.Run("unknown kind is skipped", func(t *testing.T) {
		dir := setup(t)
		raw, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
		add := strings.Replace(string(raw), `"parts": [`, `"parts": [{"kind":"recordset","name":"x","hash":"abc","size":1},`, 1)
		os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(add), 0o600)
		if _, err := LoadSplit(dir); err != nil {
			t.Errorf("a part kind of a newer version must not stop the load: %v", err)
		}
	})
}

func TestPartPath_RejectsUnsafeNames(t *testing.T) {
	for _, tt := range []struct{ kind, name string }{
		{PartScope, "../x"}, {PartScope, "a/b"}, {PartScope, ""}, {PartDomain, "../../etc"}, {PartDomain, "a/b.lan"}, {PartDomain, ".lan"}, {"nope", "x"},
	} {
		if _, err := PartPath(tt.kind, tt.name); err == nil {
			t.Errorf("PartPath(%q, %q) must fail", tt.kind, tt.name)
		}
	}
}
