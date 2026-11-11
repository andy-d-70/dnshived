// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
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

func TestStampRevision(t *testing.T) {
	fixed := func() time.Time { return time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC) }
	tests := []struct {
		name       string
		start      int64
		rev        int64
		at, origin string
		wantRev    int64
		wantAt     string
		wantOrigin string
	}{
		{"no revision supplied counts up", 4, 0, "", "", 5, "2026-11-07T12:00:00Z", ""},
		{"supplied higher is used", 4, 9, "2026-11-07T10:00:00Z", "core-2", 9, "2026-11-07T10:00:00Z", "core-2"},
		{"supplied exactly next is used", 4, 5, "2026-11-07T10:00:00Z", "core-1", 5, "2026-11-07T10:00:00Z", "core-1"},
		{"supplied lower never goes down", 7, 3, "2026-01-01T00:00:00Z", "core-2", 8, "2026-11-07T12:00:00Z", "core-2"},
		{"supplied equal to current never repeats", 7, 7, "2026-01-01T00:00:00Z", "core-2", 8, "2026-11-07T12:00:00Z", "core-2"},
		{"huge supplied is ignored", 2, 1 << 60, "x", "core-2", 3, "2026-11-07T12:00:00Z", "core-2"},
		{"negative supplied is ignored", 2, -5, "x", "core-2", 3, "2026-11-07T12:00:00Z", "core-2"},
		{"supplied without a time gets one", 2, 6, "", "core-2", 6, "2026-11-07T12:00:00Z", "core-2"},
		{"oversized origin is dropped", 2, 0, "", strings.Repeat("o", 200), 3, "2026-11-07T12:00:00Z", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Cluster{ConfigRevision: tt.start}
			c.StampRevision(tt.rev, tt.at, tt.origin, fixed)
			if c.ConfigRevision != tt.wantRev || c.ConfigRevisionAt != tt.wantAt || c.ConfigRevisionOrigin != tt.wantOrigin {
				t.Errorf("got %d %q %q, want %d %q %q", c.ConfigRevision, c.ConfigRevisionAt, c.ConfigRevisionOrigin, tt.wantRev, tt.wantAt, tt.wantOrigin)
			}
		})
	}
}

func TestConfigRevisionIsNotPartOfTheDocumentHash(t *testing.T) {
	a := Cluster{ClusterID: "c1", LogLevel: "info"}
	b := a
	b.ConfigRevision, b.ConfigRevisionAt, b.ConfigRevisionOrigin = 9, "t", "core-2"
	if a.ConfigDocumentHash() != b.ConfigDocumentHash() {
		t.Error("the revision changed the content hash")
	}
}

func TestSave_DoesNotFollowAPlantedTempFileLink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, path+".tmp"); err != nil {
		t.Fatal(err)
	}
	c, err := Load(writeFixture(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(path, c); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if got, _ := os.ReadFile(victim); string(got) != "keep me" {
		t.Errorf("the file behind the planted link was overwritten: %q", got)
	}
	if _, err := Load(path); err != nil {
		t.Errorf("the saved config does not load: %v", err)
	}
	if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("cluster.json is not a regular file: %v %v", fi, err)
	}
}

func writeFixture(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "fixture.json")
	if err := os.WriteFile(p, []byte(extraFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// extrasOracle computes what the decoders must keep: the keys of the document
// and of each scope that the structs have no field for, found with the plain
// unknownKeys function, independent of the strict fast path.
func extrasOracle(data []byte) (map[string]json.RawMessage, map[string]map[string]json.RawMessage) {
	cluster := unknownKeys(data, reflect.TypeOf(Cluster{}))
	scopes := map[string]map[string]json.RawMessage{}
	var top map[string]json.RawMessage
	if json.Unmarshal(data, &top) != nil {
		return cluster, scopes
	}
	for k, v := range top {
		if !strings.EqualFold(k, "scopes") {
			continue
		}
		var raw map[string]json.RawMessage
		if json.Unmarshal(v, &raw) != nil {
			continue
		}
		for name, r := range raw {
			scopes[name] = unknownKeys(r, reflect.TypeOf(ScopeConfig{}))
		}
	}
	return cluster, scopes
}

func checkDecodeAgainstOracle(t testing.TB, data []byte) {
	t.Helper()
	var c Cluster
	if err := json.Unmarshal(data, &c); err != nil {
		return
	}
	wantCluster, wantScopes := extrasOracle(data)
	if !reflect.DeepEqual(c.Extra, wantCluster) {
		t.Fatalf("cluster extras = %v, oracle %v\ndocument: %s", c.Extra, wantCluster, data)
	}
	for name, sc := range c.Scopes {
		if want := wantScopes[name]; !reflect.DeepEqual(sc.Extra, want) {
			t.Fatalf("scope %q extras = %v, oracle %v\ndocument: %s", name, sc.Extra, want, data)
		}
	}
	var plain clusterPlain
	if err := json.Unmarshal(data, &plain); err != nil {
		t.Fatalf("plain decode failed where the real one passed: %v", err)
	}
	got, want := c, Cluster(plain)
	got.Extra, want.Extra = nil, nil
	strip := func(m map[string]ScopeConfig) map[string]ScopeConfig {
		out := make(map[string]ScopeConfig, len(m))
		for k, v := range m {
			v.Extra = nil
			out[k] = v
		}
		return out
	}
	if len(got.Scopes) > 0 {
		got.Scopes = strip(got.Scopes)
	}
	if len(want.Scopes) > 0 {
		want.Scopes = strip(want.Scopes)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("known fields differ from a plain decode\ndocument: %s", data)
	}
}

func TestDecodeKeepsExactlyTheUnknownKeys(t *testing.T) {
	docs := map[string]string{
		"fixture with dry_run and extras": extraFixture,
		"no unknown keys at all":          `{"cluster_id":"c","node_id":"n","role":"core-1","scopes":{"a":{"parent":"eth1","vlan_id":5}}}`,
		"upper case known keys":           `{"Cluster_ID":"c","NODE_ID":"n","Scopes":{"a":{"PARENT":"eth1","VLAN_ID":5,"VIP":"10.0.0.1/24"}}}`,
		"unknown only in a scope":         `{"cluster_id":"c","scopes":{"a":{"parent":"eth1","future_field":{"x":[1,2,{"y":null}]}},"b":{"parent":"eth1"}}}`,
		"unknown only at the top":         `{"cluster_id":"c","future":[1,2,3],"scopes":{"a":{"parent":"eth1"}}}`,
		"dry_run escaped":                 `{"cluster_id":"c","dry\u005frun":true,"scopes":{"a":{"dry_run":false,"parent":"eth1"}}}`,
		"null scope":                      `{"cluster_id":"c","scopes":{"a":null,"b":{"parent":"eth1","x":1}}}`,
		"empty scopes":                    `{"cluster_id":"c","scopes":{}}`,
		"unknown key with unicode":        `{"cluster_id":"c","größe":1,"scopes":{"ä":{"parent":"eth1","größe":2}}}`,
		"nested numbers and strings":      `{"cluster_id":"c","big":12345678901234567890,"s":"a\"b\\c","scopes":{"a":{"parent":"eth1","t":"ä"}}}`,
	}
	for name, doc := range docs {
		t.Run(name, func(t *testing.T) { checkDecodeAgainstOracle(t, []byte(doc)) })
	}
}

func TestDecodeErrorsStayErrors(t *testing.T) {
	for name, doc := range map[string]string{
		"wrong type for a known field":   `{"cluster_id":"c","scopes":{"a":{"vlan_id":"ten"}}}`,
		"wrong type next to unknown key": `{"cluster_id":"c","future":1,"scopes":{"a":{"vlan_id":"ten","x":1}}}`,
		"scopes is not an object":        `{"cluster_id":"c","scopes":[1]}`,
		"top level array":                `[1,2]`,
		"known key with the wrong type":  `{"cluster_id":5}`,
	} {
		t.Run(name, func(t *testing.T) {
			var c Cluster
			if err := json.Unmarshal([]byte(doc), &c); err == nil {
				t.Errorf("expected an error for %s", doc)
			}
		})
	}
}

func TestLoadSetsLegacyDryRunOnlyWhenTheKeyIsThere(t *testing.T) {
	dir := t.TempDir()
	write := func(extra string) string {
		cfg := validBase()
		doc, _ := json.Marshal(cfg)
		doc = append(doc[:len(doc)-1], []byte(extra+"}")...)
		p := filepath.Join(dir, "c.json")
		if err := os.WriteFile(p, doc, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, tt := range []struct {
		name, extra string
		want        bool
	}{
		{"absent", "", false},
		{"present", `,"dry_run":true`, true},
		{"escaped spelling", `,"dry\u005frun":false`, true},
		{"only in a value", `,"note":"dry_run is gone"`, false},
	} {
		c, err := Load(write(tt.extra))
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if c.LegacyDryRun != tt.want {
			t.Errorf("%s: LegacyDryRun = %v, want %v", tt.name, c.LegacyDryRun, tt.want)
		}
	}
}

func FuzzDecodeKeepsExactlyTheUnknownKeys(f *testing.F) {
	for _, s := range []string{
		extraFixture,
		`{"cluster_id":"c","scopes":{"a":{"parent":"eth1","future":1}}}`,
		`{"Cluster_ID":"c","dry_run":true,"scopes":{"a":null}}`,
		`{"scopes":{"a":{"VIP":"1.2.3.4/24","vip":"5.6.7.8/24","x":{}}}}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if !json.Valid(data) {
			return
		}
		checkDecodeAgainstOracle(t, data)
	})
}

// BenchmarkLoad102Scopes measures config.Load on a document of the size of a
// real cluster: 102 scopes, about 34 KB.
func BenchmarkLoad102Scopes(b *testing.B) {
	cfg := validBase()
	scopes := map[string]interface{}{}
	for i := 0; i < 102; i++ {
		scopes[fmt.Sprintf("dante-%03d", i)] = map[string]interface{}{
			"parent": "eth1", "vlan_id": 100 + i, "vrrp_id": 1 + i, "preferred_worker": []string{"core-1", "core-2", "core-3"}[i%3],
			"vip":        fmt.Sprintf("10.%d.%d.1/24", 100+i/250, i%250),
			"dhcp_range": []string{fmt.Sprintf("10.%d.%d.50", 100+i/250, i%250), fmt.Sprintf("10.%d.%d.200", 100+i/250, i%250)},
			"gateway":    fmt.Sprintf("10.%d.%d.1", 100+i/250, i%250),
			"upstream":   []string{"1.1.1.1", "9.9.9.9"},
			"reservations": []map[string]interface{}{
				{"mac": fmt.Sprintf("aa:bb:cc:00:%02x:01", i), "ip": fmt.Sprintf("10.%d.%d.10", 100+i/250, i%250), "hostname": fmt.Sprintf("printer-%d", i)},
				{"mac": fmt.Sprintf("aa:bb:cc:00:%02x:02", i), "ip": fmt.Sprintf("10.%d.%d.11", 100+i/250, i%250), "hostname": fmt.Sprintf("camera-%d", i)},
			},
		}
	}
	cfg["scopes"] = scopes
	data, err := json.Marshal(cfg)
	if err != nil {
		b.Fatal(err)
	}
	path := filepath.Join(b.TempDir(), "cluster.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		b.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		if _, err := Load(path); err != nil {
			b.Fatal(err)
		}
	}
}

func TestTopLevelKeys(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want []string
		ok   bool
	}{
		{"flat", `{"a":1,"b":"x","c":true,"d":null}`, []string{"a", "b", "c", "d"}, true},
		{"nested values are skipped", `{"a":{"b":[1,{"c":2}],"d":"}"},"e":[ "]", {"f":"\"{" } ]}`, []string{"a", "e"}, true},
		{"braces and quotes inside strings", `{"k":"a\"}{\\","m":"[["}`, []string{"k", "m"}, true},
		{"whitespace everywhere", " {\n\t\"a\" :\r\n 1 ,\n \"b\"\t: [ ] }\n", []string{"a", "b"}, true},
		{"empty object", `{}`, nil, true},
		{"empty object with spaces", ` { } `, nil, true},
		{"numbers and literals at the end", `{"a":-1.5e3,"b":false}`, []string{"a", "b"}, true},
		{"escaped key falls back", `{"dry\u005frun":true}`, nil, false},
		{"not an object", `[1,2]`, nil, false},
		{"trailing data", `{"a":1} x`, nil, false},
		{"truncated", `{"a":1,`, nil, false},
		{"missing colon", `{"a" 1}`, nil, false},
		{"unterminated string", `{"a":"x`, nil, false},
		{"empty input", ``, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, ok := topLevelKeys([]byte(tt.doc))
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v (keys %q)", ok, tt.ok, keys)
			}
			if !ok {
				return
			}
			var got []string
			for _, k := range keys {
				got = append(got, string(k))
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("keys = %v, want %v", got, tt.want)
			}
		})
	}
}

// On every valid object the scan finds exactly the keys encoding/json sees.
func FuzzTopLevelKeysMatchTheDecoder(f *testing.F) {
	for _, s := range []string{extraFixture, `{"a":{"b":1},"c":[{"d":"}"}]}`, `{}`, `{"a\"b":1}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if !json.Valid(data) || !utf8.Valid(data) {
			return
		}
		keys, ok := topLevelKeys(data)
		var m map[string]json.RawMessage
		if json.Unmarshal(data, &m) != nil {
			if ok {
				t.Fatalf("scan accepted a document that is not an object: %s", data)
			}
			return
		}
		if !ok {
			return
		}
		seen := map[string]bool{}
		for _, k := range keys {
			seen[string(k)] = true
		}
		if len(seen) != len(m) {
			t.Fatalf("scan found %d distinct keys, decoder %d, in %s", len(seen), len(m), data)
		}
		for k := range m {
			if !seen[k] {
				t.Fatalf("key %q missing from the scan of %s", k, data)
			}
		}
	})
}
