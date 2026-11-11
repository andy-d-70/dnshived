// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dnshived/internal/config"
)

const cacheTestCluster = `{
  "cluster_id": "c1", "node_id": "n1", "role": "core-1", "control_addr": "192.0.2.1:9443",
  "dry_run": true, "future_key": {"a": [1, 2]},
  "psk": "0123456789abcdef0123456789abcdef",
  "platform": {"mgmt": "eth0", "workers": ["eth1"]},
  "scopes": {
    "office": {"parent": "eth1", "vlan_id": 10, "vrrp_id": 10, "preferred_worker": "core-1",
      "vip": "192.0.2.10/24", "dhcp_range": ["192.0.2.50", "192.0.2.90"], "gateway": "192.0.2.1", "scope_future": 7}
  }
}`

func writeFileAtomic(t testing.TB, path, body string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func TestResponseCache(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.json")
	writeFileAtomic(t, path, "one")
	var c responseCache
	builds := 0
	build := func() ([]byte, error) { builds++; b, _ := os.ReadFile(path); return b, nil }
	now := time.Now()

	for i := 0; i < 5; i++ {
		if b, err := c.get(path, time.Minute, now, build); err != nil || string(b) != "one" {
			t.Fatalf("get = %q, %v", b, err)
		}
	}
	if builds != 1 {
		t.Errorf("an unchanged file must be built once, built %d times", builds)
	}

	writeFileAtomic(t, path, "two!") // replaced by rename: new inode
	if b, _ := c.get(path, time.Minute, now, build); string(b) != "two!" || builds != 2 {
		t.Errorf("a renamed-in file must rebuild, got %q after %d builds", b, builds)
	}

	if err := os.WriteFile(path, []byte("three three"), 0o600); err != nil { // in place: size changes
		t.Fatal(err)
	}
	if b, _ := c.get(path, time.Minute, now, build); string(b) != "three three" || builds != 3 {
		t.Errorf("a write in place must rebuild, got %q after %d builds", b, builds)
	}

	if _, _ = c.get(path, time.Minute, now.Add(2*time.Minute), build); builds != 4 {
		t.Errorf("an entry older than maxAge must rebuild, builds = %d", builds)
	}

	if _, err := c.get(path, time.Minute, now.Add(2*time.Minute), func() ([]byte, error) { return nil, fmt.Errorf("boom") }); err != nil {
		t.Errorf("a fresh entry is served without building: %v", err)
	}
	os.Remove(path)
	if _, err := c.get(path, time.Minute, now, func() ([]byte, error) { return nil, fmt.Errorf("gone") }); err == nil {
		t.Error("a missing file must build, and its error must come through")
	}
	writeFileAtomic(t, path, "back")
	if b, err := c.get(path, time.Minute, now, build); err != nil || string(b) != "back" {
		t.Errorf("after a failure the next call must build again, got %q %v", b, err)
	}
}

func TestResponseCache_NeverCachesAMissingFileOrAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent")
	var c responseCache
	builds := 0
	for i := 0; i < 3; i++ {
		c.get(path, time.Minute, time.Now(), func() ([]byte, error) { builds++; return []byte("x"), nil })
	}
	if builds != 3 {
		t.Errorf("without a file every call builds (stat fails), built %d times", builds)
	}
}

func TestResponseCache_BurstBuildsOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.json")
	writeFileAtomic(t, path, "x")
	var c responseCache
	var builds atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.get(path, time.Minute, time.Now(), func() ([]byte, error) {
				builds.Add(1)
				time.Sleep(20 * time.Millisecond)
				return []byte("x"), nil
			})
		}()
	}
	wg.Wait()
	if builds.Load() != 1 {
		t.Errorf("a burst of 64 readers built %d times, want 1", builds.Load())
	}
}

// oldConfigGet is what the handler did before the cache.
func oldConfigGet(path string) (int, string, []byte) {
	rec := httptest.NewRecorder()
	current, err := config.Load(path)
	if err != nil {
		writeJSON(rec, http.StatusInternalServerError, map[string]string{"error": "load current config: " + err.Error()})
	} else {
		writeJSON(rec, http.StatusOK, current)
	}
	return rec.Code, rec.Header().Get("Content-Type"), rec.Body.Bytes()
}

func TestConfigGetHandler_SameBytesAsBefore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cluster.json")
	writeFileAtomic(t, path, cacheTestCluster)
	var cache responseCache
	h := configGetHandler(func() string { return path }, &cache)
	get := func() (int, string, []byte) {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, "/api/v1/config", nil))
		return rec.Code, rec.Header().Get("Content-Type"), rec.Body.Bytes()
	}
	wantCode, wantType, wantBody := oldConfigGet(path)
	for i := 0; i < 3; i++ {
		code, ctype, body := get()
		if code != wantCode || ctype != wantType || !bytes.Equal(body, wantBody) {
			t.Fatalf("call %d differs from the old handler: %d %q vs %d %q\n%s\n---\n%s", i, code, ctype, wantCode, wantType, body, wantBody)
		}
	}
	if !strings.Contains(string(wantBody), `"future_key"`) || !strings.Contains(string(wantBody), `"scope_future"`) {
		t.Error("the answer must carry the unknown keys, as before")
	}
	if strings.Contains(string(wantBody), "dry_run") {
		t.Error("dry_run is dropped on purpose")
	}

	writeFileAtomic(t, path, strings.Replace(cacheTestCluster, `"vlan_id": 10`, `"vlan_id": 11`, 1))
	_, _, wantBody2 := oldConfigGet(path)
	if _, _, body := get(); !bytes.Equal(body, wantBody2) || bytes.Equal(body, wantBody) {
		t.Error("after a commit the next read must show the new document")
	}

	writeFileAtomic(t, path, `{"cluster_id": 5}`)
	if code, _, body := get(); code != http.StatusInternalServerError || !strings.Contains(string(body), "load current config") {
		t.Errorf("a broken file must answer 500, got %d %s", code, body)
	}
	os.Remove(path)
	if code, _, _ := get(); code != http.StatusInternalServerError {
		t.Errorf("a missing file must answer 500, got %d", code)
	}
}

func TestCandidateGetHandler(t *testing.T) {
	dir := t.TempDir()
	var cache responseCache
	h := candidateGetHandler(func() string { return dir }, &cache)
	get := func() string {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, "/api/v1/candidate", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
		return rec.Body.String()
	}
	if got := get(); got != "{\"candidate\":null,\"exists\":false}\n" {
		t.Errorf("without a candidate: %q", got)
	}
	writeFileAtomic(t, candidatePath(dir), cacheTestCluster)
	cand, exists, err := loadCandidateConfig(dir)
	if err != nil || !exists {
		t.Fatal(err)
	}
	want, _ := encodeJSON(map[string]interface{}{"exists": exists, "candidate": cand})
	for i := 0; i < 3; i++ {
		if got := get(); got != string(want) {
			t.Fatalf("with a candidate (call %d): %s", i, got)
		}
	}
	os.Remove(candidatePath(dir))
	if got := get(); got != "{\"candidate\":null,\"exists\":false}\n" {
		t.Errorf("after the candidate is discarded: %q", got)
	}
}

func BenchmarkConfigGet102Scopes(b *testing.B) {
	var doc strings.Builder
	doc.WriteString(`{"cluster_id":"c1","node_id":"n1","role":"core-1","control_addr":"192.0.2.1:9443","psk":"0123456789abcdef0123456789abcdef","platform":{"mgmt":"eth0","workers":["eth1"]},"scopes":{`)
	for i := 0; i < 102; i++ {
		if i > 0 {
			doc.WriteString(",")
		}
		fmt.Fprintf(&doc, `"dante-%03d":{"parent":"eth1","vlan_id":%d,"vrrp_id":%d,"preferred_worker":"core-%d","vip":"10.%d.%d.1/24","dhcp_range":["10.%d.%d.50","10.%d.%d.200"],"gateway":"10.%d.%d.1","upstream":["1.1.1.1","9.9.9.9"],"reservations":[{"mac":"aa:bb:cc:00:%02x:01","ip":"10.%d.%d.10","hostname":"printer-%d"},{"mac":"aa:bb:cc:00:%02x:02","ip":"10.%d.%d.11","hostname":"camera-%d"}]}`,
			i, 100+i, 1+i, 1+i%3, 100+i/250, i%250, 100+i/250, i%250, 100+i/250, i%250, 100+i/250, i%250, i, 100+i/250, i%250, i, i, 100+i/250, i%250, i)
	}
	doc.WriteString("}}")
	path := filepath.Join(b.TempDir(), "cluster.json")
	writeFileAtomic(b, path, doc.String())
	if code, _, _ := oldConfigGet(path); code != http.StatusOK {
		b.Fatal("the benchmark document must load")
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	b.Run("read and parse every time (before)", func(b *testing.B) {
		for b.Loop() {
			oldConfigGet(path)
		}
	})
	b.Run("cached by file stamp (after)", func(b *testing.B) {
		var cache responseCache
		h := configGetHandler(func() string { return path }, &cache)
		for b.Loop() {
			rec := httptest.NewRecorder()
			h(rec, req)
		}
	})
}

func TestConfigStampHandler(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	writeFileAtomic(t, path, cacheTestCluster)
	h := configStampHandler(func() string { return path }, func() string { return dir })
	get := func() map[string]string {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, "/api/v1/config/stamp", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		out := map[string]string{}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	a := get()
	if a["config_stamp"] == "" || a["candidate_stamp"] != "" {
		t.Fatalf("config present, no candidate: %v", a)
	}
	if b := get(); b["config_stamp"] != a["config_stamp"] {
		t.Error("an unchanged file keeps its stamp")
	}
	writeFileAtomic(t, path, cacheTestCluster+" ")
	if c := get(); c["config_stamp"] == a["config_stamp"] {
		t.Error("a replaced file must change the stamp")
	}
	writeFileAtomic(t, candidatePath(dir), cacheTestCluster)
	d := get()
	if d["candidate_stamp"] == "" {
		t.Error("a staged candidate must show a stamp")
	}
	os.Remove(candidatePath(dir))
	if e := get(); e["candidate_stamp"] != "" {
		t.Error("a discarded candidate must have an empty stamp")
	}
	if strings.ContainsAny(a["config_stamp"], " \"\n") {
		t.Errorf("the stamp must be a plain token: %q", a["config_stamp"])
	}
}
