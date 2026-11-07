// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"dnshived/internal/repldoc"
)

func probeDocFixture(t *testing.T, self string, hosts ...NodeConfig) (*probeHostsDoc, *configRef) {
	t.Helper()
	cfg := &WebConfig{
		ListenAddr: "127.0.0.1:8443",
		UsersFile:  filepath.Join(t.TempDir(), "users.json"),
		Nodes:      []NodeConfig{{Name: "core-9", Addr: "192.0.2.9:9443", AdminToken: "shared-secret"}},
		ProbeHosts: hosts,
	}
	ref := newConfigRef(cfg)
	path := filepath.Join(t.TempDir(), "web.json")
	return newProbeHostsDoc(ref, path, func() string { return self }), ref
}

func wireOf(version int64, stamp, origin string, hosts ...NodeConfig) []byte {
	if hosts == nil {
		hosts = []NodeConfig{}
	}
	data, _ := json.Marshal(probeHostsWire{Meta: repldoc.Meta{Version: version, UpdatedAt: stamp, Origin: origin}, ProbeHosts: hosts})
	return data
}

func hostAddrs(ref *configRef) []string {
	var out []string
	for _, h := range ref.Load().ProbeHosts {
		out = append(out, h.Addr)
	}
	return out
}

func TestProbeHostsHash_IgnoresOrder(t *testing.T) {
	a := []NodeConfig{{Addr: "192.0.2.1:9444"}, {Addr: "192.0.2.2:9444"}}
	b := []NodeConfig{{Addr: "192.0.2.2:9444"}, {Addr: "192.0.2.1:9444"}}
	if probeHostsHash(a) != probeHostsHash(b) {
		t.Error("the hash depends on the order")
	}
	c := []NodeConfig{{Addr: "192.0.2.1:9444"}, {Addr: "192.0.2.2:9444", DisplayName: "x"}}
	if probeHostsHash(a) == probeHostsHash(c) {
		t.Error("a changed field did not change the hash")
	}
}

func TestValidateProbeHosts(t *testing.T) {
	many := make([]NodeConfig, maxReplProbeHosts+1)
	for i := range many {
		many[i] = NodeConfig{Addr: "192.0.2.1:" + strings.Repeat("1", 1) + string(rune('a'+i%26)) + string(rune('a'+i/26%26))}
	}
	tests := []struct {
		name  string
		hosts []NodeConfig
		ok    bool
	}{
		{"empty list", nil, true},
		{"one host", []NodeConfig{{Addr: "192.0.2.1:9444", Name: "probe"}}, true},
		{"empty address", []NodeConfig{{Addr: ""}}, false},
		{"duplicate address", []NodeConfig{{Addr: "a:1"}, {Addr: "a:1"}}, false},
		{"oversized address", []NodeConfig{{Addr: strings.Repeat("a", 256)}}, false},
		{"oversized token", []NodeConfig{{Addr: "a:1", AdminToken: strings.Repeat("t", maxReplHostField+1)}}, false},
		{"bad tls port", []NodeConfig{{Addr: "a:1", TLSPort: "70000"}}, false},
		{"non numeric tls port", []NodeConfig{{Addr: "a:1", TLSPort: "https"}}, false},
		{"valid tls port", []NodeConfig{{Addr: "a:1", TLSPort: "9445"}}, true},
		{"too many", many, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProbeHosts(tt.hosts)
			if (err == nil) != tt.ok {
				t.Errorf("err = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestProbeHostsAdopt_NewerReplacesAndDeletionsPropagate(t *testing.T) {
	d, ref := probeDocFixture(t, "core-1", NodeConfig{Addr: "a:1"}, NodeConfig{Addr: "b:1"})
	if err := d.StartFirst("core-1"); err != nil {
		t.Fatal(err)
	}
	adopted, spread, err := d.Adopt(wireOf(5, "2026-11-07T10:00:00Z", "core-2", NodeConfig{Addr: "a:1"}), "core-2")
	if err != nil || !adopted || spread {
		t.Fatalf("adopted=%v spread=%v err=%v", adopted, spread, err)
	}
	if got := hostAddrs(ref); len(got) != 1 || got[0] != "a:1" {
		t.Errorf("the removal of b:1 did not propagate: %v", got)
	}
	cfg := ref.Load()
	if cfg.ProbeHostsVersion != 5 || cfg.ProbeHostsOrigin != "core-2" || cfg.ProbeHostsHash != probeHostsHash(cfg.ProbeHosts) {
		t.Errorf("stamp = %d %q %q", cfg.ProbeHostsVersion, cfg.ProbeHostsOrigin, cfg.ProbeHostsHash)
	}
	disk, err := loadWebConfig2(d.cfgPath)
	if err != nil || disk.ProbeHostsVersion != 5 || len(disk.ProbeHosts) != 1 {
		t.Errorf("not saved: %+v %v", disk, err)
	}
}

// loadWebConfig2 reads web.json without the validation loadWebConfig applies.
func loadWebConfig2(path string) (*WebConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c WebConfig
	return &c, json.Unmarshal(data, &c)
}

func TestProbeHostsAdopt_OlderIgnored(t *testing.T) {
	d, ref := probeDocFixture(t, "core-1", NodeConfig{Addr: "a:1"})
	d.Adopt(wireOf(5, "t5", "core-2", NodeConfig{Addr: "a:1"}, NodeConfig{Addr: "b:1"}), "core-2")
	adopted, _, err := d.Adopt(wireOf(3, "t3", "core-3"), "core-3")
	if err != nil || adopted {
		t.Fatalf("adopted=%v err=%v", adopted, err)
	}
	if got := hostAddrs(ref); len(got) != 2 {
		t.Errorf("an older document replaced a newer one: %v", got)
	}
}

func TestProbeHostsAdopt_FirstJoinMergesByAddress(t *testing.T) {
	d, ref := probeDocFixture(t, "core-2", NodeConfig{Addr: "a:1"}, NodeConfig{Addr: "local-only:1"})
	adopted, spread, err := d.Adopt(wireOf(1, "2026-11-07T10:00:00Z", "core-1", NodeConfig{Addr: "a:1"}, NodeConfig{Addr: "remote-only:1"}), "core-1")
	if err != nil || !adopted || !spread {
		t.Fatalf("adopted=%v spread=%v err=%v", adopted, spread, err)
	}
	got := map[string]bool{}
	for _, a := range hostAddrs(ref) {
		got[a] = true
	}
	if len(got) != 3 || !got["a:1"] || !got["local-only:1"] || !got["remote-only:1"] {
		t.Errorf("merged list = %v", hostAddrs(ref))
	}
	cfg := ref.Load()
	if cfg.ProbeHostsVersion != 2 || cfg.ProbeHostsOrigin != "core-2" {
		t.Errorf("the merged list must be a new revision from this instance, got %d %q", cfg.ProbeHostsVersion, cfg.ProbeHostsOrigin)
	}
}

func TestProbeHostsAdopt_FirstJoinWithNothingToKeepDoesNotSpread(t *testing.T) {
	d, ref := probeDocFixture(t, "core-2", NodeConfig{Addr: "a:1"})
	_, spread, err := d.Adopt(wireOf(1, "t1", "core-1", NodeConfig{Addr: "a:1"}), "core-1")
	if err != nil || spread {
		t.Fatalf("spread=%v err=%v", spread, err)
	}
	if ref.Load().ProbeHostsVersion != 1 {
		t.Errorf("version = %d", ref.Load().ProbeHostsVersion)
	}
}

func TestProbeHostsAdopt_InvalidIsRefusedAndNothingChanges(t *testing.T) {
	d, ref := probeDocFixture(t, "core-1", NodeConfig{Addr: "a:1"})
	for name, raw := range map[string][]byte{
		"not json":     []byte("{"),
		"empty addr":   wireOf(9, "t9", "core-2", NodeConfig{Addr: ""}),
		"duplicate":    wireOf(9, "t9", "core-2", NodeConfig{Addr: "x:1"}, NodeConfig{Addr: "x:1"}),
		"oversized":    wireOf(9, "t9", "core-2", NodeConfig{Addr: "x:1", Name: strings.Repeat("n", maxReplHostField+1)}),
		"bad tls port": wireOf(9, "t9", "core-2", NodeConfig{Addr: "x:1", TLSPort: "0"}),
		"no list":      []byte(`{"version":9,"updated_at":"t9","origin":"core-2"}`),
		"null list":    []byte(`{"version":9,"updated_at":"t9","origin":"core-2","probe_hosts":null}`),
		"huge version": wireOf(1<<60, "t9", "core-2", NodeConfig{Addr: "x:1"}),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := d.Adopt(raw, "core-2")
			if !isInvalidDoc(err) {
				t.Fatalf("err = %v, want an invalid-document error", err)
			}
			if ref.Load().ProbeHostsVersion != 0 || len(ref.Load().ProbeHosts) != 1 {
				t.Error("a refused document changed the list")
			}
		})
	}
}

func TestProbeHostsDrift(t *testing.T) {
	d, ref := probeDocFixture(t, "core-1", NodeConfig{Addr: "a:1"})
	if changed, err := d.Drift("core-1"); err != nil || changed {
		t.Fatalf("a never-replicated list must not be stamped: %v %v", changed, err)
	}
	if err := d.StartFirst("core-1"); err != nil {
		t.Fatal(err)
	}
	if changed, _ := d.Drift("core-1"); changed {
		t.Error("an unchanged list was stamped")
	}
	next := *ref.Load()
	next.ProbeHosts = append(append([]NodeConfig(nil), next.ProbeHosts...), NodeConfig{Addr: "b:1"})
	ref.Store(&next)
	changed, err := d.Drift("core-1")
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	cfg := ref.Load()
	if cfg.ProbeHostsVersion != 2 || cfg.ProbeHostsHash != probeHostsHash(cfg.ProbeHosts) {
		t.Errorf("stamp after drift: %d %q", cfg.ProbeHostsVersion, cfg.ProbeHostsHash)
	}
	if changed, _ := d.Drift("core-1"); changed {
		t.Error("the same change was stamped twice")
	}
}

func TestProbeHostsPublish_RefusesWhenAHandlerChangedTheConfig(t *testing.T) {
	d, ref := probeDocFixture(t, "core-1", NodeConfig{Addr: "a:1"})
	old := ref.Load()
	handlerCfg := *old
	handlerCfg.SelfDisplayName = "changed by a handler"
	ref.Store(&handlerCfg)
	next := *old
	next.ProbeHostsVersion = 7
	if err := d.publish(old, &next); err == nil {
		t.Fatal("publish overwrote a concurrent change")
	}
	if ref.Load().SelfDisplayName != "changed by a handler" {
		t.Error("the handler's change was lost")
	}
}

func TestProbeHostsEndpoints(t *testing.T) {
	d, ref := probeDocFixture(t, "core-1", NodeConfig{Addr: "a:1"})
	ref.Load().Nodes[0].AdminToken = "shared-secret"
	pushed := make(chan struct{}, 1)
	h := d.handlers(func() { pushed <- struct{}{} })
	call := func(fn http.HandlerFunc, method, token string, body []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/internal/docs/probe-hosts", strings.NewReader(string(body)))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		fn(w, r)
		return w
	}
	for _, fn := range []http.HandlerFunc{h.post, h.meta, h.get} {
		if w := call(fn, "POST", "", nil); w.Code != http.StatusUnauthorized {
			t.Errorf("no token = %d", w.Code)
		}
		if w := call(fn, "POST", "wrong", nil); w.Code != http.StatusUnauthorized {
			t.Errorf("wrong token = %d", w.Code)
		}
	}
	if w := call(h.post, "POST", "shared-secret", []byte("{")); w.Code != http.StatusBadRequest {
		t.Errorf("garbage = %d", w.Code)
	}
	if w := call(h.post, "POST", "shared-secret", wireOf(4, "t4", "core-2", NodeConfig{Addr: "a:1"}, NodeConfig{Addr: "n:1"})); w.Code != http.StatusOK {
		t.Fatalf("valid post = %d %s", w.Code, w.Body)
	}
	if got := hostAddrs(ref); len(got) != 2 {
		t.Errorf("list after post = %v", got)
	}
	var m repldoc.Meta
	w := call(h.meta, "GET", "shared-secret", nil)
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil || m.Version != 4 || m.Hash == "" {
		t.Errorf("meta = %+v %v", m, err)
	}
	w = call(h.get, "GET", "shared-secret", nil)
	var wire probeHostsWire
	if err := json.Unmarshal(w.Body.Bytes(), &wire); err != nil || len(wire.ProbeHosts) != 2 || w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("get = %s %v", w.Body, err)
	}
}

// TestProbeHostsSync_SiblingThatMissedAChangeCatchesUp is the case the
// document exists for: a probe host is removed on one instance while the
// other is down, and the other learns of it later.
func TestProbeHostsSync_SiblingThatMissedAChangeCatchesUp(t *testing.T) {
	a, aRef := probeDocFixture(t, "core-1", NodeConfig{Addr: "p1:9444"}, NodeConfig{Addr: "p2:9444"})
	b, bRef := probeDocFixture(t, "core-2", NodeConfig{Addr: "p1:9444"}, NodeConfig{Addr: "p2:9444"})
	if err := a.StartFirst("core-1"); err != nil {
		t.Fatal(err)
	}
	bridge := func(to *probeHostsDoc, down *atomic.Bool) func(repldoc.Peer, string, string, []byte) ([]byte, error) {
		return func(p repldoc.Peer, method, path string, body []byte) ([]byte, error) {
			if down.Load() {
				return nil, errors.New("down")
			}
			switch {
			case method == "GET" && strings.HasSuffix(path, "/meta"):
				return json.Marshal(to.Meta())
			case method == "GET":
				return to.Marshal()
			default:
				_, _, err := to.Adopt(body, "peer")
				return []byte("{}"), err
			}
		}
	}
	var bDown, aDown atomic.Bool
	sa := newProbeHostsSyncer(aRef, a, func() string { return "core-1" })
	sa.Peers = func() []repldoc.Peer { return []repldoc.Peer{{Name: "core-2"}} }
	sa.Do = bridge(b, &bDown)
	sb := newProbeHostsSyncer(bRef, b, func() string { return "core-2" })
	sb.Peers = func() []repldoc.Peer { return []repldoc.Peer{{Name: "core-1"}} }
	sb.Do = bridge(a, &aDown)

	sa.SyncOnce()
	sb.SyncOnce()
	if bRef.Load().ProbeHostsVersion != 1 {
		t.Fatalf("b did not join revision 1: %d", bRef.Load().ProbeHostsVersion)
	}

	bDown.Store(true)
	next := *aRef.Load()
	next.ProbeHosts = []NodeConfig{{Addr: "p1:9444"}}
	aRef.Store(&next)
	sa.SyncOnce()
	if aRef.Load().ProbeHostsVersion != 2 {
		t.Fatalf("a did not stamp its change: %d", aRef.Load().ProbeHostsVersion)
	}
	if len(bRef.Load().ProbeHosts) != 2 {
		t.Fatal("b changed while it was down")
	}

	bDown.Store(false)
	sb.SyncOnce()
	if got := hostAddrs(bRef); len(got) != 1 || got[0] != "p1:9444" {
		t.Errorf("b did not catch up: %v", got)
	}
}
