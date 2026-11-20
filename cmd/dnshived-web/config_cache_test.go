// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"dnshived/internal/config"
)

type stampDaemon struct {
	stamp   atomic.Value
	cfg     atomic.Value
	fetches atomic.Int64
	stamps  atomic.Int64
	srv     *httptest.Server
}

func newStampDaemon(t *testing.T, stamp string, c config.Cluster) (*stampDaemon, NodeConfig) {
	t.Helper()
	d := &stampDaemon{}
	d.stamp.Store(stamp)
	d.cfg.Store(c)
	d.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/config/stamp":
			d.stamps.Add(1)
			json.NewEncoder(w).Encode(map[string]string{"config_stamp": d.stamp.Load().(string), "candidate_stamp": ""})
		case "/api/v1/config":
			d.fetches.Add(1)
			json.NewEncoder(w).Encode(d.cfg.Load().(config.Cluster))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(d.srv.Close)
	return d, NodeConfig{Name: "core-1", Addr: strings.TrimPrefix(d.srv.URL, "http://")}
}

func TestFetchConfig_DecodesAgainOnlyWhenTheStampMoved(t *testing.T) {
	c := validCluster()
	c.LocalDomains = []config.LocalDomain{{Name: "a.lan", Records: []config.LocalDomainHost{{Host: "h", Type: "A", Value: "10.0.0.1"}}}}
	d, node := newStampDaemon(t, "s1", c)

	for i := 0; i < 4; i++ {
		got, err := fetchConfig(node)
		if err != nil || len(got.LocalDomains) != 1 {
			t.Fatalf("%v %+v", err, got.LocalDomains)
		}
	}
	if d.fetches.Load() != 1 || d.stamps.Load() != 4 {
		t.Fatalf("config fetches %d (want 1), stamp fetches %d (want 4)", d.fetches.Load(), d.stamps.Load())
	}

	c2 := c
	c2.LogLevel = "debug"
	d.cfg.Store(c2)
	d.stamp.Store("s2")
	got, _ := fetchConfig(node)
	if got.LogLevel != "debug" || d.fetches.Load() != 2 {
		t.Fatalf("a moved stamp must fetch again: level %q, fetches %d", got.LogLevel, d.fetches.Load())
	}
}

func TestFetchConfig_EveryCallerGetsItsOwnCopy(t *testing.T) {
	c := validCluster()
	c.LocalDomains = []config.LocalDomain{{Name: "a.lan", Records: []config.LocalDomainHost{{Host: "h", Type: "A", Value: "10.0.0.1"}}}}
	c.Scopes = map[string]config.ScopeConfig{"office": {Parent: "eth1", VLANID: 10, VIP: "192.0.2.10/24"}}
	_, node := newStampDaemon(t, "s1", c)

	a, _ := fetchConfig(node)
	a.LocalDomains[0].Records[0].Value = "tampered"
	a.LocalDomains[0].Name = "tampered"
	delete(a.Scopes, "office")
	a.Scopes["extra"] = config.ScopeConfig{}

	b, err := fetchConfig(node)
	if err != nil {
		t.Fatal(err)
	}
	if b.LocalDomains[0].Records[0].Value != "10.0.0.1" || b.LocalDomains[0].Name != "a.lan" {
		t.Error("a caller's change leaked into the cache through a slice")
	}
	if _, ok := b.Scopes["office"]; !ok || len(b.Scopes) != 1 {
		t.Errorf("a caller's change leaked into the cache through the scope map: %v", b.Scopes)
	}
}

func TestFetchConfig_WithoutAStampNothingIsCached(t *testing.T) {
	var fetches atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/config" {
			fetches.Add(1)
			json.NewEncoder(w).Encode(validCluster())
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	node := NodeConfig{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}
	for i := 0; i < 3; i++ {
		if _, err := fetchConfig(node); err != nil {
			t.Fatal(err)
		}
	}
	if fetches.Load() != 3 {
		t.Errorf("an older daemon has no stamp endpoint, every call must fetch: %d", fetches.Load())
	}
}

func TestFetchCandidateResponse_CachedByItsStampAndCopiedPerCaller(t *testing.T) {
	var fetches atomic.Int64
	stamp := atomic.Value{}
	stamp.Store("c1")
	cand := validCluster()
	cand.LogLevel = "debug"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/config/stamp":
			json.NewEncoder(w).Encode(map[string]string{"config_stamp": "s", "candidate_stamp": stamp.Load().(string)})
		case "/api/v1/candidate":
			fetches.Add(1)
			json.NewEncoder(w).Encode(candidateResponse{Exists: true, Candidate: cand, Authors: map[string]string{"log_level": "alice"}})
		}
	}))
	defer srv.Close()
	node := NodeConfig{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}

	a, err := fetchCandidateResponse(node)
	if err != nil || !a.Exists || a.Authors["log_level"] != "alice" {
		t.Fatalf("%v %+v", err, a.Authors)
	}
	a.Authors["log_level"] = "tampered"
	a.Candidate.LogLevel = "tampered"
	b, _ := fetchCandidateResponse(node)
	if fetches.Load() != 1 {
		t.Errorf("an unchanged candidate must be decoded once, got %d fetches", fetches.Load())
	}
	if b.Authors["log_level"] != "alice" || b.Candidate.LogLevel != "debug" {
		t.Error("a caller's change leaked into the cache")
	}
	stamp.Store("c2")
	fetchCandidateResponse(node)
	if fetches.Load() != 2 {
		t.Errorf("a moved stamp fetches again: %d", fetches.Load())
	}
}

func TestFetchConfig_CacheStaysWithinItsMemoryBudget(t *testing.T) {
	configCaches.Range(func(k, _ any) bool { configCaches.Delete(k); return true })
	cacheBytes.Store(0)
	oldBudget := cacheBudget
	defer func() {
		cacheBudget = oldBudget
		configCaches.Range(func(k, _ any) bool { configCaches.Delete(k); return true })
		cacheBytes.Store(0)
	}()

	c := validCluster()
	raw, _ := json.Marshal(c)
	cacheBudget = int64(len(raw)) + int64(len(raw))/2

	a, nodeA := newStampDaemon(t, "s1", c)
	b, nodeB := newStampDaemon(t, "s1", c)
	for i := 0; i < 3; i++ {
		if _, err := fetchConfig(nodeA); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		if _, err := fetchConfig(nodeB); err != nil {
			t.Fatal(err)
		}
	}
	if a.fetches.Load() != 1 {
		t.Errorf("the first document fits the budget and is fetched once, got %d", a.fetches.Load())
	}
	if b.fetches.Load() != 3 {
		t.Errorf("the second does not fit and is fetched every time, got %d", b.fetches.Load())
	}
	if got := cacheBytes.Load(); got > cacheBudget || got <= 0 {
		t.Errorf("cached bytes %d must be within the budget %d", got, cacheBudget)
	}
	a.stamp.Store("s2")
	fetchConfig(nodeA)
	if got := cacheBytes.Load(); got > cacheBudget || got <= 0 {
		t.Errorf("replacing an entry must not leak the budget: %d", got)
	}
}
