// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// resetClusterSnapshotCache clears the shared cache before a test that
// depends on its exact state.
func resetClusterSnapshotCache() {
	clusterSnapshotCacheMu.Lock()
	clusterSnapshotCacheAddr = ""
	clusterSnapshotCacheAt = time.Time{}
	clusterSnapshotCacheResp = clusterSnapshotResponse{}
	clusterSnapshotCacheOK = false
	clusterSnapshotCacheMu.Unlock()
}

func newCountingSnapshotServer(t *testing.T, snapshotBody string, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/config":
			fmt.Fprintf(w, `{"role":"core-1","control_addr":%q}`, srv.Listener.Addr().String())
		case "/api/v1/cluster/snapshot":
			hits.Add(1)
			fmt.Fprint(w, snapshotBody)
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchClusterSnapshot_SurvivesSlowResponseBeyondPlainHTTPClientTimeout(t *testing.T) {
	resetClusterSnapshotCache()
	var hits atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/config":
			fmt.Fprintf(w, `{"role":"core-1","control_addr":%q}`, srv.Listener.Addr().String())
		case "/api/v1/cluster/snapshot":
			hits.Add(1)
			time.Sleep(6 * time.Second) // beyond httpClient's own 5s, within clusterSnapshotHTTPClient's 10s
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"self":{"status":{"role":"core-1"}}}`)
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	entry := NodeConfig{Addr: srv.Listener.Addr().String(), TLS: true}
	_, ok := fetchClusterSnapshot(entry)
	if !ok {
		t.Fatal("fetchClusterSnapshot() ok = false, want true — a 6s server response must not be treated as a failure")
	}
	if hits.Load() != 1 {
		t.Errorf("server hit count = %d, want exactly 1", hits.Load())
	}
}

func TestFetchClusterSnapshot_CachesRepeatedCallsWithinTTL(t *testing.T) {
	resetClusterSnapshotCache()
	var hits atomic.Int32
	srv := newCountingSnapshotServer(t, `{"self":{"status":{"role":"core-1","state":"STABLE"}}}`, &hits)
	entry := NodeConfig{Name: "core-1", Addr: srv.Listener.Addr().String(), TLS: true, AdminToken: "tok"}

	for i := 0; i < 4; i++ {
		resp, ok := fetchClusterSnapshot(entry)
		if !ok {
			t.Fatalf("call %d: fetchClusterSnapshot ok = false, want true", i)
		}
		if len(resp.Self.Status) == 0 {
			t.Fatalf("call %d: resp.Self.Status empty, want the cached/fetched status", i)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("real /cluster/snapshot requests = %d, want exactly 1 (the other 3 calls should have hit the cache)", got)
	}
}

func TestFetchClusterSnapshot_RefetchesAfterTTLExpires(t *testing.T) {
	resetClusterSnapshotCache()
	var hits atomic.Int32
	srv := newCountingSnapshotServer(t, `{"self":{"status":{"role":"core-1","state":"STABLE"}}}`, &hits)
	entry := NodeConfig{Name: "core-1", Addr: srv.Listener.Addr().String(), TLS: true, AdminToken: "tok"}

	if _, ok := fetchClusterSnapshot(entry); !ok {
		t.Fatal("first fetchClusterSnapshot ok = false, want true")
	}
	// Force the cached entry to look old, rather than sleeping past the
	// real TTL in a test — keeps this fast and deterministic.
	clusterSnapshotCacheMu.Lock()
	clusterSnapshotCacheAt = time.Now().Add(-clusterSnapshotCacheTTL - time.Second)
	clusterSnapshotCacheMu.Unlock()

	if _, ok := fetchClusterSnapshot(entry); !ok {
		t.Fatal("second fetchClusterSnapshot ok = false, want true")
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("real /cluster/snapshot requests = %d, want 2 (the second call must re-fetch once the cache entry is stale)", got)
	}
}

// TestFetchClusterSnapshot_DifferentAddrBypassesStaleCache guards against
// a stale entry for a DIFFERENT address ever being served.
func TestFetchClusterSnapshot_DifferentAddrBypassesStaleCache(t *testing.T) {
	resetClusterSnapshotCache()
	var hitsA, hitsB atomic.Int32
	srvA := newCountingSnapshotServer(t, `{"self":{"status":{"role":"core-1","state":"STABLE"}}}`, &hitsA)
	srvB := newCountingSnapshotServer(t, `{"self":{"status":{"role":"core-2","state":"STABLE"}}}`, &hitsB)

	if _, ok := fetchClusterSnapshot(NodeConfig{Addr: srvA.Listener.Addr().String(), TLS: true}); !ok {
		t.Fatal("fetchClusterSnapshot(A) ok = false, want true")
	}
	if _, ok := fetchClusterSnapshot(NodeConfig{Addr: srvB.Listener.Addr().String(), TLS: true}); !ok {
		t.Fatal("fetchClusterSnapshot(B) ok = false, want true")
	}
	if hitsA.Load() != 1 || hitsB.Load() != 1 {
		t.Fatalf("hitsA=%d hitsB=%d, want exactly one real request to each distinct address", hitsA.Load(), hitsB.Load())
	}
}
