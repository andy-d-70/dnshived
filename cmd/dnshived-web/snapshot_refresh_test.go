// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFetchClusterSnapshot_ActiveUIServesWarmCopyWithoutWaiting(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Write([]byte(`{"self":{"status":{"role":"core-1"}}}`))
	}))
	defer srv.Close()
	entry := NodeConfig{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}
	t.Cleanup(func() {
		lastUIActivity.Store(0)
		clusterSnapshotCacheMu.Lock()
		clusterSnapshotCacheAddr = ""
		clusterSnapshotCacheMu.Unlock()
	})

	if _, ok := fetchClusterSnapshotFresh(entry); !ok {
		t.Fatal("seed fetch failed")
	}
	age := func(d time.Duration) {
		clusterSnapshotCacheMu.Lock()
		clusterSnapshotCacheAt = time.Now().Add(-d)
		clusterSnapshotCacheMu.Unlock()
	}

	noteUIActivity()
	age(5 * time.Second)
	fetchClusterSnapshot(entry)
	if hits != 1 {
		t.Errorf("active UI: a 5 s old snapshot triggered a synchronous fetch (hits=%d)", hits)
	}

	lastUIActivity.Store(0)
	age(5 * time.Second)
	fetchClusterSnapshot(entry)
	if hits != 2 {
		t.Errorf("idle UI: a 5 s old snapshot was served instead of refetched (hits=%d)", hits)
	}
}
