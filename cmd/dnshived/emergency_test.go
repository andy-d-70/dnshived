// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dnshived/internal/config"
)

// fakeHelperResponse controls how the fake helper socket in these tests
// responds to every request: succeed, error, or hang until closed.
type fakeHelperResponse int

const (
	fakeHelperOK fakeHelperResponse = iota
	fakeHelperError
	fakeHelperHang
)

// startFakeHelper listens on a Unix socket at a temp path, decoding one
// JSON request per connection and responding per behavior.
func startFakeHelper(t *testing.T, behavior fakeHelperResponse, perRequestDelay time.Duration) (sockPath string, received *int64, stop func()) {
	t.Helper()
	dir := t.TempDir()
	sockPath = filepath.Join(dir, "helper.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var count int64
	quit := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				var req map[string]interface{}
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					return
				}
				atomic.AddInt64(&count, 1)
				if perRequestDelay > 0 {
					time.Sleep(perRequestDelay)
				}
				switch behavior {
				case fakeHelperOK:
					json.NewEncoder(conn).Encode(map[string]interface{}{"ok": true})
				case fakeHelperError:
					json.NewEncoder(conn).Encode(map[string]interface{}{"ok": false, "error": "simulated failure"})
				case fakeHelperHang:
					<-quit // never responds until the test tears down
				}
			}()
		}
	}()

	return sockPath, &count, func() {
		close(quit)
		ln.Close()
		wg.Wait()
	}
}

func testScopes(n int) map[string]config.ScopeConfig {
	scopes := make(map[string]config.ScopeConfig, n)
	for i := 0; i < n; i++ {
		name := string(rune('a' + i))
		scopes[name] = config.ScopeConfig{
			Parent: "dnshivedtest0", VLANID: 100 + i, VIP: "192.168.100.1/24",
			VRRPID: 51 + i, PreferredWorker: config.RoleCore1,
		}
	}
	return scopes
}

// TestEmergencyCloseAllGates_AllScopesAttempted verifies every configured
// scope gets a close attempt, not just the first.
func TestEmergencyCloseAllGates_AllScopesAttempted(t *testing.T) {
	sock, received, stop := startFakeHelper(t, fakeHelperOK, 0)
	defer stop()

	cfg := &config.Cluster{HelperSocket: sock, Scopes: testScopes(5)}
	code := emergencyCloseAllGates(cfg)
	if code != 0 {
		t.Errorf("exit code = %d, want 0 (must never block/delay the stop sequence)", code)
	}
	if got := atomic.LoadInt64(received); got != 5 {
		t.Errorf("helper received %d requests, want 5 — every configured scope must be attempted", got)
	}
}
