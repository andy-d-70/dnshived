// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcprelay

import (
	"net"
	"testing"
)

func TestResolveRateLimit_PerInterfaceOverrideWins(t *testing.T) {
	if got := resolveRateLimit(50, 100); got != 50 {
		t.Errorf("got %d, want 50 (per-interface override)", got)
	}
}

func TestResolveRateLimit_FallsBackToClusterWide(t *testing.T) {
	if got := resolveRateLimit(0, 100); got != 100 {
		t.Errorf("got %d, want 100 (cluster-wide)", got)
	}
}

func TestResolveRateLimit_FallsBackToPackageDefault(t *testing.T) {
	if got := resolveRateLimit(0, 0); got != defaultRateLimit {
		t.Errorf("got %d, want %d (package default)", got, defaultRateLimit)
	}
}

func TestResolveRateBurst_DerivesFromRateWhenUnset(t *testing.T) {
	if got := resolveRateBurst(0, 0, 50); got != 100 {
		t.Errorf("got %d, want 100 (2x resolved rate)", got)
	}
}

func TestResolveRateBurst_PerInterfaceOverrideWins(t *testing.T) {
	if got := resolveRateBurst(30, 0, 50); got != 30 {
		t.Errorf("got %d, want 30 (per-interface override)", got)
	}
}

func TestTokenBucket_AllowsBurstThenThrottles(t *testing.T) {
	tb := newTokenBucket(5)
	for i := 0; i < 5; i++ {
		if !tb.allow(1, 5) {
			t.Fatalf("request %d: expected allowed (within burst), got throttled", i)
		}
	}
	if tb.allow(1, 5) {
		t.Error("request 6: expected throttled (burst exhausted), got allowed")
	}
}

func TestHandleClientRequest_RateLimitedDropsWithoutForwarding(t *testing.T) {
	r, serverConn, ci := newTestRelay(t)
	ci.rateLimit.Store(1)
	ci.rateBurst.Store(2)
	ci.limiter = newTokenBucket(2)

	for i := uint32(1); i <= 5; i++ {
		req := buildTestPacket(bootpOpRequest, i, [6]byte{}, net.IPv4zero, net.IPv4zero, 0, true, true)
		r.handleClientRequest(ci, req, &net.UDPAddr{})
	}

	serverConn.mu.Lock()
	forwarded := len(serverConn.writes)
	serverConn.mu.Unlock()
	if forwarded != 2 {
		t.Errorf("forwarded %d requests, want exactly 2 (the configured burst)", forwarded)
	}
	if got := r.metrics.requestsRateLimited.Load(); got != 3 {
		t.Errorf("requestsRateLimited = %d, want 3 (5 sent - 2 allowed)", got)
	}
}

func TestHandleClientRequest_UnlimitedByDefaultAtTestScale(t *testing.T) {
	r, serverConn, ci := newTestRelay(t)
	for i := uint32(1); i <= 10; i++ {
		req := buildTestPacket(bootpOpRequest, i, [6]byte{}, net.IPv4zero, net.IPv4zero, 0, true, true)
		r.handleClientRequest(ci, req, &net.UDPAddr{})
	}
	if _, ok := serverConn.lastWrite(); !ok {
		t.Error("expected the 10th request to still be forwarded under the default 100/s, burst 200 limit")
	}
	if got := r.metrics.requestsRateLimited.Load(); got != 0 {
		t.Errorf("requestsRateLimited = %d, want 0 at this scale under the default limit", got)
	}
}

func TestReconfigure_RateLimitOnlyChangeUpdatesInPlace(t *testing.T) {
	r, _, ci := newTestRelay(t)
	original := ci

	newCfg := Config{
		ServerAddr: "127.0.0.21:67",
		ClientInterfaces: []ClientInterfaceConfig{
			{Name: "ens19.200", GIAddr: "192.168.200.22", RateLimit: 7, RateBurst: 14},
		},
	}
	if err := r.Reconfigure(newCfg); err != nil {
		t.Fatalf("Reconfigure: %v", err)
	}

	if len(r.clientIfaces) != 1 || r.clientIfaces[0] != original {
		t.Fatal("expected the SAME clientInterface object to survive a rate-limit-only change, got a different one (went through remove-then-add)")
	}
	if got := r.clientIfaces[0].rateLimit.Load(); got != 7 {
		t.Errorf("rateLimit = %d, want 7", got)
	}
	if got := r.clientIfaces[0].rateBurst.Load(); got != 14 {
		t.Errorf("rateBurst = %d, want 14", got)
	}
}

func TestReconfigure_ServerIdentifierOnlyChangeUpdatesInPlace(t *testing.T) {
	r, _, ci := newTestRelay(t)
	original := ci

	newCfg := Config{
		ServerAddr: "127.0.0.21:67",
		ClientInterfaces: []ClientInterfaceConfig{
			{Name: "ens19.200", GIAddr: "192.168.200.22", ServerIdentifier: "192.168.200.1"},
		},
	}
	if err := r.Reconfigure(newCfg); err != nil {
		t.Fatalf("Reconfigure: %v", err)
	}

	if len(r.clientIfaces) != 1 || r.clientIfaces[0] != original {
		t.Fatal("expected the SAME clientInterface object to survive a server-identifier-only change, got a different one (went through remove-then-add)")
	}
	want := net.IPv4(192, 168, 200, 1).To4()
	if got := r.clientIfaces[0].effectiveServerIdentifier(); !got.Equal(want) {
		t.Errorf("effectiveServerIdentifier() = %v, want %v", got, want)
	}
}
