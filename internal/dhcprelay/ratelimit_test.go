// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcprelay

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
		if !tb.allow(time.Now(), 1, 5) {
			t.Fatalf("request %d: expected allowed (within burst), got throttled", i)
		}
	}
	if tb.allow(time.Now(), 1, 5) {
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

func TestNewClientInterface_UsesTheGivenClusterWideRateLimit(t *testing.T) {
	cfg := Config{ServerAddr: "127.0.0.21:67", RateLimit: 7, RateBurst: 9}
	cif, err := newClientInterface(ClientInterfaceConfig{Name: "ens19.300", GIAddr: "192.168.30.22"}, cfg, new(atomic.Int64))
	if err != nil {
		t.Fatalf("newClientInterface: %v", err)
	}
	if got := cif.rateLimit.Load(); got != 7 {
		t.Errorf("rateLimit = %d, want 7 (cluster-wide value of the config being applied)", got)
	}
	if got := cif.rateBurst.Load(); got != 9 {
		t.Errorf("rateBurst = %d, want 9", got)
	}
}

func TestServerConnSwapDuringForwarding(t *testing.T) {
	silenceLog(t)
	r, _, ci := newTestRelay(t)
	ci.rateLimit.Store(1 << 30)
	ci.rateBurst.Store(1 << 30)
	ci.limiter = newTokenBucket(1 << 30)
	r.clientRateLimit.Store(1 << 30)
	r.clientRateBurst.Store(1 << 30)
	tmpl := buildTestPacket(bootpOpRequest, 1, [6]byte{1}, net.IPv4zero, net.IPv4zero, 0, true, true)
	from := &net.UDPAddr{IP: net.IPv4(192, 168, 200, 50), Port: dhcpClientPort}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		pkt := make([]byte, len(tmpl))
		for i := 0; i < 2000; i++ {
			copy(pkt, tmpl)
			r.handleClientRequest(ci, pkt, from)
		}
	}()
	for i := 0; i < 200; i++ {
		r.setServerConn(newFakeUDPConn())
	}
	wg.Wait()
	if got := r.Snapshot().RequestsForwarded; got != 2000 {
		t.Errorf("forwarded %d of 2000 across socket swaps", got)
	}
}

func TestOptionalLimits_DefaultsOffAndOverrides(t *testing.T) {
	r, _, _ := newTestRelay(t)
	if r.pendingPerVLAN.Load() != defaultPendingPerVLAN || r.clientRateLimit.Load() != defaultClientRateLimit || r.clientRateBurst.Load() != defaultClientRateBurst {
		t.Fatalf("defaults not applied: pending %d client %d/%d", r.pendingPerVLAN.Load(), r.clientRateLimit.Load(), r.clientRateBurst.Load())
	}
	r.applyOptionalLimits(Config{PendingPerVLAN: -1, ClientRateLimit: -1})
	if r.pendingPerVLAN.Load() != 0 || r.clientRateLimit.Load() != 0 {
		t.Fatal("-1 must turn the limits off")
	}
	r.applyOptionalLimits(Config{PendingPerVLAN: 5, ClientRateLimit: 3})
	if r.pendingPerVLAN.Load() != 5 || r.clientRateLimit.Load() != 3 || r.clientRateBurst.Load() != defaultClientRateBurst {
		t.Fatalf("overrides: pending %d client %d/%d", r.pendingPerVLAN.Load(), r.clientRateLimit.Load(), r.clientRateBurst.Load())
	}
	if err := (&Config{ServerAddr: "127.0.0.21:67", ClientInterfaces: []ClientInterfaceConfig{{Name: "a", GIAddr: "10.0.0.1"}}, ClientRateBurst: -2}).Validate(); err == nil {
		t.Fatal("-2 accepted")
	}
}

func TestClientRateLimit_LimitsOneMACNotTheOthers(t *testing.T) {
	silenceLog(t)
	r, serverConn, ci := newTestRelay(t)
	r.applyOptionalLimits(Config{ClientRateLimit: 1, ClientRateBurst: 3})
	from := &net.UDPAddr{IP: net.IPv4(192, 168, 200, 50), Port: dhcpClientPort}
	for i := 0; i < 10; i++ {
		r.handleClientRequest(ci, buildTestPacket(bootpOpRequest, uint32(i), [6]byte{0xaa}, net.IPv4zero, net.IPv4zero, 0, true, true), from)
	}
	r.handleClientRequest(ci, buildTestPacket(bootpOpRequest, 99, [6]byte{0xbb}, net.IPv4zero, net.IPv4zero, 0, true, true), from)

	serverConn.mu.Lock()
	forwarded := len(serverConn.writes)
	serverConn.mu.Unlock()
	if forwarded != 4 {
		t.Errorf("forwarded %d, want 3 (burst of one MAC) + 1 (another MAC)", forwarded)
	}
	if got := r.Snapshot().RequestsClientLimit; got != 7 {
		t.Errorf("RequestsClientLimit = %d, want 7", got)
	}
}

func TestClientLimiter_FullTableFailsOpenAndEvictsIdle(t *testing.T) {
	cl := newClientLimiter(new(atomic.Int64))
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < maxTrackedClients; i++ {
		mac := [6]byte{byte(i >> 8), byte(i)}
		if v := cl.allow(now, mac, 10, 20); v != clientAllowed {
			t.Fatalf("client %d: %v", i, v)
		}
	}
	if v := cl.allow(now, [6]byte{0xff, 0xff, 0xff}, 10, 20); v != clientTableFull {
		t.Fatalf("full table: got %v, want clientTableFull (allowed, not tracked)", v)
	}
	if v := cl.allow(now.Add(clientIdleAfter), [6]byte{0xff, 0xff, 0xff}, 10, 20); v != clientAllowed {
		t.Fatalf("after idle eviction: got %v, want clientAllowed", v)
	}
	if len(cl.buckets) != 1 {
		t.Errorf("%d buckets after eviction, want 1", len(cl.buckets))
	}
}

func TestPendingPerVLANCap_OneVLANCannotStarveAnother(t *testing.T) {
	silenceLog(t)
	r, serverConn, ciA, ciB := newTestRelayTwoBackends(t)
	r.applyOptionalLimits(Config{PendingPerVLAN: 5, ClientRateLimit: -1})
	for _, ci := range []*clientInterface{ciA, ciB} {
		ci.rateLimit.Store(1 << 30)
		ci.rateBurst.Store(1 << 30)
		ci.limiter = newTokenBucket(1 << 30)
	}
	fromA := &net.UDPAddr{IP: net.IPv4(192, 168, 200, 50), Port: dhcpClientPort}
	for i := 0; i < 50; i++ {
		r.handleClientRequest(ciA, buildTestPacket(bootpOpRequest, uint32(i), [6]byte{byte(i)}, net.IPv4zero, net.IPv4zero, 0, true, true), fromA)
	}
	r.handleClientRequest(ciB, buildTestPacket(bootpOpRequest, 1000, [6]byte{0xbb}, net.IPv4zero, net.IPv4zero, 0, true, true),
		&net.UDPAddr{IP: net.IPv4(172, 16, 50, 50), Port: dhcpClientPort})

	w, ok := serverConn.lastWrite()
	if !ok || !w.addr.IP.Equal(net.IPv4(127, 0, 2, 21)) {
		t.Fatalf("ens20.50's request was not forwarded while ens19.200 was at its cap: %v %v", w.addr, ok)
	}
	if got := r.Snapshot().RequestsPendingFull; got != 45 {
		t.Errorf("RequestsPendingFull = %d, want 45", got)
	}
	if got := ciA.pending.Load(); got != 5 {
		t.Errorf("ens19.200 pending = %d, want 5", got)
	}
}

func TestPendingTable_PerVLANCountFollowsDeleteAndSweep(t *testing.T) {
	pt := newPendingTable()
	g := [4]byte{10, 0, 0, 1}
	var vc atomic.Int64
	now := time.Now()
	k1 := txKey{xid: 1, giaddr: g}
	k2 := txKey{xid: 2, giaddr: g}
	pt.addAt(k1, now, &vc, 2)
	pt.addAt(k2, now.Add(-2*EntryTTL), &vc, 2)
	if res := pt.addAt(txKey{xid: 3, giaddr: g}, now, &vc, 2); res != addVLANFull {
		t.Fatalf("third entry: %v, want addVLANFull", res)
	}
	if res := pt.addAt(k1, now, &vc, 2); res != addOK {
		t.Fatalf("retransmit of an existing entry refused: %v", res)
	}
	pt.delete(k1)
	for i := 0; i < ShardCount; i++ {
		pt.sweepShard(i)
	}
	if got := vc.Load(); got != 0 {
		t.Errorf("per-VLAN count %d after delete + sweep, want 0", got)
	}
	if got := pt.globalCnt.Load(); got != 0 {
		t.Errorf("global count %d, want 0", got)
	}
}
