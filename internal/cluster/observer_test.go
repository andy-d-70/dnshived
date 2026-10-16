// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package cluster

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dnshived/internal/identity"
	"dnshived/internal/reliability"
)

func TestObserver_Probe_SingleFailureDoesNotFlipReachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	addr := srv.Listener.Addr().String()

	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", []string{addr}, "")
	o.probeAll() // establish initial reachable state

	srv.Close()
	o.probeAll() // one failure

	o.mu.RLock()
	ps := o.peers[addr]
	reachable, failures := ps.Reachable, ps.Failures
	o.mu.RUnlock()

	if !reachable {
		t.Error("Reachable flipped false after a single failed probe — must be debounced (unreachableThreshold)")
	}
	if failures != 1 {
		t.Errorf("Failures = %d, want 1 (still counted even though not yet unreachable)", failures)
	}
}

// TestObserver_Probe_ThresholdFailuresFlipsReachable confirms the other
// side: once consecutive failures reach unreachableThreshold, Reachable
// does flip.
func TestObserver_Probe_ThresholdFailuresFlipsReachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	addr := srv.Listener.Addr().String()

	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", []string{addr}, "")
	o.probeAll()

	srv.Close()
	for i := 0; i < unreachableThreshold; i++ {
		o.probeAll()
	}

	o.mu.RLock()
	reachable := o.peers[addr].Reachable
	o.mu.RUnlock()

	if reachable {
		t.Errorf("Reachable still true after %d consecutive failures (unreachableThreshold), want false", unreachableThreshold)
	}
}

// TestObserver_Probe_RecoveryIsNotDebounced confirms recovery is
// immediate.
func TestObserver_Probe_RecoveryIsNotDebounced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"cluster_id":"test-cluster","node_id":"peer-1","role":"core-2"}`))
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", []string{addr}, "")

	o.mu.Lock()
	o.peers[addr].Reachable = false
	o.peers[addr].Failures = unreachableThreshold
	o.mu.Unlock()

	o.probeAll()
	o.mu.RLock()
	reachable, failures := o.peers[addr].Reachable, o.peers[addr].Failures
	o.mu.RUnlock()
	if !reachable {
		t.Error("Reachable still false after one successful probe — recovery must not be debounced")
	}
	if failures != 0 {
		t.Errorf("Failures = %d, want 0 after a successful probe", failures)
	}
}

func TestObserver_Snapshot_RoundTripsPeerServing(t *testing.T) {
	peerIdentity := identity.Identity{
		ClusterID: "test-cluster",
		NodeID:    "peer-1",
		Role:      "core-2",
		Serving:   []string{"office", "lab"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(peerIdentity)
	}))
	defer srv.Close()

	addr := srv.Listener.Addr().String()
	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", []string{addr}, "")

	o.probeAll()

	snap := o.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("expected 1 peer in snapshot, got %d", len(snap))
	}
	ps := snap[0]
	if !ps.Reachable {
		t.Fatalf("expected peer reachable, LastError=%q", ps.LastError)
	}
	if ps.Identity == nil {
		t.Fatalf("expected peer Identity to be populated")
	}
	want := []string{"office", "lab"}
	got := ps.Identity.Serving
	if len(got) != len(want) {
		t.Fatalf("Serving = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Serving = %v, want %v", got, want)
		}
	}
}

func TestCoreRoleLiveness_SelfAndReachablePeers(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")

	o.SetPeerForTest("peer-core2", &PeerState{
		Addr: "peer-core2", Reachable: true,
		Identity: &identity.Identity{Role: "core-2"},
	})
	o.SetPeerForTest("peer-core3", &PeerState{
		Addr: "peer-core3", Reachable: true,
		Identity: &identity.Identity{Role: "core-3"},
	})
	o.SetPeerForTest("peer-unreachable", &PeerState{
		Addr: "peer-unreachable", Reachable: false,
		Identity: &identity.Identity{Role: "core-3"},
	})
	o.SetPeerForTest("peer-no-identity", &PeerState{
		Addr: "peer-no-identity", Reachable: true, Identity: nil,
	})

	core1, core2, core3 := o.CoreRoleLiveness()
	if !core1 {
		t.Error("core1Alive = false, want true (self)")
	}
	if !core2 {
		t.Error("core2Alive = false, want true (reachable peer with confirmed role)")
	}
	if !core3 {
		t.Error("core3Alive = false, want true (reachable peer with confirmed role) — " +
			"the exact case that couldn't be reported at all under the old, 2-return-value function")
	}
}

// TestCoreRoleLiveness_UnreachablePeerDoesNotCount confirms an unreachable
// peer's own claimed role never counts as alive, even with a
// fully-populated Identity.
func TestCoreRoleLiveness_UnreachablePeerDoesNotCount(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	o.SetPeerForTest("peer-core3", &PeerState{
		Addr: "peer-core3", Reachable: false,
		Identity: &identity.Identity{Role: "core-3"},
	})

	_, _, core3 := o.CoreRoleLiveness()
	if core3 {
		t.Error("core3Alive = true, want false (peer is unreachable)")
	}
}

func TestCoreRoleLiveness_NeverIdentifiedPeerStillCountsViaFallback(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	o.SetFallbackStatusForTest("core-3", "ens19", FallbackStatus{Role: "core-3", Parent: "ens19", Addr: "fb", Reachable: true})

	_, _, core3 := o.CoreRoleLiveness()
	if !core3 {
		t.Error("core3Alive = false, want true — confirmed via fallback despite zero primary identity ever learned")
	}
}

// TestObserver_HandlePing_AnnouncesOwnServing verifies this node's own
// UpdateServing value is actually what /api/v1/ping announces to peers.
func TestObserver_HandlePing_AnnouncesOwnServing(t *testing.T) {
	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	o.UpdateServing([]string{"office"})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ping", nil)
	o.HandlePing(rr, req)

	var got identity.Identity
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decoding ping response: %v", err)
	}
	if len(got.Serving) != 1 || got.Serving[0] != "office" {
		t.Errorf("Serving = %v, want [office]", got.Serving)
	}
}

func TestObserver_SetTrustedHosts_TakesEffectOnAnAlreadyRunningObserver(t *testing.T) {
	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	o.SetTrustedHosts([]string{"192.168.0.23"})

	deny := httptest.NewRecorder()
	denyReq := httptest.NewRequest(http.MethodPost, "/api/v1/ping", nil)
	denyReq.RemoteAddr = "192.168.0.22:54321"
	o.HandlePing(deny, denyReq)
	if deny.Code != http.StatusForbidden {
		t.Fatalf("status = %d before SetTrustedHosts includes .22, want 403", deny.Code)
	}

	o.SetTrustedHosts([]string{"192.168.0.22", "192.168.0.23"})

	allow := httptest.NewRecorder()
	allowReq := httptest.NewRequest(http.MethodPost, "/api/v1/ping", nil)
	allowReq.RemoteAddr = "192.168.0.22:54321"
	o.HandlePing(allow, allowReq)
	if allow.Code != http.StatusOK {
		t.Fatalf("status = %d after a live SetTrustedHosts update including .22, want 200 — the exact live-update-doesn't-take-effect bug this test guards against", allow.Code)
	}
}

func TestObserver_UpdateServing_EmptyClearsField(t *testing.T) {
	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")

	o.UpdateServing([]string{"office"})
	if o.self.Serving == nil {
		t.Fatalf("setup failed: expected Serving to be set")
	}

	o.UpdateServing(nil)
	if o.self.Serving != nil {
		t.Errorf("Serving = %v after UpdateServing(nil), want nil", o.self.Serving)
	}
}

func TestObserver_Probe_OversizedResponseBodyIsRejected(t *testing.T) {
	var body strings.Builder
	body.WriteString(`{"cluster_id":"test-cluster","node_id":"peer","role":"core-2","leases":{`)
	for i := 0; i < 20000; i++ {
		if i > 0 {
			body.WriteByte(',')
		}
		fmt.Fprintf(&body, `"scope-%d":{}`, i)
	}
	body.WriteString(`}}`)
	if body.Len() <= maxIdentityBodyBytes {
		t.Fatalf("test setup: body is %d bytes, want > %d to actually exercise the bound", body.Len(), maxIdentityBodyBytes)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body.String()))
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", []string{addr}, "")
	o.probeAll()

	o.mu.RLock()
	ps := o.peers[addr]
	failures, lastErr, ident := ps.Failures, ps.LastError, ps.Identity
	o.mu.RUnlock()

	if failures == 0 {
		t.Error("Failures = 0 after an oversized response body — expected the truncated decode to count as a failed probe")
	}
	if lastErr == "" {
		t.Error("LastError is empty — expected a decode error to be recorded for the truncated body")
	}
	if ident != nil && len(ident.Leases) > 1000 {
		t.Errorf("ps.Identity.Leases has %d entries — the oversized payload was decoded and stored instead of being rejected", len(ident.Leases))
	}
}

func TestObserver_AllPeerAddrs_ReturnsEveryReachablePeerRegardlessOfRole(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")

	o.mu.Lock()
	o.peers["stale-arbiter"] = &PeerState{Addr: "stale-arbiter", Reachable: false, Identity: &identity.Identity{Role: "core-3"}}
	o.peers["worker-b-addr"] = &PeerState{Addr: "worker-b-addr", Reachable: true, Identity: &identity.Identity{Role: "core-2"}}
	o.peers["real-arbiter"] = &PeerState{Addr: "real-arbiter", Reachable: true, Identity: &identity.Identity{Role: "core-3"}}
	o.peers["reachable-unidentified"] = &PeerState{Addr: "reachable-unidentified", Reachable: true, Identity: nil}
	o.mu.Unlock()

	got := o.AllPeerAddrs()
	want := map[string]bool{"worker-b-addr": true, "real-arbiter": true}
	if len(got) != len(want) {
		t.Fatalf("AllPeerAddrs() = %v, want exactly %v", got, want)
	}
	for _, addr := range got {
		if !want[addr] {
			t.Errorf("AllPeerAddrs() contains unexpected address %q", addr)
		}
	}
}

func TestObserver_IsReachable_ReflectsPerPeerBelief(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	o.SetPeerForTest("alive-addr", &PeerState{Addr: "alive-addr", Reachable: true})
	o.SetPeerForTest("dead-addr", &PeerState{Addr: "dead-addr", Reachable: false})

	if !o.IsReachable("alive-addr") {
		t.Error("IsReachable(alive-addr) = false, want true")
	}
	if o.IsReachable("dead-addr") {
		t.Error("IsReachable(dead-addr) = true, want false")
	}
}

func TestObserver_IsReachable_UnknownAddrFailsOpen(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	if !o.IsReachable("never-configured-addr") {
		t.Error("IsReachable(never-configured-addr) = false, want true (fail-open for an unknown address)")
	}
}

func TestObserver_RemovePeer_DropsFromActiveProbeSet(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", []string{"departed-addr", "kept-addr"}, "")

	o.RemovePeer("departed-addr")

	for _, ps := range o.Snapshot() {
		if ps.Addr == "departed-addr" {
			t.Error("departed-addr still present in Snapshot() after RemovePeer — the active probe set was never actually pruned")
		}
	}
	found := false
	for _, ps := range o.Snapshot() {
		if ps.Addr == "kept-addr" {
			found = true
		}
	}
	if !found {
		t.Error("kept-addr disappeared too — RemovePeer must only remove the one named address")
	}
}

// TestObserver_RemovePeer_UnknownAddrIsNoop confirms RemovePeer never
// panics or otherwise misbehaves when asked to remove an address that was
// never a peer at all.
func TestObserver_RemovePeer_UnknownAddrIsNoop(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", []string{"kept-addr"}, "")

	o.RemovePeer("never-was-a-peer")

	if len(o.Snapshot()) != 1 {
		t.Errorf("Snapshot() has %d entries after a no-op RemovePeer, want 1 unchanged", len(o.Snapshot()))
	}
}

func TestTopologyCheck_HealthyThreeRoleClusterReportsNoWarning(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", []string{"peer-2", "peer-3"}, "")

	o.mu.Lock()
	o.peers["peer-2"].Reachable = true
	o.peers["peer-2"].Identity = &identity.Identity{ClusterID: "c", NodeID: "n2", Role: "core-2"}
	o.peers["peer-3"].Reachable = true
	o.peers["peer-3"].Identity = &identity.Identity{ClusterID: "c", NodeID: "n3", Role: "core-3"}
	o.mu.Unlock()

	if got := o.TopologyCheck(); got != "" {
		t.Errorf("TopologyCheck() = %q, want empty — all 3 real core roles are present and healthy", got)
	}
}

func TestTopologyCheck_DuplicateRoleDetected(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", []string{"peer-dup"}, "")

	o.mu.Lock()
	o.peers["peer-dup"].Reachable = true
	o.peers["peer-dup"].Identity = &identity.Identity{ClusterID: "c", NodeID: "impostor", Role: "core-1"}
	o.mu.Unlock()

	got := o.TopologyCheck()
	if !strings.Contains(got, "duplicate role") || !strings.Contains(got, "core-1") {
		t.Errorf("TopologyCheck() = %q, want a duplicate-role warning naming core-1", got)
	}
}

func TestTopologyCheck_MissingRoleDetected(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", []string{"peer-2"}, "")

	o.mu.Lock()
	o.peers["peer-2"].Reachable = true
	o.peers["peer-2"].Identity = &identity.Identity{ClusterID: "c", NodeID: "n2", Role: "core-2"}
	o.mu.Unlock()

	got := o.TopologyCheck()
	if !strings.Contains(got, "no core-3 in cluster") {
		t.Errorf("TopologyCheck() = %q, want a warning naming core-3 as missing", got)
	}
}

// findFallbackStatus locates one (role, parent) entry in the flat slice
// FallbackStatuses() now returns.
func findFallbackStatus(statuses []FallbackStatus, role, parent string) (FallbackStatus, bool) {
	for _, fs := range statuses {
		if fs.Role == role && fs.Parent == parent {
			return fs, true
		}
	}
	return FallbackStatus{}, false
}

// identityResponder returns an httptest handler shaped like the real
// HandlePing response for role.
func identityResponder(role string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := json.Marshal(identity.Identity{ClusterID: "c", NodeID: "n-" + role, Role: role})
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}
}

func TestObserver_ObserveMgmtBeacon_HeardProducesReachableEntry(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")

	score := o.ObserveMgmtBeacon("core-3", true)
	if score <= 0 {
		t.Fatalf("ObserveMgmtBeacon(heard=true) score = %d, want > 0", score)
	}

	fs, ok := findFallbackStatus(o.FallbackStatuses(), "core-3", "mgmt")
	if !ok {
		t.Fatal("FallbackStatuses() has no core-3/mgmt entry after ObserveMgmtBeacon")
	}
	if !fs.Reachable {
		t.Error("fs.Reachable = false, want true")
	}
	if fs.LastError != "" {
		t.Errorf("fs.LastError = %q, want empty on a heard observation", fs.LastError)
	}
	if fs.Score != score {
		t.Errorf("fs.Score = %d, want %d (matching ObserveMgmtBeacon's own return value)", fs.Score, score)
	}
}

func TestObserver_ObserveMgmtBeacon_NotHeardProducesUnreachableEntry(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")

	o.ObserveMgmtBeacon("core-2", false)

	fs, ok := findFallbackStatus(o.FallbackStatuses(), "core-2", "mgmt")
	if !ok {
		t.Fatal("FallbackStatuses() has no core-2/mgmt entry after ObserveMgmtBeacon")
	}
	if fs.Reachable {
		t.Error("fs.Reachable = true, want false")
	}
	if fs.LastError == "" {
		t.Error("fs.LastError is empty, want a real explanation for the unreachable mgmt path")
	}
}

// TestObserver_ObserveMgmtBeacon_IndependentPerRole confirms two different
// roles' mgmt entries never clobber each other.
func TestObserver_ObserveMgmtBeacon_IndependentPerRole(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")

	o.ObserveMgmtBeacon("core-2", true)
	o.ObserveMgmtBeacon("core-3", false)

	fs2, ok := findFallbackStatus(o.FallbackStatuses(), "core-2", "mgmt")
	if !ok || !fs2.Reachable {
		t.Errorf("core-2/mgmt = %+v (ok=%v), want a real reachable entry", fs2, ok)
	}
	fs3, ok := findFallbackStatus(o.FallbackStatuses(), "core-3", "mgmt")
	if !ok || fs3.Reachable {
		t.Errorf("core-3/mgmt = %+v (ok=%v), want a real unreachable entry", fs3, ok)
	}
}

func TestObserver_ObserveMgmtBeacon_NeverClobbersRealTrunkPaths(t *testing.T) {
	srv := httptest.NewServer(identityResponder("core-2"))
	defer srv.Close()

	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	o.SetFallbackAddrs(map[string]map[string]string{"core-2": {"ens19": srv.Listener.Addr().String()}})
	o.probeFallbackSweep()
	o.ObserveMgmtBeacon("core-2", true)

	got := o.FallbackStatuses()
	trunk, ok := findFallbackStatus(got, "core-2", "ens19")
	if !ok || !trunk.Reachable {
		t.Fatalf("core-2/ens19 (real trunk path) = %+v (ok=%v), want unchanged/reachable", trunk, ok)
	}
	mgmt, ok := findFallbackStatus(got, "core-2", "mgmt")
	if !ok || !mgmt.Reachable {
		t.Fatalf("core-2/mgmt = %+v (ok=%v), want a real, separate reachable entry", mgmt, ok)
	}
}

func TestObserver_ProbeFallbackSweep_RoleKeyedNoIdentityNeeded(t *testing.T) {
	srv := httptest.NewServer(identityResponder("core-2"))
	defer srv.Close()
	fallbackAddr := srv.Listener.Addr().String()

	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	o.SetFallbackAddrs(map[string]map[string]string{"core-2": {"ens19": fallbackAddr}})

	o.probeFallbackSweep()

	got := o.FallbackStatuses()
	fs, ok := findFallbackStatus(got, "core-2", "ens19")
	if !ok {
		t.Fatalf("FallbackStatuses() = %v, want a core-2/ens19 entry", got)
	}
	if !fs.Reachable {
		t.Errorf("fs.Reachable = false, want true (fallback server answered with a real core-2 identity), LastError=%q", fs.LastError)
	}
	if fs.Addr != fallbackAddr {
		t.Errorf("fs.Addr = %q, want %q", fs.Addr, fallbackAddr)
	}
	if fs.LastError != "" {
		t.Errorf("fs.LastError = %q, want empty", fs.LastError)
	}
}

func TestObserver_ProbeFallbackSweep_NoAddrsConfiguredIsNoop(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")

	o.probeFallbackSweep()

	if got := o.FallbackStatuses(); len(got) != 0 {
		t.Errorf("FallbackStatuses() = %v, want empty", got)
	}
}

func TestObserver_ProbeFallbackSweep_FailedDialRecordsError(t *testing.T) {
	srv := httptest.NewServer(identityResponder("core-2"))
	deadAddr := srv.Listener.Addr().String()
	srv.Close()

	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	o.SetFallbackAddrs(map[string]map[string]string{"core-2": {"ens19": deadAddr}})

	o.probeFallbackSweep()

	fs, _ := findFallbackStatus(o.FallbackStatuses(), "core-2", "ens19")
	if fs.Reachable {
		t.Error("fs.Reachable = true, want false (server was closed)")
	}
	if fs.LastError == "" {
		t.Error("fs.LastError = empty, want a real dial error")
	}
}

// TestObserver_ProbeFallbackSweep_MultipleRolesProbedIndependently
// confirms each role's own fallback address is checked separately.
func TestObserver_ProbeFallbackSweep_MultipleRolesProbedIndependently(t *testing.T) {
	up := httptest.NewServer(identityResponder("core-2"))
	defer up.Close()
	down := httptest.NewServer(identityResponder("core-3"))
	deadAddr := down.Listener.Addr().String()
	down.Close()

	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	o.SetFallbackAddrs(map[string]map[string]string{
		"core-2": {"ens19": up.Listener.Addr().String()},
		"core-3": {"ens19": deadAddr},
	})

	o.probeFallbackSweep()

	got := o.FallbackStatuses()
	if fs, _ := findFallbackStatus(got, "core-2", "ens19"); !fs.Reachable {
		t.Errorf("core-2 fallback = %+v, want Reachable true", fs)
	}
	if fs, _ := findFallbackStatus(got, "core-3", "ens19"); fs.Reachable {
		t.Errorf("core-3 fallback = %+v, want Reachable false", fs)
	}
}

func TestObserver_ProbeFallbackSweep_MultiplePathsForSameRole(t *testing.T) {
	up := httptest.NewServer(identityResponder("core-2"))
	defer up.Close()
	down := httptest.NewServer(identityResponder("core-2"))
	deadAddr := down.Listener.Addr().String()
	down.Close()

	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	o.SetFallbackAddrs(map[string]map[string]string{
		"core-2": {"ens19": deadAddr, "ens20": up.Listener.Addr().String()},
	})

	o.probeFallbackSweep()

	got := o.FallbackStatuses()
	if fs, _ := findFallbackStatus(got, "core-2", "ens19"); fs.Reachable {
		t.Errorf("ens19 = %+v, want Reachable false", fs)
	}
	if fs, _ := findFallbackStatus(got, "core-2", "ens20"); !fs.Reachable {
		t.Errorf("ens20 = %+v, want Reachable true", fs)
	}
	if reachable, _ := o.RoleReachable("core-2"); !reachable {
		t.Error("roleReachable(core-2) = false, want true — ens20 alone must be enough")
	}
}

func TestObserver_ProbeFallbackSweep_WrongRoleClaimedIsRejected(t *testing.T) {
	srv := httptest.NewServer(identityResponder("core-3")) // answers as core-3
	defer srv.Close()

	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	// ... but configured/expected as core-2's own fallback path.
	o.SetFallbackAddrs(map[string]map[string]string{"core-2": {"ens19": srv.Listener.Addr().String()}})

	o.probeFallbackSweep()

	fs, ok := findFallbackStatus(o.FallbackStatuses(), "core-2", "ens19")
	if !ok {
		t.Fatal("expected a core-2/ens19 entry")
	}
	if fs.Reachable {
		t.Error("fs.Reachable = true, want false — the responder claimed core-3, not core-2")
	}
	if !strings.Contains(fs.LastError, "core-3") {
		t.Errorf("fs.LastError = %q, want it to name the unexpected role", fs.LastError)
	}
}

// TestObserver_ProbeFallbackSweep_BadSignatureIsRejected confirms the
// fallback path is authenticated exactly like the primary path when a PSK
// is configured.
func TestObserver_ProbeFallbackSweep_BadSignatureIsRejected(t *testing.T) {
	srv := httptest.NewServer(identityResponder("core-2")) // real identity, but NO signature header
	defer srv.Close()

	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "real-psk-secret")
	o.SetFallbackAddrs(map[string]map[string]string{"core-2": {"ens19": srv.Listener.Addr().String()}})

	o.probeFallbackSweep()

	fs, ok := findFallbackStatus(o.FallbackStatuses(), "core-2", "ens19")
	if !ok {
		t.Fatal("expected a core-2/ens19 entry")
	}
	if fs.Reachable {
		t.Error("fs.Reachable = true, want false — no signature was present although a PSK is configured")
	}
	if !strings.Contains(fs.LastError, "signature") {
		t.Errorf("fs.LastError = %q, want it to mention signature verification", fs.LastError)
	}
}

func TestObserver_Quorum_CountsPeerReachableViaFallback(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-2"}
	o := NewObserver(self, "self-addr", nil, "")

	o.SetPeerForTest("peer-core1", &PeerState{
		Addr: "peer-core1", Reachable: false,
		Identity: &identity.Identity{Role: "core-1"},
	})
	o.SetPeerForTest("peer-core3", &PeerState{
		Addr: "peer-core3", Reachable: false,
		Identity: &identity.Identity{Role: "core-3"},
	})
	o.SetFallbackStatusForTest("core-1", "ens19", FallbackStatus{Role: "core-1", Addr: "fallback-core1", Reachable: true})
	o.SetFallbackStatusForTest("core-3", "ens19", FallbackStatus{Role: "core-3", Addr: "fallback-core3", Reachable: true})

	v := o.Quorum()
	if !v.HasQuorum {
		t.Errorf("Quorum() = %+v, want HasQuorum true (self + 2 fallback-confirmed peers = 3/3)", v)
	}
	if v.VotesSeen != 3 {
		t.Errorf("Quorum().VotesSeen = %d, want 3 (self always counts, both peers confirmed via fallback)", v.VotesSeen)
	}
}

func TestObserver_Quorum_UnconfirmedFallbackDoesNotCount(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-2"}
	o := NewObserver(self, "self-addr", nil, "")

	o.SetPeerForTest("peer-core1", &PeerState{
		Addr: "peer-core1", Reachable: false,
		Identity: &identity.Identity{Role: "core-1"},
	})
	o.SetPeerForTest("peer-core3", &PeerState{
		Addr: "peer-core3", Reachable: false,
		Identity: &identity.Identity{Role: "core-3"},
	})
	o.SetFallbackStatusForTest("core-1", "ens19", FallbackStatus{Role: "core-1", Addr: "fallback-core1", Reachable: false})
	// core-3 has no fallback status at all — never swept.

	v := o.Quorum()
	if v.HasQuorum {
		t.Errorf("Quorum() = %+v, want HasQuorum false (self alone = 1/3, neither peer confirmed)", v)
	}
	if v.VotesSeen != 1 {
		t.Errorf("Quorum().VotesSeen = %d, want 1 (self only)", v.VotesSeen)
	}
}

// TestObserver_Quorum_PrimaryReachablePeerUnaffected confirms the fallback
// path is purely additive.
func TestObserver_Quorum_PrimaryReachablePeerUnaffected(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-2"}
	o := NewObserver(self, "self-addr", nil, "")

	o.SetPeerForTest("peer-core1", &PeerState{
		Addr: "peer-core1", Reachable: true,
		Identity: &identity.Identity{Role: "core-1"},
	})
	o.SetPeerForTest("peer-core3", &PeerState{
		Addr: "peer-core3", Reachable: false,
		Identity: &identity.Identity{Role: "core-3"},
	})

	v := o.Quorum()
	if v.VotesSeen != 2 {
		t.Errorf("Quorum().VotesSeen = %d, want 2 (self + the one primary-reachable peer)", v.VotesSeen)
	}
}

// --- FallbackRoutes: tunnel data to a node that lost only its mgmt path ---

func TestObserver_FallbackRoutes_OnlyForDownPeersWithConfirmedFallback(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	o.SetPeerForTest("core2-mgmt", &PeerState{Addr: "core2-mgmt", Reachable: false, Identity: &identity.Identity{Role: "core-2"}})
	o.SetPeerForTest("core3-mgmt", &PeerState{Addr: "core3-mgmt", Reachable: true, Identity: &identity.Identity{Role: "core-3"}})
	o.SetFallbackStatusForTest("core-2", "ens19", FallbackStatus{Role: "core-2", Addr: "core2-fb", Reachable: true})
	o.SetFallbackStatusForTest("core-3", "ens19", FallbackStatus{Role: "core-3", Addr: "core3-fb", Reachable: true})

	routes := o.FallbackRoutes()
	if len(routes) != 1 || routes["core2-mgmt"] != "core2-fb" {
		t.Fatalf("FallbackRoutes() = %v, want exactly core2-mgmt -> core2-fb (core-3 is reachable over mgmt, needs no route)", routes)
	}
	if fb, ok := o.FallbackRoute("core2-mgmt"); !ok || fb != "core2-fb" {
		t.Errorf("FallbackRoute(core2-mgmt) = %q,%v", fb, ok)
	}
	if _, ok := o.FallbackRoute("core3-mgmt"); ok {
		t.Error("FallbackRoute(core3-mgmt) ok = true, want false — reachable peers have no route")
	}
}

func TestObserver_FallbackRoutes_UnconfirmedOrUnidentifiedGivesNothing(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	o.SetPeerForTest("a", &PeerState{Addr: "a", Reachable: false, Identity: &identity.Identity{Role: "core-2"}})
	o.SetPeerForTest("b", &PeerState{Addr: "b", Reachable: false}) // identity never learned
	o.SetFallbackStatusForTest("core-2", "ens19", FallbackStatus{Role: "core-2", Addr: "fb", Reachable: false})
	if routes := o.FallbackRoutes(); len(routes) != 0 {
		t.Errorf("FallbackRoutes() = %v, want none — an unconfirmed fallback or unidentified peer is not a route", routes)
	}
}

func TestObserver_FallbackAddr_ConfirmedRegardlessOfPrimaryBelief(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	o.SetPeerForTest("up", &PeerState{Addr: "up", Reachable: true, Identity: &identity.Identity{Role: "core-2"}})
	o.SetFallbackStatusForTest("core-2", "ens19", FallbackStatus{Role: "core-2", Addr: "fb", Reachable: true})
	if fb, ok := o.FallbackAddr("up"); !ok || fb != "fb" {
		t.Errorf("FallbackAddr(up) = %q,%v, want fb,true even though primary is believed reachable", fb, ok)
	}
	o.SetFallbackStatusForTest("core-2", "ens19", FallbackStatus{Role: "core-2", Addr: "fb", Reachable: false})
	if _, ok := o.FallbackAddr("up"); ok {
		t.Error("FallbackAddr must be false when the fallback is not confirmed reachable")
	}
}

func TestProbeFallbackSweep_ScoreDecaysAcrossRealTransition(t *testing.T) {
	srv := httptest.NewServer(identityResponder("core-2"))
	addr := strings.TrimPrefix(srv.URL, "http://")

	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	o.SetFallbackAddrs(map[string]map[string]string{"core-2": {"ens19": addr}})

	o.probeFallbackSweep()
	statuses := o.FallbackStatuses()
	if len(statuses) != 1 || !statuses[0].Reachable || statuses[0].Score != 100 {
		t.Fatalf("after first (healthy) sweep: %+v, want Reachable=true Score=100", statuses)
	}

	srv.Close() // now unreachable
	o.probeFallbackSweep()
	statuses = o.FallbackStatuses()
	if len(statuses) != 1 || statuses[0].Reachable {
		t.Fatalf("after second (down) sweep: %+v, want Reachable=false", statuses)
	}
	if statuses[0].Score != int(100*reliability.DecayFactor) {
		t.Errorf("statuses[0].Score = %d, want %d (real decay after a confirmed transition)", statuses[0].Score, int(100*reliability.DecayFactor))
	}
}

// TestObserver_HandlePing_AnnouncesOwnTrunkHealth mirrors
// TestObserver_HandlePing_AnnouncesOwnServing exactly, for TrunkHealth.
func TestObserver_HandlePing_AnnouncesOwnTrunkHealth(t *testing.T) {
	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	o.UpdateTrunkHealth(map[string]bool{"ens19": true, "ens20": false})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ping", nil)
	o.HandlePing(rr, req)

	var got identity.Identity
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decoding ping response: %v", err)
	}
	if len(got.TrunkHealth) != 2 || got.TrunkHealth["ens19"] != true || got.TrunkHealth["ens20"] != false {
		t.Errorf("TrunkHealth = %v, want {ens19:true ens20:false}", got.TrunkHealth)
	}
}

// TestObserver_UpdateTrunkHealth_EmptyClearsField mirrors
// TestObserver_UpdateServing_EmptyClearsField exactly.
func TestObserver_UpdateTrunkHealth_EmptyClearsField(t *testing.T) {
	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")

	o.UpdateTrunkHealth(map[string]bool{"ens19": true})
	if o.self.TrunkHealth == nil {
		t.Fatalf("setup failed: expected TrunkHealth to be set")
	}

	o.UpdateTrunkHealth(nil)
	if o.self.TrunkHealth != nil {
		t.Errorf("TrunkHealth = %v after UpdateTrunkHealth(nil), want nil", o.self.TrunkHealth)
	}
}

func TestObserver_PeerTrunkHealth_ReturnsIdentifiedPeersOwnReport(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	o.SetPeerForTest("core-2-addr", &PeerState{
		Addr:     "core-2-addr",
		Identity: &identity.Identity{ClusterID: "c", NodeID: "n2", Role: "core-2", TrunkHealth: map[string]bool{"ens19": false}},
	})

	got := o.PeerTrunkHealth("core-2")
	if len(got) != 1 || got["ens19"] != false {
		t.Errorf("PeerTrunkHealth(core-2) = %v, want {ens19:false}", got)
	}
}

func TestObserver_PeerTrunkHealth_NeverIdentifiedReturnsNil(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	if got := o.PeerTrunkHealth("core-2"); got != nil {
		t.Errorf("PeerTrunkHealth(core-2) = %v, want nil (never identified)", got)
	}
}

// TestObserver_HandlePing_AnnouncesOwnTrunkScore mirrors
// TestObserver_HandlePing_AnnouncesOwnTrunkHealth exactly, for TrunkScore.
func TestObserver_HandlePing_AnnouncesOwnTrunkScore(t *testing.T) {
	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	o.UpdateTrunkScore(map[string]int{"ens19": 97, "ens20": 50})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ping", nil)
	o.HandlePing(rr, req)

	var got identity.Identity
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decoding ping response: %v", err)
	}
	if len(got.TrunkScore) != 2 || got.TrunkScore["ens19"] != 97 || got.TrunkScore["ens20"] != 50 {
		t.Errorf("TrunkScore = %v, want {ens19:97 ens20:50}", got.TrunkScore)
	}
}

// TestObserver_UpdateTrunkScore_EmptyClearsField mirrors
// TestObserver_UpdateTrunkHealth_EmptyClearsField exactly.
func TestObserver_UpdateTrunkScore_EmptyClearsField(t *testing.T) {
	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")

	o.UpdateTrunkScore(map[string]int{"ens19": 100})
	if o.self.TrunkScore == nil {
		t.Fatalf("setup failed: expected TrunkScore to be set")
	}

	o.UpdateTrunkScore(nil)
	if o.self.TrunkScore != nil {
		t.Errorf("TrunkScore = %v after UpdateTrunkScore(nil), want nil", o.self.TrunkScore)
	}
}

// TestObserver_PeerTrunkScore_ReturnsIdentifiedPeersOwnReport mirrors
// TestObserver_PeerTrunkHealth_ReturnsIdentifiedPeersOwnReport.
func TestObserver_PeerTrunkScore_ReturnsIdentifiedPeersOwnReport(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	o.SetPeerForTest("core-2-addr", &PeerState{
		Addr:     "core-2-addr",
		Identity: &identity.Identity{ClusterID: "c", NodeID: "n2", Role: "core-2", TrunkScore: map[string]int{"ens19": 82}},
	})

	got := o.PeerTrunkScore("core-2")
	if len(got) != 1 || got["ens19"] != 82 {
		t.Errorf("PeerTrunkScore(core-2) = %v, want {ens19:82}", got)
	}
}

// TestObserver_PathScore_UnknownUntilProbed confirms known=false before
// any real probe against this exact (role, parent) has ever happened.
func TestObserver_PathScore_UnknownUntilProbed(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	if _, known := o.PathScore("core-2", "ens19"); known {
		t.Error("PathScore() known = true before any probe, want false")
	}
}

func TestObserver_PathScore_ReflectsRealProbeOutcome(t *testing.T) {
	srv := httptest.NewServer(identityResponder("core-2"))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	o.SetFallbackAddrs(map[string]map[string]string{"core-2": {"ens19": addr}})
	o.probeFallbackSweep()

	score, known := o.PathScore("core-2", "ens19")
	if !known || score != 100 {
		t.Errorf("PathScore() = %d, %v, want 100, true", score, known)
	}
}

func TestObserver_SetReliabilityDir_PersistsPathScoreAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(identityResponder("core-2"))
	addr := strings.TrimPrefix(srv.URL, "http://")

	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o1 := NewObserver(self, "self-addr", nil, "")
	o1.SetReliabilityDir(dir)
	o1.SetFallbackAddrs(map[string]map[string]string{"core-2": {"ens19": addr}})
	o1.probeFallbackSweep()

	srv.Close() // now down
	o1.probeFallbackSweep()
	scoreBeforeRestart, _ := o1.PathScore("core-2", "ens19")
	if scoreBeforeRestart != int(100*reliability.DecayFactor) {
		t.Fatalf("setup failed: score before restart = %d, want %d", scoreBeforeRestart, int(100*reliability.DecayFactor))
	}

	// A fresh Observer, same dataDir -- simulates a real process restart.
	o2 := NewObserver(self, "self-addr", nil, "")
	o2.SetReliabilityDir(dir)
	scoreAfterRestart, known := o2.PathScore("core-2", "ens19")
	if !known || scoreAfterRestart != scoreBeforeRestart {
		t.Errorf("PathScore() after restart = %d, %v, want %d, true (persisted, not reset to 100)", scoreAfterRestart, known, scoreBeforeRestart)
	}
}

// TestObserver_ResetPathReliability_ClearsHistory confirms the
// operator-facing reset action reaches the store.
func TestObserver_ResetPathReliability_ClearsHistory(t *testing.T) {
	srv := httptest.NewServer(identityResponder("core-2"))
	addr := strings.TrimPrefix(srv.URL, "http://")

	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	o.SetFallbackAddrs(map[string]map[string]string{"core-2": {"ens19": addr}})
	o.probeFallbackSweep()
	srv.Close()
	o.probeFallbackSweep()
	if score, _ := o.PathScore("core-2", "ens19"); score == 100 {
		t.Fatalf("setup failed: expected a decayed score before reset")
	}

	o.ResetPathReliability("core-2", "ens19")
	if _, known := o.PathScore("core-2", "ens19"); known {
		t.Error("PathScore() known = true after ResetPathReliability, want false (never-observed)")
	}
}

func TestPathReliabilitySnapshot_ReflectsRealObservations(t *testing.T) {
	srv := httptest.NewServer(identityResponder("core-2"))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	o.SetFallbackAddrs(map[string]map[string]string{"core-2": {"ens19": addr}})
	o.probeFallbackSweep()

	snap := o.PathReliabilitySnapshot()
	e, ok := snap["core-2|ens19"]
	if !ok || e.Score != 100 || !e.WasHealthy {
		t.Errorf(`PathReliabilitySnapshot()["core-2|ens19"] = %+v, %v, want Score=100 WasHealthy=true`, e, ok)
	}
}

func TestObserver_RestorePathReliability_ReplacesHistory(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")

	o.RestorePathReliability(map[string]reliability.Entry{
		"core-2|ens19": {Score: 37, WasHealthy: true},
	})

	snap := o.PathReliabilitySnapshot()
	e, ok := snap["core-2|ens19"]
	if !ok || e.Score != 37 {
		t.Errorf(`PathReliabilitySnapshot()["core-2|ens19"] after restore = %+v, ok=%v, want Score=37`, e, ok)
	}
	if len(snap) != 1 {
		t.Errorf("PathReliabilitySnapshot() after restore has %d entries, want exactly 1", len(snap))
	}
}

// TestUpdateQuorumExclusion_UnreachableWithinGraceStaysIncluded confirms a
// peer down for LESS than failGrace is never excluded.
func TestUpdateQuorumExclusion_UnreachableWithinGraceStaysIncluded(t *testing.T) {
	ps := &PeerState{Reachable: false, UnreachableSince: 100}
	updateQuorumExclusion(ps, 100+30, 60*time.Second, 60*time.Second) // 30s down, 60s grace
	if ps.ExcludedFromQuorum {
		t.Error("ExcludedFromQuorum = true, want false (down for less than the fail-grace period)")
	}
}

func TestUpdateQuorumExclusion_UnreachablePastGraceExcludes(t *testing.T) {
	ps := &PeerState{Reachable: false, UnreachableSince: 100}
	updateQuorumExclusion(ps, 100+60, 60*time.Second, 60*time.Second) // exactly 60s down
	if !ps.ExcludedFromQuorum {
		t.Error("ExcludedFromQuorum = false, want true (down for at least the fail-grace period)")
	}
}

// TestUpdateQuorumExclusion_ReconnectWithinGraceStaysExcluded confirms a
// previously-excluded peer that's JUST reconnected is NOT immediately
// re-included.
func TestUpdateQuorumExclusion_ReconnectWithinGraceStaysExcluded(t *testing.T) {
	ps := &PeerState{Reachable: true, ReachableSince: 200, ExcludedFromQuorum: true}
	updateQuorumExclusion(ps, 200+10, 60*time.Second, 60*time.Second) // reachable only 10s so far
	if !ps.ExcludedFromQuorum {
		t.Error("ExcludedFromQuorum = false, want true (reconnected less than reconnect-grace ago)")
	}
}

func TestUpdateQuorumExclusion_ReconnectPastGraceReincludes(t *testing.T) {
	ps := &PeerState{Reachable: true, ReachableSince: 200, ExcludedFromQuorum: true}
	updateQuorumExclusion(ps, 200+60, 60*time.Second, 60*time.Second) // reachable exactly 60s
	if ps.ExcludedFromQuorum {
		t.Error("ExcludedFromQuorum = true, want false (stably reachable for at least the reconnect-grace period)")
	}
}

// TestUpdateQuorumExclusion_NeverExcludedReachablePeerUntouched confirms
// the common case (a normal, never-excluded reachable peer) is a complete
// no-op.
func TestUpdateQuorumExclusion_NeverExcludedReachablePeerUntouched(t *testing.T) {
	ps := &PeerState{Reachable: true, ReachableSince: 200, ExcludedFromQuorum: false}
	updateQuorumExclusion(ps, 200+1000, 60*time.Second, 60*time.Second)
	if ps.ExcludedFromQuorum {
		t.Error("ExcludedFromQuorum = true, want false — was never excluded, nothing should change it")
	}
}

func TestUpdateQuorumExclusion_FlappingPeerStaysExcludedThroughTheFlap(t *testing.T) {
	ps := &PeerState{Reachable: true, ReachableSince: 200, ExcludedFromQuorum: true}
	updateQuorumExclusion(ps, 200+30, 60*time.Second, 60*time.Second) // 30s in, still excluded
	if !ps.ExcludedFromQuorum {
		t.Fatal("ExcludedFromQuorum = false mid-reconnect-grace, want true")
	}
	// Flaps back down before the window completes.
	ps.Reachable = false
	ps.UnreachableSince = 200 + 35
	updateQuorumExclusion(ps, 200+40, 60*time.Second, 60*time.Second) // only 5s down again
	if !ps.ExcludedFromQuorum {
		t.Error("ExcludedFromQuorum = false after a flap, want true — must stay excluded, never re-included on an incomplete reconnect window")
	}
}

func TestObserver_EffectiveQuorum_ExcludesGraceFailedPeer(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-3"}
	o := NewObserver(self, "self-addr", nil, "")

	o.SetPeerForTest("peer-core1", &PeerState{
		Addr: "peer-core1", Reachable: true,
		Identity: &identity.Identity{Role: "core-1"},
	})
	o.SetPeerForTest("peer-core2", &PeerState{
		Addr: "peer-core2", Reachable: false,
		Identity:           &identity.Identity{Role: "core-2"},
		ExcludedFromQuorum: true,
	})

	raw := o.Quorum()
	if raw.TotalVoters != 3 {
		t.Errorf("Quorum().TotalVoters = %d, want 3 (true configured topology, unaffected by grace exclusion)", raw.TotalVoters)
	}

	eff := o.EffectiveQuorum()
	if eff.TotalVoters != 2 {
		t.Errorf("EffectiveQuorum().TotalVoters = %d, want 2 (self + the one non-excluded peer)", eff.TotalVoters)
	}
	if !eff.HasQuorum {
		t.Errorf("EffectiveQuorum() = %+v, want HasQuorum true (self + reachable peer-core1 = 2/2)", eff)
	}
}

func TestObserver_EffectiveQuorum_DegeneratesToStandaloneWhenAllPeersExcluded(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-3"}
	o := NewObserver(self, "self-addr", nil, "")

	o.SetPeerForTest("peer-core1", &PeerState{
		Addr: "peer-core1", Reachable: false,
		Identity:           &identity.Identity{Role: "core-1"},
		ExcludedFromQuorum: true,
	})
	o.SetPeerForTest("peer-core2", &PeerState{
		Addr: "peer-core2", Reachable: false,
		Identity:           &identity.Identity{Role: "core-2"},
		ExcludedFromQuorum: true,
	})

	eff := o.EffectiveQuorum()
	if eff.TotalVoters != 1 || !eff.HasQuorum {
		t.Errorf("EffectiveQuorum() = %+v, want TotalVoters=1, HasQuorum=true (self alone, standalone)", eff)
	}
	raw := o.Quorum()
	if raw.TotalVoters != 3 {
		t.Errorf("Quorum().TotalVoters = %d, want 3 (real configured topology, still honest for display)", raw.TotalVoters)
	}
}

func TestObserver_Probe_ReachableTransitionSetsReachableSince(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(identity.Identity{ClusterID: "c", NodeID: "peer", Role: "core-2"})
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	o := NewObserver(self, "self-addr", []string{addr}, "")
	// Force the "was unreachable" precondition directly — probe()'s own
	// transition-logging branch requires Checks>1, so seed both.
	o.mu.Lock()
	o.peers[addr].Reachable = false
	o.peers[addr].UnreachableSince = time.Now().Unix() - 30
	o.peers[addr].Checks = 1
	o.mu.Unlock()

	o.probe(addr)

	o.mu.RLock()
	rs := o.peers[addr].ReachableSince
	us := o.peers[addr].UnreachableSince
	o.mu.RUnlock()
	if rs == 0 {
		t.Error("ReachableSince = 0 after a real reachable probe following an unreachable state, want a real timestamp")
	}
	if us != 0 {
		t.Errorf("UnreachableSince = %d after reconnecting, want 0 (cleared on recovery)", us)
	}
}

func TestObserver_FailAndReconnectGrace_RealProbeLoopEndToEnd(t *testing.T) {
	var up atomic.Bool
	up.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			hj, ok := w.(http.Hijacker)
			if ok {
				conn, _, _ := hj.Hijack()
				conn.Close()
				return
			}
			return
		}
		json.NewEncoder(w).Encode(identity.Identity{ClusterID: "c", NodeID: "peer", Role: "core-2"})
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", []string{addr}, "")
	o.SetGracePeriods(2*time.Second, 2*time.Second)

	// Establish a real, confirmed-reachable baseline first.
	o.probe(addr)
	o.probe(addr)
	if eff := o.EffectiveQuorum(); !eff.HasQuorum || eff.TotalVoters != 2 {
		t.Fatalf("baseline EffectiveQuorum() = %+v, want HasQuorum=true TotalVoters=2 (self + reachable peer)", eff)
	}

	up.Store(false)
	for i := 0; i < unreachableThreshold+1; i++ {
		o.probe(addr)
	}
	o.mu.RLock()
	reachableAfterFail := o.peers[addr].Reachable
	o.mu.RUnlock()
	if reachableAfterFail {
		t.Fatal("peer still Reachable after unreachableThreshold+1 failed probes, want false")
	}
	time.Sleep(2200 * time.Millisecond) // past the 2s fail-grace
	o.probe(addr)                       // one more tick to recompute exclusion
	if eff := o.EffectiveQuorum(); eff.TotalVoters != 1 || !eff.HasQuorum {
		t.Fatalf("EffectiveQuorum() after fail-grace elapsed = %+v, want TotalVoters=1 HasQuorum=true (standalone)", eff)
	}
	if raw := o.Quorum(); raw.TotalVoters != 2 {
		t.Errorf("Quorum().TotalVoters = %d after fail-grace, want 2 (real configured topology unaffected)", raw.TotalVoters)
	}

	// Peer comes back. Must NOT be immediately re-included.
	up.Store(true)
	o.probe(addr)
	if eff := o.EffectiveQuorum(); eff.TotalVoters != 1 {
		t.Fatalf("EffectiveQuorum() immediately after reconnect = %+v, want TotalVoters=1 (still mid reconnect-grace)", eff)
	}

	time.Sleep(2200 * time.Millisecond)
	o.probe(addr)
	if eff := o.EffectiveQuorum(); eff.TotalVoters != 2 || !eff.HasQuorum {
		t.Fatalf("EffectiveQuorum() after reconnect-grace elapsed = %+v, want TotalVoters=2 HasQuorum=true (fully reintegrated)", eff)
	}
}

func TestDeriveRoleAddr_LiveIdentifiedPeer(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")

	o.SetPeerForTest("192.168.0.23:9443", &PeerState{
		Addr: "192.168.0.23:9443", Reachable: true,
		Identity: &identity.Identity{Role: "core-2"},
	})

	got := o.DeriveRoleAddr("core-2", "192.168.10.")
	if got != "192.168.10.23" {
		t.Errorf("DeriveRoleAddr(core-2, 192.168.10.) = %q, want 192.168.10.23 (derived from the peer's own real last octet, .23)", got)
	}
}

// TestDeriveRoleAddr_UnidentifiedRoleReturnsEmpty confirms a role Observer
// has never once identified over primary resolves to "".
func TestDeriveRoleAddr_UnidentifiedRoleReturnsEmpty(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")

	if got := o.DeriveRoleAddr("core-3", "192.168.10."); got != "" {
		t.Errorf("DeriveRoleAddr(core-3, ...) = %q, want empty (never identified)", got)
	}
}

func TestDeriveRoleAddr_UnreachableButPreviouslyIdentifiedStillResolves(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")

	o.SetPeerForTest("192.168.0.24:9443", &PeerState{
		Addr: "192.168.0.24:9443", Reachable: false,
		Identity: &identity.Identity{Role: "core-3"},
	})

	got := o.DeriveRoleAddr("core-3", "192.168.10.")
	if got != "192.168.10.24" {
		t.Errorf("DeriveRoleAddr(core-3, ...) = %q, want 192.168.10.24 (best-known address, even though currently unreachable)", got)
	}
}

// TestDeriveRoleAddr_MalformedPrimaryAddrReturnsEmpty confirms a non-IPv4
// (or otherwise unparseable) primary address never produces a garbage
// derived address.
func TestDeriveRoleAddr_MalformedPrimaryAddrReturnsEmpty(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")

	o.SetPeerForTest("not-a-real-address", &PeerState{
		Addr: "not-a-real-address", Reachable: true,
		Identity: &identity.Identity{Role: "core-2"},
	})

	if got := o.DeriveRoleAddr("core-2", "192.168.10."); got != "" {
		t.Errorf("DeriveRoleAddr(core-2, ...) = %q, want empty (malformed primary address)", got)
	}
}
