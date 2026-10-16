// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package topobeacon

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"
)

// TestScopeBeacon_RealLoopbackRoundTrip is the direct, real-socket proof
// of the actual wire mechanism.
func TestScopeBeacon_RealLoopbackRoundTrip(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	psk := []byte("test-cluster-psk")
	ListenScopeBeacons(ctx, "core-2", []string{"127.0.0.1"}, psk)
	time.Sleep(50 * time.Millisecond) // let the listener goroutine actually bind

	target := ScopeTarget{Scope: "office", LocalAddr: "127.0.0.1", PeerRole: "core-2", PeerAddr: "127.0.0.1"}
	ok := sendOneScopeBeacon("core-1", target, 1, psk)
	if !ok {
		t.Fatal("sendOneScopeBeacon against a real listening loopback socket returned false, want true")
	}

	monitor := NewScopeMonitor(nil)
	monitor.recordResult("office", "core-2", ok)
	snap := monitor.Snapshot()
	if len(snap) != 1 || !snap[0].Reachable {
		t.Errorf("Snapshot = %+v, want one reachable entry for (office, core-2)", snap)
	}
}

func TestScopeMonitor_DebounceFiresOnceOnTransitionThenRecoversImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	psk := []byte("test-cluster-psk")

	noListener := ScopeTarget{Scope: "office", LocalAddr: "127.0.0.1", PeerRole: "core-3", PeerAddr: "127.0.0.2"}

	var transitions int
	monitor := NewScopeMonitor(func(scope, peerRole string) { transitions++ })

	for i := 0; i < scopeStaleAfterMisses+2; i++ {
		ok := sendOneScopeBeacon("core-1", noListener, uint64(i), psk)
		monitor.recordResult(noListener.Scope, noListener.PeerRole, ok)
	}

	if transitions != 1 {
		t.Errorf("onUnreachable fired %d times across %d consecutive misses, want exactly 1 (edge-triggered, not once per miss)", transitions, scopeStaleAfterMisses+2)
	}
	snap := monitor.Snapshot()
	if len(snap) != 1 || snap[0].Reachable {
		t.Errorf("Snapshot = %+v, want one unreachable entry for (office, core-3)", snap)
	}

	// A single success afterward must immediately clear it back to
	// reachable — no further debounce on the way back up.
	ListenScopeBeacons(ctx, "core-3", []string{"127.0.0.2"}, psk)
	time.Sleep(50 * time.Millisecond)
	ok := sendOneScopeBeacon("core-1", noListener, 999, psk)
	if !ok {
		t.Fatal("expected a real reply once a listener exists on 127.0.0.2")
	}
	monitor.recordResult(noListener.Scope, noListener.PeerRole, ok)
	snap = monitor.Snapshot()
	if len(snap) != 1 || !snap[0].Reachable || snap[0].ConsecutiveMisses != 0 {
		t.Errorf("Snapshot = %+v, want immediately reachable again with ConsecutiveMisses reset to 0", snap)
	}
}

func TestScopeBeacon_WrongPSKRequestRejected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	realPSK := []byte("real-cluster-psk")
	attackerPSK := []byte("some-other-guessed-psk")

	ListenScopeBeacons(ctx, "core-2", []string{"127.0.0.1"}, realPSK)
	time.Sleep(50 * time.Millisecond)

	target := ScopeTarget{Scope: "office", LocalAddr: "127.0.0.1", PeerRole: "core-2", PeerAddr: "127.0.0.1"}
	ok := sendOneScopeBeacon("core-1", target, 1, attackerPSK)
	if ok {
		t.Fatal("a request signed with the wrong PSK was accepted as a valid round trip — the listener should have silently dropped it, producing no reply at all")
	}
}

func TestScopeBeacon_ForgedReplyRejected(t *testing.T) {
	realPSK := []byte("real-cluster-psk")
	attackerPSK := []byte("attacker-does-not-know-the-real-psk")

	laddr, err := net.ResolveUDPAddr("udp4", "127.0.0.3:9447")
	if err != nil {
		t.Fatalf("resolve fake attacker listen addr: %v", err)
	}
	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		t.Fatalf("bind fake attacker listener on 127.0.0.3:9447: %v", err)
	}
	defer conn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1024)
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		var req scopeRequest
		if err := json.Unmarshal(buf[:n], &req); err != nil {
			return
		}
		forged := scopeReply{Magic: req.Magic, Role: "core-2", Scope: req.Scope, Nonce: req.Nonce}
		forged.Signature = forged.Sign(attackerPSK)
		replyBytes, _ := json.Marshal(forged)
		conn.WriteToUDP(replyBytes, raddr)
	}()

	target := ScopeTarget{Scope: "office", LocalAddr: "127.0.0.1", PeerRole: "core-2", PeerAddr: "127.0.0.3"}
	ok := sendOneScopeBeacon("core-1", target, 1, realPSK)
	<-done
	if ok {
		t.Fatal("a reply forged under the wrong PSK (but with correct, plainly-visible Magic/Scope/Nonce) was accepted as valid — the signature check should have rejected it")
	}
}

func TestScopeBeaconRunner_UpdateStartsNewTargetsAndStopsRemovedOnes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	psk := []byte("test-cluster-psk")

	for _, addr := range []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"} {
		ListenScopeBeacons(ctx, "listener", []string{addr}, psk)
	}
	time.Sleep(50 * time.Millisecond)

	monitor := NewScopeMonitor(nil)
	runner := NewScopeBeaconRunner("core-1", psk, monitor)

	kept := ScopeTarget{Scope: "kept", LocalAddr: "127.0.0.9", PeerRole: "core-2", PeerAddr: "127.0.0.1"}
	removed := ScopeTarget{Scope: "removed", LocalAddr: "127.0.0.9", PeerRole: "core-2", PeerAddr: "127.0.0.2"}
	added := ScopeTarget{Scope: "added", LocalAddr: "127.0.0.9", PeerRole: "core-2", PeerAddr: "127.0.0.3"}

	runner.Update(ctx, []ScopeTarget{kept, removed})
	// Let both targets' own tickers fire at least once.
	time.Sleep(ScopeBeaconInterval + 200*time.Millisecond)

	snap := runner.monitor.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("after first Update, Snapshot() = %+v, want exactly 2 entries (kept, removed)", snap)
	}

	runner.Update(ctx, []ScopeTarget{kept, added})
	// Give the removed target's own goroutine time to actually exit,
	// and the newly-added one time to fire at least once.
	time.Sleep(ScopeBeaconInterval + 200*time.Millisecond)

	snap = runner.monitor.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("after second Update, Snapshot() = %+v, want exactly 2 entries (kept, added — removed must be gone)", snap)
	}
	var sawKept, sawAdded, sawRemoved bool
	for _, s := range snap {
		switch s.Scope {
		case "kept":
			sawKept = true
			if !s.Reachable {
				t.Errorf("kept target = %+v, want still reachable (never disturbed across both Update calls)", s)
			}
		case "added":
			sawAdded = true
			if !s.Reachable {
				t.Errorf("added target = %+v, want reachable (its own listener is real)", s)
			}
		case "removed":
			sawRemoved = true
		}
	}
	if !sawKept {
		t.Error("the unchanged 'kept' target disappeared from the monitor across an Update call — it should never have been touched")
	}
	if !sawAdded {
		t.Error("the newly-added target never appeared in the monitor after Update")
	}
	if sawRemoved {
		t.Error("the removed target is still present in the monitor after Update — Remove should have dropped it")
	}
}

// TestScopeBeaconRunner_UpdateIsIdempotentForUnchangedTargets confirms
// calling Update repeatedly with the IDENTICAL target set never restarts
// anything.
func TestScopeBeaconRunner_UpdateIsIdempotentForUnchangedTargets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	psk := []byte("test-cluster-psk")

	monitor := NewScopeMonitor(nil)
	runner := NewScopeBeaconRunner("core-1", psk, monitor)

	target := ScopeTarget{Scope: "office", LocalAddr: "127.0.0.9", PeerRole: "core-3", PeerAddr: "127.0.0.250"}

	runner.Update(ctx, []ScopeTarget{target})
	time.Sleep(ScopeBeaconInterval + 200*time.Millisecond)
	first := runner.monitor.Snapshot()[0].ConsecutiveMisses

	runner.Update(ctx, []ScopeTarget{target})
	time.Sleep(ScopeBeaconInterval + 200*time.Millisecond)
	second := runner.monitor.Snapshot()[0].ConsecutiveMisses

	if second <= first {
		t.Errorf("ConsecutiveMisses went from %d to %d across a no-op Update call — the unchanged target's own goroutine must not have been restarted", first, second)
	}
}

func TestScopeListenerRunner_UpdateOpensNewAndClosesRemovedLeavesUnchangedAlone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	psk := []byte("test-cluster-psk")

	runner := NewScopeListenerRunner("core-2", psk)

	const kept = "127.0.0.11"
	const removed = "127.0.0.12"
	const added = "127.0.0.13"

	runner.Update(ctx, []string{kept, removed})
	time.Sleep(50 * time.Millisecond)

	for _, addr := range []string{kept, removed} {
		target := ScopeTarget{Scope: "office", LocalAddr: "127.0.0.9", PeerRole: "core-2", PeerAddr: addr}
		if ok := sendOneScopeBeacon("core-1", target, 1, psk); !ok {
			t.Fatalf("address %s did not answer right after the first Update — its listener never bound", addr)
		}
	}

	runner.Update(ctx, []string{kept, added})
	// Give the removed address's own goroutine time to actually exit
	// and close its socket, and the newly-added one time to bind.
	time.Sleep(200 * time.Millisecond)

	keptTarget := ScopeTarget{Scope: "office", LocalAddr: "127.0.0.9", PeerRole: "core-2", PeerAddr: kept}
	if ok := sendOneScopeBeacon("core-1", keptTarget, 2, psk); !ok {
		t.Error("the unchanged 'kept' address stopped answering after an unrelated Update call — it should never have been touched")
	}

	addedTarget := ScopeTarget{Scope: "office", LocalAddr: "127.0.0.9", PeerRole: "core-2", PeerAddr: added}
	if ok := sendOneScopeBeacon("core-1", addedTarget, 3, psk); !ok {
		t.Error("the newly-added address never started answering after Update")
	}

	removedTarget := ScopeTarget{Scope: "office", LocalAddr: "127.0.0.9", PeerRole: "core-2", PeerAddr: removed}
	if ok := sendOneScopeBeacon("core-1", removedTarget, 4, psk); ok {
		t.Error("the removed address still answered after Update dropped it — its listener should have been torn down")
	}

	laddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(removed, "9447"))
	if err != nil {
		t.Fatalf("resolve %s:9447: %v", removed, err)
	}
	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		t.Fatalf("rebind %s:9447 after it was removed from the listener set: %v (the old socket's fd was likely never released)", removed, err)
	}
	conn.Close()
}

func TestScopeBeaconRunner_UpdateRestartsTargetWhenPeerAddrChanges(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	psk := []byte("test-cluster-psk")

	const oldPeerAddr = "127.0.0.21"
	const newPeerAddr = "127.0.0.22"
	ListenScopeBeacons(ctx, "listener", []string{oldPeerAddr, newPeerAddr}, psk)
	time.Sleep(50 * time.Millisecond)

	monitor := NewScopeMonitor(nil)
	runner := NewScopeBeaconRunner("core-1", psk, monitor)

	target := ScopeTarget{Scope: "office", LocalAddr: "127.0.0.9", PeerRole: "core-2", PeerAddr: oldPeerAddr}
	runner.Update(ctx, []ScopeTarget{target})
	time.Sleep(ScopeBeaconInterval + 200*time.Millisecond)

	snap := runner.monitor.Snapshot()
	if len(snap) != 1 || !snap[0].Reachable {
		t.Fatalf("after first Update, Snapshot() = %+v, want one reachable entry against the OLD peer address", snap)
	}

	changed := ScopeTarget{Scope: "office", LocalAddr: "127.0.0.9", PeerRole: "core-2", PeerAddr: newPeerAddr}
	runner.Update(ctx, []ScopeTarget{changed})
	time.Sleep(ScopeBeaconInterval + 200*time.Millisecond)

	snap = runner.monitor.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("after second Update, Snapshot() = %+v, want exactly 1 entry (same scope+peerRole key, restarted against the new address)", snap)
	}
	if !snap[0].Reachable {
		t.Errorf("after the peer's own address changed, the target never recovered reachable=true against the NEW address — snapshot = %+v (the old goroutine is likely still stuck beaconing the OLD address)", snap)
	}
}

// A result that lands after its pairing was removed must not re-create it,
// and a stale result must not touch a re-added pairing.
func TestScopeBeaconRunner_LateResultAfterRemoveIsDropped(t *testing.T) {
	monitor := NewScopeMonitor(nil)
	runner := NewScopeBeaconRunner("core-1", nil, monitor)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	target := ScopeTarget{Scope: "gone", LocalAddr: "127.0.0.1", PeerRole: "core-2", PeerAddr: "127.0.0.1"}
	key := scopeKey(target.Scope, target.PeerRole)

	runner.Update(ctx, []ScopeTarget{target})
	oldID := runner.running[key].id
	runner.Update(ctx, nil)
	runner.record(key, oldID, target, false)
	if n := len(monitor.Snapshot()); n != 0 {
		t.Fatalf("late result after removal re-created %d pairing(s), want 0", n)
	}

	runner.Update(ctx, []ScopeTarget{target})
	newID := runner.running[key].id
	runner.record(key, oldID, target, false)
	if n := len(monitor.Snapshot()); n != 0 {
		t.Fatalf("stale result recorded against the re-added pairing")
	}
	runner.record(key, newID, target, true)
	if snap := monitor.Snapshot(); len(snap) != 1 || !snap[0].Reachable {
		t.Fatalf("live result not recorded: %+v", snap)
	}
}
