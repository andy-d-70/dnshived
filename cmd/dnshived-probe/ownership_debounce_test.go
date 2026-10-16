// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"testing"

	"dnshived/internal/dhcpprobe"
	"dnshived/internal/eventlog"
)

// ---- isOwnershipOnlyFailure ----

func TestIsOwnershipOnlyFailure_TrueWhenVerdictOKButInvalid(t *testing.T) {
	r := ScopeProbeResult{Reachable: true, Enabled: true}
	r.DHCP.Verdict = string(dhcpprobe.VerdictOK)
	r.DHCP.Valid = false
	r.DHCP.Reason = "no arbiter token exists for this scope"

	if !isOwnershipOnlyFailure(r) {
		t.Error("isOwnershipOnlyFailure = false, want true — Verdict is ok, only the ownership cross-check failed")
	}
}

func TestIsOwnershipOnlyFailure_FalseWhenVerdictItselfIsBad(t *testing.T) {
	for _, verdict := range []dhcpprobe.Verdict{dhcpprobe.VerdictNoAnswer, dhcpprobe.VerdictDualActive} {
		r := ScopeProbeResult{Reachable: true, Enabled: true}
		r.DHCP.Verdict = string(verdict)
		r.DHCP.Valid = false
		if isOwnershipOnlyFailure(r) {
			t.Errorf("isOwnershipOnlyFailure(verdict=%s) = true, want false — a genuine DHCP-mechanism problem must never be debounced", verdict)
		}
	}
}

func TestIsOwnershipOnlyFailure_FalseWhenValid(t *testing.T) {
	r := ScopeProbeResult{Reachable: true, Enabled: true}
	r.DHCP.Verdict = string(dhcpprobe.VerdictOK)
	r.DHCP.Valid = true
	if isOwnershipOnlyFailure(r) {
		t.Error("isOwnershipOnlyFailure = true, want false — a genuinely valid result is never a failure of any kind")
	}
}

func TestIsOwnershipOnlyFailure_FalseWhenUnreachableOrDisabled(t *testing.T) {
	unreachable := ScopeProbeResult{Reachable: false}
	if isOwnershipOnlyFailure(unreachable) {
		t.Error("isOwnershipOnlyFailure = true for an unreachable scope, want false — no probe even ran")
	}
	disabled := ScopeProbeResult{Reachable: true, Enabled: false}
	if isOwnershipOnlyFailure(disabled) {
		t.Error("isOwnershipOnlyFailure = true for a probe-disabled scope, want false — no probe even ran")
	}
}

// ---- ownershipDebounce ----

func TestOwnershipDebounce_RecordFailureIncrementsPerScope(t *testing.T) {
	d := newOwnershipDebounce()
	if got := d.recordFailure("a"); got != 1 {
		t.Errorf("first recordFailure(a) = %d, want 1", got)
	}
	if got := d.recordFailure("a"); got != 2 {
		t.Errorf("second recordFailure(a) = %d, want 2", got)
	}
	if got := d.recordFailure("b"); got != 1 {
		t.Errorf("recordFailure(b) = %d, want 1 — a different scope's own streak must be independent", got)
	}
}

func TestOwnershipDebounce_ResetClearsJustThatScope(t *testing.T) {
	d := newOwnershipDebounce()
	d.recordFailure("a")
	d.recordFailure("a")
	d.recordFailure("b")
	d.reset("a")
	if got := d.recordFailure("a"); got != 1 {
		t.Errorf("recordFailure(a) after reset = %d, want 1 — reset must drop the prior streak entirely", got)
	}
	if got := d.recordFailure("b"); got != 2 {
		t.Errorf("recordFailure(b) = %d, want 2 — resetting scope a must not touch scope b's own streak", got)
	}
}

func TestOwnershipDebounce_ClearWipesEveryScope(t *testing.T) {
	d := newOwnershipDebounce()
	d.recordFailure("a")
	d.recordFailure("b")
	d.clear()
	if got := d.recordFailure("a"); got != 1 {
		t.Errorf("recordFailure(a) after clear = %d, want 1", got)
	}
	if got := d.recordFailure("b"); got != 1 {
		t.Errorf("recordFailure(b) after clear = %d, want 1", got)
	}
}

// ---- settleOwnershipResult ----

func ownershipFailureResult(scope string) ScopeProbeResult {
	r := ScopeProbeResult{Scope: scope, Reachable: true, Enabled: true}
	r.DHCP.Verdict = string(dhcpprobe.VerdictOK)
	r.DHCP.Valid = false
	r.DHCP.Reason = "no arbiter token exists for this scope"
	return r
}

func validResult(scope string) ScopeProbeResult {
	r := ScopeProbeResult{Scope: scope, Reachable: true, Enabled: true}
	r.DHCP.Verdict = string(dhcpprobe.VerdictOK)
	r.DHCP.Valid = true
	return r
}

func TestSettleOwnershipResult_FirstFailureSuppressedAndCleared(t *testing.T) {
	store := newResultStore()
	store.set("rand-ens19-0003", validResult("rand-ens19-0003")) // a real prior good result
	debounce := newOwnershipDebounce()
	tracker := newProbeLogTracker(nil)
	events := eventlog.New(10, "probe")

	published := settleOwnershipResult(store, debounce, tracker, events, "rand-ens19-0003", ownershipFailureResult("rand-ens19-0003"))

	if published {
		t.Error("published = true, want false — a first-occurrence ownership-only failure must not be confirmed yet")
	}
	if _, ok := store.get("rand-ens19-0003"); ok {
		t.Error("store still has an entry — a not-yet-confirmed ownership failure must genuinely clear it (revert to pending), not leave the old OR the new reading visible")
	}
}

// TestSettleOwnershipResult_SecondConsecutiveFailurePublishes confirms a
// REAL, persistent ownership problem still gets surfaced.
func TestSettleOwnershipResult_SecondConsecutiveFailurePublishes(t *testing.T) {
	store := newResultStore()
	debounce := newOwnershipDebounce()
	tracker := newProbeLogTracker(nil)
	events := eventlog.New(10, "probe")

	settleOwnershipResult(store, debounce, tracker, events, "s1", ownershipFailureResult("s1"))
	published := settleOwnershipResult(store, debounce, tracker, events, "s1", ownershipFailureResult("s1"))

	if !published {
		t.Error("published = false on the SECOND consecutive failure, want true — a real, repeating ownership problem must be surfaced")
	}
	stored, ok := store.get("s1")
	if !ok {
		t.Fatal("store has no entry after the second consecutive failure, want the confirmed result stored")
	}
	if stored.DHCP.Valid {
		t.Error("stored.DHCP.Valid = true, want false — the confirmed failure's own content must be preserved")
	}
}

func TestSettleOwnershipResult_RecoveryIsImmediateNotDebounced(t *testing.T) {
	store := newResultStore()
	debounce := newOwnershipDebounce()
	tracker := newProbeLogTracker(nil)
	events := eventlog.New(10, "probe")

	settleOwnershipResult(store, debounce, tracker, events, "s1", ownershipFailureResult("s1")) // streak=1, suppressed
	published := settleOwnershipResult(store, debounce, tracker, events, "s1", validResult("s1"))

	if !published {
		t.Error("published = false for a genuinely valid result, want true — recovery must never be debounced")
	}
	stored, ok := store.get("s1")
	if !ok || !stored.DHCP.Valid {
		t.Error("store does not reflect the recovered, valid result")
	}

	published = settleOwnershipResult(store, debounce, tracker, events, "s1", ownershipFailureResult("s1"))
	if published {
		t.Error("published = true for the first ownership failure after a recovery, want false — the streak must have reset, not carried over")
	}
}

func TestSettleOwnershipResult_VerdictLevelFailureNeverSuppressed(t *testing.T) {
	store := newResultStore()
	debounce := newOwnershipDebounce()
	tracker := newProbeLogTracker(nil)
	events := eventlog.New(10, "probe")

	r := ScopeProbeResult{Scope: "s1", Reachable: true, Enabled: true}
	r.DHCP.Verdict = string(dhcpprobe.VerdictDualActive)
	r.DHCP.Valid = false
	r.DHCP.Reason = "dual-active: more than one server answered"

	published := settleOwnershipResult(store, debounce, tracker, events, "s1", r)
	if !published {
		t.Fatal("published = false for a dual-active finding, want true — a real safety problem must never wait for a second sample")
	}
	stored, ok := store.get("s1")
	if !ok || stored.DHCP.Verdict != string(dhcpprobe.VerdictDualActive) {
		t.Error("store does not reflect the dual-active finding immediately")
	}
}
