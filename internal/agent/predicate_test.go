// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"testing"

	"dnshived/internal/fencing"
	"dnshived/internal/fsm"
)

// --- withinSafetyMargin tests ---

func TestWithinSafetyMargin(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt int64
		now       int64
		want      bool
	}{
		{"well before expiry", 1000, 990, false},
		{"exactly at margin boundary", 1000, 998, true},
		{"inside margin", 1000, 999, true},
		{"at expiry", 1000, 1000, true},
		{"past expiry", 1000, 1005, true},
		{"zero expiry", 0, 0, true},
		{"far future expiry", 9999, 100, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := withinSafetyMargin(tt.expiresAt, tt.now)
			if got != tt.want {
				t.Errorf("withinSafetyMargin(%d, %d) = %v, want %v",
					tt.expiresAt, tt.now, got, tt.want)
			}
		})
	}
}

// --- scopeServeAllowed tests ---

// validInputs returns AuthorityInputs where all conditions are met.
func validInputs() AuthorityInputs {
	return AuthorityInputs{
		State:            fsm.StateStable,
		OwnsScope:        true,
		LeaseValid:       true,
		LeaseExpiresAt:   2000, // well in the future
		SelfToken:        fencing.Token{Epoch: 5, Generation: 50},
		Watermark:        fencing.Token{Epoch: 5, Generation: 50},
		Witness:          WitnessState{Held: true, ExpiresAt: 2000},
		WitnessRequired:  true,
		CurrentlyServing: true,
		Now:              1000,
	}
}

func TestAllConditionsMet(t *testing.T) {
	in := validInputs()
	allowed, reason := scopeServeAllowed(in)
	if !allowed {
		t.Fatalf("expected allowed, got denied: %s", reason)
	}
	if reason == "" {
		t.Error("reason should be set even when allowed")
	}
}

func TestNotStable(t *testing.T) {
	states := []fsm.State{fsm.StateInit, fsm.StateIsolated, "DEGRADED", "UNKNOWN"}
	for _, st := range states {
		t.Run(string(st), func(t *testing.T) {
			in := validInputs()
			in.State = st
			allowed, reason := scopeServeAllowed(in)
			if allowed {
				t.Fatal("should be denied when not STABLE")
			}
			if reason == "" {
				t.Error("reason should explain denial")
			}
		})
	}
}

func TestNotOwned(t *testing.T) {
	in := validInputs()
	in.OwnsScope = false
	allowed, reason := scopeServeAllowed(in)
	if allowed {
		t.Fatalf("should be denied when not owned, reason: %s", reason)
	}
}

func TestNoLease(t *testing.T) {
	in := validInputs()
	in.LeaseValid = false
	allowed, reason := scopeServeAllowed(in)
	if allowed {
		t.Fatalf("should be denied without valid lease, reason: %s", reason)
	}
}

func TestLeaseExpiring(t *testing.T) {
	in := validInputs()
	in.LeaseExpiresAt = 1001 // within 2s safety margin of now=1000
	allowed, reason := scopeServeAllowed(in)
	if allowed {
		t.Fatalf("should be denied when lease expiring within safety margin, reason: %s", reason)
	}
}

func TestLeaseNotExpiring(t *testing.T) {
	in := validInputs()
	in.LeaseExpiresAt = 1010 // well outside 2s margin
	allowed, _ := scopeServeAllowed(in)
	if !allowed {
		t.Fatal("should be allowed when lease has time remaining")
	}
}

func TestFenced(t *testing.T) {
	tests := []struct {
		name      string
		selfToken fencing.Token
		watermark fencing.Token
		wantAllow bool
	}{
		{"equal tokens", fencing.Token{Epoch: 5, Generation: 50}, fencing.Token{Epoch: 5, Generation: 50}, true},
		{"self ahead", fencing.Token{Epoch: 5, Generation: 51}, fencing.Token{Epoch: 5, Generation: 50}, true},
		{"self behind generation", fencing.Token{Epoch: 5, Generation: 49}, fencing.Token{Epoch: 5, Generation: 50}, false},
		{"self behind epoch", fencing.Token{Epoch: 4, Generation: 99}, fencing.Token{Epoch: 5, Generation: 1}, false},
		{"self ahead epoch", fencing.Token{Epoch: 6, Generation: 1}, fencing.Token{Epoch: 5, Generation: 99}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := validInputs()
			in.SelfToken = tt.selfToken
			in.Watermark = tt.watermark
			allowed, reason := scopeServeAllowed(in)
			if allowed != tt.wantAllow {
				t.Errorf("selfToken=%s watermark=%s: got allowed=%v (reason: %s), want %v",
					tt.selfToken, tt.watermark, allowed, reason, tt.wantAllow)
			}
		})
	}
}

// --- Witness token: start vs stop path ---

func TestWitnessNotHeld_CurrentlyServing(t *testing.T) {
	in := validInputs()
	in.CurrentlyServing = true
	in.WitnessRequired = true
	in.Witness = WitnessState{Held: false}
	allowed, reason := scopeServeAllowed(in)
	if allowed {
		t.Fatalf("should be denied: serving without witness token, reason: %s", reason)
	}
}

func TestWitnessNotHeld_NotServing(t *testing.T) {
	in := validInputs()
	in.CurrentlyServing = false
	in.WitnessRequired = true
	in.Witness = WitnessState{Held: false}
	allowed, _ := scopeServeAllowed(in)
	if !allowed {
		t.Fatal("should be allowed: not serving yet, token will be acquired in startScope")
	}
}

func TestWitnessExpiring_CurrentlyServing(t *testing.T) {
	in := validInputs()
	in.CurrentlyServing = true
	in.WitnessRequired = true
	in.Witness = WitnessState{Held: true, ExpiresAt: 1001} // within margin
	allowed, reason := scopeServeAllowed(in)
	if allowed {
		t.Fatalf("should be denied: witness expiring within safety margin, reason: %s", reason)
	}
}

func TestWitnessExpiring_NotServing(t *testing.T) {
	in := validInputs()
	in.CurrentlyServing = false
	in.WitnessRequired = true
	in.Witness = WitnessState{Held: true, ExpiresAt: 1001} // within margin
	allowed, _ := scopeServeAllowed(in)
	if !allowed {
		t.Fatal("should be allowed: not serving, witness check skipped on start path")
	}
}

func TestWitnessNotRequired(t *testing.T) {
	in := validInputs()
	in.WitnessRequired = false
	in.Witness = WitnessState{Held: false} // no token, but not required
	in.CurrentlyServing = true
	allowed, _ := scopeServeAllowed(in)
	if !allowed {
		t.Fatal("should be allowed when witness is not required (no PSK)")
	}
}

// --- Priority: first failing condition is reported ---

func TestDenialPriority(t *testing.T) {
	// All conditions failing — state check should be first.
	in := AuthorityInputs{
		State:            fsm.StateIsolated,
		OwnsScope:        false,
		LeaseValid:       false,
		SelfToken:        fencing.Token{Epoch: 1, Generation: 1},
		Watermark:        fencing.Token{Epoch: 9, Generation: 9},
		Witness:          WitnessState{Held: false},
		WitnessRequired:  true,
		CurrentlyServing: true,
		Now:              1000,
	}
	_, reason := scopeServeAllowed(in)
	if reason == "" {
		t.Fatal("expected a denial reason")
	}
	// The first check is State — reason should mention STABLE.
	if !contains(reason, "not STABLE") {
		t.Errorf("expected 'not STABLE' in reason, got: %s", reason)
	}
}

// --- Edge cases ---

func TestExactlyAtSafetyBoundary(t *testing.T) {
	in := validInputs()
	// tokenSafetyMargin = 2s, so at now=998, expiresAt=1000 → exactly at boundary
	in.Now = 998
	in.LeaseExpiresAt = 1000
	in.Witness.ExpiresAt = 1000
	allowed, _ := scopeServeAllowed(in)
	if allowed {
		t.Fatal("should be denied at exact safety margin boundary")
	}
}

func TestOneTickBeforeSafetyBoundary(t *testing.T) {
	in := validInputs()
	in.Now = 997
	in.LeaseExpiresAt = 1000
	in.Witness.ExpiresAt = 1000
	allowed, _ := scopeServeAllowed(in)
	if !allowed {
		t.Fatal("should be allowed one second before safety margin")
	}
}

func TestZeroEpochToken(t *testing.T) {
	in := validInputs()
	in.SelfToken = fencing.Token{Epoch: 0, Generation: 0}
	in.Watermark = fencing.Token{Epoch: 0, Generation: 0}
	allowed, _ := scopeServeAllowed(in)
	if !allowed {
		t.Fatal("zero tokens should be equal, not fenced")
	}
}

// helper
func contains(s, sub string) bool {
	return len(s) >= len(sub) && searchString(s, sub)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
