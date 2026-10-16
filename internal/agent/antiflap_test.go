// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"testing"
	"time"

	"dnshived/internal/config"
)

// TestEvaluateAntiFlap exercises the pure AntiFlap policy stage in
// isolation.
func TestEvaluateAntiFlap(t *testing.T) {
	now := time.Unix(1000000, 0)
	const (
		rebalanceDelay    = 60 * time.Second
		quickReclaimDelay = 5 * time.Second
		quietWindow       = 5 * time.Minute
	)

	tests := []struct {
		name              string
		allowed           bool
		reason            string
		wasServing        bool
		timer             *AntiFlap
		peerServing       bool
		isPreferred       bool
		rebalanceApproved bool
		wantServe         bool
		wantReason        string
		wantAction        antiFlapTimerAction
		wantDelay         time.Duration
	}{
		{
			name:       "eager stop, not previously serving — no timer change",
			allowed:    false,
			reason:     "not owned in authoritative map",
			wasServing: false,
			wantServe:  false,
			wantReason: "not owned in authoritative map",
			wantAction: timerNoChange,
			wantDelay:  rebalanceDelay,
		},
		{
			// No prior timer at all (this scope's very first fencing
			// ever) — the quiet-scope fast path applies.
			name:       "eager stop, was serving, no prior timer — quick-reclaim delay",
			allowed:    false,
			reason:     "lease expired",
			wasServing: true,
			wantServe:  false,
			wantReason: "lease expired",
			wantAction: timerReset,
			wantDelay:  quickReclaimDelay,
		},
		{
			name:       "eager stop, was serving, timer quiet for a long time — quick-reclaim delay",
			allowed:    false,
			reason:     "fenced: token stale",
			wasServing: true,
			timer:      &AntiFlap{StableSince: now.Add(-10 * time.Minute), Delay: rebalanceDelay},
			wantServe:  false,
			wantReason: "fenced: token stale",
			wantAction: timerReset,
			wantDelay:  quickReclaimDelay,
		},
		{
			name:       "eager stop, was serving, timer reset recently — still the full delay",
			allowed:    false,
			reason:     "fenced: token stale",
			wasServing: true,
			timer:      &AntiFlap{StableSince: now.Add(-30 * time.Second), Delay: rebalanceDelay},
			wantServe:  false,
			wantReason: "fenced: token stale",
			wantAction: timerReset,
			wantDelay:  rebalanceDelay,
		},
		{
			name:       "eager stop, was serving, timer exactly at quiet-window boundary",
			allowed:    false,
			reason:     "fenced: token stale",
			wasServing: true,
			timer:      &AntiFlap{StableSince: now.Add(-quietWindow), Delay: rebalanceDelay},
			wantServe:  false,
			wantReason: "fenced: token stale",
			wantAction: timerReset,
			wantDelay:  quickReclaimDelay,
		},
		{
			// One second inside the quiet-window boundary — must NOT
			// qualify yet.
			name:       "eager stop, was serving, timer one second before quiet-window boundary",
			allowed:    false,
			reason:     "fenced: token stale",
			wasServing: true,
			timer:      &AntiFlap{StableSince: now.Add(-quietWindow + time.Second), Delay: rebalanceDelay},
			wantServe:  false,
			wantReason: "fenced: token stale",
			wantAction: timerReset,
			wantDelay:  rebalanceDelay,
		},
		{
			name:       "steady state — already serving, keep serving regardless of timer",
			allowed:    true,
			reason:     "all conditions met",
			wasServing: true,
			wantServe:  true,
			wantReason: "all conditions met",
			wantAction: timerNoChange,
		},
		{
			name:        "no timer, nobody else serving — emergency open",
			allowed:     true,
			reason:      "all conditions met",
			wasServing:  false,
			peerServing: false,
			isPreferred: false,
			wantServe:   true,
			wantReason:  "all conditions met",
			wantAction:  timerNoChange,
		},
		{
			name:        "no timer, peer serving, not preferred — start timer, stay closed",
			allowed:     true,
			reason:      "all conditions met",
			wasServing:  false,
			peerServing: true,
			isPreferred: false,
			wantServe:   false,
			wantReason:  "waiting for anti-flap eligibility",
			wantAction:  timerStart,
			wantDelay:   rebalanceDelay,
		},
		{
			name:              "no timer, peer serving, we are preferred, no approval — HOLD, no timer",
			allowed:           true,
			reason:            "all conditions met",
			wasServing:        false,
			peerServing:       true,
			isPreferred:       true,
			rebalanceApproved: false,
			wantServe:         false,
			wantReason:        "preferred worker holding — peer already serving, rebalance not approved",
			wantAction:        timerNoChange,
		},
		{
			name:              "no timer, peer serving, we are preferred, approved — open immediately",
			allowed:           true,
			reason:            "all conditions met",
			wasServing:        false,
			peerServing:       true,
			isPreferred:       true,
			rebalanceApproved: true,
			wantServe:         true,
			wantReason:        "all conditions met",
			wantAction:        timerNoChange,
		},
		{
			name:              "no timer, nobody else serving, we are preferred, no approval — open anyway",
			allowed:           true,
			reason:            "all conditions met",
			wasServing:        false,
			peerServing:       false,
			isPreferred:       true,
			rebalanceApproved: false,
			wantServe:         true,
			wantReason:        "all conditions met",
			wantAction:        timerNoChange,
		},
		{
			name:       "timer pending, not yet eligible",
			allowed:    true,
			reason:     "all conditions met",
			wasServing: false,
			timer:      &AntiFlap{StableSince: now.Add(-30 * time.Second), Delay: 60 * time.Second},
			wantServe:  false,
			wantReason: "waiting for anti-flap eligibility",
			wantAction: timerNoChange,
		},
		{
			name:       "timer eligible, comfortably past delay",
			allowed:    true,
			reason:     "all conditions met",
			wasServing: false,
			timer:      &AntiFlap{StableSince: now.Add(-61 * time.Second), Delay: 60 * time.Second},
			wantServe:  true,
			wantReason: "all conditions met",
			wantAction: timerNoChange,
		},
		{
			// now.Sub(StableSince) == Delay exactly — the >= boundary.
			name:       "timer exactly at eligibility boundary",
			allowed:    true,
			reason:     "all conditions met",
			wasServing: false,
			timer:      &AntiFlap{StableSince: now.Add(-60 * time.Second), Delay: 60 * time.Second},
			wantServe:  true,
			wantReason: "all conditions met",
			wantAction: timerNoChange,
		},
		{
			// One tick before the boundary — must still be denied.
			name:       "timer one second before eligibility boundary",
			allowed:    true,
			reason:     "all conditions met",
			wasServing: false,
			timer:      &AntiFlap{StableSince: now.Add(-59 * time.Second), Delay: 60 * time.Second},
			wantServe:  false,
			wantReason: "waiting for anti-flap eligibility",
			wantAction: timerNoChange,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, action, delay := EvaluateAntiFlap(now, tt.allowed, tt.reason, tt.wasServing, tt.timer, tt.peerServing, tt.isPreferred, tt.rebalanceApproved,
				rebalanceDelay, quickReclaimDelay, quietWindow)
			if got.Serve != tt.wantServe {
				t.Errorf("Serve = %v, want %v", got.Serve, tt.wantServe)
			}
			if got.Reason != tt.wantReason {
				t.Errorf("Reason = %q, want %q", got.Reason, tt.wantReason)
			}
			if action != tt.wantAction {
				t.Errorf("action = %v, want %v", action, tt.wantAction)
			}
			if delay != tt.wantDelay {
				t.Errorf("delay = %v, want %v", delay, tt.wantDelay)
			}
		})
	}
}

func TestEvaluateAntiFlap_RepeatedFencingNeverShortcutsTheFullDelay(t *testing.T) {
	const (
		rebalanceDelay    = 60 * time.Second
		quickReclaimDelay = 5 * time.Second
		quietWindow       = 5 * time.Minute
	)
	var timer *AntiFlap
	now := time.Unix(1000000, 0)

	for i := 0; i < 20; i++ {
		_, action, delay := EvaluateAntiFlap(now, false, "fenced: token stale", true, timer, false, true, false,
			rebalanceDelay, quickReclaimDelay, quietWindow)
		if action != timerReset {
			t.Fatalf("cycle %d: action = %v, want timerReset", i, action)
		}
		wantDelay := rebalanceDelay
		if i == 0 {
			wantDelay = quickReclaimDelay // first-ever fencing: legitimately quiet
		}
		if delay != wantDelay {
			t.Fatalf("cycle %d: delay = %v, want %v — a repeatedly-flapping scope must never get the fast path past its own first fencing, that's the exact Phase 3 VIP-bouncing regression this guards against", i, delay, wantDelay)
		}
		timer = &AntiFlap{StableSince: now, Delay: delay}
		now = now.Add(20 * time.Second)
	}
}

func TestRenderAdvertInt(t *testing.T) {
	tests := []struct {
		name string
		ms   int
		want string
	}{
		{"unset defaults to 1s", 0, "1"},
		{"exactly 1s", 1000, "1"},
		{"exactly 2s", 2000, "2"},
		{"sub-second, 100ms", 100, "0.10"},
		{"sub-second, 500ms", 500, "0.50"},
		{"sub-second, 150ms", 150, "0.15"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := renderAdvertInt(tt.ms)
			if got != tt.want {
				t.Errorf("renderAdvertInt(%d) = %q, want %q", tt.ms, got, tt.want)
			}
		})
	}
}

// TestVRRPPriority exercises the pure VRRP priority tier mapping in
// isolation.
func TestVRRPPriority(t *testing.T) {
	tests := []struct {
		name     string
		serve    bool
		allowed  bool
		wantPrio int
	}{
		{"serving — top tier regardless of allowed", true, true, vrrpPriorityServing},
		{"serve wins even over an inconsistent allowed=false", true, false, vrrpPriorityServing},
		{"not serving, predicate would allow it — anti-flap penalty tier", false, true, vrrpPriorityPenalized},
		{"not serving, not allowed at all — standby, no penalty implied", false, false, vrrpPriorityStandby},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := vrrpPriority(tt.serve, tt.allowed)
			if got != tt.wantPrio {
				t.Errorf("vrrpPriority(%v, %v) = %d, want %d", tt.serve, tt.allowed, got, tt.wantPrio)
			}
		})
	}
}

// TestRebalanceApproved exercises the real Agent-level wiring.
func TestRebalanceApproved(t *testing.T) {
	startedAt := time.Unix(1000000, 0)

	newTestAgent := func(approvedAt int64) *Agent {
		a := New(config.RoleCore2, "test-node", 1, "", "", map[string]config.ScopeConfig{
			"test-scope": {
				PreferredWorker:     config.RoleCore2,
				RebalanceApprovedAt: approvedAt,
			},
		}, nil)
		a.startedAt = startedAt
		return a
	}

	t.Run("never approved", func(t *testing.T) {
		a := newTestAgent(0)
		if a.rebalanceApproved("test-scope") {
			t.Error("rebalanceApproved = true, want false (RebalanceApprovedAt unset)")
		}
	})

	t.Run("approved before this node's own aliveness window — stale, does not count", func(t *testing.T) {
		a := newTestAgent(startedAt.Add(-time.Hour).Unix())
		if a.rebalanceApproved("test-scope") {
			t.Error("rebalanceApproved = true, want false (approval predates this node's own startedAt)")
		}
	})

	t.Run("approved exactly at startedAt — boundary, counts", func(t *testing.T) {
		a := newTestAgent(startedAt.Unix())
		if !a.rebalanceApproved("test-scope") {
			t.Error("rebalanceApproved = false, want true (approval at the exact boundary must count)")
		}
	})

	t.Run("approved after this node's own aliveness window — fresh, counts", func(t *testing.T) {
		a := newTestAgent(startedAt.Add(time.Hour).Unix())
		if !a.rebalanceApproved("test-scope") {
			t.Error("rebalanceApproved = false, want true (approval postdates this node's own startedAt)")
		}
	})

	t.Run("unconfigured scope — false, not a panic", func(t *testing.T) {
		a := newTestAgent(startedAt.Add(time.Hour).Unix())
		if a.rebalanceApproved("no-such-scope") {
			t.Error("rebalanceApproved = true, want false (scope not configured at all)")
		}
	})
}
