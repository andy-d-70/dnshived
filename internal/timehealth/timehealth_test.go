// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package timehealth

import (
	"testing"
	"time"
)

func TestIsHealthy_AvailableSynced(t *testing.T) {
	st := Status{Available: true, Synchronized: true, Offset: 0}
	if !isHealthy(st, 5*time.Second) {
		t.Error("expected healthy for synced clock within threshold")
	}
}

func TestIsHealthy_AvailableUnsynced(t *testing.T) {
	st := Status{Available: true, Synchronized: false}
	if isHealthy(st, 5*time.Second) {
		t.Error("expected unhealthy for unsynced clock")
	}
}

func TestIsHealthy_AvailableOffsetExceedsThreshold(t *testing.T) {
	st := Status{Available: true, Synchronized: true, Offset: 10 * time.Second}
	if isHealthy(st, 5*time.Second) {
		t.Error("expected unhealthy when offset exceeds threshold")
	}
	st.Offset = -10 * time.Second
	if isHealthy(st, 5*time.Second) {
		t.Error("expected unhealthy when negative offset exceeds threshold")
	}
}

// IsHealthy's documented fail-open contract: when the check tool is
// unavailable, advisory callers must never be blocked.
func TestIsHealthy_UnavailableFailsOpen(t *testing.T) {
	mu.Lock()
	cached = Status{Available: false}
	lastCheck = time.Now()
	mu.Unlock()

	if !IsHealthy(5 * time.Second) {
		t.Error("IsHealthy must fail open (return true) when the check tool is unavailable")
	}
}

func TestIsHealthyStrict_UnavailableFailsClosed(t *testing.T) {
	mu.Lock()
	cached = Status{Available: false}
	lastCheck = time.Now()
	mu.Unlock()

	if IsHealthyStrict(5 * time.Second) {
		t.Error("IsHealthyStrict must fail closed (return false) when the check tool is unavailable")
	}
}

func TestIsHealthyStrict_AvailableSyncedMatchesIsHealthy(t *testing.T) {
	mu.Lock()
	cached = Status{Available: true, Synchronized: true, Offset: 0}
	lastCheck = time.Now()
	mu.Unlock()

	if !IsHealthy(5 * time.Second) {
		t.Error("IsHealthy should report healthy for a synced, available clock")
	}
	if !IsHealthyStrict(5 * time.Second) {
		t.Error("IsHealthyStrict should report healthy for a synced, available clock")
	}
}

func TestIsHealthyStrict_AvailableUnsyncedFailsClosed(t *testing.T) {
	mu.Lock()
	cached = Status{Available: true, Synchronized: false}
	lastCheck = time.Now()
	mu.Unlock()

	if IsHealthyStrict(5 * time.Second) {
		t.Error("IsHealthyStrict must be unhealthy when available but unsynced")
	}
}
