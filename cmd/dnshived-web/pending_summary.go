// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"sync/atomic"
	"time"
)

// pendingHasChanges caches whether ANY node currently has a real pending
// change staged.
var pendingHasChanges atomic.Bool

const pendingSummaryRefreshSeconds = 1

func startPendingSummaryTicker(ref *configRef) {
	go func() {
		refreshPendingHasChanges(ref)
		ticker := time.NewTicker(pendingSummaryRefreshSeconds * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			refreshPendingHasChanges(ref)
		}
	}()
}

// refreshPendingHasChanges recomputes pendingHasChanges.
func refreshPendingHasChanges(ref *configRef) {
	if currentNodeOp() != nil {
		pendingHasChanges.Store(true)
		return
	}
	cfg := ref.Load()
	live, _, err := firstReachableConfig(nodesIncludingSelf(cfg))
	if err != nil {
		return
	}
	candidate, exists, _, err := firstReachableCandidate(nodesIncludingSelf(cfg))
	if err != nil {
		return
	}
	hasChanges := false
	if exists {
		hasChanges = len(diffClusterFields(live, candidate)) > 0 ||
			len(diffScopes(live.Scopes, candidate.Scopes, candidate.GlobalDNSRecords, candidate.DefaultDHCPOptions)) > 0
	}
	pendingHasChanges.Store(hasChanges)
}

// handlePendingSummary (GET /api/pending-summary) is the cheap, O(1)
// endpoint the nav marker's own client-side fetch calls.
func handlePendingSummary() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if pendingHasChanges.Load() {
			w.Write([]byte(`{"hasChanges":true}`))
		} else {
			w.Write([]byte(`{"hasChanges":false}`))
		}
	}
}
