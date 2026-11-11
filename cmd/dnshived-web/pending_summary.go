// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// pendingHasChanges caches whether ANY node currently has a real pending
// change staged.
var pendingHasChanges atomic.Bool

const (
	pendingSummaryRefreshSeconds = 1
	// pendingIdleEvery is how often the state is rechecked while nobody has
	// used the UI for a while.
	pendingIdleEvery = 30 * time.Second
	// pendingFullEvery is how often the documents are fetched and compared even
	// when no stamp changed, as a safety net.
	pendingFullEvery = 60 * time.Second
)

// pendingChecker decides whether the pending state must be recomputed. Asking
// every node for its two file stamps is a few bytes; fetching and diffing the
// whole configuration and candidate is not, so the documents are fetched only
// when a stamp changed, a node answers without stamps (an older daemon), or
// pendingFullEvery has passed.
type pendingChecker struct {
	// stamps returns one key for the stamps of all nodes; ok is false when any
	// node cannot give stamps.
	stamps func(nodes []NodeConfig) (key string, ok bool)
	// full fetches the documents and reports whether a real change is staged.
	full func(nodes []NodeConfig) (hasChanges bool, err error)
	now  func() time.Time

	mu     sync.Mutex
	key    string
	fullAt time.Time
	known  bool
	last   bool
}

// refresh returns the current answer and whether it was recomputed.
func (p *pendingChecker) refresh(nodes []NodeConfig) (hasChanges, recomputed bool) {
	key, ok := p.stamps(nodes)
	p.mu.Lock()
	defer p.mu.Unlock()
	if ok && p.known && key == p.key && p.now().Sub(p.fullAt) < pendingFullEvery {
		return p.last, false
	}
	changed, err := p.full(nodes)
	if err != nil {
		return p.last, false
	}
	p.last, p.known, p.fullAt = changed, true, p.now()
	if ok {
		p.key = key
	} else {
		p.key = ""
	}
	return changed, true
}

type configStamps struct {
	Config    string `json:"config_stamp"`
	Candidate string `json:"candidate_stamp"`
}

// fetchStampKey asks every node for its stamps and joins them into one key.
func fetchStampKey(nodes []NodeConfig) (string, bool) {
	results := fetchAllNodes(nodes, func(n NodeConfig) (configStamps, error) {
		var st configStamps
		status, err := doGet(httpClient, n, "/api/v1/config/stamp", &st)
		if status == http.StatusNotFound || status == http.StatusMethodNotAllowed {
			return st, errNoStamps
		}
		return st, err
	})
	var b strings.Builder
	for _, res := range results {
		switch {
		case errors.Is(res.Err, errNoStamps):
			return "", false
		case res.Err != nil:
			fmt.Fprintf(&b, "%s=down;", res.Node.Addr)
		default:
			fmt.Fprintf(&b, "%s=%s,%s;", res.Node.Addr, res.Value.Config, res.Value.Candidate)
		}
	}
	return b.String(), true
}

var errNoStamps = errors.New("node has no stamp endpoint")

// fetchPendingFull is the full comparison: the live configuration against the
// staged candidate.
func fetchPendingFull(nodes []NodeConfig) (bool, error) {
	live, _, err := firstReachableConfig(nodes)
	if err != nil {
		return false, err
	}
	candidate, exists, _, err := firstReachableCandidate(nodes)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}
	return len(diffClusterFields(live, candidate)) > 0 ||
		len(diffScopes(live.Scopes, candidate.Scopes, candidate.GlobalDNSRecords, candidate.DefaultDHCPOptions)) > 0, nil
}

var pendingState = &pendingChecker{stamps: fetchStampKey, full: fetchPendingFull, now: time.Now}

// pendingRunDue says whether the ticker should recompute now: every second
// while the UI is in use, every pendingIdleEvery otherwise.
func pendingRunDue(active bool, sinceLast time.Duration) bool {
	return active || sinceLast >= pendingIdleEvery
}

func startPendingSummaryTicker(ref *configRef) {
	go func() {
		last := time.Now()
		refreshPendingHasChanges(ref)
		ticker := time.NewTicker(pendingSummaryRefreshSeconds * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if !pendingRunDue(uiActive(), time.Since(last)) {
				continue
			}
			last = time.Now()
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
	changed, recomputed := pendingState.refresh(nodesIncludingSelf(ref.Load()))
	if recomputed {
		pendingHasChanges.Store(changed)
	}
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
