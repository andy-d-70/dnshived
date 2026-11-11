// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"strings"
	"sync"
	"time"
)

// settleGrace is how long a warning of a kind that appears briefly while the
// cluster settles after a node restart (no arbiter token yet, a probe result that
// has not caught up) must have been present before the Overview shows it.
const settleGrace = 30 * time.Second

// settleTracker remembers when each such warning was first seen. A warning that
// disappears is forgotten, so a flapping one starts its grace again.
type settleTracker struct {
	mu    sync.Mutex
	first map[string]time.Time
}

var settleState = &settleTracker{first: map[string]time.Time{}}

// young returns the keys that were first seen less than grace ago, and forgets
// every key that is not in keys.
func (t *settleTracker) young(now time.Time, keys []string, grace time.Duration) map[string]bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	present := make(map[string]bool, len(keys))
	young := map[string]bool{}
	for _, k := range keys {
		present[k] = true
		if _, seen := t.first[k]; !seen {
			t.first[k] = now
		}
		if now.Sub(t.first[k]) < grace {
			young[k] = true
		}
	}
	for k := range t.first {
		if !present[k] {
			delete(t.first, k)
		}
	}
	return young
}

// isSettlingWarning is true for the coherence warnings that are expected for a
// short while after a node restart.
func isSettlingWarning(w string) bool { return strings.HasPrefix(w, "NO TOKEN:") }

// isSettlingProbeIssue is true for a probe issue that is only "no answer yet"; a
// rogue DHCP server is never held back.
func isSettlingProbeIssue(p probeIssue) bool {
	return !p.Rogue && (strings.Contains(p.DHCPText, "NONE") || strings.Contains(p.Detail, "no answer"))
}

func probeIssueKey(p probeIssue) string {
	return "probe|" + p.Scope + "|" + p.Worker + "|" + p.DNSText + "|" + p.DHCPText
}

// settleFilter drops the settling warnings and probe issues that have not been
// present for settleGrace yet.
func (t *settleTracker) settleFilter(now time.Time, coherence []string, probes []probeIssue) ([]string, []probeIssue) {
	var keys []string
	for _, w := range coherence {
		if isSettlingWarning(w) {
			keys = append(keys, "coh|"+w)
		}
	}
	for _, p := range probes {
		if isSettlingProbeIssue(p) {
			keys = append(keys, probeIssueKey(p))
		}
	}
	young := t.young(now, keys, settleGrace)
	if len(young) == 0 {
		return coherence, probes
	}
	var outC []string
	for _, w := range coherence {
		if !(isSettlingWarning(w) && young["coh|"+w]) {
			outC = append(outC, w)
		}
	}
	var outP []probeIssue
	for _, p := range probes {
		if !(isSettlingProbeIssue(p) && young[probeIssueKey(p)]) {
			outP = append(outP, p)
		}
	}
	return outC, outP
}
