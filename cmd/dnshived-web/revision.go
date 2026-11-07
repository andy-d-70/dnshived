// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"os"
	"sync"
	"time"
)

// selfNameFn names this web instance in revision stamps; main sets it to the
// instance's core role once known.
var selfNameFn = func() string {
	host, _ := os.Hostname()
	return host
}

// statusFetcher is fetchStatus, replaceable in tests.
var statusFetcher = fetchStatus

// fetchStatuses asks every node for /api/v1/status concurrently. A node that
// does not answer is left out of the result.
func fetchStatuses(nodes []NodeConfig) map[string]nodeStatus {
	var mu sync.Mutex
	out := make(map[string]nodeStatus, len(nodes))
	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		go func(n NodeConfig) {
			defer wg.Done()
			st, err := statusFetcher(n)
			if err != nil {
				return
			}
			mu.Lock()
			out[n.Name] = st
			mu.Unlock()
		}(n)
	}
	wg.Wait()
	return out
}

// withNextRevision sets the revision this push creates: one more than the
// highest revision any reachable node reports. When no node reports one (all
// too old or unreachable) the payload is left alone and each daemon counts up
// by itself.
func withNextRevision(nodes []NodeConfig, p configPushPayload) configPushPayload {
	var highest int64
	reported := false
	for _, st := range fetchStatuses(nodes) {
		if st.ConfigRevision != nil {
			reported = true
			if *st.ConfigRevision > highest {
				highest = *st.ConfigRevision
			}
		}
	}
	if !reported {
		return p
	}
	p.ConfigRevision = highest + 1
	p.ConfigRevisionAt = time.Now().UTC().Format(time.RFC3339)
	p.ConfigRevisionOrigin = selfNameFn()
	return p
}
