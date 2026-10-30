// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcprelay

import "sync/atomic"

type dropReason int

const (
	dropGateClosed dropReason = iota
	dropRateLimited
	dropClientLimited
	dropPendingFull
	dropMalformed
	dropHopLimit
	dropTransactionKey
	dropUpstreamWrite
	dropBadSource
	dropGIAddr
	dropUnknownTransaction
	dropDownstreamWrite
	dropCount
)

var dropNames = [dropCount]string{
	dropGateClosed:         "gate_closed",
	dropRateLimited:        "rate_limited",
	dropClientLimited:      "client_limited",
	dropPendingFull:        "pending_full",
	dropMalformed:          "malformed",
	dropHopLimit:           "hop_limit",
	dropTransactionKey:     "transaction_key",
	dropUpstreamWrite:      "upstream_write",
	dropBadSource:          "bad_source",
	dropGIAddr:             "giaddr_mismatch",
	dropUnknownTransaction: "unknown_transaction",
	dropDownstreamWrite:    "downstream_write",
}

// vlanStats are one client interface's counters, read by the gate socket's status.
type vlanStats struct {
	requestsSeen      atomic.Int64
	requestsForwarded atomic.Int64
	repliesSeen       atomic.Int64
	repliesForwarded  atomic.Int64
	clientTableFull   atomic.Int64
	drops             [dropCount]atomic.Int64
}

func (s *vlanStats) drop(r dropReason) {
	s.drops[r].Add(1)
}

// VLANSnapshot is one client interface's counters at a point in time. Drops has an entry for every reason, zeros included.
type VLANSnapshot struct {
	RequestsSeen      int64            `json:"requests_seen"`
	RequestsForwarded int64            `json:"requests_forwarded"`
	RepliesSeen       int64            `json:"replies_seen"`
	RepliesForwarded  int64            `json:"replies_forwarded"`
	ClientTableFull   int64            `json:"client_table_full"`
	Drops             map[string]int64 `json:"drops"`
}

func (s *vlanStats) snapshot() VLANSnapshot {
	snap := VLANSnapshot{
		RequestsSeen:      s.requestsSeen.Load(),
		RequestsForwarded: s.requestsForwarded.Load(),
		RepliesSeen:       s.repliesSeen.Load(),
		RepliesForwarded:  s.repliesForwarded.Load(),
		ClientTableFull:   s.clientTableFull.Load(),
		Drops:             make(map[string]int64, dropCount),
	}
	for i := range s.drops {
		snap.Drops[dropNames[i]] = s.drops[i].Load()
	}
	return snap
}

// VLANSnapshots returns every client interface's counters, keyed by interface name.
func (r *Relay) VLANSnapshots() map[string]VLANSnapshot {
	r.cifMu.Lock()
	defer r.cifMu.Unlock()
	out := make(map[string]VLANSnapshot, len(r.clientIfaces))
	for _, ci := range r.clientIfaces {
		out[ci.name] = ci.stats.snapshot()
	}
	return out
}
