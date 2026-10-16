// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package identity defines the node identity exchanged between peers
// during the cluster visibility handshake.
package identity

import (
	"dnshived/internal/fencing"
	"dnshived/internal/lease"
)

// Identity is what a node announces about itself during a handshake.
type Identity struct {
	ClusterID   string `json:"cluster_id"`
	NodeID      string `json:"node_id"`
	Role        string `json:"role"`
	Epoch       uint64 `json:"epoch"`
	Incarnation uint64 `json:"incarnation"`
	Generation  uint64 `json:"generation"`
	Version     string `json:"version"` // software version, e.g. "0.4.4-dev"

	// Leases is the set of ownership leases this node currently asserts, keyed
	// by scope.
	Leases map[string]lease.Lease `json:"leases,omitempty"`

	// Token is this node's current fencing token (epoch, generation).
	Token fencing.Token `json:"token"`

	// ClaimsQuorum is whether this node currently believes it has quorum.
	ClaimsQuorum bool `json:"claims_quorum"`

	// Serving is the set of scopes this node's DHCP gate is actually open for
	// right now, as of its last Reconcile tick.
	Serving []string `json:"serving,omitempty"`

	TrunkHealth map[string]bool `json:"trunk_health,omitempty"`

	TrunkScore map[string]int `json:"trunk_score,omitempty"`
}
