// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package quorum computes whether this node currently sees a voting
// majority of the cluster.
package quorum

import (
	"dnshived/internal/config"
	"dnshived/internal/identity"
)

// CanVote reports whether a role counts toward quorum.
func CanVote(role string) bool {
	switch role {
	case config.RoleCore1, config.RoleCore2, config.RoleCore3:
		return true
	default:
		return false
	}
}

// Verdict is the computed quorum opinion of this node.
type Verdict struct {
	// TotalVoters is the number of voting members in the cluster, including
	// self (derived from configured peers + self, filtered by CanVote).
	TotalVoters int `json:"total_voters"`
	// VotesSeen is how many voting members this node can currently see,
	// including itself (self is always counted — a node can see itself).
	VotesSeen int `json:"votes_seen"`
	// Needed is the strict majority required: floor(TotalVoters/2) + 1.
	Needed int `json:"needed"`
	// HasQuorum is true when VotesSeen >= Needed.
	HasQuorum bool `json:"has_quorum"`
	// SelfVotes records whether this node itself is a voter (always true for
	// the three valid roles; false would indicate a misconfiguration).
	SelfVotes bool `json:"self_votes"`
}

// PeerView is the minimal slice of peer state the calculator needs: is the
// peer reachable, and what role does it claim?
type PeerView struct {
	Reachable bool
	Role      string // claimed role from handshake; "" if never seen
}

// Calculate computes the quorum verdict from this node's identity and what
// it currently observes about its peers.
func Calculate(self identity.Identity, peers []PeerView) Verdict {
	v := Verdict{}

	v.SelfVotes = CanVote(self.Role)

	// Total voters = self (if voting) + every configured peer.
	total := 0
	if v.SelfVotes {
		total++
	}
	total += len(peers)
	v.TotalVoters = total

	// Votes seen = self (if voting) + reachable peers whose claimed role votes.
	seen := 0
	if v.SelfVotes {
		seen++
	}
	for _, p := range peers {
		if !p.Reachable {
			continue
		}
		// If we've handshaked the peer we know its role; require it to vote.
		if p.Role != "" && CanVote(p.Role) {
			seen++
		}
	}
	v.VotesSeen = seen

	// Strict majority.
	v.Needed = total/2 + 1
	v.HasQuorum = seen >= v.Needed

	return v
}
