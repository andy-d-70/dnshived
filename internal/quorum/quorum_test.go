// SPDX-License-Identifier: Apache-2.0

package quorum

import (
	"testing"

	"dnshived/internal/config"
	"dnshived/internal/identity"
)

func TestCalculate(t *testing.T) {
	core1 := identity.Identity{Role: config.RoleCore1}
	up := func(role string) PeerView { return PeerView{Reachable: true, Role: role} }
	down := func(role string) PeerView { return PeerView{Reachable: false, Role: role} }

	cases := []struct {
		name               string
		self               identity.Identity
		peers              []PeerView
		total, seen, need  int
		hasQuorum, selfVot bool
	}{
		{"all three up", core1, []PeerView{up(config.RoleCore2), up(config.RoleCore3)}, 3, 3, 2, true, true},
		{"one peer down (2 of 3)", core1, []PeerView{up(config.RoleCore2), down(config.RoleCore3)}, 3, 2, 2, true, true},
		{"isolated node (1 of 3)", core1, []PeerView{down(config.RoleCore2), down(config.RoleCore3)}, 3, 1, 2, false, true},
		{"reachable but never handshaked does not vote", core1, []PeerView{up(""), down(config.RoleCore3)}, 3, 1, 2, false, true},
		{"reachable non-voting role does not vote", core1, []PeerView{up("probe"), down(config.RoleCore3)}, 3, 1, 2, false, true},
		{"single-node cluster", core1, nil, 1, 1, 1, true, true},
		{"two-node cluster, peer down", core1, []PeerView{down(config.RoleCore2)}, 2, 1, 2, false, true},
		{"non-voting self", identity.Identity{Role: "probe"}, []PeerView{up(config.RoleCore1), up(config.RoleCore2)}, 2, 2, 2, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := Calculate(c.self, c.peers)
			if v.TotalVoters != c.total || v.VotesSeen != c.seen || v.Needed != c.need || v.HasQuorum != c.hasQuorum || v.SelfVotes != c.selfVot {
				t.Errorf("Calculate = %+v; want total=%d seen=%d needed=%d quorum=%v self_votes=%v",
					v, c.total, c.seen, c.need, c.hasQuorum, c.selfVot)
			}
		})
	}
}

// Nodes on opposite sides of a partition must never both hold quorum.
func TestCalculate_PartitionsNeverYieldTwoMajorities(t *testing.T) {
	roles := []string{config.RoleCore1, config.RoleCore2, config.RoleCore3}
	for mask := 0; mask < 1<<len(roles); mask++ {
		side := func(i int) bool { return mask&(1<<i) != 0 }
		quorate := make([]bool, len(roles))
		for i, role := range roles {
			var peers []PeerView
			for j, other := range roles {
				if j != i {
					peers = append(peers, PeerView{Reachable: side(i) == side(j), Role: other})
				}
			}
			quorate[i] = Calculate(identity.Identity{Role: role}, peers).HasQuorum
		}
		for i := range roles {
			for j := range roles {
				if side(i) != side(j) && quorate[i] && quorate[j] {
					t.Errorf("mask %03b: %s and %s are partitioned and both hold quorum", mask, roles[i], roles[j])
				}
			}
		}
	}
}

func TestCanVote(t *testing.T) {
	for _, r := range []string{config.RoleCore1, config.RoleCore2, config.RoleCore3} {
		if !CanVote(r) {
			t.Errorf("CanVote(%q) = false", r)
		}
	}
	for _, r := range []string{"", "probe", "arbiter", "worker-a"} {
		if CanVote(r) {
			t.Errorf("CanVote(%q) = true", r)
		}
	}
}
