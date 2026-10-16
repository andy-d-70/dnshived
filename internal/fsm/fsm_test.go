// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package fsm

import (
	"testing"

	"dnshived/internal/quorum"
)

func TestDecide_ZeroReachablePeersWithMultipleConfiguredIsIsolated(t *testing.T) {
	m := New(1)
	in := Inputs{
		Verdict:        quorum.Verdict{TotalVoters: 3, VotesSeen: 1, Needed: 2, HasQuorum: false, SelfVotes: true},
		ReachablePeers: 0,
		ObservedOnce:   true,
	}
	if got := m.Evaluate(in); got != StateIsolated {
		t.Errorf("Evaluate() = %s, want ISOLATED (configured peers exist but none reachable)", got)
	}
}

func TestDecide_ZeroReachablePeersWithSingleConfiguredNodeIsStable(t *testing.T) {
	m := New(1)
	in := Inputs{
		Verdict:        quorum.Verdict{TotalVoters: 1, VotesSeen: 1, Needed: 1, HasQuorum: true, SelfVotes: true},
		ReachablePeers: 0,
		ObservedOnce:   true,
	}
	if got := m.Evaluate(in); got != StateStable {
		t.Errorf("Evaluate() = %s, want STABLE (genuinely standalone by configured topology, not a partition)", got)
	}
}

func TestDecide_ZeroReachablePeersNoVerdictYetIsIsolated(t *testing.T) {
	m := New(1)
	in := Inputs{
		Verdict:        quorum.Verdict{}, // zero value: TotalVoters=0, HasQuorum=false
		ReachablePeers: 0,
		ObservedOnce:   true,
	}
	if got := m.Evaluate(in); got == StateStable {
		t.Errorf("Evaluate() = %s, want NOT stable for a zero-value/unresolved verdict", got)
	}
}

func TestDecide_ObservedOnceFalseStaysInit(t *testing.T) {
	m := New(1)
	got := m.Evaluate(Inputs{ObservedOnce: false})
	if got != StateInit {
		t.Errorf("Evaluate() = %s, want INIT before the first observation cycle", got)
	}
}

func TestDecide_PeersVisibleNoQuorumIsDegraded(t *testing.T) {
	m := New(1)
	in := Inputs{
		Verdict:        quorum.Verdict{TotalVoters: 3, VotesSeen: 1, Needed: 2, HasQuorum: false, SelfVotes: true},
		ReachablePeers: 1,
		ObservedOnce:   true,
	}
	if got := m.Evaluate(in); got != StateDegraded {
		t.Errorf("Evaluate() = %s, want DEGRADED", got)
	}
}
