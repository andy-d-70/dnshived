// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package fsm implements the cluster state machine.
package fsm

import (
	"sync"
	"time"

	"dnshived/internal/fencing"
	"dnshived/internal/quorum"
)

type State string

const (
	StateInit     State = "INIT"
	StateJoining  State = "JOINING"
	StateStable   State = "STABLE"
	StateDegraded State = "DEGRADED"
	StateIsolated State = "ISOLATED"
)

// Inputs is what the FSM evaluates on each tick.
type Inputs struct {
	Verdict        quorum.Verdict
	ReachablePeers int
	ObservedOnce   bool // true once the observer has completed >=1 probe cycle
}

// Transition records a single state change for visibility/debugging.
type Transition struct {
	From      State  `json:"from"`
	To        State  `json:"to"`
	Reason    string `json:"reason"`
	Epoch     uint64 `json:"epoch"`
	Timestamp int64  `json:"timestamp"`
}

// Machine is the cluster FSM.
type Machine struct {
	mu         sync.RWMutex
	state      State
	epoch      uint64
	enteredAt  int64
	lastReason string
	history    []Transition // capped ring of recent transitions
	maxHistory int

	// OnEpochChange is invoked (if set) when the epoch is bumped, so the
	// observer's announced identity can be updated.
	OnEpochChange func(epoch uint64)
}

// New creates a machine starting in INIT at the given initial epoch
// (typically 1, or a persisted value in a later release).
func New(initialEpoch uint64) *Machine {
	return &Machine{
		state:      StateInit,
		epoch:      initialEpoch,
		enteredAt:  time.Now().Unix(),
		lastReason: "initialized",
		maxHistory: 32,
	}
}

// Evaluate applies the current inputs and returns the (possibly unchanged)
// state.
func (m *Machine) Evaluate(in Inputs) State {
	m.mu.Lock()
	defer m.mu.Unlock()

	next, reason := m.decide(in)
	if next == m.state {
		return m.state
	}

	prev := m.state
	m.state = next
	m.enteredAt = time.Now().Unix()
	m.lastReason = reason

	// Epoch bump: entering STABLE from a non-stable state asserts a new
	// authority era from this node's perspective.
	bumped := false
	if next == StateStable && prev != StateStable {
		m.epoch++
		bumped = true
	}

	m.record(Transition{
		From: prev, To: next, Reason: reason,
		Epoch: m.epoch, Timestamp: m.enteredAt,
	})

	// Fire the epoch callback in a separate goroutine.
	if bumped && m.OnEpochChange != nil {
		epoch := m.epoch
		cb := m.OnEpochChange
		go cb(epoch)
	}

	return m.state
}

// decide is the pure transition function.
func (m *Machine) decide(in Inputs) (State, string) {
	// Until the observer has completed a cycle, we stay in INIT regardless.
	if !in.ObservedOnce {
		return StateInit, "awaiting first observation cycle"
	}

	if in.ReachablePeers == 0 && in.Verdict.TotalVoters > 1 {
		return StateIsolated, "no peers reachable"
	}

	if in.Verdict.HasQuorum {
		return StateStable, "quorum present"
	}

	// Some peers visible but no quorum — partial connectivity.
	return StateDegraded, "peers visible but no quorum"
}

func (m *Machine) record(t Transition) {
	m.history = append(m.history, t)
	if len(m.history) > m.maxHistory {
		m.history = m.history[len(m.history)-m.maxHistory:]
	}
}

// Snapshot is the FSM view exposed via API.
type Snapshot struct {
	State     State        `json:"state"`
	Epoch     uint64       `json:"epoch"`
	EnteredAt int64        `json:"entered_at"`
	Reason    string       `json:"reason"`
	History   []Transition `json:"history"`
}

func (m *Machine) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	hist := make([]Transition, len(m.history))
	copy(hist, m.history)
	return Snapshot{
		State:     m.state,
		Epoch:     m.epoch,
		EnteredAt: m.enteredAt,
		Reason:    m.lastReason,
		History:   hist,
	}
}

// Epoch returns the current epoch.
func (m *Machine) Epoch() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.epoch
}

// FloorToken ensures the machine's epoch is at least the given token's
// epoch.
func (m *Machine) FloorToken(floor fencing.Token) {
	m.mu.Lock()
	if floor.Epoch <= m.epoch {
		m.mu.Unlock()
		return
	}
	m.epoch = floor.Epoch
	epoch := m.epoch
	cb := m.OnEpochChange
	m.mu.Unlock()

	if cb != nil {
		go cb(epoch)
	}
}
