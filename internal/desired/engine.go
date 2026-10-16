// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package desired

import (
	"sync"
	"time"

	"dnshived/internal/fsm"
)

// Engine holds the current desired-state map and advances generation only
// while the node is STABLE.
type Engine struct {
	mu         sync.RWMutex
	scopes     []ScopeDefinition
	current    Map
	lastChange int64

	// Worker stability tracking — a worker becomes "stable" after being
	// continuously alive for rebalanceDelay.
	core1AliveAt   time.Time // when core-1 was first seen continuously alive
	core2AliveAt   time.Time
	core3AliveAt   time.Time
	wasCore1Alive  bool
	wasCore2Alive  bool
	wasCore3Alive  bool
	rebalanceDelay time.Duration

	trunkDownSince   map[string]time.Time
	trunkGracePeriod time.Duration

	trunkGraceMin time.Duration
	trunkGraceMax time.Duration

	// OnGenerationChange fires (async) when generation advances, so the
	// observer's announced generation can be updated.
	OnGenerationChange func(generation uint64)
}

// New creates an engine starting at the given generation with an empty,
// non-authoritative map.
func New(initialGen uint64, scopes []ScopeDefinition, rebalanceDelay, trunkGracePeriod time.Duration) *Engine {
	if len(scopes) == 0 {
		scopes = DefaultScopes()
	}
	if rebalanceDelay == 0 {
		rebalanceDelay = 60 * time.Second
	}
	if trunkGracePeriod == 0 {
		trunkGracePeriod = 30 * time.Second
	}
	return &Engine{
		scopes: scopes,
		current: Map{
			Assignments:   nil,
			Authoritative: false,
			Generation:    initialGen,
		},
		lastChange:       time.Now().Unix(),
		rebalanceDelay:   rebalanceDelay,
		trunkDownSince:   make(map[string]time.Time),
		trunkGracePeriod: trunkGracePeriod,
	}
}

// Reconcile recomputes desired state from current FSM state and worker
// liveness.
func (e *Engine) Reconcile(state fsm.State, live WorkerLiveness, genFloor uint64) Map {
	now := time.Now()

	// Held for the ENTIRE pass, including Compute() — not released and
	// reacquired around it.
	e.mu.Lock()
	defer e.mu.Unlock()

	if live.Core1Alive && !e.wasCore1Alive {
		e.core1AliveAt = now // just came alive
	}
	if !live.Core1Alive {
		e.core1AliveAt = time.Time{} // reset
	}
	e.wasCore1Alive = live.Core1Alive

	if live.Core2Alive && !e.wasCore2Alive {
		e.core2AliveAt = now
	}
	if !live.Core2Alive {
		e.core2AliveAt = time.Time{}
	}
	e.wasCore2Alive = live.Core2Alive

	if live.Core3Alive && !e.wasCore3Alive {
		e.core3AliveAt = now
	}
	if !live.Core3Alive {
		e.core3AliveAt = time.Time{}
	}
	e.wasCore3Alive = live.Core3Alive

	// A core role is stable if it has been continuously alive for rebalanceDelay.
	live.Core1Stable = live.Core1Alive &&
		!e.core1AliveAt.IsZero() &&
		now.Sub(e.core1AliveAt) >= e.rebalanceDelay
	live.Core2Stable = live.Core2Alive &&
		!e.core2AliveAt.IsZero() &&
		now.Sub(e.core2AliveAt) >= e.rebalanceDelay
	live.Core3Stable = live.Core3Alive &&
		!e.core3AliveAt.IsZero() &&
		now.Sub(e.core3AliveAt) >= e.rebalanceDelay

	live.Core1AliveSince = e.core1AliveAt
	live.Core2AliveSince = e.core2AliveAt
	live.Core3AliveSince = e.core3AliveAt

	if live.TrunkHealth != nil {
		debounced := make(map[string]map[string]bool, len(live.TrunkHealth))
		for role, byParent := range live.TrunkHealth {
			out := make(map[string]bool, len(byParent))
			for parent, healthy := range byParent {
				key := role + "|" + parent
				if healthy {
					delete(e.trunkDownSince, key)
					out[parent] = true
					continue
				}
				since, seen := e.trunkDownSince[key]
				if !seen {
					since = now
					e.trunkDownSince[key] = now
				}
				out[parent] = now.Sub(since) < e.graceFor(role, parent, live.TrunkScore)
			}
			debounced[role] = out
		}
		live.TrunkHealth = debounced
	}

	// Current owner per scope: what is observably serving, else this
	// engine's own last answer.
	currentServing := make(CurrentServing)
	for _, a := range e.current.Assignments {
		if a.Owner != "" {
			currentServing[a.Scope] = a.Owner
		}
	}
	for scope, owner := range live.Observed {
		currentServing[scope] = owner
	}

	assignments := Compute(e.scopes, live, currentServing)
	stable := state == fsm.StateStable

	if !stable {
		// Non-authoritative: expose the computed map, freeze generation.
		e.current.Assignments = assignments
		e.current.Authoritative = false
		return e.current
	}

	// STABLE: authoritative. First, fast-forward generation to the
	// quorum-grounded floor if we are behind it (rejoin case).
	floored := false
	if e.current.Generation < genFloor {
		e.current.Generation = genFloor
		floored = true
	}

	// Determine whether ownership actually changed vs. what we last held.
	ownershipChanged := !Equal(e.current.Assignments, assignments)
	firstAuthoritative := !e.current.Authoritative
	e.current.Assignments = assignments
	e.current.Authoritative = true

	// Generation accounting — the three cases are mutually exclusive in
	// effect:
	moved := false
	switch {
	case floored:
		// Landed exactly at the floor. No extra bump.
		moved = true
	case ownershipChanged || firstAuthoritative:
		e.current.Generation++
		moved = true
	}

	if moved {
		e.lastChange = time.Now().Unix()
		if e.OnGenerationChange != nil {
			gen := e.current.Generation
			cb := e.OnGenerationChange
			go cb(gen)
		}
	}

	return e.current
}

// Snapshot returns a copy of the current desired-state map.
func (e *Engine) Snapshot() Map {
	e.mu.RLock()
	defer e.mu.RUnlock()
	cp := e.current
	if e.current.Assignments != nil {
		cp.Assignments = make([]Assignment, len(e.current.Assignments))
		copy(cp.Assignments, e.current.Assignments)
	}
	return cp
}

// SetScopes replaces the engine's own scope→preferred-worker definitions
// used by the next Reconcile's Compute() call.
func (e *Engine) SetScopes(scopes []ScopeDefinition) {
	if len(scopes) == 0 {
		scopes = DefaultScopes()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.scopes = scopes
}

// SetTrunkGraceRange enables the continuous, score-based grace period.
func (e *Engine) SetTrunkGraceRange(min, max time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.trunkGraceMin = min
	e.trunkGraceMax = max
}

// graceFor returns the grace period to use for one (role, parent)
// trunk-down debounce this tick.
func (e *Engine) graceFor(role, parent string, scores map[string]map[string]int) time.Duration {
	if e.trunkGraceMin == 0 && e.trunkGraceMax == 0 {
		return e.trunkGracePeriod
	}
	byParent, ok := scores[role]
	if !ok {
		return e.trunkGracePeriod
	}
	score, ok := byParent[parent]
	if !ok {
		return e.trunkGracePeriod
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	span := e.trunkGraceMax - e.trunkGraceMin
	return e.trunkGraceMin + time.Duration(float64(span)*float64(score)/100)
}

// Generation returns the current generation.
func (e *Engine) Generation() uint64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.current.Generation
}

// OwnedScopes returns the scopes owned by the given role under the CURRENT
// map, but ONLY if the map is authoritative.
func (e *Engine) OwnedScopes(role string) (scopes []string, generation uint64) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if !e.current.Authoritative {
		return nil, e.current.Generation
	}
	for _, a := range e.current.Assignments {
		if a.Owner == role {
			scopes = append(scopes, a.Scope)
		}
	}
	return scopes, e.current.Generation
}
