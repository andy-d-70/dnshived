// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package desired computes the desired cluster ownership map.
package desired

import (
	"hash/fnv"
	"sort"
	"time"

	"dnshived/internal/config"
)

const (
	// OwnerNone marks a scope no live worker can serve.
	OwnerNone = ""
)

// ScopeDefinition is the input that drives scope→worker assignment.
type ScopeDefinition struct {
	Name            string
	PreferredWorker string // config.RoleCore1, RoleCore2, or RoleCore3
	// Parent is the scope's own physical worker trunk (e.g. "ens19").
	Parent string

	// RebalanceApprovedAt mirrors config.ScopeConfig's own field of the same
	// name (converted from Unix seconds to time.Time by ScopesFromConfig).
	RebalanceApprovedAt time.Time
}

// WorkerLiveness is the input: which core roles are currently alive and
// stable.
type WorkerLiveness struct {
	Core1Alive  bool
	Core2Alive  bool
	Core3Alive  bool
	Core1Stable bool // alive long enough for rebalance
	Core2Stable bool
	Core3Stable bool

	// Core{1,2,3}AliveSince is when the Engine first observed that role
	// continuously alive in its CURRENT run.
	Core1AliveSince time.Time
	Core2AliveSince time.Time
	Core3AliveSince time.Time

	TrunkHealth map[string]map[string]bool

	TrunkScore map[string]map[string]int

	// Observed is who is actually serving each scope right now, from every
	// node's own announced gate state (see ObservedServing).
	Observed CurrentServing
}

// trunkHealthy answers whether role's own self-reported trunk health for
// parent is known-and-healthy.
func (l WorkerLiveness) trunkHealthy(role, parent string) bool {
	if parent == "" {
		return true // nothing to check (ScopeDefinition.Parent unset)
	}
	byParent, ok := l.TrunkHealth[role]
	if !ok {
		return true
	}
	healthy, known := byParent[parent]
	if !known {
		return true
	}
	return healthy
}

// aliveForScope is alive(role) additionally scoped to one specific worker
// trunk.
func (l WorkerLiveness) aliveForScope(role, parent string) bool {
	return l.alive(role) && l.trunkHealthy(role, parent)
}

// coreRoleOrder is the fixed, deterministic tie-break order every node
// computes identically.
var coreRoleOrder = []string{config.RoleCore1, config.RoleCore2, config.RoleCore3}

func (l WorkerLiveness) alive(role string) bool {
	switch role {
	case config.RoleCore1:
		return l.Core1Alive
	case config.RoleCore2:
		return l.Core2Alive
	case config.RoleCore3:
		return l.Core3Alive
	default:
		return false
	}
}

func (l WorkerLiveness) stable(role string) bool {
	switch role {
	case config.RoleCore1:
		return l.Core1Stable
	case config.RoleCore2:
		return l.Core2Stable
	case config.RoleCore3:
		return l.Core3Stable
	default:
		return false
	}
}

func (l WorkerLiveness) aliveSince(role string) time.Time {
	switch role {
	case config.RoleCore1:
		return l.Core1AliveSince
	case config.RoleCore2:
		return l.Core2AliveSince
	case config.RoleCore3:
		return l.Core3AliveSince
	default:
		return time.Time{}
	}
}

// CurrentServing maps scope → worker role currently serving it.
type CurrentServing map[string]string

// ObservedServing turns each role's announced serving set into one owner
// per scope.
func ObservedServing(byRole map[string][]string) CurrentServing {
	out := make(CurrentServing)
	for _, role := range coreRoleOrder {
		for _, scope := range byRole[role] {
			if _, taken := out[scope]; !taken {
				out[scope] = role
			}
		}
	}
	return out
}

// Assignment is a single scope→owner mapping.
type Assignment struct {
	Scope string `json:"scope"`
	Owner string `json:"owner"` // worker role, or "" if unowned
}

// Map is the computed desired ownership state.
type Map struct {
	Assignments   []Assignment `json:"assignments"`
	Authoritative bool         `json:"authoritative"`
	Generation    uint64       `json:"generation"`
}

// Compute returns the deterministic ownership map.
func Compute(scopes []ScopeDefinition, live WorkerLiveness, current CurrentServing) []Assignment {
	// Sort by name for determinism.
	sorted := make([]ScopeDefinition, len(scopes))
	copy(sorted, scopes)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Name < sorted[j].Name
	})

	out := make([]Assignment, 0, len(sorted))
	for _, sd := range sorted {
		owner := ownerForStable(sd.Name, sd.PreferredWorker, sd.Parent, live, current[sd.Name], sd.RebalanceApprovedAt)
		out = append(out, Assignment{
			Scope: sd.Name,
			Owner: owner,
		})
	}
	return out
}

// DefaultScopes returns the legacy A/B scope definitions the engine falls
// back to when no scopes are configured.
func DefaultScopes() []ScopeDefinition {
	return []ScopeDefinition{
		{Name: "A", PreferredWorker: config.RoleCore1},
		{Name: "B", PreferredWorker: config.RoleCore2},
	}
}

// ScopesFromConfig converts config scope definitions to the desired-state
// input format.
func ScopesFromConfig(scopes map[string]config.ScopeConfig) []ScopeDefinition {
	out := make([]ScopeDefinition, 0, len(scopes))
	for name, sc := range scopes {
		sd := ScopeDefinition{
			Name:            name,
			PreferredWorker: sc.PreferredWorker,
			Parent:          sc.Parent,
		}
		if sc.RebalanceApprovedAt > 0 {
			sd.RebalanceApprovedAt = time.Unix(sc.RebalanceApprovedAt, 0)
		}
		out = append(out, sd)
	}
	return out
}

func ownerForStable(scope, preferred, parent string, live WorkerLiveness, currentOwner string, rebalanceApprovedAt time.Time) string {
	var others []string
	for _, role := range coreRoleOrder {
		if role != preferred {
			others = append(others, role)
		}
	}

	anyAlive := live.aliveForScope(preferred, parent)
	for _, o := range others {
		anyAlive = anyAlive || live.aliveForScope(o, parent)
	}
	if !anyAlive {
		return OwnerNone
	}

	if live.aliveForScope(preferred, parent) {
		if live.stable(preferred) {
			// Preferred is alive and proven stable — the normal steady-state case
			// (rule 2).
			for _, o := range others {
				if o == currentOwner && live.aliveForScope(o, parent) {
					since := live.aliveSince(preferred)
					approved := !rebalanceApprovedAt.IsZero() &&
						(since.IsZero() || !rebalanceApprovedAt.Before(since))
					if !approved {
						return o
					}
					break
				}
			}
			return preferred
		}
		// Preferred alive but not proven stable yet — hold if a live
		// other candidate is already serving.
		for _, o := range others {
			if o == currentOwner && live.aliveForScope(o, parent) {
				return o
			}
		}
		// Nobody else serving — emergency, give it to preferred even
		// though it hasn't proven stable yet.
		return preferred
	}

	for _, o := range others {
		if o == currentOwner && live.aliveForScope(o, parent) {
			return o
		}
	}
	if picked := pickOtherByHash(scope, parent, others, live); picked != OwnerNone {
		return picked
	}
	return OwnerNone // unreachable given the anyAlive check above, but safe
}

// pickOtherByHash deterministically distributes scope across whichever of
// others are currently alive.
func pickOtherByHash(scope, parent string, others []string, live WorkerLiveness) string {
	var liveOthers []string
	for _, o := range others {
		if live.aliveForScope(o, parent) {
			liveOthers = append(liveOthers, o)
		}
	}
	if len(liveOthers) == 0 {
		return OwnerNone
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(scope))
	idx := int(h.Sum32() % uint32(len(liveOthers)))
	return liveOthers[idx]
}

// Equal reports whether two assignment slices describe the same ownership.
func Equal(a, b []Assignment) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Scope != b[i].Scope || a[i].Owner != b[i].Owner {
			return false
		}
	}
	return true
}
