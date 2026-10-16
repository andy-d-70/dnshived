// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package lease

import (
	"sync"
	"time"
)

// Manager mints and renews leases for the scopes this node currently owns
// under an authoritative desired map.
type Manager struct {
	mu   sync.RWMutex
	role string // this node's role (worker-a / worker-b)
	ttl  time.Duration
	held map[string]Lease // scope → lease currently asserted by this node
}

// NewManager creates a lease manager for a node with the given role.
func NewManager(role string, ttl time.Duration) *Manager {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Manager{
		role: role,
		ttl:  ttl,
		held: make(map[string]Lease),
	}
}

// Reconcile updates held leases to match the scopes this node owns.
func (m *Manager) Reconcile(ownedScopes []string, generation, incarnation uint64) {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()

	ownedSet := make(map[string]bool, len(ownedScopes))
	for _, s := range ownedScopes {
		ownedSet[s] = true
	}

	// Drop leases for scopes no longer owned.
	for scope := range m.held {
		if !ownedSet[scope] {
			delete(m.held, scope)
		}
	}

	// Mint or renew leases for owned scopes.
	for _, scope := range ownedScopes {
		existing, ok := m.held[scope]
		if ok && existing.Generation == generation && existing.Incarnation == incarnation {
			// Renew: push expiry forward, keep granted_at.
			existing.ExpiresAt = now.Add(m.ttl).Unix()
			m.held[scope] = existing
		} else {
			// Mint fresh (new scope, or generation/incarnation changed).
			m.held[scope] = Lease{
				Scope:       scope,
				Owner:       m.role,
				Generation:  generation,
				Incarnation: incarnation,
				GrantedAt:   now.Unix(),
				ExpiresAt:   now.Add(m.ttl).Unix(),
			}
		}
	}
}

// Held returns a copy of the leases this node currently asserts.
func (m *Manager) Held() []Lease {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Lease, 0, len(m.held))
	for _, l := range m.held {
		out = append(out, l)
	}
	return out
}

// HeldMap returns scope→lease for announcement in the handshake
// identity.
func (m *Manager) HeldMap() map[string]Lease {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]Lease, len(m.held))
	for k, v := range m.held {
		out[k] = v
	}
	return out
}
