// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package lease implements time-bounded ownership leases.
package lease

import "time"

// DefaultTTL is how long a lease remains valid after it is
// granted/renewed.
const DefaultTTL = 15 * time.Second

// DefaultRenewInterval is how often an owner renews its held leases.
const DefaultRenewInterval = 5 * time.Second

// Lease is a time-bounded ownership grant for a single scope.
type Lease struct {
	Scope       string `json:"scope"`
	Owner       string `json:"owner"`       // node role (worker-a / worker-b)
	Generation  uint64 `json:"generation"`  // authoritative gen that minted this lease
	Incarnation uint64 `json:"incarnation"` // owner's incarnation at mint time
	GrantedAt   int64  `json:"granted_at"`  // unix seconds
	ExpiresAt   int64  `json:"expires_at"`  // unix seconds
}

// Expired reports whether the lease's clock has run out as of now.
func (l Lease) Expired(now time.Time) bool {
	return now.Unix() >= l.ExpiresAt
}

// ValidityInput carries what a peer needs to judge an observed lease
// beyond the raw expiry clock.
type ValidityInput struct {
	Now                     time.Time
	AuthoritativeGeneration uint64 // the evaluating node's belief of current authoritative gen
	OwnerCurrentIncarnation uint64 // the owner's currently-announced incarnation
}

// Validity is the decomposed result of evaluating an observed lease, so
// the API can show WHY a lease is or isn't valid — not just a boolean.
type Validity struct {
	Valid         bool   `json:"valid"`
	ClockOK       bool   `json:"clock_ok"`         // expires_at > now
	GenerationOK  bool   `json:"generation_ok"`    // gen matches authoritative
	IncarnationOK bool   `json:"incarnation_ok"`   // incarnation matches current
	Reason        string `json:"reason,omitempty"` // first failing check, for humans
}

// Evaluate applies the three-part validity rule to an observed lease.
func (l Lease) Evaluate(in ValidityInput) Validity {
	v := Validity{
		ClockOK:       !l.Expired(in.Now),
		GenerationOK:  l.Generation == in.AuthoritativeGeneration,
		IncarnationOK: l.Incarnation == in.OwnerCurrentIncarnation,
	}
	v.Valid = v.ClockOK && v.GenerationOK && v.IncarnationOK

	// Record the first failing reason (ordered: clock, generation, incarnation).
	switch {
	case !v.ClockOK:
		v.Reason = "expired"
	case !v.GenerationOK:
		v.Reason = "stale generation (minority/partition)"
	case !v.IncarnationOK:
		v.Reason = "stale incarnation (owner restarted)"
	}
	return v
}
