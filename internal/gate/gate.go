// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package gate holds the relay's authority checks: token verification, deadline and quorum. It has no I/O,
// so the relay and its tests use the same code.
package gate

import (
	"errors"
	"fmt"
	"time"

	"dnshived/internal/arbiter"
)

// DeadlineMargin is subtracted from the earliest expiry of the counted tokens.
const DeadlineMargin = 3 * time.Second

// MaxAhead is how far in the future a token's expiry may be.
const MaxAhead = time.Minute

// CheckError names the first failed check, using the reason strings of SOCKET_PROTOCOL §3.
type CheckError struct {
	Reason string
}

func (e *CheckError) Error() string { return e.Reason }

// Verify runs checks 1-5 of SOCKET_PROTOCOL §3 in order: signature, scope, owner, incarnation, expiry.
func Verify(tok arbiter.Token, psk []byte, scope, owner string, incarnation uint64, now time.Time) error {
	if !tok.Verify(psk) {
		return &CheckError{Reason: "signature"}
	}
	if tok.Scope != scope {
		return &CheckError{Reason: "scope"}
	}
	if tok.Owner != owner {
		return &CheckError{Reason: "owner"}
	}
	if tok.Incarnation != incarnation {
		return &CheckError{Reason: "incarnation"}
	}
	if !tok.ExpiresAt.After(now) {
		return &CheckError{Reason: "expired"}
	}
	if tok.ExpiresAt.Sub(now) > MaxAhead {
		return &CheckError{Reason: "too far ahead"}
	}
	return nil
}

// RequiredQuorum returns the number of distinct arbiters needed. The configured count is the majority of the
// configured cores. A request may lower it (never below 1) and the caller logs the lowering; it never raises it.
func RequiredQuorum(configured, requested int) (int, bool, error) {
	if configured < 1 {
		return 0, false, errors.New("configured quorum must be at least 1")
	}
	if requested == 0 || requested >= configured {
		return configured, false, nil
	}
	if requested < 1 {
		return 0, false, fmt.Errorf("requested quorum %d below 1", requested)
	}
	return requested, true, nil
}

// Result is the outcome of authorizing one scope from a token set.
type Result struct {
	Deadline time.Time
	Arbiters int
	Lowered  bool
}

// Authorize verifies every token, counts distinct non-empty arbiters among the valid ones, and sets the deadline
// from the earliest expiry among the counted tokens minus DeadlineMargin. A token that fails any check is
// ignored and reported in the error only if the quorum is not reached.
func Authorize(tokens []arbiter.Token, psk []byte, scope, owner string, incarnation uint64, configured, requested int, now time.Time) (Result, error) {
	required, lowered, err := RequiredQuorum(configured, requested)
	if err != nil {
		return Result{}, err
	}
	distinct := make(map[string]time.Time)
	var firstFailure error
	for _, tok := range tokens {
		if err := Verify(tok, psk, scope, owner, incarnation, now); err != nil {
			if firstFailure == nil {
				firstFailure = err
			}
			continue
		}
		if tok.Arbiter == "" {
			continue
		}
		if prev, seen := distinct[tok.Arbiter]; !seen || tok.ExpiresAt.Before(prev) {
			distinct[tok.Arbiter] = tok.ExpiresAt
		}
	}
	if len(distinct) < required {
		if firstFailure != nil {
			return Result{}, firstFailure
		}
		return Result{}, &CheckError{Reason: "quorum"}
	}
	var earliest time.Time
	for _, exp := range distinct {
		if earliest.IsZero() || exp.Before(earliest) {
			earliest = exp
		}
	}
	return Result{Deadline: earliest.Add(-DeadlineMargin), Arbiters: len(distinct), Lowered: lowered}, nil
}
