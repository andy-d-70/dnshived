// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package desired

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// MaxAnnouncedOwners bounds how many scopes a node announces per scope in
// its handshake; larger maps are announced by hash only.
const MaxAnnouncedOwners = 512

const maxDetailScopes = 20

// splitWarnAfter exceeds DefaultUnservedGrace: a split that grace heals
// (a restarted owner) is logged as healed, not warned.
const (
	splitWarnAfter = 45 * time.Second
	splitRepeat    = 5 * time.Minute
	splitLogMin    = 5 * time.Second
)

func OwnerMap(assignments []Assignment) map[string]string {
	out := make(map[string]string, len(assignments))
	for _, a := range assignments {
		out[a.Scope] = a.Owner
	}
	return out
}

// MapHash identifies a map's contents independent of assignment order.
func MapHash(owners map[string]string) string {
	scopes := make([]string, 0, len(owners))
	for s := range owners {
		scopes = append(scopes, s)
	}
	sort.Strings(scopes)
	h := sha256.New()
	for _, s := range scopes {
		h.Write([]byte(s))
		h.Write([]byte{0})
		h.Write([]byte(owners[s]))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

func DisputedScopes(here, peer map[string]string) []string {
	var out []string
	for s, h := range here {
		if p, ok := peer[s]; !ok || p != h {
			out = append(out, s)
		}
	}
	for s := range peer {
		if _, ok := here[s]; !ok {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// DiffOwners lists the scopes two maps disagree on, sorted, as
// "scope: here=X peer=Y".
func DiffOwners(here, peer map[string]string) []string {
	seen := make(map[string]bool, len(here)+len(peer))
	var out []string
	add := func(scope string) {
		if seen[scope] {
			return
		}
		seen[scope] = true
		h, hok := here[scope]
		p, pok := peer[scope]
		if hok && pok && h == p {
			return
		}
		out = append(out, scope+": here="+ownerOrMissing(h, hok)+" peer="+ownerOrMissing(p, pok))
	}
	for s := range here {
		add(s)
	}
	for s := range peer {
		add(s)
	}
	sort.Strings(out)
	return out
}

func ownerOrMissing(owner string, ok bool) string {
	if !ok {
		return "missing"
	}
	return ownerLabel(owner)
}

// JoinDiff joins DiffOwners lines for a log line, listing at most
// maxDetailScopes of them.
func JoinDiff(lines []string) string {
	if len(lines) <= maxDetailScopes {
		return strings.Join(lines, "; ")
	}
	return fmt.Sprintf("%s; (+%d more)", strings.Join(lines[:maxDetailScopes], "; "), len(lines)-maxDetailScopes)
}

// SplitTracker debounces "same generation, different map" per peer.
type SplitTracker struct {
	since   map[string]time.Time
	lastLog map[string]time.Time
}

func NewSplitTracker() *SplitTracker {
	return &SplitTracker{since: make(map[string]time.Time), lastLog: make(map[string]time.Time)}
}

type SplitAction int

const (
	SplitNone SplitAction = iota
	SplitWarn
	SplitResolved
	SplitHealed // ended before a warning, lasted at least splitLogMin
)

func (t *SplitTracker) Observe(now time.Time, peer string, split bool) (SplitAction, time.Duration) {
	since, tracked := t.since[peer]
	if !split {
		_, warned := t.lastLog[peer]
		delete(t.since, peer)
		delete(t.lastLog, peer)
		switch {
		case tracked && warned:
			return SplitResolved, now.Sub(since)
		case tracked && now.Sub(since) >= splitLogMin:
			return SplitHealed, now.Sub(since)
		}
		return SplitNone, 0
	}
	if !tracked {
		t.since[peer] = now
		return SplitNone, 0
	}
	if now.Sub(since) < splitWarnAfter {
		return SplitNone, 0
	}
	if last, warned := t.lastLog[peer]; warned && now.Sub(last) < splitRepeat {
		return SplitNone, 0
	}
	t.lastLog[peer] = now
	return SplitWarn, now.Sub(since)
}

func (t *SplitTracker) Forget(keep map[string]bool) {
	for p := range t.since {
		if !keep[p] {
			delete(t.since, p)
			delete(t.lastLog, p)
		}
	}
}
