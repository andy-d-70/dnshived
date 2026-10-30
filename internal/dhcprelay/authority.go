// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcprelay

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"dnshived/internal/arbiter"
	"dnshived/internal/gate"
)

const (
	clockStateError   = 5         // TIME_ERROR from adjtimex
	clockUnsynced     = 0x0040    // STA_UNSYNC
	clockMaxError     = 2_000_000 // µs: the 2 s skew limit, judged by maxerror (RELAY_GATE §4)
	gateCheckInterval = 250 * time.Millisecond
)

// scopeGate is one scope's authority. deadline is unix nanoseconds, 0 when closed; the packet path reads it
// without a lock.
type scopeGate struct {
	name     string
	deadline atomic.Int64
	eligible bool   // last state written to the track file; guarded by gateTable.mu
	reason   string // last open or close reason; guarded by gateTable.mu
}

// gateTable holds every scope's gate and the node's own gate settings.
type gateTable struct {
	mu        sync.Mutex
	scopes    map[string]*scopeGate
	psk       []byte
	nodeID    string
	coreCount int
	runDir    string
	clockOK   atomic.Bool
}

func newGateTable() *gateTable {
	return &gateTable{scopes: make(map[string]*scopeGate)}
}

// clockHealthy reports whether the adjtimex result is a synchronised clock within the skew limit.
func clockHealthy(state int, tx syscall.Timex) bool {
	return state != clockStateError && tx.Status&clockUnsynced == 0 && tx.Maxerror <= clockMaxError
}

// allows is the packet path's check: one atomic clock read, one atomic deadline read, no lock.
func (t *gateTable) allows(g *scopeGate, now time.Time) bool {
	if g == nil || !t.clockOK.Load() {
		return false
	}
	d := g.deadline.Load()
	return d != 0 && now.UnixNano() < d
}

// scope returns name's gate, creating it closed. The track file is written as fault on creation.
func (t *gateTable) scope(name string) *scopeGate {
	t.mu.Lock()
	defer t.mu.Unlock()
	if g, ok := t.scopes[name]; ok {
		return g
	}
	g := &scopeGate{name: name, reason: "not authorized"}
	t.scopes[name] = g
	t.writeTrackLocked(g, false)
	return g
}

func (t *gateTable) applyConfig(nodeID string, coreCount int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nodeID = nodeID
	t.coreCount = coreCount
}

// setRunDir sets the track-file directory and writes every existing scope's current state there.
func (t *gateTable) setRunDir(dir string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.runDir = dir
	for _, g := range t.scopes {
		t.writeTrackLocked(g, g.eligible)
	}
}

func (t *gateTable) setPSK(psk []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.psk = psk
}

// authorize verifies tokens for scope and opens its gate until the earliest counted expiry minus the margin.
func (t *gateTable) authorize(scope string, tokens []json.RawMessage, incarnation uint64, requested int, daemonReason string, now time.Time) (time.Time, error) {
	toks := make([]arbiter.Token, 0, len(tokens))
	for _, raw := range tokens {
		tok, err := parseToken(raw)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid request: token: %w", err)
		}
		toks = append(toks, tok)
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.psk) == 0 {
		return time.Time{}, errors.New("no PSK set (set-psk first)")
	}
	if t.nodeID == "" {
		return time.Time{}, errors.New("node_id not configured")
	}
	if t.coreCount < 1 {
		return time.Time{}, errors.New("core_count not configured")
	}
	g, ok := t.scopes[scope]
	if !ok {
		return time.Time{}, fmt.Errorf("unknown scope %q", scope)
	}

	res, err := gate.Authorize(toks, t.psk, scope, t.nodeID, incarnation, t.coreCount/2+1, requested, now)
	if err != nil {
		log.Printf("[RELAY:GATE] authorize scope %s rejected: %v (daemon reason: %s)", scope, err, daemonReason)
		return time.Time{}, err
	}
	if res.Lowered {
		log.Printf("[RELAY:GATE] quorum lowered to %d for scope %s (daemon reason: %s)", requested, scope, daemonReason)
	}
	g.deadline.Store(res.Deadline.UnixNano())
	g.reason = fmt.Sprintf("authorized by %d arbiter(s)", res.Arbiters)
	t.evaluateLocked(now)
	return res.Deadline, nil
}

func parseToken(raw json.RawMessage) (arbiter.Token, error) {
	var tok arbiter.Token
	if len(raw) > 0 && raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return tok, err
		}
		raw = json.RawMessage(s)
	}
	err := json.Unmarshal(raw, &tok)
	return tok, err
}

// revoke closes scope now, with no proof needed.
func (t *gateTable) revoke(scope, reason string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if g, ok := t.scopes[scope]; ok {
		g.deadline.Store(0)
		g.reason = reason
		t.evaluateLocked(now)
	}
}

func (t *gateTable) revokeAll(reason string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, g := range t.scopes {
		g.deadline.Store(0)
		g.reason = reason
	}
	t.evaluateLocked(now)
}

// retain closes and forgets every scope not in keep.
func (t *gateTable) retain(keep map[string]bool, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for name, g := range t.scopes {
		if keep[name] {
			continue
		}
		g.deadline.Store(0)
		g.reason = "scope removed from configuration"
		t.evaluateLocked(now)
		delete(t.scopes, name)
	}
}

// checkClock records the clock state and re-evaluates every gate.
func (t *gateTable) checkClock(now time.Time) {
	var tx syscall.Timex
	state, err := syscall.Adjtimex(&tx)
	healthy := err == nil && clockHealthy(state, tx)

	t.mu.Lock()
	defer t.mu.Unlock()
	if healthy != t.clockOK.Load() {
		t.clockOK.Store(healthy)
		if healthy {
			log.Printf("[RELAY:GATE] clock healthy again")
		} else {
			log.Printf("[RELAY:GATE] clock unhealthy (adjtimex state %d, maxerror %d µs, err %v): every scope closed", state, tx.Maxerror, err)
		}
	}
	t.evaluateLocked(now)
}

// evaluateLocked closes gates whose deadline has passed and writes the track file on every change. Caller holds t.mu.
func (t *gateTable) evaluateLocked(now time.Time) {
	clockOK := t.clockOK.Load()
	for _, g := range t.scopes {
		d := g.deadline.Load()
		if d != 0 && now.UnixNano() >= d {
			g.deadline.Store(0)
			g.reason = "deadline reached"
			d = 0
		}
		eligible := clockOK && d != 0
		if eligible == g.eligible {
			continue
		}
		g.eligible = eligible
		if eligible {
			log.Printf("[RELAY:GATE] scope %s opened until %s (%s)", g.name, time.Unix(0, d).Format(time.RFC3339Nano), g.reason)
		} else {
			reason := g.reason
			if !clockOK {
				reason = "clock unhealthy"
			}
			log.Printf("[RELAY:GATE] scope %s closed: %s", g.name, reason)
		}
		t.writeTrackLocked(g, eligible)
	}
}

// writeTrackLocked writes the scope's track file (keepalived reads it for the VIP). Caller holds t.mu.
func (t *gateTable) writeTrackLocked(g *scopeGate, eligible bool) {
	if t.runDir == "" {
		return
	}
	state := "fault\n"
	if eligible {
		state = "eligible\n"
	}
	path := filepath.Join(t.runDir, g.name+".track")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(state), 0o644); err != nil {
		log.Printf("[RELAY:GATE] write track file %s: %v", path, err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("[RELAY:GATE] write track file %s: %v", path, err)
	}
}
