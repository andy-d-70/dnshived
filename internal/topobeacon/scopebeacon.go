// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package topobeacon

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"dnshived/internal/psksign"
)

// ScopePort is the dedicated port for the routed, unicast, per-scope
// liveness beacon.
const ScopePort = 9447

// ScopeMagic guards a scope-beacon packet from ever being mistaken for the
// unrelated broadcast Beacon type above, or vice versa.
const ScopeMagic = "DNSHIVED-SCOPE-BEACON-V1"

const ScopeBeaconInterval = 2 * time.Second

// scopeStaleAfterMisses: this many CONSECUTIVE missed replies before a
// (scope, peer) pairing is reported as unreachable.
const scopeStaleAfterMisses = 3

// scopeRequest/scopeReply are the small JSON payloads exchanged —
// request/reply, unicast, unlike the broadcast-only Beacon above.
type scopeRequest struct {
	Magic     string `json:"magic"`
	Role      string `json:"role"`
	Scope     string `json:"scope"`
	Nonce     uint64 `json:"nonce"`
	Signature string `json:"signature"`
}

// signData returns the canonical string this request's signature covers.
func (r *scopeRequest) signData() string {
	return fmt.Sprintf("%s:%s:%s:%d", r.Magic, r.Role, r.Scope, r.Nonce)
}

func (r *scopeRequest) Sign(psk []byte) string { return psksign.Sign(psk, r.signData()) }
func (r *scopeRequest) Verify(psk []byte) bool {
	return psksign.Verify(psk, r.signData(), r.Signature)
}

type scopeReply struct {
	Magic     string `json:"magic"`
	Role      string `json:"role"`
	Scope     string `json:"scope"`
	Nonce     uint64 `json:"nonce"`
	Signature string `json:"signature"`
}

func (r *scopeReply) signData() string {
	return fmt.Sprintf("%s:%s:%s:%d", r.Magic, r.Role, r.Scope, r.Nonce)
}

func (r *scopeReply) Sign(psk []byte) string { return psksign.Sign(psk, r.signData()) }
func (r *scopeReply) Verify(psk []byte) bool {
	return psksign.Verify(psk, r.signData(), r.Signature)
}

// randomScopeNonce returns a cryptographically random nonce — not an
// incrementing counter.
func randomScopeNonce() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return binary.BigEndian.Uint64(b[:])
}

type ScopeTarget struct {
	Scope     string
	LocalAddr string // this node's own real node_ip (bare, no /prefix) on Scope
	PeerRole  string
	PeerAddr  string // peer's own real node_ip (bare, no /prefix) on Scope
}

// ScopeStatus is one (scope, peer) pairing's current liveness belief.
type ScopeStatus struct {
	Scope             string    `json:"scope"`
	PeerRole          string    `json:"peer_role"`
	Reachable         bool      `json:"reachable"`
	ConsecutiveMisses int       `json:"consecutive_misses"`
	LastChecked       time.Time `json:"last_checked"`
	// Parent/VLANID: the scope's trunk and VLAN, filled in by the agent (this
	// package doesn't know scope config) so the web UI can list VLAN paths
	// under their trunk.
	Parent string `json:"parent,omitempty"`
	VLANID int    `json:"vlan_id,omitempty"`

	// everReachable tracks whether this pairing has ever had a real confirmed
	// success.
	everReachable bool
}

// ScopeMonitor tracks live (scope, peer) reachability state across
// repeated beacon rounds.
type ScopeMonitor struct {
	mu      sync.Mutex
	entries map[string]*ScopeStatus // key: scope+"|"+peerRole
	// onUnreachable, when set, is called exactly once per transition INTO the
	// unreachable state (edge-triggered, not every miss).
	onUnreachable func(scope, peerRole string)
}

func scopeKey(scope, peerRole string) string { return scope + "|" + peerRole }

// NewScopeMonitor creates a ScopeMonitor.
func NewScopeMonitor(onUnreachable func(scope, peerRole string)) *ScopeMonitor {
	return &ScopeMonitor{entries: make(map[string]*ScopeStatus), onUnreachable: onUnreachable}
}

// recordResult updates one (scope, peerRole) pairing's state after a
// single beacon round.
func (m *ScopeMonitor) recordResult(scope, peerRole string, ok bool) {
	if notify := m.applyResult(scope, peerRole, ok); notify != nil {
		notify()
	}
}

// applyResult updates the pairing's state and returns the edge-triggered
// unreachable callback to run, if any, without running it.
func (m *ScopeMonitor) applyResult(scope, peerRole string, ok bool) func() {
	m.mu.Lock()
	key := scopeKey(scope, peerRole)
	e, exists := m.entries[key]
	wasReachable := true
	if exists {
		wasReachable = e.Reachable
	} else {
		e = &ScopeStatus{Scope: scope, PeerRole: peerRole}
		m.entries[key] = e
	}
	e.LastChecked = time.Now()
	if ok {
		e.ConsecutiveMisses = 0
		e.Reachable = true
		e.everReachable = true
	} else {
		e.ConsecutiveMisses++
		if e.everReachable {
			// The 3-miss debounce tolerance is earned by a target that
			// was previously confirmed reachable and just blipped.
			e.Reachable = e.ConsecutiveMisses < scopeStaleAfterMisses
		} else {
			e.Reachable = false
		}
	}
	justWentUnreachable := wasReachable && !e.Reachable
	cb := m.onUnreachable
	m.mu.Unlock()

	if justWentUnreachable && cb != nil {
		return func() { cb(scope, peerRole) }
	}
	return nil
}

// Snapshot returns every currently-tracked (scope, peer) pairing's status,
// sorted deterministically (Scope, then PeerRole).
func (m *ScopeMonitor) Snapshot() []ScopeStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ScopeStatus, 0, len(m.entries))
	for _, e := range m.entries {
		out = append(out, *e)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && scopeStatusLess(out[j], out[j-1]); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// Remove drops a (scope, peerRole) pairing from the tracked set entirely.
func (m *ScopeMonitor) Remove(scope, peerRole string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, scopeKey(scope, peerRole))
}

func scopeStatusLess(a, b ScopeStatus) bool {
	if a.Scope != b.Scope {
		return a.Scope < b.Scope
	}
	return a.PeerRole < b.PeerRole
}

// ListenScopeBeacons binds one real, routed (NOT SO_BINDTODEVICE) UDP
// socket per entry in localAddrs.
func ListenScopeBeacons(ctx context.Context, role string, localAddrs []string, psk []byte) {
	for _, addr := range localAddrs {
		addr := addr
		go listenScopeBeaconOnAddr(ctx, role, addr, psk)
	}
}

func listenScopeBeaconOnAddr(ctx context.Context, role, addr string, psk []byte) {
	laddr := &net.UDPAddr{IP: net.ParseIP(addr), Port: ScopePort}
	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		log.Printf("[TOPOBEACON:ERROR] bind scope-beacon listen socket on %s: %v", addr, err)
		return
	}
	defer conn.Close()
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	buf := make([]byte, 1024)
	for {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return // ctx done (socket closed above) or a real read error either way
		}
		var req scopeRequest
		if err := json.Unmarshal(buf[:n], &req); err != nil {
			continue
		}
		if req.Magic != ScopeMagic || req.Scope == "" || req.Role == "" {
			continue
		}
		if !req.Verify(psk) {
			continue
		}
		reply := scopeReply{Magic: ScopeMagic, Role: role, Scope: req.Scope, Nonce: req.Nonce}
		reply.Signature = reply.Sign(psk)
		replyBytes, err := json.Marshal(reply)
		if err != nil {
			continue
		}
		conn.WriteToUDP(replyBytes, raddr)
	}
}

// ScopeListenerRunner tracks the currently-bound set of per-address
// listening goroutines, diffing a later Update call's address set against
// what's already bound.
type ScopeListenerRunner struct {
	mu      sync.Mutex
	role    string
	psk     []byte
	running map[string]context.CancelFunc // key: bare local address
}

// NewScopeListenerRunner creates a runner.
func NewScopeListenerRunner(role string, psk []byte) *ScopeListenerRunner {
	return &ScopeListenerRunner{role: role, psk: psk, running: make(map[string]context.CancelFunc)}
}

func (r *ScopeListenerRunner) Update(ctx context.Context, addrs []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	wanted := make(map[string]bool, len(addrs))
	for _, addr := range addrs {
		wanted[addr] = true
	}

	for addr, cancel := range r.running {
		if wanted[addr] {
			continue
		}
		cancel()
		delete(r.running, addr)
	}

	for addr := range wanted {
		if _, exists := r.running[addr]; exists {
			continue // unchanged — leave its own listener goroutine alone
		}
		actx, cancel := context.WithCancel(ctx)
		r.running[addr] = cancel
		go listenScopeBeaconOnAddr(actx, r.role, addr, r.psk)
	}
}

type ScopeBeaconRunner struct {
	mu      sync.Mutex
	role    string
	psk     []byte
	monitor *ScopeMonitor
	running map[string]runningScopeBeacon // key: scopeKey(scope, peerRole)
	nextID  uint64
}

// runningScopeBeacon pairs a target's own cancel func with the (scope,
// peerRole) it belongs to.
type runningScopeBeacon struct {
	id              uint64
	cancel          context.CancelFunc
	scope, peerRole string
	target          ScopeTarget
}

// NewScopeBeaconRunner creates a runner.
func NewScopeBeaconRunner(role string, psk []byte, monitor *ScopeMonitor) *ScopeBeaconRunner {
	return &ScopeBeaconRunner{role: role, psk: psk, monitor: monitor, running: make(map[string]runningScopeBeacon)}
}

func (r *ScopeBeaconRunner) Update(ctx context.Context, targets []ScopeTarget) {
	r.mu.Lock()
	defer r.mu.Unlock()

	wanted := make(map[string]ScopeTarget, len(targets))
	for _, t := range targets {
		wanted[scopeKey(t.Scope, t.PeerRole)] = t
	}

	for key, rb := range r.running {
		t, ok := wanted[key]
		if ok && t == rb.target {
			continue
		}
		rb.cancel()
		delete(r.running, key)
		r.monitor.Remove(rb.scope, rb.peerRole)
	}

	for key, t := range wanted {
		if _, exists := r.running[key]; exists {
			continue // unchanged — leave its own goroutine/state alone
		}
		tctx, cancel := context.WithCancel(ctx)
		r.nextID++
		id := r.nextID
		r.running[key] = runningScopeBeacon{id: id, cancel: cancel, scope: t.Scope, peerRole: t.PeerRole, target: t}
		go runOneScopeBeacon(tctx, r.role, t, func(ok bool) { r.record(key, id, t, ok) }, r.psk)
	}
}

// record stores a beacon result only while that exact pairing is still
// running, so a reply that lands after Update removed it can't re-create
// the entry.
func (r *ScopeBeaconRunner) record(key string, id uint64, t ScopeTarget, ok bool) {
	r.mu.Lock()
	rb, live := r.running[key]
	var notify func()
	if live && rb.id == id {
		notify = r.monitor.applyResult(t.Scope, t.PeerRole, ok)
	}
	r.mu.Unlock()
	if notify != nil {
		notify()
	}
}

func runOneScopeBeacon(ctx context.Context, role string, t ScopeTarget, record func(ok bool), psk []byte) {
	ticker := time.NewTicker(ScopeBeaconInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ok := sendOneScopeBeacon(role, t, randomScopeNonce(), psk)
			if ctx.Err() != nil {
				return
			}
			record(ok)
		}
	}
}

// sendOneScopeBeacon fires one request/reply round trip.
func sendOneScopeBeacon(role string, t ScopeTarget, nonce uint64, psk []byte) bool {
	req := scopeRequest{Magic: ScopeMagic, Role: role, Scope: t.Scope, Nonce: nonce}
	req.Signature = req.Sign(psk)
	payload, err := json.Marshal(req)
	if err != nil {
		return false
	}
	conn, err := net.DialTimeout("udp4", net.JoinHostPort(t.PeerAddr, itoa(ScopePort)), ScopeBeaconInterval)
	if err != nil {
		return false
	}
	defer conn.Close()
	uc, ok := conn.(*net.UDPConn)
	if !ok {
		return false
	}
	if _, err := uc.Write(payload); err != nil {
		return false
	}
	// Timeout shorter than the interval so a slow/missing reply never
	// overlaps the NEXT tick's own send for the same target.
	uc.SetReadDeadline(time.Now().Add(ScopeBeaconInterval * 3 / 4))
	buf := make([]byte, 1024)
	n, err := uc.Read(buf)
	if err != nil {
		return false
	}
	var reply scopeReply
	if err := json.Unmarshal(buf[:n], &reply); err != nil {
		return false
	}
	return reply.Magic == ScopeMagic && reply.Scope == t.Scope && reply.Nonce == nonce && reply.Verify(psk)
}
