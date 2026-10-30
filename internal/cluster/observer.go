// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package cluster provides peer awareness for dnshived.
package cluster

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"dnshived/internal/config"
	"dnshived/internal/fencing"
	"dnshived/internal/identity"
	"dnshived/internal/lease"
	"dnshived/internal/loglevel"
	"dnshived/internal/quorum"
	"dnshived/internal/reliability"
	"dnshived/internal/tlspin"
	"dnshived/internal/trustedhosts"
)

const pingSigHeader = "X-Dnshived-Ping-Sig"

// signedPing POSTs a ping. With a PSK the body is signed, so the responder can verify the caller (F5).
func signedPing(client *http.Client, url string, body []byte, psk []byte) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if len(psk) > 0 {
		req.Header.Set(pingSigHeader, signPingBody(psk, body))
	}
	return client.Do(req)
}

// signPingBody returns the hex HMAC-SHA256 of body under psk.
func signPingBody(psk []byte, body []byte) string {
	mac := hmac.New(sha256.New, psk)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// maxIdentityBodyBytes bounds any wire-decoded identity.Identity payload.
const maxIdentityBodyBytes = 64 * 1024

// PeerState is the observed state of a single peer.
type PeerState struct {
	Addr      string `json:"addr"`
	Reachable bool   `json:"reachable"`
	LastSeen  int64  `json:"last_seen"` // unix seconds, 0 = never
	LastError string `json:"last_error,omitempty"`
	RTTms     int64  `json:"rtt_ms"`
	Checks    uint64 `json:"checks"`
	Failures  uint64 `json:"failures"`

	// UnreachableSince is the unix timestamp when this peer last transitioned
	// from reachable to unreachable.
	UnreachableSince int64 `json:"unreachable_since,omitempty"`

	// ReachableSince is the unix timestamp of this peer's most recent
	// unreachable→reachable transition.
	ReachableSince int64 `json:"reachable_since,omitempty"`

	// ExcludedFromQuorum is true once this CONFIGURED peer has been
	// continuously unreachable for at least failGracePeriod.
	ExcludedFromQuorum bool `json:"excluded_from_quorum,omitempty"`

	// StateChanges is a bounded ring of recent reachability transitions.
	StateChanges []StateChange `json:"state_changes,omitempty"`

	// Identity claimed by the peer in its last successful handshake.
	Identity *identity.Identity `json:"identity,omitempty"`
	// IdentityMismatch is set when the peer reports a different cluster_id
	// than ours — a misconfiguration we surface but never act on.
	ClusterMismatch bool `json:"cluster_mismatch,omitempty"`
}

// FallbackStatus is a SECOND, independent liveness check against another
// core role over its own scope-VLAN address instead of the primary mgmt/
// control address.
type FallbackStatus struct {
	Role string `json:"role"`
	// Parent is the physical trunk this path runs over (e.g. "ens19").
	Parent    string `json:"parent"`
	Addr      string `json:"addr"`
	Reachable bool   `json:"reachable"`
	LastError string `json:"last_error,omitempty"`
	// Score is a light, single-dimension, PROCESS-LOCAL trust index (0-100)
	// for this ONE path.
	Score int `json:"score"`
}

// StateChange records a single reachability transition for a peer.
type StateChange struct {
	Reachable bool  `json:"reachable"`
	At        int64 `json:"at"` // unix seconds
}

const maxStateChanges = 16

// Observer tracks reachability and identity of all configured peers.
type Observer struct {
	mu       sync.RWMutex
	self     identity.Identity
	selfAddr string
	peers    map[string]*PeerState
	started  time.Time
	quit     chan struct{}
	// probeTicker is the live handshake-cycle ticker loop() creates.
	probeTicker *time.Ticker
	client      *http.Client
	cycles      uint64 // completed probe cycles
	// scheme is "https" when the cluster is configured with tls_cert/tls_key
	// (see SetTLS).
	scheme string

	// changed signals a peer reachability transition.
	changed chan struct{}

	// psk authenticates /api/v1/ping responses — see pingSigHeader's doc
	// comment.
	psk []byte

	// trustedHosts gates WHO may call HandlePing at all.
	trustedHosts trustedhosts.Set

	fallbackAddrs map[string]map[string]string

	fallbackStatus map[string]map[string]FallbackStatus

	// departedRoles are roles RemovePeer cleared; ObserveMgmtBeacon stops
	// recreating their mgmt entry until the role is heard or claimed by a peer
	// again.
	departedRoles map[string]bool

	// pathReliability persists this node's own view of reaching each (role,
	// trunk) fallback path.
	pathReliability *reliability.Store

	// failGracePeriod / reconnectGracePeriod drive PeerState.
	failGracePeriod      time.Duration
	reconnectGracePeriod time.Duration
}

// NewObserver creates an observer.
func NewObserver(self identity.Identity, selfAddr string, peerAddrs []string, psk string) *Observer {
	o := &Observer{
		self:                 self,
		selfAddr:             selfAddr,
		peers:                make(map[string]*PeerState),
		started:              time.Now(),
		quit:                 make(chan struct{}),
		changed:              make(chan struct{}, 1),
		psk:                  []byte(psk),
		pathReliability:      reliability.NewStore(""),
		failGracePeriod:      time.Minute,
		reconnectGracePeriod: time.Minute,
		client: &http.Client{
			Timeout: 2 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:      10,
				MaxConnsPerHost:   2,
				IdleConnTimeout:   30 * time.Second,
				DisableKeepAlives: false,
				DialContext:       (&net.Dialer{Timeout: 1 * time.Second}).DialContext,
			},
		},
	}
	for _, addr := range peerAddrs {
		o.peers[addr] = &PeerState{Addr: addr}
	}
	o.scheme = "http"
	return o
}

// SetTLS tells the observer whether the cluster's HTTP API (this node's
// own listener, and by implication every peer's) is HTTPS.
func (o *Observer) SetTLS(useTLS bool) {
	if useTLS {
		o.scheme = "https"
		o.client.Transport = &http.Transport{
			MaxIdleConns:      10,
			MaxConnsPerHost:   2,
			IdleConnTimeout:   30 * time.Second,
			DisableKeepAlives: false,
			DialContext:       (&net.Dialer{Timeout: 1 * time.Second}).DialContext,
			TLSClientConfig:   tlspin.Config(),
		}
	}
}

// SetTrustedHosts installs a source-IP allowlist for HandlePing — see
// trustedHosts' own field doc comment.
func (o *Observer) SetTrustedHosts(hosts []string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.trustedHosts = trustedhosts.New(hosts)
}

func (o *Observer) SetGracePeriods(fail, reconnect time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if fail > 0 {
		o.failGracePeriod = fail
	}
	if reconnect > 0 {
		o.reconnectGracePeriod = reconnect
	}
}

// SetFallbackAddrs installs the role -> trunk -> scope-VLAN-address map
// probeFallbackSweep consults — see fallbackAddrs' own field doc
// comment.
func (o *Observer) SetFallbackAddrs(targets map[string]map[string]string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.fallbackAddrs = targets
	for role, byParent := range o.fallbackStatus {
		for parent := range byParent {
			if parent == mgmtParentKey {
				continue
			}
			if _, ok := targets[role][parent]; !ok {
				delete(byParent, parent)
			}
		}
		if len(byParent) == 0 {
			delete(o.fallbackStatus, role)
		}
	}
}

func (o *Observer) Start(interval time.Duration) {
	go o.loop(interval)
}

// SetProbeInterval changes the live handshake-cycle interval without
// restarting the daemon.
func (o *Observer) SetProbeInterval(interval time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.probeTicker != nil {
		o.probeTicker.Reset(interval)
	}
}

// Changed signals a peer reachability transition.
func (o *Observer) Changed() <-chan struct{} {
	return o.changed
}

// signalChanged is called (under o.mu, already held by every call site) at
// each reachability transition.
func (o *Observer) signalChanged() {
	select {
	case o.changed <- struct{}{}:
	default:
	}
}

func (o *Observer) loop(interval time.Duration) {
	// Initial jitter: stagger the first probe to prevent synchronized storms
	// when all nodes start simultaneously (e.g., after a cluster restart).
	jitter := time.Duration(rand.Intn(1000)) * time.Millisecond
	time.Sleep(jitter)

	o.probeAll()
	o.mu.Lock()
	o.cycles++
	o.mu.Unlock()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	o.mu.Lock()
	o.probeTicker = ticker
	o.mu.Unlock()
	for {
		select {
		case <-o.quit:
			return
		case <-ticker.C:
			o.probeAll()
			o.mu.Lock()
			o.cycles++
			o.mu.Unlock()
		}
	}
}

// ObservedOnce reports whether at least one full probe cycle has
// completed.
func (o *Observer) ObservedOnce() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.cycles > 0
}

// UpdateSelf updates the mutable identity counters this node announces in
// handshakes.
func (o *Observer) UpdateSelf(epoch, generation uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.self.Epoch = epoch
	o.self.Generation = generation
}

// UpdateLeases sets the leases this node announces to peers.
func (o *Observer) UpdateLeases(leases map[string]lease.Lease) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(leases) == 0 {
		o.self.Leases = nil
		return
	}
	cp := make(map[string]lease.Lease, len(leases))
	for k, v := range leases {
		cp[k] = v
	}
	o.self.Leases = cp
}

// UpdateFencing sets this node's announced fencing token and quorum claim.
func (o *Observer) UpdateFencing(token fencing.Token, claimsQuorum bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.self.Token = token
	o.self.ClaimsQuorum = claimsQuorum
}

func (o *Observer) UpdateTrunkHealth(health map[string]bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(health) == 0 {
		o.self.TrunkHealth = nil
		return
	}
	cp := make(map[string]bool, len(health))
	for k, v := range health {
		cp[k] = v
	}
	o.self.TrunkHealth = cp
}

// PeerTrunkHealth returns role's own most-recently-announced TrunkHealth
// map.
func (o *Observer) PeerTrunkHealth(role string) map[string]bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	for _, ps := range o.peers {
		if ps.Identity != nil && ps.Identity.Role == role {
			return ps.Identity.TrunkHealth
		}
	}
	return nil
}

func (o *Observer) UpdateDesired(generation uint64, authoritative bool, hash string, owners map[string]string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.self.DesiredGeneration = generation
	o.self.DesiredAuthoritative = authoritative
	o.self.DesiredHash = hash
	o.self.DesiredOwners = owners
}

type PeerDesired struct {
	Role          string
	Generation    uint64
	Authoritative bool
	Hash          string
	Owners        map[string]string
}

func (o *Observer) PeerDesiredMaps() []PeerDesired {
	o.mu.RLock()
	defer o.mu.RUnlock()
	var out []PeerDesired
	for _, ps := range o.peers {
		id := ps.Identity
		if !ps.Reachable || id == nil || id.Role == "" || id.DesiredHash == "" {
			continue
		}
		out = append(out, PeerDesired{Role: id.Role, Generation: id.DesiredGeneration,
			Authoritative: id.DesiredAuthoritative, Hash: id.DesiredHash, Owners: id.DesiredOwners})
	}
	return out
}

// PeerServing returns each reachable, identified peer's own announced
// serving set, keyed by role.
func (o *Observer) PeerServing() map[string][]string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	out := make(map[string][]string)
	for _, ps := range o.peers {
		if ps.Reachable && ps.Identity != nil && ps.Identity.Role != "" {
			out[ps.Identity.Role] = append([]string(nil), ps.Identity.Serving...)
		}
	}
	return out
}

// UpdateServing sets the scopes this node announces as actively served.
func (o *Observer) UpdateServing(serving []string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(serving) == 0 {
		o.self.Serving = nil
		return
	}
	cp := make([]string, len(serving))
	copy(cp, serving)
	o.self.Serving = cp
}

// AdvanceWatermark advances the given watermark from observed peers,
// applying the anti-spoofing rule: a peer's token is adopted ONLY IF
func (o *Observer) AdvanceWatermark(wm *fencing.Watermark, myVerdict quorum.Verdict) (fencing.Token, bool) {
	// If WE don't see quorum, we adopt nothing — no authority to corroborate.
	if !myVerdict.HasQuorum {
		return wm.Current(), false
	}

	o.mu.RLock()
	// Always consider our own token (we have quorum, so our authority counts).
	best := o.self.Token
	for _, ps := range o.peers {
		if !ps.Reachable || ps.Identity == nil {
			continue
		}
		id := ps.Identity
		// Peer must claim quorum AND be a voter we can see (corroboration).
		if !id.ClaimsQuorum {
			continue
		}
		if !quorum.CanVote(id.Role) {
			continue
		}
		// Peer is reachable (loop condition) with a voting role and claims
		// quorum, and we independently have quorum → corroborated. Adopt.
		if id.Token.Compare(best) > 0 {
			best = id.Token
		}
	}
	o.mu.RUnlock()

	moved := wm.Advance(best)
	return wm.Current(), moved
}

func (o *Observer) probeAll() {
	o.mu.RLock()
	addrs := make([]string, 0, len(o.peers))
	for addr := range o.peers {
		addrs = append(addrs, addr)
	}
	o.mu.RUnlock()

	var wg sync.WaitGroup
	for _, addr := range addrs {
		wg.Add(1)
		go func(a string) {
			defer wg.Done()
			o.probe(a)
		}(addr)
	}
	wg.Wait()

	o.probeFallbackSweep()
}

// unreachableThreshold is how many CONSECUTIVE failed probes are required
// before a peer transitions to Reachable=false.
const unreachableThreshold = 2

// probe performs a /api/v1/ping handshake: we POST our identity, the peer
// replies with theirs.
func (o *Observer) probe(addr string) {
	start := time.Now()

	// Copy self under the read lock — UpdateSelf() may write o.self
	// concurrently (epoch changes from the FSM).
	o.mu.RLock()
	selfCopy := o.self
	o.mu.RUnlock()

	body, _ := json.Marshal(selfCopy)
	url := o.scheme + "://" + addr + "/api/v1/ping"
	resp, err := signedPing(o.client, url, body, o.psk)
	rtt := time.Since(start).Milliseconds()
	now := time.Now().Unix()

	o.mu.Lock()
	defer o.mu.Unlock()
	ps := o.peers[addr]
	if ps == nil {
		return
	}
	defer func() {
		wasExcluded := ps.ExcludedFromQuorum
		updateQuorumExclusion(ps, now, o.failGracePeriod, o.reconnectGracePeriod)
		if !wasExcluded && ps.ExcludedFromQuorum {
			loglevel.Warnf("[CLUSTER:QUORUM_EXCLUDE] peer %s excluded from EffectiveQuorum — unreachable for at least %s, may now serve standalone", peerNodeDesc(ps), o.failGracePeriod)
		} else if wasExcluded && !ps.ExcludedFromQuorum {
			loglevel.Infof("[CLUSTER:QUORUM_REINCLUDE] peer %s re-included in EffectiveQuorum — reachable again for at least %s", peerNodeDesc(ps), o.reconnectGracePeriod)
		}
	}()
	ps.Checks++

	wasReachable := ps.Reachable

	if err != nil {
		o.recordProbeFailure(ps, now, wasReachable, err.Error(), "last seen "+formatAge(now, ps.LastSeen)+" ago")
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxIdentityBodyBytes))
	if err != nil {
		o.recordProbeFailure(ps, now, wasReachable, "bad handshake response: "+err.Error(), "bad handshake")
		return
	}

	if len(o.psk) > 0 {
		sig := resp.Header.Get(pingSigHeader)
		if sig == "" || !hmac.Equal([]byte(signPingBody(o.psk, respBody)), []byte(sig)) {
			o.recordProbeFailure(ps, now, wasReachable, "handshake signature verification failed (possible spoofed/MITM peer response)", "signature verification failed")
			return
		}
	}

	var peerID identity.Identity
	if err := json.Unmarshal(respBody, &peerID); err != nil {
		o.recordProbeFailure(ps, now, wasReachable, "bad handshake response: "+err.Error(), "bad handshake")
		return
	}

	ps.Reachable = true
	ps.Failures = 0
	ps.LastError = ""
	ps.LastSeen = now
	ps.RTTms = rtt
	ps.Identity = &peerID
	ps.ClusterMismatch = peerID.ClusterID != o.self.ClusterID

	if !wasReachable && ps.Checks > 1 {
		// TRANSITION: unreachable → reachable (skip first probe: that's just
		// initial discovery, not a recovery event worth logging).
		downFor := ""
		if ps.UnreachableSince > 0 {
			downFor = ", was down " + formatAge(now, ps.UnreachableSince)
		}
		ps.UnreachableSince = 0
		ps.ReachableSince = now
		ps.pushStateChange(true, now)
		o.signalChanged()
		loglevel.Infof("[CLUSTER:REACHABLE] peer %s (%s)%s",
			peerID.NodeID, peerID.Role, downFor)
	}
}

// pathReliabilityKey is the o.pathReliability Store key for one (role,
// parent) fallback path.
func pathReliabilityKey(role, parent string) string {
	return role + "|" + parent
}

func (o *Observer) SetReliabilityDir(dataDir string) {
	if dataDir == "" {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.pathReliability = reliability.NewStore(filepath.Join(dataDir, "reliability-path.json"))
}

// PeerTrunkScore returns role's own most-recently-announced TrunkScore
// map.
func (o *Observer) PeerTrunkScore(role string) map[string]int {
	o.mu.RLock()
	defer o.mu.RUnlock()
	for _, ps := range o.peers {
		if ps.Identity != nil && ps.Identity.Role == role {
			return ps.Identity.TrunkScore
		}
	}
	return nil
}

func (o *Observer) UpdateTrunkScore(scores map[string]int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(scores) == 0 {
		o.self.TrunkScore = nil
		return
	}
	cp := make(map[string]int, len(scores))
	for k, v := range scores {
		cp[k] = v
	}
	o.self.TrunkScore = cp
}

// PathScore returns THIS node's own view of how reliably it has managed to
// reach role over parent.
func (o *Observer) PathScore(role, parent string) (score int, known bool) {
	e, ok := o.pathReliability.Get(pathReliabilityKey(role, parent))
	if !ok {
		return 0, false
	}
	return e.Score, true
}

// PathReliabilitySnapshot returns this node's own COMPLETE PATH
// reliability history.
func (o *Observer) PathReliabilitySnapshot() map[string]reliability.Entry {
	return o.pathReliability.Snapshot()
}

// ResetPathReliability clears this node's own persisted view of (role,
// parent) back to "never observed".
func (o *Observer) ResetPathReliability(role, parent string) {
	o.pathReliability.Reset(pathReliabilityKey(role, parent))
}

// RestorePathReliability replaces this node's own persisted PATH
// reliability history wholesale with entries from a backup.
func (o *Observer) RestorePathReliability(entries map[string]reliability.Entry) {
	o.pathReliability.RestoreAll(entries)
}

func (o *Observer) probeFallbackSweep() {
	o.mu.RLock()
	type target struct{ role, parent, addr string }
	var targets []target
	for role, byParent := range o.fallbackAddrs {
		for parent, addr := range byParent {
			targets = append(targets, target{role, parent, addr})
		}
	}
	selfCopy := o.self
	scheme := o.scheme
	psk := o.psk
	o.mu.RUnlock()

	if len(targets) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(t target) {
			defer wg.Done()
			result := FallbackStatus{Role: t.role, Parent: t.parent, Addr: t.addr}

			body, _ := json.Marshal(selfCopy)
			url := scheme + "://" + t.addr + "/api/v1/ping"
			resp, err := signedPing(o.client, url, body, psk)
			switch {
			case err != nil:
				result.LastError = err.Error()
			default:
				func() {
					defer resp.Body.Close()
					respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxIdentityBodyBytes))
					if err != nil {
						result.LastError = "bad handshake response: " + err.Error()
						return
					}
					if resp.StatusCode != http.StatusOK {
						result.LastError = fmt.Sprintf("status %d", resp.StatusCode)
						return
					}
					if len(psk) > 0 {
						sig := resp.Header.Get(pingSigHeader)
						if sig == "" || !hmac.Equal([]byte(signPingBody(psk, respBody)), []byte(sig)) {
							result.LastError = "handshake signature verification failed (possible spoofed/MITM peer response)"
							return
						}
					}
					var peerID identity.Identity
					if err := json.Unmarshal(respBody, &peerID); err != nil {
						result.LastError = "bad handshake response: " + err.Error()
						return
					}
					if peerID.Role != t.role {
						result.LastError = fmt.Sprintf("responder claims role %q, expected %q", peerID.Role, t.role)
						return
					}
					result.Reachable = true
				}()
			}

			result.Score = o.pathReliability.Observe(pathReliabilityKey(t.role, t.parent), result.Reachable)

			o.mu.Lock()
			if o.fallbackAddrs[t.role][t.parent] != t.addr {
				o.mu.Unlock()
				return
			}
			if o.fallbackStatus == nil {
				o.fallbackStatus = make(map[string]map[string]FallbackStatus)
			}
			if o.fallbackStatus[t.role] == nil {
				o.fallbackStatus[t.role] = make(map[string]FallbackStatus)
			}
			o.fallbackStatus[t.role][t.parent] = result
			o.mu.Unlock()
		}(t)
	}
	wg.Wait()
}

// mgmtParentKey is the canonical, LOGICAL parent name used for every
// mgmt-interface entry in fallbackStatus/pathReliability.
const mgmtParentKey = "mgmt"

func (o *Observer) ObserveMgmtBeacon(role string, heard bool) int {
	o.mu.Lock()
	if o.departedRoles[role] {
		if !heard && !o.peerClaimsRoleLocked(role) {
			o.mu.Unlock()
			return 0
		}
		delete(o.departedRoles, role)
	}
	o.mu.Unlock()
	score := o.pathReliability.Observe(pathReliabilityKey(role, mgmtParentKey), heard)

	result := FallbackStatus{Role: role, Parent: mgmtParentKey, Reachable: heard, Score: score}
	if !heard {
		result.LastError = "no mgmt-interface beacon heard recently"
	}

	o.mu.Lock()
	if o.fallbackStatus == nil {
		o.fallbackStatus = make(map[string]map[string]FallbackStatus)
	}
	if o.fallbackStatus[role] == nil {
		o.fallbackStatus[role] = make(map[string]FallbackStatus)
	}
	o.fallbackStatus[role][mgmtParentKey] = result
	o.mu.Unlock()
	return score
}

func (o *Observer) FallbackStatuses() []FallbackStatus {
	o.mu.RLock()
	defer o.mu.RUnlock()
	var out []FallbackStatus
	for _, byParent := range o.fallbackStatus {
		for _, fs := range byParent {
			out = append(out, fs)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Role != out[j].Role {
			return out[i].Role < out[j].Role
		}
		return out[i].Parent < out[j].Parent
	})
	return out
}

// RoleReachable reports whether role (never this node's own) is currently
// considered reachable.
func (o *Observer) RoleReachable(role string) (reachable bool, primaryAddr string) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	for _, ps := range o.peers {
		if ps.Identity == nil || ps.Identity.Role != role {
			continue
		}
		primaryAddr = ps.Addr
		if ps.Reachable {
			reachable = true
		}
	}
	if reachable {
		return true, primaryAddr
	}
	for _, fs := range o.fallbackStatus[role] {
		if fs.Reachable {
			return true, primaryAddr
		}
	}
	return false, primaryAddr
}

func (o *Observer) DeriveRoleAddr(role, subnetBase string) string {
	_, primaryAddr := o.RoleReachable(role)
	if primaryAddr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(primaryAddr)
	if err != nil {
		host = primaryAddr
	}
	idx := strings.LastIndexByte(host, '.')
	if idx < 0 || net.ParseIP(host) == nil {
		return ""
	}
	return subnetBase + host[idx+1:]
}

// OtherCoreRoles returns the two core roles that are not self.
func OtherCoreRoles(self string) []string {
	var out []string
	for _, r := range []string{config.RoleCore1, config.RoleCore2, config.RoleCore3} {
		if r != self {
			out = append(out, r)
		}
	}
	return out
}

func (o *Observer) recordProbeFailure(ps *PeerState, now int64, wasReachable bool, lastError, logReason string) {
	ps.Failures++
	ps.LastError = lastError
	if wasReachable && ps.Failures >= unreachableThreshold {
		ps.Reachable = false
		ps.UnreachableSince = now
		ps.pushStateChange(false, now)
		o.signalChanged()
		nodeDesc := peerNodeDesc(ps)
		loglevel.Warnf("[CLUSTER:UNREACHABLE] peer %s (%s, after %d consecutive failed probes)",
			nodeDesc, logReason, ps.Failures)
	}
}

// pushStateChange appends a state transition, keeping the ring bounded.
func (ps *PeerState) pushStateChange(reachable bool, at int64) {
	ps.StateChanges = append(ps.StateChanges, StateChange{
		Reachable: reachable,
		At:        at,
	})
	if len(ps.StateChanges) > maxStateChanges {
		ps.StateChanges = ps.StateChanges[len(ps.StateChanges)-maxStateChanges:]
	}
}

// updateQuorumExclusion recomputes ps.ExcludedFromQuorum from its current
// Reachable/UnreachableSince/ReachableSince fields and the two configured
// grace periods.
func updateQuorumExclusion(ps *PeerState, now int64, failGrace, reconnectGrace time.Duration) {
	if !ps.Reachable {
		if ps.UnreachableSince > 0 && now-ps.UnreachableSince >= int64(failGrace/time.Second) {
			ps.ExcludedFromQuorum = true
		}
		return
	}
	if ps.ExcludedFromQuorum && ps.ReachableSince > 0 && now-ps.ReachableSince >= int64(reconnectGrace/time.Second) {
		ps.ExcludedFromQuorum = false
	}
}

func peerNodeDesc(ps *PeerState) string {
	if ps.Identity != nil {
		return ps.Identity.NodeID + " (" + ps.Identity.Role + ")"
	}
	return ps.Addr
}

// formatAge renders the duration between now and a past unix timestamp as
// a human-friendly string (e.g. "12s", "2m35s"). Returns "never" for zero.
func formatAge(now, past int64) string {
	if past <= 0 {
		return "never"
	}
	d := time.Duration(now-past) * time.Second
	if d < time.Minute {
		return d.String()
	}
	m := int(d.Minutes())
	s := int(d.Seconds()) - m*60
	if s > 0 {
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%dm", m)
}

// Snapshot returns a copy of all peer states.
func (o *Observer) Snapshot() []PeerState {
	o.mu.RLock()
	defer o.mu.RUnlock()
	out := make([]PeerState, 0, len(o.peers))
	for _, ps := range o.peers {
		cp := *ps
		if ps.Identity != nil {
			id := *ps.Identity
			cp.Identity = &id
		}
		if len(ps.StateChanges) > 0 {
			cp.StateChanges = make([]StateChange, len(ps.StateChanges))
			copy(cp.StateChanges, ps.StateChanges)
		}
		out = append(out, cp)
	}
	return out
}

func (o *Observer) ReachableCount() int {
	o.mu.RLock()
	defer o.mu.RUnlock()
	n := 0
	for _, ps := range o.peers {
		if ps.Reachable {
			n++
		}
	}
	return n
}

// PeerVisibility returns the list of reachable and unreachable peer
// addresses as seen by this node.
func (o *Observer) PeerVisibility() (visible, unreachable []string) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	for _, ps := range o.peers {
		if ps.Reachable {
			visible = append(visible, ps.Addr)
		} else {
			unreachable = append(unreachable, ps.Addr)
		}
	}
	return
}

// Quorum computes the current quorum verdict from observed peer state.
func (o *Observer) Quorum() quorum.Verdict {
	return o.computeQuorum(false)
}

// EffectiveQuorum is like Quorum() but excludes any CONFIGURED peer
// currently ExcludedFromQuorum.
func (o *Observer) EffectiveQuorum() quorum.Verdict {
	return o.computeQuorum(true)
}

// computeQuorum is the shared implementation behind Quorum() and
// EffectiveQuorum().
func (o *Observer) computeQuorum(excludeGraceFailed bool) quorum.Verdict {
	o.mu.RLock()
	self := o.self
	views := make([]quorum.PeerView, 0, len(o.peers))
	for _, ps := range o.peers {
		if excludeGraceFailed && ps.ExcludedFromQuorum {
			continue
		}
		role := ""
		if ps.Identity != nil {
			role = ps.Identity.Role
		}
		reachable := ps.Reachable
		if !reachable && ps.Identity != nil {
			for _, fs := range o.fallbackStatus[ps.Identity.Role] {
				if fs.Reachable {
					reachable = true
					break
				}
			}
		}
		views = append(views, quorum.PeerView{
			Reachable: reachable,
			Role:      role,
		})
	}
	o.mu.RUnlock()
	return quorum.Calculate(self, views)
}

// HandleQuorumAPI serves GET /api/v1/quorum.
func (o *Observer) HandleQuorumAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(o.Quorum())
}

func (o *Observer) CoreRoleLiveness() (core1Alive, core2Alive, core3Alive bool) {
	o.mu.RLock()
	self := o.self.Role
	o.mu.RUnlock()

	alive := map[string]bool{self: true}
	for _, role := range OtherCoreRoles(self) {
		if reachable, _ := o.RoleReachable(role); reachable {
			alive[role] = true
		}
	}
	return alive[config.RoleCore1], alive[config.RoleCore2], alive[config.RoleCore3]
}

// ObservedToken pairs a peer with its announced fencing token and quorum
// claim.
type ObservedToken struct {
	NodeID       string        `json:"node_id"`
	Token        fencing.Token `json:"token"`
	ClaimsQuorum bool          `json:"claims_quorum"`
	Reachable    bool          `json:"reachable"`
}

// ObservedTokens returns the fencing token and quorum claim announced by
// each peer that has been handshaked, for fencing visibility.
func (o *Observer) ObservedTokens() []ObservedToken {
	o.mu.RLock()
	defer o.mu.RUnlock()
	var out []ObservedToken
	for _, ps := range o.peers {
		if ps.Identity == nil {
			continue
		}
		out = append(out, ObservedToken{
			NodeID:       ps.Identity.NodeID,
			Token:        ps.Identity.Token,
			ClaimsQuorum: ps.Identity.ClaimsQuorum,
			Reachable:    ps.Reachable,
		})
	}
	return out
}

// ObservedLease pairs a peer's announced lease with this node's validity
// verdict on it, plus whether it is fenced out by the watermark.
type ObservedLease struct {
	Lease    lease.Lease    `json:"lease"`
	Validity lease.Validity `json:"validity"`
	Fenced   bool           `json:"fenced"` // token below watermark → refused
	FromNode string         `json:"from_node"`
}

// ObservedLeases evaluates every lease announced by reachable peers
// against the given authoritative generation.
func (o *Observer) ObservedLeases(authoritativeGen uint64, wm *fencing.Watermark) []ObservedLease {
	now := time.Now()
	o.mu.RLock()
	defer o.mu.RUnlock()

	var out []ObservedLease
	for _, ps := range o.peers {
		if !ps.Reachable || ps.Identity == nil {
			continue
		}
		ownerIncarnation := ps.Identity.Incarnation
		peerToken := ps.Identity.Token
		for _, l := range ps.Identity.Leases {
			v := l.Evaluate(lease.ValidityInput{
				Now:                     now,
				AuthoritativeGeneration: authoritativeGen,
				OwnerCurrentIncarnation: ownerIncarnation,
			})
			fenced := false
			if wm != nil {
				fenced = wm.Fenced(peerToken)
			}
			out = append(out, ObservedLease{
				Lease:    l,
				Validity: v,
				Fenced:   fenced,
				FromNode: ps.Identity.NodeID,
			})
		}
	}
	return out
}

// ClusterView is the JSON returned by /api/v1/cluster.
type ClusterView struct {
	Self            identity.Identity `json:"self"`
	SelfAddr        string            `json:"self_addr"`
	ObserverSince   int64             `json:"observer_since"`
	PeerCount       int               `json:"peer_count"`
	ReachableNow    int               `json:"reachable_now"`
	Quorum          quorum.Verdict    `json:"quorum"`
	Peers           []PeerState       `json:"peers"`
	TopologyWarning string            `json:"topology_warning,omitempty"`
	Fallback        []FallbackStatus  `json:"fallback,omitempty"`
}

// TopologyCheck validates the observed role distribution across the
// cluster.
func (o *Observer) TopologyCheck() string {
	o.mu.RLock()
	selfRole := o.self.Role
	o.mu.RUnlock()

	roles := map[string][]string{selfRole: {o.selfAddr}}

	for _, p := range o.Snapshot() {
		if !p.Reachable || p.Identity == nil {
			continue
		}
		roles[p.Identity.Role] = append(roles[p.Identity.Role], p.Addr)
	}

	// Check for duplicate roles.
	for role, addrs := range roles {
		if len(addrs) > 1 && isCoreRole(role) {
			return fmt.Sprintf("duplicate role %q claimed by %d nodes: %s",
				role, len(addrs), strings.Join(addrs, ", "))
		}
	}

	// Check for missing roles (only if we've seen all peers).
	if len(roles) > 0 {
		for _, role := range []string{config.RoleCore1, config.RoleCore2, config.RoleCore3} {
			if _, ok := roles[role]; !ok {
				return fmt.Sprintf("no %s in cluster — arbiter-quorum witness-token majority (2 of 3) depends on every core role being present", role)
			}
		}
	}

	return ""
}

// isCoreRole reports whether role is one of the 3 real core roles.
func isCoreRole(role string) bool {
	switch role {
	case config.RoleCore1, config.RoleCore2, config.RoleCore3:
		return true
	default:
		return false
	}
}

// HandleClusterAPI serves GET /api/v1/cluster.
func (o *Observer) HandleClusterAPI(w http.ResponseWriter, r *http.Request) {
	o.mu.RLock()
	self := o.self
	o.mu.RUnlock()

	view := ClusterView{
		Self:            self,
		SelfAddr:        o.selfAddr,
		ObserverSince:   o.started.Unix(),
		PeerCount:       len(o.peers),
		ReachableNow:    o.ReachableCount(),
		Quorum:          o.Quorum(),
		Peers:           o.Snapshot(),
		TopologyWarning: o.TopologyCheck(),
		Fallback:        o.FallbackStatuses(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(view)
}

// HandlePing serves POST /api/v1/ping.
func (o *Observer) HandlePing(w http.ResponseWriter, r *http.Request) {
	o.mu.RLock()
	trusted := o.trustedHosts
	o.mu.RUnlock()
	if !trusted.Allowed(r.RemoteAddr) {
		loglevel.Warnf("[OBSERVER:DENY_UNTRUSTED] ping from untrusted host: remote_addr=%s", r.RemoteAddr)
		http.Error(w, "source address not in trusted_hosts", http.StatusForbidden)
		return
	}
	o.mu.RLock()
	self := o.self
	psk := o.psk
	o.mu.RUnlock()
	if len(psk) > 0 {
		var reqBody []byte
		if r.Body != nil {
			reqBody, _ = io.ReadAll(http.MaxBytesReader(w, r.Body, maxIdentityBodyBytes))
			r.Body.Close()
		}
		if sig := r.Header.Get(pingSigHeader); sig == "" || !hmac.Equal([]byte(signPingBody(psk, reqBody)), []byte(sig)) {
			loglevel.Warnf("[OBSERVER:DENY_UNSIGNED] ping without a valid cluster signature: remote_addr=%s", r.RemoteAddr)
			http.Error(w, "ping not signed with the cluster PSK", http.StatusForbidden)
			return
		}
	}

	body, err := json.Marshal(self)
	if err != nil {
		http.Error(w, "encode identity", http.StatusInternalServerError)
		return
	}
	if len(psk) > 0 {
		w.Header().Set(pingSigHeader, signPingBody(psk, body))
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

// RemovePeer drops addr from the active probe set immediately.
func (o *Observer) AddPeer(addr string) {
	if addr == "" || addr == o.selfAddr {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, ok := o.peers[addr]; !ok {
		o.peers[addr] = &PeerState{Addr: addr}
	}
}

func (o *Observer) RemovePeer(addr string) {
	o.mu.Lock()
	var role string
	if ps := o.peers[addr]; ps != nil && ps.Identity != nil {
		role = ps.Identity.Role
	}
	delete(o.peers, addr)
	parents := map[string]bool{}
	if role != "" && !o.peerClaimsRoleLocked(role) {
		parents[mgmtParentKey] = true
		for parent := range o.fallbackStatus[role] {
			parents[parent] = true
		}
		for parent := range o.fallbackAddrs[role] {
			parents[parent] = true
		}
		delete(o.fallbackStatus, role)
		if o.departedRoles == nil {
			o.departedRoles = make(map[string]bool)
		}
		o.departedRoles[role] = true
		if _, ok := o.fallbackAddrs[role]; ok {
			kept := make(map[string]map[string]string, len(o.fallbackAddrs))
			for r, byParent := range o.fallbackAddrs {
				if r != role {
					kept[r] = byParent
				}
			}
			o.fallbackAddrs = kept
		}
	}
	o.mu.Unlock()

	for parent := range parents {
		o.pathReliability.Reset(pathReliabilityKey(role, parent))
	}
}

func (o *Observer) peerClaimsRoleLocked(role string) bool {
	for _, ps := range o.peers {
		if ps.Identity != nil && ps.Identity.Role == role {
			return true
		}
	}
	return false
}

// SetPeerForTest directly injects a peer's observed state, bypassing the
// real probe/handshake path entirely.
func (o *Observer) SetPeerForTest(addr string, ps *PeerState) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.peers[addr] = ps
}

// SetFallbackStatusForTest directly injects a role's own fallback sweep
// result, bypassing the real probeFallbackSweep network call.
func (o *Observer) SetFallbackStatusForTest(role, parent string, fs FallbackStatus) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.fallbackStatus == nil {
		o.fallbackStatus = make(map[string]map[string]FallbackStatus)
	}
	if o.fallbackStatus[role] == nil {
		o.fallbackStatus[role] = make(map[string]FallbackStatus)
	}
	o.fallbackStatus[role][parent] = fs
}

// firstReachableFallback returns ONE reachable fallback address for role.
func (o *Observer) firstReachableFallback(role string) (addr string, ok bool) {
	var parents []string
	for parent := range o.fallbackStatus[role] {
		parents = append(parents, parent)
	}
	sort.Strings(parents)
	for _, parent := range parents {
		if fs := o.fallbackStatus[role][parent]; fs.Reachable && fs.Addr != "" {
			return fs.Addr, true
		}
	}
	return "", false
}

// AllPeerAddrs returns the control addresses of every currently reachable
// core peer, regardless of role.
func (o *Observer) AllPeerAddrs() []string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	var addrs []string
	for _, ps := range o.peers {
		if ps.Identity == nil || !ps.Reachable {
			continue
		}
		addrs = append(addrs, ps.Addr)
	}
	return addrs
}

func (o *Observer) FallbackRoutes() map[string]string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	out := map[string]string{}
	for addr, ps := range o.peers {
		if ps.Reachable || ps.Identity == nil {
			continue
		}
		if fb, ok := o.firstReachableFallback(ps.Identity.Role); ok {
			out[addr] = fb
		}
	}
	return out
}

// FallbackAddr returns a peer's confirmed-alive scope-VLAN fallback
// address REGARDLESS of whether its primary is currently believed down.
func (o *Observer) FallbackAddr(primaryAddr string) (string, bool) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	ps, ok := o.peers[primaryAddr]
	if !ok || ps.Identity == nil {
		return "", false
	}
	return o.firstReachableFallback(ps.Identity.Role)
}

// FallbackRoute is FallbackRoutes for one peer address.
func (o *Observer) FallbackRoute(primaryAddr string) (string, bool) {
	fb, ok := o.FallbackRoutes()[primaryAddr]
	return fb, ok
}

func (o *Observer) BelievedDown(addr string) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	ps, ok := o.peers[addr]
	if !ok || ps.Reachable {
		return false
	}
	return ps.LastSeen != 0 || ps.Failures > 0
}

func (o *Observer) IsReachable(addr string) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	ps, ok := o.peers[addr]
	if !ok {
		return true
	}
	return ps.Reachable
}
