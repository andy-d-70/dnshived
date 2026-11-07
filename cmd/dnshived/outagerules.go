// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"dnshived/internal/activation"
	"dnshived/internal/cluster"
	"dnshived/internal/config"
	"dnshived/internal/quorum"
)

// configVerifyWait is how long a starting node waits for a peer to answer
// before it serves its own configuration with an "unverified" notice.
const configVerifyWait = 30 * time.Second

// peerView is what the outage rules need to know about one configured peer.
type peerView struct {
	Addr            string
	Reachable       bool
	Known           bool
	Version         string
	Revision        int64
	Hash            string
	HashV2          string
	MembershipEpoch int64
}

func peerViews(snap []cluster.PeerState) []peerView {
	out := make([]peerView, 0, len(snap))
	for _, ps := range snap {
		v := peerView{Addr: ps.Addr, Reachable: ps.Reachable}
		if ps.Identity != nil {
			v.Known = true
			v.Version = ps.Identity.Version
			v.Revision = ps.Identity.ConfigRevision
			v.Hash = ps.Identity.ConfigHash
			v.HashV2 = ps.Identity.ConfigHashV2
			v.MembershipEpoch = ps.Identity.MembershipEpoch
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	return out
}

// peersRunAtLeast reports whether this node and every configured peer run at
// least required. A peer that was never seen blocks, and so does one on an
// older version; blocking names them.
func peersRunAtLeast(selfVersion, required string, configured int, peers []peerView) (ok bool, blocking []string) {
	if c, valid := activation.Compare(selfVersion, required); !valid || c < 0 {
		return false, []string{"this node"}
	}
	known := map[string]bool{}
	for _, p := range peers {
		known[p.Addr] = true
		if !p.Known {
			blocking = append(blocking, p.Addr+" (not seen)")
			continue
		}
		if c, valid := activation.Compare(p.Version, required); !valid || c < 0 {
			blocking = append(blocking, p.Addr+" ("+p.Version+")")
		}
	}
	if len(known) < configured {
		blocking = append(blocking, "a configured peer is missing from the observer")
	}
	return len(blocking) == 0, blocking
}

// Configuration states a starting node goes through.
const (
	cfgVerifying  = "verifying"
	cfgVerified   = "verified"
	cfgUnverified = "unverified"
	cfgBehind     = "behind"
)

// configVerdict compares this node's configuration with its peers after a
// start. verifying and behind hold new scope starts; unverified (no peer
// answered within the wait) serves with a notice.
func configVerdict(selfRev int64, selfHash, selfHashV2 string, configured int, peers []peerView, sinceStart time.Duration) (state, reason string) {
	if configured == 0 {
		return cfgVerified, ""
	}
	informative := false
	for _, p := range peers {
		if !p.Reachable || !p.Known || p.Hash == "" {
			continue
		}
		informative = true
		differs := p.Hash != selfHash
		if p.HashV2 != "" && selfHashV2 != "" {
			differs = p.HashV2 != selfHashV2
		}
		if p.Revision > selfRev && differs {
			return cfgBehind, fmt.Sprintf("peer %s is at config revision %d, this node at %d; waiting for the catch-up", p.Addr, p.Revision, selfRev)
		}
	}
	if informative {
		return cfgVerified, ""
	}
	if sinceStart < configVerifyWait {
		return cfgVerifying, fmt.Sprintf("comparing with the peers (%ds left before serving unverified)", int((configVerifyWait - sinceStart).Seconds()))
	}
	return cfgUnverified, "no peer answered; serving this node's own configuration unverified"
}

// startHoldFor turns a verdict into the reason that holds scope starts, or "".
func startHoldFor(state, reason string) string {
	if state == cfgVerifying || state == cfgBehind {
		return reason
	}
	return ""
}

// membershipVerdict returns the reason this node must stop serving, or "":
// a reachable peer announces a higher membership epoch, meaning the operator
// declared another node the only member while this one was away.
func membershipVerdict(selfEpoch int64, peers []peerView) string {
	for _, p := range peers {
		if p.Reachable && p.Known && p.MembershipEpoch > selfEpoch {
			return fmt.Sprintf("removed while away: peer %s is at membership epoch %d, this node at %d; re-adopt this node", p.Addr, p.MembershipEpoch, selfEpoch)
		}
	}
	return ""
}

// outageRules holds the latch that switches the rules on once every
// configured core runs a version that enforces them.
type outageRules struct {
	active atomic.Bool
	mu     sync.Mutex
}

func (o *outageRules) Active() bool { return o.active.Load() }

// refresh latches the rules on when every configured core qualifies and, if
// that changed anything, persists the latch. It returns whether the latch
// was newly set.
func (o *outageRules) refresh(selfVersion string, configured int, peers []peerView, persist func() error) bool {
	if o.active.Load() {
		return false
	}
	if ok, _ := peersRunAtLeast(selfVersion, activation.OutageRulesVersion, configured, peers); !ok {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.active.Load() {
		return false
	}
	if persist != nil {
		if err := persist(); err != nil {
			return false
		}
	}
	o.active.Store(true)
	return true
}

type quorumSource interface{ Quorum() quorum.Verdict }

// checkWriteRules applies the rules to one configuration push. It returns
// ok=false with the HTTP status and body to answer when the push is refused.
func checkWriteRules(active bool, q quorumSource, cur *config.Cluster, upd configUpdate) (status int, body map[string]string, ok bool) {
	if !active {
		return 0, nil, true
	}
	if v := q.Quorum(); !v.HasQuorum {
		return http.StatusServiceUnavailable, map[string]string{
			"code":  "no_quorum",
			"error": fmt.Sprintf("configuration change refused: this node sees %d of %d cores and needs %d. Bring a core back, or run dnshived --force-standalone on the console if the others are gone for good", v.VotesSeen, v.TotalVoters, v.Needed),
		}, false
	}
	if upd.ConfigBaseRevision != nil && cur.ConfigRevision > *upd.ConfigBaseRevision {
		return http.StatusConflict, map[string]string{
			"code":  "stale_base",
			"error": fmt.Sprintf("configuration change refused: it was staged on revision %d but this node is already at revision %d; stage the change again", *upd.ConfigBaseRevision, cur.ConfigRevision),
		}, false
	}
	return 0, nil, true
}

// cfgWriteMu serialises the read-modify-write cycles on cluster.json that run
// inside the daemon (a configuration push, the latch).
var cfgWriteMu sync.Mutex

// outageState is what the reconcile loop publishes about the outage rules.
type outageState struct {
	rules     outageRules
	startedAt time.Time

	mu        sync.RWMutex
	cfgState  string
	cfgReason string
	member    string
}

var outage = &outageState{startedAt: time.Now()}

// evaluate computes the verdicts for one reconcile pass, publishes them and
// returns the holds to pass to the agent. Holds only apply once the rules are
// latched on.
func (s *outageState) evaluate(cur *config.Cluster, hash, hashV2 string, peers []peerView, now time.Time) (startHold, memberHold string) {
	state, reason := configVerdict(cur.ConfigRevision, hash, hashV2, len(cur.Peers), peers, now.Sub(s.startedAt))
	member := membershipVerdict(cur.MembershipEpoch, peers)
	s.mu.Lock()
	s.cfgState, s.cfgReason, s.member = state, reason, member
	s.mu.Unlock()
	if !s.rules.Active() {
		return "", ""
	}
	return startHoldFor(state, reason), member
}

func (s *outageState) view() (cfgState, cfgReason, member string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfgState, s.cfgReason, s.member
}

// membershipHeld reports whether the rules are on and a peer announces a
// higher membership epoch.
func (s *outageState) membershipHeld() bool {
	if !s.rules.Active() {
		return false
	}
	_, _, m := s.view()
	return m != ""
}

// persistOutageLatch records the latch in cluster.json.
func persistOutageLatch(cfgPath string) error {
	cfgWriteMu.Lock()
	defer cfgWriteMu.Unlock()
	c, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if c.OutageRulesActive {
		currentConfig.Store(c)
		return nil
	}
	c.OutageRulesActive = true
	if err := config.Save(cfgPath, c); err != nil {
		return err
	}
	currentConfig.Store(c)
	return nil
}

// outageStatus is the "outage_rules" object of /api/v1/status.
func outageStatus() map[string]interface{} {
	state, reason, member := outage.view()
	return map[string]interface{}{
		"active":           outage.rules.Active(),
		"required_version": activation.OutageRulesVersion,
		"config_state":     state,
		"config_state_why": reason,
		"membership_hold":  member,
	}
}
