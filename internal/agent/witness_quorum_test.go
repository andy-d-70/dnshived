// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"dnshived/internal/arbiter"
	"dnshived/internal/cluster"
	"dnshived/internal/config"
	"dnshived/internal/identity"
	"dnshived/internal/timehealth"
)

// --- arbiterAddrs ---

func TestArbiterAddrs_EmptyWithNoObserverAndNoSelfAddr(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", testScopes("office"), nil)
	if got := a.arbiterAddrs(); len(got) != 0 {
		t.Errorf("arbiterAddrs() = %v, want empty (no observer, no selfAddr configured)", got)
	}
}

// candidateAddrs extracts just the primary addresses from a candidate
// list, for tests that only care about which instances are present.
func candidateAddrs(cands []arbiterCandidate) []string {
	out := make([]string, len(cands))
	for i, c := range cands {
		out[i] = c.addr
	}
	return out
}

func TestArbiterAddrs_IncludesSelfForEveryRole(t *testing.T) {
	worker := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", testScopes("office"), nil)
	worker.SetSelfAddr("10.0.0.22:8080")
	got := worker.arbiterAddrs()
	if len(got) != 1 || got[0].addr != "10.0.0.22:8080" {
		t.Errorf("worker arbiterAddrs() = %v, want [10.0.0.22:8080]", got)
	}
	if got[0].fallback != "127.0.0.1:8080" {
		t.Errorf("worker arbiterAddrs()[0].fallback = %q, want 127.0.0.1:8080 (self's own paired loopback backup)", got[0].fallback)
	}

	arb := New(config.RoleCore3, "test-node", 1, "psk", "/tmp", nil, nil)
	arb.SetSelfAddr("10.0.0.24:8080")
	got = arb.arbiterAddrs()
	if len(got) != 1 || got[0].addr != "10.0.0.24:8080" {
		t.Errorf("arbiter arbiterAddrs() = %v, want [10.0.0.24:8080] (every core role is now an equal requester)", got)
	}
}

// findCandidate returns the candidate for addr, or nil.
func findCandidate(cands []arbiterCandidate, addr string) *arbiterCandidate {
	for i := range cands {
		if cands[i].addr == addr {
			return &cands[i]
		}
	}
	return nil
}

func TestArbiterAddrs_CombinesSelfAndEveryIdentifiedPeer(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "worker-a-node", Role: config.RoleCore1}
	o := cluster.NewObserver(self, "self-control-addr", nil, "psk")
	setPeer(o, "arbiter-addr", config.RoleCore3, true)
	setPeer(o, "worker-b-addr", config.RoleCore2, true)

	a := New(config.RoleCore1, "worker-a-node", 1, "psk", "/tmp", testScopes("office"), o)
	a.SetSelfAddr("self-control-addr")

	got := a.arbiterAddrs()
	if len(got) == 0 || got[0].addr != "self-control-addr" {
		t.Fatalf("arbiterAddrs() = %v, want self-control-addr first", got)
	}
	want := map[string]bool{"self-control-addr": true, "arbiter-addr": true, "worker-b-addr": true}
	if len(got) != len(want) {
		t.Fatalf("arbiterAddrs() = %v, want exactly %v (order aside)", got, want)
	}
	for _, addr := range candidateAddrs(got) {
		if !want[addr] {
			t.Errorf("arbiterAddrs() contains unexpected address %q (full: %v)", addr, got)
		}
	}
}

func TestArbiterAddrs_PairsFallbackAddrRegardlessOfCurrentReachability(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "worker-a-node", Role: config.RoleCore1}
	o := cluster.NewObserver(self, "self-control-addr", nil, "psk")
	setPeer(o, "arbiter-addr", config.RoleCore3, true)
	setPeer(o, "worker-b-addr", config.RoleCore2, true)
	o.SetFallbackStatusForTest(config.RoleCore2, "ens19", cluster.FallbackStatus{
		Role: config.RoleCore2, Addr: "worker-b-fallback-addr", Reachable: true,
	})

	a := New(config.RoleCore1, "worker-a-node", 1, "psk", "/tmp", testScopes("office"), o)
	a.SetSelfAddr("self-control-addr")

	got := a.arbiterAddrs()
	want := map[string]bool{"self-control-addr": true, "arbiter-addr": true, "worker-b-addr": true}
	if len(got) != len(want) {
		t.Fatalf("arbiterAddrs() = %v, want exactly 3 candidates (order aside)", got)
	}
	wb := findCandidate(got, "worker-b-addr")
	if wb == nil {
		t.Fatalf("arbiterAddrs() = %v, missing worker-b-addr", got)
	}
	if wb.fallback != "worker-b-fallback-addr" {
		t.Errorf("worker-b-addr candidate fallback = %q, want worker-b-fallback-addr (paired in unconditionally)", wb.fallback)
	}
	arbC := findCandidate(got, "arbiter-addr")
	if arbC == nil {
		t.Fatalf("arbiterAddrs() = %v, missing arbiter-addr", got)
	}
	if arbC.fallback != "" {
		t.Errorf("arbiter-addr candidate fallback = %q, want empty (no fallback status was ever set for it)", arbC.fallback)
	}
}

func TestArbiterAddrs_UnreachedFallbackStatusIsNotPaired(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "worker-a-node", Role: config.RoleCore1}
	o := cluster.NewObserver(self, "self-control-addr", nil, "psk")
	setPeer(o, "worker-b-addr", config.RoleCore2, true)
	o.SetFallbackStatusForTest(config.RoleCore2, "ens19", cluster.FallbackStatus{
		Role: config.RoleCore2, Addr: "worker-b-fallback-addr", Reachable: false,
	})

	a := New(config.RoleCore1, "worker-a-node", 1, "psk", "/tmp", testScopes("office"), o)
	a.SetSelfAddr("self-control-addr")

	got := a.arbiterAddrs()
	wb := findCandidate(got, "worker-b-addr")
	if wb == nil {
		t.Fatalf("arbiterAddrs() = %v, missing worker-b-addr", got)
	}
	if wb.fallback != "" {
		t.Errorf("worker-b-addr candidate fallback = %q, want empty (fallback status was explicitly Reachable:false)", wb.fallback)
	}
}

// setPeer directly injects a peer's state into an Observer, mirroring the
// established direct-manipulation pattern in observer_test.go.
func setPeer(o *cluster.Observer, addr, role string, reachable bool) {
	o.SetPeerForTest(addr, &cluster.PeerState{
		Addr:      addr,
		Reachable: reachable,
		Identity:  &identity.Identity{Role: role},
	})
}

// --- acquireWitness / quorum ---

// fakeArbiter is a minimal stand-in for one arbiter.Manager instance's own
// /api/v1/token/request and /token/renew endpoints.
type fakeArbiter struct {
	accept       atomic.Bool
	requestCalls atomic.Int64
	renewCalls   atomic.Int64
	tamper       func(*arbiter.Token)
}

func newFakeArbiter(accept bool) *fakeArbiter {
	f := &fakeArbiter{}
	f.accept.Store(accept)
	return f
}

func (f *fakeArbiter) server() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/token/request", func(w http.ResponseWriter, r *http.Request) {
		f.requestCalls.Add(1)
		var req struct {
			Scope       string `json:"scope"`
			NodeID      string `json:"node_id"`
			Incarnation uint64 `json:"incarnation"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		f.respond(w, req.Scope, req.NodeID, req.Incarnation)
	})
	mux.HandleFunc("/api/v1/token/renew", func(w http.ResponseWriter, r *http.Request) {
		f.renewCalls.Add(1)
		var req struct {
			Token arbiter.Token `json:"token"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		f.respond(w, req.Token.Scope, req.Token.Owner, req.Token.Incarnation)
	})
	return httptest.NewServer(mux)
}

func (f *fakeArbiter) respond(w http.ResponseWriter, scope, owner string, incarnation uint64) {
	w.Header().Set("Content-Type", "application/json")
	if !f.accept.Load() {
		json.NewEncoder(w).Encode(map[string]interface{}{"accepted": false})
		return
	}
	tok := &arbiter.Token{
		Scope:       scope,
		Owner:       owner,
		Incarnation: incarnation,
		GrantedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(15 * time.Second),
		Nonce:       "n",
	}
	tok.Signature = tok.Sign([]byte("psk"))
	if f.tamper != nil {
		f.tamper(tok)
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"accepted": true, "token": tok})
}

func witnessTestSetup(t *testing.T, arbiterAccept, selfAccept, peerAccept bool) (a *Agent, arbiterFake, selfFake, peerFake *fakeArbiter) {
	t.Helper()
	arbiterFake = newFakeArbiter(arbiterAccept)
	selfFake = newFakeArbiter(selfAccept)
	peerFake = newFakeArbiter(peerAccept)

	arbiterSrv := arbiterFake.server()
	selfSrv := selfFake.server()
	peerSrv := peerFake.server()
	t.Cleanup(func() {
		arbiterSrv.Close()
		selfSrv.Close()
		peerSrv.Close()
	})

	self := identity.Identity{ClusterID: "c", NodeID: "worker-a-node", Role: config.RoleCore1}
	o := cluster.NewObserver(self, selfSrv.Listener.Addr().String(), nil, "psk")
	setPeer(o, arbiterSrv.Listener.Addr().String(), config.RoleCore3, true)
	setPeer(o, peerSrv.Listener.Addr().String(), config.RoleCore2, true)

	a = New(config.RoleCore1, "worker-a-node", 1, "psk", t.TempDir(), testScopes("office"), o)
	a.SetSelfAddr(selfSrv.Listener.Addr().String())
	return a, arbiterFake, selfFake, peerFake
}

func TestAcquireWitness_QuorumReachedWithTwoOfThreeAccepting(t *testing.T) {
	a, _, _, _ := witnessTestSetup(t, true /* arbiter */, true /* self */, false /* peer denies */)

	ok := a.acquireWitness("office")
	if !ok {
		t.Fatal("acquireWitness() = false, want true (2 of 3 instances agreed)")
	}
	ws := a.witnessFor("office")
	if !ws.Held {
		t.Error("witnessFor(office).Held = false, want true")
	}
	if ws.ExpiresAt == 0 {
		t.Error("witnessFor(office).ExpiresAt = 0, want a real future expiry")
	}
}

func TestAcquireWitness_DeniedWithOnlyOneOfThreeAccepting(t *testing.T) {
	a, _, _, _ := witnessTestSetup(t, false, true, false)

	ok := a.acquireWitness("office")
	if ok {
		t.Fatal("acquireWitness() = true, want false (only 1 of 3 instances agreed)")
	}
	ws := a.witnessFor("office")
	if ws.Held {
		t.Error("witnessFor(office).Held = true, want false — quorum was not reached")
	}
}

func TestAcquireWitness_SecondRoundRenewsInstancesThatAlreadyGranted(t *testing.T) {
	a, arbiterFake, selfFake, peerFake := witnessTestSetup(t, true, true, false)

	if !a.acquireWitness("office") {
		t.Fatal("first acquireWitness() = false, want true")
	}
	if got := arbiterFake.requestCalls.Load(); got != 1 {
		t.Errorf("arbiter requestCalls after round 1 = %d, want 1", got)
	}
	if got := peerFake.requestCalls.Load(); got != 1 {
		t.Errorf("peer requestCalls after round 1 = %d, want 1 (it denied, but was still asked)", got)
	}

	if !a.acquireWitness("office") {
		t.Fatal("second acquireWitness() = false, want true")
	}
	if got := arbiterFake.renewCalls.Load(); got != 1 {
		t.Errorf("arbiter renewCalls after round 2 = %d, want 1 (should renew, not re-request)", got)
	}
	if got := selfFake.renewCalls.Load(); got != 1 {
		t.Errorf("self renewCalls after round 2 = %d, want 1 (should renew, not re-request)", got)
	}
	if got := arbiterFake.requestCalls.Load(); got != 1 {
		t.Errorf("arbiter requestCalls after round 2 = %d, want still 1 (must not re-request an already-held token)", got)
	}
	if got := peerFake.requestCalls.Load(); got != 2 {
		t.Errorf("peer requestCalls after round 2 = %d, want 2 (no prior grant to renew, must request fresh every round)", got)
	}
}

func TestAcquireWitness_SelfVotingCountsTowardQuorum(t *testing.T) {
	a, _, selfFake, _ := witnessTestSetup(t, false /* arbiter denies */, true /* self accepts */, true /* peer accepts */)

	ok := a.acquireWitness("office")
	if !ok {
		t.Fatal("acquireWitness() = false, want true (self + peer = 2 of 3)")
	}
	if got := selfFake.requestCalls.Load(); got != 1 {
		t.Errorf("self requestCalls = %d, want 1 — self must actually be queried like any other instance", got)
	}
}

func TestRequiredArbiterQuorum_ScalesWithConfiguredTopology(t *testing.T) {
	cases := []struct {
		name           string
		peers          int
		excludedPeers  int // first N of peers marked ExcludedFromQuorum (grace-failed)
		wantNeeded     int
		wantStandalone bool
		wantViaFailure bool
	}{
		{"no observer at all", -1, 0, 2, false, false},
		{"self only, zero configured peers", 0, 0, 1, true, false},
		{"self plus one configured peer", 1, 0, 2, false, false},
		{"self plus two configured peers", 2, 0, 2, false, false},
		{"self plus one CONFIGURED-but-grace-excluded peer", 1, 1, 1, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var a *Agent
			if c.peers < 0 {
				a = New(config.RoleCore1, "test-node", 1, "psk", "/tmp", testScopes("office"), nil)
			} else {
				self := identity.Identity{ClusterID: "c", NodeID: "test-node", Role: config.RoleCore1}
				o := cluster.NewObserver(self, "self-addr", nil, "psk")
				for i := 0; i < c.peers; i++ {
					addr := "peer-addr-" + string(rune('a'+i))
					setPeer(o, addr, config.RoleCore2, true)
					if i < c.excludedPeers {
						o.SetPeerForTest(addr, &cluster.PeerState{
							Addr: addr, Reachable: false,
							Identity:           &identity.Identity{Role: config.RoleCore2},
							ExcludedFromQuorum: true,
						})
					}
				}
				a = New(config.RoleCore1, "test-node", 1, "psk", "/tmp", testScopes("office"), o)
			}
			needed, standalone, viaFailure := a.requiredArbiterQuorum()
			if needed != c.wantNeeded || standalone != c.wantStandalone || viaFailure != c.wantViaFailure {
				t.Errorf("requiredArbiterQuorum() = (%d, %v, %v), want (%d, %v, %v)",
					needed, standalone, viaFailure, c.wantNeeded, c.wantStandalone, c.wantViaFailure)
			}
		})
	}
}

func TestAcquireWitness_StandaloneSingleNodeServesOnItsOwnAgreementAlone(t *testing.T) {
	selfFake := newFakeArbiter(true)
	selfSrv := selfFake.server()
	t.Cleanup(selfSrv.Close)

	self := identity.Identity{ClusterID: "c", NodeID: "last-node", Role: config.RoleCore3}
	o := cluster.NewObserver(self, selfSrv.Listener.Addr().String(), nil, "psk") // zero configured peers

	a := New(config.RoleCore3, "last-node", 1, "psk", t.TempDir(), testScopes("office"), o)
	a.SetSelfAddr(selfSrv.Listener.Addr().String())

	ok := a.acquireWitness("office")
	if !ok {
		t.Fatal("acquireWitness() = false, want true — the only configured core node must serve standalone on its own agreement")
	}
	ws := a.witnessFor("office")
	if !ws.Held {
		t.Error("witnessFor(office).Held = false, want true")
	}
	if got := selfFake.requestCalls.Load(); got != 1 {
		t.Errorf("self requestCalls = %d, want 1", got)
	}
}

func TestAcquireWitness_NoInstancesKnownDeniesImmediately(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", testScopes("office"), nil)
	if a.acquireWitness("office") {
		t.Error("acquireWitness() = true, want false — no arbiter instance known at all")
	}
}

func TestAcquireFromInstance_FallsBackWithinTheSameCallOnPrimaryDialFailure(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadAddr := dead.Listener.Addr().String()
	dead.Close()

	fallback := newFakeArbiter(true)
	fallbackSrv := fallback.server()
	t.Cleanup(fallbackSrv.Close)

	a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", testScopes("office"), nil)
	c := arbiterCandidate{addr: deadAddr, fallback: fallbackSrv.Listener.Addr().String()}

	raw, expiresAt, ok := a.acquireFromInstance("office", c)
	if !ok {
		t.Fatal("acquireFromInstance() ok = false, want true — must succeed via the paired fallback when primary dial fails outright")
	}
	if len(raw) == 0 || expiresAt == 0 {
		t.Errorf("acquireFromInstance() raw=%v expiresAt=%d, want a real token from the fallback", raw, expiresAt)
	}
	if got := fallback.requestCalls.Load(); got != 1 {
		t.Errorf("fallback requestCalls = %d, want 1 — the fallback must actually be dialed, not just theoretically available", got)
	}
}

// TestAcquireFromInstance_NoFallbackMeansPrimaryDialFailureIsFinal
// confirms there's no fallback attempt at all when none is known.
func TestAcquireFromInstance_NoFallbackMeansPrimaryDialFailureIsFinal(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadAddr := dead.Listener.Addr().String()
	dead.Close()

	a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", testScopes("office"), nil)
	c := arbiterCandidate{addr: deadAddr, fallback: ""}

	if _, _, ok := a.acquireFromInstance("office", c); ok {
		t.Error("acquireFromInstance() ok = true, want false — primary dial failed and no fallback was known")
	}
}

func TestAcquireFromInstance_ADenialFromPrimaryIsNotRetriedViaFallback(t *testing.T) {
	primary := newFakeArbiter(false) // reachable, but declines
	primarySrv := primary.server()
	t.Cleanup(primarySrv.Close)
	fallback := newFakeArbiter(true)
	fallbackSrv := fallback.server()
	t.Cleanup(fallbackSrv.Close)

	a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", testScopes("office"), nil)
	c := arbiterCandidate{addr: primarySrv.Listener.Addr().String(), fallback: fallbackSrv.Listener.Addr().String()}

	if _, _, ok := a.acquireFromInstance("office", c); ok {
		t.Error("acquireFromInstance() ok = true, want false — primary genuinely declined, must not be overridden by trying the fallback")
	}
	if got := primary.requestCalls.Load(); got != 1 {
		t.Errorf("primary requestCalls = %d, want 1", got)
	}
	if got := fallback.requestCalls.Load(); got != 0 {
		t.Errorf("fallback requestCalls = %d, want 0 — a real decline must never be retried elsewhere", got)
	}
}

func TestAcquireFromInstance_RejectsGrantsThatAreNotGenuineOrNotOurs(t *testing.T) {
	resign := func(tok *arbiter.Token) { tok.Signature = tok.Sign([]byte("psk")) }
	cases := []struct {
		name   string
		tamper func(*arbiter.Token)
	}{
		{"unsigned", func(tok *arbiter.Token) { tok.Signature = "" }},
		{"signed with another psk", func(tok *arbiter.Token) { tok.Signature = tok.Sign([]byte("other")) }},
		{"altered after signing", func(tok *arbiter.Token) { tok.ExpiresAt = tok.ExpiresAt.Add(10 * time.Second) }},
		{"other scope", func(tok *arbiter.Token) { tok.Scope = "dante"; resign(tok) }},
		{"other owner", func(tok *arbiter.Token) { tok.Owner = "worker-b-node"; resign(tok) }},
		{"other incarnation", func(tok *arbiter.Token) { tok.Incarnation++; resign(tok) }},
		{"expired", func(tok *arbiter.Token) { tok.ExpiresAt = time.Now().Add(-time.Second); resign(tok) }},
		{"expiry too far ahead", func(tok *arbiter.Token) { tok.ExpiresAt = time.Now().Add(2 * time.Minute); resign(tok) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			arb := newFakeArbiter(true)
			arb.tamper = tc.tamper
			srv := arb.server()
			t.Cleanup(srv.Close)
			fallback := newFakeArbiter(true)
			fallbackSrv := fallback.server()
			t.Cleanup(fallbackSrv.Close)

			a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", testScopes("office"), nil)
			c := arbiterCandidate{addr: srv.Listener.Addr().String(), fallback: fallbackSrv.Listener.Addr().String()}
			if _, _, ok := a.acquireFromInstance("office", c); ok {
				t.Fatal("acquireFromInstance() ok = true, want false")
			}
			if got := fallback.requestCalls.Load(); got != 0 {
				t.Errorf("fallback requestCalls = %d, want 0 — a rejected answer is not a dial failure", got)
			}
		})
	}
}

func TestAcquireFromInstance_AcceptsGenuineGrantAndUsesItsExpiry(t *testing.T) {
	arb := newFakeArbiter(true)
	srv := arb.server()
	t.Cleanup(srv.Close)

	a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", testScopes("office"), nil)
	_, expiresAt, ok := a.acquireFromInstance("office", arbiterCandidate{addr: srv.Listener.Addr().String()})
	if !ok {
		t.Fatal("acquireFromInstance() ok = false, want true for a correctly signed grant")
	}
	if d := time.Until(time.Unix(expiresAt, 0)); d < 10*time.Second || d > 16*time.Second {
		t.Errorf("expiresAt is %s ahead, want about 15s", d)
	}
}

func TestAcquireWitness_ForgedRenewalLosesTheVote(t *testing.T) {
	a, arbiterFake, selfFake, _ := witnessTestSetup(t, true, true, false)
	if !a.acquireWitness("office") {
		t.Fatal("first acquireWitness() = false, want true")
	}
	forge := func(tok *arbiter.Token) { tok.Signature = "" }
	arbiterFake.tamper = forge
	selfFake.tamper = forge
	if a.acquireWitness("office") {
		t.Fatal("second acquireWitness() = true, want false — both renewals and fresh requests were forged")
	}
	if a.witnessFor("office").Held {
		t.Error("witnessFor(office).Held = true, want false")
	}
}

func TestAcquireFromInstance_AcceptsGrantAndRenewalFromRealArbiter(t *testing.T) {
	if !timehealth.IsHealthyStrict(5 * time.Second) {
		t.Skip("host clock not synchronised; the real arbiter refuses grants")
	}
	m := arbiter.New([]byte("psk"), func() bool { return true }, t.TempDir())
	m.ResumeGrants()
	mux := http.NewServeMux()
	m.AddRoutes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	a := New(config.RoleCore1, "test-node", 7, "psk", "/tmp", testScopes("office"), nil)
	c := arbiterCandidate{addr: srv.Listener.Addr().String()}
	raw, _, ok := a.acquireFromInstance("office", c)
	if !ok {
		t.Fatal("acquireFromInstance() ok = false, want true for a grant from the real arbiter")
	}
	if _, _, ok := a.renewFromInstance("office", c, raw); !ok {
		t.Fatal("renewFromInstance() ok = false, want true for a renewal from the real arbiter")
	}
}
