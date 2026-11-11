// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package topobeacon

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

type sentProbe struct {
	at          time.Time
	scope, peer string
}

// fakeSender completes every probe at once (or holds the completion when hold
// is set) with the outcome the test scripts.
type fakeSender struct {
	clock   *fakeClock
	outcome func(t ScopeTarget, at time.Time) bool
	hold    bool

	mu     sync.Mutex
	sends  []sentProbe
	held   []func()
	closed bool
}

func (f *fakeSender) send(t ScopeTarget, done func(bool)) {
	f.mu.Lock()
	f.sends = append(f.sends, sentProbe{f.clock.now(), t.Scope, t.PeerRole})
	hold, ok := f.hold, f.outcome == nil || f.outcome(t, f.clock.now())
	if hold {
		f.held = append(f.held, func() { done(ok) })
	}
	f.mu.Unlock()
	if !hold {
		done(ok)
	}
}
func (f *fakeSender) sweep(time.Time) {}
func (f *fakeSender) close()          { f.closed = true }
func (f *fakeSender) count() int      { f.mu.Lock(); defer f.mu.Unlock(); return len(f.sends) }

type simEnv struct {
	r       *ScopeBeaconRunner
	s       *fakeSender
	clock   *fakeClock
	mon     *ScopeMonitor
	cfg     schedConfig
	perTick []int
}

func newSim(cfg schedConfig, outcome func(ScopeTarget, time.Time) bool) *simEnv {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s := &fakeSender{clock: clock, outcome: outcome}
	mon := NewScopeMonitor(nil)
	r := newScopeBeaconRunner("core-1", []byte("psk"), mon, cfg, clock.now, func(string, []byte, time.Duration) (scopeProbeSender, error) { return s, nil })
	r.noLoop = true
	return &simEnv{r: r, s: s, clock: clock, mon: mon, cfg: cfg}
}

// run advances the fake clock tick by tick for d, running the scheduler.
func (e *simEnv) run(d time.Duration) {
	for end := e.clock.t.Add(d); e.clock.t.Before(end); {
		e.clock.advance(e.cfg.tick)
		before := e.s.count()
		e.r.tick(e.s, e.clock.now())
		e.perTick = append(e.perTick, e.s.count()-before)
	}
}

func simTargets(pairs int) []ScopeTarget {
	var out []ScopeTarget
	for i := 0; len(out) < pairs; i++ {
		for _, peer := range []string{"core-2", "core-3"} {
			if len(out) < pairs {
				out = append(out, ScopeTarget{Scope: fmt.Sprintf("s%04d", i), LocalAddr: "10.0.0.1", PeerRole: peer, PeerAddr: "10.0.0.2"})
			}
		}
	}
	return out
}

func maxInt(v []int) int {
	m := 0
	for _, x := range v {
		if x > m {
			m = x
		}
	}
	return m
}

func TestSched_BatchLimitAndNoStarvation(t *testing.T) {
	for _, pairs := range []int{204, 1000, 5000} {
		t.Run(fmt.Sprintf("%d pairs", pairs), func(t *testing.T) {
			cfg := defaultSchedConfig()
			e := newSim(cfg, nil)
			e.r.Update(context.Background(), simTargets(pairs))
			eff := e.r.effTOK
			e.run(4*eff + 2*time.Second)

			if m := maxInt(e.perTick); m > cfg.batch {
				t.Fatalf("a tick sent %d probes, the limit is %d", m, cfg.batch)
			}
			byPair := map[string][]time.Time{}
			for _, sp := range e.s.sends {
				k := scopeKey(sp.scope, sp.peer)
				byPair[k] = append(byPair[k], sp.at)
			}
			if len(byPair) != pairs {
				t.Fatalf("%d of %d pairs were probed at all", len(byPair), pairs)
			}
			var worst time.Duration
			for k, ts := range byPair {
				if len(ts) < 3 {
					t.Fatalf("pair %s probed only %d times in 4 intervals", k, len(ts))
				}
				for i := 1; i < len(ts); i++ {
					if g := ts[i].Sub(ts[i-1]); g > worst {
						worst = g
					}
				}
			}
			if bound := eff*3/2 + 3*time.Second; worst > bound {
				t.Errorf("longest gap between two probes of one pair is %v, bound %v (effective interval %v)", worst, bound, eff)
			}
		})
	}
}

func TestSched_EffectiveIntervalStretchesOnlyWhenNeeded(t *testing.T) {
	cfg := defaultSchedConfig()
	for _, tt := range []struct {
		pairs   int
		stretch bool
	}{{204, false}, {400, false}, {600, false}, {2000, true}, {5000, true}} {
		e := newSim(cfg, nil)
		e.r.Update(context.Background(), simTargets(tt.pairs))
		stretched := e.r.effTOK > cfg.tOK
		if stretched != tt.stretch {
			t.Errorf("%d pairs: effective interval %v, stretched = %v, want %v", tt.pairs, e.r.effTOK, stretched, tt.stretch)
		}
		if used := float64(tt.pairs) / e.r.effTOK.Seconds() / cfg.capacity(); used > cfg.maxUtil+0.001 {
			t.Errorf("%d pairs use %.0f%% of the capacity, limit %.0f%%", tt.pairs, used*100, cfg.maxUtil*100)
		}
	}
}

func TestSched_SteadyRateIsPairsOverInterval(t *testing.T) {
	e := newSim(defaultSchedConfig(), nil)
	e.r.Update(context.Background(), simTargets(204))
	e.run(30 * time.Second) // settle into the slot grid
	before := e.s.count()
	e.run(60 * time.Second)
	rate := float64(e.s.count()-before) / 60
	if rate < 18 || rate > 22 {
		t.Errorf("steady rate %.1f probes per second, want about 20 (204 pairs every 10 s)", rate)
	}
	// 204 hashed phases over 100 ms ticks average two probes per tick; clumps of a
	// few are expected, a tick must never reach the batch limit in steady state.
	if m := maxInt(e.perTick[len(e.perTick)-600:]); m >= e.cfg.batch {
		t.Errorf("in steady state a tick sent %d probes, want an even spread well below the limit of %d", m, e.cfg.batch)
	}
}

func unreachableSince(e *simEnv, scope, peer string) bool {
	for _, st := range e.mon.Snapshot() {
		if st.Scope == scope && st.PeerRole == peer {
			return !st.Reachable
		}
	}
	return false
}

func TestSched_DetectionAndRecoveryTimes(t *testing.T) {
	var failFrom, recoverAt time.Time
	e := newSim(defaultSchedConfig(), func(t ScopeTarget, at time.Time) bool {
		return failFrom.IsZero() || at.Before(failFrom) || !at.Before(recoverAt)
	})
	target := ScopeTarget{Scope: "office", LocalAddr: "10.0.0.1", PeerRole: "core-2", PeerAddr: "10.0.0.2"}
	e.r.Update(context.Background(), []ScopeTarget{target})
	e.run(25 * time.Second)
	if unreachableSince(e, "office", "core-2") {
		t.Fatal("a healthy pair is reported unreachable")
	}

	failFrom = e.clock.now()
	recoverAt = failFrom.Add(90 * time.Second)
	var detected time.Duration
	for step := time.Duration(0); step < 30*time.Second; step += e.cfg.tick {
		e.run(e.cfg.tick)
		if unreachableSince(e, "office", "core-2") {
			detected = e.clock.now().Sub(failFrom)
			break
		}
	}
	if detected == 0 || detected > 13*time.Second {
		t.Fatalf("detection took %v, want within 13 s (10 s interval plus two retries)", detected)
	}

	var misses []time.Time
	for _, sp := range e.s.sends {
		if !sp.at.Before(failFrom) {
			misses = append(misses, sp.at)
		}
	}
	if len(misses) < 3 || misses[1].Sub(misses[0]) > 1200*time.Millisecond || misses[2].Sub(misses[1]) > 1200*time.Millisecond {
		t.Errorf("after the first miss the retries must follow about a second apart, got %v", misses)
	}

	e.run(recoverAt.Sub(e.clock.now()))
	var recovered time.Duration
	for step := time.Duration(0); step < 30*time.Second; step += e.cfg.tick {
		e.run(e.cfg.tick)
		if !unreachableSince(e, "office", "core-2") {
			recovered = e.clock.now().Sub(recoverAt)
			break
		}
	}
	if recovered == 0 || recovered > 6*time.Second {
		t.Errorf("recovery took %v, want within 6 s (the unreachable interval of 5 s plus its jitter)", recovered)
	}
}

func TestSched_ASilentPeerIsPacedAndDetected(t *testing.T) {
	var failFrom time.Time
	e := newSim(defaultSchedConfig(), func(t ScopeTarget, at time.Time) bool {
		return t.PeerRole != "core-3" || failFrom.IsZero() || at.Before(failFrom)
	})
	e.r.Update(context.Background(), simTargets(204))
	e.run(25 * time.Second)
	e.perTick = nil
	failFrom = e.clock.now()
	var allDown time.Duration
	for step := time.Duration(0); step < 40*time.Second; step += e.cfg.tick {
		e.run(e.cfg.tick)
		down := 0
		for _, st := range e.mon.Snapshot() {
			if st.PeerRole == "core-3" && !st.Reachable {
				down++
			}
		}
		if down == 102 {
			allDown = e.clock.now().Sub(failFrom)
			break
		}
	}
	if allDown == 0 || allDown > 16*time.Second {
		t.Errorf("all 102 pairs to the silent peer were flagged after %v, want within 16 s", allDown)
	}
	if m := maxInt(e.perTick); m > e.cfg.batch {
		t.Errorf("a tick sent %d probes while a peer was silent, limit %d", m, e.cfg.batch)
	}
	for _, st := range e.mon.Snapshot() {
		if st.PeerRole == "core-2" && !st.Reachable {
			t.Fatalf("the healthy peer's pair %s was flagged", st.Scope)
		}
	}
}

func TestSched_NewPairsGetAnEarlyFirstProbe(t *testing.T) {
	e := newSim(defaultSchedConfig(), nil)
	e.r.Update(context.Background(), simTargets(20))
	e.run(2 * time.Second)
	if n := e.s.count(); n != 20 {
		t.Fatalf("%d of 20 new pairs probed within 2 s", n)
	}
	e.run(20 * time.Second)
	late := ScopeTarget{Scope: "added", LocalAddr: "10.0.0.1", PeerRole: "core-2", PeerAddr: "10.0.0.2"}
	e.r.Update(context.Background(), append(simTargets(20), late))
	added := e.clock.now()
	before := e.s.count()
	e.run(1500 * time.Millisecond)
	var seen bool
	for _, sp := range e.s.sends[before:] {
		if sp.scope == "added" && sp.at.Sub(added) <= 1200*time.Millisecond {
			seen = true
		}
	}
	if !seen {
		t.Error("a pair added later was not probed within about a second")
	}
}

func TestSched_RemovedPairsAreNeverProbedOrRecorded(t *testing.T) {
	e := newSim(defaultSchedConfig(), nil)
	e.s.hold = true
	targets := simTargets(6)
	e.r.Update(context.Background(), targets)
	e.run(1500 * time.Millisecond)
	if e.s.count() != 6 {
		t.Fatalf("setup: %d probes in flight, want 6", e.s.count())
	}
	e.r.Update(context.Background(), targets[:3]) // three removed while their probes are in flight
	for _, done := range e.s.held {
		done()
	}
	if n := len(e.mon.Snapshot()); n != 3 {
		t.Fatalf("late results of removed pairs re-created entries: %d entries, want 3", n)
	}
	e.s.hold = false
	before := e.s.count()
	e.run(30 * time.Second)
	for _, sp := range e.s.sends[before:] {
		for _, gone := range targets[3:] {
			if sp.scope == gone.Scope && sp.peer == gone.PeerRole {
				t.Fatalf("removed pair %s/%s was probed again", sp.scope, sp.peer)
			}
		}
	}
	e.r.Update(context.Background(), nil)
	if e.r.queue.Len() != 0 || len(e.r.running) != 0 {
		t.Errorf("after removing everything the queue holds %d and %d are running", e.r.queue.Len(), len(e.r.running))
	}
}

func TestSched_ProbeScopesRunsThePairsOfThoseScopesAtOnce(t *testing.T) {
	e := newSim(defaultSchedConfig(), nil)
	e.r.Update(context.Background(), simTargets(20))
	e.run(8 * time.Second) // everything probed once, next probes far away
	before := e.s.count()
	e.r.ProbeScopes("s0003", "unknown-scope")
	e.run(2 * e.cfg.tick)
	got := e.s.sends[before:]
	if len(got) != 2 {
		t.Fatalf("%d probes after ProbeScopes, want the 2 pairs of s0003: %v", len(got), got)
	}
	for _, sp := range got {
		if sp.scope != "s0003" {
			t.Errorf("probed %s, only s0003 was asked for", sp.scope)
		}
	}

	e.s.hold = true
	e.r.ProbeScopes("s0005")
	e.run(2 * e.cfg.tick)
	inFlight := e.s.count()
	e.r.ProbeScopes("s0005") // while probes are in flight: probe again as soon as they complete
	e.s.hold = false
	held := e.s.held
	e.s.held = nil
	for _, done := range held {
		done()
	}
	e.run(2 * e.cfg.tick)
	again := 0
	for _, sp := range e.s.sends[inFlight:] {
		if sp.scope == "s0005" {
			again++
		}
	}
	if again != 2 {
		t.Errorf("%d re-probes of s0005 after the in-flight ones completed, want 2", again)
	}
}

func TestSched_SlotGridIsStableAndAtLeastHalfAnIntervalAway(t *testing.T) {
	e := newSim(defaultSchedConfig(), nil)
	e.r.Update(context.Background(), simTargets(2))
	var p *scopePair
	for _, x := range e.r.running {
		p = x
		break
	}
	T := e.r.effTOK
	phase := time.Duration(p.hash % uint64(T))
	e.r.mu.Lock()
	defer e.r.mu.Unlock()
	for _, off := range []time.Duration{0, 1234 * time.Millisecond, 4999 * time.Millisecond, 7 * time.Second, 9999 * time.Millisecond} {
		now := e.clock.now().Add(off)
		next := e.r.nextSlotLocked(p, now)
		if next.Sub(now) < T/2 || next.Sub(now) > T/2+T {
			t.Errorf("from +%v the next slot is %v away, want between half and one and a half intervals", off, next.Sub(now))
		}
		if (next.UnixNano()-int64(phase))%int64(T) != 0 {
			t.Errorf("slot %v is not on the pair's grid", next)
		}
		if again := e.r.nextSlotLocked(p, next); again.Sub(next) != T {
			t.Errorf("probing at its slot must keep the cadence: next after %v is %v later, want %v", next, again.Sub(next), T)
		}
	}
	if p2 := pairHash("core-1", p.target); p2 != p.hash {
		t.Error("the phase must be stable for the same pair")
	}
	if pairHash("core-2", p.target) == p.hash {
		t.Error("the two nodes of a pair should not share a phase")
	}
}

func TestSched_ConcurrentUpdateProbeAndTick(t *testing.T) {
	e := newSim(defaultSchedConfig(), func(ScopeTarget, time.Time) bool { return true })
	e.cfg.tick = 10 * time.Millisecond
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for g := 0; g < 3; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				switch g {
				case 0:
					e.r.Update(context.Background(), simTargets(10+i%30))
				case 1:
					e.r.ProbeScopes(fmt.Sprintf("s%04d", i%20))
				case 2:
					e.r.mu.Lock()
					e.clock.advance(100 * time.Millisecond)
					now := e.clock.now()
					e.r.mu.Unlock()
					e.r.tick(e.s, now)
				}
			}
		}(g)
	}
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func BenchmarkSchedTick204(b *testing.B) {
	e := newSim(defaultSchedConfig(), nil)
	e.r.Update(context.Background(), simTargets(204))
	b.ReportAllocs()
	for b.Loop() {
		e.clock.advance(e.cfg.tick)
		e.r.tick(e.s, e.clock.now())
	}
	e.s.sends = nil
}

// ---- the real prober ----

// reply answers a probe from the given socket, with the given changes.
func startResponder(t *testing.T, listenIP, replyFromIP string, psk []byte, mutate func(*scopeReply)) func() int {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(listenIP), Port: ScopePort})
	if err != nil {
		t.Skipf("cannot bind %s:%d: %v", listenIP, ScopePort, err)
	}
	out := conn
	if replyFromIP != listenIP {
		out, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(replyFromIP)})
		if err != nil {
			t.Skip(err)
		}
	}
	var answered atomic.Int32
	go func() {
		buf := make([]byte, 1024)
		for {
			n, raddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var req scopeRequest
			if json.Unmarshal(buf[:n], &req) != nil || !req.Verify(psk) {
				continue
			}
			rep := scopeReply{Magic: ScopeMagic, Role: "core-2", Scope: req.Scope, Nonce: req.Nonce}
			if mutate != nil {
				mutate(&rep)
			}
			rep.Signature = rep.Sign(psk)
			b, _ := json.Marshal(rep)
			out.WriteToUDP(b, raddr)
			answered.Add(1)
		}
	}()
	t.Cleanup(func() {
		conn.Close()
		out.Close()
	})
	return func() int { return int(answered.Load()) }
}

func TestProber_AcceptsOnlyTheRealAnswer(t *testing.T) {
	psk := []byte("prober-psk")
	target := func(ip string) ScopeTarget {
		return ScopeTarget{Scope: "office", LocalAddr: "10.0.0.1", PeerRole: "core-2", PeerAddr: ip}
	}
	startResponder(t, "127.0.0.11", "127.0.0.11", psk, nil)
	if !probeOnce(t, "core-1", target("127.0.0.11"), psk, 400*time.Millisecond) {
		t.Error("a correct reply from the probed address must count")
	}
	startResponder(t, "127.0.0.12", "127.0.0.13", psk, nil)
	if probeOnce(t, "core-1", target("127.0.0.12"), psk, 200*time.Millisecond) {
		t.Error("a reply from another source address must not count")
	}
	startResponder(t, "127.0.0.14", "127.0.0.14", psk, func(r *scopeReply) { r.Nonce++ })
	if probeOnce(t, "core-1", target("127.0.0.14"), psk, 200*time.Millisecond) {
		t.Error("a reply with another nonce must not count")
	}
	startResponder(t, "127.0.0.15", "127.0.0.15", psk, func(r *scopeReply) { r.Scope = "other" })
	if probeOnce(t, "core-1", target("127.0.0.15"), psk, 200*time.Millisecond) {
		t.Error("a reply for another scope must not count")
	}
}

func TestProber_OutcomeIsReportedOnceAndLateRepliesAreIgnored(t *testing.T) {
	psk := []byte("prober-psk")
	startResponder(t, "127.0.0.16", "127.0.0.16", psk, nil)
	p, err := newUDPScopeProber("core-1", psk, 150*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	var calls atomic.Int32
	var last atomic.Bool
	p.send(ScopeTarget{Scope: "office", PeerRole: "core-2", PeerAddr: "127.0.0.16"}, func(ok bool) { calls.Add(1); last.Store(ok) })
	time.Sleep(100 * time.Millisecond)
	p.sweep(time.Now())
	p.sweep(time.Now().Add(time.Second))
	time.Sleep(100 * time.Millisecond)
	if calls.Load() != 1 || !last.Load() {
		t.Errorf("done called %d times, last ok = %v, want once with true", calls.Load(), last.Load())
	}

	// A probe nobody answers expires once; a reply that arrives afterwards is dropped.
	var misses atomic.Int32
	p.send(ScopeTarget{Scope: "office", PeerRole: "core-2", PeerAddr: "127.0.0.99"}, func(ok bool) {
		if !ok {
			misses.Add(1)
		}
	})
	p.sweep(time.Now().Add(time.Second))
	p.sweep(time.Now().Add(2 * time.Second))
	if misses.Load() != 1 {
		t.Errorf("an unanswered probe was reported %d times, want once", misses.Load())
	}
}

func TestProber_WriteErrorIsAnImmediateMiss(t *testing.T) {
	p, err := newUDPScopeProber("core-1", []byte("x"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	got := make(chan bool, 1)
	p.send(ScopeTarget{Scope: "s", PeerRole: "core-2", PeerAddr: "not-an-address"}, func(ok bool) { got <- ok })
	select {
	case ok := <-got:
		if ok {
			t.Error("an unusable peer address cannot be reachable")
		}
	case <-time.After(time.Second):
		t.Error("an unusable peer address must be reported as a miss at once")
	}
}

// BenchmarkProbeRoundTrip204 sends 204 probes through the real prober to a
// loopback listener and waits for every reply.
func BenchmarkProbeRoundTrip204(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	psk := []byte("bench-psk")
	ListenScopeBeacons(ctx, "core-2", []string{"127.0.0.1"}, psk)
	time.Sleep(50 * time.Millisecond)
	p, err := newUDPScopeProber("core-1", psk, 2*time.Second)
	if err != nil {
		b.Fatal(err)
	}
	defer p.close()
	targets := simTargets(204)
	for i := range targets {
		targets[i].PeerAddr = "127.0.0.1"
	}
	b.ReportAllocs()
	for b.Loop() {
		var wg sync.WaitGroup
		wg.Add(len(targets))
		for _, t := range targets {
			p.send(t, func(bool) { wg.Done() })
		}
		wg.Wait()
	}
}
