// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package topobeacon

import (
	"container/heap"
	"context"
	"encoding/json"
	"hash/fnv"
	"net"
	"sync"
	"time"

	"dnshived/internal/loglevel"
)

// ScopeBeaconInterval is how often a healthy (scope, peer) pairing is probed.
const ScopeBeaconInterval = 10 * time.Second

// schedConfig holds the scheduler's timing. The defaults are the production
// values; tests use faster ones.
type schedConfig struct {
	tick         time.Duration // how often the scheduler looks at the queue
	batch        int           // most probes sent in one tick
	tOK          time.Duration // interval of a healthy pairing
	tDown        time.Duration // interval of an unreachable pairing
	retry        time.Duration // re-probe after a missed reply, until the miss limit
	early        time.Duration // first probe of a new pairing happens within this
	replyTimeout time.Duration // how long a reply is waited for
	maxUtil      float64       // share of the capacity the rotation may use
}

func defaultSchedConfig() schedConfig {
	return schedConfig{
		tick: 100 * time.Millisecond, batch: 10, tOK: ScopeBeaconInterval,
		tDown: 5 * time.Second, retry: time.Second, early: time.Second,
		replyTimeout: 1500 * time.Millisecond, maxUtil: 0.6,
	}
}

// capacity is the most probes per second the scheduler can send.
func (c schedConfig) capacity() float64 { return float64(c.batch) / c.tick.Seconds() }

// scopeProbeSender sends one probe and reports the outcome exactly once, from
// any goroutine. send never blocks on the network.
type scopeProbeSender interface {
	send(t ScopeTarget, done func(ok bool))
	// sweep reports a miss for every probe that has waited longer than its timeout.
	sweep(now time.Time)
	close()
}

// scopePair is the scheduler's state for one (scope, peer) pairing.
type scopePair struct {
	key    string
	id     uint64
	target ScopeTarget
	hash   uint64
	due    time.Time
	idx    int // position in the queue, -1 while sent or removed

	inflight bool
	again    bool // probe again at once when the one in flight completes
	everOK   bool
	misses   int
}

type pairQueue []*scopePair

func (q pairQueue) Len() int { return len(q) }
func (q pairQueue) Less(i, j int) bool {
	if !q[i].due.Equal(q[j].due) {
		return q[i].due.Before(q[j].due)
	}
	return q[i].key < q[j].key
}
func (q pairQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i]; q[i].idx, q[j].idx = i, j }
func (q *pairQueue) Push(x any)   { p := x.(*scopePair); p.idx = len(*q); *q = append(*q, p) }
func (q *pairQueue) Pop() any {
	old := *q
	n := len(old)
	p := old[n-1]
	old[n-1] = nil
	p.idx = -1
	*q = old[:n-1]
	return p
}

// ScopeBeaconRunner probes every (scope, peer) pairing from one scheduler: a
// fixed tick sends the pairings that are due, at most a batch per tick, over
// one long-lived socket, and never waits for a reply, so the rotation always
// finishes. Healthy pairings are probed every tOK from a stable phase, a
// pairing that missed a reply is probed again after a short retry until the
// miss limit, an unreachable one every tDown. When there are so many pairings
// that the rotation would use more than maxUtil of the capacity, the interval
// is stretched instead of falling behind.
type ScopeBeaconRunner struct {
	mu      sync.Mutex
	role    string
	psk     []byte
	monitor *ScopeMonitor
	cfg     schedConfig
	now     func() time.Time

	newSender func(role string, psk []byte, replyTimeout time.Duration) (scopeProbeSender, error)
	noLoop    bool // tests drive tick themselves
	loopCtx   context.Context

	running map[string]*scopePair
	queue   pairQueue
	nextID  uint64
	effTOK  time.Duration
}

// NewScopeBeaconRunner creates a runner.
func NewScopeBeaconRunner(role string, psk []byte, monitor *ScopeMonitor) *ScopeBeaconRunner {
	return newScopeBeaconRunner(role, psk, monitor, defaultSchedConfig(), time.Now, newUDPScopeProber)
}

func newScopeBeaconRunner(role string, psk []byte, monitor *ScopeMonitor, cfg schedConfig, now func() time.Time,
	newSender func(string, []byte, time.Duration) (scopeProbeSender, error)) *ScopeBeaconRunner {
	return &ScopeBeaconRunner{
		role: role, psk: psk, monitor: monitor, cfg: cfg, now: now, newSender: newSender,
		running: make(map[string]*scopePair), effTOK: cfg.tOK,
	}
}

func pairHash(role string, t ScopeTarget) uint64 {
	h := fnv.New64a()
	h.Write([]byte(role))
	h.Write([]byte{0})
	h.Write([]byte(t.Scope))
	h.Write([]byte{0})
	h.Write([]byte(t.PeerRole))
	return h.Sum64()
}

// Update makes the set of pairings match targets: new ones are queued for an
// early first probe, removed or changed ones are dropped, unchanged ones keep
// their place.
func (r *ScopeBeaconRunner) Update(ctx context.Context, targets []ScopeTarget) {
	r.mu.Lock()
	defer r.mu.Unlock()

	wanted := make(map[string]ScopeTarget, len(targets))
	for _, t := range targets {
		wanted[scopeKey(t.Scope, t.PeerRole)] = t
	}
	for key, p := range r.running {
		if t, ok := wanted[key]; ok && t == p.target {
			continue
		}
		if p.idx >= 0 {
			heap.Remove(&r.queue, p.idx)
		}
		delete(r.running, key)
		r.monitor.Remove(p.target.Scope, p.target.PeerRole)
	}
	now := r.now()
	for key, t := range wanted {
		if _, exists := r.running[key]; exists {
			continue
		}
		r.nextID++
		p := &scopePair{key: key, id: r.nextID, target: t, hash: pairHash(r.role, t), idx: -1}
		p.due = now.Add(time.Duration(p.hash % uint64(r.cfg.early+1)))
		r.running[key] = p
		heap.Push(&r.queue, p)
	}
	r.stretchLocked()
	if !r.noLoop {
		r.ensureLoopLocked(ctx)
	}
}

// stretchLocked sets the effective healthy interval for the current number of
// pairings.
func (r *ScopeBeaconRunner) stretchLocked() {
	eff := r.cfg.tOK
	if need := time.Duration(float64(len(r.running)) / (r.cfg.maxUtil * r.cfg.capacity()) * float64(time.Second)); need > eff {
		eff = need.Round(time.Millisecond)
	}
	if eff != r.effTOK && eff > r.cfg.tOK {
		loglevel.Warnf("[TOPOBEACON:SCOPE] %d pairings need more than %.0f%% of the beacon capacity at %v, probing every %v instead", len(r.running), r.cfg.maxUtil*100, r.cfg.tOK, eff)
	}
	r.effTOK = eff
}

func (r *ScopeBeaconRunner) ensureLoopLocked(ctx context.Context) {
	if r.loopCtx != nil && r.loopCtx.Err() == nil {
		return
	}
	s, err := r.newSender(r.role, r.psk, r.cfg.replyTimeout)
	if err != nil {
		loglevel.Warnf("[TOPOBEACON:ERROR] scope beacon socket: %v", err)
		return
	}
	r.loopCtx = ctx
	go r.run(ctx, s)
}

func (r *ScopeBeaconRunner) run(ctx context.Context, s scopeProbeSender) {
	defer s.close()
	tk := time.NewTicker(r.cfg.tick)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			r.tick(s, r.now())
		}
	}
}

// tick sends the pairings that are due, at most a batch.
func (r *ScopeBeaconRunner) tick(s scopeProbeSender, now time.Time) {
	s.sweep(now)
	r.mu.Lock()
	var batch []*scopePair
	for len(batch) < r.cfg.batch && len(r.queue) > 0 && !r.queue[0].due.After(now) {
		p := heap.Pop(&r.queue).(*scopePair)
		p.inflight = true
		batch = append(batch, p)
	}
	r.mu.Unlock()
	for _, p := range batch {
		key, id, t := p.key, p.id, p.target
		s.send(t, func(ok bool) { r.record(key, id, t, ok) })
	}
}

// record stores a probe result only while that exact pairing is still
// running, so a reply that lands after Update removed it can't re-create the
// entry, and schedules the pairing's next probe.
func (r *ScopeBeaconRunner) record(key string, id uint64, t ScopeTarget, ok bool) {
	r.mu.Lock()
	p, live := r.running[key]
	var notify func()
	if live && p.id == id {
		notify = r.monitor.applyResult(t.Scope, t.PeerRole, ok)
		r.rescheduleLocked(p, ok, r.now())
	}
	r.mu.Unlock()
	if notify != nil {
		notify()
	}
}

// rescheduleLocked queues p for its next probe after one that just completed.
func (r *ScopeBeaconRunner) rescheduleLocked(p *scopePair, ok bool, now time.Time) {
	if !p.inflight {
		return
	}
	p.inflight = false
	switch {
	case ok:
		p.everOK, p.misses = true, 0
		p.due = r.nextSlotLocked(p, now)
	case !p.everOK:
		p.misses++
		p.due = now.Add(r.cfg.tDown + r.downJitter(p))
	default:
		p.misses++
		if p.misses < scopeStaleAfterMisses {
			p.due = now.Add(r.cfg.retry)
		} else {
			p.due = now.Add(r.cfg.tDown + r.downJitter(p))
		}
	}
	if p.again {
		p.again = false
		p.due = now
	}
	heap.Push(&r.queue, p)
}

func (r *ScopeBeaconRunner) downJitter(p *scopePair) time.Duration {
	return time.Duration(p.hash % uint64(r.cfg.tDown/10+1))
}

// nextSlotLocked is the pairing's next healthy probe time: the first point of
// its own grid (a stable phase from its hash, one point per effective
// interval, aligned to the clock) that is at least half an interval away.
func (r *ScopeBeaconRunner) nextSlotLocked(p *scopePair, now time.Time) time.Time {
	t := int64(r.effTOK)
	phase := int64(p.hash % uint64(t))
	off := now.Add(r.effTOK/2).UnixNano() - phase
	k := off / t
	if off%t != 0 && off > 0 {
		k++
	}
	return time.Unix(0, phase+k*t)
}

// ProbeScopes makes the pairings of the named scopes due at once, for an event
// such as a trunk changing state or a scope being rebuilt. A pairing that has a
// probe in flight is probed again as soon as it completes.
func (r *ScopeBeaconRunner) ProbeScopes(names ...string) {
	if len(names) == 0 {
		return
	}
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	for _, p := range r.running {
		if !want[p.target.Scope] {
			continue
		}
		if p.idx >= 0 {
			p.due = now
			heap.Fix(&r.queue, p.idx)
		} else if p.inflight {
			p.again = true
		}
	}
}

// udpScopeProber sends probes from one long-lived, unbound UDP socket (the
// route to the peer's scope address decides the interface, as it did with a
// socket per probe) and a reader goroutine matches the replies.
type udpScopeProber struct {
	role    string
	psk     []byte
	timeout time.Duration
	conn    *net.UDPConn

	mu      sync.Mutex
	pending map[uint64]*pendingProbe
}

type pendingProbe struct {
	target   ScopeTarget
	peer     net.IP
	deadline time.Time
	done     func(ok bool)
}

func newUDPScopeProber(role string, psk []byte, timeout time.Duration) (scopeProbeSender, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	p := &udpScopeProber{role: role, psk: psk, timeout: timeout, conn: conn, pending: make(map[uint64]*pendingProbe)}
	go p.readLoop()
	return p, nil
}

func (p *udpScopeProber) send(t ScopeTarget, done func(ok bool)) {
	peer := net.ParseIP(t.PeerAddr).To4()
	if peer == nil {
		done(false)
		return
	}
	nonce := randomScopeNonce()
	req := scopeRequest{Magic: ScopeMagic, Role: p.role, Scope: t.Scope, Nonce: nonce}
	req.Signature = req.Sign(p.psk)
	payload, err := json.Marshal(req)
	if err != nil {
		done(false)
		return
	}
	p.mu.Lock()
	p.pending[nonce] = &pendingProbe{target: t, peer: peer, deadline: time.Now().Add(p.timeout), done: done}
	p.mu.Unlock()
	if _, err := p.conn.WriteToUDP(payload, &net.UDPAddr{IP: peer, Port: ScopePort}); err != nil {
		if pp := p.take(nonce); pp != nil {
			pp.done(false)
		}
	}
}

func (p *udpScopeProber) take(nonce uint64) *pendingProbe {
	p.mu.Lock()
	defer p.mu.Unlock()
	pp := p.pending[nonce]
	delete(p.pending, nonce)
	return pp
}

func (p *udpScopeProber) readLoop() {
	buf := make([]byte, 1024)
	for {
		n, raddr, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		var reply scopeReply
		if json.Unmarshal(buf[:n], &reply) != nil || reply.Magic != ScopeMagic {
			continue
		}
		p.mu.Lock()
		pp := p.pending[reply.Nonce]
		p.mu.Unlock()
		// A reply that does not match leaves the probe waiting: a forged
		// packet must not be able to cancel the real answer.
		if pp == nil || reply.Scope != pp.target.Scope || !raddr.IP.Equal(pp.peer) || !reply.Verify(p.psk) {
			continue
		}
		if got := p.take(reply.Nonce); got != nil {
			got.done(true)
		}
	}
}

func (p *udpScopeProber) sweep(now time.Time) {
	p.mu.Lock()
	var expired []*pendingProbe
	for nonce, pp := range p.pending {
		if now.After(pp.deadline) {
			expired = append(expired, pp)
			delete(p.pending, nonce)
		}
	}
	p.mu.Unlock()
	for _, pp := range expired {
		pp.done(false)
	}
}

func (p *udpScopeProber) close() { p.conn.Close() }
