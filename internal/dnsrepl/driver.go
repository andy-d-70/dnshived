// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsrepl

import (
	"context"
	"errors"
	"math/rand"
	"sync"
	"time"

	"dnshived/internal/dnsstore"
)

type Transport interface {
	Vote(ctx context.Context, peer string, req VoteReq) (VoteResp, error)
	Append(ctx context.Context, peer string, req AppendReq) (AppendResp, error)
	Snapshot(ctx context.Context, peer string, req SnapReq) (SnapResp, error)
}

var (
	ErrLost    = errors.New("dnsrepl: another leader replaced the proposed record")
	ErrUnknown = errors.New("dnsrepl: the outcome of the proposal is not known")
	ErrStopped = errors.New("dnsrepl: stopped")
)

type DriverConfig struct {
	Tick        time.Duration
	Heartbeat   time.Duration
	ElectionMin time.Duration
	ElectionMax time.Duration
	RPCTimeout  time.Duration
	SnapTimeout time.Duration
	// Permit says whether this node may campaign and lead; the daemon ties it to a stable cluster.
	Permit   func() bool
	OnCommit func()
	Log      func(format string, a ...any)
	Seed     int64
}

func (c *DriverConfig) defaults() {
	set := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	set(&c.Tick, 50*time.Millisecond)
	set(&c.Heartbeat, 250*time.Millisecond)
	set(&c.ElectionMin, 1500*time.Millisecond)
	set(&c.ElectionMax, 3000*time.Millisecond)
	set(&c.RPCTimeout, 2*time.Second)
	set(&c.SnapTimeout, 60*time.Second)
	if c.OnCommit == nil {
		c.OnCommit = func() {}
	}
	if c.Log == nil {
		c.Log = func(string, ...any) {}
	}
	if c.ElectionMax < c.ElectionMin {
		c.ElectionMax = c.ElectionMin
	}
}

// Driver runs a Node in real time: election timer, heartbeats, one replication loop per peer.
type Driver struct {
	node *Node
	tr   Transport
	cfg  DriverConfig

	mu       sync.Mutex
	deadline time.Time
	nextBeat time.Time
	busy     map[string]bool
	last     uint64
	rng      *rand.Rand
	role     Role

	stop chan struct{}
	once sync.Once
	wg   sync.WaitGroup
}

func NewDriver(n *Node, tr Transport, cfg DriverConfig) *Driver {
	cfg.defaults()
	d := &Driver{node: n, tr: tr, cfg: cfg, busy: map[string]bool{}, stop: make(chan struct{}), rng: rand.New(rand.NewSource(cfg.Seed + time.Now().UnixNano()))}
	d.resetDeadlineLocked(time.Now())
	d.last = n.st.CommitIndex()
	return d
}

func (d *Driver) Node() *Node { return d.node }

func (d *Driver) resetDeadlineLocked(now time.Time) {
	span := d.cfg.ElectionMax - d.cfg.ElectionMin
	jitter := time.Duration(0)
	if span > 0 {
		jitter = time.Duration(d.rng.Int63n(int64(span)))
	}
	d.deadline = now.Add(d.cfg.ElectionMin + jitter)
}

func (d *Driver) heard() {
	d.mu.Lock()
	d.resetDeadlineLocked(time.Now())
	d.mu.Unlock()
}

func (d *Driver) Start() {
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		t := time.NewTicker(d.cfg.Tick)
		defer t.Stop()
		for {
			select {
			case <-d.stop:
				return
			case <-t.C:
				d.tick()
			}
		}
	}()
}

func (d *Driver) Stop() {
	d.once.Do(func() { close(d.stop) })
	d.wg.Wait()
}

func (d *Driver) ctx(timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	go func() {
		select {
		case <-d.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

func (d *Driver) commitMaybeChanged() {
	c := d.node.st.CommitIndex()
	d.mu.Lock()
	changed := c != d.last
	d.last = c
	d.mu.Unlock()
	if changed {
		d.cfg.OnCommit()
	}
}

func (d *Driver) tick() {
	now := time.Now()
	role := d.node.Role()
	d.mu.Lock()
	if role != d.role {
		d.cfg.Log("[DNSREPL] role %s -> %s, term %d, leader %q", d.role, role, d.node.Term(), d.node.Leader())
		d.role = role
	}
	d.mu.Unlock()
	if d.cfg.Permit != nil && !d.cfg.Permit() {
		if role != Follower {
			d.node.StepDown()
		}
		d.heard()
		return
	}
	d.commitMaybeChanged()
	if role == Leader {
		d.mu.Lock()
		beat := now.After(d.nextBeat)
		if beat {
			d.nextBeat = now.Add(d.cfg.Heartbeat)
		}
		d.mu.Unlock()
		if beat {
			for _, p := range d.node.Peers() {
				d.replicateAsync(p)
			}
		}
		return
	}
	d.mu.Lock()
	due := now.After(d.deadline)
	if due {
		d.resetDeadlineLocked(now)
	}
	d.mu.Unlock()
	if due {
		d.campaign()
	}
}

func (d *Driver) campaign() {
	req, peers, err := d.node.Campaign()
	if err != nil {
		d.cfg.Log("[DNSREPL] cannot campaign: %v", err)
		return
	}
	if d.node.Role() == Leader {
		d.becameLeader()
		return
	}
	for _, p := range peers {
		d.wg.Add(1)
		go func(p string) {
			defer d.wg.Done()
			ctx, cancel := d.ctx(d.cfg.RPCTimeout)
			defer cancel()
			resp, err := d.tr.Vote(ctx, p, req)
			if err != nil {
				return
			}
			became, err := d.node.OnVote(p, req, resp)
			if err != nil {
				d.cfg.Log("[DNSREPL] vote from %s: %v", p, err)
				return
			}
			if became {
				d.becameLeader()
			}
		}(p)
	}
}

func (d *Driver) becameLeader() {
	d.cfg.Log("[DNSREPL] leader of term %d", d.node.Term())
	d.mu.Lock()
	d.nextBeat = time.Now().Add(d.cfg.Heartbeat)
	d.mu.Unlock()
	d.commitMaybeChanged()
	for _, p := range d.node.Peers() {
		d.replicateAsync(p)
	}
}

func (d *Driver) replicateAsync(peer string) {
	d.mu.Lock()
	if d.busy[peer] {
		d.mu.Unlock()
		return
	}
	d.busy[peer] = true
	d.mu.Unlock()
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		defer func() {
			d.mu.Lock()
			d.busy[peer] = false
			d.mu.Unlock()
		}()
		for i := 0; i < 64; i++ {
			select {
			case <-d.stop:
				return
			default:
			}
			if !d.replicateOnce(peer) {
				return
			}
		}
	}()
}

// replicateOnce sends one message to a peer and reports whether another one should follow at once.
func (d *Driver) replicateOnce(peer string) bool {
	kind, areq, sreq, err := d.node.Replicate(peer)
	if err != nil || kind == SendNothing {
		return false
	}
	switch kind {
	case SendAppend:
		ctx, cancel := d.ctx(d.cfg.RPCTimeout)
		resp, err := d.tr.Append(ctx, peer, areq)
		cancel()
		if err != nil {
			return false
		}
		if err := d.node.OnAppendResp(peer, areq, resp); err != nil {
			return false
		}
		d.commitMaybeChanged()
		head, _, _ := d.node.st.Head()
		return !resp.Success || len(areq.Entries) > 0 && resp.Match < head
	default:
		ctx, cancel := d.ctx(d.cfg.SnapTimeout)
		resp, err := d.tr.Snapshot(ctx, peer, sreq)
		cancel()
		if err != nil {
			return false
		}
		if err := d.node.OnSnapResp(peer, sreq, resp); err != nil {
			return false
		}
		d.commitMaybeChanged()
		return resp.Success
	}
}

// HandleVote, HandleAppend and HandleSnapshot are the receiving side; the transport's server calls them.
func (d *Driver) HandleVote(req VoteReq) (VoteResp, error) {
	resp, err := d.node.HandleVote(req)
	if err == nil && resp.Granted {
		d.heard()
	}
	return resp, err
}

func (d *Driver) HandleAppend(req AppendReq) (AppendResp, error) {
	resp, err := d.node.HandleAppend(req)
	if err == nil && resp.Term == req.Term {
		d.heard()
	}
	d.commitMaybeChanged()
	return resp, err
}

func (d *Driver) HandleSnapshot(req SnapReq) (SnapResp, error) {
	resp, err := d.node.HandleSnapshot(req)
	if err == nil && resp.Term == req.Term {
		d.heard()
	}
	d.commitMaybeChanged()
	return resp, err
}

// Propose appends a gated batch as leader and waits until it is committed, replaced, or ctx ends.
func (d *Driver) Propose(ctx context.Context, b dnsstore.Batch) (uint64, error) {
	rev, chain, term, err := d.node.Propose(b)
	if err != nil {
		return 0, err
	}
	d.commitMaybeChanged()
	for _, p := range d.node.Peers() {
		d.replicateAsync(p)
	}
	t := time.NewTicker(5 * time.Millisecond)
	defer t.Stop()
	for {
		switch d.node.Outcome(rev, chain, term) {
		case Committed:
			d.commitMaybeChanged()
			return rev, nil
		case Lost:
			return 0, ErrLost
		}
		select {
		case <-ctx.Done():
			return rev, ErrUnknown
		case <-d.stop:
			return rev, ErrStopped
		case <-t.C:
		}
	}
}
