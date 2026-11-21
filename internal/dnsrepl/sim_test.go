// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsrepl

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"testing"

	"dnshived/internal/dnsstore"
	"dnshived/internal/dnsstore/vfs/faultfs"
)

const simDir = "/n"

type msgKind int

const (
	mVoteReq msgKind = iota
	mVoteResp
	mAppReq
	mAppResp
	mSnapReq
	mSnapResp
)

type simMsg struct {
	at       int
	from, to string
	kind     msgKind
	vreq     VoteReq
	vresp    VoteResp
	areq     AppendReq
	aresp    AppendResp
	sreq     SnapReq
	sresp    SnapResp
}

type simNode struct {
	id        string
	fs        *faultfs.FS
	st        *dnsstore.Store
	n         *Node
	up        bool
	downUntil int
	lastHeard int
	timeout   int
	checked   uint64
}

type pend struct {
	node  string
	rev   uint64
	chain [32]byte
	term  uint64
	since int
	row   int
}

type sim struct {
	t         *testing.T
	rng       *rand.Rand
	tick      int
	ids       []string
	nodes     map[string]*simNode
	q         []simMsg
	group     map[string]int
	storeID   dnsstore.ID
	leaders   map[uint64]string
	committed map[uint64][32]byte
	acked     map[int]bool
	pending   []pend
	nextRow   int
	drop, dup float64
	faults    bool
	proposals int
	elections int
	snapshots int
	debug     bool
	seed      int64
	ackInfo   map[int]string
}

func simKeys() dnsstore.Keys {
	return dnsstore.StaticKeys{Cur: 1, Epochs: map[uint32][]byte{1: []byte("0123456789abcdef0123456789abcdef"), 2: []byte("fedcba9876543210fedcba9876543210")}}
}

func newSim(t *testing.T, seed int64, n int) *sim {
	s := &sim{t: t, seed: seed, debug: os.Getenv("SIM_DEBUG") != "", rng: rand.New(rand.NewSource(seed)), nodes: map[string]*simNode{}, group: map[string]int{},
		leaders: map[uint64]string{}, committed: map[uint64][32]byte{}, acked: map[int]bool{}, storeID: dnsstore.ID{7, 7, 7}}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("n%d", i+1)
		s.ids = append(s.ids, id)
		s.nodes[id] = &simNode{id: id, fs: faultfs.New(seed*100 + int64(i)), timeout: 12 + s.rng.Intn(20)}
	}
	for _, id := range s.ids {
		s.start(s.nodes[id], true)
	}
	return s
}

func (s *sim) peersOf(id string) []string {
	var p []string
	for _, o := range s.ids {
		if o != id {
			p = append(p, o)
		}
	}
	return p
}

func (s *sim) start(n *simNode, create bool) {
	st, err := dnsstore.Open(simDir, dnsstore.Options{FS: n.fs, Keys: simKeys(), Create: create, StoreID: s.storeID, SegmentSize: 900, SnapshotBytes: 1 << 40})
	if err != nil {
		s.t.Fatalf("tick %d: open %s: %v", s.tick, n.id, err)
	}
	node, err := New(Config{ID: n.id, Peers: s.peersOf(n.id), Membership: 1, BatchEntries: 8}, st, n.fs, simDir)
	if err != nil {
		s.t.Fatalf("tick %d: node %s: %v", s.tick, n.id, err)
	}
	n.st, n.n, n.up, n.lastHeard, n.checked = st, node, true, s.tick, 0
}

func (s *sim) crash(n *simNode) {
	n.fs.Crash()
	n.up = false
	n.downUntil = s.tick + 3 + s.rng.Intn(25)
	n.n, n.st = nil, nil
}

func (s *sim) send(m simMsg) {
	if s.rng.Float64() < s.drop {
		return
	}
	m.at = s.tick + 1 + s.rng.Intn(4)
	s.q = append(s.q, m)
	if s.rng.Float64() < s.dup {
		m.at = s.tick + 1 + s.rng.Intn(6)
		s.q = append(s.q, m)
	}
}

func (s *sim) linked(a, b string) bool { return s.group[a] == s.group[b] }

func (s *sim) check(n *simNode) {
	if n.fs.Crashed() {
		s.crash(n)
	}
}

func (s *sim) replicate(from *simNode, to string) {
	if !from.up || from.n.Role() != Leader {
		return
	}
	kind, areq, sreq, err := from.n.Replicate(to)
	s.check(from)
	if err != nil {
		return
	}
	switch kind {
	case SendAppend:
		s.send(simMsg{from: from.id, to: to, kind: mAppReq, areq: areq})
	case SendSnapshot:
		s.snapshots++
		s.send(simMsg{from: from.id, to: to, kind: mSnapReq, sreq: sreq})
	}
}

func (s *sim) replicateAll(from *simNode) {
	for _, p := range s.peersOf(from.id) {
		s.replicate(from, p)
	}
}

func (s *sim) deliver(m simMsg) {
	to := s.nodes[m.to]
	if !to.up || !s.linked(m.from, m.to) {
		return
	}
	switch m.kind {
	case mVoteReq:
		resp, err := to.n.HandleVote(m.vreq)
		s.check(to)
		if err == nil {
			if resp.Granted {
				to.lastHeard = s.tick
			}
			s.send(simMsg{from: to.id, to: m.from, kind: mVoteResp, vreq: m.vreq, vresp: resp})
		}
	case mVoteResp:
		became, err := to.n.OnVote(m.from, m.vreq, m.vresp)
		s.check(to)
		if err == nil && became {
			s.replicateAll(to)
		}
	case mAppReq:
		resp, err := to.n.HandleAppend(m.areq)
		s.check(to)
		if err != nil && s.debug && !to.fs.Crashed() {
			s.t.Logf("tick %d: %s HandleAppend from %s prev=%d entries=%d: %v", s.tick, to.id, m.from, m.areq.PrevRev, len(m.areq.Entries), err)
		}
		if err == nil {
			if resp.Term == m.areq.Term {
				to.lastHeard = s.tick
			}
			s.send(simMsg{from: to.id, to: m.from, kind: mAppResp, areq: m.areq, aresp: resp})
		}
	case mAppResp:
		if err := to.n.OnAppendResp(m.from, m.areq, m.aresp); err == nil {
			s.check(to)
			if to.up && (!m.aresp.Success || to.n.Role() == Leader && m.aresp.Match < func() uint64 { r, _, _ := to.st.Head(); return r }()) {
				s.replicate(to, m.from)
			}
		} else {
			s.check(to)
		}
	case mSnapReq:
		resp, err := to.n.HandleSnapshot(m.sreq)
		s.check(to)
		if err == nil {
			to.lastHeard = s.tick
			s.send(simMsg{from: to.id, to: m.from, kind: mSnapResp, sreq: m.sreq, sresp: resp})
		}
	case mSnapResp:
		_ = to.n.OnSnapResp(m.from, m.sreq, m.sresp)
		s.check(to)
		s.replicate(to, m.from)
	}
}

func rowID(i int) dnsstore.ID {
	var id dnsstore.ID
	binary.BigEndian.PutUint64(id[:8], uint64(i)*0x9E3779B97F4A7C15)
	binary.BigEndian.PutUint64(id[8:], uint64(i))
	return id
}

func (s *sim) propose(n *simNode) {
	s.nextRow++
	row := s.nextRow
	b := dnsstore.Batch{Origin: 3, Author: "sim", Ops: []dnsstore.Op{{Kind: dnsstore.OpPut, Type: 1, ID: rowID(row), Body: []byte(fmt.Sprintf("v%d", row))}}}
	rev, chain, term, err := n.n.Propose(b)
	s.check(n)
	if err != nil {
		return
	}
	s.proposals++
	s.pending = append(s.pending, pend{node: n.id, rev: rev, chain: chain, term: term, since: s.tick, row: row})
	s.replicateAll(n)
}

func (s *sim) settle() {
	rest := s.pending[:0]
	for _, p := range s.pending {
		n := s.nodes[p.node]
		if !n.up {
			if s.tick-p.since < 400 {
				rest = append(rest, p)
			}
			continue
		}
		switch n.n.Outcome(p.rev, p.chain, p.term) {
		case Committed:
			s.acked[p.row] = true
			if s.ackInfo == nil {
				s.ackInfo = map[int]string{}
			}
			cr := n.st.CommitIndex()
			hr, ht, _ := n.st.Head()
			s.ackInfo[p.row] = fmt.Sprintf("tick %d node %s proposed at rev %d term %d (node term %d), commit now %d head %d/%d", s.tick, p.node, p.rev, p.term, n.n.Term(), cr, hr, ht)
		case Lost:
		default:
			if s.tick-p.since < 400 {
				rest = append(rest, p)
			}
		}
	}
	s.pending = rest
}

func (s *sim) invariants() {
	for _, id := range s.ids {
		n := s.nodes[id]
		if !n.up {
			continue
		}
		if n.n.Role() == Leader {
			term := n.n.Term()
			if prev, ok := s.leaders[term]; ok && prev != id {
				s.t.Fatalf("tick %d: election safety: %s and %s are both leader of term %d", s.tick, prev, id, term)
			}
			s.leaders[term] = id
		}
		c := n.st.CommitIndex()
		if c < n.checked {
			n.checked = c
		}
		for r := n.checked + 1; r <= c; r++ {
			_, chain, ok := n.st.ChainAt(r)
			if !ok {
				continue
			}
			if g, seen := s.committed[r]; seen && g != chain {
				s.t.Fatalf("tick %d: state machine safety: revision %d is committed with two different records (%s)", s.tick, r, id)
			}
			s.committed[r] = chain
		}
		n.checked = c
	}
}

func (s *sim) step() {
	s.tick++
	var due, rest []simMsg
	for _, m := range s.q {
		if m.at <= s.tick {
			due = append(due, m)
		} else {
			rest = append(rest, m)
		}
	}
	s.q = rest
	s.rng.Shuffle(len(due), func(i, j int) { due[i], due[j] = due[j], due[i] })
	for _, m := range due {
		s.deliver(m)
	}
	for _, id := range s.ids {
		n := s.nodes[id]
		if !n.up {
			if s.tick >= n.downUntil {
				s.start(n, false)
			}
			continue
		}
		if s.faults && s.rng.Float64() < 0.004 {
			n.fs.SetCrashAt(n.fs.Ops()+1+s.rng.Intn(25), s.rng.Intn(2) == 0)
		}
		if s.faults && s.rng.Float64() < 0.004 {
			s.crash(n)
			continue
		}
		if n.n.Role() == Leader {
			if s.tick%4 == 0 {
				s.replicateAll(n)
			}
		} else if s.tick-n.lastHeard > n.timeout || s.faults && s.rng.Float64() < 0.003 {
			n.lastHeard = s.tick
			req, peers, err := n.n.Campaign()
			s.check(n)
			if err == nil {
				s.elections++
				for _, p := range peers {
					s.send(simMsg{from: id, to: p, kind: mVoteReq, vreq: req})
				}
				if n.up && n.n.Role() == Leader {
					s.replicateAll(n)
				}
			}
		}
		if n.up && s.rng.Float64() < 0.01 && n.st.CommitIndex() > 0 {
			_ = n.st.Snapshot()
			s.check(n)
		}
	}
	if s.faults && s.rng.Float64() < 0.012 {
		g := s.rng.Intn(len(s.ids))
		for i, id := range s.ids {
			s.group[id] = 0
			if i == g {
				s.group[id] = 1
			}
		}
	}
	if s.rng.Float64() < 0.02 {
		for _, id := range s.ids {
			s.group[id] = 0
		}
	}
}

func (s *sim) run(ticks int, propose bool) {
	for i := 0; i < ticks; i++ {
		s.step()
		if propose && s.rng.Float64() < 0.4 {
			for _, id := range s.ids {
				n := s.nodes[id]
				if n.up && n.n.Role() == Leader && s.rng.Intn(2) == 0 {
					s.propose(n)
				}
			}
		}
		s.settle()
		s.invariants()
	}
}

func (s *sim) converge(limit int) {
	s.faults, s.drop, s.dup = false, 0, 0
	for _, id := range s.ids {
		s.group[id] = 0
		n := s.nodes[id]
		if !n.up {
			n.downUntil = s.tick
		}
	}
	for i := 0; i < limit; i++ {
		s.step()
		s.settle()
		s.invariants()
		if s.converged() {
			return
		}
	}
	s.dump()
	s.t.Fatalf("seed %d: no convergence after %d ticks", s.seed, limit)
}

func (s *sim) converged() bool {
	var chain [32]byte
	var man [32]byte
	for i, id := range s.ids {
		n := s.nodes[id]
		if !n.up {
			return false
		}
		rev, _, c := n.st.Head()
		if n.st.CommitIndex() != rev || rev == 0 {
			return false
		}
		m := n.st.View().Manifest()
		if i == 0 {
			chain, man = c, m
		} else if c != chain || m != man {
			return false
		}
	}
	return true
}

func (s *sim) dump() {
	for _, id := range s.ids {
		n := s.nodes[id]
		if !n.up {
			s.t.Logf("%s: down", id)
			continue
		}
		rev, term, _ := n.st.Head()
		s.t.Logf("%s: %s term=%d head=%d/%d commit=%d", id, n.n.Role(), n.n.Term(), rev, term, n.st.CommitIndex())
	}
}

func (s *sim) finalChecks() {
	for _, id := range s.ids {
		n := s.nodes[id]
		if err := n.st.Verify(); err != nil {
			s.t.Fatalf("%s: verify: %v", id, err)
		}
		v := n.st.View()
		var missing []int
		for row := range s.acked {
			body, _, ok := v.Get(1, rowID(row))
			if !ok || string(body) != fmt.Sprintf("v%d", row) {
				missing = append(missing, row)
			}
		}
		if len(missing) > 0 {
			sort.Ints(missing)
			s.t.Logf("first missing row %d: %s", missing[0], s.ackInfo[missing[0]])
			for _, oid := range s.ids {
				o := s.nodes[oid]
				hr, ht, _ := o.st.Head()
				s.t.Logf("  %s head %d/%d commit %d role %s", oid, hr, ht, o.st.CommitIndex(), o.n.Role())
			}
			s.t.Fatalf("seed %d: %s lost %d acknowledged writes, first rows %v", s.seed, id, len(missing), missing[:min(5, len(missing))])
		}
	}
}

func TestSim_ThreeNodesUnderFaults(t *testing.T) {
	for seed := int64(1); seed <= simSeeds(40); seed++ {
		if v := os.Getenv("SIM_SEED"); v != "" {
			n, _ := strconv.ParseInt(v, 10, 64)
			if seed != n {
				continue
			}
		}
		s := newSim(t, seed, 3)
		s.drop, s.dup, s.faults = 0.08, 0.05, true
		s.run(1500, true)
		s.converge(3000)
		s.finalChecks()
		if seed == 1 {
			t.Logf("seed 1: %d proposals, %d acknowledged, %d elections, %d snapshots, terms %d", s.proposals, len(s.acked), s.elections, s.snapshots, len(s.leaders))
		}
		if len(s.acked) == 0 {
			t.Fatalf("seed %d: nothing was ever acknowledged, the cluster made no progress", seed)
		}
	}
}

func TestSim_FiveNodesUnderFaults(t *testing.T) {
	for seed := int64(100); seed < 100+simSeeds(15); seed++ {
		if v := os.Getenv("SIM_SEED"); v != "" {
			n, _ := strconv.ParseInt(v, 10, 64)
			if seed != n {
				continue
			}
		}
		s := newSim(t, seed, 5)
		s.drop, s.dup, s.faults = 0.05, 0.05, true
		s.run(1200, true)
		s.converge(4000)
		s.finalChecks()
	}
}

func TestSim_SingleNodeCommitsAlone(t *testing.T) {
	s := newSim(t, 9, 1)
	s.run(200, true)
	s.converge(100)
	s.finalChecks()
	if len(s.acked) < 10 {
		t.Fatalf("only %d acknowledged writes", len(s.acked))
	}
}

func TestSim_NoProgressWithoutMajorityButNeverWrong(t *testing.T) {
	s := newSim(t, 3, 3)
	s.run(100, true)
	before := len(s.acked)
	s.group["n1"], s.group["n2"], s.group["n3"] = 0, 1, 2
	for i := 0; i < 300; i++ {
		s.step()
		if s.rng.Float64() < 0.4 {
			for _, id := range s.ids {
				if n := s.nodes[id]; n.up && n.n.Role() == Leader {
					s.propose(n)
				}
			}
		}
		s.settle()
		s.invariants()
		s.group["n1"], s.group["n2"], s.group["n3"] = 0, 1, 2
	}
	if len(s.acked) != before {
		t.Fatalf("a minority acknowledged %d writes", len(s.acked)-before)
	}
	s.converge(3000)
	s.finalChecks()
}

func simSeeds(def int64) int64 {
	if v := os.Getenv("SIM_SEEDS"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}
