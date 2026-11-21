// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsrepl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"dnshived/internal/dnsstore"
	"dnshived/internal/dnsstore/vfs"
)

const (
	stateFile    = "repl.state"
	stateMagic   = "DHRS"
	defaultBatch = 64

	// maxAppendBytes keeps one message well under the receiver's body limit; one record may exceed it alone.
	maxAppendBytes = 8 << 20
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)

type Node struct {
	mu  sync.Mutex
	cfg Config
	st  *dnsstore.Store
	fs  vfs.FS
	dir string

	term     uint64
	votedFor string
	role     Role
	leader   string
	votes    map[string]bool
	next     map[string]uint64
	match    map[string]uint64
}

// New loads the persisted term and vote from the store directory. A node that has never run starts as a follower.
func New(cfg Config, st *dnsstore.Store, fs vfs.FS, dir string) (*Node, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.BatchEntries <= 0 {
		cfg.BatchEntries = defaultBatch
	}
	n := &Node{cfg: cfg, st: st, fs: fs, dir: dir}
	term, voted, err := n.loadState()
	if err != nil {
		return nil, err
	}
	_, headTerm, _ := st.Head()
	n.term, n.votedFor = max(term, headTerm), voted
	if headTerm > term {
		n.votedFor = ""
	}
	return n, nil
}

func (n *Node) loadState() (uint64, string, error) {
	f, err := n.fs.OpenFile(filepath.Join(n.dir, stateFile), os.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	size, err := f.Size()
	if err != nil || size < 4+8+1+4 || size > 4+8+1+255+4 {
		return 0, "", fmt.Errorf("dnsrepl: %s has %d bytes", stateFile, size)
	}
	b := make([]byte, size)
	if _, err := f.ReadAt(b, 0); err != nil {
		return 0, "", err
	}
	if string(b[:4]) != stateMagic || crc32.Checksum(b[:size-4], crcTable) != binary.LittleEndian.Uint32(b[size-4:]) {
		return 0, "", fmt.Errorf("dnsrepl: %s is damaged", stateFile)
	}
	l := int(b[12])
	if int(size) != 4+8+1+l+4 {
		return 0, "", fmt.Errorf("dnsrepl: %s has a bad length", stateFile)
	}
	return binary.LittleEndian.Uint64(b[4:]), string(b[13 : 13+l]), nil
}

// persistLocked makes the term and vote durable; a vote must be durable before it is answered.
func (n *Node) persistLocked() error {
	b := append([]byte(stateMagic), 0, 0, 0, 0, 0, 0, 0, 0)
	binary.LittleEndian.PutUint64(b[4:], n.term)
	b = append(b, byte(len(n.votedFor)))
	b = append(b, n.votedFor...)
	b = binary.LittleEndian.AppendUint32(b, crc32.Checksum(b, crcTable))
	path := filepath.Join(n.dir, stateFile)
	tmp := path + ".tmp"
	_ = n.fs.Remove(tmp)
	f, err := n.fs.OpenFile(tmp, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteAt(b, 0); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := n.fs.Rename(tmp, path); err != nil {
		return err
	}
	return n.fs.SyncDir(n.dir)
}

func (n *Node) Term() uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.term
}

func (n *Node) Role() Role {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.role
}

func (n *Node) Leader() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.leader
}

func (n *Node) ID() string { return n.cfg.ID }

func (n *Node) Peers() []string { return append([]string(nil), n.cfg.Peers...) }

func (n *Node) Store() *dnsstore.Store { return n.st }

// observeLocked adopts a higher term; the vote of the old term no longer counts.
func (n *Node) observeLocked(term uint64) error {
	if term <= n.term {
		return nil
	}
	n.term, n.votedFor = term, ""
	n.role, n.leader = Follower, ""
	n.votes, n.next, n.match = nil, nil, nil
	return n.persistLocked()
}

// StepDown makes a leader or candidate a follower of the same term, for when the authority model withdraws permission.
func (n *Node) StepDown() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.role != Follower {
		n.role, n.leader = Follower, ""
		n.votes, n.next, n.match = nil, nil, nil
	}
}

// Campaign starts an election for the next term and returns the vote request for every peer. With no peers the node
// becomes leader at once.
func (n *Node) Campaign() (VoteReq, []string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.term++
	n.votedFor = n.cfg.ID
	if err := n.persistLocked(); err != nil {
		n.term--
		n.votedFor = ""
		return VoteReq{}, nil, err
	}
	n.role, n.leader = Candidate, ""
	n.votes = map[string]bool{n.cfg.ID: true}
	n.next, n.match = nil, nil
	rev, term, _ := n.st.Head()
	req := VoteReq{Term: n.term, Candidate: n.cfg.ID, LastRev: rev, LastTerm: term, Membership: n.cfg.Membership}
	if len(n.votes) >= n.cfg.majority() {
		if err := n.becomeLeaderLocked(); err != nil {
			return req, nil, err
		}
		return req, nil, nil
	}
	return req, n.Peers(), nil
}

// HandleVote answers a vote request. The vote is persisted before it is granted.
func (n *Node) HandleVote(req VoteReq) (VoteResp, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if req.Membership != n.cfg.Membership {
		return VoteResp{Term: n.term}, ErrMembership
	}
	if req.Term < n.term {
		return VoteResp{Term: n.term}, nil
	}
	if err := n.observeLocked(req.Term); err != nil {
		return VoteResp{Term: n.term}, err
	}
	rev, term, _ := n.st.Head()
	upToDate := req.LastTerm > term || req.LastTerm == term && req.LastRev >= rev
	if (n.votedFor == "" || n.votedFor == req.Candidate) && upToDate {
		n.votedFor = req.Candidate
		if err := n.persistLocked(); err != nil {
			return VoteResp{Term: n.term}, err
		}
		return VoteResp{Term: n.term, Granted: true}, nil
	}
	return VoteResp{Term: n.term}, nil
}

// OnVote counts a vote response; it reports whether this node just became leader.
func (n *Node) OnVote(from string, req VoteReq, resp VoteResp) (bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if resp.Term > n.term {
		return false, n.observeLocked(resp.Term)
	}
	if n.role != Candidate || req.Term != n.term || !resp.Granted {
		return false, nil
	}
	n.votes[from] = true
	if len(n.votes) < n.cfg.majority() {
		return false, nil
	}
	return true, n.becomeLeaderLocked()
}

func (n *Node) becomeLeaderLocked() error {
	n.role, n.leader = Leader, n.cfg.ID
	rev, _, _ := n.st.Head()
	n.next, n.match = map[string]uint64{}, map[string]uint64{}
	for _, p := range n.cfg.Peers {
		n.next[p] = rev + 1
	}
	if _, err := n.st.AppendNoop(n.term); err != nil {
		n.role, n.leader = Follower, ""
		return err
	}
	return n.advanceCommitLocked()
}

// advanceCommitLocked commits the highest record that a majority holds, provided it belongs to the current term.
func (n *Node) advanceCommitLocked() error {
	rev, _, _ := n.st.Head()
	idx := []uint64{rev}
	for _, p := range n.cfg.Peers {
		idx = append(idx, n.match[p])
	}
	sort.Slice(idx, func(i, j int) bool { return idx[i] > idx[j] })
	cand := idx[n.cfg.majority()-1]
	if cand <= n.st.CommitIndex() {
		return nil
	}
	term, _, ok := n.st.ChainAt(cand)
	if !ok || term != n.term {
		return nil
	}
	return n.st.AdvanceCommit(cand)
}

// Propose appends a batch as leader; it returns the revision and chain the caller then waits on with Outcome. The
// batch must already have passed the write gate.
func (n *Node) Propose(b dnsstore.Batch) (rev uint64, chain [32]byte, term uint64, err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.role != Leader {
		return 0, chain, 0, &NotLeaderError{Leader: n.leader}
	}
	rec, err := n.st.AppendLocal(n.term, b)
	if err != nil {
		return 0, chain, 0, err
	}
	if err := n.advanceCommitLocked(); err != nil {
		return 0, chain, 0, err
	}
	return rec.Rev, rec.Chain, n.term, nil
}

// Outcome reports whether the record proposed at rev with chain is committed, lost to another leader, or undecided.
func (n *Node) Outcome(rev uint64, chain [32]byte, term uint64) Outcome {
	n.mu.Lock()
	defer n.mu.Unlock()
	head, _, _ := n.st.Head()
	if head < rev {
		return Lost
	}
	_, c, ok := n.st.ChainAt(rev)
	if ok && c != chain {
		return Lost
	}
	if n.st.CommitIndex() >= rev {
		if !ok {
			return Unknown
		}
		return Committed
	}
	if n.role != Leader || n.term != term {
		return Unknown
	}
	return Pending
}

// ReplicateKind says which message Replicate produced.
type ReplicateKind int

const (
	SendNothing ReplicateKind = iota
	SendAppend
	SendSnapshot
)

// Replicate builds the next message for a peer: entries from where the peer is known to match, a heartbeat when it is
// caught up, or a snapshot when the log no longer reaches back far enough.
func (n *Node) Replicate(peer string) (ReplicateKind, AppendReq, SnapReq, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.role != Leader {
		return SendNothing, AppendReq{}, SnapReq{}, &NotLeaderError{Leader: n.leader}
	}
	next, ok := n.next[peer]
	if !ok {
		return SendNothing, AppendReq{}, SnapReq{}, fmt.Errorf("dnsrepl: unknown peer %q", peer)
	}
	head, _, _ := n.st.Head()
	if next > head+1 {
		next = head + 1
		n.next[peer] = next
	}
	req := AppendReq{Term: n.term, Leader: n.cfg.ID, Membership: n.cfg.Membership, PrevRev: next - 1, LeaderCommit: n.st.CommitIndex()}
	_, c, ok := n.st.ChainAt(next - 1)
	if !ok {
		return n.snapshotLocked()
	}
	req.PrevChain = c
	if next <= head {
		limit := next + uint64(n.cfg.BatchEntries)
		size := 0
		err := n.st.Records(next, func(r dnsstore.Record) error {
			if r.Rev >= limit || len(req.Entries) > 0 && size+len(r.Payload) > maxAppendBytes {
				return errStop
			}
			size += len(r.Payload)
			req.Entries = append(req.Entries, r)
			return nil
		})
		if errors.Is(err, dnsstore.ErrGap) {
			return n.snapshotLocked()
		}
		if err != nil && !errors.Is(err, errStop) {
			return SendNothing, AppendReq{}, SnapReq{}, err
		}
	}
	return SendAppend, req, SnapReq{}, nil
}

var errStop = errors.New("stop")

func (n *Node) snapshotLocked() (ReplicateKind, AppendReq, SnapReq, error) {
	rev, data, err := n.st.ExportSnapshot()
	if err != nil {
		return SendNothing, AppendReq{}, SnapReq{}, err
	}
	return SendSnapshot, AppendReq{}, SnapReq{Term: n.term, Leader: n.cfg.ID, Membership: n.cfg.Membership, Rev: rev, Data: data}, nil
}

// OnAppendResp updates what the leader knows about a peer and advances the commit index.
func (n *Node) OnAppendResp(peer string, req AppendReq, resp AppendResp) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if resp.Term > n.term {
		return n.observeLocked(resp.Term)
	}
	if n.role != Leader || req.Term != n.term {
		return nil
	}
	if resp.Success {
		if resp.Match > n.match[peer] {
			n.match[peer] = resp.Match
		}
		n.next[peer] = n.match[peer] + 1
		return n.advanceCommitLocked()
	}
	back := req.PrevRev
	if resp.Hint+1 < back {
		back = resp.Hint + 1
	}
	if back < 1 {
		back = 1
	}
	if back <= n.match[peer] {
		n.match[peer] = back - 1
	}
	n.next[peer] = back
	return nil
}

// OnSnapResp records that a peer installed a snapshot.
func (n *Node) OnSnapResp(peer string, req SnapReq, resp SnapResp) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if resp.Term > n.term {
		return n.observeLocked(resp.Term)
	}
	if n.role != Leader || req.Term != n.term || !resp.Success {
		return nil
	}
	n.match[peer] = max(n.match[peer], resp.Head)
	n.next[peer] = n.match[peer] + 1
	return n.advanceCommitLocked()
}

func (n *Node) followLocked(term uint64, leader string) error {
	if err := n.observeLocked(term); err != nil {
		return err
	}
	if n.role != Follower {
		n.role = Follower
		n.votes, n.next, n.match = nil, nil, nil
	}
	n.leader = leader
	return nil
}

// HandleAppend is the follower side: it checks term and membership, appends or cuts back records, and moves its commit
// index up to what the leader says is committed and this log is proven to match.
func (n *Node) HandleAppend(req AppendReq) (AppendResp, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if req.Membership != n.cfg.Membership {
		return AppendResp{Term: n.term, Reason: "membership"}, ErrMembership
	}
	if req.Term < n.term {
		return AppendResp{Term: n.term, Reason: "stale term"}, nil
	}
	if req.Term == n.term && n.role == Leader {
		return AppendResp{Term: n.term, Reason: "two leaders in one term"}, nil
	}
	if err := n.followLocked(req.Term, req.Leader); err != nil {
		return AppendResp{Term: n.term}, err
	}
	match, err := n.st.AppendRecords(req.PrevRev, req.PrevChain, req.Entries)
	head, _, _ := n.st.Head()
	switch {
	case errors.Is(err, dnsstore.ErrBehind), errors.Is(err, dnsstore.ErrPrevMismatch):
		return AppendResp{Term: n.term, Hint: head, Reason: err.Error()}, nil
	case err != nil:
		return AppendResp{Term: n.term, Hint: head, Reason: err.Error()}, err
	}
	if err := n.st.AdvanceCommit(min(req.LeaderCommit, match)); err != nil {
		return AppendResp{Term: n.term, Hint: head, Reason: err.Error()}, err
	}
	return AppendResp{Term: n.term, Success: true, Match: match, Hint: head}, nil
}

// HandleSnapshot installs a leader's snapshot when this log is behind it.
func (n *Node) HandleSnapshot(req SnapReq) (SnapResp, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if req.Membership != n.cfg.Membership {
		return SnapResp{Term: n.term, Reason: "membership"}, ErrMembership
	}
	if req.Term < n.term {
		return SnapResp{Term: n.term, Reason: "stale term"}, nil
	}
	if err := n.followLocked(req.Term, req.Leader); err != nil {
		return SnapResp{Term: n.term}, err
	}
	err := n.st.InstallSnapshot(req.Data)
	head, _, _ := n.st.Head()
	switch {
	case err == nil:
		return SnapResp{Term: n.term, Success: true, Head: head}, nil
	case errors.Is(err, dnsstore.ErrNotNewer):
		return SnapResp{Term: n.term, Success: true, Head: req.Rev, Reason: err.Error()}, nil
	}
	return SnapResp{Term: n.term, Head: head, Reason: err.Error()}, err
}
