// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsrepl

import (
	"errors"
	"fmt"
	"testing"

	"dnshived/internal/dnsstore"
	"dnshived/internal/dnsstore/vfs/faultfs"
)

var testID = dnsstore.ID{4, 4, 4}

func newStore(t testing.TB, fs *faultfs.FS, create bool) *dnsstore.Store {
	t.Helper()
	st, err := dnsstore.Open(simDir, dnsstore.Options{FS: fs, Keys: simKeys(), Create: create, StoreID: testID, SegmentSize: 900, SnapshotBytes: 1 << 40})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func newNode(t testing.TB, id string, fs *faultfs.FS, create bool) (*Node, *dnsstore.Store) {
	t.Helper()
	st := newStore(t, fs, create)
	n, err := New(Config{ID: id, Peers: peersFor(id), Membership: 1}, st, fs, simDir)
	if err != nil {
		t.Fatal(err)
	}
	return n, st
}

func peersFor(id string) []string {
	var p []string
	for _, o := range []string{"n1", "n2", "n3"} {
		if o != id {
			p = append(p, o)
		}
	}
	return p
}

func recs(t testing.TB, st *dnsstore.Store, term uint64, from, n int) []dnsstore.Record {
	t.Helper()
	var out []dnsstore.Record
	for i := 0; i < n; i++ {
		r, err := st.AppendLocal(term, dnsstore.Batch{Ops: []dnsstore.Op{{Kind: dnsstore.OpPut, Type: 1, ID: rowID(from + i), Body: []byte(fmt.Sprintf("t%d-%d", term, from+i))}}})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func genesis(t testing.TB, st *dnsstore.Store) [32]byte {
	t.Helper()
	_, c, ok := st.ChainAt(0)
	if !ok {
		t.Fatal("no genesis chain")
	}
	return c
}

func TestNode_FollowerNeverCommitsPastWhatItHasVerified(t *testing.T) {
	stale := newStore(t, faultfs.New(1), true)
	defer stale.Close()
	old := recs(t, stale, 1, 0, 4)
	f, fst := newNode(t, "n2", faultfs.New(2), true)
	defer fst.Close()
	if _, err := fst.AppendRecords(0, genesis(t, fst), old); err != nil {
		t.Fatal(err)
	}
	resp, err := f.HandleAppend(AppendReq{Term: 2, Leader: "n1", Membership: 1, PrevRev: 2, PrevChain: old[1].Chain, LeaderCommit: 3})
	if err != nil || !resp.Success || resp.Match != 2 {
		t.Fatalf("heartbeat: %+v %v", resp, err)
	}
	if fst.CommitIndex() != 2 || fst.View().Rev() != 2 {
		t.Fatalf("the follower's records 3 and 4 are unverified leftovers of an old leader: commit %d, view %d", fst.CommitIndex(), fst.View().Rev())
	}
}

func TestNode_VoteRules(t *testing.T) {
	n, st := newNode(t, "n2", faultfs.New(1), true)
	defer st.Close()
	other := newStore(t, faultfs.New(2), true)
	defer other.Close()
	recs(t, other, 1, 0, 3)
	if _, err := st.AppendLocal(1, dnsstore.Batch{Ops: []dnsstore.Op{{Kind: dnsstore.OpPut, Type: 1, ID: rowID(9), Body: []byte("x")}}}); err != nil {
		t.Fatal(err)
	}
	v, err := n.HandleVote(VoteReq{Term: 5, Candidate: "n1", LastRev: 0, LastTerm: 0, Membership: 1})
	if err != nil || v.Granted {
		t.Fatalf("a candidate with an emptier log must be refused: %+v %v", v, err)
	}
	if n.Term() != 5 {
		t.Fatal("the node must adopt the higher term even when it refuses")
	}
	if v, _ = n.HandleVote(VoteReq{Term: 5, Candidate: "n3", LastRev: 1, LastTerm: 1, Membership: 1}); !v.Granted {
		t.Fatalf("an up-to-date candidate gets the vote: %+v", v)
	}
	if v, _ = n.HandleVote(VoteReq{Term: 5, Candidate: "n1", LastRev: 9, LastTerm: 1, Membership: 1}); v.Granted {
		t.Fatal("one vote per term")
	}
	if v, _ = n.HandleVote(VoteReq{Term: 5, Candidate: "n3", LastRev: 1, LastTerm: 1, Membership: 1}); !v.Granted {
		t.Fatal("the same candidate may ask again")
	}
	if v, _ = n.HandleVote(VoteReq{Term: 4, Candidate: "n1", LastRev: 9, LastTerm: 9, Membership: 1}); v.Granted || v.Term != 5 {
		t.Fatalf("an old term is refused: %+v", v)
	}
	if _, err := n.HandleVote(VoteReq{Term: 6, Candidate: "n1", Membership: 2}); !errors.Is(err, ErrMembership) {
		t.Fatalf("membership: %v", err)
	}
	if v, _ = n.HandleVote(VoteReq{Term: 5, Candidate: "n3", LastRev: 1, LastTerm: 2, Membership: 1}); !v.Granted {
		t.Fatal("candidate with a higher last term is up to date")
	}
}

func TestNode_VoteAndTermSurviveARestart(t *testing.T) {
	fs := faultfs.New(1)
	n, st := newNode(t, "n2", fs, true)
	if v, err := n.HandleVote(VoteReq{Term: 7, Candidate: "n3", Membership: 1}); err != nil || !v.Granted {
		t.Fatal("vote")
	}
	_ = st.Close()
	fs.Crash()
	n, st = newNode(t, "n2", fs, false)
	defer st.Close()
	if n.Term() != 7 {
		t.Fatalf("term %d after the restart", n.Term())
	}
	if v, _ := n.HandleVote(VoteReq{Term: 7, Candidate: "n1", Membership: 1}); v.Granted {
		t.Fatal("a vote given before a crash must not be given again to someone else")
	}
}

func TestNode_AppendRefusals(t *testing.T) {
	n, st := newNode(t, "n2", faultfs.New(1), true)
	defer st.Close()
	if _, err := n.HandleVote(VoteReq{Term: 3, Candidate: "n1", Membership: 1}); err != nil {
		t.Fatal(err)
	}
	if r, _ := n.HandleAppend(AppendReq{Term: 2, Leader: "n3", Membership: 1}); r.Success || r.Term != 3 {
		t.Fatalf("stale leader: %+v", r)
	}
	if _, err := n.HandleAppend(AppendReq{Term: 3, Leader: "n1", Membership: 9}); !errors.Is(err, ErrMembership) {
		t.Fatalf("membership: %v", err)
	}
	r, err := n.HandleAppend(AppendReq{Term: 3, Leader: "n1", Membership: 1, PrevRev: 5, PrevChain: [32]byte{1}})
	if err != nil || r.Success || r.Hint != 0 {
		t.Fatalf("a gap tells the leader to back up: %+v %v", r, err)
	}
	if n.Leader() != "n1" {
		t.Fatal("the node follows the leader of the current term")
	}
	req, peers, err := n.Campaign()
	if err != nil || len(peers) != 2 || req.Term != 4 {
		t.Fatalf("campaign: %+v %v", req, err)
	}
	if became, _ := n.OnVote("n1", req, VoteResp{Term: 4, Granted: true}); !became {
		t.Fatal("two votes of three make a leader")
	}
	if r, _ := n.HandleAppend(AppendReq{Term: 4, Leader: "n3", Membership: 1}); r.Success {
		t.Fatal("two leaders in one term must be refused")
	}
	if r, _ := n.HandleAppend(AppendReq{Term: 5, Leader: "n3", Membership: 1, PrevChain: genesis(t, st)}); !r.Success || n.Role() != Follower {
		t.Fatalf("a leader of a higher term takes over: %+v role %s", r, n.Role())
	}
}

func TestNode_OldTermRecordsCommitOnlyWithTheNewTermsNoop(t *testing.T) {
	fs := faultfs.New(1)
	lst := newStore(t, fs, true)
	defer lst.Close()
	recs(t, lst, 1, 0, 3)
	l, err := New(Config{ID: "n1", Peers: peersFor("n1"), Membership: 1}, lst, fs, simDir)
	if err != nil {
		t.Fatal(err)
	}
	req, _, err := l.Campaign()
	if err != nil {
		t.Fatal(err)
	}
	if became, err := l.OnVote("n2", req, VoteResp{Term: req.Term, Granted: true}); err != nil || !became {
		t.Fatal("elected")
	}
	rev, _, _ := lst.Head()
	if rev != 4 {
		t.Fatalf("the new leader writes a no-op: head %d", rev)
	}
	if lst.CommitIndex() != 0 {
		t.Fatal("nothing may be committed before a majority holds a record of the new term")
	}
	kind, areq, _, err := l.Replicate("n2")
	if err != nil || kind != SendAppend || areq.PrevRev != 3 || len(areq.Entries) != 1 {
		t.Fatalf("a new leader starts just after its own log: %v %v prev %d entries %d", kind, err, areq.PrevRev, len(areq.Entries))
	}
	if err := l.OnAppendResp("n2", areq, AppendResp{Term: areq.Term, Success: true, Match: 3}); err != nil {
		t.Fatal(err)
	}
	if lst.CommitIndex() != 0 {
		t.Fatalf("a majority holds only the old-term records: commit %d", lst.CommitIndex())
	}
	if err := l.OnAppendResp("n2", areq, AppendResp{Term: areq.Term, Success: true, Match: 4}); err != nil {
		t.Fatal(err)
	}
	if lst.CommitIndex() != 4 {
		t.Fatalf("the no-op reached a majority, so everything before it commits: %d", lst.CommitIndex())
	}
}

func TestNode_ProposeAndOutcome(t *testing.T) {
	l, lst := newNode(t, "n1", faultfs.New(1), true)
	defer lst.Close()
	b := dnsstore.Batch{Ops: []dnsstore.Op{{Kind: dnsstore.OpPut, Type: 1, ID: rowID(1), Body: []byte("a")}}}
	if _, _, _, err := l.Propose(b); err == nil {
		t.Fatal("a follower cannot propose")
	} else {
		var nl *NotLeaderError
		if !errors.As(err, &nl) {
			t.Fatalf("want NotLeaderError, got %v", err)
		}
	}
	req, _, _ := l.Campaign()
	_, _ = l.OnVote("n2", req, VoteResp{Term: req.Term, Granted: true})
	rev, chain, term, err := l.Propose(b)
	if err != nil {
		t.Fatal(err)
	}
	if o := l.Outcome(rev, chain, term); o != Pending {
		t.Fatalf("outcome %s", o)
	}
	kind, areq, _, _ := l.Replicate("n3")
	if kind != SendAppend {
		t.Fatal(kind)
	}
	_ = l.OnAppendResp("n3", areq, AppendResp{Term: areq.Term, Success: true, Match: rev})
	if o := l.Outcome(rev, chain, term); o != Committed {
		t.Fatalf("outcome %s", o)
	}
	if o := l.Outcome(rev, [32]byte{1}, term); o != Lost {
		t.Fatalf("a different record at that revision is a lost proposal: %s", o)
	}
	if o := l.Outcome(rev+50, chain, term); o != Lost {
		t.Fatalf("a revision beyond the log is lost: %s", o)
	}
	l.StepDown()
	if _, _, _, err := l.Propose(b); err == nil {
		t.Fatal("a node that stepped down cannot propose")
	}
}

func TestNode_SingleVoterLeadsAndCommitsAlone(t *testing.T) {
	fs := faultfs.New(1)
	st := newStore(t, fs, true)
	defer st.Close()
	n, err := New(Config{ID: "solo", Membership: 1}, st, fs, simDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, peers, err := n.Campaign(); err != nil || len(peers) != 0 || n.Role() != Leader {
		t.Fatalf("a single voter wins at once: %v %v", err, n.Role())
	}
	rev, chain, term, err := n.Propose(dnsstore.Batch{Ops: []dnsstore.Op{{Kind: dnsstore.OpPut, Type: 1, ID: rowID(1), Body: []byte("a")}}})
	if err != nil || n.Outcome(rev, chain, term) != Committed {
		t.Fatalf("single node commit: %v", err)
	}
}

func TestConfig_Validation(t *testing.T) {
	fs := faultfs.New(1)
	st := newStore(t, fs, true)
	defer st.Close()
	for _, c := range []Config{{}, {ID: "a", Peers: []string{"a"}}, {ID: "a", Peers: []string{"b", "b"}}, {ID: "a", Peers: []string{""}}} {
		if _, err := New(c, st, fs, simDir); err == nil {
			t.Errorf("config %+v must be refused", c)
		}
	}
}

func TestNode_MessagesAreBoundedInBytes(t *testing.T) {
	fs := faultfs.New(1)
	lst := newStore(t, fs, true)
	defer lst.Close()
	l, err := New(Config{ID: "n1", Peers: peersFor("n1"), Membership: 1, BatchEntries: 64}, lst, fs, simDir)
	if err != nil {
		t.Fatal(err)
	}
	req, _, _ := l.Campaign()
	_, _ = l.OnVote("n2", req, VoteResp{Term: req.Term, Granted: true})
	big := make([]byte, dnsstore.MaxRow)
	for i := 0; i < 30; i++ {
		var ops []dnsstore.Op
		for j := 0; j < 8; j++ {
			ops = append(ops, dnsstore.Op{Kind: dnsstore.OpPut, Type: 1, ID: rowID(i*8 + j), Body: big})
		}
		if _, _, _, err := l.Propose(dnsstore.Batch{Ops: ops}); err != nil {
			t.Fatal(err)
		}
		_ = lst.AdvanceCommit(1 << 20)
	}
	l.mu.Lock()
	l.next["n2"] = 1
	l.mu.Unlock()
	kind, areq, _, err := l.Replicate("n2")
	if err != nil || kind != SendAppend {
		t.Fatalf("%v %v", kind, err)
	}
	total := 0
	for _, e := range areq.Entries {
		total += len(e.Payload)
	}
	if len(areq.Entries) == 0 || len(areq.Entries) >= 30 || total > maxAppendBytes+dnsstore.MaxRow*8+4096 {
		t.Fatalf("%d entries of %d bytes in one message", len(areq.Entries), total)
	}
}
