// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package dnsrepl replicates the DNS store between the cores with Raft's safety rules: terms that name their leader,
// votes restricted to the most up-to-date log, a previous-record check on every append, and commit only when a record
// of the current term has reached a majority. Node is a pure state machine: it has no goroutines, timers or clock,
// so a driver (the daemon, or the test simulator) decides when to campaign, replicate and step down.
package dnsrepl

import (
	"errors"
	"fmt"

	"dnshived/internal/dnsstore"
)

type Role int

const (
	Follower Role = iota
	Candidate
	Leader
)

func (r Role) String() string {
	return [...]string{"follower", "candidate", "leader"}[r]
}

type VoteReq struct {
	Term       uint64
	Candidate  string
	LastRev    uint64
	LastTerm   uint64
	Membership uint64
}

type VoteResp struct {
	Term    uint64
	Granted bool
}

type AppendReq struct {
	Term         uint64
	Leader       string
	Membership   uint64
	PrevRev      uint64
	PrevChain    [32]byte
	Entries      []dnsstore.Record
	LeaderCommit uint64
}

type AppendResp struct {
	Term    uint64
	Success bool
	Match   uint64
	Hint    uint64
	Reason  string
}

type SnapReq struct {
	Term       uint64
	Leader     string
	Membership uint64
	Rev        uint64
	Data       []byte
}

type SnapResp struct {
	Term    uint64
	Success bool
	Head    uint64
	Reason  string
}

// NotLeaderError tells a writer where to go.
type NotLeaderError struct{ Leader string }

func (e *NotLeaderError) Error() string {
	if e.Leader == "" {
		return "dnsrepl: no leader is known"
	}
	return "dnsrepl: this node is not the leader, the leader is " + e.Leader
}

var (
	ErrNotLeader  = errors.New("dnsrepl: not the leader")
	ErrMembership = errors.New("dnsrepl: membership differs")
)

// Outcome is what became of a proposed record.
type Outcome int

const (
	Pending Outcome = iota
	Committed
	Lost
	Unknown
)

func (o Outcome) String() string {
	return [...]string{"pending", "committed", "lost", "unknown"}[o]
}

type Config struct {
	ID           string
	Peers        []string
	Membership   uint64
	BatchEntries int
}

func (c *Config) voters() int   { return len(c.Peers) + 1 }
func (c *Config) majority() int { return c.voters()/2 + 1 }

func (c *Config) validate() error {
	if c.ID == "" {
		return fmt.Errorf("dnsrepl: no node id")
	}
	seen := map[string]bool{c.ID: true}
	for _, p := range c.Peers {
		if p == "" || seen[p] {
			return fmt.Errorf("dnsrepl: bad or duplicate peer %q", p)
		}
		seen[p] = true
	}
	return nil
}
