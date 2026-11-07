// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"sync"
	"time"

	"dnshived/internal/config"
)

// catchUpInterval is how often the revision comparison runs. A node must lag
// on two passes in a row before it is brought up to date, so a commit that is
// still being sent to every node is never "repaired".
const catchUpInterval = 60 * time.Second

type lagSeen struct{ rev, leaderRev int64 }

// catchUp brings a node that missed a commit up to the cluster's current
// configuration. Only the web instance on the node with the highest config
// revision acts, so the three instances never push at the same time.
type catchUp struct {
	ref *configRef

	mu   sync.Mutex
	seen map[string]lagSeen

	self     func() string
	statuses func([]NodeConfig) map[string]nodeStatus
	fetchCfg func(NodeConfig) (config.Cluster, error)
	push     func(NodeConfig, []byte) (int, []byte, error)
	audit    func(NodeConfig, string, string, string) error
}

func newCatchUp(ref *configRef) *catchUp {
	return &catchUp{
		ref: ref, seen: map[string]lagSeen{},
		self:     func() string { return selfNameFn() },
		statuses: fetchStatuses,
		fetchCfg: fetchConfigDirect,
		push:     pushConfig,
		audit:    pushAudit,
	}
}

// run starts the periodic pass; it stops when ctx ends.
func (c *catchUp) run(ctx context.Context) {
	go func() {
		t := time.NewTimer(90 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				c.pass()
				t.Reset(catchUpInterval)
			}
		}
	}()
}

// pickLeader returns the node with the highest reported revision; the lowest
// name wins a tie. Nodes that report no revision are ignored.
func pickLeader(st map[string]nodeStatus) (name string, rev int64) {
	names := make([]string, 0, len(st))
	for n := range st {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		r := st[n].ConfigRevision
		if r != nil && *r > rev {
			name, rev = n, *r
		}
	}
	return name, rev
}

func (c *catchUp) resetSeen() {
	for k := range c.seen {
		delete(c.seen, k)
	}
}

// pass compares the nodes once.
func (c *catchUp) pass() {
	c.mu.Lock()
	defer c.mu.Unlock()
	cfg := c.ref.Load()
	nodes := nodesIncludingSelf(cfg)
	if len(nodes) < 2 {
		return
	}
	st := c.statuses(nodes)
	if len(st)*2 <= len(nodes) {
		c.resetSeen()
		return
	}
	leaderName, leaderRev := pickLeader(st)
	if leaderRev == 0 || c.self() != leaderName {
		c.resetSeen()
		return
	}
	var leader NodeConfig
	for _, n := range nodes {
		if n.Name == leaderName {
			leader = n
		}
	}
	for _, n := range nodes {
		if n.Name == leaderName {
			continue
		}
		s, ok := st[n.Name]
		if !ok || s.ConfigRevision == nil || *s.ConfigRevision >= leaderRev || s.ConfigHash == st[leaderName].ConfigHash {
			delete(c.seen, n.Name)
			continue
		}
		key := lagSeen{rev: *s.ConfigRevision, leaderRev: leaderRev}
		if c.seen[n.Name] != key {
			c.seen[n.Name] = key
			continue
		}
		if err := c.bringUp(leader, n); err != nil {
			log.Printf("[CATCHUP] %s: %v", n.Name, err)
			continue
		}
		delete(c.seen, n.Name)
	}
}

// catchUpPayload is the leader's committed configuration as it should reach
// lag: the leader's own node_ip values are dropped, lag's are derived the way
// a commit derives them, and where nothing can be derived lag keeps the one it
// has (never the leader's address).
func catchUpPayload(leaderCfg, lagCfg config.Cluster, lag NodeConfig) configPushPayload {
	p := clusterPushPayloadFrom(leaderCfg)
	p.Scopes = make(map[string]config.ScopeConfig, len(leaderCfg.Scopes))
	for name, sc := range leaderCfg.Scopes {
		sc.NodeIP = ""
		p.Scopes[name] = sc
	}
	p.ConfigRevision = leaderCfg.ConfigRevision
	p.ConfigRevisionAt = leaderCfg.ConfigRevisionAt
	p.ConfigRevisionOrigin = leaderCfg.ConfigRevisionOrigin
	p.ConfigCatchUp = true
	p = payloadForNode(p, lag)
	for name, sc := range p.Scopes {
		if sc.NodeIP == "" {
			if own, ok := lagCfg.Scopes[name]; ok {
				sc.NodeIP = own.NodeIP
				p.Scopes[name] = sc
			}
		}
	}
	return p
}

// bringUp pushes the leader's committed configuration to lag, after checking
// again that lag is still behind.
func (c *catchUp) bringUp(leader, lag NodeConfig) error {
	fresh, ok := c.statuses([]NodeConfig{lag})[lag.Name]
	if !ok || fresh.ConfigRevision == nil {
		return fmt.Errorf("not answering")
	}
	leaderCfg, err := c.fetchCfg(leader)
	if err != nil {
		return fmt.Errorf("read the configuration of %s: %w", leader.Name, err)
	}
	if leaderCfg.ConfigRevision <= *fresh.ConfigRevision {
		return nil
	}
	lagCfg, err := c.fetchCfg(lag)
	if err != nil {
		return fmt.Errorf("read its own configuration: %w", err)
	}
	body, err := json.Marshal(catchUpPayload(leaderCfg, lagCfg, lag))
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	status, resp, err := c.push(lag, body)
	if err != nil {
		return fmt.Errorf("push: %w", err)
	}
	var check configCheckResponse
	if status != http.StatusOK || json.Unmarshal(resp, &check) != nil || !check.OK {
		return fmt.Errorf("the node refused the configuration (HTTP %d): %.200s", status, resp)
	}
	msg := fmt.Sprintf("brought %s from configuration revision %d to %d (taken from %s) after it missed a commit", lag.Name, *fresh.ConfigRevision, leaderCfg.ConfigRevision, leader.Name)
	if check.RestartNeeded {
		msg += "; it needs a restart to finish (platform, PSK or TLS changed)"
	}
	log.Printf("[CATCHUP] %s", msg)
	for _, n := range []NodeConfig{leader, lag} {
		if err := c.audit(n, "system", "config.catchup", msg); err != nil {
			log.Printf("[CATCHUP] audit on %s: %v", n.Name, err)
		}
	}
	return nil
}
