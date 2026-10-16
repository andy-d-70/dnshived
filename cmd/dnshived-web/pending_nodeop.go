// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"sync"
	"time"
)

type nodeOpKind string

const (
	nodeOpReplace  nodeOpKind = "replace"
	nodeOpOffboard nodeOpKind = "offboard"
)

// probeRoleName is the sentinel Role value meaning "the probe host," not a
// core cluster role — used with nodeOpReplace.
const probeRoleName = "probe"

// pendingNodeOp is a staged-but-not-yet-executed node action.
type pendingNodeOp struct {
	Kind nodeOpKind
	Role string // nodeOpReplace/nodeOpOffboard target role, or probeRoleName
	Addr string // target address (host:port), nodeOpReplace only
	// Onboarding is true when Role had NO existing entry (cfg.Nodes for a core
	// role, or an empty cfg.ProbeHosts for probeRoleName) at the moment this
	// op was staged.
	Onboarding        bool
	BreaksQuorumFloor bool
	// LeavesZeroCoreNodes is true when this offboard targets the literal LAST
	// remaining core node.
	LeavesZeroCoreNodes bool
	JoinCode            string // OTP — held only until Commit or Discard, never displayed back
	StagedBy            string
	StagedAt            time.Time
}

// Describe renders a short, human-readable summary of what committing this
// op will actually do.
func (op pendingNodeOp) Describe() string {
	switch op.Kind {
	case nodeOpReplace:
		roleLabel := op.Role
		if op.Role == probeRoleName {
			roleLabel = "the probe host"
		}
		if op.Onboarding {
			return fmt.Sprintf("Onboard %s as %s", op.Addr, roleLabel)
		}
		return fmt.Sprintf("Replace %s with %s", roleLabel, op.Addr)
	case nodeOpOffboard:
		return fmt.Sprintf("Offboard %s", op.Role)
	default:
		return string(op.Kind)
	}
}

// DescribeJSON is Describe encoded as a JSON string literal.
func (op pendingNodeOp) DescribeJSON() template.JS {
	b, _ := json.Marshal(op.Describe())
	return template.JS(b)
}

// Steps returns the real, deterministic step sequence that actually runs
// server-side once this op is committed.
func (op pendingNodeOp) Steps() []string {
	switch op.Kind {
	case nodeOpOffboard:
		steps := []string{
			"closing this node's DHCP gates for every scope",
			"notifying peers to stop trusting this node (trusted_hosts)",
			"tearing down every scope's VLAN interface",
			"stopping the DHCP relay, DNS relay, keepalived, and web UI services",
			"deleting cluster.json, credentials, and both TLS key pairs",
			"sweeping any remaining files — no leftovers",
			"stopping the privileged helper",
			"re-entering bootstrap mode, ready to be readopted",
		}
		switch {
		case op.LeavesZeroCoreNodes:
			steps = append([]string{"⚠ WARNING: this is the LAST remaining core node — committing this PERMANENTLY WIPES the entire cluster (every credential, every scope, gone), with nothing left to recover from except a backup taken beforehand"}, steps...)
		case op.BreaksQuorumFloor:
			steps = append([]string{"⚠ WARNING: this drops the cluster to fewer than 2 remaining core nodes — zero quorum, zero witness-token majority, zero failover until a replacement is onboarded"}, steps...)
		}
		return steps
	case nodeOpReplace:
		if op.Role == probeRoleName {
			steps := []string{
				"pushing a probe configuration to the new host",
				"writing its own admin token",
				"restarting it as a probe",
				"saving it to this cluster's node list",
			}
			if !op.Onboarding {
				steps = append([]string{"removing the currently-adopted probe host from this cluster's node list — only one is ever kept"}, steps...)
			}
			return steps
		}
		return []string{
			"pushing this cluster's configuration to the new node",
			"writing web UI credentials and TLS material",
			"restarting the new node as a configured daemon",
			"updating trusted_hosts across the cluster",
			"waiting for it to rejoin — this can take a few seconds",
		}
	default:
		return nil
	}
}

// StepsJSON is Steps encoded as a JSON array literal.
func (op pendingNodeOp) StepsJSON() template.JS {
	b, _ := json.Marshal(op.Steps())
	return template.JS(b)
}

var (
	nodeOpMu     sync.Mutex
	stagedNodeOp *pendingNodeOp
)

// stageNodeOp records op as the one staged node action, refusing if one is
// already staged.
func stageNodeOp(op pendingNodeOp) error {
	nodeOpMu.Lock()
	defer nodeOpMu.Unlock()
	if stagedNodeOp != nil {
		return fmt.Errorf("a node action is already staged (%s) — commit or discard it first", stagedNodeOp.Describe())
	}
	op.StagedAt = time.Now()
	stagedNodeOp = &op
	return nil
}

// currentNodeOp returns a copy of the staged op, or nil if none.
func currentNodeOp() *pendingNodeOp {
	nodeOpMu.Lock()
	defer nodeOpMu.Unlock()
	if stagedNodeOp == nil {
		return nil
	}
	cp := *stagedNodeOp
	return &cp
}

// clearNodeOp discards whatever's staged, if anything.
func clearNodeOp() {
	nodeOpMu.Lock()
	defer nodeOpMu.Unlock()
	stagedNodeOp = nil
}
