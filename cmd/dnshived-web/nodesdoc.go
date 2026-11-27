// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"fmt"
	"time"

	"dnshived/internal/repldoc"
)

// The core node list of web.json (role, control address, TLS, admin token, display name, colour) is replicated
// between the web instances like the probe-host list, keyed by role, so an instance that missed an adoption,
// replacement, offboarding or rename catches up.

const maxReplNodes = 64

var nodesSpec = listSpec{
	tag:     "nodes",
	path:    "/internal/docs/nodes",
	wireKey: "nodes",
	part:    "nodes",
	noun:    "node",
	key:     func(n NodeConfig) string { return n.Name },
	get:     func(c *WebConfig) []NodeConfig { return c.Nodes },
	set:     func(c *WebConfig, l []NodeConfig) { c.Nodes = l },
	stamp: func(c *WebConfig) (*int64, *string, *string, *string) {
		return &c.NodesVersion, &c.NodesUpdatedAt, &c.NodesOrigin, &c.NodesHash
	},
	check: validateNodes,
}

func newNodesDoc(ref *configRef, cfgPath string, self func() string) *listDoc {
	return &listDoc{spec: nodesSpec, ref: ref, cfgPath: cfgPath, self: self}
}

func runNodesSync(ctx context.Context, s *repldoc.Syncer) { runListSync(ctx, s, 9*time.Second) }

// validateNodes refuses a node list no real instance would send.
func validateNodes(nodes []NodeConfig) error {
	if len(nodes) > maxReplNodes {
		return fmt.Errorf("node list has %d entries, more than the limit of %d", len(nodes), maxReplNodes)
	}
	seen := make(map[string]bool, len(nodes))
	for i, n := range nodes {
		if n.Name == "" || len(n.Name) > 64 {
			return fmt.Errorf("node list: entry %d has an empty or oversized role", i)
		}
		if seen[n.Name] {
			return fmt.Errorf("node list: role %q appears twice", n.Name)
		}
		seen[n.Name] = true
		if n.Addr == "" || len(n.Addr) > 255 {
			return fmt.Errorf("node list: role %q has an empty or oversized address", n.Name)
		}
		for _, f := range []string{n.DisplayName, n.AdminToken, n.Color, n.TLSPort, n.TLSFingerprint} {
			if len(f) > maxReplHostField {
				return fmt.Errorf("node list: role %q has an oversized field", n.Name)
			}
		}
	}
	return nil
}
