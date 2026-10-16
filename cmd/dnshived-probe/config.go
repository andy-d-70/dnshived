// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"

	"dnshived/internal/config"
)

type ClusterNode struct {
	Name string `json:"name"`
	Addr string `json:"addr"` // host:port
	TLS  bool   `json:"tls"`
}

func (n ClusterNode) baseURL() string {
	scheme := "http"
	if n.TLS {
		scheme = "https"
	}
	return scheme + "://" + n.Addr
}

// ProbeConfig is cmd/dnshived-probe's own config file.
type ProbeConfig struct {
	ListenAddr string `json:"listen_addr"`

	TrunkParent string `json:"trunk_parent"`

	// ProbeIntervalMS paces the background probing loop — same shape as
	// Agent.RunProbes.
	ProbeIntervalMS int `json:"probe_interval_ms,omitempty"`

	ClusterToken string `json:"cluster_token"`

	ClusterNodes []ClusterNode `json:"cluster_nodes"`

	// APITokens gates THIS binary's own read API (GET /api/v1/status, GET
	// /api/v1/probe/<scope>) for dnshived-web/dnshived-top to poll.
	APITokens []config.APIToken `json:"api_tokens,omitempty"`

	// DHCPWaitMS bounds how long one DHCP probe listens for offers.
	DHCPWaitMS int `json:"dhcp_wait_ms,omitempty"`

	// EventLogPath, when set, persists every edge-triggered PROBE:* transition
	// (see probeLogTracker) to this file as append-only NDJSON, size-rotated
	// at 10MB.
	EventLogPath string `json:"event_log_path,omitempty"`

	// ProbeHelperSocket, when set, enables the admin-gated POST
	// /api/v1/restart endpoint.
	ProbeHelperSocket string `json:"probe_helper_socket,omitempty"`

	LocalOctet int `json:"local_octet,omitempty"`

	// TrunkParents is the set of this host's own local trunk NICs eligible for
	// VLAN construction.
	TrunkParents []string `json:"trunk_parents,omitempty"`

	// KnownVLANsPath persists, across restarts, the (parent, vlan_id) set this
	// host last actually constructed.
	KnownVLANsPath string `json:"known_vlans_path,omitempty"`

	// ParallelProbing fires every scope's probe concurrently instead of one at
	// a time.
	ParallelProbing bool `json:"parallel_probing,omitempty"`

	parallelLive atomic.Int32
}

// Parallel reports whether sweeps should probe scopes concurrently right
// now — the live override if one was applied, else the loaded config
// value.
func (c *ProbeConfig) Parallel() bool {
	switch c.parallelLive.Load() {
	case 1:
		return false
	case 2:
		return true
	default:
		return c.ParallelProbing
	}
}

// SetParallel applies a new parallel_probing value to the running process.
func (c *ProbeConfig) SetParallel(on bool) {
	if on {
		c.parallelLive.Store(2)
	} else {
		c.parallelLive.Store(1)
	}
}

func loadProbeConfig(path string) (*ProbeConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read probe config %s: %w", path, err)
	}
	var c ProbeConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse probe config: %w", err)
	}
	if c.ListenAddr == "" {
		return nil, fmt.Errorf("listen_addr is required")
	}
	if c.TrunkParent == "" {
		return nil, fmt.Errorf("trunk_parent is required")
	}
	if c.ClusterToken == "" {
		return nil, fmt.Errorf("cluster_token is required")
	}
	if len(c.ClusterNodes) == 0 {
		return nil, fmt.Errorf("at least one cluster_node is required")
	}
	for i, n := range c.ClusterNodes {
		if n.Name == "" {
			return nil, fmt.Errorf("cluster_nodes[%d]: name is required", i)
		}
		if n.Addr == "" {
			return nil, fmt.Errorf("cluster_nodes[%d]: addr is required", i)
		}
	}
	if c.LocalOctet != 0 {
		if c.LocalOctet < 1 || c.LocalOctet > 254 {
			return nil, fmt.Errorf("local_octet out of range: %d", c.LocalOctet)
		}
		if c.ProbeHelperSocket == "" {
			return nil, fmt.Errorf("probe_helper_socket is required when local_octet is set — VLAN construction needs the privileged helper")
		}
		if c.KnownVLANsPath == "" {
			return nil, fmt.Errorf("known_vlans_path is required when local_octet is set")
		}
	}
	return &c, nil
}

func (c *ProbeConfig) trunkParents() []string {
	if len(c.TrunkParents) > 0 {
		return c.TrunkParents
	}
	if c.TrunkParent != "" {
		return []string{c.TrunkParent}
	}
	return nil
}

func (c *ProbeConfig) knownVLANsPath() string {
	if c.KnownVLANsPath != "" {
		return c.KnownVLANsPath
	}
	return "/var/lib/dnshived-probe/known-vlans.json"
}

func (c *ProbeConfig) probeInterval() int {
	if c.ProbeIntervalMS > 0 {
		return c.ProbeIntervalMS
	}
	return 20000
}

func (c *ProbeConfig) dhcpWaitMS() int {
	if c.DHCPWaitMS > 0 {
		return c.DHCPWaitMS
	}
	return 9000
}
