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

	// ClusterCertPEM is the cores' shared certificate (public part); when set, connections to the cores are pinned to it.
	ClusterCertPEM string `json:"cluster_cert_pem,omitempty"`

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

	// MgmtInterface is this host's management NIC. It may serve scopes
	// (untagged ones), but its static address and sub-interfaces are never
	// touched: it is not a trunk and no VLAN is built or removed on it.
	MgmtInterface string `json:"mgmt_interface,omitempty"`

	// ManualProbes are operator-defined DHCP watches on any interface this
	// host serves, tagged or untagged; see ManualProbe.
	ManualProbes []ManualProbe `json:"manual_probes,omitempty"`

	// History is what the probe host records of its own results; see HistoryConfig.
	History *HistoryConfig `json:"history,omitempty"`

	// PlainHTTP keeps the unencrypted API on listen_addr. Absent means on, so
	// a configuration written before this key keeps working; a probe adopted
	// with a pinned certificate has it switched off by the web UI.
	PlainHTTP *bool `json:"plain_http,omitempty"`

	manualLive atomic.Pointer[[]ManualProbe]

	// KnownVLANsPath persists, across restarts, the (parent, vlan_id) set this
	// host last actually constructed.
	KnownVLANsPath string `json:"known_vlans_path,omitempty"`

	// ParallelProbing fires every scope's probe concurrently instead of one at
	// a time.
	ParallelProbing bool `json:"parallel_probing,omitempty"`

	parallelLive atomic.Int32
}

func (c *ProbeConfig) plainHTTP() bool { return c.PlainHTTP == nil || *c.PlainHTTP }

// manualProbeList returns the manual probes now in force: the live list when
// one was applied, else the loaded one.
func (c *ProbeConfig) manualProbeList() []ManualProbe {
	if l := c.manualLive.Load(); l != nil {
		return *l
	}
	return c.ManualProbes
}

// SetManualProbes applies a new manual probe list to the running process.
func (c *ProbeConfig) SetManualProbes(list []ManualProbe) {
	c.manualLive.Store(&list)
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

// trunkParents are the NICs VLANs are built on; the management interface
// never is one.
func (c *ProbeConfig) trunkParents() []string {
	var all []string
	if len(c.TrunkParents) > 0 {
		all = c.TrunkParents
	} else if c.TrunkParent != "" {
		all = []string{c.TrunkParent}
	}
	var out []string
	for _, p := range all {
		if p != c.MgmtInterface {
			out = append(out, p)
		}
	}
	return out
}

// servingParents are the NICs scopes are probed on: the trunks and the
// management interface.
func (c *ProbeConfig) servingParents() []string {
	out := c.trunkParents()
	if c.MgmtInterface != "" {
		out = append(out, c.MgmtInterface)
	}
	if len(out) == 0 && c.TrunkParent != "" {
		out = []string{c.TrunkParent}
	}
	return out
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
