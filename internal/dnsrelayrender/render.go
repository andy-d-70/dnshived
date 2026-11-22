// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package dnsrelayrender derives the standalone dnshived-dnsrelay binary's
// own JSON config from a live dnshived cluster config.
package dnsrelayrender

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"dnshived/internal/access"
	"dnshived/internal/config"
	"dnshived/internal/dnscentralrender"
	"dnshived/internal/ifname"
	"dnshived/internal/ownership"
)

// RelayConfig mirrors the subset of cmd/dnshived-dnsrelay's own Config
// struct this renderer actually populates.
type RelayConfig struct {
	Upstreams         []string `json:"upstreams"`
	AllowedInterfaces []string `json:"allowed_interfaces"`
	CacheSize         int      `json:"cache_size,omitempty"`
	CacheMaxBytes     int      `json:"cache_max_bytes,omitempty"`

	// Access and AccessAlways are the access list and the addresses served no matter what; both stay empty until
	// every core can enforce the list.
	Access       *access.Config `json:"access,omitempty"`
	AccessAlways []string       `json:"access_always,omitempty"`
}

func RenderRelayConfig(cluster config.Cluster) (RelayConfig, error) {
	upstream := cluster.CoreDNSAddress
	if upstream == "" {
		upstream = dnscentralrender.DefaultAddress
	}
	cfg := RelayConfig{
		Upstreams:     []string{upstream},
		CacheSize:     cluster.DNSRelayCacheSize,
		CacheMaxBytes: cluster.DNSRelayCacheMaxBytes,
	}

	if cluster.Access != nil && cluster.AccessListActive {
		cfg.Access = cluster.Access
		cfg.AccessAlways = cluster.AccessAlways()
	}

	names := make([]string, 0, len(cluster.Scopes))
	for name := range cluster.Scopes {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		sc := cluster.Scopes[name]
		if sc.DNSMasqDisabled {
			continue
		}
		cfg.AllowedInterfaces = append(cfg.AllowedInterfaces, ifname.InterfaceName(sc.Parent, sc.VLANID))
	}

	if len(cfg.AllowedInterfaces) == 0 {
		return RelayConfig{}, fmt.Errorf("no scope in cluster config is eligible for the DNS relay -- nothing for it to serve")
	}
	return cfg, nil
}

// TableFile, when set by the daemon, is written into the relay config as the answer table to serve from.
var TableFile string

// FeedSocket, when set by the daemon, is written into the relay config as the socket to follow the table feed on.
var FeedSocket string

// WriteRelayConfig renders cluster and MERGES the result into whatever's
// already at path, rather than overwriting the file wholesale.
func WriteRelayConfig(path string, cluster config.Cluster) error {
	rendered, err := RenderRelayConfig(cluster)
	if err != nil {
		return err
	}

	existing := map[string]any{}
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &existing)
	}

	upstreams := make([]any, len(rendered.Upstreams))
	for i, u := range rendered.Upstreams {
		upstreams[i] = u
	}
	ifaces := make([]any, len(rendered.AllowedInterfaces))
	for i, ifn := range rendered.AllowedInterfaces {
		ifaces[i] = ifn
	}
	existing["upstreams"] = upstreams
	existing["allowed_interfaces"] = ifaces
	if rendered.CacheSize != 0 {
		existing["cache_size"] = rendered.CacheSize
	}
	if rendered.CacheMaxBytes != 0 {
		existing["cache_max_bytes"] = rendered.CacheMaxBytes
	}
	if TableFile != "" {
		existing["table_file"] = TableFile
	}
	if FeedSocket != "" {
		existing["feed_socket"] = FeedSocket
	} else {
		delete(existing, "feed_socket")
	}
	if rendered.Access != nil {
		existing["access"] = rendered.Access
		existing["access_always"] = rendered.AccessAlways
	} else {
		delete(existing, "access")
		delete(existing, "access_always")
	}

	data, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal relay config: %w", err)
	}
	if err := atomicWriteFile(path, data, 0640); err != nil {
		return err
	}
	return chownToDnshivedGroup(path)
}

// chownToDnshivedGroup sets path's group ownership to the "dnshived"
// system group (created by debian/dnshived.postinst on every real
// install).
func chownToDnshivedGroup(path string) error {
	return ownership.Dnshived(path)
}

// atomicWriteFile writes data to path via a temp file + rename.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
