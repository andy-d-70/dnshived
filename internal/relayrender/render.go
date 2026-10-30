// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package relayrender

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"sort"
	"strconv"
	"strings"

	"dnshived/internal/config"
	"dnshived/internal/dhcprelay"
	"dnshived/internal/ifname"
	"dnshived/internal/trunkaddr"
)

var DefaultServerAddr = trunkaddr.DHCPAddress(trunkaddr.CoreIndex) + ":67"

func RenderRelayConfig(cluster config.Cluster, serverAddr string) (dhcprelay.Config, error) {
	if serverAddr == "" {
		serverAddr = DefaultServerAddr
	}

	cfg := dhcprelay.Config{ServerAddr: serverAddr, ServerInterface: "lo"}
	if cluster.NodeID != "" {
		// The gate needs this node's ID (tokens name their owner) and the core count (quorum = majority).
		cfg.NodeID = cluster.NodeID
		cfg.CoreCount = len(cluster.Peers) + 1
	}

	names := make([]string, 0, len(cluster.Scopes))
	for name := range cluster.Scopes {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		sc := cluster.Scopes[name]
		if sc.NodeIP == "" {
			continue
		}
		giaddr, _, _ := strings.Cut(sc.NodeIP, "/")
		serverIdentifier, _, _ := strings.Cut(sc.VIP, "/")

		cfg.ClientInterfaces = append(cfg.ClientInterfaces, dhcprelay.ClientInterfaceConfig{
			Name:             ifname.InterfaceName(sc.Parent, sc.VLANID),
			GIAddr:           giaddr,
			ServerIdentifier: serverIdentifier,
			Scope:            name,
		})
	}

	if len(cfg.ClientInterfaces) == 0 {
		return dhcprelay.Config{}, fmt.Errorf("no scope in cluster config has a node_ip set -- nothing for the relay to serve")
	}
	if err := cfg.Validate(); err != nil {
		return dhcprelay.Config{}, fmt.Errorf("rendered relay config is invalid: %w", err)
	}
	return cfg, nil
}

// WriteRelayConfig renders cluster and atomically writes the result to
// path as indented JSON, then hands group-read ownership to relayGroup.
func WriteRelayConfig(path string, cluster config.Cluster, serverAddr string) error {
	cfg, err := RenderRelayConfig(cluster, serverAddr)
	if err != nil {
		return err
	}

	if data, err := os.ReadFile(path); err == nil {
		var existing dhcprelay.Config
		if err := json.Unmarshal(data, &existing); err == nil {
			cfg.RateLimit = existing.RateLimit
			cfg.RateBurst = existing.RateBurst
			cfg.PendingPerVLAN = existing.PendingPerVLAN
			cfg.ClientRateLimit = existing.ClientRateLimit
			cfg.ClientRateBurst = existing.ClientRateBurst
			existingByName := make(map[string]dhcprelay.ClientInterfaceConfig, len(existing.ClientInterfaces))
			for _, ci := range existing.ClientInterfaces {
				existingByName[ci.Name] = ci
			}
			for i, ci := range cfg.ClientInterfaces {
				if old, ok := existingByName[ci.Name]; ok {
					cfg.ClientInterfaces[i].RateLimit = old.RateLimit
					cfg.ClientInterfaces[i].RateBurst = old.RateBurst
				}
			}
		}
	}

	return writeRelayFile(path, cfg)
}

// ClearRelayConfig empties the client interface list in path, keeping its rate limits. A file that
// already lists no interfaces is left untouched; a missing one is written empty.
func ClearRelayConfig(path string) error {
	cfg := dhcprelay.Config{ServerAddr: DefaultServerAddr, ServerInterface: "lo"}
	data, err := os.ReadFile(path)
	if err == nil {
		var existing dhcprelay.Config
		if err := json.Unmarshal(data, &existing); err == nil {
			if len(existing.ClientInterfaces) == 0 {
				return nil
			}
			cfg.ServerAddr = existing.ServerAddr
			cfg.NodeID = existing.NodeID
			cfg.CoreCount = existing.CoreCount
			cfg.RateLimit = existing.RateLimit
			cfg.RateBurst = existing.RateBurst
			cfg.PendingPerVLAN = existing.PendingPerVLAN
			cfg.ClientRateLimit = existing.ClientRateLimit
			cfg.ClientRateBurst = existing.ClientRateBurst
		}
	}
	return writeRelayFile(path, cfg)
}

func writeRelayFile(path string, cfg dhcprelay.Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal relay config: %w", err)
	}
	if err := atomicWriteFile(path, data, 0640); err != nil {
		return err
	}
	return chownToRelayGroup(path)
}

// relayGroup is the system group the relay process runs under; the daemon
// joins it to reach the relay's gate socket. Created by the packages.
const relayGroup = "dnshived-relay"

// chownToRelayGroup sets path's group ownership to relayGroup.
func chownToRelayGroup(path string) error {
	g, err := user.LookupGroup(relayGroup)
	if err != nil {
		return fmt.Errorf("lookup %s group: %w", relayGroup, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return fmt.Errorf("parse %s group gid %q: %w", relayGroup, g.Gid, err)
	}
	return os.Chown(path, -1, gid)
}

// atomicWriteFile writes data to path via a temp file + rename.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
