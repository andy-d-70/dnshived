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
	"dnshived/internal/nftgate"
	"dnshived/internal/trunkaddr"
)

var DefaultServerAddr = trunkaddr.DHCPAddress(trunkaddr.CoreIndex) + ":67"

func RenderRelayConfig(cluster config.Cluster, serverAddr string) (dhcprelay.Config, error) {
	if serverAddr == "" {
		serverAddr = DefaultServerAddr
	}

	cfg := dhcprelay.Config{ServerAddr: serverAddr, ServerInterface: "lo"}

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
			Name:             nftgate.InterfaceName(sc.Parent, sc.VLANID),
			GIAddr:           giaddr,
			ServerIdentifier: serverIdentifier,
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
// path as indented JSON, then hands group-read ownership to the "dnshived"
// system group.
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

	data, err := json.MarshalIndent(cfg, "", "  ")
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
	g, err := user.LookupGroup("dnshived")
	if err != nil {
		return fmt.Errorf("lookup dnshived group: %w", err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return fmt.Errorf("parse dnshived group gid %q: %w", g.Gid, err)
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
