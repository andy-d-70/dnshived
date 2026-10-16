// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcprelay

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
)

// Config is the relay's standalone configuration.
type Config struct {
	// ClientInterfaces lists every VLAN interface this relay listens on for
	// client broadcast traffic (DHCPDISCOVER/REQUEST).
	ClientInterfaces []ClientInterfaceConfig `json:"client_interfaces"`

	// ServerAddr is the DHCP server this relay forwards to, e.g.
	// "127.0.0.21:67" for the central per-worker DHCP-only dnsmasq instance.
	ServerAddr string `json:"server_addr"`

	// ServerInterface optionally scopes the server-facing socket with
	// SO_BINDTODEVICE the same way each client interface is scoped.
	ServerInterface string `json:"server_interface,omitempty"`

	// RateLimit/RateBurst bound how many client requests per second EACH
	// client interface accepts before dropping the rest.
	RateLimit int `json:"rate_limit,omitempty"`
	RateBurst int `json:"rate_burst,omitempty"`
}

type ClientInterfaceConfig struct {
	// Name is the VLAN interface to bind, e.g. "ens19.200".
	Name string `json:"name"`

	// GIAddr is this node's own address on that VLAN -- in this project's
	// topology, the scope's already-assigned node_ip for this worker.
	GIAddr string `json:"giaddr"`

	// ServerIdentifier, when set, is what handleServerReply rewrites a reply's
	// option 54 (server identifier) to on its way to the real client.
	ServerIdentifier string `json:"server_identifier,omitempty"`

	// ServerAddr overrides Config.ServerAddr for this one client interface.
	ServerAddr string `json:"server_addr,omitempty"`

	// RateLimit/RateBurst override Config.RateLimit/RateBurst for this one
	// client interface.
	RateLimit int `json:"rate_limit,omitempty"`
	RateBurst int `json:"rate_burst,omitempty"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) Validate() error {
	if len(c.ClientInterfaces) == 0 {
		return fmt.Errorf("client_interfaces must not be empty")
	}
	if c.ServerAddr == "" {
		return fmt.Errorf("server_addr is required")
	}
	if _, _, err := net.SplitHostPort(c.ServerAddr); err != nil {
		return fmt.Errorf("server_addr %q: %w", c.ServerAddr, err)
	}

	if c.RateLimit < 0 {
		return fmt.Errorf("rate_limit must not be negative")
	}
	if c.RateBurst < 0 {
		return fmt.Errorf("rate_burst must not be negative")
	}

	seenNames := make(map[string]bool, len(c.ClientInterfaces))
	seenGIAddrs := make(map[string]string, len(c.ClientInterfaces))
	for _, ci := range c.ClientInterfaces {
		if ci.Name == "" {
			return fmt.Errorf("client interface entry has an empty name")
		}
		if seenNames[ci.Name] {
			return fmt.Errorf("client interface %q listed more than once", ci.Name)
		}
		seenNames[ci.Name] = true
		if ci.RateLimit < 0 {
			return fmt.Errorf("client interface %q: rate_limit must not be negative", ci.Name)
		}
		if ci.RateBurst < 0 {
			return fmt.Errorf("client interface %q: rate_burst must not be negative", ci.Name)
		}

		ip := net.ParseIP(ci.GIAddr)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("client interface %q: giaddr %q is not a valid IPv4 address", ci.Name, ci.GIAddr)
		}
		if ip.IsUnspecified() {
			return fmt.Errorf("client interface %q: giaddr must not be 0.0.0.0", ci.Name)
		}
		if other, dup := seenGIAddrs[ip.String()]; dup {
			return fmt.Errorf("giaddr %s used by both %q and %q", ip.String(), other, ci.Name)
		}
		seenGIAddrs[ip.String()] = ci.Name

		if ci.ServerAddr != "" {
			if _, _, err := net.SplitHostPort(ci.ServerAddr); err != nil {
				return fmt.Errorf("client interface %q: server_addr %q: %w", ci.Name, ci.ServerAddr, err)
			}
		}

		if ci.ServerIdentifier != "" {
			sid := net.ParseIP(ci.ServerIdentifier)
			if sid == nil || sid.To4() == nil {
				return fmt.Errorf("client interface %q: server_identifier %q is not a valid IPv4 address", ci.Name, ci.ServerIdentifier)
			}
			if sid.IsUnspecified() {
				return fmt.Errorf("client interface %q: server_identifier must not be 0.0.0.0", ci.Name)
			}
		}
	}
	return nil
}
