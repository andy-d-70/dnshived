// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// NodeConfig is one cluster node dnshived-web talks to.
type NodeConfig struct {
	Name        string `json:"name"`
	Addr        string `json:"addr"`        // host:port
	TLS         bool   `json:"tls"`         // use https:// when true
	AdminToken  string `json:"admin_token"` // Bearer token, admin role, for POST endpoints
	DisplayName string `json:"display_name,omitempty"`
}

// displayName returns n's cosmetic DisplayName when set, falling back to
// its real Name.
func (n NodeConfig) displayName() string {
	if n.DisplayName != "" {
		return n.DisplayName
	}
	return n.Name
}

// WebConfig is cmd/dnshived-web's own config file.
type WebConfig struct {
	ListenAddr string       `json:"listen_addr"`
	HTTPAddr   string       `json:"http_addr,omitempty"`
	TLSCert    string       `json:"tls_cert,omitempty"`
	TLSKey     string       `json:"tls_key,omitempty"`
	UsersFile  string       `json:"users_file"`
	Nodes      []NodeConfig `json:"nodes"`

	// TemplatesFile is the named DHCP-option-set / DNS-record-set template
	// library (templates.go, scope_wizard.go).
	TemplatesFile string `json:"templates_file,omitempty"`

	// VIPHost is the mgmt VIP's hostname or bare IP (no port).
	VIPHost string `json:"vip_host,omitempty"`

	ExternalHosts []string `json:"external_hosts,omitempty"`

	ProbeHosts []NodeConfig `json:"probe_hosts,omitempty"`

	CoordinatorNode *NodeConfig `json:"coordinator,omitempty"`

	SelfAdminToken string `json:"self_admin_token,omitempty"`

	// WebHelperSocket is dnshived-web-helper's Unix socket
	// (internal/webhelper).
	WebHelperSocket string `json:"web_helper_socket,omitempty"`

	// SelfDisplayName is this instance's OWN cosmetic nickname.
	SelfDisplayName string `json:"self_display_name,omitempty"`
}

func loadWebConfig(path string) (*WebConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read web config %s: %w", path, err)
	}
	var c WebConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse web config: %w", err)
	}
	if c.ListenAddr == "" {
		return nil, fmt.Errorf("listen_addr is required")
	}
	if c.UsersFile == "" {
		return nil, fmt.Errorf("users_file is required")
	}
	if c.TemplatesFile == "" {
		c.TemplatesFile = "/etc/dnshived/web-templates.json"
	}
	if c.WebHelperSocket == "" {
		c.WebHelperSocket = "/run/dnshived/web-helper.sock"
	}
	for i, n := range c.Nodes {
		if n.Name == "" {
			return nil, fmt.Errorf("nodes[%d]: name is required", i)
		}
		if n.Addr == "" {
			return nil, fmt.Errorf("nodes[%d]: addr is required", i)
		}
	}
	return &c, nil
}

func (n NodeConfig) baseURL() string {
	scheme := "http"
	if n.TLS {
		scheme = "https"
	}
	return scheme + "://" + n.Addr
}
