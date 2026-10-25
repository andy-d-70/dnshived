// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"dnshived/internal/config"
	"dnshived/internal/tlspin"
)

var clusterHTTPClient = &http.Client{
	Timeout: 8 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: tlspin.Config(),
	},
}

// remoteScope mirrors GET /api/v1/probe-config's per-scope shape
// (cmd/dnshived/main.go).
type remoteScope struct {
	Parent          string             `json:"parent"`
	VLANID          int                `json:"vlan_id"`
	VIP             string             `json:"vip"`
	NodeIP          string             `json:"node_ip"`
	Gateway         string             `json:"gateway"`
	DHCPRange       [2]string          `json:"dhcp_range"`
	PreferredWorker string             `json:"preferred_worker"`
	DNSRecords      []config.DNSRecord `json:"dns_records"`
	ProbeDisabled   bool               `json:"probe_disabled"`
}

type probeConfigResponse struct {
	NodeID           string                 `json:"node_id"`
	Role             string                 `json:"role"`
	Scopes           map[string]remoteScope `json:"scopes"`
	DefaultDNSChecks []config.DNSCheck      `json:"default_dns_checks"`
	// Incarnation is this node's own state.NextIncarnation counter, bumped on
	// every daemon start.
	Incarnation        uint64 `json:"incarnation"`
	ClusterHasUpstream bool   `json:"cluster_has_upstream"`
}

func fetchProbeConfig(n ClusterNode, token string) (probeConfigResponse, error) {
	var out probeConfigResponse
	req, err := http.NewRequest("GET", n.baseURL()+"/api/v1/probe-config", nil)
	if err != nil {
		return out, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := clusterHTTPClient.Do(req)
	if err != nil {
		return out, fmt.Errorf("fetch probe-config from %s: %w", n.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("fetch probe-config from %s: HTTP %d", n.Name, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, fmt.Errorf("decode probe-config from %s: %w", n.Name, err)
	}
	return out, nil
}

type remoteStatus struct {
	ConfiguredScopes []string `json:"configured_scopes"`
	Serving          []string `json:"serving"`
}

// fetchStatus requires the cluster token like every other call in this
// file.
func fetchStatus(n ClusterNode, token string) (remoteStatus, error) {
	var out remoteStatus
	req, err := http.NewRequest("GET", n.baseURL()+"/api/v1/status", nil)
	if err != nil {
		return out, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := clusterHTTPClient.Do(req)
	if err != nil {
		return out, fmt.Errorf("fetch status from %s: %w", n.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("fetch status from %s: HTTP %d", n.Name, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, fmt.Errorf("decode status from %s: %w", n.Name, err)
	}
	return out, nil
}

// tokenInfo mirrors GET /api/v1/token/status's per-scope entries
// (internal/arbiter/manager.go).
type tokenInfo struct {
	Owner     string `json:"owner"`
	ExpiresAt string `json:"expires_at"`
	Expired   bool   `json:"expired"`
}

func fetchTokenStatus(n ClusterNode, token string) (map[string]tokenInfo, error) {
	var out map[string]tokenInfo
	req, err := http.NewRequest("GET", n.baseURL()+"/api/v1/token/status", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := clusterHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch token/status from %s: %w", n.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch token/status from %s: HTTP %d", n.Name, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode token/status from %s: %w", n.Name, err)
	}
	return out, nil
}
