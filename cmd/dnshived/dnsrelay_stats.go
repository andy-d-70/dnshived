// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"net/http"
	"os"

	"dnshived/internal/agent"
)

// dnsRelayStatsResponse is GET /api/v1/dnsrelay-stats' own wire shape.
type dnsRelayStatsResponse struct {
	Available bool `json:"available"`

	Entries       int     `json:"entries,omitempty"`
	CacheSize     int     `json:"cache_size,omitempty"`
	CacheMaxBytes int     `json:"cache_max_bytes,omitempty"`
	BytesUsed     int64   `json:"bytes_used,omitempty"`
	Hits          uint64  `json:"hits,omitempty"`
	Misses        uint64  `json:"misses,omitempty"`
	HitRatePct    float64 `json:"hit_rate_pct,omitempty"`
	UpdatedAt     string  `json:"updated_at,omitempty"`
}

// readDNSRelayStats reads path (written by cmd/dnshived-dnsrelay's own
// statsFileLoop, same host, no cross-process signaling needed) and returns
// its content.
func readDNSRelayStats(path string) dnsRelayStatsResponse {
	data, err := os.ReadFile(path)
	if err != nil {
		return dnsRelayStatsResponse{Available: false}
	}
	var snap dnsRelayStatsResponse
	if err := json.Unmarshal(data, &snap); err != nil {
		return dnsRelayStatsResponse{Available: false}
	}
	snap.Available = true
	return snap
}

// dnsRelayStatsHandler passes agent.DNSRelayStatsPath's own content
// straight through via readDNSRelayStats.
func dnsRelayStatsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, readDNSRelayStats(agent.DNSRelayStatsPath))
	}
}
