// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

// GET /api/v1/cluster/status.
import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"dnshived/internal/cluster"
	"dnshived/internal/config"
	"dnshived/internal/tlspin"
)

// clusterStatusPeerTimeout bounds a single peer fetch.
const clusterStatusPeerTimeout = 5 * time.Second

// clusterStatusHTTPClient is shared across every peer fetch.
var clusterStatusHTTPClient = &http.Client{
	Timeout:   clusterStatusPeerTimeout,
	Transport: &http.Transport{TLSClientConfig: tlspin.Config()},
	// A redirect means the address points at the wrong service (e.g. the
	// web UI's port-443 redirect); report it instead of following it.
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// peerStatusEntry is one peer's own result in the aggregate response —
// exactly one of Status/Error is ever populated.
type peerStatusEntry struct {
	Status map[string]interface{} `json:"status,omitempty"`
	Error  string                 `json:"error,omitempty"`
}

// anyAPIToken picks one usable token from the cluster's own replicated
// list.
func anyAPIToken(tokens []config.APIToken) string {
	for _, t := range tokens {
		if t.Role == "admin" {
			return t.Token
		}
	}
	if len(tokens) > 0 {
		return tokens[0].Token
	}
	return ""
}

// fetchPeerStatus dials one peer's own GET /api/v1/status directly — a
// real HTTP round trip, not a shortcut.
func fetchPeerStatus(scheme, addr, token string) peerStatusEntry {
	raw, err := fetchJSONFrom(scheme, addr, "/api/v1/status", token)
	if err != nil {
		return peerStatusEntry{Error: err.Error()}
	}
	var status map[string]interface{}
	if err := json.Unmarshal(raw, &status); err != nil {
		return peerStatusEntry{Error: "decode: " + err.Error()}
	}
	return peerStatusEntry{Status: status}
}

// clusterStatusHandler builds GET /api/v1/cluster/status's handler.
func clusterStatusHandler(buildStatus func() map[string]interface{}, observer *cluster.Observer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fresh := currentConfig.Load()
		scheme := "http"
		if fresh.TLSEnabled() {
			scheme = "https"
		}
		token := anyAPIToken(fresh.APITokens)

		peers := fresh.Peers
		results := make([]peerStatusEntry, len(peers))
		var wg sync.WaitGroup
		for i, addr := range peers {
			if observer != nil && observer.BelievedDown(addr) {
				results[i] = peerStatusEntry{Error: "peer believed unreachable (cluster observer) — not re-dialed"}
				continue
			}
			wg.Add(1)
			go func(i int, addr string) {
				defer wg.Done()
				results[i] = fetchPeerStatus(scheme, addr, token)
			}(i, addr)
		}
		wg.Wait()

		peerMap := make(map[string]peerStatusEntry, len(peers))
		for i, addr := range peers {
			peerMap[addr] = results[i]
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"self":  buildStatus(),
			"peers": peerMap,
		})
	}
}
