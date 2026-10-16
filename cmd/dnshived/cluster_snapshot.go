// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

// GET /api/v1/cluster/snapshot.
import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"dnshived/internal/cluster"
)

// nodeSnapshot is one node's (self or peer) full bundle — exactly the
// four endpoints dnshived-top's own collectAll already fetches per node.
type nodeSnapshot struct {
	Status  json.RawMessage `json:"status,omitempty"`
	System  json.RawMessage `json:"system,omitempty"`
	Events  json.RawMessage `json:"events,omitempty"`
	Daemons json.RawMessage `json:"daemons,omitempty"`
	Error   string          `json:"error,omitempty"`
	// Via is "fallback" when this node's mgmt/control address was unreachable
	// and the bundle was fetched over its scope-VLAN fallback address instead
	// (ViaAddr).
	Via     string `json:"via,omitempty"`
	ViaAddr string `json:"via_addr,omitempty"`
}

// fetchJSONFrom does one plain GET against a node's own API and returns
// the raw, still-encoded response body.
func fetchJSONFrom(scheme, addr, path, token string) (json.RawMessage, error) {
	req, err := http.NewRequest(http.MethodGet, scheme+"://"+addr+path, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := clusterStatusHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		msg := resp.Status
		if loc := resp.Header.Get("Location"); loc != "" {
			msg += " (redirect to " + loc + ") — wrong port in this node's address?"
		}
		return nil, &httpStatusError{status: msg}
	}
	if !json.Valid(body) {
		return nil, &httpStatusError{status: notJSONReason(resp, body)}
	}
	return json.RawMessage(body), nil
}

// notJSONReason describes a 200 answer that is not JSON, so the operator
// sees what actually answered instead of a decoder error.
func notJSONReason(resp *http.Response, body []byte) string {
	snippet := strings.TrimSpace(string(body))
	if len(snippet) > 60 {
		snippet = snippet[:60] + "…"
	}
	return fmt.Sprintf("%s but not JSON (%s: %q)", resp.Status, resp.Header.Get("Content-Type"), snippet)
}

// httpStatusError wraps a non-200 HTTP status as a real error value.
type httpStatusError struct{ status string }

func (e *httpStatusError) Error() string { return e.status }

// fetchNodeSnapshot fetches all four bundled endpoints for one node.
func fetchNodeSnapshot(scheme, addr, token string) nodeSnapshot {
	status, err := fetchJSONFrom(scheme, addr, "/api/v1/status", token)
	if err != nil {
		return nodeSnapshot{Error: err.Error()}
	}
	snap := nodeSnapshot{Status: status}
	if system, err := fetchJSONFrom(scheme, addr, "/api/v1/system", token); err == nil {
		snap.System = system
	}
	if events, err := fetchJSONFrom(scheme, addr, "/api/v1/events?n=50", token); err == nil {
		snap.Events = events
	}
	if daemons, err := fetchJSONFrom(scheme, addr, "/api/v1/daemons", token); err == nil {
		snap.Daemons = daemons
	}
	return snap
}

func fetchPeerSnapshot(scheme, addr, token string, observer *cluster.Observer) nodeSnapshot {
	if observer == nil {
		return fetchNodeSnapshot(scheme, addr, token)
	}
	if fb, ok := observer.FallbackRoute(addr); ok {
		snap := fetchNodeSnapshot(scheme, fb, token)
		if snap.Error == "" {
			snap.Via, snap.ViaAddr = "fallback", fb
		}
		return snap
	}
	if observer.BelievedDown(addr) {
		return nodeSnapshot{Error: "peer believed unreachable (cluster observer) — not re-dialed"}
	}
	snap := fetchNodeSnapshot(scheme, addr, token)
	if snap.Error != "" {
		if fb, ok := observer.FallbackAddr(addr); ok {
			if retry := fetchNodeSnapshot(scheme, fb, token); retry.Error == "" {
				retry.Via, retry.ViaAddr = "fallback", fb
				return retry
			}
		}
	}
	return snap
}

func selfLoopbackAddr(listenAddr string) string {
	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil || port == "" {
		port = "9443"
	}
	return "127.0.0.1:" + port
}

// clusterSnapshotHandler builds GET /api/v1/cluster/snapshot's handler.
func clusterSnapshotHandler(observer *cluster.Observer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fresh := currentConfig.Load()
		scheme := "http"
		if fresh.TLSEnabled() {
			scheme = "https"
		}
		token := anyAPIToken(fresh.APITokens)
		selfAddr := selfLoopbackAddr(fresh.ListenAddr())

		self := fetchNodeSnapshot(scheme, selfAddr, token)

		peers := fresh.Peers
		results := make([]nodeSnapshot, len(peers))
		var wg sync.WaitGroup
		for i, addr := range peers {
			wg.Add(1)
			go func(i int, addr string) {
				defer wg.Done()
				results[i] = fetchPeerSnapshot(scheme, addr, token, observer)
			}(i, addr)
		}
		wg.Wait()

		peerMap := make(map[string]nodeSnapshot, len(peers))
		for i, addr := range peers {
			peerMap[addr] = results[i]
		}

		tokens, _ := fetchJSONFrom(scheme, selfAddr, "/api/v1/token/status", token)

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"self":   self,
			"peers":  peerMap,
			"tokens": tokens,
		})
	}
}
