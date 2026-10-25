// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package leasesync

import (
	"bytes"
	"dnshived/internal/loglevel"
	"encoding/json"
	"fmt"
	"net/http"

	"dnshived/internal/trustedhosts"
)

// wireMessage is the POST body both directions of the sync protocol use.
type wireMessage struct {
	Action    string `json:"action"` // "upsert" or "remove"
	MAC       string `json:"mac"`
	IP        string `json:"ip,omitempty"`         // only meaningful for "upsert"
	ExpiresAt int64  `json:"expires_at,omitempty"` // only meaningful for "upsert"
	Hostname  string `json:"hostname,omitempty"`   // only meaningful for "upsert"
}

// Handler receives lease-sync pushes from the peer worker and applies them
// to Store.
type Handler struct {
	Store              *Store
	OnChange           func()
	MergedSnapshotFunc func() []SyncedLease
	trustedHosts       trustedhosts.Set
}

// NewHandler returns a Handler with an empty Store, ready for AddRoutes.
func NewHandler() *Handler {
	return &Handler{Store: NewStore()}
}

// SetTrustedHosts installs the source-IP allowlist gating this endpoint.
func (h *Handler) SetTrustedHosts(hosts []string) {
	h.trustedHosts = trustedhosts.New(hosts)
}

// AddRoutes registers this handler's endpoints on mux — mirrors
// internal/arbiter.Manager.AddRoutes' own shape.
func (h *Handler) AddRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/leasesync", h.handle)
	mux.HandleFunc("/api/v1/leasesync/fingerprint", h.handleFingerprint)
	mux.HandleFunc("/api/v1/leasesync/snapshot", h.handleSnapshot)
}

// mergedSnapshot returns this node's own MergedSnapshotFunc result, or
// falls back to the peer-only Store if never wired.
func (h *Handler) mergedSnapshot() []SyncedLease {
	if h.MergedSnapshotFunc != nil {
		return h.MergedSnapshotFunc()
	}
	return h.Store.Snapshot()
}

type fingerprintResponse struct {
	Fingerprint string `json:"fingerprint"`
}

func (h *Handler) handleFingerprint(w http.ResponseWriter, r *http.Request) {
	if !h.trustedHosts.Allowed(r.RemoteAddr) {
		loglevel.Warnf("[LEASESYNC:DENY_UNTRUSTED] request from untrusted host: remote_addr=%s", r.RemoteAddr)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(fingerprintResponse{Fingerprint: Fingerprint(h.mergedSnapshot())})
}

// handleSnapshot returns this node's full merged view — fetched by a
// peer only after its own fingerprint check already found a mismatch,
// never unconditionally.
func (h *Handler) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	if !h.trustedHosts.Allowed(r.RemoteAddr) {
		loglevel.Warnf("[LEASESYNC:DENY_UNTRUSTED] request from untrusted host: remote_addr=%s", r.RemoteAddr)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.mergedSnapshot())
}

func (h *Handler) handle(w http.ResponseWriter, r *http.Request) {
	if !h.trustedHosts.Allowed(r.RemoteAddr) {
		loglevel.Warnf("[LEASESYNC:DENY_UNTRUSTED] request from untrusted host: remote_addr=%s", r.RemoteAddr)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var msg wireMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "malformed body", http.StatusBadRequest)
		return
	}
	if msg.MAC == "" {
		http.Error(w, "mac is required", http.StatusBadRequest)
		return
	}

	switch msg.Action {
	case "upsert":
		h.Store.Upsert(SyncedLease{MAC: msg.MAC, IP: msg.IP, ExpiresAt: msg.ExpiresAt, Hostname: msg.Hostname})
	case "remove":
		h.Store.Remove(msg.MAC)
	default:
		http.Error(w, fmt.Sprintf("unknown action %q", msg.Action), http.StatusBadRequest)
		return
	}

	if h.OnChange != nil {
		h.OnChange()
	}
	w.WriteHeader(http.StatusOK)
}

func Push(client *http.Client, scheme, addr string, l SyncedLease, action string) error {
	msg := wireMessage{Action: action, MAC: l.MAC, IP: l.IP, ExpiresAt: l.ExpiresAt, Hostname: l.Hostname}
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal lease-sync message: %w", err)
	}
	url := fmt.Sprintf("%s://%s/api/v1/leasesync", scheme, addr)
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("push lease-sync to %s: %w", addr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("push lease-sync to %s: status %d", addr, resp.StatusCode)
	}
	return nil
}

// FetchFingerprint gets addr's own current fingerprint — the cheap half
// of the periodic cross-node check (Agent.CheckLeaseSanity).
func FetchFingerprint(client *http.Client, scheme, addr string) (string, error) {
	url := fmt.Sprintf("%s://%s/api/v1/leasesync/fingerprint", scheme, addr)
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("fetch fingerprint from %s: %w", addr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch fingerprint from %s: status %d", addr, resp.StatusCode)
	}
	var out fingerprintResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode fingerprint from %s: %w", addr, err)
	}
	return out.Fingerprint, nil
}

// FetchSnapshot gets addr's own full merged view.
func FetchSnapshot(client *http.Client, scheme, addr string) ([]SyncedLease, error) {
	url := fmt.Sprintf("%s://%s/api/v1/leasesync/snapshot", scheme, addr)
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch snapshot from %s: %w", addr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch snapshot from %s: status %d", addr, resp.StatusCode)
	}
	var out []SyncedLease
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode snapshot from %s: %w", addr, err)
	}
	return out, nil
}
