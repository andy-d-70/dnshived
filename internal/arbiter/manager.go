// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package arbiter implements the witness protocol for scope ownership.
package arbiter

import (
	"crypto/rand"
	"dnshived/internal/loglevel"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"dnshived/internal/psksign"
	"dnshived/internal/timehealth"
	"dnshived/internal/trustedhosts"
)

const (
	tokenTTL        = 15 * time.Second
	nonceMaxAge     = 60 // seconds
	cleanupInterval = 2 * time.Second
	timestampWindow = 5 // seconds
)

// Manager tracks granted scope tokens and serves the token API.
type Manager struct {
	mu           sync.Mutex
	tokens       map[string]*Token // scope → active token
	psk          []byte
	quorumFunc   func() bool
	nonceCache   map[string]int64 // nonce → timestamp (replay protection)
	startOnce    sync.Once
	trustedHosts trustedhosts.Set

	// dataDir/dirty back Manager's own persistence.
	dataDir string
	dirty   bool
}

// New creates a Manager.
func New(psk []byte, quorumFunc func() bool, dataDir string) *Manager {
	return &Manager{
		tokens:     loadTokens(dataDir),
		psk:        psk,
		quorumFunc: quorumFunc,
		nonceCache: make(map[string]int64),
		dataDir:    dataDir,
	}
}

func (m *Manager) SetTrustedHosts(hosts []string) {
	m.trustedHosts = trustedhosts.New(hosts)
}

// checkTrustedHost denies a request from a source address not in the
// configured allowlist, writing the response itself on denial.
func (m *Manager) checkTrustedHost(w http.ResponseWriter, r *http.Request) bool {
	if m.trustedHosts.Allowed(r.RemoteAddr) {
		return true
	}
	loglevel.Warnf("[ARBITER:DENY_UNTRUSTED] request from untrusted host: remote_addr=%s path=%s", r.RemoteAddr, r.URL.Path)
	http.Error(w, "source address not in trusted_hosts", http.StatusForbidden)
	return false
}

// AddRoutes registers the token API endpoints on the given mux.
func (m *Manager) AddRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/token/request", m.handleRequest)
	mux.HandleFunc("/api/v1/token/renew", m.handleRenew)
	mux.HandleFunc("/api/v1/token/status", m.handleStatus)
	m.startOnce.Do(func() { go m.cleanupLoop() })
	loglevel.Infof("[ARBITER:INIT] token endpoints registered")
}

func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		for scope, tok := range m.tokens {
			if now.After(tok.ExpiresAt) {
				delete(m.tokens, scope)
				m.dirty = true
				loglevel.Warnf("[ARBITER:EXPIRE] token expired: scope=%s owner=%s", scope, tok.Owner)
			}
		}
		cutoff := now.Unix() - nonceMaxAge
		for nonce, ts := range m.nonceCache {
			if ts < cutoff {
				delete(m.nonceCache, nonce)
			}
		}

		// Debounced persistence flush.
		var snapshot map[string]*Token
		if m.dirty {
			snapshot = make(map[string]*Token, len(m.tokens))
			for scope, tok := range m.tokens {
				snapshot[scope] = tok
			}
			m.dirty = false
		}
		m.mu.Unlock()

		if snapshot != nil {
			if err := saveTokens(m.dataDir, snapshot); err != nil {
				loglevel.Warnf("[ARBITER:WARN] persist tokens: %v", err)
			}
		}
	}
}

// handleRequest handles POST /api/v1/token/request — a worker asks to
// own a scope.
func (m *Manager) handleRequest(w http.ResponseWriter, r *http.Request) {
	if !m.checkTrustedHost(w, r) {
		return
	}
	if !timehealth.IsHealthyStrict(5 * time.Second) {
		http.Error(w, "arbiter time unhealthy", http.StatusServiceUnavailable)
		return
	}
	if !m.quorumFunc() {
		http.Error(w, "no quorum", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Scope       string `json:"scope"`
		NodeID      string `json:"node_id"`
		Incarnation uint64 `json:"incarnation"`
		Timestamp   int64  `json:"timestamp"`
		Nonce       string `json:"nonce"`
		HMAC        string `json:"hmac"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Verify HMAC.
	data := fmt.Sprintf("%s:%s:%d:%d:%s", req.Scope, req.NodeID, req.Incarnation, req.Timestamp, req.Nonce)
	if !m.verifyHMAC(data, req.HMAC) {
		http.Error(w, "HMAC invalid", http.StatusUnauthorized)
		return
	}

	// Timestamp window check.
	now := time.Now().Unix()
	if abs64(now-req.Timestamp) > timestampWindow {
		http.Error(w, "timestamp out of window", http.StatusBadRequest)
		return
	}

	// Nonce replay check.
	m.mu.Lock()
	if _, ok := m.nonceCache[req.Nonce]; ok {
		m.mu.Unlock()
		http.Error(w, "nonce reused", http.StatusBadRequest)
		return
	}
	m.nonceCache[req.Nonce] = now

	// Grant or deny.
	existing, occupied := m.tokens[req.Scope]
	if occupied && !existing.Expired() && existing.Owner != req.NodeID {
		m.mu.Unlock()
		loglevel.Warnf("[ARBITER:DENY] token request denied: scope=%s requester=%s held_by=%s",
			req.Scope, req.NodeID, existing.Owner)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"accepted": false,
			"reason":   "scope already owned by " + existing.Owner,
		})
		return
	}

	tok := &Token{
		Scope:       req.Scope,
		Owner:       req.NodeID,
		Incarnation: req.Incarnation,
		GrantedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(tokenTTL),
		Nonce:       randomHex(16),
	}
	tok.Signature = tok.Sign(m.psk)
	m.tokens[req.Scope] = tok
	m.dirty = true
	m.mu.Unlock()

	loglevel.Infof("[ARBITER:GRANT] token granted: scope=%s owner=%s", req.Scope, req.NodeID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"accepted": true,
		"token":    tok,
	})
}

// handleRenew handles POST /api/v1/token/renew — a worker extends its
// token.
func (m *Manager) handleRenew(w http.ResponseWriter, r *http.Request) {
	if !m.checkTrustedHost(w, r) {
		return
	}
	if !timehealth.IsHealthyStrict(5 * time.Second) {
		http.Error(w, "arbiter time unhealthy", http.StatusServiceUnavailable)
		return
	}
	if !m.quorumFunc() {
		http.Error(w, "no quorum", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Token     Token  `json:"token"`
		Nonce     string `json:"nonce"`
		Timestamp int64  `json:"timestamp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Verify the token's own cryptographic signature.
	if !req.Token.Verify(m.psk) {
		http.Error(w, "invalid token signature", http.StatusUnauthorized)
		return
	}

	now := time.Now().Unix()
	if abs64(now-req.Timestamp) > timestampWindow {
		http.Error(w, "timestamp out of window", http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	if _, ok := m.nonceCache[req.Nonce]; ok {
		m.mu.Unlock()
		http.Error(w, "nonce reused", http.StatusBadRequest)
		return
	}
	m.nonceCache[req.Nonce] = now

	existing, ok := m.tokens[req.Token.Scope]
	if !ok {
		if req.Token.Expired() {
			m.mu.Unlock()
			http.Error(w, "token not found or mismatched", http.StatusNotFound)
			return
		}
		cp := req.Token
		m.tokens[req.Token.Scope] = &cp
		existing = &cp
		loglevel.Infof("[ARBITER:REHEAL] accepted still-valid token with no prior memory: scope=%s owner=%s", req.Token.Scope, req.Token.Owner)
	} else if existing.Owner != req.Token.Owner || existing.Incarnation != req.Token.Incarnation {
		m.mu.Unlock()
		http.Error(w, "token not found or mismatched", http.StatusNotFound)
		return
	}

	// Extend the token.
	existing.ExpiresAt = time.Now().Add(tokenTTL)
	existing.Nonce = randomHex(16)
	existing.Signature = existing.Sign(m.psk)
	m.dirty = true
	m.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"accepted": true,
		"token":    existing,
	})
}

// handleStatus serves GET /api/v1/token/status — visibility into active
// tokens.
func (m *Manager) handleStatus(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]interface{})
	for scope, tok := range m.tokens {
		out[scope] = map[string]interface{}{
			"owner":      tok.Owner,
			"expires_at": tok.ExpiresAt,
			"expired":    tok.Expired(),
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (m *Manager) verifyHMAC(data, received string) bool {
	return psksign.Verify(m.psk, data, received)
}

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// randomHex returns n random bytes hex-encoded (2n characters).
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("[ARBITER] crypto/rand failed, refusing to issue a predictable nonce: %v", err)
	}
	return hex.EncodeToString(b)
}
