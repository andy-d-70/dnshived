// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package arbiter

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func signRequest(psk []byte, scope, nodeID string, incarnation uint64, ts int64, nonce string) string {
	data := fmt.Sprintf("%s:%s:%d:%d:%s", scope, nodeID, incarnation, ts, nonce)
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

func newSignedRequestBody(psk []byte, scope, nodeID string) []byte {
	ts := time.Now().Unix()
	nonce := "test-nonce-" + scope + "-" + nodeID
	body, _ := json.Marshal(map[string]interface{}{
		"scope": scope, "node_id": nodeID, "incarnation": 1,
		"timestamp": ts, "nonce": nonce,
		"hmac": signRequest(psk, scope, nodeID, 1, ts, nonce),
	})
	return body
}

func TestUntrustedHostDeniedDespiteValidHMAC(t *testing.T) {
	psk := []byte("test-psk")
	m := New(psk, func() bool { return true }, t.TempDir())
	m.SetTrustedHosts([]string{"192.0.2.22", "192.0.2.23", "192.0.2.24"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/token/request",
		bytes.NewReader(newSignedRequestBody(psk, "rw-100", "rogue-node")))
	req.RemoteAddr = "192.0.2.43:55555" // not in trusted_hosts
	w := httptest.NewRecorder()

	m.handleRequest(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for untrusted host, got %d: %s", w.Code, w.Body.String())
	}
	if _, occupied := m.tokens["rw-100"]; occupied {
		t.Fatal("untrusted request must never actually grant a token")
	}
}

// TestTrustedHostStillGrantedWithValidHMAC confirms the allowlist doesn't
// break the legitimate path when it's actually configured.
func TestTrustedHostStillGrantedWithValidHMAC(t *testing.T) {
	psk := []byte("test-psk")
	m := New(psk, func() bool { return true }, t.TempDir())
	m.ResumeGrants()
	m.SetTrustedHosts([]string{"192.0.2.22"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/token/request",
		bytes.NewReader(newSignedRequestBody(psk, "rw-100", "core-1")))
	req.RemoteAddr = "192.0.2.22:55555"
	w := httptest.NewRecorder()

	m.handleRequest(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for trusted host, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Accepted bool `json:"accepted"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Accepted {
		t.Fatal("expected grant to be accepted for a trusted host")
	}
}

// TestEmptyTrustedHostsFailsOpen confirms an upgraded-but-not-yet-
// reconfigured cluster (no trusted_hosts set) keeps today's exact
// behavior.
func TestEmptyTrustedHostsFailsOpen(t *testing.T) {
	psk := []byte("test-psk")
	m := New(psk, func() bool { return true }, t.TempDir())
	m.ResumeGrants()
	// No SetTrustedHosts call at all — zero value.

	req := httptest.NewRequest(http.MethodPost, "/api/v1/token/request",
		bytes.NewReader(newSignedRequestBody(psk, "rw-100", "any-node")))
	req.RemoteAddr = "203.0.113.99:55555" // arbitrary, unconfigured
	w := httptest.NewRecorder()

	m.handleRequest(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected fail-open 200 with no trusted_hosts configured, got %d: %s", w.Code, w.Body.String())
	}
}

// TestUntrustedHostDeniedOnRenewToo covers handleRenew, not just
// handleRequest.
func TestUntrustedHostDeniedOnRenewToo(t *testing.T) {
	psk := []byte("test-psk")
	m := New(psk, func() bool { return true }, t.TempDir())
	m.SetTrustedHosts([]string{"192.0.2.22"})

	// Seed a token directly (bypassing handleRequest) so renew has
	// something to act on.
	tok := &Token{
		Scope: "rw-100", Owner: "rogue-node", Incarnation: 1,
		GrantedAt: time.Now(), ExpiresAt: time.Now().Add(15 * time.Second),
		Nonce: "seed-nonce",
	}
	tok.Signature = tok.Sign(psk)
	m.tokens["rw-100"] = tok

	body, _ := json.Marshal(map[string]interface{}{
		"token": tok, "timestamp": time.Now().Unix(), "nonce": "renew-nonce",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/token/renew", bytes.NewReader(body))
	req.RemoteAddr = "192.0.2.43:55555" // not trusted
	w := httptest.NewRecorder()

	m.handleRenew(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for untrusted renew, got %d: %s", w.Code, w.Body.String())
	}
}

// renewRequest builds a signed handleRenew request body for tok.
func renewRequest(tok *Token) *http.Request {
	body, _ := json.Marshal(map[string]interface{}{
		"token": tok, "timestamp": time.Now().Unix(), "nonce": "renew-nonce-" + tok.Nonce,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/token/renew", bytes.NewReader(body))
	req.RemoteAddr = "192.0.2.22:55555"
	return req
}

// TestLoadTokens_MissingFileReturnsEmptyMap mirrors loadKnownScopes' own
// tolerance: a fresh install must never fail startup.
func TestLoadTokens_MissingFileReturnsEmptyMap(t *testing.T) {
	got := loadTokens(t.TempDir())
	if got == nil {
		t.Fatal("loadTokens returned nil, want a non-nil empty map")
	}
	if len(got) != 0 {
		t.Errorf("loadTokens = %v, want empty for a missing file", got)
	}
}

func TestLoadTokens_CorruptFileReturnsEmptyMap(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(tokensPath(dir), []byte("not json"), 0o640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got := loadTokens(dir)
	if len(got) != 0 {
		t.Errorf("loadTokens = %v, want empty for a corrupt file", got)
	}
}

// TestLoadTokens_FiltersExpiredEntries confirms an already-expired
// persisted token is never loaded back into memory.
func TestLoadTokens_FiltersExpiredEntries(t *testing.T) {
	dir := t.TempDir()
	psk := []byte("test-psk")
	expired := &Token{
		Scope: "rw-100", Owner: "core-1", Incarnation: 1,
		GrantedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(-time.Second),
	}
	expired.Signature = expired.Sign(psk)
	if err := saveTokens(dir, map[string]*Token{"rw-100": expired}); err != nil {
		t.Fatalf("saveTokens: %v", err)
	}
	got := loadTokens(dir)
	if len(got) != 0 {
		t.Errorf("loadTokens = %v, want empty — the only persisted entry was already expired", got)
	}
}

func TestTokenPersistence_SurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	psk := []byte("test-psk")

	m1 := New(psk, func() bool { return true }, dir)
	m1.ResumeGrants()
	m1.SetTrustedHosts([]string{"192.0.2.22"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/token/request",
		bytes.NewReader(newSignedRequestBody(psk, "rw-100", "core-2")))
	req.RemoteAddr = "192.0.2.22:55555"
	w := httptest.NewRecorder()
	m1.handleRequest(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("grant failed: %d: %s", w.Code, w.Body.String())
	}

	m1.mu.Lock()
	snapshot := make(map[string]*Token, len(m1.tokens))
	for k, v := range m1.tokens {
		snapshot[k] = v
	}
	m1.mu.Unlock()
	if err := saveTokens(dir, snapshot); err != nil {
		t.Fatalf("saveTokens: %v", err)
	}

	m2 := New(psk, func() bool { return true }, dir)
	if _, ok := m2.tokens["rw-100"]; !ok {
		t.Fatal("a fresh Manager built against the same dataDir has no memory of the prior grant — persistence did not survive the simulated restart")
	}

	m2.SetTrustedHosts([]string{"192.0.2.22"})
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/token/request",
		bytes.NewReader(newSignedRequestBody(psk, "rw-100", "core-1")))
	req2.RemoteAddr = "192.0.2.22:55555"
	w2 := httptest.NewRecorder()
	m2.handleRequest(w2, req2)
	var resp struct {
		Accepted bool `json:"accepted"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Accepted {
		t.Fatal("a restarted arbiter granted a CONFLICTING token to a different node for a scope it should still remember worker-b holds — this is the exact dual-active mechanism from the live incident")
	}
}

func TestHandleRenew_SelfHealsFromValidSignedTokenAfterRestart(t *testing.T) {
	psk := []byte("test-psk")
	m := New(psk, func() bool { return true }, t.TempDir())
	m.SetTrustedHosts([]string{"192.0.2.22"})

	tok := &Token{
		Scope: "rw-100", Owner: "core-2", Incarnation: 3,
		GrantedAt: time.Now().Add(-5 * time.Second), ExpiresAt: time.Now().Add(10 * time.Second),
		Nonce: "pre-restart-nonce",
	}
	tok.Signature = tok.Sign(psk)
	if _, ok := m.tokens["rw-100"]; ok {
		t.Fatal("precondition failed: token should not be pre-seeded")
	}

	w := httptest.NewRecorder()
	m.handleRenew(w, renewRequest(tok))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (self-healed renewal), got %d: %s", w.Code, w.Body.String())
	}
	m.mu.Lock()
	_, known := m.tokens["rw-100"]
	m.mu.Unlock()
	if !known {
		t.Error("renewal succeeded but did not re-seed m.tokens — a subsequent conflicting grant would not be denied")
	}
}

// TestHandleRenew_RejectsExpiredTokenEvenWithValidSignature confirms the
// self-heal path above is not a blanket bypass.
func TestHandleRenew_RejectsExpiredTokenEvenWithValidSignature(t *testing.T) {
	psk := []byte("test-psk")
	m := New(psk, func() bool { return true }, t.TempDir())
	m.SetTrustedHosts([]string{"192.0.2.22"})

	tok := &Token{
		Scope: "rw-100", Owner: "core-2", Incarnation: 1,
		GrantedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(-time.Second),
		Nonce: "expired-nonce",
	}
	tok.Signature = tok.Sign(psk)

	w := httptest.NewRecorder()
	m.handleRenew(w, renewRequest(tok))

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for an expired token even with a valid signature, got %d: %s", w.Code, w.Body.String())
	}
}

func requestGrant(t *testing.T, m *Manager, psk []byte, scope, nodeID string) bool {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/token/request",
		bytes.NewReader(newSignedRequestBody(psk, scope, nodeID)))
	w := httptest.NewRecorder()
	m.handleRequest(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("request %s/%s: status %d: %s", scope, nodeID, w.Code, w.Body.String())
	}
	var resp struct {
		Accepted bool `json:"accepted"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp.Accepted
}

func TestHandleRequest_PausedAfterStart(t *testing.T) {
	psk := []byte("test-psk")
	m := New(psk, func() bool { return true }, t.TempDir())

	if requestGrant(t, m, psk, "rw-100", "core-1") {
		t.Fatal("a just-started arbiter granted a new token; it may have forgotten a still-valid grant for this scope")
	}
	if _, ok := m.tokens["rw-100"]; ok {
		t.Fatal("a deferred request must not store a token")
	}
}

func TestHandleRequest_PauseAllowsCurrentOwner(t *testing.T) {
	psk := []byte("test-psk")
	m := New(psk, func() bool { return true }, t.TempDir())
	m.tokens["rw-100"] = &Token{Scope: "rw-100", Owner: "core-2", Incarnation: 1, ExpiresAt: time.Now().Add(tokenTTL)}

	if !requestGrant(t, m, psk, "rw-100", "core-2") {
		t.Fatal("the remembered owner of a still-valid token was refused during the pause")
	}
	if requestGrant(t, m, psk, "rw-100", "core-1") {
		t.Fatal("a different node was granted a scope with a valid owner")
	}
}

func TestHandleRequest_GrantsAfterPause(t *testing.T) {
	psk := []byte("test-psk")
	m := New(psk, func() bool { return true }, t.TempDir())
	m.grantsPausedUntil = time.Now().Add(-time.Second)

	if !requestGrant(t, m, psk, "rw-100", "core-1") {
		t.Fatal("grant refused after the pause ended")
	}
}
