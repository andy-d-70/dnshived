// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"dnshived/internal/auth"
	"dnshived/internal/config"
)

const (
	oldAdminTok = "old-admin-token-0123456789abcdef0123456789"
	newAdminTok = "N3w-admin-token-Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1"
	roTok       = "readonly-token-0123456789abcdef0123456789"
)

// fakeHelper answers the write-config verb and keeps what it was asked to write.
func fakeHelper(t *testing.T) (sock string, written func() []byte) {
	t.Helper()
	sock = filepath.Join(t.TempDir(), "h.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []byte
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			var req struct {
				Command string `json:"command"`
				Content []byte `json:"content"`
			}
			_ = json.NewDecoder(c).Decode(&req)
			mu.Lock()
			got = req.Content
			mu.Unlock()
			_ = json.NewEncoder(c).Encode(map[string]bool{"ok": true})
			c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return sock, func() []byte { mu.Lock(); defer mu.Unlock(); return got }
}

func rotateSetup(t *testing.T) (http.Handler, *auth.Middleware, func() []byte) {
	t.Helper()
	sock, written := fakeHelper(t)
	toks := []config.APIToken{
		{Name: "probe-admin", Token: oldAdminTok, Role: "admin"},
		{Name: "monitoring", Token: roTok, Role: "readonly"},
	}
	cfgPath := filepath.Join(t.TempDir(), "probe.json")
	raw, _ := json.Marshal(ProbeConfig{ListenAddr: "0.0.0.0:9444", TrunkParent: "ens19", ClusterToken: "c", APITokens: toks})
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &ProbeConfig{ProbeHelperSocket: sock, APITokens: toks}
	mw := auth.New(toks)
	h := mw.Wrap(mw.RequireAdmin(rotateTokenHandler(cfg, cfgPath, mw)))
	return h, mw, written
}

func rotateReq(tok, newTok string, overTLS bool) *http.Request {
	body, _ := json.Marshal(map[string]string{"new_token": newTok})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/rotate-token", strings.NewReader(string(body)))
	r.Header.Set("Authorization", "Bearer "+tok)
	if overTLS {
		r.TLS = &tls.ConnectionState{}
	}
	return r
}

func TestRotateToken_ReplacesTheTokenThatMadeTheCallAndOnlyOverTLS(t *testing.T) {
	h, mw, written := rotateSetup(t)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, rotateReq(oldAdminTok, newAdminTok, false))
	if rec.Code != http.StatusBadRequest || written() != nil {
		t.Fatalf("plain HTTP: status %d written %v, want 400 and nothing written: the new token must not cross an unencrypted connection", rec.Code, written() != nil)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, rotateReq(oldAdminTok, newAdminTok, true))
	if rec.Code != http.StatusOK {
		t.Fatalf("over TLS: status %d: %s", rec.Code, rec.Body.String())
	}
	var saved ProbeConfig
	if err := json.Unmarshal(written(), &saved); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tk := range saved.APITokens {
		names = append(names, tk.Name+"="+tk.Token)
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "probe-admin="+newAdminTok) || strings.Contains(joined, oldAdminTok) || !strings.Contains(joined, "monitoring="+roTok) {
		t.Errorf("written tokens %s, want only the admin token replaced", joined)
	}

	check := func(tok string) int {
		rr := httptest.NewRecorder()
		mw.Wrap(http.HandlerFunc(handlerOKProbe)).ServeHTTP(rr, func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/x", nil)
			r.Header.Set("Authorization", "Bearer "+tok)
			return r
		}())
		return rr.Code
	}
	if check(oldAdminTok) == http.StatusOK {
		t.Error("the old token must stop working at once, it may have been seen in cleartext")
	}
	if check(newAdminTok) != http.StatusOK || check(roTok) != http.StatusOK {
		t.Error("the new admin token and the untouched readonly token must work")
	}
	live := liveTokens.Load()
	if live == nil || len(*live) != 2 {
		t.Fatalf("live tokens %v, want the rotated set (tls-info must sign with the new token)", live)
	}
}

func handlerOKProbe(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }

func TestRotateToken_RefusesWeakTokensAndNonAdminCallers(t *testing.T) {
	h, _, written := rotateSetup(t)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, rotateReq(oldAdminTok, "short", true))
	if rec.Code != http.StatusBadRequest || written() != nil {
		t.Errorf("weak token: status %d written %v, want 400 and nothing written", rec.Code, written() != nil)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, rotateReq(roTok, newAdminTok, true))
	if rec.Code == http.StatusOK || written() != nil {
		t.Errorf("readonly caller: status %d written %v, want it refused", rec.Code, written() != nil)
	}
}
