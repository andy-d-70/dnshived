// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package auth provides HTTP middleware for API token authentication.
package auth

import (
	"context"
	"log"
	"net/http"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"dnshived/internal/config"
)

// tokenContextKey is unexported so only this package can set/read the
// resolved token from a request's context — callers use
// TokenFromContext.
type tokenContextKey struct{}

// exemptPaths are never subject to Bearer-token auth, regardless of
// whether api_tokens is configured.
var exemptPaths = map[string]bool{
	"/api/v1/ping":               true,
	"/api/v1/coord/config/relay": true,
	"/api/v1/token/request":      true,
	"/api/v1/token/renew":        true,
	// Peer-to-peer lease sync, gated by trusted_hosts in internal/leasesync.
	"/api/v1/leasesync":             true,
	"/api/v1/leasesync/fingerprint": true,
	"/api/v1/leasesync/snapshot":    true,
}

// resolvedToken pairs a config.APIToken with its expiry pre-parsed once at
// New() time, rather than re-parsing the same RFC3339 string on every
// single request.
type resolvedToken struct {
	config.APIToken
	hasExpiry      bool
	expiredAtParse bool
	expiresAt      time.Time
}

// Middleware wraps an http.Handler with bearer token authentication.
type Middleware struct {
	tokens atomic.Pointer[map[string]resolvedToken]
}

// New creates auth middleware from the configured API tokens.
func New(tokens []config.APIToken) *Middleware {
	m := &Middleware{}
	m.SetTokens(tokens)
	return m
}

// SetTokens atomically replaces the live token set.
func (m *Middleware) SetTokens(tokens []config.APIToken) {
	resolved := make(map[string]resolvedToken, len(tokens))
	for _, t := range tokens {
		rt := resolvedToken{APIToken: t}
		if t.Expires != "" {
			exp, err := time.Parse(time.RFC3339, t.Expires)
			switch {
			case err != nil:
				log.Printf("[AUTH:WARN] token %q (role %s) has an invalid expires value %q — treating as already expired, not as never-expiring", t.Name, t.Role, t.Expires)
				rt.expiredAtParse = true
			default:
				rt.hasExpiry = true
				rt.expiresAt = exp
			}
		}
		resolved[t.Token] = rt
	}
	m.tokens.Store(&resolved)
}

// Enabled returns true if authentication is configured.
func (m *Middleware) Enabled() bool {
	toks := m.tokens.Load()
	return toks != nil && len(*toks) > 0
}

// Wrap returns an http.Handler that checks for a valid bearer token.
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.Enabled() {
			next.ServeHTTP(w, r) // no tokens configured — pass through
			return
		}
		if exemptPaths[path.Clean(r.URL.Path)] {
			next.ServeHTTP(w, r)
			return
		}

		bearer := extractBearer(r)
		if bearer == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"authentication required"}`))
			return
		}

		tok, valid := (*m.tokens.Load())[bearer]
		if !valid {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"invalid token"}`))
			return
		}

		// Check expiry — pre-parsed once in New(), not re-parsed on every
		// request.
		if tok.expiredAtParse || (tok.hasExpiry && time.Now().After(tok.expiresAt)) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"token expired"}`))
			return
		}

		ctx := context.WithValue(r.Context(), tokenContextKey{}, tok.APIToken)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// TokenFromContext returns the token that authenticated the current
// request, if Wrap resolved one.
func TokenFromContext(r *http.Request) (config.APIToken, bool) {
	tok, ok := r.Context().Value(tokenContextKey{}).(config.APIToken)
	return tok, ok
}

// RequireAdmin wraps a handler that must only be reachable by an
// "admin"-role token.
func (m *Middleware) RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !m.Enabled() {
			next(w, r)
			return
		}
		tok, ok := TokenFromContext(r)
		if !ok || tok.Role != "admin" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"admin role required"}`))
			return
		}
		next(w, r)
	}
}

// RequireProbeOrReadonly wraps a handler reachable by either a "probe"- or
// "readonly"-role token.
func (m *Middleware) RequireProbeOrReadonly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !m.Enabled() {
			next(w, r)
			return
		}
		tok, ok := TokenFromContext(r)
		if !ok || (tok.Role != "probe" && tok.Role != "readonly") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"probe or readonly role required"}`))
			return
		}
		next(w, r)
	}
}

func extractBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return h[7:]
	}
	return ""
}
