// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"dnshived/internal/webauth"
)

// userContextKey is unexported so only this file sets/reads the
// authenticated user from a request's context.
type userContextKey struct{}

// A successful check stays cached until the users file changes
// (watchUsersFile clears the cache); a failed one only briefly.
const (
	verifyCacheTTL         = 12 * time.Hour
	verifyCacheNegativeTTL = 30 * time.Second
	verifyCacheMaxEntries  = 10000
)

type verifyCacheEntry struct {
	user    webauth.User
	ok      bool
	expires time.Time
}

var (
	verifyCacheMu sync.Mutex
	verifyCache   = make(map[string]verifyCacheEntry)
)

// verifyCacheKey hashes the credential pair with a fast, non-PBKDF2 hash
// purely so this cache's keys aren't plaintext passwords.
func verifyCacheKey(username, password string) string {
	sum := sha256.Sum256([]byte(username + "\x00" + password))
	return hex.EncodeToString(sum[:])
}

// verifyResult tells basicAuth why a check failed.
type verifyResult int

const (
	verifyOK verifyResult = iota
	verifyBad
	verifyLimited
)

var (
	verifyInflightMu sync.Mutex
	verifyInflight   = map[string]chan struct{}{}
	// pbkdf2Slots bounds concurrent password hashing (~0.65 s CPU each on
	// a small node).
	pbkdf2Slots = make(chan struct{}, 2)
)

const pbkdf2SlotWait = 10 * time.Second

func cachedVerify(key string, now time.Time) (verifyCacheEntry, bool) {
	verifyCacheMu.Lock()
	defer verifyCacheMu.Unlock()
	entry, found := verifyCache[key]
	return entry, found && now.Before(entry.expires)
}

// verifyWithCache answers from the cache when it can; otherwise one
// caller per (user, password) hashes while the others wait for its
// result, and uncached checks from a locked-out client are refused before
// any hashing.
func verifyWithCache(verify func(username, password string) (webauth.User, bool), username, password, client string) (webauth.User, verifyResult) {
	key := verifyCacheKey(username, password)
	for {
		if entry, ok := cachedVerify(key, time.Now()); ok {
			if entry.ok {
				return entry.user, verifyOK
			}
			return webauth.User{}, verifyBad
		}
		verifyInflightMu.Lock()
		wait, busy := verifyInflight[key]
		if !busy {
			verifyInflight[key] = make(chan struct{})
		}
		verifyInflightMu.Unlock()
		if !busy {
			break
		}
		<-wait
	}
	defer func() {
		verifyInflightMu.Lock()
		close(verifyInflight[key])
		delete(verifyInflight, key)
		verifyInflightMu.Unlock()
	}()

	if loginLimiter.blocked(client, time.Now()) {
		return webauth.User{}, verifyLimited
	}
	select {
	case pbkdf2Slots <- struct{}{}:
	case <-time.After(pbkdf2SlotWait):
		return webauth.User{}, verifyLimited
	}
	user, ok := verify(username, password)
	<-pbkdf2Slots

	now := time.Now()
	ttl := verifyCacheTTL
	if !ok {
		ttl = verifyCacheNegativeTTL
		loginLimiter.fail(client, now)
	}
	verifyCacheMu.Lock()
	if len(verifyCache) >= verifyCacheMaxEntries {
		for k, e := range verifyCache {
			if !e.ok || now.After(e.expires) {
				delete(verifyCache, k)
			}
		}
	}
	if ok || len(verifyCache) < verifyCacheMaxEntries {
		verifyCache[key] = verifyCacheEntry{user: user, ok: ok, expires: now.Add(ttl)}
	}
	verifyCacheMu.Unlock()
	if ok {
		return user, verifyOK
	}
	return webauth.User{}, verifyBad
}

// failLimiter locks a client out of password checks after repeated
// failures: 5 within 5 minutes, then 30 s doubling up to 15 minutes.
type failLimiter struct {
	mu      sync.Mutex
	clients map[string]*failState
}

type failState struct {
	failures []time.Time
	until    time.Time
	strikes  int
}

const (
	failWindow    = 5 * time.Minute
	failThreshold = 5
	failBaseBlock = 30 * time.Second
	failMaxBlock  = 15 * time.Minute
)

var loginLimiter = &failLimiter{clients: map[string]*failState{}}

func (l *failLimiter) blocked(client string, now time.Time) bool {
	return l.retryAfter(client, now) > 0
}

func (l *failLimiter) retryAfter(client string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if st := l.clients[client]; st != nil && now.Before(st.until) {
		return st.until.Sub(now)
	}
	return 0
}

func (l *failLimiter) fail(client string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.clients[client]
	if st == nil {
		st = &failState{}
		l.clients[client] = st
	}
	kept := st.failures[:0]
	for _, t := range st.failures {
		if now.Sub(t) < failWindow {
			kept = append(kept, t)
		}
	}
	st.failures = append(kept, now)
	if len(st.failures) < failThreshold {
		return
	}
	block := failMaxBlock
	if st.strikes < 6 {
		block = failBaseBlock << st.strikes
		if block > failMaxBlock {
			block = failMaxBlock
		}
	}
	st.strikes++
	st.until = now.Add(block)
	st.failures = st.failures[:0]
	log.Printf("[AUTH] %s locked out of password checks for %s after %d failed logins", client, block, failThreshold)
}

func (l *failLimiter) prune(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for c, st := range l.clients {
		idle := len(st.failures) == 0 || now.Sub(st.failures[len(st.failures)-1]) > failWindow
		if idle && now.Sub(st.until) > failMaxBlock {
			delete(l.clients, c)
		}
	}
}

func clientAddr(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

// watchUsersFile reloads the users file and clears the verify cache when
// the file changes (password change, -reset-user, removed user); onChange
// then runs, so a console change spreads to the other cores.
func watchUsersFile(store *webauth.Store, path string, onChange func()) {
	stamp := func() (time.Time, int64) {
		fi, err := os.Stat(path)
		if err != nil {
			return time.Time{}, -1
		}
		return fi.ModTime(), fi.Size()
	}
	mt, sz := stamp()
	go func() {
		for range time.Tick(2 * time.Second) {
			m, z := stamp()
			if m.Equal(mt) && z == sz {
				continue
			}
			mt, sz = m, z
			if err := store.ReplaceFrom(path); err != nil {
				log.Printf("[AUTH] users file changed but could not be reloaded: %v — keeping the previous users", err)
			} else {
				log.Printf("[AUTH] users file changed — reloaded, cached logins cleared")
				if onChange != nil {
					onChange()
				}
			}
			clearVerifyCache()
		}
	}()
}

// clearVerifyCache drops every cached credential-verification result.
func clearVerifyCache() {
	verifyCacheMu.Lock()
	verifyCache = make(map[string]verifyCacheEntry)
	verifyCacheMu.Unlock()
}

// startVerifyCacheCleanup periodically sweeps expired entries so the cache
// doesn't grow from normal (non-burst) traffic accumulating over time.
func startVerifyCacheCleanup() {
	go func() {
		ticker := time.NewTicker(verifyCacheNegativeTTL)
		for range ticker.C {
			now := time.Now()
			verifyCacheMu.Lock()
			for key, entry := range verifyCache {
				if now.After(entry.expires) {
					delete(verifyCache, key)
				}
			}
			verifyCacheMu.Unlock()
			loginLimiter.prune(now)
		}
	}()
}

// basicAuth wraps next with HTTP Basic authentication against store.
func basicAuth(store *webauth.Store, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			challenge(w)
			return
		}
		user, res := verifyWithCache(store.Verify, username, password, clientAddr(r))
		switch res {
		case verifyLimited:
			if wait := loginLimiter.retryAfter(clientAddr(r), time.Now()); wait > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
			}
			http.Error(w, "too many failed logins — try again later", http.StatusTooManyRequests)
			return
		case verifyBad:
			challenge(w)
			return
		}
		ctx := context.WithValue(r.Context(), userContextKey{}, user)
		next(w, r.WithContext(ctx))
	}
}

// requirePermission wraps next with authenticate AND a permission check.
func requirePermission(store *webauth.Store, perm webauth.Permission, next http.HandlerFunc) http.HandlerFunc {
	return authenticate(store, func(w http.ResponseWriter, r *http.Request) {
		user, _ := userFromContext(r)
		if !user.HasPermission(perm) {
			http.Error(w, "forbidden: missing required permission", http.StatusForbidden)
			return
		}
		rememberReturnPage(w, r)
		noteUIActivity()
		next(w, r)
	})
}

func requirePermissionOrToken(store *webauth.Store, perm webauth.Permission, ref *configRef, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		if tok, ok := bearerToken(r); ok {
			user, matched := matchAPIToken(cfg, tok)
			if !matched {
				http.Error(w, "invalid or unrecognized API token", http.StatusUnauthorized)
				return
			}
			if !user.HasPermission(perm) {
				http.Error(w, "forbidden: missing required permission", http.StatusForbidden)
				return
			}
			ctx := context.WithValue(r.Context(), userContextKey{}, user)
			next(w, r.WithContext(ctx))
			return
		}
		requirePermission(store, perm, next)(w, r)
	}
}

// bearerToken extracts the token from an `Authorization: Bearer <tok>`
// header.
func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(prefix) && h[:len(prefix)] == prefix {
		return h[len(prefix):], true
	}
	return "", false
}

// matchAPIToken checks tok against the live cluster's own api_tokens.
func matchAPIToken(cfg *WebConfig, tok string) (webauth.User, bool) {
	c, _, err := firstReachableConfig(nodesIncludingSelf(cfg))
	if err != nil {
		return webauth.User{}, false
	}
	for _, at := range c.APITokens {
		if subtle.ConstantTimeCompare([]byte(at.Token), []byte(tok)) != 1 || (at.Role != "readonly" && at.Role != "admin") {
			continue
		}
		if at.Expires != "" {
			exp, err := time.Parse(time.RFC3339, at.Expires)
			if err != nil || time.Now().After(exp) {
				continue
			}
		}
		return webauth.User{Name: at.Name, Role: at.Role}, true
	}
	return webauth.User{}, false
}

func userFromContext(r *http.Request) (webauth.User, bool) {
	u, ok := r.Context().Value(userContextKey{}).(webauth.User)
	return u, ok
}

func challenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="dnshived-web"`)
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte("authentication required\n"))
}
