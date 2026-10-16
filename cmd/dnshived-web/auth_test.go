// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"testing"
	"time"

	"dnshived/internal/webauth"
)

// resetVerifyCache clears package-level cache state between tests.
func resetVerifyCache(t *testing.T) {
	t.Helper()
	verifyCacheMu.Lock()
	verifyCache = make(map[string]verifyCacheEntry)
	verifyCacheMu.Unlock()
	loginLimiter = &failLimiter{clients: map[string]*failState{}}
	t.Cleanup(func() {
		loginLimiter = &failLimiter{clients: map[string]*failState{}}
		verifyCacheMu.Lock()
		verifyCache = make(map[string]verifyCacheEntry)
		verifyCacheMu.Unlock()
	})
}

func TestVerifyWithCache_ReusesResultForIdenticalCredentials(t *testing.T) {
	resetVerifyCache(t)
	calls := 0
	verify := func(username, password string) (webauth.User, bool) {
		calls++
		return webauth.User{Name: username, Role: "admin"}, true
	}

	for i := 0; i < 5; i++ {
		user, ok := vwc(verify, "admin", "secret")
		if !ok || user.Name != "admin" {
			t.Fatalf("call %d: verifyWithCache = (%+v, %v), want (admin user, true)", i, user, ok)
		}
	}
	if calls != 1 {
		t.Errorf("underlying verify called %d times, want 1 — repeated identical credentials should reuse the cached result", calls)
	}
}

func TestVerifyWithCache_DistinctCredentialsAlwaysVerify(t *testing.T) {
	resetVerifyCache(t)
	calls := 0
	verify := func(username, password string) (webauth.User, bool) {
		calls++
		return webauth.User{}, password == "correct"
	}

	passwords := []string{"wrong1", "wrong2", "wrong3", "correct"}
	for _, pw := range passwords {
		vwc(verify, "admin", pw)
	}
	if calls != len(passwords) {
		t.Errorf("underlying verify called %d times, want %d — each distinct credential must be independently verified", calls, len(passwords))
	}
}

// TestVerifyWithCache_CachesFailuresToo confirms a repeated WRONG password
// also gets cached.
func TestVerifyWithCache_CachesFailuresToo(t *testing.T) {
	resetVerifyCache(t)
	calls := 0
	verify := func(username, password string) (webauth.User, bool) {
		calls++
		return webauth.User{}, false
	}

	for i := 0; i < 3; i++ {
		if _, ok := vwc(verify, "admin", "wrong"); ok {
			t.Fatalf("call %d: expected verification to fail", i)
		}
	}
	if calls != 1 {
		t.Errorf("underlying verify called %d times, want 1 — repeated identical wrong credentials should also be cached", calls)
	}
}

// TestVerifyWithCache_ExpiredEntryReVerifies confirms an expired cache
// entry is not trusted — the cache must not extend a stale result
// forever.
func TestVerifyWithCache_ExpiredEntryReVerifies(t *testing.T) {
	resetVerifyCache(t)
	calls := 0
	verify := func(username, password string) (webauth.User, bool) {
		calls++
		return webauth.User{Name: username}, true
	}

	vwc(verify, "admin", "secret")
	if calls != 1 {
		t.Fatalf("setup: calls = %d, want 1", calls)
	}

	// Force the cached entry to look expired without a real sleep.
	verifyCacheMu.Lock()
	for k, e := range verifyCache {
		e.expires = time.Now().Add(-1 * time.Second)
		verifyCache[k] = e
	}
	verifyCacheMu.Unlock()

	vwc(verify, "admin", "secret")
	if calls != 2 {
		t.Errorf("underlying verify called %d times, want 2 — an expired entry must be re-verified, not trusted forever", calls)
	}
}

func TestVerifyWithCache_DifferentUsernamesAreIndependent(t *testing.T) {
	resetVerifyCache(t)
	calls := 0
	verify := func(username, password string) (webauth.User, bool) {
		calls++
		return webauth.User{Name: username}, true
	}

	vwc(verify, "admin", "secret")
	vwc(verify, "readonly", "secret")
	if calls != 2 {
		t.Errorf("underlying verify called %d times, want 2 — different usernames must not share a cache entry", calls)
	}
}

func TestVerifyWithCache_MaxEntriesGuardClearsCache(t *testing.T) {
	resetVerifyCache(t)
	verify := func(username, password string) (webauth.User, bool) {
		return webauth.User{}, false
	}

	verifyCacheMu.Lock()
	for i := 0; i < verifyCacheMaxEntries; i++ {
		verifyCache[verifyCacheKey("admin", string(rune(i)))] = verifyCacheEntry{expires: time.Now().Add(verifyCacheTTL)}
	}
	sizeBefore := len(verifyCache)
	verifyCacheMu.Unlock()
	if sizeBefore != verifyCacheMaxEntries {
		t.Fatalf("setup: cache size = %d, want %d", sizeBefore, verifyCacheMaxEntries)
	}

	vwc(verify, "admin", "one-more-distinct-guess")

	verifyCacheMu.Lock()
	sizeAfter := len(verifyCache)
	verifyCacheMu.Unlock()
	if sizeAfter >= verifyCacheMaxEntries {
		t.Errorf("cache size after hitting the cap = %d, want it cleared (well under %d)", sizeAfter, verifyCacheMaxEntries)
	}
}

// vwc is verifyWithCache from one fixed test client, as a bool.
func vwc(verify func(username, password string) (webauth.User, bool), username, password string) (webauth.User, bool) {
	user, res := verifyWithCache(verify, username, password, "test-client")
	return user, res == verifyOK
}
