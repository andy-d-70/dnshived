// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dnshived/internal/webauth"
)

func TestVerifyWithCache_LocksOutAfterRepeatedFailures(t *testing.T) {
	resetVerifyCache(t)
	var calls int32
	verify := func(u, p string) (webauth.User, bool) {
		atomic.AddInt32(&calls, 1)
		return webauth.User{}, false
	}
	for i := 0; i < failThreshold; i++ {
		if _, res := verifyWithCache(verify, "admin", "guess-"+string(rune('a'+i)), "10.0.0.9"); res != verifyBad {
			t.Fatalf("attempt %d: res = %v, want verifyBad", i, res)
		}
	}
	if _, res := verifyWithCache(verify, "admin", "guess-next", "10.0.0.9"); res != verifyLimited {
		t.Fatalf("after %d failures: res = %v, want verifyLimited", failThreshold, res)
	}
	if calls != failThreshold {
		t.Errorf("hashed %d times, want %d (no hashing while locked out)", calls, failThreshold)
	}
	if _, res := verifyWithCache(verify, "admin", "guess-other", "10.0.0.10"); res != verifyBad {
		t.Errorf("another client was locked out too: res = %v", res)
	}
}

func TestVerifyWithCache_CachedLoginIgnoresLockout(t *testing.T) {
	resetVerifyCache(t)
	verify := func(u, p string) (webauth.User, bool) { return webauth.User{Name: u}, p == "right" }
	if _, res := verifyWithCache(verify, "admin", "right", "10.0.0.9"); res != verifyOK {
		t.Fatal("seed login failed")
	}
	for i := 0; i < failThreshold; i++ {
		verifyWithCache(verify, "admin", "wrong-"+string(rune('a'+i)), "10.0.0.9")
	}
	if _, res := verifyWithCache(verify, "admin", "right", "10.0.0.9"); res != verifyOK {
		t.Errorf("an already verified login was refused after its address got locked out: %v", res)
	}
}

func TestVerifyWithCache_ParallelIdenticalChecksHashOnce(t *testing.T) {
	resetVerifyCache(t)
	var calls int32
	verify := func(u, p string) (webauth.User, bool) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(100 * time.Millisecond)
		return webauth.User{Name: u}, true
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, res := verifyWithCache(verify, "admin", "pw", "10.0.0.9"); res != verifyOK {
				t.Errorf("res = %v", res)
			}
		}()
	}
	wg.Wait()
	if calls != 1 {
		t.Errorf("10 parallel identical logins hashed %d times, want 1", calls)
	}
}

func TestWatchUsersFile_ReloadsAndClearsCache(t *testing.T) {
	resetVerifyCache(t)
	path := filepath.Join(t.TempDir(), "users.json")
	store := &webauth.Store{}
	if err := store.Upsert("admin", "old-password", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(path); err != nil {
		t.Fatal(err)
	}
	if _, ok := vwc(store.Verify, "admin", "old-password"); !ok {
		t.Fatal("seed login failed")
	}
	watchUsersFile(store, path, nil)

	other := &webauth.Store{}
	other.Upsert("admin", "new-password", "admin")
	time.Sleep(1100 * time.Millisecond)
	if err := other.Save(path); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := vwc(store.Verify, "admin", "new-password"); ok {
			if _, still := vwc(store.Verify, "admin", "old-password"); still {
				t.Fatal("old password still accepted after the users file changed")
			}
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("users file change was not picked up within 6 s")
}
