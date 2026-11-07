// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"dnshived/internal/webauth"
)

// junkBlob has a valid header with the given key-derivation count and a body that never
// authenticates, so Decrypt fails with the wrong-password error after a cheap derivation.
func junkBlob(iterations uint32) []byte {
	blob := []byte{1, byte(iterations >> 24), byte(iterations >> 16), byte(iterations >> 8), byte(iterations)}
	return append(blob, make([]byte, 16+12+32)...)
}

func freshRestoreLimiter(t *testing.T) {
	t.Helper()
	reset := func() {
		restoreLimiter = &failLimiter{clients: map[string]*failState{}, what: "restore attempts"}
	}
	reset()
	t.Cleanup(reset)
}

func restoreAttempt(t *testing.T, blob []byte, user, client string) *httptest.ResponseRecorder {
	t.Helper()
	r, err := buildMultipartBackupUpload(t, "backup-20260101-000000.enc", "any-password", blob)
	if err != nil {
		t.Fatal(err)
	}
	r.RemoteAddr = client + ":5555"
	r = withAuthedUser(r, webauth.User{Name: user, Role: webauth.RoleAdmin})
	w := httptest.NewRecorder()
	handleBackupRestorePost(newConfigRef(&WebConfig{}))(w, r)
	return w
}

func TestHandleBackupRestorePost_FiveWrongPasswordsLockBeforeAnyDecrypt(t *testing.T) {
	freshRestoreLimiter(t)
	for i := 0; i < failThreshold; i++ {
		w := restoreAttempt(t, junkBlob(1000), "ops", "192.0.2.10")
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "wrong password") {
			t.Fatalf("attempt %d: %d %s", i+1, w.Code, w.Body.String())
		}
	}

	w := restoreAttempt(t, junkBlob(1000), "ops", "192.0.2.10")
	if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), restoreLockedText) {
		t.Fatalf("sixth attempt not locked: %d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("locked answer has no Retry-After")
	}

	r := httptest.NewRequest(http.MethodPost, "/backup/restore", strings.NewReader("not a multipart body"))
	r.Header.Set("Content-Type", "multipart/form-data; boundary=x")
	r.RemoteAddr = "192.0.2.10:5555"
	r = withAuthedUser(r, webauth.User{Name: "ops", Role: webauth.RoleAdmin})
	bad := httptest.NewRecorder()
	handleBackupRestorePost(newConfigRef(&WebConfig{}))(bad, r)
	if bad.Code != http.StatusTooManyRequests {
		t.Errorf("the lock is checked after the form is parsed: %d", bad.Code)
	}
}

func TestHandleBackupRestorePost_OnlyAWrongPasswordCounts(t *testing.T) {
	freshRestoreLimiter(t)
	tests := []struct {
		name string
		blob []byte
	}{
		{"blob too short", []byte{1, 2}},
		{"key derivation count above the cap", junkBlob(4_000_000_000)},
		{"key derivation count of zero", junkBlob(0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < failThreshold+1; i++ {
				w := restoreAttempt(t, tt.blob, "ops", "192.0.2.11")
				if w.Code != http.StatusOK {
					t.Fatalf("attempt %d counted as a failed password: %d", i+1, w.Code)
				}
			}
		})
	}
	w := restoreAttempt(t, junkBlob(1000), "ops", "192.0.2.11")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "wrong password") {
		t.Errorf("a real wrong password was not processed: %d %s", w.Code, w.Body.String())
	}
}

func TestHandleBackupRestorePost_LockIsPerUserAndClient(t *testing.T) {
	freshRestoreLimiter(t)
	for i := 0; i < failThreshold; i++ {
		restoreAttempt(t, junkBlob(1000), "ops", "192.0.2.12")
	}
	tests := []struct {
		name       string
		user       string
		client     string
		wantLocked bool
	}{
		{"same user, same client", "ops", "192.0.2.12", true},
		{"same user, other client", "ops", "192.0.2.99", false},
		{"other user, same client", "admin2", "192.0.2.12", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := restoreAttempt(t, junkBlob(1000), tt.user, tt.client)
			if locked := w.Code == http.StatusTooManyRequests; locked != tt.wantLocked {
				t.Errorf("locked = %v, want %v (%d)", locked, tt.wantLocked, w.Code)
			}
		})
	}
}

func TestHandleBackupRestorePost_ParallelGuessesStopAtFive(t *testing.T) {
	freshRestoreLimiter(t)
	const burst = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	decrypted, locked := 0, 0
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := restoreAttempt(t, junkBlob(1000), "ops", "192.0.2.13")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case w.Code == http.StatusTooManyRequests:
				locked++
			case strings.Contains(w.Body.String(), "wrong password"):
				decrypted++
			}
		}()
	}
	wg.Wait()
	if decrypted != failThreshold || locked != burst-failThreshold {
		t.Errorf("decrypted %d, locked %d; want %d and %d", decrypted, locked, failThreshold, burst-failThreshold)
	}
}

func TestHandleBackupRestorePost_WaitsForTheSlotWithoutTimingOut(t *testing.T) {
	freshRestoreLimiter(t)
	restoreSlot <- struct{}{}
	released := false
	release := func() {
		if !released {
			released = true
			<-restoreSlot
		}
	}
	defer release()

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- restoreAttempt(t, junkBlob(1000), "ops", "192.0.2.14") }()
	select {
	case <-done:
		t.Fatal("finished while another restore held the slot")
	case <-time.After(500 * time.Millisecond):
	}
	release()
	select {
	case w := <-done:
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "wrong password") {
			t.Errorf("waiting restore did not run normally: %d %s", w.Code, w.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting restore never resumed")
	}
}

func TestHandleBackupRestorePost_WaitEndsWhenTheClientLeaves(t *testing.T) {
	freshRestoreLimiter(t)
	restoreSlot <- struct{}{}
	defer func() { <-restoreSlot }()

	r, err := buildMultipartBackupUpload(t, "backup-20260101-000000.enc", "any-password", junkBlob(1000))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(r.Context())
	r = withAuthedUser(r.WithContext(ctx), webauth.User{Name: "ops", Role: webauth.RoleAdmin})
	w := httptest.NewRecorder()
	finished := make(chan struct{})
	go func() {
		handleBackupRestorePost(newConfigRef(&WebConfig{}))(w, r)
		close(finished)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler kept waiting after the client left")
	}
	if w.Body.Len() != 0 {
		t.Errorf("a response was written to a client that had left: %s", w.Body.String())
	}
}
