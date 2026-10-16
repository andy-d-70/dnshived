// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dnshived/internal/webauth"
)

func newTestStore(t *testing.T, name, password, role string) (*webauth.Store, string) {
	t.Helper()
	store := &webauth.Store{}
	if err := store.Upsert(name, password, role); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	path := filepath.Join(t.TempDir(), "webui-users.json")
	if err := store.Save(path); err != nil {
		t.Fatalf("save seed store: %v", err)
	}
	return store, path
}

// testRepl is an authSync with a fixed name, so tests never ask a local
// core who they are.
func testRepl(store *webauth.Store, cfg *WebConfig) *authSync {
	a := newAuthSync(store, newConfigRef(cfg))
	a.self = "test"
	return a
}

func withAuthedUser(r *http.Request, u webauth.User) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), userContextKey{}, u))
}

func TestChangePasswordFormHandler_WrongCurrentPasswordRejected(t *testing.T) {
	store, usersFile := newTestStore(t, "admin", "correct-horse", "admin")
	cfg := &WebConfig{UsersFile: usersFile}

	form := url.Values{"current_password": {"wrong"}, "new_password": {"new-pass-1234"}, "confirm_password": {"new-pass-1234"}}
	req := httptest.NewRequest(http.MethodPost, "/password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withAuthedUser(req, webauth.User{Name: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	changePasswordFormHandler(newConfigRef(cfg), store, testRepl(store, cfg))(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if _, ok := store.Verify("admin", "new-pass-1234"); ok {
		t.Error("password was changed despite a wrong current-password check")
	}
	if _, ok := store.Verify("admin", "correct-horse"); !ok {
		t.Error("original password no longer verifies — should be untouched")
	}
}

func TestChangePasswordFormHandler_MismatchedConfirmationRejected(t *testing.T) {
	store, usersFile := newTestStore(t, "admin", "correct-horse", "admin")
	cfg := &WebConfig{UsersFile: usersFile}

	form := url.Values{"current_password": {"correct-horse"}, "new_password": {"new-pass-1234"}, "confirm_password": {"different"}}
	req := httptest.NewRequest(http.MethodPost, "/password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withAuthedUser(req, webauth.User{Name: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	changePasswordFormHandler(newConfigRef(cfg), store, testRepl(store, cfg))(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if _, ok := store.Verify("admin", "new-pass-1234"); ok {
		t.Error("password was changed despite mismatched confirmation")
	}
}

// TestChangePasswordFormHandler_SuccessTakesEffectImmediately confirms the
// handler mutates the SAME *webauth.Store pointer basicAuth already
// closures over.
func TestChangePasswordFormHandler_SuccessTakesEffectImmediately(t *testing.T) {
	store, usersFile := newTestStore(t, "admin", "correct-horse", "admin")
	cfg := &WebConfig{UsersFile: usersFile}

	form := url.Values{"current_password": {"correct-horse"}, "new_password": {"new-pass-1234"}, "confirm_password": {"new-pass-1234"}}
	req := httptest.NewRequest(http.MethodPost, "/password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withAuthedUser(req, webauth.User{Name: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	changePasswordFormHandler(newConfigRef(cfg), store, testRepl(store, cfg))(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	if _, ok := store.Verify("admin", "correct-horse"); ok {
		t.Error("old password still verifies after a successful change")
	}
	if u, ok := store.Verify("admin", "new-pass-1234"); !ok || u.Role != "admin" {
		t.Errorf("new password does not verify (or role changed): user=%+v ok=%v", u, ok)
	}

	reloaded, err := webauth.Load(usersFile)
	if err != nil {
		t.Fatalf("reload saved file: %v", err)
	}
	if _, ok := reloaded.Verify("admin", "new-pass-1234"); !ok {
		t.Error("new password was not persisted to disk")
	}
}

func TestChangePasswordFormHandler_ClearsVerifyCache(t *testing.T) {
	store, usersFile := newTestStore(t, "admin", "correct-horse", "admin")
	cfg := &WebConfig{UsersFile: usersFile}

	if _, ok := vwc(store.Verify, "admin", "correct-horse"); !ok {
		t.Fatal("seed: old credentials should verify and populate the cache")
	}

	form := url.Values{"current_password": {"correct-horse"}, "new_password": {"new-pass-1234"}, "confirm_password": {"new-pass-1234"}}
	req := httptest.NewRequest(http.MethodPost, "/password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withAuthedUser(req, webauth.User{Name: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	changePasswordFormHandler(newConfigRef(cfg), store, testRepl(store, cfg))(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	if _, ok := vwc(store.Verify, "admin", "correct-horse"); ok {
		t.Error("old credentials still verify through the cache after a password change — cache was not cleared")
	}
}

func TestApplyPasswordChangeHandler_RequiresSharedToken(t *testing.T) {
	store, usersFile := newTestStore(t, "admin", "correct-horse", "admin")
	cfg := &WebConfig{
		UsersFile: usersFile,
		Nodes:     []NodeConfig{{Name: "core-1", Addr: "10.0.0.1:9443", AdminToken: "shared-secret"}},
	}

	req := httptest.NewRequest(http.MethodPost, "/internal/password/change", strings.NewReader(`{"name":"admin","password_hash":"x:1:y","role":"admin"}`))
	w := httptest.NewRecorder()
	applyPasswordChangeHandler(newConfigRef(cfg), testRepl(store, cfg))(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", w.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/internal/password/change", strings.NewReader(`{"name":"admin","password_hash":"x:1:y","role":"admin"}`))
	req2.Header.Set("Authorization", "Bearer wrong-token")
	w2 := httptest.NewRecorder()
	applyPasswordChangeHandler(newConfigRef(cfg), testRepl(store, cfg))(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: status = %d, want 401", w2.Code)
	}
}

func TestApplyPasswordChangeHandler_AppliesHashDirectly(t *testing.T) {
	store, usersFile := newTestStore(t, "admin", "correct-horse", "admin")
	cfg := &WebConfig{
		UsersFile: usersFile,
		Nodes:     []NodeConfig{{Name: "core-1", Addr: "10.0.0.1:9443", AdminToken: "shared-secret"}},
	}

	newHash, err := webauth.HashPassword("new-pass-1234")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/internal/password/change",
		strings.NewReader(`{"name":"admin","password_hash":"`+newHash+`","role":"admin"}`))
	req.Header.Set("Authorization", "Bearer shared-secret")
	w := httptest.NewRecorder()
	applyPasswordChangeHandler(newConfigRef(cfg), testRepl(store, cfg))(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	if _, ok := store.Verify("admin", "new-pass-1234"); !ok {
		t.Error("applied hash does not verify against the plaintext it was derived from")
	}
	if _, err := os.Stat(usersFile); err != nil {
		t.Errorf("users file missing after apply: %v", err)
	}
}

// TestChangePasswordFormHandler_WritesAuditEntryOnEveryNode confirms a
// password change leaves a paper trail, same as config.save and
// daemon.restart already do.
func TestChangePasswordFormHandler_WritesAuditEntryOnEveryNode(t *testing.T) {
	store, usersFile := newTestStore(t, "admin", "correct-horse", "admin")

	got := make(chan struct{ Action, Summary string }, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/audit" {
			http.NotFound(w, r)
			return
		}
		var body struct{ Actor, Action, Summary string }
		json.NewDecoder(r.Body).Decode(&body)
		got <- struct{ Action, Summary string }{body.Action, body.Summary}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &WebConfig{
		UsersFile: usersFile,
		Nodes:     []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://"), AdminToken: "shared-secret"}},
	}

	form := url.Values{"current_password": {"correct-horse"}, "new_password": {"new-pass-1234"}, "confirm_password": {"new-pass-1234"}}
	req := httptest.NewRequest(http.MethodPost, "/password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withAuthedUser(req, webauth.User{Name: "admin", Role: "admin"})
	w := httptest.NewRecorder()

	changePasswordFormHandler(newConfigRef(cfg), store, testRepl(store, cfg))(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	var gotAction, gotSummary string
	select {
	case e := <-got:
		gotAction, gotSummary = e.Action, e.Summary
	case <-time.After(5 * time.Second):
		t.Fatal("no audit entry arrived")
	}
	if gotAction != "password.change" {
		t.Errorf("audit action = %q, want %q", gotAction, "password.change")
	}
	if !strings.Contains(gotSummary, "admin") {
		t.Errorf("audit summary = %q, want it to name the account", gotSummary)
	}
	if strings.Contains(gotSummary, "new-pass-1234") {
		t.Error("audit summary must never contain the actual password")
	}
}
