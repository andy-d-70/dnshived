// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"dnshived/internal/config"
	"dnshived/internal/webauth"
)

func TestRequirePermissionOrToken_ValidAdminTokenGrantsAccess(t *testing.T) {
	c := config.Cluster{APITokens: []config.APIToken{{Name: "script", Token: "s3cr3t", Role: "admin"}}}
	srv := fakeConfigServer(t, c)
	defer srv.Close()
	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}
	store := &webauth.Store{}

	called := false
	h := requirePermissionOrToken(store, webauth.PermEditConfig, newConfigRef(cfg), func(w http.ResponseWriter, r *http.Request) {
		called = true
		u, ok := userFromContext(r)
		if !ok || u.Name != "script" || u.Role != "admin" {
			t.Errorf("userFromContext = %+v, ok=%v, want name=script role=admin", u, ok)
		}
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodGet, "/config/export", nil)
	r.Header.Set("Authorization", "Bearer s3cr3t")
	w := httptest.NewRecorder()
	h(w, r)

	if !called {
		t.Fatal("handler was not called")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestRequirePermissionOrToken_ReadonlyTokenDeniedForEditPermission(t *testing.T) {
	c := config.Cluster{APITokens: []config.APIToken{{Name: "viewer", Token: "readtok", Role: "readonly"}}}
	srv := fakeConfigServer(t, c)
	defer srv.Close()
	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}
	store := &webauth.Store{}

	h := requirePermissionOrToken(store, webauth.PermEditConfig, newConfigRef(cfg), func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not have been called")
	})

	r := httptest.NewRequest(http.MethodGet, "/config/export", nil)
	r.Header.Set("Authorization", "Bearer readtok")
	w := httptest.NewRecorder()
	h(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestRequirePermissionOrToken_ReadonlyTokenAllowedForViewPermission(t *testing.T) {
	c := config.Cluster{APITokens: []config.APIToken{{Name: "viewer", Token: "readtok", Role: "readonly"}}}
	srv := fakeConfigServer(t, c)
	defer srv.Close()
	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}
	store := &webauth.Store{}

	called := false
	h := requirePermissionOrToken(store, webauth.PermViewStatus, newConfigRef(cfg), func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodGet, "/backup/list", nil)
	r.Header.Set("Authorization", "Bearer readtok")
	w := httptest.NewRecorder()
	h(w, r)

	if !called || w.Code != http.StatusOK {
		t.Fatalf("called=%v status=%d, want called=true status=200", called, w.Code)
	}
}

func TestRequirePermissionOrToken_UnknownTokenRejected(t *testing.T) {
	c := config.Cluster{APITokens: []config.APIToken{{Name: "script", Token: "s3cr3t", Role: "admin"}}}
	srv := fakeConfigServer(t, c)
	defer srv.Close()
	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}
	store := &webauth.Store{}

	h := requirePermissionOrToken(store, webauth.PermEditConfig, newConfigRef(cfg), func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not have been called")
	})

	r := httptest.NewRequest(http.MethodGet, "/config/export", nil)
	r.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	h(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestRequirePermissionOrToken_ProbeRoleTokenRejected(t *testing.T) {
	c := config.Cluster{APITokens: []config.APIToken{{Name: "probe-host", Token: "probetok", Role: "probe"}}}
	srv := fakeConfigServer(t, c)
	defer srv.Close()
	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}
	store := &webauth.Store{}

	h := requirePermissionOrToken(store, webauth.PermViewStatus, newConfigRef(cfg), func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not have been called — a probe-role token must never grant web access")
	})

	r := httptest.NewRequest(http.MethodGet, "/backup/list", nil)
	r.Header.Set("Authorization", "Bearer probetok")
	w := httptest.NewRecorder()
	h(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (probe token must not match)", w.Code)
	}
}

func TestRequirePermissionOrToken_ExpiredTokenRejected(t *testing.T) {
	c := config.Cluster{APITokens: []config.APIToken{{
		Name: "script", Token: "s3cr3t", Role: "admin",
		Expires: time.Now().Add(-time.Hour).Format(time.RFC3339),
	}}}
	srv := fakeConfigServer(t, c)
	defer srv.Close()
	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}
	store := &webauth.Store{}

	h := requirePermissionOrToken(store, webauth.PermEditConfig, newConfigRef(cfg), func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not have been called — token is expired")
	})

	r := httptest.NewRequest(http.MethodGet, "/config/export", nil)
	r.Header.Set("Authorization", "Bearer s3cr3t")
	w := httptest.NewRecorder()
	h(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

// TestRequirePermissionOrToken_MalformedExpiresTreatedAsExpired checks a
// malformed expiry counts as expired.
func TestRequirePermissionOrToken_MalformedExpiresTreatedAsExpired(t *testing.T) {
	c := config.Cluster{APITokens: []config.APIToken{{
		Name: "script", Token: "s3cr3t", Role: "admin", Expires: "not-a-real-timestamp",
	}}}
	srv := fakeConfigServer(t, c)
	defer srv.Close()
	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}
	store := &webauth.Store{}

	h := requirePermissionOrToken(store, webauth.PermEditConfig, newConfigRef(cfg), func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not have been called — a malformed expires value must be treated as expired, not never-expiring")
	})

	r := httptest.NewRequest(http.MethodGet, "/config/export", nil)
	r.Header.Set("Authorization", "Bearer s3cr3t")
	w := httptest.NewRecorder()
	h(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestRequirePermissionOrToken_NoAuthHeaderGoesToLogin(t *testing.T) {
	cfg := &WebConfig{}
	store := &webauth.Store{}

	h := requirePermissionOrToken(store, webauth.PermViewStatus, newConfigRef(cfg), func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not have been called — no credentials at all were presented")
	})

	r := httptest.NewRequest(http.MethodGet, "/status", nil)
	w := httptest.NewRecorder()
	h(w, r)

	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login?next=%2Fstatus" {
		t.Fatalf("status = %d, Location = %q; want 303 to /login?next=%%2Fstatus", w.Code, w.Header().Get("Location"))
	}
	if w.Header().Get("WWW-Authenticate") != "" {
		t.Error("a browser without a session must get the login page, not the Basic-auth popup")
	}
}
