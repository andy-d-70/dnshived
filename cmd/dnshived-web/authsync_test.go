// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"dnshived/internal/webauth"
)

func syncFixture(t *testing.T, users ...webauth.User) (*authSync, *WebConfig) {
	t.Helper()
	cfg := &WebConfig{
		UsersFile: filepath.Join(t.TempDir(), "webui-users.json"),
		Nodes:     []NodeConfig{{Name: "core-9", Addr: "192.0.2.9:9443", AdminToken: "shared-secret"}},
	}
	store := &webauth.Store{Users: users}
	return testRepl(store, cfg), cfg
}

func postDoc(a *authSync, doc *webauth.Store, token string) *httptest.ResponseRecorder {
	data, _ := doc.Marshal()
	r := httptest.NewRequest(http.MethodPost, "/internal/auth-doc", strings.NewReader(string(data)))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	a.handleAuthDocPost(w, r)
	return w
}

func TestAuthDocPost_RequiresToken(t *testing.T) {
	a, _ := syncFixture(t)
	if w := postDoc(a, &webauth.Store{Version: 5}, ""); w.Code != http.StatusUnauthorized {
		t.Errorf("no token = %d", w.Code)
	}
	if w := postDoc(a, &webauth.Store{Version: 5}, "wrong"); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong token = %d", w.Code)
	}
	if a.store.Meta().Version != 0 {
		t.Error("document adopted without a valid token")
	}
}

func TestAuthDocPost_NewerAdoptedAndSaved(t *testing.T) {
	a, cfg := syncFixture(t, webauth.User{Name: "old"})
	a.store.Version = 3
	remote := &webauth.Store{Version: 4, UpdatedAt: "2026-10-16T10:00:00Z", Origin: "core-2", Users: []webauth.User{{Name: "new"}}}
	w := postDoc(a, remote, "shared-secret")
	var m webauth.Meta
	json.Unmarshal(w.Body.Bytes(), &m)
	if w.Code != http.StatusOK || m.Version != 4 {
		t.Fatalf("status %d, meta %+v", w.Code, m)
	}
	disk, err := webauth.Load(cfg.UsersFile)
	if err != nil || disk.Version != 4 || len(disk.Users) != 1 || disk.Users[0].Name != "new" {
		t.Errorf("not saved: %+v %v", disk, err)
	}
	if w := postDoc(a, &webauth.Store{Version: 2, Users: []webauth.User{{Name: "stale"}}}, "shared-secret"); w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	if _, ok := a.store.Lookup("stale"); ok {
		t.Error("older document replaced a newer one")
	}
}

func TestAuthDocPost_LegacyNodeKeepsItsUsers(t *testing.T) {
	a, _ := syncFixture(t, webauth.User{Name: "admin"}, webauth.User{Name: "local-only"})
	remote := &webauth.Store{Version: 1, UpdatedAt: "2026-10-16T10:00:00Z", Origin: "core-1", Users: []webauth.User{{Name: "admin"}}}
	postDoc(a, remote, "shared-secret")
	if _, ok := a.store.Lookup("local-only"); !ok {
		t.Fatal("a user only this never-replicated node had was dropped")
	}
	if a.store.Meta().Version != 2 {
		t.Errorf("merged document must be a new revision, got %+v", a.store.Meta())
	}
}

func TestAuthDocMetaAndGet_RequireToken(t *testing.T) {
	a, _ := syncFixture(t, webauth.User{Name: "x", PasswordHash: "secret-hash"})
	w := httptest.NewRecorder()
	a.handleAuthDocGet(w, httptest.NewRequest(http.MethodGet, "/internal/auth-doc", nil))
	if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "secret-hash") {
		t.Errorf("document served without token: %d", w.Code)
	}
	w = httptest.NewRecorder()
	a.handleAuthDocMeta(w, httptest.NewRequest(http.MethodGet, "/internal/auth-doc/meta", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("meta served without token: %d", w.Code)
	}
}

func TestStartsFirstRevision_LowestNameOnly(t *testing.T) {
	if !startsFirstRevision("core-1", []string{"core-2", "core-3"}) {
		t.Error("lowest name must start")
	}
	if startsFirstRevision("core-2", []string{"core-1"}) {
		t.Error("a higher name must wait for the lower one")
	}
	if !startsFirstRevision("core-3", nil) {
		t.Error("alone (siblings unreachable or not upgraded yet) must start")
	}
}
