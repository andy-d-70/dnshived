// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"dnshived/internal/repldoc"
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

func TestAuthDocPost_RefusesAnOversizedDocument(t *testing.T) {
	a, _ := syncFixture(t, webauth.User{Name: "local"})
	users := make([]webauth.User, maxReplUsers+1)
	for i := range users {
		users[i] = webauth.User{Name: fmt.Sprintf("u%d", i), Role: webauth.RoleReadonly}
	}
	w := postDoc(a, &webauth.Store{Version: 9, UpdatedAt: "t", Origin: "core-2", Users: users}, "shared-secret")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", w.Code)
	}
	if _, ok := a.store.Lookup("local"); !ok || a.store.Meta().Version != 0 {
		t.Error("a refused document changed the store")
	}
	w = postDoc(a, &webauth.Store{Version: 9, UpdatedAt: "t", Origin: "core-2", Users: []webauth.User{{Name: strings.Repeat("n", 300)}}}, "shared-secret")
	if w.Code != http.StatusBadRequest {
		t.Errorf("oversized name: status %d, want 400", w.Code)
	}
}

func TestAuthDocPost_AcceptsAnUnknownRole(t *testing.T) {
	a, _ := syncFixture(t)
	w := postDoc(a, &webauth.Store{Version: 4, UpdatedAt: "t", Origin: "core-2", Users: []webauth.User{{Name: "future", Role: "auditor"}}}, "shared-secret")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: a role added by a newer version must not break replication", w.Code)
	}
	if _, ok := a.store.Lookup("future"); !ok {
		t.Error("user with a newer version's role not installed")
	}
}

func TestAuthDocMeta_CarriesTheContentHash(t *testing.T) {
	a, _ := syncFixture(t, webauth.User{Name: "a", Role: webauth.RoleAdmin})
	r := httptest.NewRequest(http.MethodGet, "/internal/auth-doc/meta", nil)
	r.Header.Set("Authorization", "Bearer shared-secret")
	w := httptest.NewRecorder()
	a.handleAuthDocMeta(w, r)
	var m webauth.Meta
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil || m.Hash == "" {
		t.Errorf("meta = %+v %v", m, err)
	}
}

func TestAuthDocPost_RefusesAnOutOfRangeRevision(t *testing.T) {
	a, _ := syncFixture(t)
	w := postDoc(a, &webauth.Store{Version: 1 << 60, UpdatedAt: "t", Origin: "core-2", Users: []webauth.User{{Name: "x"}}}, "shared-secret")
	if w.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400", w.Code)
	}
	if a.store.Meta().Version != 0 {
		t.Error("a huge revision was installed")
	}
}

func TestReplConflict_ReportsOncePerPairOfContents(t *testing.T) {
	cfg := &WebConfig{}
	report := replConflict(newConfigRef(cfg), "test")
	var logged strings.Builder
	old := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(old)
	l := repldoc.Meta{Version: 3, Hash: "aaaaaaaaaaaa"}
	r := repldoc.Meta{Version: 3, Hash: "bbbbbbbbbbbb"}
	report(l, r, "core-2")
	report(l, r, "core-2")
	report(l, r, "core-3")
	report(l, repldoc.Meta{Version: 3, Hash: "cccccccccccc"}, "core-2")
	if n := strings.Count(logged.String(), "[REPL]"); n != 3 {
		t.Errorf("reported %d times, want 3 (once per peer and content pair):\n%s", n, logged.String())
	}
}
