// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"dnshived/internal/webauth"
)

func usersFixture(t *testing.T, users ...webauth.User) (*webauth.Store, *authSync, *configRef) {
	t.Helper()
	cfg := &WebConfig{UsersFile: filepath.Join(t.TempDir(), "webui-users.json")}
	store := &webauth.Store{Version: 1, Users: users}
	return store, testRepl(store, cfg), newConfigRef(cfg)
}

func userForm(t *testing.T, h http.HandlerFunc, path, actor string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if i := strings.Index(path, "/users/"); i >= 0 {
		rest := strings.TrimPrefix(path[i:], "/users/")
		r.SetPathValue("name", strings.SplitN(rest, "/", 2)[0])
	}
	r = withAuthedUser(r, webauth.User{Name: actor, Role: webauth.RoleAdmin})
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func TestUserCreate_ValidatesAndAdds(t *testing.T) {
	store, repl, ref := usersFixture(t, webauth.User{Name: "admin", Role: webauth.RoleAdmin})
	h := handleUserCreate(store, repl, ref)
	cases := []url.Values{
		{"name": {"bad name"}, "role": {"readonly"}, "new_password": {"long-enough-1"}, "confirm_password": {"long-enough-1"}},
		{"name": {"ok"}, "role": {"root"}, "new_password": {"long-enough-1"}, "confirm_password": {"long-enough-1"}},
		{"name": {"ok"}, "role": {"readonly"}, "new_password": {"short"}, "confirm_password": {"short"}},
		{"name": {"ok"}, "role": {"readonly"}, "email": {"not-an-address"}, "new_password": {"long-enough-1"}, "confirm_password": {"long-enough-1"}},
		{"name": {"admin"}, "role": {"readonly"}, "new_password": {"long-enough-1"}, "confirm_password": {"long-enough-1"}},
	}
	for i, f := range cases {
		if w := userForm(t, h, "/users/new", "admin", f); w.Code != http.StatusBadRequest {
			t.Errorf("case %d accepted: %d", i, w.Code)
		}
	}
	w := userForm(t, h, "/users/new", "admin", url.Values{"name": {"ops"}, "role": {"scopeadmin"}, "email": {"ops@example.org"},
		"new_password": {"long-enough-1"}, "confirm_password": {"long-enough-1"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("valid user refused: %d %s", w.Code, w.Body.String())
	}
	if u, ok := store.Lookup("ops"); !ok || u.Role != webauth.RoleScopeAdmin || u.Email != "ops@example.org" || !webauth.VerifyPassword("long-enough-1", u.PasswordHash) {
		t.Errorf("created user = %+v", u)
	}
	if store.Meta().Version != 2 {
		t.Error("creating a user must be a new revision")
	}
}

func TestUserUpdate_LastAdminAndSelfProtected(t *testing.T) {
	store, repl, ref := usersFixture(t,
		webauth.User{Name: "admin", Role: webauth.RoleAdmin},
		webauth.User{Name: "ops", Role: webauth.RoleReadonly})
	h := handleUserUpdate(store, repl, ref)

	if w := userForm(t, h, "/users/admin", "ops", url.Values{"role": {"readonly"}}); w.Code != http.StatusBadRequest {
		t.Errorf("last admin demoted: %d", w.Code)
	}
	if w := userForm(t, h, "/users/admin", "ops", url.Values{"role": {"admin"}, "disabled": {"on"}}); w.Code != http.StatusBadRequest {
		t.Errorf("last admin disabled: %d", w.Code)
	}
	userForm(t, h, "/users/admin", "admin", url.Values{"role": {"readonly"}, "disabled": {"on"}})
	if u, _ := store.Lookup("admin"); u.Role != webauth.RoleAdmin || u.Disabled {
		t.Errorf("an admin changed their own role/status: %+v", u)
	}

	before, _ := store.Lookup("ops")
	if w := userForm(t, h, "/users/ops", "admin", url.Values{"role": {"admin"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("promotion refused: %d", w.Code)
	}
	after, _ := store.Lookup("ops")
	if after.Role != webauth.RoleAdmin || after.SessionEpoch != before.SessionEpoch+1 {
		t.Errorf("role change must end the user's sessions: %+v", after)
	}
	if w := userForm(t, h, "/users/admin", "ops", url.Values{"role": {"readonly"}}); w.Code != http.StatusSeeOther {
		t.Errorf("demoting an admin while another admin exists refused: %d", w.Code)
	}
}

func TestUserDelete_Guardrails(t *testing.T) {
	store, repl, ref := usersFixture(t,
		webauth.User{Name: "admin", Role: webauth.RoleAdmin},
		webauth.User{Name: "ops", Role: webauth.RoleAdmin, Disabled: true},
		webauth.User{Name: "viewer", Role: webauth.RoleReadonly})
	h := handleUserDelete(store, repl, ref)
	if w := userForm(t, h, "/users/admin/delete", "admin", nil); w.Code != http.StatusBadRequest {
		t.Errorf("self-delete allowed: %d", w.Code)
	}
	if w := userForm(t, h, "/users/admin/delete", "viewer", nil); w.Code != http.StatusBadRequest {
		t.Errorf("last active admin deleted: %d", w.Code)
	}
	if len(store.List()) != 3 {
		t.Fatalf("a refused delete changed the user list: %+v", store.List())
	}
	if w := userForm(t, h, "/users/viewer/delete", "admin", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("delete refused: %d", w.Code)
	}
	if _, ok := store.Lookup("viewer"); ok {
		t.Error("user not deleted")
	}
}

func TestUserSignout_BumpsEpoch(t *testing.T) {
	store, repl, ref := usersFixture(t, webauth.User{Name: "admin", Role: webauth.RoleAdmin}, webauth.User{Name: "ops", Role: webauth.RoleReadonly})
	userForm(t, handleUserSignout(store, repl, ref), "/users/ops/signout", "admin", nil)
	if u, _ := store.Lookup("ops"); u.SessionEpoch != 1 {
		t.Errorf("sign out everywhere did not bump the epoch: %+v", u)
	}
}

func TestRoles_ScopeAdminRights(t *testing.T) {
	sa := webauth.User{Role: webauth.RoleScopeAdmin}
	if !sa.HasPermission(webauth.PermEditScopes) || sa.HasPermission(webauth.PermEditConfig) || !sa.HasPermission(webauth.PermViewStatus) {
		t.Error("scopeadmin permissions wrong")
	}
	ro := webauth.User{Role: webauth.RoleReadonly}
	if ro.HasPermission(webauth.PermEditScopes) {
		t.Error("readonly may edit scopes")
	}
	ad := webauth.User{Role: webauth.RoleAdmin}
	if !ad.HasPermission(webauth.PermEditScopes) || !ad.HasPermission(webauth.PermEditConfig) {
		t.Error("admin lacks a permission")
	}
}
