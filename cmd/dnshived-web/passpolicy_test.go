// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"dnshived/internal/config"
	"dnshived/internal/webauth"
)

func TestPolicyContext(t *testing.T) {
	store := &webauth.Store{MinPasswordLength: 16}
	c := policyContext(store, "ops", "ops.team@example.org")
	if c.MinLength != 16 {
		t.Errorf("MinLength = %d, want 16", c.MinLength)
	}
	got := strings.Join(c.Names, ",")
	if !strings.HasPrefix(got, "ops,ops.team") {
		t.Errorf("Names = %q, want the user name and the mail local part first", got)
	}
}

func TestHandlePasswordStrength(t *testing.T) {
	tests := []struct {
		name        string
		minLength   int
		form        url.Values
		wantProblem string
		wantNone    bool
	}{
		{"meets the policy", 0, url.Values{"password": {"Tn4#kWz8@Lq2"}}, "", true},
		{"too short", 0, url.Values{"password": {"Tn4#kWz8"}}, "at least 12 characters", false},
		{"contains the user name", 0, url.Values{"password": {"Tn4#opsWz8@Lq2"}, "name": {"ops"}}, "user name", false},
		{"raised minimum from the store", 20, url.Values{"password": {"Tn4#kWz8@Lq2"}}, "at least 20 characters", false},
		{"empty", 0, url.Values{}, "at least 12 characters", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &webauth.Store{MinPasswordLength: tt.minLength}
			req := httptest.NewRequest(http.MethodPost, "/password-strength", strings.NewReader(tt.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			handlePasswordStrength(store)(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d", w.Code)
			}
			var res struct {
				Level    int      `json:"level"`
				Label    string   `json:"label"`
				Problems []string `json:"problems"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
				t.Fatalf("response is not JSON: %v: %s", err, w.Body.String())
			}
			if res.Problems == nil || res.Label == "" {
				t.Errorf("incomplete response: %+v", res)
			}
			joined := strings.Join(res.Problems, "; ")
			if tt.wantNone && len(res.Problems) != 0 {
				t.Errorf("unexpected problems: %s", joined)
			}
			if !tt.wantNone && !strings.Contains(joined, tt.wantProblem) {
				t.Errorf("problems %q do not contain %q", joined, tt.wantProblem)
			}
		})
	}
}

func TestHandlePasswordStrength_OversizedBodyRefused(t *testing.T) {
	big := "password=" + strings.Repeat("a", 20<<10)
	req := httptest.NewRequest(http.MethodPost, "/password-strength", strings.NewReader(big))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handlePasswordStrength(&webauth.Store{})(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestChangePassword_WeakNewPasswordRefused(t *testing.T) {
	tests := []struct {
		name string
		pw   string
		want string
	}{
		{"too short", "Ab1#xY", "at least 12 characters"},
		{"no special character", "Newpass8342Xqzz", "special character"},
		{"contains the user name", "Admin#Pass7Xqwz", "user name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, usersFile := newTestStore(t, "admin", "correct-horse", "admin")
			cfg := &WebConfig{UsersFile: usersFile}
			form := url.Values{"current_password": {"correct-horse"}, "new_password": {tt.pw}, "confirm_password": {tt.pw}}
			req := httptest.NewRequest(http.MethodPost, "/password", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req = withAuthedUser(req, webauth.User{Name: "admin", Role: "admin"})
			w := httptest.NewRecorder()

			changePasswordFormHandler(newConfigRef(cfg), store, testRepl(store, cfg))(w, req)

			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), tt.want) {
				t.Errorf("status = %d, body does not mention %q: %s", w.Code, tt.want, w.Body.String())
			}
			if _, ok := store.Verify("admin", "correct-horse"); !ok {
				t.Error("the old password stopped working after a refused change")
			}
		})
	}
}

func TestHandleUsersPolicyPost(t *testing.T) {
	tests := []struct {
		name      string
		minLength string
		wantCode  int
		wantMin   int
	}{
		{"valid", "16", http.StatusSeeOther, 16},
		{"lowest allowed", "8", http.StatusSeeOther, 8},
		{"below the floor", "7", http.StatusBadRequest, 0},
		{"above the ceiling", "65", http.StatusBadRequest, 0},
		{"not a number", "abc", http.StatusBadRequest, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, repl, ref := usersFixture(t, webauth.User{Name: "admin", Role: webauth.RoleAdmin})
			w := userForm(t, handleUsersPolicyPost(store, repl, ref), "/users/policy", "admin", url.Values{"min_length": {tt.minLength}})
			if w.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d: %s", w.Code, tt.wantCode, w.Body.String())
			}
			if got := store.PasswordMinLength(); got != tt.wantMin {
				t.Errorf("stored minimum = %d, want %d", got, tt.wantMin)
			}
		})
	}
}

func TestUserCreate_RaisedMinimumApplies(t *testing.T) {
	store, repl, ref := usersFixture(t, webauth.User{Name: "admin", Role: webauth.RoleAdmin})
	if w := userForm(t, handleUsersPolicyPost(store, repl, ref), "/users/policy", "admin", url.Values{"min_length": {"20"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("policy not saved: %d", w.Code)
	}
	pw := "Long-Enough#1Xq"
	w := userForm(t, handleUserCreate(store, repl, ref), "/users/new", "admin", url.Values{
		"name": {"ops"}, "role": {"readonly"}, "new_password": {pw}, "confirm_password": {pw}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "at least 20 characters") {
		t.Errorf("a 15 character password was accepted with a minimum of 20: %d %s", w.Code, w.Body.String())
	}
}

func TestPasswordPages_CarryTheStrengthBar(t *testing.T) {
	store, _, ref := usersFixture(t, webauth.User{Name: "admin", Role: webauth.RoleAdmin})

	users := httptest.NewRecorder()
	handleUsersGet(store)(users, withAuthedUser(httptest.NewRequest(http.MethodGet, "/users", nil), webauth.User{Name: "admin", Role: webauth.RoleAdmin}))
	for _, want := range []string{`data-pwbar`, `/password-strength`, `name="min_length"`, `value="12"`} {
		if !strings.Contains(users.Body.String(), want) {
			t.Errorf("users page lacks %q", want)
		}
	}

	change := httptest.NewRecorder()
	handlePasswordForm(ref)(change, withAuthedUser(httptest.NewRequest(http.MethodGet, "/password", nil), webauth.User{Name: "admin", Role: webauth.RoleAdmin}))
	for _, want := range []string{`data-pwbar`, `/password-strength`} {
		if !strings.Contains(change.Body.String(), want) {
			t.Errorf("password page lacks %q", want)
		}
	}
}

func TestHandleBackupSettingsPost_WeakBackupPasswordRefused(t *testing.T) {
	srv, pushed := fakeCandidateNode(t, config.Cluster{BackupPassword: "old"})
	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}
	post := func(form string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/backup/settings", strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handleBackupSettingsPost(newConfigRef(cfg), &webauth.Store{})(w, r)
		return w
	}
	if w := post("backup_password=weakpass"); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "too weak") {
		t.Errorf("weak backup password: %d %s", w.Code, w.Body.String())
	}
	if pushed.BackupPassword != "" {
		t.Error("a refused backup password was pushed")
	}
	if w := post("backup_password="); w.Code >= 400 {
		t.Errorf("a blank password (keep the current one) was refused: %d %s", w.Code, w.Body.String())
	}
	if pushed.BackupPassword != "old" {
		t.Errorf("the existing weaker backup password was not kept: %q", pushed.BackupPassword)
	}
}

func TestHandleBackupCreatePost_WeakBackupPasswordRefused(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/backup/create", strings.NewReader("password=weakpass"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleBackupCreatePost(newConfigRef(&WebConfig{}), &webauth.Store{})(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "too weak") {
		t.Errorf("weak manual backup password: %d %s", w.Code, w.Body.String())
	}
}

func TestHandleSecurityPost_TokenStrength(t *testing.T) {
	live := config.Cluster{APITokens: []config.APIToken{{Name: "old", Token: "weak-but-existing", Role: "admin"}}}
	tests := []struct {
		name     string
		form     url.Values
		wantCode int
	}{
		{"existing weak token kept unchanged", url.Values{"__token_row_count__": {"1"}, "token_name_0": {"old"}, "token_role_0": {"admin"}}, http.StatusOK},
		{"existing token changed to a weak value", url.Values{"__token_row_count__": {"1"}, "token_name_0": {"old"}, "token_value_0": {"short"}, "token_role_0": {"admin"}}, http.StatusBadRequest},
		{"new weak token", url.Values{"__token_row_count__": {"2"}, "token_name_0": {"old"}, "token_role_0": {"admin"}, "token_name_1": {"new"}, "token_value_1": {"short"}, "token_role_1": {"readonly"}}, http.StatusBadRequest},
		{"new strong token", url.Values{"__token_row_count__": {"2"}, "token_name_0": {"old"}, "token_role_0": {"admin"}, "token_name_1": {"new"}, "token_value_1": {"k8Zp2QvN7xLw4RtY9bGd3HsF6mCj1VeA"}, "token_role_1": {"readonly"}}, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, _ := fakeCandidateNode(t, live)
			cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}
			r := httptest.NewRequest(http.MethodPost, "/security", strings.NewReader(tt.form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			handleSecurityPost(newConfigRef(cfg))(w, r)
			if w.Code != tt.wantCode {
				t.Errorf("status = %d, want %d: %s", w.Code, tt.wantCode, w.Body.String())
			}
		})
	}
}

func TestLogin_WeakPasswordGoesToTheChangePageFirst(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantLoc  string
	}{
		{"weak password", "correct-horse", "/password?weak=1&next=%2Fscopes"},
		{"strong password", "Tn4#kWz8@Lq2", "/scopes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, _ := newTestStore(t, "admin", tt.password, "admin")
			form := url.Values{"username": {"admin"}, "password": {tt.password}, "next": {"/scopes"}}
			r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.RemoteAddr = "192.0.2.50:4000"
			w := httptest.NewRecorder()
			handleLoginPost(store, newConfigRef(&WebConfig{}))(w, r)
			if w.Code != http.StatusSeeOther || w.Header().Get("Location") != tt.wantLoc {
				t.Errorf("status %d, Location %q; want %q", w.Code, w.Header().Get("Location"), tt.wantLoc)
			}
		})
	}
}

func TestPasswordPage_WeakNotice(t *testing.T) {
	_, _, ref := usersFixture(t, webauth.User{Name: "admin", Role: webauth.RoleAdmin})
	get := func(query string) string {
		r := withAuthedUser(httptest.NewRequest(http.MethodGet, "/password"+query, nil), webauth.User{Name: "admin", Role: webauth.RoleAdmin})
		w := httptest.NewRecorder()
		handlePasswordForm(ref)(w, r)
		return w.Body.String()
	}
	if body := get("?weak=1&next=%2Fscopes"); !strings.Contains(body, "does not meet the current password policy") || !strings.Contains(body, `href="/scopes"`) {
		t.Errorf("notice or continue link missing: %s", body)
	}
	if body := get(""); strings.Contains(body, "does not meet the current password policy") {
		t.Error("the notice shows without weak=1")
	}
	if body := get("?weak=1&next=https%3A%2F%2Fevil.example"); strings.Contains(body, "evil.example") {
		t.Error("an external next address reached the page")
	}
}
