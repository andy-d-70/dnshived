// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"dnshived/internal/webauth"
)

func sessionStore(t *testing.T) *webauth.Store {
	t.Helper()
	s := &webauth.Store{Users: []webauth.User{{Name: "ops", Role: webauth.RoleScopeAdmin, SessionEpoch: 2}}}
	if _, err := s.EnsureSessionKey("test"); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSessionCookie_RoundTripAndLimits(t *testing.T) {
	s := sessionStore(t)
	now := time.Now()
	c := sessionClaims{User: "ops", Epoch: 2, Issued: now.Unix(), Seen: now.Unix()}
	v := signSession(s.SessionKeyBytes(), c)

	if u, _, ok := sessionUser(s, v, now); !ok || u.Role != webauth.RoleScopeAdmin {
		t.Fatalf("valid cookie refused: %+v %v", u, ok)
	}
	if _, _, ok := sessionUser(s, v, now.Add(sessionIdle+time.Second)); ok {
		t.Error("cookie accepted after the idle timeout")
	}
	old := c
	old.Issued = now.Add(-sessionMax - time.Minute).Unix()
	if _, _, ok := sessionUser(s, signSession(s.SessionKeyBytes(), old), now); ok {
		t.Error("cookie accepted after the absolute maximum")
	}
	if _, _, ok := sessionUser(s, v[:len(v)-2]+"AA", now); ok {
		t.Error("tampered signature accepted")
	}
	forged := signSession([]byte("another-cluster-key-another-key!"), c)
	if _, _, ok := sessionUser(s, forged, now); ok {
		t.Error("cookie signed with another key accepted")
	}
}

func TestSessionCookie_EpochAndDisableEndSessions(t *testing.T) {
	s := sessionStore(t)
	now := time.Now()
	v := signSession(s.SessionKeyBytes(), sessionClaims{User: "ops", Epoch: 2, Issued: now.Unix(), Seen: now.Unix()})
	s.Mutate("test", func(d *webauth.Store) error { d.Users[0].SessionEpoch++; return nil })
	if _, _, ok := sessionUser(s, v, now); ok {
		t.Error("cookie survived a session-epoch bump (password change / sign out everywhere)")
	}
	v = signSession(s.SessionKeyBytes(), sessionClaims{User: "ops", Epoch: 3, Issued: now.Unix(), Seen: now.Unix()})
	s.Mutate("test", func(d *webauth.Store) error { d.Users[0].Disabled = true; return nil })
	if _, _, ok := sessionUser(s, v, now); ok {
		t.Error("cookie of a disabled user accepted")
	}
}

func TestAuthenticate_SessionPassesAndAPIGets401(t *testing.T) {
	s := sessionStore(t)
	now := time.Now()
	v := signSession(s.SessionKeyBytes(), sessionClaims{User: "ops", Epoch: 2, Issued: now.Unix(), Seen: now.Unix()})
	var got webauth.User
	h := authenticate(s, func(w http.ResponseWriter, r *http.Request) { got, _ = userFromContext(r) })

	r := httptest.NewRequest(http.MethodGet, "/scopes", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: v})
	h(httptest.NewRecorder(), r)
	if got.Name != "ops" {
		t.Errorf("session user not passed on: %+v", got)
	}

	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodGet, "/api/pending-summary", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("API call without session = %d, want 401 (no redirect)", w.Code)
	}
	w = httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodPost, "/scopes/x/config", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("POST without session = %d, want 401", w.Code)
	}
}

func TestLoginPost_SetsCookieAndRedirectsSafely(t *testing.T) {
	orig := pbkdf2Slots
	t.Cleanup(func() { pbkdf2Slots = orig; clearVerifyCache() })
	s := sessionStore(t)
	if err := s.Upsert("admin", "correct-horse-1", webauth.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	cfg := &WebConfig{}
	post := func(user, pw, next string) *httptest.ResponseRecorder {
		form := url.Values{"username": {user}, "password": {pw}, "next": {next}}
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.RemoteAddr = "192.0.2.10:5000"
		w := httptest.NewRecorder()
		handleLoginPost(s, newConfigRef(cfg))(w, r)
		return w
	}
	w := post("admin", "correct-horse-1", "//evil.example/x")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Errorf("open redirect not blocked: %d %q", w.Code, w.Header().Get("Location"))
	}
	ck := w.Result().Cookies()
	if len(ck) != 1 || ck[0].Name != sessionCookieName || !ck[0].HttpOnly || ck[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie = %+v", ck)
	}
	if _, _, ok := sessionUser(s, ck[0].Value, time.Now()); !ok {
		t.Error("issued cookie does not validate")
	}
	if w := post("admin", "correct-horse-1", "/scopes?x=1"); w.Header().Get("Location") != "/scopes?x=1" {
		t.Errorf("next not honored: %q", w.Header().Get("Location"))
	}
	if w := post("admin", "wrong", "/"); w.Code != http.StatusUnauthorized || len(w.Result().Cookies()) != 0 {
		t.Errorf("wrong password: %d, cookies %v", w.Code, w.Result().Cookies())
	}
}

func TestLogout_ClearsCookie(t *testing.T) {
	w := httptest.NewRecorder()
	handleLogout(w, httptest.NewRequest(http.MethodPost, "/logout", nil))
	ck := w.Result().Cookies()
	if len(ck) != 1 || ck[0].MaxAge >= 0 || w.Header().Get("Location") != "/login?msg=logout" {
		t.Errorf("logout: cookies %+v, location %q", ck, w.Header().Get("Location"))
	}
}
