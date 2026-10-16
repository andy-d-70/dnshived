// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func TestBootstrapPaths_DerivesSiblingsFromClusterConfigDir(t *testing.T) {
	paths := bootstrapPaths("/etc/dnshived/cluster.json", defaultBootstrapDataDir)

	if paths.ClusterConfigPath != "/etc/dnshived/cluster.json" {
		t.Errorf("ClusterConfigPath = %q, want /etc/dnshived/cluster.json", paths.ClusterConfigPath)
	}
	if paths.ProbeConfigPath != "/etc/dnshived/probe.json" {
		t.Errorf("ProbeConfigPath = %q, want /etc/dnshived/probe.json", paths.ProbeConfigPath)
	}
	if paths.WebUsersPath != "/etc/dnshived/webui-users.json" {
		t.Errorf("WebUsersPath = %q, want /etc/dnshived/webui-users.json", paths.WebUsersPath)
	}
	if paths.DataDir != defaultBootstrapDataDir {
		t.Errorf("DataDir = %q, want %q", paths.DataDir, defaultBootstrapDataDir)
	}
	if len(paths.Units) == 0 {
		t.Error("Units is empty, want the real unit set to check")
	}
}

func TestBootstrapUnits_ExcludesSelfAndItsRequiredHelper(t *testing.T) {
	for _, forbidden := range []string{"dnshived.service", "dnshived-helper.service"} {
		for _, u := range bootstrapUnits {
			if u == forbidden {
				t.Errorf("bootstrapUnits contains %q — this unit's active state is unreliable when checked from within dnshived's own startup (see this test's doc comment)", forbidden)
			}
		}
	}
}

func TestBootstrapUnits_ExcludesProbeDaemon(t *testing.T) {
	for _, u := range bootstrapUnits {
		if u == "dnshived-probe.service" {
			t.Error("bootstrapUnits contains \"dnshived-probe.service\" — its active state is no longer reliable now that it's enabled by default on every fresh install (see this test's doc comment)")
		}
	}
}

func TestBootstrapOTPPath_IsNotUnderDataDir(t *testing.T) {
	rel, err := filepath.Rel(defaultBootstrapDataDir, defaultBootstrapOTPPath)
	if err == nil && !strings.HasPrefix(rel, "..") {
		t.Errorf("defaultBootstrapOTPPath (%s) is under defaultBootstrapDataDir (%s) — this exact layout previously caused bootstrap mode to permanently refuse to restart itself",
			defaultBootstrapOTPPath, defaultBootstrapDataDir)
	}
}

// TestBootstrapStatusHandler_ReportsUnconfigured pins the response shape.
func TestBootstrapStatusHandler_ReportsUnconfigured(t *testing.T) {
	handler := bootstrapStatusHandler("test-host", "0.9.7-dev+abc123")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var got bootstrapStatusResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Configured {
		t.Error("Configured = true, want false — this handler only ever runs in bootstrap mode")
	}
	if got.Hostname != "test-host" {
		t.Errorf("Hostname = %q, want test-host", got.Hostname)
	}
	if got.Version != "0.9.7-dev+abc123" {
		t.Errorf("Version = %q, want 0.9.7-dev+abc123", got.Version)
	}
}

// TestBootstrapStatusHandler_NeverLeaksOTP is a direct, explicit guard on
// the one thing this handler must never do — serve the join code over
// HTTP.
func TestBootstrapStatusHandler_NeverLeaksOTP(t *testing.T) {
	handler := bootstrapStatusHandler("test-host", "0.9.7-dev")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	body := rec.Body.String()
	for _, forbidden := range []string{"otp", "OTP", "join_code", "code"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("response body contains %q — the join code must never be served over HTTP: %s", forbidden, body)
		}
	}
}

func TestBootstrapSession_ValidAfterIssue(t *testing.T) {
	sess := &bootstrapSession{}
	token, err := sess.issue()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !sess.valid(token) {
		t.Error("valid(token) = false right after issue(), want true")
	}
}

// TestBootstrapSession_WrongTokenInvalid covers the actual security
// property.
func TestBootstrapSession_WrongTokenInvalid(t *testing.T) {
	sess := &bootstrapSession{}
	if _, err := sess.issue(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sess.valid("0000000000000000000000000000000000000000000000000000000000000000") {
		t.Error("valid() = true for a token never issued, want false")
	}
}

func TestBootstrapSession_EmptyTokenNeverValidBeforeIssue(t *testing.T) {
	sess := &bootstrapSession{}
	if sess.valid("") {
		t.Error("valid(\"\") = true before any token was issued, want false")
	}
}

// TestBootstrapSession_IssueInvalidatesPrevious confirms only one session
// is meaningful at a time.
func TestBootstrapSession_IssueInvalidatesPrevious(t *testing.T) {
	sess := &bootstrapSession{}
	first, err := sess.issue()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := sess.issue(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sess.valid(first) {
		t.Error("the first-issued token is still valid after a second issue() — only the latest should be")
	}
}

func TestBootstrapSessionMiddleware_ValidCookieGrantsAccess(t *testing.T) {
	sess := &bootstrapSession{}
	token, err := sess.issue()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	reached := false
	handler := bootstrapSessionMiddleware(sess, func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: bootstrapSessionCookie, Value: token})
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !reached {
		t.Error("the wrapped handler was never called — a valid session cookie must grant access")
	}
}

// TestBootstrapSessionMiddleware_MissingCookieRedirectsToLogin covers a
// fresh browser visit (no cookie at all yet).
func TestBootstrapSessionMiddleware_MissingCookieRedirectsToLogin(t *testing.T) {
	sess := &bootstrapSession{}
	handler := bootstrapSessionMiddleware(sess, func(w http.ResponseWriter, r *http.Request) {
		t.Error("wrapped handler must not be called with no session cookie at all")
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303 (redirect to /login)", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/login" {
		t.Errorf("Location = %q, want /login", got)
	}
}

// TestBootstrapSessionMiddleware_InvalidCookieRedirectsToLogin covers a
// tampered or stale cookie value.
func TestBootstrapSessionMiddleware_InvalidCookieRedirectsToLogin(t *testing.T) {
	sess := &bootstrapSession{}
	if _, err := sess.issue(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	handler := bootstrapSessionMiddleware(sess, func(w http.ResponseWriter, r *http.Request) {
		t.Error("wrapped handler must not be called with a tampered cookie")
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: bootstrapSessionCookie, Value: "tampered-value"})
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303 (redirect to /login)", rec.Code)
	}
}

func TestBootstrapLoginHandler_GetShowsFormWithOneField(t *testing.T) {
	handler := bootstrapLoginHandler("AB3F-9K2M-XQ7T-5H1P", &bootstrapSession{})

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if strings.Count(body, "<input") != 1 {
		t.Errorf("expected exactly one <input> field, got %d: %s", strings.Count(body, "<input"), body)
	}
	if strings.Contains(strings.ToLower(body), "username") {
		t.Errorf("body mentions a username field, want none: %s", body)
	}
}

func TestBootstrapLoginHandler_CorrectCodeIssuesSessionAndRedirects(t *testing.T) {
	const otp = "AB3F-9K2M-XQ7T-5H1P"
	sess := &bootstrapSession{}
	handler := bootstrapLoginHandler(otp, sess)

	form := url.Values{"code": {otp}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/" {
		t.Errorf("Location = %q, want /", got)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != bootstrapSessionCookie {
		t.Fatalf("expected exactly one %s cookie, got %v", bootstrapSessionCookie, cookies)
	}
	if !sess.valid(cookies[0].Value) {
		t.Error("the issued cookie value does not validate against the session — login must actually establish a working session")
	}
	if !cookies[0].HttpOnly {
		t.Error("session cookie is not HttpOnly — a real requirement for a credential-bearing cookie, not just a nicety")
	}
}

// TestBootstrapLoginHandler_WrongCodeRejectedNoSession covers the actual
// security property — a wrong code must neither issue a session nor
// redirect anywhere.
func TestBootstrapLoginHandler_WrongCodeRejectedNoSession(t *testing.T) {
	sess := &bootstrapSession{}
	handler := bootstrapLoginHandler("AB3F-9K2M-XQ7T-5H1P", sess)

	form := url.Values{"code": {"WRONG-CODE"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Error("a session cookie was set despite a wrong code — must never happen")
	}
}

func TestNewBootstrapMux_DoesNotPanicOnRegistration(t *testing.T) {
	newBootstrapMux("test-host", "TEST-OTP", "/tmp/does-not-matter/cluster.json", &builderState{}, &bootstrapSession{})
}
