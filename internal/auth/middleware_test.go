// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"dnshived/internal/config"
)

func handlerOK(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// TestRequireAdmin_ReadonlyRejected: a readonly token cannot reach an
// admin-only route.
func TestRequireAdmin_ReadonlyRejected(t *testing.T) {
	m := New([]config.APIToken{{Name: "viewer", Token: "ro-tok", Role: "readonly"}})
	h := m.Wrap(http.HandlerFunc(m.RequireAdmin(handlerOK)))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/scopes", nil)
	req.Header.Set("Authorization", "Bearer ro-tok")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d (readonly token must not reach an admin-gated handler)", rr.Code, http.StatusForbidden)
	}
}

func TestWrap_MalformedExpiryFailsClosed(t *testing.T) {
	m := New([]config.APIToken{{Name: "bad", Token: "bad-tok", Role: "admin", Expires: "not-a-date"}})
	h := m.Wrap(http.HandlerFunc(handlerOK))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer bad-tok")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d (a malformed expiry must fail closed, not grant perpetual validity)", rr.Code, http.StatusForbidden)
	}
}

// TestWrap_ValidFutureExpiryAccepted confirms the fix above didn't break
// the normal case: a well-formed, not-yet-reached expiry still admits the
// request.
func TestWrap_ValidFutureExpiryAccepted(t *testing.T) {
	m := New([]config.APIToken{{Name: "ok", Token: "ok-tok", Role: "admin", Expires: "2099-01-01T00:00:00Z"}})
	h := m.Wrap(http.HandlerFunc(handlerOK))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer ok-tok")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d for a valid, not-yet-expired token", rr.Code, http.StatusOK)
	}
}

func TestRequireAdmin_AdminAccepted(t *testing.T) {
	m := New([]config.APIToken{{Name: "op", Token: "admin-tok", Role: "admin"}})
	h := m.Wrap(http.HandlerFunc(m.RequireAdmin(handlerOK)))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/scopes", nil)
	req.Header.Set("Authorization", "Bearer admin-tok")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (admin token should reach the handler)", rr.Code, http.StatusOK)
	}
}

// TestRequireAdmin_DisabledPassesThrough matches Wrap's own passthrough
// behavior when no api_tokens are configured.
func TestRequireAdmin_DisabledPassesThrough(t *testing.T) {
	m := New(nil)
	h := m.Wrap(http.HandlerFunc(m.RequireAdmin(handlerOK)))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/scopes", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (auth disabled entirely — write path should pass through like everything else)", rr.Code, http.StatusOK)
	}
}

func TestRequireAdmin_NoTokenRejectedByWrapFirst(t *testing.T) {
	m := New([]config.APIToken{{Name: "op", Token: "admin-tok", Role: "admin"}})
	h := m.Wrap(http.HandlerFunc(m.RequireAdmin(handlerOK)))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/config/scopes", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d (Wrap should reject the missing token before RequireAdmin ever runs)", rr.Code, http.StatusUnauthorized)
	}
}

func TestWrap_WitnessEndpointsExemptEvenWithAuthEnabled(t *testing.T) {
	m := New([]config.APIToken{{Name: "op", Token: "admin-tok", Role: "admin"}})
	h := m.Wrap(http.HandlerFunc(handlerOK))

	for _, path := range []string{"/api/v1/token/request", "/api/v1/token/renew"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want %d (witness endpoints must be reachable with no Bearer header even when auth is enabled)", path, rr.Code, http.StatusOK)
		}
	}
}

func TestWrap_CoordRelayExemptEvenWithAuthEnabled(t *testing.T) {
	m := New([]config.APIToken{{Name: "op", Token: "admin-tok", Role: "admin"}})
	h := m.Wrap(http.HandlerFunc(handlerOK))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/coord/config/relay", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (coord relay must be reachable with no Bearer header even when auth is enabled)", rr.Code, http.StatusOK)
	}
}

func TestWrap_LeaseSyncExemptEvenWithAuthEnabled(t *testing.T) {
	m := New([]config.APIToken{{Name: "op", Token: "admin-tok", Role: "admin"}})
	h := m.Wrap(http.HandlerFunc(handlerOK))

	for _, p := range []string{"/api/v1/leasesync", "/api/v1/leasesync/fingerprint", "/api/v1/leasesync/snapshot"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want %d without a Bearer header", p, rr.Code, http.StatusOK)
		}
	}
}

func TestWrap_CoordConfigStillRequiresAuth(t *testing.T) {
	m := New([]config.APIToken{{Name: "op", Token: "admin-tok", Role: "admin"}})
	h := m.Wrap(http.HandlerFunc(handlerOK))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/coord/config", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d (/api/v1/coord/config must still require a Bearer token)", rr.Code, http.StatusUnauthorized)
	}
}

func TestWrap_TokenStatusStillRequiresAuth(t *testing.T) {
	m := New([]config.APIToken{{Name: "op", Token: "admin-tok", Role: "admin"}})
	h := m.Wrap(http.HandlerFunc(handlerOK))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/token/status", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d (/api/v1/token/status must still require a Bearer token)", rr.Code, http.StatusUnauthorized)
	}
}

func TestRequireProbeOrReadonly_ProbeAccepted(t *testing.T) {
	m := New([]config.APIToken{{Name: "probe-host", Token: "probe-tok", Role: "probe"}})
	h := m.Wrap(http.HandlerFunc(m.RequireProbeOrReadonly(handlerOK)))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/probe-config", nil)
	req.Header.Set("Authorization", "Bearer probe-tok")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (a probe-role token must still reach this handler)", rr.Code, http.StatusOK)
	}
}

func TestRequireProbeOrReadonly_ReadonlyAccepted(t *testing.T) {
	m := New([]config.APIToken{{Name: "validate", Token: "ro-tok", Role: "readonly"}})
	h := m.Wrap(http.HandlerFunc(m.RequireProbeOrReadonly(handlerOK)))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/probe-config", nil)
	req.Header.Set("Authorization", "Bearer ro-tok")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (a readonly-role token must now reach this handler too)", rr.Code, http.StatusOK)
	}
}

func TestRequireProbeOrReadonly_OtherRolesRejected(t *testing.T) {
	m := New([]config.APIToken{{Name: "web-ui", Token: "admin-tok", Role: "admin"}})
	h := m.Wrap(http.HandlerFunc(m.RequireProbeOrReadonly(handlerOK)))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/probe-config", nil)
	req.Header.Set("Authorization", "Bearer admin-tok")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d (a token with neither probe nor readonly role must be rejected)", rr.Code, http.StatusForbidden)
	}
}

func TestTokenFromContext_AbsentWhenAuthDisabled(t *testing.T) {
	m := New(nil)
	var gotOK bool
	h := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, gotOK = TokenFromContext(r)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if gotOK {
		t.Error("TokenFromContext returned ok=true with auth disabled — Wrap never resolves a token in that mode")
	}
}

func TestSetTokens_LiveRevocationTakesEffectImmediately(t *testing.T) {
	m := New([]config.APIToken{{Name: "web-ui", Token: "tok-1", Role: "admin"}})
	h := m.Wrap(http.HandlerFunc(handlerOK))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer tok-1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("before revocation: status = %d, want 200", rr.Code)
	}

	m.SetTokens([]config.APIToken{{Name: "web-ui-2", Token: "tok-2", Role: "admin"}})

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req2.Header.Set("Authorization", "Bearer tok-1")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusForbidden {
		t.Errorf("after revocation, same *Middleware/handler: status = %d, want %d (tok-1 must stop working immediately, no restart)", rr2.Code, http.StatusForbidden)
	}

	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req3.Header.Set("Authorization", "Bearer tok-2")
	rr3 := httptest.NewRecorder()
	h.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Errorf("new token after SetTokens: status = %d, want 200", rr3.Code)
	}
}

func TestSetTokens_EnablingAuthLiveIsNotPermanentlyCachedAtWrapTime(t *testing.T) {
	m := New(nil) // auth disabled at Wrap-build time
	h := m.Wrap(http.HandlerFunc(handlerOK))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("auth disabled, no bearer token: status = %d, want 200", rr.Code)
	}

	m.SetTokens([]config.APIToken{{Name: "web-ui", Token: "tok-1", Role: "admin"}})

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Errorf("same *Middleware/handler, auth enabled live, no bearer token: status = %d, want %d (auth must now actually be enforced, not permanently bypassed from the earlier disabled state)", rr2.Code, http.StatusUnauthorized)
	}
}
