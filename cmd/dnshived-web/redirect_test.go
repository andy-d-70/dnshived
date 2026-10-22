// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRedirectToHTTPS_PreservesHostAndPath(t *testing.T) {
	handler := redirectToHTTPS("0.0.0.0:8443", fixedHost(""))

	req := httptest.NewRequest(http.MethodGet, "http://192.0.2.230:8080/scopes?page=2", nil)
	req.Host = "192.0.2.230:8080"
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMovedPermanently)
	}
	want := "https://192.0.2.230:8443/scopes?page=2"
	if got := rec.Header().Get("Location"); got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
}

func TestRedirectToHTTPS_HostWithoutExplicitPort(t *testing.T) {
	handler := redirectToHTTPS(":8443", fixedHost(""))

	req := httptest.NewRequest(http.MethodGet, "http://dnshived.example/", nil)
	req.Host = "dnshived.example"
	rec := httptest.NewRecorder()

	handler(rec, req)

	want := "https://dnshived.example:8443/"
	if got := rec.Header().Get("Location"); got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
}

func TestRedirectToHTTPS_VIPHostOverridesRequestHost(t *testing.T) {
	handler := redirectToHTTPS("0.0.0.0:8443", fixedHost("vip.example"))

	req := httptest.NewRequest(http.MethodGet, "http://worker-a.example:8080/scopes?page=2", nil)
	req.Host = "worker-a.example:8080"
	rec := httptest.NewRecorder()

	handler(rec, req)

	want := "https://vip.example:8443/scopes?page=2"
	if got := rec.Header().Get("Location"); got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
}

func TestVIPHostMiddleware_RedirectsNonVIPHost(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not run for a non-VIP host")
	})
	handler := vipHostMiddleware(fixedHost("vip.example"), nil, "https", "8443", inner)

	req := httptest.NewRequest(http.MethodGet, "https://worker-a.example:8443/scopes?page=2", nil)
	req.Host = "worker-a.example:8443"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMovedPermanently)
	}
	want := "https://vip.example:8443/scopes?page=2"
	if got := rec.Header().Get("Location"); got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
}

func TestVIPHostMiddleware_ServesRequestOnVIPHost(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	handler := vipHostMiddleware(fixedHost("vip.example"), nil, "https", "8443", inner)

	req := httptest.NewRequest(http.MethodGet, "https://vip.example:8443/scopes", nil)
	req.Host = "vip.example:8443"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("inner handler should run when Host matches vipHost")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestVIPHostMiddleware_ExemptsInternalPathsEvenOnNonVIPHost(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	handler := vipHostMiddleware(fixedHost("vip.example"), nil, "https", "8443", inner)

	req := httptest.NewRequest(http.MethodPost, "https://worker-a.example:8443/internal/nodes/probe/add", nil)
	req.Host = "worker-a.example:8443"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("inner handler should run for /internal/ paths regardless of Host — must never redirect to the VIP")
	}
	if rec.Code == http.StatusMovedPermanently {
		t.Error("got a redirect for an /internal/ path — the whole point of the exemption is no redirect")
	}
}

func TestVIPHostMiddleware_ServesRequestOnExtraHost(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	handler := vipHostMiddleware(fixedHost("vip.example"), []string{"ops.example.com", "ops2.example.com"}, "https", "8443", inner)

	req := httptest.NewRequest(http.MethodGet, "https://ops.example.com/scopes", nil)
	req.Host = "ops.example.com"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("inner handler should run when Host matches an ExternalHosts entry")
	}
	if rec.Code == http.StatusMovedPermanently {
		t.Error("got a redirect for a configured external host — the whole point of ExternalHosts is no redirect")
	}
}

// TestVIPHostMiddleware_StillRedirectsUnknownHostWithExtraHostsSet
// confirms ExternalHosts is a real allowlist, not a blanket disable.
func TestVIPHostMiddleware_StillRedirectsUnknownHostWithExtraHostsSet(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not run for a host matching neither vipHost nor ExternalHosts")
	})
	handler := vipHostMiddleware(fixedHost("vip.example"), []string{"ops.example.com"}, "https", "8443", inner)

	req := httptest.NewRequest(http.MethodGet, "https://worker-a.example:8443/scopes", nil)
	req.Host = "worker-a.example:8443"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMovedPermanently)
	}
	want := "https://vip.example:8443/scopes"
	if got := rec.Header().Get("Location"); got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
}

func TestRedirectToHTTPS_BootstrapPortsGoToWebUIPort(t *testing.T) {
	cases := []struct {
		vip, host, want string
	}{
		{"192.0.2.230", "192.0.2.51:443", "https://192.0.2.230:8443/scopes"},
		{"192.0.2.230", "192.0.2.51", "https://192.0.2.230:8443/scopes"},
		{"", "192.0.2.51:443", "https://192.0.2.51:8443/scopes"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/scopes", nil)
		req.Host = c.host
		rec := httptest.NewRecorder()
		redirectToHTTPS("0.0.0.0:8443", fixedHost(c.vip))(rec, req)
		if got := rec.Header().Get("Location"); got != c.want {
			t.Errorf("vip=%q host=%q: Location = %q, want %q", c.vip, c.host, got, c.want)
		}
	}
}

func fixedHost(h string) func() string { return func() string { return h } }

func TestVIPHostMiddleware_FollowsLiveVIPChange(t *testing.T) {
	vip := "192.0.2.230"
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := vipHostMiddleware(func() string { return vip }, nil, "https", "8443", inner)

	vip = "192.0.2.231"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "192.0.2.231:8443"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("request on the new VIP got %d, want 200 (served, not redirected to the old VIP)", rec.Code)
	}

	vip = ""
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "192.0.2.51:8443"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("with no mgmt VIP any more, got %d, want 200 (served on the node's own address)", rec.Code)
	}
}
