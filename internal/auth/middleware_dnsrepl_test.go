// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"dnshived/internal/config"
)

func TestWrap_DNSReplicationPathsAreExemptButNothingElseUnderInternal(t *testing.T) {
	m := New([]config.APIToken{{Name: "a", Token: "secret", Role: "admin"}})
	h := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	for _, p := range []string{"/internal/dnsrepl/vote", "/internal/dnsrepl/append", "/internal/dnsrepl/snapshot"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", p, nil))
		if w.Code != 200 {
			t.Errorf("%s: %d, the replication endpoints gate themselves", p, w.Code)
		}
	}
	for _, p := range []string{"/internal/dnsrepl/other", "/internal/dnsrepl/vote/x", "/api/v1/dnsstore/status", "/api/v1/dnsstore/commit"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", p, nil))
		if w.Code != 401 {
			t.Errorf("%s: %d, want 401 without a token", p, w.Code)
		}
	}
}
