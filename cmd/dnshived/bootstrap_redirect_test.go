// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRedirectPagesToHTTPS(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	cases := []struct {
		tlsAddr, host, path string
		wantCode            int
		wantLoc             string
	}{
		{":443", "192.0.2.5", "/api/v1/bootstrap/adopt", http.StatusTeapot, ""},
		{":443", "192.0.2.5", "/login", http.StatusPermanentRedirect, "https://192.0.2.5/login"},
		{":443", "192.0.2.5:80", "/setup/nodes?x=1", http.StatusPermanentRedirect, "https://192.0.2.5/setup/nodes?x=1"},
		{":8443", "node-a", "/", http.StatusPermanentRedirect, "https://node-a:8443/"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, c.path, nil)
		req.Host = c.host
		rec := httptest.NewRecorder()
		redirectPagesToHTTPS(next, c.tlsAddr).ServeHTTP(rec, req)
		if rec.Code != c.wantCode || rec.Header().Get("Location") != c.wantLoc {
			t.Errorf("%s %s: got %d %q, want %d %q", c.host, c.path, rec.Code, rec.Header().Get("Location"), c.wantCode, c.wantLoc)
		}
	}
}
