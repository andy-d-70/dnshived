// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchJSONFrom_ReadableErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "https://192.0.2.254:8443/x", http.StatusMovedPermanently)
		case "/text":
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("authentication required\n"))
		case "/json":
			w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	_, err := fetchJSONFrom("http", addr, "/redirect", "")
	if err == nil || !strings.Contains(err.Error(), "301") || !strings.Contains(err.Error(), "wrong port") {
		t.Errorf("redirect: err = %v, want the 301 named with a port hint (and not followed)", err)
	}
	_, err = fetchJSONFrom("http", addr, "/text", "")
	if err == nil || !strings.Contains(err.Error(), "not JSON") || !strings.Contains(err.Error(), "authentication required") {
		t.Errorf("plain text: err = %v, want a not-JSON reason with the body start", err)
	}
	if body, err := fetchJSONFrom("http", addr, "/json", ""); err != nil || string(body) != `{"ok":true}` {
		t.Errorf("json: %s, %v", body, err)
	}
}
