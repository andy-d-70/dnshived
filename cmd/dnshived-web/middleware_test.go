// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSameOriginGuard(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := sameOriginGuard(func() []string { return []string{"192.0.2.254"} }, ok)
	cases := []struct {
		name    string
		method  string
		headers map[string]string
		want    int
	}{
		{"GET from anywhere", http.MethodGet, map[string]string{"Sec-Fetch-Site": "cross-site"}, 200},
		{"POST same-origin fetch", http.MethodPost, map[string]string{"Sec-Fetch-Site": "same-origin"}, 200},
		{"POST cross-site fetch", http.MethodPost, map[string]string{"Sec-Fetch-Site": "cross-site"}, 403},
		{"POST same-site other host", http.MethodPost, map[string]string{"Sec-Fetch-Site": "same-site"}, 403},
		{"POST matching Origin", http.MethodPost, map[string]string{"Origin": "https://node1:8443"}, 200},
		{"POST Origin is the VIP", http.MethodPost, map[string]string{"Origin": "https://192.0.2.254:8443"}, 200},
		{"POST foreign Origin", http.MethodPost, map[string]string{"Origin": "https://evil.example"}, 403},
		{"POST null Origin", http.MethodPost, map[string]string{"Origin": "null"}, 403},
		{"POST foreign Referer", http.MethodPost, map[string]string{"Referer": "https://evil.example/x"}, 403},
		{"POST script, no browser headers", http.MethodPost, nil, 200},
		{"POST Bearer token API", http.MethodPost, map[string]string{"Authorization": "Bearer tok", "Sec-Fetch-Site": "cross-site"}, 200},
		{"POST Basic auth cross-site", http.MethodPost, map[string]string{"Authorization": "Basic YTpi", "Origin": "https://evil.example"}, 403},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, "https://node1:8443/pending/commit", nil)
		for k, v := range c.headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s: status %d, want %d", c.name, rec.Code, c.want)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://node1/", nil))
	for _, k := range []string{"X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy", "Strict-Transport-Security"} {
		if rec.Header().Get(k) == "" {
			t.Errorf("missing %s", k)
		}
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Error("CSP does not forbid framing")
	}
}

func TestCompressResponses(t *testing.T) {
	page := strings.Repeat("<tr><td>scope</td></tr>", 500)
	h := compressResponses(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/page":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, page)
		case "/download":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write([]byte("binary"))
		case "/stream":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			io.WriteString(w, "step 1\n")
			w.(http.Flusher).Flush()
			io.WriteString(w, "step 2\n")
		}
	}))
	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Accept-Encoding", "gzip, deflate")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	unzip := func(rec *httptest.ResponseRecorder) string {
		zr, err := gzip.NewReader(rec.Body)
		if err != nil {
			t.Fatalf("gunzip: %v", err)
		}
		b, _ := io.ReadAll(zr)
		return string(b)
	}

	rec := get("/page")
	if rec.Header().Get("Content-Encoding") != "gzip" || rec.Body.Len() >= len(page)/4 {
		t.Fatalf("page not compressed: encoding=%q size=%d of %d", rec.Header().Get("Content-Encoding"), rec.Body.Len(), len(page))
	}
	if got := unzip(rec); got != page {
		t.Error("page content changed by compression")
	}
	if rec := get("/download"); rec.Header().Get("Content-Encoding") != "" || rec.Body.String() != "binary" {
		t.Error("binary download must pass through uncompressed")
	}
	rec = get("/stream")
	if !rec.Flushed {
		t.Error("streamed response no longer flushes")
	}
	if got := unzip(rec); got != "step 1\nstep 2\n" {
		t.Errorf("stream = %q", got)
	}
	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	plain := httptest.NewRecorder()
	h.ServeHTTP(plain, req)
	if plain.Header().Get("Content-Encoding") != "" || plain.Body.String() != page {
		t.Error("client without gzip support got a compressed page")
	}
}

func TestLimitBody(t *testing.T) {
	h := limitBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, "too large", http.StatusRequestEntityTooLarge)
		}
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(strings.Repeat("a", maxRequestBody+1))))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body accepted: %d", rec.Code)
	}
}
