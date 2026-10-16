// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDoGetJSON_Success pins the basic happy path: a 200 response decodes
// into v with no reason string.
func TestDoGetJSON_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"cluster_id":"lab01"}`))
	}))
	defer srv.Close()

	var s nodeStatus
	reason, err := doGetJSON(strings.TrimPrefix(srv.URL, "http://"), "/api/v1/status", &s)
	if err != nil {
		t.Fatalf("doGetJSON() error = %v", err)
	}
	if reason != "" {
		t.Errorf("reason = %q, want empty on success", reason)
	}
	if s.ClusterID != "lab01" {
		t.Errorf("ClusterID = %q, want lab01", s.ClusterID)
	}
}

func TestDoGetJSON_AuthFailedReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"missing token"}`))
	}))
	defer srv.Close()

	var c clusterView
	reason, err := doGetJSON(strings.TrimPrefix(srv.URL, "http://"), "/api/v1/cluster", &c)
	if err == nil {
		t.Fatal("doGetJSON() error = nil, want an error for a 401 response")
	}
	if !strings.Contains(reason, "auth failed") {
		t.Errorf("reason = %q, want it to mention auth failed", reason)
	}
}

// TestDoGetJSON_NonAuthHTTPError pins the generic non-2xx case (no "auth
// failed" wording, just the plain status code).
func TestDoGetJSON_NonAuthHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	var t2 tokenStatus
	reason, err := doGetJSON(strings.TrimPrefix(srv.URL, "http://"), "/api/v1/token/status", &t2)
	if err == nil {
		t.Fatal("doGetJSON() error = nil, want an error for a 500 response")
	}
	if reason != "HTTP 500" {
		t.Errorf("reason = %q, want %q", reason, "HTTP 500")
	}
}

// TestDoGetJSON_BadBody pins the decode-failure case: a 200 response with
// a body that doesn't parse as JSON at all.
func TestDoGetJSON_BadBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	var s nodeStatus
	reason, err := doGetJSON(strings.TrimPrefix(srv.URL, "http://"), "/api/v1/status", &s)
	if err == nil {
		t.Fatal("doGetJSON() error = nil, want an error for an unparseable body")
	}
	if reason != "bad response body" {
		t.Errorf("reason = %q, want %q", reason, "bad response body")
	}
}
