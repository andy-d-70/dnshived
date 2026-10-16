// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDoGet_NonJSONAnswerIsReadable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>moved</html>"))
	}))
	defer srv.Close()
	var v map[string]interface{}
	_, err := doGet(directHTTPClient, NodeConfig{Name: "core-2", Addr: strings.TrimPrefix(srv.URL, "http://")}, "/api/v1/status", &v)
	if err == nil || strings.Contains(err.Error(), "invalid character") || !strings.Contains(err.Error(), "not a JSON answer") || !strings.Contains(err.Error(), "text/html") {
		t.Errorf("err = %v, want a readable not-JSON reason instead of a decoder error", err)
	}
}
