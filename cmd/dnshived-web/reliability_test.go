// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestHandleReliabilityResetPost_RedirectsWithSuccessCount mirrors
// TestHandleBackupCreatePost_RedirectsWithSuccessCount's own shape.
func TestHandleReliabilityResetPost_RedirectsWithSuccessCount(t *testing.T) {
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer node.Close()
	n := nodeConfigFor(t, node)
	n.Name = "core-1"
	cfg := &WebConfig{Nodes: []NodeConfig{n}}

	form := strings.NewReader("role=core-2&parent=ens19")
	r := httptest.NewRequest(http.MethodPost, "/paths/reset", form)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleReliabilityResetPost(newConfigRef(cfg))(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "reset_ok=1") {
		t.Errorf("Location = %q, want it to contain reset_ok=1", loc)
	}
	if strings.Contains(loc, "reset_failed=") {
		t.Errorf("Location = %q, want no reset_failed on full success", loc)
	}
	if !strings.Contains(loc, url.QueryEscape("core-2 / ens19")) {
		t.Errorf("Location = %q, want it to name the reset target", loc)
	}
}

func TestHandleReliabilityResetPost_ReportsFailedNode(t *testing.T) {
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer node.Close()
	n := nodeConfigFor(t, node)
	n.Name = "core-1"
	cfg := &WebConfig{Nodes: []NodeConfig{n}}

	form := strings.NewReader("role=core-2&parent=ens19")
	r := httptest.NewRequest(http.MethodPost, "/paths/reset", form)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleReliabilityResetPost(newConfigRef(cfg))(w, r)

	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "reset_ok=0") {
		t.Errorf("Location = %q, want reset_ok=0", loc)
	}
	if !strings.Contains(loc, "reset_failed=core-1") {
		t.Errorf("Location = %q, want reset_failed=core-1", loc)
	}
}

func TestHandleReliabilityResetPost_MissingFieldsRedirectsWithoutAction(t *testing.T) {
	var called bool
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer node.Close()
	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, node)}}

	form := strings.NewReader("role=&parent=")
	r := httptest.NewRequest(http.MethodPost, "/paths/reset", form)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleReliabilityResetPost(newConfigRef(cfg))(w, r)

	if called {
		t.Error("handler fanned out to the node despite missing role/parent")
	}
	if w.Header().Get("Location") != "/" {
		t.Errorf("Location = %q, want plain \"/\"", w.Header().Get("Location"))
	}
}

func TestResetResultBanner_EmptyTargetRendersNothing(t *testing.T) {
	text, class := resetResultBanner(url.Values{})
	if text != "" || class != "" {
		t.Errorf("resetResultBanner(empty) = %q, %q, want empty/empty", text, class)
	}
}

func TestResetResultBanner_AllOkRendersOkClass(t *testing.T) {
	q := url.Values{"reset_target": {"core-2 / ens19"}, "reset_ok": {"3"}}
	text, class := resetResultBanner(q)
	if class != "ok" {
		t.Errorf("class = %q, want \"ok\"", class)
	}
	if !strings.Contains(text, "core-2 / ens19") || !strings.Contains(text, "3 node(s)") {
		t.Errorf("text = %q, want it to name the target and node count", text)
	}
}

func TestResetResultBanner_PartialFailureRendersWarnClass(t *testing.T) {
	q := url.Values{"reset_target": {"core-2 / ens19"}, "reset_ok": {"1"}, "reset_failed": {"core-3"}}
	text, class := resetResultBanner(q)
	if class != "warn" {
		t.Errorf("class = %q, want \"warn\"", class)
	}
	if !strings.Contains(text, "core-3") {
		t.Errorf("text = %q, want it to name the failed node", text)
	}
}
