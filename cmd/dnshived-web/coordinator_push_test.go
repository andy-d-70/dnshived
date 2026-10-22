// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"dnshived/internal/webauth"
)

func TestPushConfigViaCoordinator_DocumentsIncludeSelf(t *testing.T) {
	local := newLocalConfigServer(t, "core-3", "192.0.2.24:9443")
	port := localPort(t, local)

	var captured map[string]json.RawMessage
	coordinator := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Documents map[string]json.RawMessage `json:"documents"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode coordinator request: %v", err)
		}
		captured = req.Documents
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"coordinator":"192.0.2.24:9443","results":{"192.0.2.24:9443":{"applied":true}}}`)
	}))
	defer coordinator.Close()

	coordAddr := coordinator.Listener.Addr().String()
	cfg := &WebConfig{
		Nodes: []NodeConfig{
			{Name: "core-1", Addr: "192.0.2.22:" + port, AdminToken: "tok"},
			{Name: "core-2", Addr: "192.0.2.23:" + port, AdminToken: "tok"},
		},
		CoordinatorNode: &NodeConfig{Name: "core-3", Addr: coordAddr, AdminToken: "tok"},
	}

	rec := httptest.NewRecorder()
	user := webauth.User{Name: "automation", Role: "admin"}
	pushConfigViaCoordinator(rec, cfg, configPushPayload{}, user, "/", "back", func() {})

	if captured == nil {
		t.Fatal("coordinator never received a request")
	}
	if _, ok := captured["192.0.2.24:9443"]; !ok {
		t.Errorf("documents map missing self's own address (192.0.2.24:9443) — got keys: %v", keysOf(captured))
	}
	if _, ok := captured["192.0.2.22:"+port]; !ok {
		t.Errorf("documents map missing worker-a's address")
	}
	if _, ok := captured["192.0.2.23:"+port]; !ok {
		t.Errorf("documents map missing worker-b's address")
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func TestPushConfigViaCoordinator_SurfacesRealErrorOnRejection(t *testing.T) {
	coordinator := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"no document provided for this node's own address"}`)
	}))
	defer coordinator.Close()

	coordAddr := coordinator.Listener.Addr().String()
	cfg := &WebConfig{
		CoordinatorNode: &NodeConfig{Name: "core-3", Addr: coordAddr, AdminToken: "tok"},
	}

	rec := httptest.NewRecorder()
	user := webauth.User{Name: "automation", Role: "admin"}
	pushConfigViaCoordinator(rec, cfg, configPushPayload{}, user, "/", "back", func() {})

	body := rec.Body.String()
	if !strings.Contains(body, "no document provided for this node") {
		t.Errorf("rendered page does not surface the real coordinator error text, got:\n%s", body)
	}
	if strings.Contains(body, "coordinator reported no result for this node") {
		t.Errorf("rendered page still shows the old, misleading generic message:\n%s", body)
	}
	if !strings.Contains(body, "rejected") {
		t.Errorf("rendered page does not indicate the push was rejected, got:\n%s", body)
	}
}

func TestPushConfigViaCoordinator_ShowsAnimatedDotsAndHintWhilePending(t *testing.T) {
	coordinator := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"coordinator":"core-3","results":{}}`)
	}))
	defer coordinator.Close()

	coordAddr := coordinator.Listener.Addr().String()
	cfg := &WebConfig{
		CoordinatorNode: &NodeConfig{Name: "core-3", Addr: coordAddr, AdminToken: "tok"},
	}

	rec := httptest.NewRecorder()
	user := webauth.User{Name: "automation", Role: "admin"}
	pushConfigViaCoordinator(rec, cfg, configPushPayload{}, user, "/", "back", func() {})

	body := rec.Body.String()
	if !strings.Contains(body, `class="loading-dots"`) {
		t.Errorf("rendered page missing the animated loading-dots span, got:\n%s", body)
	}
	if !strings.Contains(body, "can take several seconds") {
		t.Errorf("rendered page missing the explanatory hint about DHCP-affecting pushes, got:\n%s", body)
	}
}

func TestPushConfigViaCoordinator_LockedStillHandledAsFrozen(t *testing.T) {
	coordinator := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusLocked)
		fmt.Fprint(w, `{"frozen":true,"reason":"arbiter unreachable"}`)
	}))
	defer coordinator.Close()

	coordAddr := coordinator.Listener.Addr().String()
	cfg := &WebConfig{
		CoordinatorNode: &NodeConfig{Name: "core-3", Addr: coordAddr, AdminToken: "tok"},
	}

	rec := httptest.NewRecorder()
	user := webauth.User{Name: "automation", Role: "admin"}
	pushConfigViaCoordinator(rec, cfg, configPushPayload{}, user, "/", "back", func() {})

	body := rec.Body.String()
	if !strings.Contains(body, "frozen") {
		t.Errorf("rendered page does not show the frozen-config message, got:\n%s", body)
	}
	if !strings.Contains(body, "arbiter unreachable") {
		t.Errorf("rendered page does not surface the real frozen reason, got:\n%s", body)
	}
}
