// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"dnshived/internal/config"
)

func TestFetchArbiterTokens_FallsBackToWorkerWhenArbiterUnreachable(t *testing.T) {
	workerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"test-42":{"owner":"n1","expires_at":"2026-01-01T00:00:00Z","expired":false}}`))
	}))
	defer workerSrv.Close()

	rows := []statusRow{
		{
			Node:       NodeConfig{Name: "core-3", Addr: "127.0.0.1:1"}, // unreachable, nothing listens here
			Status:     nodeStatus{Role: config.RoleCore3},
			FetchError: "dial tcp 127.0.0.1:1: connect: connection refused",
		},
		{
			Node:   NodeConfig{Name: "core-1", Addr: strings.TrimPrefix(workerSrv.URL, "http://")},
			Status: nodeStatus{Role: config.RoleCore1},
		},
	}

	tokens := fetchArbiterTokensLegacy(rows)
	tok, ok := tokens["test-42"]
	if !ok {
		t.Fatalf("fetchArbiterTokens() = %v, want a real token for test-42 via the worker fallback", tokens)
	}
	if tok.Owner != "n1" {
		t.Errorf("tokens[test-42].Owner = %q, want %q", tok.Owner, "n1")
	}
}

func TestFetchArbiterTokens_PrefersArbiterWhenReachable(t *testing.T) {
	arbiterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"test-42":{"owner":"from-arbiter","expires_at":"2026-01-01T00:00:00Z","expired":false}}`))
	}))
	defer arbiterSrv.Close()
	workerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"test-42":{"owner":"from-worker","expires_at":"2026-01-01T00:00:00Z","expired":false}}`))
	}))
	defer workerSrv.Close()

	rows := []statusRow{
		{Node: NodeConfig{Name: "core-1", Addr: strings.TrimPrefix(workerSrv.URL, "http://")}, Status: nodeStatus{Role: config.RoleCore1}},
		{Node: NodeConfig{Name: "core-3", Addr: strings.TrimPrefix(arbiterSrv.URL, "http://")}, Status: nodeStatus{Role: config.RoleCore3}},
	}

	tokens := fetchArbiterTokensLegacy(rows)
	if tok := tokens["test-42"]; tok.Owner != "from-arbiter" {
		t.Errorf("tokens[test-42].Owner = %q, want %q (arbiter preferred over a reachable worker)", tok.Owner, "from-arbiter")
	}
}

func TestFetchArbiterTokens_EmptyWhenNothingReachable(t *testing.T) {
	rows := []statusRow{
		{Node: NodeConfig{Name: "core-3"}, Status: nodeStatus{Role: config.RoleCore3}, FetchError: "unreachable"},
		{Node: NodeConfig{Name: "core-1"}, Status: nodeStatus{Role: config.RoleCore1}, FetchError: "unreachable"},
	}
	tokens := fetchArbiterTokensLegacy(rows)
	if len(tokens) != 0 {
		t.Errorf("fetchArbiterTokens() = %v, want empty when no row is reachable at all", tokens)
	}
}
