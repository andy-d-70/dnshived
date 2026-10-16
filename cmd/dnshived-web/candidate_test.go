// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"dnshived/internal/config"
)

// candidateStub serves GET /api/v1/candidate and GET /api/v1/config for
// one fake node.
func candidateStub(t *testing.T, hasCandidate bool, candidateScope string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/candidate":
			if hasCandidate {
				json.NewEncoder(w).Encode(candidateResponse{
					Exists:    true,
					Candidate: config.Cluster{Scopes: map[string]config.ScopeConfig{candidateScope: {}}},
				})
			} else {
				json.NewEncoder(w).Encode(candidateResponse{Exists: false})
			}
		case r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{Scopes: map[string]config.ScopeConfig{"office": {}}})
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
}

// noOpCandidateStub serves a candidate that's byte-identical to live.
func noOpCandidateStub(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cluster := config.Cluster{Scopes: map[string]config.ScopeConfig{"test2": {VLANID: 42}}}
		switch r.URL.Path {
		case "/api/v1/candidate":
			json.NewEncoder(w).Encode(candidateResponse{Exists: true, Candidate: cluster})
		case "/api/v1/config":
			json.NewEncoder(w).Encode(cluster)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
}

func TestCurrentEditableConfig_NoOpCandidateIsNotReportedAsPending(t *testing.T) {
	srv := noOpCandidateStub(t)
	defer srv.Close()
	nodes := []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}

	_, _, isPending, err := currentEditableConfig(nodes)
	if err != nil {
		t.Fatalf("currentEditableConfig: %v", err)
	}
	if isPending {
		t.Error("expected isPending=false — the candidate is byte-identical to live, not a real pending change")
	}
}

func TestCurrentEditableConfig_ChecksAllNodesBeforeFallingBackToLive(t *testing.T) {
	nodeA := candidateStub(t, false, "")
	defer nodeA.Close()
	nodeB := candidateStub(t, true, "staged-scope")
	defer nodeB.Close()

	nodes := []NodeConfig{
		{Name: "core-1", Addr: strings.TrimPrefix(nodeA.URL, "http://")},
		{Name: "core-2", Addr: strings.TrimPrefix(nodeB.URL, "http://")},
	}

	c, _, isPending, err := currentEditableConfig(nodes)
	if err != nil {
		t.Fatalf("currentEditableConfig: %v", err)
	}
	if !isPending {
		t.Fatal("expected isPending=true — node B's real candidate must not be missed just because node A (tried first) has none")
	}
	if _, ok := c.Scopes["staged-scope"]; !ok {
		t.Errorf("expected the returned config to be node B's candidate (with staged-scope), got: %+v", c.Scopes)
	}
	if _, ok := c.Scopes["office"]; ok {
		t.Error("must not have silently fallen back to live (which only has 'office', not 'staged-scope')")
	}
}

func TestCurrentEditableConfig_FallsBackToLiveWhenNoNodeHasCandidate(t *testing.T) {
	nodeA := candidateStub(t, false, "")
	defer nodeA.Close()
	nodeB := candidateStub(t, false, "")
	defer nodeB.Close()

	nodes := []NodeConfig{
		{Name: "core-1", Addr: strings.TrimPrefix(nodeA.URL, "http://")},
		{Name: "core-2", Addr: strings.TrimPrefix(nodeB.URL, "http://")},
	}

	c, _, isPending, err := currentEditableConfig(nodes)
	if err != nil {
		t.Fatalf("currentEditableConfig: %v", err)
	}
	if isPending {
		t.Error("expected isPending=false when no node has a candidate")
	}
	if _, ok := c.Scopes["office"]; !ok {
		t.Errorf("expected live config (with 'office'), got: %+v", c.Scopes)
	}
}

func TestFirstReachableCandidate_ChecksAllNodesBeforeReportingNone(t *testing.T) {
	nodeA := candidateStub(t, false, "")
	defer nodeA.Close()
	nodeB := candidateStub(t, true, "staged-scope")
	defer nodeB.Close()

	nodes := []NodeConfig{
		{Name: "core-1", Addr: strings.TrimPrefix(nodeA.URL, "http://")},
		{Name: "core-2", Addr: strings.TrimPrefix(nodeB.URL, "http://")},
	}

	c, exists, _, err := firstReachableCandidate(nodes)
	if err != nil {
		t.Fatalf("firstReachableCandidate: %v", err)
	}
	if !exists {
		t.Fatal("expected exists=true — node B's real candidate must not be missed")
	}
	if _, ok := c.Scopes["staged-scope"]; !ok {
		t.Errorf("expected node B's candidate, got: %+v", c.Scopes)
	}
}
