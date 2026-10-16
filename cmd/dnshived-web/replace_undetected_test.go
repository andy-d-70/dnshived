// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecuteReplaceNode_UndetectedTrunkRefusalIsExplained(t *testing.T) {
	var gotAllow interface{}
	survivor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		gotAllow = body["allow_undetected_trunks"]
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"error":"interface check incomplete","interface_warnings":["trunk ens20: no candidate interface heard, keeping the name ens20"]}`))
	}))
	defer survivor.Close()
	ref := newConfigRef(&WebConfig{ListenAddr: "127.0.0.1:0", Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(survivor.URL, "http://"), AdminToken: "tok"}}})

	_, err := executeReplaceNode(filepath.Join(t.TempDir(), "web.json"), ref, "tester", pendingNodeOp{Kind: nodeOpReplace, Role: "core-3", Addr: "192.168.0.26", JoinCode: "J"}, false)
	if err == nil {
		t.Fatal("refused replace returned no error")
	}
	for _, want := range []string{"nothing was changed", "trunk ens20", "/pending", "Onboard anyway"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err.Error(), want)
		}
	}
	if gotAllow != false {
		t.Errorf("allow_undetected_trunks = %v, want false", gotAllow)
	}
	for _, n := range ref.Load().Nodes {
		if n.Name == "core-3" {
			t.Error("refused replace still added core-3 to the web node list")
		}
	}
}

func TestExecuteReplaceNode_ForwardsOnboardAnyway(t *testing.T) {
	var gotAllow interface{}
	survivor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/nodes/replace" {
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			gotAllow = body["allow_undetected_trunks"]
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer survivor.Close()
	ref := newConfigRef(&WebConfig{ListenAddr: "127.0.0.1:0", Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(survivor.URL, "http://"), AdminToken: "tok"}}})

	if _, err := executeReplaceNode(filepath.Join(t.TempDir(), "web.json"), ref, "tester", pendingNodeOp{Kind: nodeOpReplace, Role: "core-3", Addr: "192.168.0.26", JoinCode: "J"}, true); err != nil {
		t.Fatalf("executeReplaceNode: %v", err)
	}
	if gotAllow != true {
		t.Errorf("allow_undetected_trunks = %v, want true", gotAllow)
	}
}
