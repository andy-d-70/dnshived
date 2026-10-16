// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"strings"
	"testing"

	"dnshived/internal/config"
)

func TestRefreshPendingHasChanges_StagedNodeOpSetsMarkerTrue(t *testing.T) {
	t.Cleanup(clearNodeOp)
	pendingHasChanges.Store(false)

	if err := stageNodeOp(pendingNodeOp{Kind: nodeOpOffboard, Role: "core-2"}); err != nil {
		t.Fatalf("stage: %v", err)
	}

	ref := newConfigRef(&WebConfig{})
	refreshPendingHasChanges(ref)

	if !pendingHasChanges.Load() {
		t.Error("pendingHasChanges = false, want true with a node action staged")
	}
}

func TestRefreshPendingHasChanges_ClearedNodeOpFallsThroughToCandidateCheck(t *testing.T) {
	t.Cleanup(clearNodeOp)
	pendingHasChanges.Store(true)

	if err := stageNodeOp(pendingNodeOp{Kind: nodeOpOffboard, Role: "core-2"}); err != nil {
		t.Fatalf("stage: %v", err)
	}
	clearNodeOp()

	srv := candidateTestServer(t, config.Cluster{}, nil) // no candidate anywhere
	defer srv.Close()
	ref := newConfigRef(&WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}})
	refreshPendingHasChanges(ref)

	if pendingHasChanges.Load() {
		t.Error("pendingHasChanges = true, want false once the node op is discarded and no candidate exists")
	}
}
