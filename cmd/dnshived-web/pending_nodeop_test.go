// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"dnshived/internal/config"
	"dnshived/internal/webauth"
)

// TestStageNodeOp_RefusesASecondOpWhileOneIsStaged confirms only one node
// action can ever be staged at a time.
func TestStageNodeOp_RefusesASecondOpWhileOneIsStaged(t *testing.T) {
	t.Cleanup(clearNodeOp)
	if err := stageNodeOp(pendingNodeOp{Kind: nodeOpOffboard, Role: "core-2"}); err != nil {
		t.Fatalf("first stage: %v", err)
	}
	if err := stageNodeOp(pendingNodeOp{Kind: nodeOpOffboard, Role: "core-1"}); err == nil {
		t.Fatal("expected an error staging a second node op while one is already staged")
	}
	op := currentNodeOp()
	if op == nil || op.Role != "core-2" {
		t.Fatalf("currentNodeOp() = %+v, want the FIRST staged op untouched", op)
	}
}

func TestHandlePendingNodeOpCommit_ExecutesAndClearsTheStagedOp(t *testing.T) {
	t.Cleanup(clearNodeOp)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer target.Close()
	targetAddr := strings.TrimPrefix(target.URL, "http://")

	cfgPath := filepath.Join(t.TempDir(), "web.json")
	cfg := &WebConfig{Nodes: []NodeConfig{
		{Name: "core-1", Addr: "192.0.2.22:9443"},
		{Name: "core-2", Addr: "192.0.2.23:9443"},
		{Name: "core-3", Addr: targetAddr},
	}}
	ref := newConfigRef(cfg)

	if err := stageNodeOp(pendingNodeOp{Kind: nodeOpOffboard, Role: "core-3", StagedBy: "tester"}); err != nil {
		t.Fatalf("stage: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/pending/nodeop/commit", nil)
	req = req.WithContext(context.WithValue(req.Context(), userContextKey{}, webauth.User{Name: "tester"}))
	rec := httptest.NewRecorder()
	handlePendingNodeOpCommit(cfgPath, ref)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if len(ref.Load().Nodes) != 2 {
		t.Fatalf("cfg.Nodes = %v, want the 2 remaining core roles after committing the offboard", ref.Load().Nodes)
	}
	if op := currentNodeOp(); op != nil {
		t.Fatalf("currentNodeOp() = %+v, want nil after a successful commit", op)
	}

	// A second commit with nothing staged must be a harmless redirect,
	// never a repeat of the same action.
	rec2 := httptest.NewRecorder()
	handlePendingNodeOpCommit(cfgPath, ref)(rec2, req)
	if rec2.Code != http.StatusSeeOther {
		t.Errorf("second commit with nothing staged: status = %d, want %d", rec2.Code, http.StatusSeeOther)
	}
}

func TestHandlePendingNodeOpCommit_RequiresConfirmWipeCheckboxForLastNode(t *testing.T) {
	t.Cleanup(clearNodeOp)
	var offboardCalled bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offboardCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer target.Close()
	targetAddr := strings.TrimPrefix(target.URL, "http://")

	cfgPath := filepath.Join(t.TempDir(), "web.json")
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: targetAddr}}}
	ref := newConfigRef(cfg)

	if err := stageNodeOp(pendingNodeOp{Kind: nodeOpOffboard, Role: "core-1", LeavesZeroCoreNodes: true, StagedBy: "tester"}); err != nil {
		t.Fatalf("stage: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/pending/nodeop/commit", nil)
	req = req.WithContext(context.WithValue(req.Context(), userContextKey{}, webauth.User{Name: "tester"}))
	rec := httptest.NewRecorder()
	handlePendingNodeOpCommit(cfgPath, ref)(rec, req)

	if !strings.Contains(rec.Body.String(), "FAILED") {
		t.Errorf("without confirm_wipe, body = %q, want a FAILED refusal", rec.Body.String())
	}
	if offboardCalled {
		t.Error("target's own /api/v1/nodes/offboard was called despite no confirm_wipe field — the gate didn't hold")
	}
	if len(ref.Load().Nodes) != 1 {
		t.Fatalf("cfg.Nodes = %v, want core-1 left untouched by the refused commit", ref.Load().Nodes)
	}

	// Re-stage (the failed attempt above already cleared the op) and
	// retry with the checkbox present.
	if err := stageNodeOp(pendingNodeOp{Kind: nodeOpOffboard, Role: "core-1", LeavesZeroCoreNodes: true, StagedBy: "tester"}); err != nil {
		t.Fatalf("re-stage: %v", err)
	}
	req2 := httptest.NewRequest(http.MethodPost, "/pending/nodeop/commit", strings.NewReader("confirm_wipe=on"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2 = req2.WithContext(context.WithValue(req2.Context(), userContextKey{}, webauth.User{Name: "tester"}))
	rec2 := httptest.NewRecorder()
	handlePendingNodeOpCommit(cfgPath, ref)(rec2, req2)

	if strings.Contains(rec2.Body.String(), "FAILED") {
		t.Errorf("with confirm_wipe=on, body = %q, want it to proceed", rec2.Body.String())
	}
	if !offboardCalled {
		t.Error("target's own /api/v1/nodes/offboard was never called despite confirm_wipe=on")
	}
	if len(ref.Load().Nodes) != 0 {
		t.Fatalf("cfg.Nodes = %v, want core-1 actually removed once confirmed", ref.Load().Nodes)
	}
}

func TestHandlePendingNodeOpCommit_ForceOffboardSkipsLiveCallToTarget(t *testing.T) {
	t.Cleanup(clearNodeOp)
	var offboardCalled bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/nodes/offboard" {
			offboardCalled = true
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer target.Close()
	targetAddr := strings.TrimPrefix(target.URL, "http://")

	cfgPath := filepath.Join(t.TempDir(), "web.json")
	cfg := &WebConfig{Nodes: []NodeConfig{
		{Name: "core-1", Addr: targetAddr},
		{Name: "core-2", Addr: "192.0.2.23:9443"},
	}}
	ref := newConfigRef(cfg)

	if err := stageNodeOp(pendingNodeOp{Kind: nodeOpOffboard, Role: "core-1", StagedBy: "tester"}); err != nil {
		t.Fatalf("stage: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/pending/nodeop/commit", strings.NewReader("confirm_force=on"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), userContextKey{}, webauth.User{Name: "tester"}))
	rec := httptest.NewRecorder()
	handlePendingNodeOpCommit(cfgPath, ref)(rec, req)

	if strings.Contains(rec.Body.String(), "FAILED") {
		t.Errorf("with confirm_force=on, body = %q, want it to proceed", rec.Body.String())
	}
	if offboardCalled {
		t.Error("target's own /api/v1/nodes/offboard WAS called despite confirm_force=on — force must never contact an unreachable node")
	}
	if len(ref.Load().Nodes) != 1 || ref.Load().Nodes[0].Name != "core-2" {
		t.Fatalf("cfg.Nodes = %v, want only core-2 left, core-1 removed from the surviving side even though it was never contacted", ref.Load().Nodes)
	}
}

// TestHandlePendingNodeOpCommit_ClearsOpEvenOnFailure confirms a failed
// commit (target unreachable) still clears the staged op.
func TestHandlePendingNodeOpCommit_ClearsOpEvenOnFailure(t *testing.T) {
	t.Cleanup(clearNodeOp)
	cfgPath := filepath.Join(t.TempDir(), "web.json")
	// No nodes configured at all — executeReplaceProbe fails immediately.
	cfg := &WebConfig{}
	ref := newConfigRef(cfg)

	if err := stageNodeOp(pendingNodeOp{Kind: nodeOpReplace, Role: probeRoleName, Addr: "192.0.2.99:9443", JoinCode: "X", Onboarding: true}); err != nil {
		t.Fatalf("stage: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/pending/nodeop/commit", nil)
	req = req.WithContext(context.WithValue(req.Context(), userContextKey{}, webauth.User{Name: "tester"}))
	rec := httptest.NewRecorder()
	handlePendingNodeOpCommit(cfgPath, ref)(rec, req)

	if !strings.Contains(rec.Body.String(), "FAILED") {
		t.Errorf("expected a FAILED response body, got: %s", rec.Body.String())
	}
	if op := currentNodeOp(); op != nil {
		t.Fatalf("currentNodeOp() = %+v, want nil even after a failed commit", op)
	}
}

// TestHandlePendingNodeOpDiscard_ClearsWithoutExecuting confirms discard
// never touches anything real — no target contacted, no config mutated.
func TestHandlePendingNodeOpDiscard_ClearsWithoutExecuting(t *testing.T) {
	t.Cleanup(clearNodeOp)
	called := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	targetAddr := strings.TrimPrefix(target.URL, "http://")

	if err := stageNodeOp(pendingNodeOp{Kind: nodeOpOffboard, Role: "core-2", Addr: targetAddr}); err != nil {
		t.Fatalf("stage: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/pending/nodeop/discard", nil)
	rec := httptest.NewRecorder()
	handlePendingNodeOpDiscard()(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if called {
		t.Fatal("discard must never contact the target node")
	}
	if op := currentNodeOp(); op != nil {
		t.Fatalf("currentNodeOp() = %+v, want nil after discard", op)
	}
}

// TestPendingNodeOp_DescribeRedactsJoinCode confirms Describe never
// includes the join code.
func TestPendingNodeOp_DescribeRedactsJoinCode(t *testing.T) {
	op := pendingNodeOp{Kind: nodeOpReplace, Role: "core-2", Addr: "192.0.2.23:9443", JoinCode: "SECRET-CODE"}
	if strings.Contains(op.Describe(), "SECRET-CODE") {
		t.Errorf("Describe() leaked the join code: %q", op.Describe())
	}
	if strings.Contains(string(op.DescribeJSON()), "SECRET-CODE") {
		t.Errorf("DescribeJSON() leaked the join code: %s", op.DescribeJSON())
	}
}

func TestPendingNodeOp_Steps_BreaksQuorumFloorPrependsWarning(t *testing.T) {
	op := pendingNodeOp{Kind: nodeOpOffboard, Role: "core-1", BreaksQuorumFloor: true}
	steps := op.Steps()
	if len(steps) == 0 {
		t.Fatal("Steps() returned nothing")
	}
	if !strings.Contains(steps[0], "fewer than 2 remaining core nodes") {
		t.Errorf("steps[0] = %q, want the quorum-floor warning first", steps[0])
	}
}

// TestPendingNodeOp_Steps_NoWarningWhenFloorNotBroken confirms the
// ordinary case (BreaksQuorumFloor false, the default zero value) has no
// warning at all.
func TestPendingNodeOp_Steps_NoWarningWhenFloorNotBroken(t *testing.T) {
	op := pendingNodeOp{Kind: nodeOpOffboard, Role: "core-1"}
	for _, s := range op.Steps() {
		if strings.Contains(s, "quorum") {
			t.Errorf("Steps() = %v, want no quorum warning when BreaksQuorumFloor is false", op.Steps())
		}
	}
}

func TestPendingNodeOp_Steps_LeavesZeroCoreNodesTakesPriorityOverQuorumWarning(t *testing.T) {
	op := pendingNodeOp{Kind: nodeOpOffboard, Role: "core-1", BreaksQuorumFloor: true, LeavesZeroCoreNodes: true}
	steps := op.Steps()
	if len(steps) == 0 {
		t.Fatal("Steps() returned nothing")
	}
	if !strings.Contains(steps[0], "PERMANENTLY WIPES") {
		t.Errorf("steps[0] = %q, want the zero-core-nodes wipe warning first", steps[0])
	}
	for _, s := range steps[1:] {
		if strings.Contains(s, "fewer than 2 remaining core nodes") {
			t.Errorf("Steps() = %v, want the generic quorum-floor warning replaced, not duplicated alongside the wipe warning", steps)
		}
	}
}

// TestHandlePending_RendersStagedNodeOp confirms /pending itself shows the
// staged action.
func TestHandlePending_RendersStagedNodeOp(t *testing.T) {
	t.Cleanup(clearNodeOp)
	srv := candidateTestServer(t, config.Cluster{}, nil)
	defer srv.Close()

	if err := stageNodeOp(pendingNodeOp{Kind: nodeOpReplace, Role: "core-2", Addr: "192.0.2.23:9443", JoinCode: "X", StagedBy: "tester"}); err != nil {
		t.Fatalf("stage: %v", err)
	}

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest(http.MethodGet, "/pending", nil)
	rec := httptest.NewRecorder()
	handlePending(newConfigRef(cfg))(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "Replace core-2 with 192.0.2.23:9443") {
		t.Errorf("expected the staged node action described on /pending, got:\n%s", body)
	}
	if !strings.Contains(body, `action="/pending/nodeop/commit"`) || !strings.Contains(body, `action="/pending/nodeop/discard"`) {
		t.Errorf("expected commit/discard forms for the node action, got:\n%s", body)
	}
	if strings.Contains(body, "confirm_wipe") {
		t.Errorf("expected no confirm_wipe checkbox for an ordinary (non-wipe) staged action, got:\n%s", body)
	}
}

func TestHandlePending_RendersConfirmWipeCheckboxForLastNode(t *testing.T) {
	t.Cleanup(clearNodeOp)
	srv := candidateTestServer(t, config.Cluster{}, nil)
	defer srv.Close()

	if err := stageNodeOp(pendingNodeOp{Kind: nodeOpOffboard, Role: "core-1", LeavesZeroCoreNodes: true, StagedBy: "tester"}); err != nil {
		t.Fatalf("stage: %v", err)
	}

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest(http.MethodGet, "/pending", nil)
	rec := httptest.NewRecorder()
	handlePending(newConfigRef(cfg))(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, `name="confirm_wipe"`) || !strings.Contains(body, "required") {
		t.Errorf("expected a required confirm_wipe checkbox, got:\n%s", body)
	}
	if !strings.Contains(body, `href="/backup"`) {
		t.Errorf("expected a link to the backup page, got:\n%s", body)
	}
	if !strings.Contains(body, "PERMANENTLY WIPE") {
		t.Errorf("expected the wipe warning text, got:\n%s", body)
	}
}
