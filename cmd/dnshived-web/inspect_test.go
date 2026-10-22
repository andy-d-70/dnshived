// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestFormatInspectResult_AllDetectedReadsClean confirms the happy path
// — every trunk matched by name — reads as a clear go-ahead.
func TestFormatInspectResult_AllDetectedReadsClean(t *testing.T) {
	out := formatInspectResult("192.0.2.25:9443", inspectResponse{
		OK: true, OS: "Debian GNU/Linux 13 (trixie)",
		CandidateInterfaces: []string{"ens19", "ens20"},
		Mapping:             map[string]string{"ens19": "ens19", "ens20": "ens20"},
	})
	if !strings.Contains(out, "Debian GNU/Linux 13 (trixie)") {
		t.Errorf("expected OS in output, got:\n%s", out)
	}
	if !strings.Contains(out, "ens19 -> ens19 (detected, name matches)") {
		t.Errorf("expected a clean match line, got:\n%s", out)
	}
	if !strings.Contains(out, "Every trunk was physically detected") {
		t.Errorf("expected the all-clear summary, got:\n%s", out)
	}
}

// TestFormatInspectResult_UndetectedTrunkWarnsClearly checks an undetected
// trunk assignment tells the operator to choose one.
func TestFormatInspectResult_UndetectedTrunkWarnsClearly(t *testing.T) {
	out := formatInspectResult("192.0.2.25:9443", inspectResponse{
		OK: true, OS: "Debian GNU/Linux 13 (trixie)",
		CandidateInterfaces: []string{"ens19"},
		Mapping:             map[string]string{"ens19": "ens19", "ens20": ""},
	})
	if !strings.Contains(out, "ens20 -> NOT DETECTED") {
		t.Errorf("expected an explicit NOT DETECTED line for ens20, got:\n%s", out)
	}
	if strings.Contains(out, "Every trunk was physically detected") {
		t.Error("must not claim every trunk was detected when one wasn't")
	}
	if !strings.Contains(out, "Do not assume it's fine") {
		t.Errorf("expected the explicit caution summary, got:\n%s", out)
	}
}

func TestFormatInspectResult_DifferentNameFlaggedNotSilentlyAccepted(t *testing.T) {
	out := formatInspectResult("192.0.2.25:9443", inspectResponse{
		OK: true, OS: "Some OS",
		CandidateInterfaces: []string{"eth1"},
		Mapping:             map[string]string{"ens19": "eth1"},
	})
	if !strings.Contains(out, `ens19 -> eth1 (detected, but the candidate calls it "eth1" — names differ)`) {
		t.Errorf("expected a name-mismatch line, got:\n%s", out)
	}
}

func TestFormatInspectResult_VersionMismatchWarnsButDoesNotBlock(t *testing.T) {
	out := formatInspectResult("192.0.2.25:9443", inspectResponse{
		OK: true, OS: "Debian GNU/Linux 13 (trixie)",
		CandidateInterfaces: []string{"ens19"},
		Mapping:             map[string]string{"ens19": "ens19"},
		CandidateVersion:    "0.9.5-3+abc1234", ThisVersion: "0.9.8-63+c313d6a", VersionMismatch: true,
	})
	if !strings.Contains(out, "VERSION MISMATCH") {
		t.Errorf("expected a version mismatch warning, got:\n%s", out)
	}
	if !strings.Contains(out, "0.9.5-3+abc1234") || !strings.Contains(out, "0.9.8-63+c313d6a") {
		t.Errorf("expected both real version strings in the warning, got:\n%s", out)
	}
	if !strings.Contains(out, "at your own risk") {
		t.Errorf("expected the explicit go-ahead-at-your-own-risk framing, got:\n%s", out)
	}
	if !strings.Contains(out, "Every trunk was physically detected") {
		t.Errorf("a version mismatch must not suppress the normal all-clear summary, got:\n%s", out)
	}
}

// TestFormatInspectResult_NoVersionMismatchIsSilent confirms the common
// case (same version, or a candidate that never reported one) prints no
// warning at all.
func TestFormatInspectResult_NoVersionMismatchIsSilent(t *testing.T) {
	out := formatInspectResult("192.0.2.25:9443", inspectResponse{
		OK: true, OS: "Some OS",
		CandidateInterfaces: []string{"ens19"},
		Mapping:             map[string]string{"ens19": "ens19"},
	})
	if strings.Contains(out, "VERSION MISMATCH") {
		t.Errorf("expected no version warning when VersionMismatch is false, got:\n%s", out)
	}
}

// TestFormatInspectResult_FailureShowsError confirms a hard failure (e.g.
// candidate unreachable) is shown plainly, not silently blank.
func TestFormatInspectResult_FailureShowsError(t *testing.T) {
	out := formatInspectResult("192.0.2.25:9443", inspectResponse{OK: false, Error: "reach candidate: dial tcp: timeout"})
	if !strings.Contains(out, "FAILED: reach candidate: dial tcp: timeout") {
		t.Errorf("expected the failure reason surfaced, got:\n%s", out)
	}
}

func TestInspectNodeFormHandler_Core3CanBeTheRunnerNow(t *testing.T) {
	var hitPath string
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		json.NewEncoder(w).Encode(inspectResponse{OK: true, OS: "Test OS", Mapping: map[string]string{}})
	}))
	defer core.Close()
	core3Addr := strings.TrimPrefix(core.URL, "http://")

	cfg := &WebConfig{Nodes: []NodeConfig{
		{Name: "core-3", Addr: core3Addr}, // first in order, reachable — must be picked
		{Name: "core-1", Addr: "192.0.2.99:9443"},
	}}
	req := httptest.NewRequest(http.MethodPost, "/nodes/inspect", strings.NewReader("addr=192.0.2.25:9443"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	inspectNodeFormHandler(newConfigRef(cfg))(rec, req)

	if hitPath != "/api/v1/nodes/inspect" {
		t.Errorf("hit path = %q, want /api/v1/nodes/inspect — core-3 is the first core node and must be usable as the runner", hitPath)
	}
	if !strings.Contains(rec.Body.String(), "Test OS") {
		t.Errorf("expected the inspection result in the response body, got:\n%s", rec.Body.String())
	}
}

// TestInspectNodeFormHandler_RequiresAddr covers basic validation.
func TestInspectNodeFormHandler_RequiresAddr(t *testing.T) {
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: "x"}}}
	req := httptest.NewRequest(http.MethodPost, "/nodes/inspect", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	inspectNodeFormHandler(newConfigRef(cfg))(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
