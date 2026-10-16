// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dnshived/internal/cluster"
	"dnshived/internal/config"
	"dnshived/internal/identity"
)

func TestReplaceNodeHandler_RefusesUndetectedTrunkWithoutChanges(t *testing.T) {
	candidate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(bootstrapStatusResponse{Hostname: "cand", Interfaces: nil, MgmtInterface: "eth0"})
	}))
	defer candidate.Close()

	origCfg := currentConfig.Load()
	t.Cleanup(func() { currentConfig.Store(origCfg) })
	cfg := &config.Cluster{Role: "core-1", ControlAddr: "192.168.0.51:9443",
		Platform: &config.Platform{Mgmt: "ens18", Workers: []string{"ens19"}}}
	currentConfig.Store(cfg)
	cfgPath := filepath.Join(t.TempDir(), "cluster.json")

	observer := cluster.NewObserver(identity.Identity{Role: "core-1"}, "192.168.0.51:9443", nil, "")
	handler := replaceNodeHandler(cfgPath, observer, nil, nil, nil)

	body, _ := json.Marshal(replaceNodeRequest{Role: "core-3", Addr: candidateAt(t, candidate), OTP: "x"})
	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodPost, "/api/v1/nodes/replace", bytes.NewReader(body)))

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "trunk ens19") {
		t.Errorf("response does not name the undetected trunk: %s", rec.Body.String())
	}
	if _, err := os.Stat(cfgPath); !os.IsNotExist(err) {
		t.Errorf("refused replace wrote %s (stat err %v)", cfgPath, err)
	}
}
