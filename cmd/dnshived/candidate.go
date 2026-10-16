// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"

	"dnshived/internal/config"
)

// candidateFileName is the on-disk name of the staged, not-yet-applied
// config document.
const candidateFileName = "candidate.json"

func candidatePath(dataDir string) string {
	return filepath.Join(dataDir, candidateFileName)
}

// loadCandidateConfig reads the staged candidate, if one exists.
func loadCandidateConfig(dataDir string) (*config.Cluster, bool, error) {
	c, err := config.Load(candidatePath(dataDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return c, true, nil
}

// discardCandidateConfig removes the staged candidate entirely — the
// "revert all pending changes" action.
func discardCandidateConfig(dataDir string) error {
	if err := os.Remove(candidatePath(dataDir)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// applyCandidateUpdate is POST /api/v1/candidate's core logic — the
// staged-config counterpart to applyConfigUpdate.
func applyCandidateUpdate(dataDir, cfgPath string, upd configUpdate) (status int, body interface{}) {
	live, err := config.Load(cfgPath)
	if err != nil {
		return http.StatusInternalServerError, map[string]string{"error": "load live config: " + err.Error()}
	}

	candidate := *live
	upd.applyTo(&candidate)

	result := candidate.ValidateExtended()
	if !result.OK() {
		return http.StatusBadRequest, result
	}

	if err := config.Save(candidatePath(dataDir), &candidate); err != nil {
		return http.StatusInternalServerError, map[string]string{"error": "save candidate: " + err.Error()}
	}
	return http.StatusOK, map[string]interface{}{"ok": true, "warnings": result.Warnings}
}

// discardCandidateScope reverts exactly one scope inside the candidate
// back to its live value.
func discardCandidateScope(dataDir, cfgPath, scope string) error {
	candidate, exists, err := loadCandidateConfig(dataDir)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	live, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if liveSC, ok := live.Scopes[scope]; ok {
		if candidate.Scopes == nil {
			candidate.Scopes = make(map[string]config.ScopeConfig)
		}
		candidate.Scopes[scope] = liveSC
	} else {
		delete(candidate.Scopes, scope)
	}
	return config.Save(candidatePath(dataDir), candidate)
}
