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
	return removeCandidateAuthors(dataDir)
}

// applyCandidateUpdate is POST /api/v1/candidate's core logic — the
// staged-config counterpart to applyConfigUpdate.
func applyCandidateUpdate(dataDir, cfgPath string, upd configUpdate) (status int, body interface{}) {
	if j := cfgJournal.Load(); j != nil {
		return applyCandidateThroughJournal(j, dataDir, cfgPath, upd)
	}
	candidateMu.Lock()
	defer candidateMu.Unlock()
	live, err := config.Load(cfgPath)
	if err != nil {
		return http.StatusInternalServerError, map[string]string{"error": "load live config: " + err.Error()}
	}

	accessUpd, err := parseAccessUpdate(upd.Access)
	if err != nil {
		return http.StatusBadRequest, map[string]string{"error": err.Error()}
	}
	candidate := *live
	upd.applyTo(&candidate)
	accessUpd.applyTo(&candidate)

	result := candidate.ValidateExtended()
	if !result.OK() {
		return http.StatusBadRequest, result
	}

	old, _, _ := loadCandidateConfig(dataDir)
	recordCandidateAuthors(dataDir, live, old, &candidate, upd.Author)
	if err := config.Save(candidatePath(dataDir), &candidate); err != nil {
		return http.StatusInternalServerError, map[string]string{"error": "save candidate: " + err.Error()}
	}
	return http.StatusOK, map[string]interface{}{"ok": true, "warnings": result.Warnings}
}

// discardCandidateScope reverts exactly one scope inside the candidate
// back to its live value.
func discardCandidateScope(dataDir, cfgPath, scope string) error {
	candidateMu.Lock()
	defer candidateMu.Unlock()
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
	if err := config.Save(candidatePath(dataDir), candidate); err != nil {
		return err
	}
	pruneCandidateAuthors(dataDir, live, candidate)
	return nil
}

// applyCandidateThroughJournal stages a whole candidate as the existing web sends it while the configuration journal
// runs: the cluster-wide part as staged items, secrets and identity in the per-core candidate file.
func applyCandidateThroughJournal(j *cfgJournalRuntime, dataDir, cfgPath string, upd configUpdate) (int, interface{}) {
	cfgWriteMu.Lock()
	defer cfgWriteMu.Unlock()
	live, err := config.Load(cfgPath)
	if err != nil {
		return http.StatusInternalServerError, map[string]string{"error": "load live config: " + err.Error()}
	}
	accessUpd, err := parseAccessUpdate(upd.Access)
	if err != nil {
		return http.StatusBadRequest, map[string]string{"error": err.Error()}
	}
	next := *live
	upd.applyTo(&next)
	accessUpd.applyTo(&next)
	result := next.ValidateExtended()
	if !result.OK() {
		return http.StatusBadRequest, result
	}
	if err := j.stageLocked(dataDir, &next, upd.Author); err != nil {
		return proposeStatus(err), proposeError(err)
	}
	return http.StatusOK, map[string]interface{}{"ok": true, "warnings": result.Warnings}
}
