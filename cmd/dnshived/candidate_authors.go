// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"dnshived/internal/changeset"
	"dnshived/internal/config"
	"dnshived/internal/loglevel"
)

var candidateMu sync.Mutex

const candidateAuthorsFileName = "candidate-authors.json"

func candidateAuthorsPath(dataDir string) string {
	return filepath.Join(dataDir, candidateAuthorsFileName)
}

func loadCandidateAuthors(dataDir string) map[string]string {
	raw, err := os.ReadFile(candidateAuthorsPath(dataDir))
	if err != nil {
		return map[string]string{}
	}
	out := map[string]string{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]string{}
	}
	return out
}

func saveCandidateAuthors(dataDir string, journal map[string]string) error {
	if len(journal) == 0 {
		return removeCandidateAuthors(dataDir)
	}
	raw, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	path := candidateAuthorsPath(dataDir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func removeCandidateAuthors(dataDir string) error {
	if err := os.Remove(candidateAuthorsPath(dataDir)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// recordCandidateAuthors updates the journal for a candidate that is about to
// replace old (the live document when nothing was staged). A failure is only
// logged: staging must not depend on the journal.
func recordCandidateAuthors(dataDir string, live, old, next *config.Cluster, author string) {
	if old == nil {
		old = live
	}
	tl, err1 := changeset.TreeMax(live, changeset.MaxDocBytes)
	tb, err2 := changeset.TreeMax(old, changeset.MaxDocBytes)
	tn, err3 := changeset.TreeMax(next, changeset.MaxDocBytes)
	if err := errors.Join(err1, err2, err3); err != nil {
		loglevel.Warnf("[CANDIDATE] author journal not updated, changes will show without an author: %v", err)
		if rerr := removeCandidateAuthors(dataDir); rerr != nil {
			loglevel.Warnf("[CANDIDATE] author journal not removed: %v", rerr)
		}
		return
	}
	journal := changeset.Attribute(tl, tb, tn, author, loadCandidateAuthors(dataDir))
	if err := saveCandidateAuthors(dataDir, journal); err != nil {
		loglevel.Warnf("[CANDIDATE] author journal not saved: %v", err)
	}
}

// pruneCandidateAuthors drops journal entries the candidate no longer differs
// from live at.
func pruneCandidateAuthors(dataDir string, live, cand *config.Cluster) {
	tl, err1 := changeset.TreeMax(live, changeset.MaxDocBytes)
	tn, err2 := changeset.TreeMax(cand, changeset.MaxDocBytes)
	if err := errors.Join(err1, err2); err != nil {
		loglevel.Warnf("[CANDIDATE] author journal not pruned: %v", err)
		return
	}
	if err := saveCandidateAuthors(dataDir, changeset.Prune(tl, tn, loadCandidateAuthors(dataDir))); err != nil {
		loglevel.Warnf("[CANDIDATE] author journal not saved: %v", err)
	}
}
