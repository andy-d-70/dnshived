// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"

	"dnshived/internal/cfgjournal"
	"dnshived/internal/config"
)

// With the configuration journal on, Pending is the journal's "pending" document: staged items replicated to every
// core. Secrets and identity fields (cfgjournal.Excluded) are staged in the per-core candidate file as before, so
// nothing secret enters the journal. The candidate the web reads is computed: live configuration + staged items +
// staged secrets.

// pendingLocked reads the staged items after bringing the pending document up to date. The caller holds cfgWriteMu.
func (j *cfgJournalRuntime) pendingLocked() (cfgjournal.Pending, error) {
	if _, _, err := j.pendingWriter.Sync(); err != nil {
		return nil, err
	}
	tree, _, _, err := j.pendingDoc.Load()
	if err != nil {
		return nil, err
	}
	return cfgjournal.PendingFromTree(tree)
}

func excludedChanged(live, c *config.Cluster) bool {
	lt, _ := json.Marshal(live)
	ct, _ := json.Marshal(c)
	var lm, cm map[string]json.RawMessage
	_ = json.Unmarshal(lt, &lm)
	_ = json.Unmarshal(ct, &cm)
	for k := range cfgjournal.Excluded {
		if string(lm[k]) != string(cm[k]) {
			return true
		}
	}
	return false
}

// candidateLocked is the candidate the web shows: live + staged items + staged secrets, with the author of each
// staged path. exists is false when nothing is staged. The caller holds cfgWriteMu.
func (j *cfgJournalRuntime) candidateLocked(dataDir string) (cand *config.Cluster, authors map[string]string, exists bool, err error) {
	live, err := config.Load(j.path)
	if err != nil {
		return nil, nil, false, err
	}
	pd, err := j.pendingLocked()
	if err != nil {
		return nil, nil, false, err
	}
	lt, err := cfgjournal.Replicated(live)
	if err != nil {
		return nil, nil, false, err
	}
	mat, err := pd.Materialize(lt)
	if err != nil {
		return nil, nil, false, err
	}
	if cand, err = j.doc.Candidate(mat); err != nil {
		return nil, nil, false, err
	}
	cand.ConfigRevision = live.ConfigRevision
	authors = map[string]string{}
	for p, s := range pd {
		authors[p] = s.Author
	}
	legacy, legacyExists, err := loadCandidateConfig(dataDir)
	if err != nil {
		return nil, nil, false, err
	}
	if legacyExists && excludedChanged(live, legacy) {
		if cand, err = withExcluded(cand, legacy); err != nil {
			return nil, nil, false, err
		}
		for p, a := range loadCandidateAuthors(dataDir) {
			if cfgjournal.Excluded[strings.SplitN(p, "/", 2)[0]] {
				authors[p] = a
			}
		}
	}
	return cand, authors, len(pd) > 0 || (legacyExists && excludedChanged(live, legacy)), nil
}

// withExcluded returns c with the secret and identity fields taken from src.
func withExcluded(c, src *config.Cluster) (*config.Cluster, error) {
	cm, err := toMap(c)
	if err != nil {
		return nil, err
	}
	sm, err := toMap(src)
	if err != nil {
		return nil, err
	}
	for k := range cfgjournal.Excluded {
		if v, ok := sm[k]; ok {
			cm[k] = v
		} else {
			delete(cm, k)
		}
	}
	raw, _ := json.Marshal(cm)
	var out config.Cluster
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func toMap(c *config.Cluster) (map[string]json.RawMessage, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	return m, json.Unmarshal(raw, &m)
}

// stageLocked stages a whole candidate the way the existing web sends it: its replicated part becomes staged items
// (changes against the current candidate), its secret and identity fields go to the per-core candidate file. The
// caller holds cfgWriteMu.
func (j *cfgJournalRuntime) stageLocked(dataDir string, next *config.Cluster, author string) error {
	live, err := config.Load(j.path)
	if err != nil {
		return err
	}
	pd, err := j.pendingLocked()
	if err != nil {
		return err
	}
	lt, err := cfgjournal.Replicated(live)
	if err != nil {
		return err
	}
	mat, err := pd.Materialize(lt)
	if err != nil {
		return err
	}
	nt, err := cfgjournal.Replicated(next)
	if err != nil {
		return err
	}
	changes, err := cfgjournal.FromChange(cfgJournalDoc, mat, nt, 0)
	if err != nil {
		return err
	}
	if len(changes) > 0 {
		entries, err := pd.Stage(lt, changes, author, time.Now().UnixMilli())
		if err != nil {
			return err
		}
		if len(entries) > 0 {
			if _, err := j.propose(cfgjournal.Meta{Author: author, Origin: 2, TimeMs: time.Now().UnixMilli()}, entries); err != nil {
				return err
			}
		}
	}
	if excludedChanged(live, next) {
		old, _, _ := loadCandidateConfig(dataDir)
		recordCandidateAuthors(dataDir, live, old, next, author)
		return config.Save(candidatePath(dataDir), next)
	}
	if err := os.Remove(candidatePath(dataDir)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return removeCandidateAuthors(dataDir)
}

// discardLocked drops staged items chosen by pick, and the staged secrets when all is true. The caller holds
// cfgWriteMu.
func (j *cfgJournalRuntime) discardLocked(dataDir string, pick func(path string, s cfgjournal.Staged) bool, all bool) error {
	pd, err := j.pendingLocked()
	if err != nil {
		return err
	}
	entries, err := pd.Discard(pick)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		if _, err := j.propose(cfgjournal.Meta{Origin: 2, TimeMs: time.Now().UnixMilli()}, entries); err != nil {
			return err
		}
	}
	if all {
		return discardCandidateConfig(dataDir)
	}
	return nil
}

// pruneCommittedLocked drops staged items the live configuration already holds, after a commit. The caller holds
// cfgWriteMu.
func (j *cfgJournalRuntime) pruneCommittedLocked() error {
	live, err := config.Load(j.path)
	if err != nil {
		return err
	}
	lt, err := cfgjournal.Replicated(live)
	if err != nil {
		return err
	}
	pd, err := j.pendingLocked()
	if err != nil {
		return err
	}
	entries, err := pd.Discard(pd.Committed(lt))
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	_, err = j.propose(cfgjournal.Meta{Origin: 2, TimeMs: time.Now().UnixMilli()}, entries)
	return err
}

func scopePick(scope string) func(string, cfgjournal.Staged) bool {
	prefix := "scopes/" + scope
	return func(p string, _ cfgjournal.Staged) bool { return p == prefix || strings.HasPrefix(p, prefix+"/") }
}

func (j *cfgJournalRuntime) handleCandidateGet(dataDir func() string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfgWriteMu.Lock()
		cand, authors, exists, err := j.candidateLocked(dataDir())
		cfgWriteMu.Unlock()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "load candidate: " + err.Error()})
			return
		}
		resp := map[string]any{"exists": exists, "candidate": nil}
		if exists {
			resp["candidate"], resp["authors"] = cand, authors
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func (j *cfgJournalRuntime) pendingStamp() string {
	var b strings.Builder
	for _, p := range []string{j.pendingDoc.Path, j.path} {
		if s, err := statStamp(p); err == nil {
			b.WriteString(s.String())
		}
	}
	return fmt.Sprint(len(b.String())) + ":" + b.String()
}
