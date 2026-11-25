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
	"dnshived/internal/loglevel"
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

const maxStageBody = 64 << 20

type stageRequest struct {
	Author  string             `json:"author"`
	Changes []cfgjournal.Entry `json:"changes"`
	// Own holds the secret and identity fields of the staged candidate (cfgjournal.Excluded), staged per core.
	Own *config.Cluster `json:"own,omitempty"`
}

// handlePendingStage stages item changes the web computed between the document it read and the one it wants: each
// change carries the value it was based on, so a change of an item someone else changed meanwhile is refused and kept,
// and nothing the web did not change is written. Secret and identity fields come along in Own for this core's
// candidate file.
func (j *cfgJournalRuntime) handlePendingStage(dataDir func() string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req stageRequest
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxStageBody))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, proposeAnswer{Error: "bad request: " + err.Error()})
			return
		}
		for i := range req.Changes {
			if cfgjournal.Excluded[strings.SplitN(req.Changes[i].Path, "/", 2)[0]] {
				writeJSON(w, http.StatusBadRequest, proposeAnswer{Error: "secret and identity fields are sent in own, never as changes"})
				return
			}
			req.Changes[i].Doc = cfgJournalDoc
		}
		cfgWriteMu.Lock()
		defer cfgWriteMu.Unlock()
		if err := j.stageChangesLocked(req.Changes, req.Author); err != nil {
			writeJSON(w, proposeStatus(err), proposeError(err))
			return
		}
		if req.Own != nil {
			if err := j.stageOwnLocked(dataDir(), req.Own, req.Author); err != nil {
				writeJSON(w, http.StatusInternalServerError, proposeAnswer{Error: err.Error()})
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// stageChangesLocked stages item changes with their based-on values (refused on conflict, validated as a whole). The
// caller holds cfgWriteMu.
func (j *cfgJournalRuntime) stageChangesLocked(changes []cfgjournal.Entry, author string) error {
	if len(changes) == 0 {
		return nil
	}
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
	entries, err := pd.Stage(lt, changes, author, time.Now().UnixMilli())
	if err != nil || len(entries) == 0 {
		return err
	}
	if err := j.validateStaged(lt, pd, changes); err != nil {
		return err
	}
	_, err = j.propose(cfgjournal.Meta{Author: author, Origin: 2, TimeMs: time.Now().UnixMilli()}, entries)
	return err
}

// stageOwnLocked keeps the staged secret and identity fields in this core's candidate file; when they equal the live
// configuration the file is removed. The caller holds cfgWriteMu.
func (j *cfgJournalRuntime) stageOwnLocked(dataDir string, own *config.Cluster, author string) error {
	live, err := config.Load(j.path)
	if err != nil {
		return err
	}
	next, err := withExcluded(live, own)
	if err != nil {
		return err
	}
	if !excludedChanged(live, next) {
		if err := os.Remove(candidatePath(dataDir)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return removeCandidateAuthors(dataDir)
	}
	old, _, _ := loadCandidateConfig(dataDir)
	recordCandidateAuthors(dataDir, live, old, next, author)
	return config.Save(candidatePath(dataDir), next)
}

type commitRequest struct {
	Author string `json:"author"`
	// Mine commits only the items author staged; otherwise everything staged.
	Mine bool `json:"mine"`
}

// handlePendingCommit commits staged items: each from the value it had when it was staged to its staged value, so an
// item that moved in the meantime refuses the commit and nothing else is touched. This core's staged secret and
// identity fields are saved with it. Sent to every core, the items commit once and each core saves its own fields.
func (j *cfgJournalRuntime) handlePendingCommit(dataDir func() string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req commitRequest
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, proposeAnswer{Error: "bad request: " + err.Error()})
			return
		}
		pick := func(_ string, s cfgjournal.Staged) bool { return !req.Mine || s.Author == req.Author }
		cfgWriteMu.Lock()
		defer cfgWriteMu.Unlock()
		pd, err := j.pendingLocked()
		if err == nil {
			if entries := pd.Commit(cfgJournalDoc, pick); len(entries) > 0 {
				var cand any
				live, lerr := config.Load(j.path)
				if lerr == nil {
					lt, _ := cfgjournal.Replicated(live)
					recs := make([]cfgjournal.Record, len(entries))
					for i := range entries {
						recs[i] = cfgjournal.Record{Entry: entries[i]}
					}
					if cand, err = cfgjournal.Apply(lt, recs); err == nil {
						var c *config.Cluster
						if c, err = j.doc.Candidate(cand); err == nil {
							if res := c.ValidateExtended(); !res.OK() {
								err = fmt.Errorf("the committed configuration would not be valid: %v", res.Errors)
							}
						}
					}
				} else {
					err = lerr
				}
				if err == nil {
					if _, err = j.propose(cfgjournal.Meta{Author: req.Author, Origin: 1, TimeMs: time.Now().UnixMilli()}, entries); err == nil {
						err = j.pruneCommittedLocked()
					}
				}
			}
		}
		if err != nil {
			writeJSON(w, proposeStatus(err), proposeError(err))
			return
		}
		if err := j.commitOwnLocked(dataDir(), req); err != nil {
			writeJSON(w, http.StatusInternalServerError, proposeAnswer{Error: "save this core's own fields: " + err.Error()})
			return
		}
		if _, err := j.refreshLocked(); err != nil {
			loglevel.Warnf("[CFGJOURNAL:ERROR] reload after commit: %v", err)
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// commitOwnLocked saves this core's staged secret and identity fields into its configuration and removes them from
// its candidate file. The caller holds cfgWriteMu.
func (j *cfgJournalRuntime) commitOwnLocked(dataDir string, req commitRequest) error {
	staged, exists, err := loadCandidateConfig(dataDir)
	if err != nil || !exists {
		return err
	}
	if req.Mine {
		for p, a := range loadCandidateAuthors(dataDir) {
			if cfgjournal.Excluded[strings.SplitN(p, "/", 2)[0]] && a != req.Author {
				return nil
			}
		}
	}
	live, err := config.Load(j.path)
	if err != nil {
		return err
	}
	next, err := withExcluded(live, staged)
	if err != nil {
		return err
	}
	if res := next.ValidateExtended(); !res.OK() {
		return fmt.Errorf("not valid: %v", res.Errors)
	}
	if err := config.Save(j.path, next); err != nil {
		return err
	}
	currentConfig.Store(next)
	return discardCandidateConfig(dataDir)
}

// validateStaged refuses a staging whose resulting candidate would not be a valid configuration, as staging always did.
func (j *cfgJournalRuntime) validateStaged(lt any, pd cfgjournal.Pending, changes []cfgjournal.Entry) error {
	mat, err := pd.Materialize(lt)
	if err != nil {
		return err
	}
	recs := make([]cfgjournal.Record, len(changes))
	for i := range changes {
		recs[i] = cfgjournal.Record{Entry: changes[i]}
	}
	want, err := cfgjournal.Apply(mat, recs)
	if err != nil {
		return err
	}
	c, err := j.doc.Candidate(want)
	if err != nil {
		return err
	}
	if res := c.ValidateExtended(); !res.OK() {
		return fmt.Errorf("the staged configuration would not be valid: %v", res.Errors)
	}
	return nil
}
