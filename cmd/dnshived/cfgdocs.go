// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"net/http"
	"time"

	"dnshived/internal/cfgjournal"
)

// templatesDoc is the web's templates document (templates, option sets, scope groups) in the configuration journal,
// so every web instance shows the same templates. It holds no secrets.
const templatesDoc = "templates"

func emptyTemplates() any {
	return map[string]any{"templates": []any{}, "option_sets": []any{}, "scope_groups": []any{}}
}

// secretIndexDoc orders changes of the web's secret-bearing documents (users, probe hosts, nodes): per item only a
// sha256 of its content and who changed it when. The content itself never enters the journal.
const secretIndexDoc = "secret-index"

func emptySecretIndex() any {
	return map[string]any{"users": map[string]any{}, "probe_hosts": map[string]any{}, "nodes": map[string]any{}}
}

// sharedDocs are the documents the web may read and change through the journal; documents with secrets are never
// among them.
var sharedDocs = map[string]bool{templatesDoc: true, secretIndexDoc: true}

type docAnswer struct {
	Rev  uint64          `json:"rev"`
	Tree json.RawMessage `json:"tree"`
}

// handleDocGet answers GET /api/v1/journal/docs/{name}: the document as every core holds it, and its revision.
func (j *cfgJournalRuntime) handleDocGet(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !sharedDocs[name] {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such shared document"})
		return
	}
	ans, err := j.docAnswerFor(name)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, ans)
}

// docAnswerFor reads a shared document only when the journal moved since its last answer; an idle cluster answers
// every web's refresh from memory.
func (j *cfgJournalRuntime) docAnswerFor(name string) (docAnswer, error) {
	cfgWriteMu.Lock()
	defer cfgWriteMu.Unlock()
	_, serr := j.syncLocked()
	head := j.store.View().Rev()
	if c, ok := j.docCache[name]; serr == nil && ok && c.head == head {
		return c.ans, nil
	}
	delete(j.docCache, name)
	_, doc, err := j.sharedDoc(name)
	if err != nil {
		return docAnswer{}, err
	}
	tree, rev, _, err := doc.Load()
	if err != nil {
		return docAnswer{}, err
	}
	raw, err := json.Marshal(tree)
	if err != nil {
		return docAnswer{}, err
	}
	ans := docAnswer{Rev: rev, Tree: raw}
	if serr == nil {
		if j.docCache == nil {
			j.docCache = map[string]cachedDoc{}
		}
		j.docCache[name] = cachedDoc{ans: ans, head: head}
	}
	return ans, nil
}

type cachedDoc struct {
	ans  docAnswer
	head uint64
}

type docChangeRequest struct {
	Author  string             `json:"author"`
	Changes []cfgjournal.Entry `json:"changes"`
}

// handleDocChange answers POST /api/v1/journal/docs/{name}/changes: item changes with the value each was based on;
// an item someone else changed meanwhile refuses the change (kept in the conflict log), the same change twice is a
// no-op.
func (j *cfgJournalRuntime) handleDocChange(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !sharedDocs[name] {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such shared document"})
		return
	}
	var req docChangeRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxStageBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, proposeAnswer{Error: "bad request: " + err.Error()})
		return
	}
	if len(req.Changes) == 0 {
		writeJSON(w, http.StatusOK, proposeAnswer{Noop: true})
		return
	}
	for i := range req.Changes {
		req.Changes[i].Doc = name
	}
	cfgWriteMu.Lock()
	res, err := j.propose(cfgjournal.Meta{Author: req.Author, Origin: 3, TimeMs: time.Now().UnixMilli()}, req.Changes)
	cfgWriteMu.Unlock()
	if err != nil {
		writeJSON(w, proposeStatus(err), proposeError(err))
		return
	}
	writeJSON(w, http.StatusOK, proposeAnswer{Rev: res.Rev, Noop: res.Noop})
}
