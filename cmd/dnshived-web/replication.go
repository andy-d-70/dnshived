// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"

	"dnshived/internal/repldoc"
)

// minReplicationTokenLen is the shortest shared token replication accepts (F7).
const minReplicationTokenLen = 32

// maxReplicatedDocBytes caps a replicated document in either direction.
const maxReplicatedDocBytes = 4 << 20

// siblingRequest sends one replication request to another web instance:
// TLS only, with the shared token of at least minReplicationTokenLen.
func siblingRequest(cfg *WebConfig, n NodeConfig, method, path string, body []byte) ([]byte, error) {
	url := siblingWebURL(n, cfg) + path
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("replication refused: %s is not TLS (replicated documents carry password hashes and tokens and only travel over TLS, F7)", n.Addr)
	}
	token := nodesSharedToken(cfg)
	if len(token) < minReplicationTokenLen {
		return nil, fmt.Errorf("replication refused: the shared token is shorter than %d characters (F7)", minReplicationTokenLen)
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := siblingClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, maxReplicatedDocBytes))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, bytes.TrimSpace(out))
	}
	return out, nil
}

func decodeMeta(raw []byte) (repldoc.Meta, error) {
	var m repldoc.Meta
	err := json.Unmarshal(raw, &m)
	return m, err
}

// replPeers lists the other web instances as syncer peers.
func replPeers(ref *configRef) []repldoc.Peer {
	var out []repldoc.Peer
	for _, n := range siblingNodes(ref.Load()) {
		out = append(out, repldoc.Peer{Name: n.Name, Data: n})
	}
	return out
}

// replDo is the syncer transport over siblingRequest.
func replDo(ref *configRef) func(repldoc.Peer, string, string, []byte) ([]byte, error) {
	return func(p repldoc.Peer, method, path string, body []byte) ([]byte, error) {
		n, ok := p.Data.(NodeConfig)
		if !ok {
			return nil, fmt.Errorf("peer %q carries no node address", p.Name)
		}
		return siblingRequest(ref.Load(), n, method, path, body)
	}
}

// replConflict reports two different documents with the same revision once
// per pair of contents and peer, not on every comparison, and does the
// audit write off the syncer's goroutine.
func replConflict(ref *configRef, doc string) func(local, remote repldoc.Meta, peer string) {
	var mu sync.Mutex
	reported := map[string]string{}
	return func(local, remote repldoc.Meta, peer string) {
		key := local.Hash + "/" + remote.Hash
		mu.Lock()
		seen := reported[peer] == key
		reported[peer] = key
		mu.Unlock()
		if seen {
			return
		}
		msg := fmt.Sprintf("%s document: %s holds a different document with the same revision %d (this node %s, there %s); one is chosen by timestamp and origin", doc, peer, local.Version, short(local.Hash), short(remote.Hash))
		log.Printf("[REPL] %s", msg)
		go auditAll(ref.Load(), "system", "doc.conflict", msg)
	}
}

func short(h string) string {
	if len(h) > 8 {
		return h[:8]
	}
	return h
}

// replHandlers are the three endpoints of one replicated document.
type replHandlers struct {
	ref *configRef
	doc repldoc.Doc
	// push sends the local document to the other instances after a merge.
	push func()
}

func (h replHandlers) auth(w http.ResponseWriter, r *http.Request) bool {
	if !checkSharedToken(h.ref.Load(), r) {
		writeJSONWeb(w, http.StatusUnauthorized, map[string]string{"error": "invalid or missing token"})
		return false
	}
	return true
}

// post receives a sibling's document.
func (h replHandlers) post(w http.ResponseWriter, r *http.Request) {
	if !h.auth(w, r) {
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxReplicatedDocBytes))
	if err != nil {
		writeJSONWeb(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if _, spread, err := h.doc.Adopt(data, clientAddr(r)); err != nil {
		code := http.StatusInternalServerError
		if isInvalidDoc(err) {
			code = http.StatusBadRequest
		}
		writeJSONWeb(w, code, map[string]string{"error": err.Error()})
		return
	} else if spread && h.push != nil {
		go h.push()
	}
	writeJSONWeb(w, http.StatusOK, h.doc.Meta())
}

func (h replHandlers) meta(w http.ResponseWriter, r *http.Request) {
	if !h.auth(w, r) {
		return
	}
	writeJSONWeb(w, http.StatusOK, h.doc.Meta())
}

func (h replHandlers) get(w http.ResponseWriter, r *http.Request) {
	if !h.auth(w, r) {
		return
	}
	data, err := h.doc.Marshal()
	if err != nil {
		writeJSONWeb(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(data)
}

// invalidDocError marks a document refused for its shape or size.
type invalidDocError struct{ msg string }

func (e invalidDocError) Error() string { return e.msg }

func isInvalidDoc(err error) bool {
	var e invalidDocError
	return errors.As(err, &e)
}
