// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"dnshived/internal/webauth"
)

// authSyncInterval is how often each web instance compares its users
// document with its siblings'.
const authSyncInterval = 60 * time.Second

// authSync replicates the users document (users, reset tokens, session
// key, mail settings) between the web instances of a cluster. Each change
// gets a higher revision and is pushed to every sibling; the periodic
// compare lets a node that was down or newly added catch up.
type authSync struct {
	store *webauth.Store
	ref   *configRef

	selfMu sync.Mutex
	self   string
}

func newAuthSync(store *webauth.Store, ref *configRef) *authSync {
	return &authSync{store: store, ref: ref}
}

// selfName names this instance in revision stamps: its core role once the
// local core answers, the hostname until then.
func (a *authSync) selfName() string {
	a.selfMu.Lock()
	defer a.selfMu.Unlock()
	if a.self != "" {
		return a.self
	}
	if n, ok := selfNodeConfig(a.ref.Load()); ok && n.Name != "" {
		a.self = n.Name
		return a.self
	}
	host, _ := os.Hostname()
	return host
}

// change applies fn as a new revision, saves it and pushes it.
func (a *authSync) change(fn func(d *webauth.Store) error) error {
	if err := a.store.Mutate(a.selfName(), fn); err != nil {
		return err
	}
	return a.persist()
}

func (a *authSync) persist() error {
	if err := a.store.Save(a.ref.Load().UsersFile); err != nil {
		return err
	}
	clearVerifyCache()
	go a.pushAll()
	return nil
}

func (a *authSync) pushAll() {
	cfg := a.ref.Load()
	for _, n := range siblingNodes(cfg) {
		if err := a.pushTo(cfg, n); err != nil {
			log.Printf("[AUTHSYNC] push users document to %s: %v (it catches up within %s)", n.Name, err, authSyncInterval)
		}
	}
}

func (a *authSync) pushTo(cfg *WebConfig, n NodeConfig) error {
	data, err := a.store.Marshal()
	if err != nil {
		return err
	}
	_, err = a.siblingDo(cfg, n, http.MethodPost, "/internal/auth-doc", data)
	return err
}

// minReplicationTokenLen is the shortest shared token replication accepts (F7).
const minReplicationTokenLen = 32

func (a *authSync) siblingDo(cfg *WebConfig, n NodeConfig, method, path string, body []byte) ([]byte, error) {
	url := siblingWebURL(n, cfg) + path
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("replication refused: %s is not TLS (users and password hashes are only replicated over TLS, F7)", n.Addr)
	}
	if token := nodesSharedToken(cfg); len(token) < minReplicationTokenLen {
		return nil, fmt.Errorf("replication refused: the shared token is shorter than %d characters (F7)", minReplicationTokenLen)
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token := nodesSharedToken(cfg); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := siblingClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, bytes.TrimSpace(out))
	}
	return out, nil
}

// adopt takes remote when it is newer and saves it.
func (a *authSync) adopt(remote *webauth.Store, from string) (bool, error) {
	before := a.store.Meta()
	adopted, kept := a.store.Adopt(remote, a.selfName())
	if !adopted {
		return false, nil
	}
	if err := a.store.Save(a.ref.Load().UsersFile); err != nil {
		return true, err
	}
	clearVerifyCache()
	after := a.store.Meta()
	log.Printf("[AUTHSYNC] users document %d → %d from %s", before.Version, after.Version, from)
	if len(kept) > 0 {
		log.Printf("[AUTHSYNC] kept this node's own users %v while joining the replicated users document", kept)
		auditAll(a.ref.Load(), "system", "users.merge", fmt.Sprintf("merged users %v from %s into the replicated users document", kept, a.selfName()))
		go a.pushAll()
	}
	return true, nil
}

// syncOnce compares with every sibling: pulls a newer document, pushes
// this one to a sibling that is behind. While no instance has replicated
// yet, the reachable instance with the lowest name starts revision 1; the
// others merge their users into it.
func (a *authSync) syncOnce() {
	cfg := a.ref.Load()
	local := a.store.Meta()
	var legacyPeers []string
	newerSeen := false
	for _, n := range siblingNodes(cfg) {
		raw, err := a.siblingDo(cfg, n, http.MethodGet, "/internal/auth-doc/meta", nil)
		if err != nil {
			continue
		}
		var m webauth.Meta
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		switch {
		case webauth.Newer(m, local):
			newerSeen = true
			doc, err := a.siblingDo(cfg, n, http.MethodGet, "/internal/auth-doc", nil)
			if err != nil {
				log.Printf("[AUTHSYNC] fetch users document from %s: %v", n.Name, err)
				continue
			}
			remote, err := webauth.Parse(doc)
			if err != nil {
				log.Printf("[AUTHSYNC] users document from %s: %v", n.Name, err)
				continue
			}
			if _, err := a.adopt(remote, n.Name); err != nil {
				log.Printf("[AUTHSYNC] save users document from %s: %v", n.Name, err)
			}
			local = a.store.Meta()
		case webauth.Newer(local, m):
			if err := a.pushTo(cfg, n); err != nil {
				log.Printf("[AUTHSYNC] push users document to %s: %v", n.Name, err)
			}
		}
		if m.Version == 0 {
			legacyPeers = append(legacyPeers, n.Name)
		}
	}
	if local.Version == 0 && !newerSeen && startsFirstRevision(a.selfName(), legacyPeers) {
		if err := a.change(func(*webauth.Store) error { return nil }); err != nil {
			log.Printf("[AUTHSYNC] start the replicated users document: %v", err)
			return
		}
		log.Printf("[AUTHSYNC] started the replicated users document (revision 1); the other cores merge their users into it")
	}
}

func startsFirstRevision(self string, legacyPeers []string) bool {
	names := append([]string{self}, legacyPeers...)
	sort.Strings(names)
	return names[0] == self
}

func (a *authSync) run() {
	go func() {
		time.Sleep(5 * time.Second)
		a.syncOnce()
		for range time.Tick(authSyncInterval) {
			a.syncOnce()
		}
	}()
}

// handleAuthDocPost (POST /internal/auth-doc) receives a sibling's document.
func (a *authSync) handleAuthDocPost(w http.ResponseWriter, r *http.Request) {
	if !checkSharedToken(a.ref.Load(), r) {
		writeJSONWeb(w, http.StatusUnauthorized, map[string]string{"error": "invalid or missing token"})
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		writeJSONWeb(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	remote, err := webauth.Parse(data)
	if err != nil {
		writeJSONWeb(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if _, err := a.adopt(remote, clientAddr(r)); err != nil {
		writeJSONWeb(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSONWeb(w, http.StatusOK, a.store.Meta())
}

func (a *authSync) handleAuthDocMeta(w http.ResponseWriter, r *http.Request) {
	if !checkSharedToken(a.ref.Load(), r) {
		writeJSONWeb(w, http.StatusUnauthorized, map[string]string{"error": "invalid or missing token"})
		return
	}
	writeJSONWeb(w, http.StatusOK, a.store.Meta())
}

func (a *authSync) handleAuthDocGet(w http.ResponseWriter, r *http.Request) {
	if !checkSharedToken(a.ref.Load(), r) {
		writeJSONWeb(w, http.StatusUnauthorized, map[string]string{"error": "invalid or missing token"})
		return
	}
	data, err := a.store.Marshal()
	if err != nil {
		writeJSONWeb(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(data)
}
