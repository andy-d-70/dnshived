// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"dnshived/internal/repldoc"
	"dnshived/internal/webauth"
)

// authSyncInterval is how often each web instance compares its users
// document with its siblings'.
const authSyncInterval = 60 * time.Second

// Limits on an incoming users document. They are far above real use; they
// only stop a malformed or hostile document from being installed.
const (
	maxReplUsers      = 2000
	maxReplResets     = 20000
	maxReplFieldBytes = 8192
)

// authSync replicates the users document (users, reset tokens, session
// key, mail settings) between the web instances of a cluster. Each change
// gets a higher revision and is pushed to every sibling; the periodic
// compare lets a node that was down or newly added catch up.
type authSync struct {
	store *webauth.Store
	ref   *configRef

	selfMu sync.Mutex
	self   string

	syncer *repldoc.Syncer

	startedAt time.Time
	synced    atomic.Bool
}

// loginSyncWait is the longest a web instance holds back logins after a start
// to compare its users with the other cores first.
const loginSyncWait = 30 * time.Second

// waitingForFirstSync reports whether logins should still be held back: there
// are other cores, the first comparison has not finished, and the wait is not
// over yet.
func (a *authSync) waitingForFirstSync() bool {
	if a.synced.Load() || time.Since(a.startedAt) >= loginSyncWait {
		return false
	}
	return len(siblingNodes(a.ref.Load())) > 0
}

func newAuthSync(store *webauth.Store, ref *configRef) *authSync {
	a := &authSync{store: store, ref: ref, startedAt: time.Now()}
	a.syncer = &repldoc.Syncer{
		Name:       "AUTHSYNC",
		Path:       "/internal/auth-doc",
		Doc:        usersDoc{a},
		Self:       a.selfName,
		Peers:      func() []repldoc.Peer { return replPeers(ref) },
		Do:         replDo(ref),
		DecodeMeta: decodeMeta,
		OnConflict: replConflict(ref, "users"),
		AfterPass:  func() { a.synced.Store(true) },
		Logf:       log.Printf,
	}
	return a
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

func (a *authSync) pushAll() { a.syncer.PushAll() }

// usersDoc is the users document as the syncer sees it.
type usersDoc struct{ a *authSync }

func (d usersDoc) Meta() repldoc.Meta       { return d.a.store.Meta() }
func (d usersDoc) Marshal() ([]byte, error) { return d.a.store.Marshal() }

func (d usersDoc) StartFirst(string) error {
	return d.a.change(func(*webauth.Store) error { return nil })
}

// Adopt takes the document in raw when it is newer than this node's and
// saves it. A never-replicated local document is merged, so its own users
// are kept (spread is then true).
func (d usersDoc) Adopt(raw []byte, from string) (adopted, spread bool, err error) {
	a := d.a
	remote, err := webauth.Parse(raw)
	if err != nil {
		return false, false, invalidDocError{err.Error()}
	}
	if err := repldoc.ValidMeta(remote.Meta()); err != nil {
		return false, false, invalidDocError{err.Error()}
	}
	if err := validateUsersDoc(remote); err != nil {
		return false, false, invalidDocError{err.Error()}
	}
	before := a.store.Meta()
	adopted, kept := a.store.Adopt(remote, a.selfName())
	if !adopted {
		return false, false, nil
	}
	if err := a.store.Save(a.ref.Load().UsersFile); err != nil {
		return true, false, fmt.Errorf("save users document: %w", err)
	}
	clearVerifyCache()
	after := a.store.Meta()
	log.Printf("[AUTHSYNC] users document %d → %d from %s", before.Version, after.Version, from)
	if len(kept) > 0 {
		log.Printf("[AUTHSYNC] kept this node's own users %v while joining the replicated users document", kept)
		auditAll(a.ref.Load(), "system", "users.merge", fmt.Sprintf("merged users %v from %s into the replicated users document", kept, a.selfName()))
	}
	return true, len(kept) > 0, nil
}

// validateUsersDoc refuses a document whose size no real instance would
// send. Roles are not checked: a newer version may add one.
func validateUsersDoc(s *webauth.Store) error {
	users := s.List()
	if len(users) > maxReplUsers {
		return fmt.Errorf("users document has %d users, more than the limit of %d", len(users), maxReplUsers)
	}
	for i, u := range users {
		if u.Name == "" || len(u.Name) > 256 {
			return fmt.Errorf("users document: user %d has an empty or oversized name", i)
		}
		if len(u.PasswordHash) > maxReplFieldBytes || len(u.Email) > maxReplFieldBytes {
			return fmt.Errorf("users document: user %q has an oversized field", u.Name)
		}
	}
	if n := s.ResetCount(); n > maxReplResets {
		return fmt.Errorf("users document has %d reset tokens, more than the limit of %d", n, maxReplResets)
	}
	return nil
}

func startsFirstRevision(self string, legacyPeers []string) bool {
	return repldoc.StartsFirstRevision(self, legacyPeers)
}

func (a *authSync) run() {
	a.syncer.Run(context.Background(), 5*time.Second, authSyncInterval)
}

func (a *authSync) handlers() replHandlers {
	return replHandlers{ref: a.ref, doc: usersDoc{a}, push: a.pushAll}
}

// handleAuthDocPost (POST /internal/auth-doc) receives a sibling's document.
func (a *authSync) handleAuthDocPost(w http.ResponseWriter, r *http.Request) {
	a.handlers().post(w, r)
}

func (a *authSync) handleAuthDocMeta(w http.ResponseWriter, r *http.Request) {
	a.handlers().meta(w, r)
}

func (a *authSync) handleAuthDocGet(w http.ResponseWriter, r *http.Request) {
	a.handlers().get(w, r)
}
