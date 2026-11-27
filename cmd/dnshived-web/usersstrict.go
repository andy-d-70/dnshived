// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"dnshived/internal/cfgjournal"
	"dnshived/internal/ownership"
	"dnshived/internal/secretindex"
	"dnshived/internal/webauth"
)

// With every core offering the secret index, a change of the users document is ordered by the cores: it names the
// version of each item it was based on, the first change wins and a later one from the same version is refused.
// A sibling's document is taken item by item, only where it holds what the index names. Secrets stay here; the
// cores see only hashes.

const usersIndexPart = "users"

type usersStrict struct {
	mu       sync.Mutex
	latched  bool
	refresh  func()
	getIndex func() (any, error)
	post     func(author string, es []cfgjournal.Entry) error
	now      func() time.Time
}

func newUsersStrict(ref *configRef) *usersStrict {
	u := &usersStrict{now: time.Now}
	path := ref.Load().UsersFile + ".strict"
	if _, err := os.Stat(path); err == nil {
		u.latched = true
	}
	u.refresh = func() { u.decide(ref, path) }
	u.getIndex = func() (any, error) {
		_, tree, err := fetchSharedDoc(nodesIncludingSelf(ref.Load()), secretindex.Doc)
		return tree, err
	}
	u.post = func(author string, es []cfgjournal.Entry) error {
		return postSharedDocChanges(nodesIncludingSelf(ref.Load()), secretindex.Doc, author, es)
	}
	return u
}

// active reports the last decision; it never waits for the cores. The decision is made in the background (start
// and every comparison) and survives a restart in the latch file.
func (u *usersStrict) active() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.latched
}

// decide switches strict mode on once a majority of the cores answers and every answering core offers the index;
// it stays on while cores are unreachable, and goes off only when a majority answers with the journal switched off.
func (u *usersStrict) decide(ref *configRef, latchPath string) {
	nodes := nodesIncludingSelf(ref.Load())
	sts := fetchStatuses(nodes)
	majority := len(sts) >= len(nodes)/2+1
	all, off := majority, 0
	for _, st := range sts {
		if !offersSecretIndex(st.ConfigJournal) {
			all = false
		}
		if !journalOn(st.ConfigJournal) {
			off++
		}
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	switch {
	case all && !u.latched:
		if err := writeMarker(latchPath, []byte("on\n")); err != nil {
			log.Printf("[AUTHSYNC] strict users mode: %v", err)
		}
		u.latched = true
		log.Printf("[AUTHSYNC] every core orders user changes now: a second version of a user is refused")
	case u.latched && majority && off == len(sts):
		_ = os.Remove(latchPath)
		u.latched = false
		log.Printf("[AUTHSYNC] the configuration journal is off on the cores: user changes are no longer ordered")
	}
}

func offersSecretIndex(state json.RawMessage) bool {
	if !journalOn(state) {
		return false
	}
	var st struct {
		Docs []string `json:"docs"`
	}
	if json.Unmarshal(state, &st) != nil {
		return false
	}
	for _, d := range st.Docs {
		if d == secretindex.Doc {
			return true
		}
	}
	return false
}

func writeMarker(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	if f, err := os.Open(tmp); err == nil {
		_ = f.Sync()
		f.Close()
	}
	if err := ownership.Dnshived(tmp); err != nil && !errors.Is(err, os.ErrPermission) {
		log.Printf("[AUTHSYNC] %s: %v", path, err)
	}
	return os.Rename(tmp, path)
}

// itemLabel names an item for an operator.
func itemLabel(key string) string {
	switch {
	case strings.HasPrefix(key, "user/"):
		return "user " + strings.TrimPrefix(key, "user/")
	case strings.HasPrefix(key, "reset/"):
		return "a password reset link"
	}
	return "the " + strings.ReplaceAll(key, "_", " ") + " setting"
}

func conflictText(ce *secretindex.ConflictError) string {
	what := "changed"
	if ce.Entry.Deleted {
		what = "deleted"
	}
	return fmt.Sprintf("not saved: %s was %s on %s at %s since this page was loaded. Reload and enter the change again if it is still needed.",
		itemLabel(ce.Key), what, ce.Entry.By, ce.Entry.At)
}

// pendingUsers is a change sent to the cores and not yet confirmed; it is kept on disk so a crash or a lost answer
// cannot lose it: once the index names it, it is applied; if the cores never ordered it, it is dropped.
type pendingUsers struct {
	Keys  []string                   `json:"keys"`
	Items map[string]json.RawMessage `json:"items"`
}

type forcedUsers struct {
	Keys []string `json:"keys"`
}

func (a *authSync) pendingPath() string { return a.ref.Load().UsersFile + ".pending" }
func (a *authSync) forcedPath() string  { return a.ref.Load().UsersFile + ".forced" }

func readJSONFile(path string, v any) (bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(raw, v)
}

func (a *authSync) forcedKeys() map[string]bool {
	var f forcedUsers
	ok, err := readJSONFile(a.forcedPath(), &f)
	if err != nil {
		log.Printf("[AUTHSYNC] %s: %v", a.forcedPath(), err)
	}
	if !ok {
		return nil
	}
	out := map[string]bool{}
	for _, k := range f.Keys {
		out[k] = true
	}
	return out
}

// strictChange orders fn's result through the cores before it is applied here.
func (a *authSync) strictChange(fn func(d *webauth.Store) error) error {
	a.strictMu.Lock()
	defer a.strictMu.Unlock()
	next, err := a.store.Clone()
	if err != nil {
		return err
	}
	before, err := a.store.Items()
	if err != nil {
		return err
	}
	if err := next.Mutate(a.selfName(), fn); err != nil {
		return err
	}
	after, err := next.Items()
	if err != nil {
		return err
	}
	keys := secretindex.Changed(before, after)
	if len(keys) == 0 {
		return nil
	}
	tree, err := a.strict.getIndex()
	if err != nil {
		return fmt.Errorf("not saved: user changes need a majority of the cores, and their change order cannot be reached (%v)", err)
	}
	es, err := secretindex.Plan(tree, usersIndexPart, before, after, keys, a.selfName(), a.strict.now(), false)
	var ce *secretindex.ConflictError
	if errors.As(err, &ce) {
		a.auditRejected(ce)
		return errors.New(conflictText(ce))
	}
	if err != nil {
		return err
	}
	p := pendingUsers{Keys: keys, Items: map[string]json.RawMessage{}}
	for _, k := range keys {
		p.Items[k] = json.RawMessage(after[k])
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err := writeMarker(a.pendingPath(), raw); err != nil {
		return fmt.Errorf("not saved: keep the change on disk before sending it: %w", err)
	}
	perr := a.strict.post(a.selfName(), es)
	switch {
	case perr == nil:
		a.store.Install(next)
		_ = os.Remove(a.pendingPath())
		return a.persist()
	case errors.Is(perr, cfgjournal.ErrConflict):
		_ = os.Remove(a.pendingPath())
		if tree, err := a.strict.getIndex(); err == nil {
			if _, err := secretindex.Plan(tree, usersIndexPart, before, after, keys, a.selfName(), a.strict.now(), false); errors.As(err, &ce) {
				a.auditRejected(ce)
				return errors.New(conflictText(ce))
			}
		}
		return errors.New("not saved: someone changed this at the same moment. Reload and enter the change again if it is still needed.")
	}
	return fmt.Errorf("not confirmed by the cores yet (%v): the change is kept and applied as soon as they confirm it, or dropped if they refuse it", perr)
}

func (a *authSync) auditRejected(ce *secretindex.ConflictError) {
	msg := fmt.Sprintf("refused a change of %s on %s: it was changed by %s at %s", itemLabel(ce.Key), a.selfName(), ce.Entry.By, ce.Entry.At)
	log.Printf("[AUTHSYNC] %s", msg)
	go auditAll(a.ref.Load(), "system", "users.rejected", msg)
}

// strictAdopt takes a sibling's newer document item by item: only what the index names.
func (a *authSync) strictAdopt(remote *webauth.Store, from string) (adopted, spread bool, err error) {
	a.strictMu.Lock()
	defer a.strictMu.Unlock()
	if !webauth.Newer(remote.Meta(), a.store.Meta()) {
		return false, false, nil
	}
	tree, err := a.strict.getIndex()
	if err != nil {
		return false, false, fmt.Errorf("users document from %s not taken yet: the cores' change order cannot be read: %w", from, err)
	}
	idx, err := secretindex.Parse(tree, usersIndexPart)
	if err != nil {
		return false, false, err
	}
	local, err := a.store.Items()
	if err != nil {
		return false, false, err
	}
	incoming, err := remote.Items()
	if err != nil {
		return false, false, invalidDocError{err.Error()}
	}
	out, refused, missing := secretindex.Reconcile(idx, local, incoming, a.forcedKeys())
	next, err := remote.WithItems(out)
	if err != nil {
		return false, false, invalidDocError{err.Error()}
	}
	if len(refused) > 0 {
		next.Stamp(a.selfName())
		labels := make([]string, len(refused))
		for i, k := range refused {
			labels[i] = itemLabel(k)
		}
		log.Printf("[AUTHSYNC] from %s not taken (the cores ordered another version): %s", from, strings.Join(labels, ", "))
	}
	for _, k := range missing {
		log.Printf("[AUTHSYNC] the cores name a version of %s that no instance holds; following %s's copy", itemLabel(k), from)
	}
	if err := validateUsersDoc(next); err != nil {
		return false, false, invalidDocError{err.Error()}
	}
	a.store.Install(next)
	if err := a.store.Save(a.ref.Load().UsersFile); err != nil {
		return true, false, fmt.Errorf("save users document: %w", err)
	}
	clearVerifyCache()
	return true, len(refused) > 0, nil
}

// settle applies a change the cores confirmed after its answer was lost, drops one they never ordered, and orders
// console resets. It runs after every comparison while strict mode is on.
func (a *authSync) settle() {
	a.strict.refresh()
	if !a.strict.active() {
		return
	}
	a.strictMu.Lock()
	defer a.strictMu.Unlock()
	var p pendingUsers
	hasPending, perr := readJSONFile(a.pendingPath(), &p)
	forced := a.forcedKeys()
	if !hasPending && len(forced) == 0 {
		return
	}
	tree, err := a.strict.getIndex()
	if err != nil {
		return
	}
	if perr != nil {
		log.Printf("[AUTHSYNC] unreadable %s, kept for inspection: %v", a.pendingPath(), perr)
	} else if hasPending {
		a.settlePending(tree, p)
	}
	if len(forced) > 0 {
		a.orderForced(tree, forced)
	}
}

func (a *authSync) settlePending(tree any, p pendingUsers) {
	idx, err := secretindex.Parse(tree, usersIndexPart)
	if err != nil {
		return
	}
	confirmed := true
	for _, k := range p.Keys {
		raw, ok := p.Items[k]
		e := idx[k]
		if !ok || string(raw) == "null" {
			confirmed = confirmed && e.Deleted
		} else {
			confirmed = confirmed && !e.Deleted && e.Hash == secretindex.Hash(raw)
		}
	}
	if !confirmed {
		_ = os.Remove(a.pendingPath())
		msg := fmt.Sprintf("dropped an unconfirmed change on %s: the cores never ordered it", a.selfName())
		log.Printf("[AUTHSYNC] %s", msg)
		go auditAll(a.ref.Load(), "system", "users.rejected", msg)
		return
	}
	cur, err := a.store.Items()
	if err != nil {
		return
	}
	for _, k := range p.Keys {
		if raw := p.Items[k]; raw == nil || string(raw) == "null" {
			delete(cur, k)
		} else {
			cur[k] = raw
		}
	}
	next, err := a.store.WithItems(cur)
	if err != nil {
		log.Printf("[AUTHSYNC] confirmed change not applied: %v", err)
		return
	}
	next.Stamp(a.selfName())
	a.store.Install(next)
	_ = os.Remove(a.pendingPath())
	if err := a.persist(); err != nil {
		log.Printf("[AUTHSYNC] save confirmed change: %v", err)
		return
	}
	log.Printf("[AUTHSYNC] applied a change the cores confirmed after its answer was lost")
}

func (a *authSync) orderForced(tree any, forced map[string]bool) {
	items, err := a.store.Items()
	if err != nil {
		return
	}
	keys := make([]string, 0, len(forced))
	for k := range forced {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	es, err := secretindex.Plan(tree, usersIndexPart, nil, items, keys, "console@"+a.selfName(), a.strict.now(), true)
	if err != nil {
		return
	}
	if err := a.strict.post("console@"+a.selfName(), es); err != nil {
		return
	}
	_ = os.Remove(a.forcedPath())
	a.store.Stamp(a.selfName())
	if err := a.persist(); err != nil {
		log.Printf("[AUTHSYNC] save after ordering the console reset: %v", err)
	}
	labels := make([]string, len(keys))
	for i, k := range keys {
		labels[i] = itemLabel(k)
	}
	msg := fmt.Sprintf("console reset on %s now ordered on every core: %s", a.selfName(), strings.Join(labels, ", "))
	log.Printf("[AUTHSYNC] %s", msg)
	go auditAll(a.ref.Load(), "system", "users.forced", msg)
}

// markForced records that an administrator changed key at the console, so the web orders it on the cores as a
// forced change (whatever version they hold) instead of taking their version over it.
func markForced(usersFile, key string) error {
	path := usersFile + ".forced"
	var f forcedUsers
	if _, err := readJSONFile(path, &f); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	for _, k := range f.Keys {
		if k == key {
			return nil
		}
	}
	f.Keys = append(f.Keys, key)
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return writeMarker(path, raw)
}
