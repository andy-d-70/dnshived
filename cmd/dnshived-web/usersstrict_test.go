// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"dnshived/internal/cfgjournal"
	"dnshived/internal/webauth"
)

// fakeIndex is the cores' secret index with the journal's apply rule. lose makes the next post apply but answer
// with an error (a lost answer); fail makes it refuse without applying (no majority).
type fakeIndex struct {
	mu   sync.Mutex
	tree any
	lose bool
	fail bool
	down bool
}

func newFakeIndex() *fakeIndex {
	return &fakeIndex{tree: map[string]any{"users": map[string]any{}, "probe_hosts": map[string]any{}, "nodes": map[string]any{}}}
}

func (f *fakeIndex) get() (any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errors.New("no core answered")
	}
	return jsonRoundTrip(f.tree)
}

func (f *fakeIndex) post(_ string, es []cfgjournal.Entry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down || f.fail {
		return errors.New("no majority")
	}
	cp, _ := jsonRoundTrip(f.tree)
	recs := make([]cfgjournal.Record, len(es))
	for i := range es {
		recs[i] = cfgjournal.Record{Rev: 1, Entry: es[i]}
	}
	out, err := cfgjournal.Apply(cp, recs)
	if err != nil {
		return err
	}
	f.tree = out
	if f.lose {
		f.lose = false
		return errors.New("timeout")
	}
	return nil
}

func strictInstance(t *testing.T, idx *fakeIndex, name string, seed *webauth.Store) *authSync {
	t.Helper()
	store, err := seed.Clone()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "webui-users.json")
	if err := store.Save(path); err != nil {
		t.Fatal(err)
	}
	a := newAuthSync(store, newConfigRef(&WebConfig{UsersFile: path}))
	a.self = name
	a.strict.latched = true
	a.strict.refresh = func() {}
	a.strict.getIndex = idx.get
	a.strict.post = idx.post
	return a
}

func seedUsers(t *testing.T) *webauth.Store {
	t.Helper()
	s := &webauth.Store{}
	if err := s.Mutate("seed", func(d *webauth.Store) error {
		d.Users = []webauth.User{{Name: "bob", Role: "scopeadmin", PasswordHash: "h1"}, {Name: "eve", Role: "readonly", PasswordHash: "h2"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

func setRole(name, role string) func(*webauth.Store) error {
	return func(d *webauth.Store) error {
		for i := range d.Users {
			if d.Users[i].Name == name {
				d.Users[i].Role = role
				return nil
			}
		}
		return errors.New("no such user")
	}
}

func roleOf(a *authSync, name string) string {
	u, _ := a.store.Lookup(name)
	return u.Role
}

func TestUsersStrict_TheSecondChangeOfTheSameUserIsRefused(t *testing.T) {
	idx, seed := newFakeIndex(), seedUsers(t)
	a, b := strictInstance(t, idx, "core1", seed), strictInstance(t, idx, "core2", seed)
	if err := a.change(setRole("bob", "admin")); err != nil {
		t.Fatal(err)
	}
	err := b.change(func(d *webauth.Store) error {
		d.Users[0].Disabled = true
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "user bob was changed on core1") {
		t.Fatalf("the second version is refused and names who changed it: %v", err)
	}
	if u, _ := b.store.Lookup("bob"); u.Disabled || u.Role != "scopeadmin" {
		t.Fatalf("nothing of the refused change is kept: %+v", u)
	}
	if _, err := os.Stat(b.pendingPath()); !os.IsNotExist(err) {
		t.Fatal("a refused change leaves nothing pending")
	}
}

func TestUsersStrict_ChangesOfDifferentUsersBothStayAndMeet(t *testing.T) {
	idx, seed := newFakeIndex(), seedUsers(t)
	a, b := strictInstance(t, idx, "core1", seed), strictInstance(t, idx, "core2", seed)
	if err := a.change(setRole("bob", "admin")); err != nil {
		t.Fatal(err)
	}
	if err := b.change(setRole("eve", "scopeadmin")); err != nil {
		t.Fatalf("a change of another user is not refused: %v", err)
	}
	raw, _ := b.store.Marshal()
	if _, _, err := (usersDoc{a}).Adopt(raw, "core2"); err != nil {
		t.Fatal(err)
	}
	if roleOf(a, "bob") != "admin" || roleOf(a, "eve") != "scopeadmin" {
		t.Fatalf("core1 holds both changes: bob %s eve %s", roleOf(a, "bob"), roleOf(a, "eve"))
	}
	raw, _ = a.store.Marshal()
	if _, _, err := (usersDoc{b}).Adopt(raw, "core1"); err != nil {
		t.Fatal(err)
	}
	if roleOf(b, "bob") != "admin" || roleOf(b, "eve") != "scopeadmin" {
		t.Fatalf("core2 holds both changes: bob %s eve %s", roleOf(b, "bob"), roleOf(b, "eve"))
	}
}

func TestUsersStrict_AStaleCopyNeverReplacesTheOrderedVersion(t *testing.T) {
	idx, seed := newFakeIndex(), seedUsers(t)
	a, stale := strictInstance(t, idx, "core1", seed), strictInstance(t, idx, "core3", seed)
	if err := a.change(setRole("bob", "admin")); err != nil {
		t.Fatal(err)
	}
	if err := stale.store.Mutate("core3", setRole("bob", "readonly")); err != nil {
		t.Fatal(err)
	}
	stale.store.Stamp("core3")
	stale.store.Stamp("core3")
	raw, _ := stale.store.Marshal()
	_, spread, err := (usersDoc{a}).Adopt(raw, "core3")
	if err != nil {
		t.Fatal(err)
	}
	if roleOf(a, "bob") != "admin" || !spread {
		t.Fatalf("the ordered version stays and the result spreads: bob %s spread %v", roleOf(a, "bob"), spread)
	}
}

func TestUsersStrict_NoMajorityRefusesAndKeepsNothing(t *testing.T) {
	idx, seed := newFakeIndex(), seedUsers(t)
	a := strictInstance(t, idx, "core1", seed)
	idx.down = true
	err := a.change(setRole("bob", "admin"))
	if err == nil || !strings.Contains(err.Error(), "majority") || roleOf(a, "bob") != "scopeadmin" {
		t.Fatalf("refused, nothing changed: %v, bob %s", err, roleOf(a, "bob"))
	}
	if _, err := os.Stat(a.pendingPath()); !os.IsNotExist(err) {
		t.Fatal("nothing pending when the order could not even be read")
	}
}

func TestUsersStrict_ALostAnswerIsAppliedOnceTheCoresConfirm(t *testing.T) {
	idx, seed := newFakeIndex(), seedUsers(t)
	a := strictInstance(t, idx, "core1", seed)
	idx.lose = true
	err := a.change(setRole("bob", "admin"))
	if err == nil || !strings.Contains(err.Error(), "not confirmed") || roleOf(a, "bob") != "scopeadmin" {
		t.Fatalf("an unconfirmed change is reported and not applied yet: %v, bob %s", err, roleOf(a, "bob"))
	}
	if _, err := os.Stat(a.pendingPath()); err != nil {
		t.Fatal("the unconfirmed change is kept on disk")
	}
	a.settle()
	if roleOf(a, "bob") != "admin" {
		t.Fatal("the change the cores ordered is applied")
	}
	if _, err := os.Stat(a.pendingPath()); !os.IsNotExist(err) {
		t.Fatal("pending cleared after it was applied")
	}
	if err := a.change(setRole("bob", "readonly")); err != nil {
		t.Fatalf("the next change builds on it: %v", err)
	}
}

func TestUsersStrict_AChangeTheCoresNeverOrderedIsDropped(t *testing.T) {
	idx, seed := newFakeIndex(), seedUsers(t)
	a := strictInstance(t, idx, "core1", seed)
	idx.fail = true
	if err := a.change(setRole("bob", "admin")); err == nil {
		t.Fatal("not confirmed")
	}
	idx.fail = false
	a.settle()
	if _, err := os.Stat(a.pendingPath()); !os.IsNotExist(err) || roleOf(a, "bob") != "scopeadmin" {
		t.Fatalf("dropped, nothing applied: bob %s", roleOf(a, "bob"))
	}
}

func TestUsersStrict_AConsoleResetWinsAndIsOrdered(t *testing.T) {
	idx, seed := newFakeIndex(), seedUsers(t)
	a, b := strictInstance(t, idx, "core1", seed), strictInstance(t, idx, "core2", seed)
	if err := b.change(setRole("bob", "admin")); err != nil {
		t.Fatal(err)
	}
	if err := a.store.Mutate("console@core1", func(d *webauth.Store) error {
		d.Users[0].PasswordHash = "reset"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.store.Save(a.ref.Load().UsersFile); err != nil {
		t.Fatal(err)
	}
	if err := markForced(a.ref.Load().UsersFile, "user/bob"); err != nil {
		t.Fatal(err)
	}
	b.store.Stamp("core2")
	raw, _ := b.store.Marshal()
	if _, _, err := (usersDoc{a}).Adopt(raw, "core2"); err != nil {
		t.Fatal(err)
	}
	if u, _ := a.store.Lookup("bob"); u.PasswordHash != "reset" {
		t.Fatal("before it is ordered, the console reset is not replaced by another version")
	}
	a.settle()
	if _, err := os.Stat(a.forcedPath()); !os.IsNotExist(err) {
		t.Fatal("the forced change is ordered on the cores")
	}
	raw, _ = a.store.Marshal()
	if _, _, err := (usersDoc{b}).Adopt(raw, "core1"); err != nil {
		t.Fatal(err)
	}
	if u, _ := b.store.Lookup("bob"); u.PasswordHash != "reset" {
		t.Fatal("every instance takes the console reset once ordered")
	}
}
