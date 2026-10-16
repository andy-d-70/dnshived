// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package webauth

import (
	"testing"
	"time"
)

func TestNewer_OrdersByVersionThenTimeThenOrigin(t *testing.T) {
	base := Meta{Version: 3, UpdatedAt: "2026-10-16T10:00:00Z", Origin: "core-1"}
	if !Newer(Meta{Version: 4}, base) || Newer(Meta{Version: 2, UpdatedAt: "9999"}, base) {
		t.Error("version must decide first")
	}
	later := base
	later.UpdatedAt = "2026-10-16T10:00:01Z"
	if !Newer(later, base) {
		t.Error("same version: later timestamp must win")
	}
	other := base
	other.Origin = "core-2"
	if !Newer(other, base) || Newer(base, other) {
		t.Error("same version and time: origin must break the tie in one direction only")
	}
	if Newer(base, base) {
		t.Error("a revision is not newer than itself")
	}
}

func TestMutate_StampsRevisionOnlyOnSuccess(t *testing.T) {
	s := &Store{}
	if err := s.Mutate("core-1", func(d *Store) error { d.PublicURL = "https://x"; return nil }); err != nil {
		t.Fatal(err)
	}
	if m := s.Meta(); m.Version != 1 || m.Origin != "core-1" || m.UpdatedAt == "" {
		t.Errorf("meta after mutate = %+v", m)
	}
	_ = s.Mutate("core-2", func(d *Store) error { return errTest })
	if s.Meta().Version != 1 {
		t.Error("a failed mutation must not stamp a new revision")
	}
}

type testErr string

func (e testErr) Error() string { return string(e) }

const errTest = testErr("refused")

func TestAdopt_NewerReplacesOlderIgnored(t *testing.T) {
	local := &Store{Version: 5, Users: []User{{Name: "a"}}}
	if ok, _ := local.Adopt(&Store{Version: 4, Users: []User{{Name: "b"}}}, "core-1"); ok {
		t.Error("older document adopted")
	}
	ok, kept := local.Adopt(&Store{Version: 6, Users: []User{{Name: "b"}}}, "core-1")
	if !ok || len(kept) != 0 || len(local.List()) != 1 || local.List()[0].Name != "b" {
		t.Errorf("newer document not adopted as is: ok=%v kept=%v users=%v", ok, kept, local.List())
	}
}

func TestAdopt_LegacyDocumentMergesItsUsers(t *testing.T) {
	local := &Store{Users: []User{{Name: "admin", Role: RoleAdmin}, {Name: "ops", Role: RoleAdmin}}}
	remote := &Store{Version: 2, Users: []User{{Name: "admin", Role: RoleAdmin, Email: "a@x"}}}
	ok, kept := local.Adopt(remote, "core-2")
	if !ok || len(kept) != 1 || kept[0] != "ops" {
		t.Fatalf("ok=%v kept=%v", ok, kept)
	}
	if m := local.Meta(); m.Version != 3 || m.Origin != "core-2" {
		t.Errorf("merged document must get a new revision to spread, got %+v", m)
	}
	if u, _ := local.Lookup("admin"); u.Email != "a@x" {
		t.Error("the remote copy of a user present on both sides must win")
	}
	if _, ok := local.Lookup("ops"); !ok {
		t.Error("a user only the legacy side had was lost")
	}
}

func TestEnsureSessionKey_OnceOnly(t *testing.T) {
	s := &Store{}
	created, err := s.EnsureSessionKey("core-1")
	if err != nil || !created || len(s.SessionKeyBytes()) != 32 {
		t.Fatalf("created=%v err=%v key=%d bytes", created, err, len(s.SessionKeyBytes()))
	}
	key := s.SessionKey
	if created, _ := s.EnsureSessionKey("core-1"); created || s.SessionKey != key {
		t.Error("an existing key must be kept")
	}
}

func TestVerify_DisabledUserRefused(t *testing.T) {
	orig := verifyPassword
	verifyPassword = func(pw, hash string) bool { return pw == hash }
	t.Cleanup(func() { verifyPassword = orig })
	s := &Store{Users: []User{{Name: "x", PasswordHash: "pw", Disabled: true}}}
	if _, ok := s.Verify("x", "pw"); ok {
		t.Error("disabled user logged in")
	}
}

func TestLookupLogin_NameThenEmail(t *testing.T) {
	s := &Store{Users: []User{{Name: "ops", Email: "Ops@Example.org"}, {Name: "x@y", Email: "other@z"}}}
	if u, ok := s.LookupLogin("ops@example.org"); !ok || u.Name != "ops" {
		t.Error("email lookup must ignore case")
	}
	if u, ok := s.LookupLogin("x@y"); !ok || u.Name != "x@y" {
		t.Error("an exact user name must win over email")
	}
}

func TestPruneResets_DropsExpired(t *testing.T) {
	now := time.Now()
	d := &Store{Resets: []ResetToken{
		{User: "a", Expires: now.Add(time.Minute).Format(time.RFC3339)},
		{User: "b", Expires: now.Add(-time.Minute).Format(time.RFC3339)},
		{User: "c", Expires: "garbage"},
	}}
	PruneResets(d, now)
	if len(d.Resets) != 1 || d.Resets[0].User != "a" {
		t.Errorf("resets after prune = %+v", d.Resets)
	}
}

func TestUpsertHash_KeepsEmailAndBumpsEpoch(t *testing.T) {
	s := &Store{Users: []User{{Name: "a", Email: "a@x", Role: RoleReadonly, SessionEpoch: 4}}}
	s.UpsertHash("a", "h", RoleScopeAdmin)
	u, _ := s.Lookup("a")
	if u.Email != "a@x" || u.Role != RoleScopeAdmin || u.SessionEpoch != 5 || u.PasswordHash != "h" {
		t.Errorf("user after UpsertHash = %+v", u)
	}
}

func TestEnsureSessionKey_LegacyDocumentStaysVersionZero(t *testing.T) {
	s := &Store{Users: []User{{Name: "a"}}}
	if _, err := s.EnsureSessionKey("core-1"); err != nil {
		t.Fatal(err)
	}
	if s.Meta().Version != 0 {
		t.Error("creating the key must not turn a never-replicated document into a competing revision")
	}
	r := &Store{Version: 1, SessionKey: "aa"}
	if _, err := r.EnsureSessionKey("core-1"); err != nil || r.Meta().Version != 1 {
		t.Error("an existing key on a replicated document must stay untouched")
	}
}
