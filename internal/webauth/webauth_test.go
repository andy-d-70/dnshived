// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package webauth

import (
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

func TestHashAndVerifyPassword_RoundTrip(t *testing.T) {
	hash, err := HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !VerifyPassword("correct-horse-battery-staple", hash) {
		t.Error("VerifyPassword rejected the correct password")
	}
}

func TestVerifyPassword_WrongPasswordRejected(t *testing.T) {
	hash, err := HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if VerifyPassword("wrong-password", hash) {
		t.Error("VerifyPassword accepted an incorrect password")
	}
}

func TestHashPassword_UniqueSaltPerCall(t *testing.T) {
	h1, err1 := HashPassword("same-password")
	h2, err2 := HashPassword("same-password")
	if err1 != nil || err2 != nil {
		t.Fatalf("HashPassword errors: %v, %v", err1, err2)
	}
	if h1 == h2 {
		t.Error("two hashes of the same password produced identical output — salt isn't varying")
	}
	// Both must still verify correctly despite differing.
	if !VerifyPassword("same-password", h1) || !VerifyPassword("same-password", h2) {
		t.Error("both independently-salted hashes should verify the same password")
	}
}

func TestVerifyPassword_MalformedHashFailsClosed(t *testing.T) {
	cases := []string{"", "not-enough-parts", "salt:not-a-number:key", "zzzz:600000:zzzz"}
	for _, c := range cases {
		if VerifyPassword("anything", c) {
			t.Errorf("VerifyPassword(%q) = true, want false (fail closed on malformed input)", c)
		}
	}
}

func TestStore_VerifyUnknownUserRejected(t *testing.T) {
	hash, _ := HashPassword("secret")
	s := &Store{Users: []User{{Name: "alice", PasswordHash: hash, Role: "admin"}}}

	if _, ok := s.Verify("bob", "secret"); ok {
		t.Error("Verify accepted an unknown username")
	}
}

func TestStore_VerifyCorrectCredentials(t *testing.T) {
	hash, _ := HashPassword("secret")
	s := &Store{Users: []User{{Name: "alice", PasswordHash: hash, Role: "admin"}}}

	u, ok := s.Verify("alice", "secret")
	if !ok {
		t.Fatal("Verify rejected correct credentials")
	}
	if u.Role != "admin" {
		t.Errorf("Role = %q, want admin", u.Role)
	}
}

func TestLoad_RoundTrip(t *testing.T) {
	hash, _ := HashPassword("secret")
	store := &Store{Users: []User{{Name: "alice", PasswordHash: hash, Role: "readonly"}}}
	data, err := json.Marshal(store)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "webui-users.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.Users) != 1 || loaded.Users[0].Name != "alice" {
		t.Errorf("loaded = %+v, want one user named alice", loaded.Users)
	}
}

func TestUpsert_AddsNewUser(t *testing.T) {
	s := &Store{}
	if err := s.Upsert("alice", "secret", "admin"); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if len(s.Users) != 1 || s.Users[0].Name != "alice" || s.Users[0].Role != "admin" {
		t.Fatalf("Users = %+v, want one alice/admin", s.Users)
	}
	if !VerifyPassword("secret", s.Users[0].PasswordHash) {
		t.Error("stored hash doesn't verify against the password just set")
	}
}

func TestUpsert_ResetsExistingUserPassword(t *testing.T) {
	oldHash, _ := HashPassword("old-password")
	s := &Store{Users: []User{{Name: "admin", PasswordHash: oldHash, Role: "admin"}}}

	if err := s.Upsert("admin", "new-password", "admin"); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if len(s.Users) != 1 {
		t.Fatalf("Upsert on an existing name must replace, not append — got %d users", len(s.Users))
	}
	if VerifyPassword("old-password", s.Users[0].PasswordHash) {
		t.Error("old password still verifies after reset — not actually replaced")
	}
	if !VerifyPassword("new-password", s.Users[0].PasswordHash) {
		t.Error("new password doesn't verify after reset")
	}
}

func TestUpsert_PreservesOtherUsers(t *testing.T) {
	bobHash, _ := HashPassword("bob-secret")
	s := &Store{Users: []User{{Name: "bob", PasswordHash: bobHash, Role: "readonly"}}}

	if err := s.Upsert("alice", "alice-secret", "admin"); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if len(s.Users) != 2 {
		t.Fatalf("Users = %+v, want bob preserved plus new alice", s.Users)
	}
	if _, ok := s.Verify("bob", "bob-secret"); !ok {
		t.Error("bob's credentials broke after adding a different user")
	}
}

func TestSaveLoad_RoundTrip(t *testing.T) {
	s := &Store{}
	if err := s.Upsert("admin", "secret", "admin"); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	path := filepath.Join(t.TempDir(), "webui-users.json")
	if err := s.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat saved file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o640 {
		t.Errorf("file permissions = %o, want 0640 (owner + the dnshived group only -- the service itself runs as that group, see Save's own doc comment)", perm)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := loaded.Verify("admin", "secret"); !ok {
		t.Error("round-tripped store doesn't verify the password that was just saved")
	}
}

func TestSave_GroupOwnedByDnshived(t *testing.T) {
	g, err := user.LookupGroup("dnshived")
	if err != nil {
		t.Skipf("no \"dnshived\" group on this host, skipping: %v", err)
	}
	s := &Store{}
	if err := s.Upsert("admin", "secret", "admin"); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	path := filepath.Join(t.TempDir(), "webui-users.json")
	if err := s.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("could not read raw stat_t for gid check")
	}
	wantGid, _ := strconv.Atoi(g.Gid)
	if int(stat.Gid) != wantGid {
		t.Errorf("webui-users.json group gid = %d, want %d (dnshived) — dnshived-web.service (User=dnshived) must be able to read its own users file", stat.Gid, wantGid)
	}
}

func TestSave_NoLeftoverTempFile(t *testing.T) {
	s := &Store{}
	if err := s.Upsert("admin", "secret", "admin"); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	path := filepath.Join(t.TempDir(), "webui-users.json")
	if err := s.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("expected no leftover .tmp file, stat err: %v", err)
	}
}

func TestSave_OverwriteReplacesContentAtomically(t *testing.T) {
	s := &Store{}
	if err := s.Upsert("admin", "first", "admin"); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	path := filepath.Join(t.TempDir(), "webui-users.json")
	if err := s.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := s.Upsert("admin", "second", "admin"); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := s.Save(path); err != nil {
		t.Fatalf("Save (overwrite): %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := loaded.Verify("admin", "first"); ok {
		t.Error("stale password from before the overwrite still verifies")
	}
	if _, ok := loaded.Verify("admin", "second"); !ok {
		t.Error("new password from the overwrite doesn't verify")
	}
}

func TestHasPermission_RoleGating(t *testing.T) {
	admin := User{Role: "admin"}
	readonly := User{Role: "readonly"}
	unknown := User{Role: "bogus-role"}

	if !admin.HasPermission(PermEditConfig) {
		t.Error("admin should have PermEditConfig")
	}
	if readonly.HasPermission(PermEditConfig) {
		t.Error("readonly must not have PermEditConfig")
	}
	if !readonly.HasPermission(PermViewStatus) {
		t.Error("readonly should have PermViewStatus")
	}
	if unknown.HasPermission(PermViewStatus) {
		t.Error("an unrecognized role must grant nothing (fail closed)")
	}
}
