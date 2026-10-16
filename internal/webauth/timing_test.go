// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package webauth

import "testing"

func TestVerify_UnknownUserStillHashes(t *testing.T) {
	s := &Store{}
	if err := s.Upsert("admin", "right", "admin"); err != nil {
		t.Fatal(err)
	}
	var hashed []string
	orig := verifyPassword
	verifyPassword = func(password, stored string) bool {
		hashed = append(hashed, stored)
		return orig(password, stored)
	}
	t.Cleanup(func() { verifyPassword = orig })

	if _, ok := s.Verify("nobody", "guess"); ok {
		t.Fatal("unknown user verified")
	}
	if len(hashed) != 1 || hashed[0] != dummyHash() || hashed[0] == "" {
		t.Errorf("unknown user: %d hash checks against %v, want exactly one against the dummy hash", len(hashed), hashed)
	}
	hashed = nil
	if _, ok := s.Verify("admin", "right"); !ok || len(hashed) != 1 {
		t.Errorf("known user: ok=%v checks=%d", ok, len(hashed))
	}
}
