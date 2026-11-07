// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package webauth

import "testing"

func TestMinPasswordLength_SpreadsWithTheUserStore(t *testing.T) {
	remote := &Store{}
	if err := remote.Mutate("core-1", func(d *Store) error {
		d.MinPasswordLength = 16
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	local := &Store{}
	if adopted, _ := local.Adopt(remote, "core-2"); !adopted {
		t.Fatal("the newer document was not adopted")
	}
	if got := local.PasswordMinLength(); got != 16 {
		t.Errorf("minimum after adopting = %d, want 16", got)
	}
}
