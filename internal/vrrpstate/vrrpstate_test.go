// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package vrrpstate

import (
	"os"
	"testing"
)

func TestVerifyProcessIsKeepalived_WrongComm(t *testing.T) {
	// The test binary itself is definitely not named "keepalived".
	if err := verifyProcessIsKeepalived(os.Getpid()); err == nil {
		t.Error("expected an error for a pid whose comm is not keepalived")
	}
}

func TestVerifyProcessIsKeepalived_NonexistentPid(t *testing.T) {
	// PID 1 is always init/systemd, never keepalived, and always exists —
	// use an implausibly high PID instead to hit the "no such process" path.
	if err := verifyProcessIsKeepalived(1 << 30); err == nil {
		t.Error("expected an error for a nonexistent pid")
	}
}

func TestParseInstanceState(t *testing.T) {
	data, err := os.ReadFile("testdata/keepalived.data")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	cases := []struct {
		instance string
		want     string
		wantErr  bool
	}{
		{"DNSHIVED_office", "BACKUP", false},
		{"DNSHIVED_avdante", "MASTER", false},
		{"DNSHIVED_nonexistent", "", true},
		// A shorter name must not match as a prefix of a longer one.
		{"DNSHIVED_off", "", true},
	}

	for _, c := range cases {
		got, err := ParseInstanceState(data, c.instance)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: expected error, got state %q", c.instance, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error: %v", c.instance, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.instance, got, c.want)
		}
	}
}
