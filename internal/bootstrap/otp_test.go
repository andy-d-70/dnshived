// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package bootstrap

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

var otpFormat = regexp.MustCompile(`^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}$`)

// TestGenerateOTP_MatchesExpectedFormat pins the human-readable shape.
func TestGenerateOTP_MatchesExpectedFormat(t *testing.T) {
	otp, err := GenerateOTP()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !otpFormat.MatchString(otp) {
		t.Errorf("GenerateOTP() = %q, does not match expected AAAA-BBBB-CCCC-DDDD shape", otp)
	}
}

func TestGenerateOTP_ExcludesAmbiguousCharacters(t *testing.T) {
	if len(otpAlphabet) != 32 {
		t.Fatalf("otpAlphabet has %d characters, want exactly 32 (byte&0x1F must map onto it without bias)", len(otpAlphabet))
	}
	for _, ambiguous := range []byte{'0', 'O', '1', 'I'} {
		for i := 0; i < len(otpAlphabet); i++ {
			if otpAlphabet[i] == ambiguous {
				t.Errorf("otpAlphabet contains ambiguous character %q", ambiguous)
			}
		}
	}
}

// TestGenerateOTP_ProducesDistinctValues is a coarse randomness sanity
// check, not a statistical entropy proof.
func TestGenerateOTP_ProducesDistinctValues(t *testing.T) {
	a, err := GenerateOTP()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	b, err := GenerateOTP()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a == b {
		t.Errorf("two independent GenerateOTP() calls produced the same value %q", a)
	}
}

func TestLoadOrCreateOTP_GeneratesAndPersistsOnFirstCall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap-otp")

	otp, err := LoadOrCreateOTP(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !otpFormat.MatchString(otp) {
		t.Errorf("LoadOrCreateOTP() = %q, does not match expected format", otp)
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected file to exist after LoadOrCreateOTP: %v", err)
	}
	if string(onDisk) != otp {
		t.Errorf("on-disk content %q does not match returned value %q", onDisk, otp)
	}
}

func TestLoadOrCreateOTP_IdempotentAcrossRestarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap-otp")

	first, err := LoadOrCreateOTP(path)
	if err != nil {
		t.Fatalf("unexpected error on first call: %v", err)
	}
	second, err := LoadOrCreateOTP(path)
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}

	if first != second {
		t.Errorf("LoadOrCreateOTP() returned %q then %q — must be stable across calls", first, second)
	}
}

func TestLoadOrCreateOTP_FilePermissionsNoOtherAccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap-otp")

	if _, err := LoadOrCreateOTP(path); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o640 {
		t.Errorf("file permissions = %o, want 0640", perm)
	}
}

func TestLoadOrCreateOTP_ConcurrentCallersAgreeOnOneCode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "otp")
	const n = 16
	codes := make(chan string, n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			c, err := LoadOrCreateOTP(path)
			errs <- err
			codes <- c
		}()
	}
	first := ""
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("LoadOrCreateOTP: %v", err)
		}
		c := <-codes
		if first == "" {
			first = c
		} else if c != first {
			t.Fatalf("callers got different codes: %q and %q", first, c)
		}
	}
	onDisk, _ := os.ReadFile(path)
	if string(onDisk) != first {
		t.Errorf("file holds %q, callers got %q", onDisk, first)
	}
}
