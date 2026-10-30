// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadOrCreateProbeCert_StableAcrossStarts(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	_, first, err := loadOrCreateProbeCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first, "sha256:") || len(first) != len("sha256:")+64 {
		t.Fatalf("fingerprint %q is not sha256:<64 hex>", first)
	}
	_, second, err := loadOrCreateProbeCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("fingerprint changed across starts: %s then %s", first, second)
	}
	info, err := os.Stat(filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key.pem mode %v, want 0600", info.Mode().Perm())
	}
}
