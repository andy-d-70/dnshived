// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package rpfilter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeProc(t *testing.T, all string, ifaces ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range append([]string{"all"}, ifaces...) {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, d, "rp_filter"), []byte("2\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(root, "all", "rp_filter"), []byte(all+"\n"), 0o644)
	origRoot, origExists := procRoot, interfaceExists
	procRoot = root
	interfaceExists = func(string) error { return nil }
	t.Cleanup(func() { procRoot, interfaceExists = origRoot, origExists })
	return root
}

func TestDisableOnTrunk_SetsZero(t *testing.T) {
	root := fakeProc(t, "0", "ens19")
	if err := DisableOnTrunk("ens19"); err != nil {
		t.Fatalf("DisableOnTrunk: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(root, "ens19", "rp_filter"))
	if strings.TrimSpace(string(got)) != "0" {
		t.Errorf("ens19 rp_filter = %q, want 0", got)
	}
}

func TestDisableOnTrunk_ReportsNonZeroAll(t *testing.T) {
	root := fakeProc(t, "2", "ens19")
	err := DisableOnTrunk("ens19")
	if err == nil || !strings.Contains(err.Error(), "conf.all.rp_filter=2") {
		t.Fatalf("err = %v, want a conf.all warning", err)
	}
	got, _ := os.ReadFile(filepath.Join(root, "ens19", "rp_filter"))
	if strings.TrimSpace(string(got)) != "0" {
		t.Errorf("ens19 rp_filter = %q, want 0 even when all is non-zero", got)
	}
	gotAll, _ := os.ReadFile(filepath.Join(root, "all", "rp_filter"))
	if strings.TrimSpace(string(gotAll)) != "2" {
		t.Errorf("conf.all changed to %q, must be left alone", gotAll)
	}
}

func TestDisableOnTrunk_RejectsPathLikeNames(t *testing.T) {
	fakeProc(t, "0")
	for _, name := range []string{"", ".", "..", "../all", "a/b"} {
		if err := DisableOnTrunk(name); err == nil {
			t.Errorf("DisableOnTrunk(%q) = nil, want an error", name)
		}
	}
}

func TestValue(t *testing.T) {
	fakeProc(t, "0", "ens19")
	if got := Value("ens19"); got != "2" {
		t.Errorf("Value(ens19) = %q, want 2", got)
	}
	for _, name := range []string{"missing", "", "../all", ".."} {
		if got := Value(name); got != "unknown" {
			t.Errorf("Value(%q) = %q, want unknown", name, got)
		}
	}
}
