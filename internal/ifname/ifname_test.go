// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package ifname

import (
	"os"
	"path/filepath"
	"testing"
)

func withFakeSys(t *testing.T, present []string, alt map[string]string) *int {
	t.Helper()
	dir := t.TempDir()
	for _, p := range present {
		os.WriteFile(filepath.Join(dir, p), nil, 0o644)
	}
	calls := 0
	origSys, origLookup := sysClassNet, lookupAltname
	sysClassNet = dir + "/"
	lookupAltname = func(name string) (string, bool) {
		calls++
		k, ok := alt[name]
		return k, ok
	}
	mu.Lock()
	cache = map[string]entry{}
	logged = map[string]string{}
	mu.Unlock()
	t.Cleanup(func() { sysClassNet, lookupAltname = origSys, origLookup })
	return &calls
}

func TestResolve_KernelNameUnchangedWithoutLookup(t *testing.T) {
	calls := withFakeSys(t, []string{"eth1"}, nil)
	if got := Resolve("eth1"); got != "eth1" {
		t.Fatalf("Resolve(eth1) = %q", got)
	}
	if *calls != 0 {
		t.Errorf("kernel name triggered %d altname lookups, want 0", *calls)
	}
}

func TestResolve_AltnameMapsToKernelNameAndIsCached(t *testing.T) {
	calls := withFakeSys(t, []string{"eth1"}, map[string]string{"ens19": "eth1"})
	for i := 0; i < 3; i++ {
		if got := Resolve("ens19"); got != "eth1" {
			t.Fatalf("Resolve(ens19) = %q, want eth1", got)
		}
	}
	if *calls != 1 {
		t.Errorf("altname looked up %d times, want 1 (cached)", *calls)
	}
}

func TestResolve_UnknownNameReturnedAsIs(t *testing.T) {
	withFakeSys(t, nil, nil)
	if got := Resolve("ens99"); got != "ens99" {
		t.Errorf("Resolve(ens99) = %q, want ens99", got)
	}
	if got := Resolve(""); got != "" {
		t.Errorf("Resolve(\"\") = %q", got)
	}
}
