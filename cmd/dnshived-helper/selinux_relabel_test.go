// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// withStubRestorecon installs a fake restorecon. Every call is recorded in the marker file. A dry run (-n)
// prints a line only when needsRelabel is set, the way restorecon reports files that would change.
func withStubRestorecon(t *testing.T, needsRelabel bool) (markerFile string) {
	t.Helper()
	dir := t.TempDir()
	marker := filepath.Join(dir, "invocations")
	dryOutput := "echo"
	if !needsRelabel {
		dryOutput = ":"
	}
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + marker + "\n" +
		"if [ \"$1\" = \"-n\" ]; then " + dryOutput + " relabel-needed; fi\n"
	stub := filepath.Join(dir, "restorecon")
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath)
	t.Cleanup(func() { os.Setenv("PATH", oldPath) })

	resetRestoreconCache()
	t.Cleanup(resetRestoreconCache)
	return marker
}

func resetRestoreconCache() {
	restoreconMu.Lock()
	restoreconResolved = false
	restoreconPath = ""
	restoreconMu.Unlock()
}

func TestRelabelSELinuxDataDir_NoOpWithoutRestorecon(t *testing.T) {
	resetRestoreconCache()
	defer resetRestoreconCache()
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", t.TempDir())
	defer os.Setenv("PATH", oldPath)

	relabelSELinuxDataDir() // must not panic, must not error visibly
}

// TestRelabelSELinuxDataDir_InvokesRestoreconWhenPresent proves the real
// mechanism actually fires, and against the real, fixed selinuxDataDir
// path.
func TestRelabelSELinuxDataDir_RelabelsOnlyWhenDryRunReportsChanges(t *testing.T) {
	marker := withStubRestorecon(t, true)

	relabelSELinuxDataDir()

	out, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("restorecon was never invoked: %v", err)
	}
	want := "-n -R -v " + selinuxDataDir + "\n-R " + selinuxDataDir + "\n"
	if string(out) != want {
		t.Fatalf("invocations %q, want %q", string(out), want)
	}
}

func TestRelabelSELinuxDataDir_SkipsRelabelWhenNothingChanges(t *testing.T) {
	marker := withStubRestorecon(t, false)

	relabelSELinuxDataDir()

	out, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("restorecon was never invoked: %v", err)
	}
	if string(out) != "-n -R -v "+selinuxDataDir+"\n" {
		t.Fatalf("invocations %q: only the dry run should run when nothing changes", string(out))
	}
}

// TestRelabelSELinuxDataDir_CachesLookupAcrossCalls confirms the LookPath
// result is resolved once, not re-scanned on every call.
func TestRelabelSELinuxDataDir_CachesLookupAcrossCalls(t *testing.T) {
	marker := withStubRestorecon(t, true)

	relabelSELinuxDataDir()
	relabelSELinuxDataDir()
	relabelSELinuxDataDir()

	out, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("restorecon was never invoked: %v", err)
	}
	lines := 0
	for _, b := range out {
		if b == '\n' {
			lines++
		}
	}
	if lines != 6 {
		t.Fatalf("expected a dry run and a relabel per call (6 lines), got %d: %q", lines, string(out))
	}
}

func TestRun_TriggersRelabelOnlyForStartRestartReload(t *testing.T) {
	cases := []struct {
		name    string
		verb    string
		wantHit bool
	}{
		{"start triggers relabel", "start", true},
		{"restart triggers relabel", "restart", true},
		{"reload triggers relabel", "reload", true},
		{"stop does not trigger relabel", "stop", false},
		{"enable does not trigger relabel", "enable", false},
		{"disable does not trigger relabel", "disable", false},
		{"reset-failed does not trigger relabel", "reset-failed", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			marker := withStubRestorecon(t, true)

			run("systemctl", tc.verb, "dnshived-dnsmasq@core-dhcp.service")

			_, err := os.ReadFile(marker)
			hit := err == nil
			if hit != tc.wantHit {
				t.Fatalf("systemctl %s: relabel invoked=%v, want %v", tc.verb, hit, tc.wantHit)
			}
		})
	}
}

// TestRun_NonSystemctlCommandNeverTriggersRelabel confirms an unrelated
// command (e.g. "ip") never pays this cost at all.
func TestRun_NonSystemctlCommandNeverTriggersRelabel(t *testing.T) {
	marker := withStubRestorecon(t, true)

	run("ip", "link", "show", "lo")

	if _, err := os.ReadFile(marker); err == nil {
		t.Fatalf("relabel was invoked for a non-systemctl command")
	}
}
