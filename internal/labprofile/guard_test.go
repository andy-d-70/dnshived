// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package labprofile

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// No release recipe may turn the lab profiling tool on.
func TestReleaseRecipesNeverSetTheLabTag(t *testing.T) {
	for _, f := range []string{"../../debian/rules", "../../rpm/dnshived.spec", "../../.github/workflows/ci.yml"} {
		b, err := os.ReadFile(f)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "labprofile") {
			t.Errorf("%s mentions the labprofile tag; only make lab-deb and make lab-rpm may set it", f)
		}
	}
	mk, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(string(mk), "\n") {
		if strings.Contains(line, "labprofile") && !strings.HasPrefix(strings.TrimSpace(line), "GOFLAGS=-tags=labprofile $(MAKE)") && !strings.HasPrefix(line, "#") {
			t.Errorf("Makefile line %d sets the lab tag outside the lab-deb and lab-rpm recipes: %q", i+1, line)
		}
	}
}

func TestReleaseGuardScriptCarriesTheSameMarker(t *testing.T) {
	b, err := os.ReadFile("../../tools/release-guard.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `MARKER="DNSHIVED-LAB-PROFILE""-BUILD"`) {
		t.Error("tools/release-guard.sh must search for the marker string compiled into the lab build")
	}
}

func runGuard(t *testing.T, files ...string) (int, string) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{"../../tools/release-guard.sh"}, files...)...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, string(out)
}

func TestReleaseGuardScript(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	marker := "DNSHIVED-LAB-PROFILE" + "-BUILD"
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if code, out := runGuard(t, write("clean.bin", strings.Repeat("ordinary binary data ", 1000))); code != 0 {
		t.Errorf("a clean file must pass, got %d: %s", code, out)
	}
	if code, _ := runGuard(t, write("dirty.bin", strings.Repeat("x", 100000)+marker+strings.Repeat("y", 100000))); code != 1 {
		t.Errorf("a file with the marker must be refused with 1, got %d", code)
	}
	if code, _ := runGuard(t, write("lab.LAB-PROFILE.bin", "clean content")); code != 1 {
		t.Errorf("a file named as a lab build must be refused, got %d", code)
	}
	if code, _ := runGuard(t, write("empty.bin", "")); code != 2 {
		t.Errorf("an empty file must not count as clean (want 2), got %d", code)
	}

	if _, err := exec.LookPath("dpkg-deb"); err != nil {
		t.Log("dpkg-deb not available, the .deb cases are skipped")
		return
	}
	build := func(name, content string) string {
		root := filepath.Join(dir, name+"-root")
		if err := os.MkdirAll(filepath.Join(root, "DEBIAN"), 0o755); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(root, "DEBIAN", "control"), []byte("Package: guardtest\nVersion: 1\nArchitecture: all\nMaintainer: t <t@example.com>\nDescription: t\n"), 0o644)
		os.WriteFile(filepath.Join(root, "binary"), []byte(content), 0o755)
		deb := filepath.Join(dir, name+".deb")
		if out, err := exec.Command("dpkg-deb", "--build", "--root-owner-group", root, deb).CombinedOutput(); err != nil {
			t.Skipf("cannot build a test deb: %v %s", err, out)
		}
		return deb
	}
	if code, out := runGuard(t, build("clean", strings.Repeat("ordinary ", 5000))); code != 0 {
		t.Errorf("a clean deb must pass, got %d: %s", code, out)
	}
	if code, out := runGuard(t, build("dirty", strings.Repeat("ordinary ", 5000)+marker)); code != 1 {
		t.Errorf("a deb whose binary carries the marker must be refused even when renamed (want 1), got %d: %s", code, out)
	}
}
