// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package daemonstatus

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestQueryVersion_ExecsOnlyWhenBinaryChanges(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "fake-daemon")
	os.WriteFile(bin, []byte("v1"), 0o755)
	execs := 0
	orig := versionExec
	versionExec = func(ctx context.Context, b string) ([]byte, error) {
		execs++
		data, _ := os.ReadFile(b)
		return []byte("fake-daemon " + string(data) + "\n"), nil
	}
	t.Cleanup(func() { versionExec = orig })

	for i := 0; i < 3; i++ {
		if v := Version(bin); v != "v1" {
			t.Fatalf("Version = %q, want v1", v)
		}
	}
	if execs != 1 {
		t.Errorf("%d --version execs for an unchanged binary, want 1", execs)
	}

	os.WriteFile(bin, []byte("v2.0"), 0o755)
	later := time.Now().Add(time.Minute)
	os.Chtimes(bin, later, later)
	if v := Version(bin); v != "v2.0" {
		t.Errorf("after upgrade Version = %q, want v2.0", v)
	}
	if execs != 2 {
		t.Errorf("%d execs after the binary changed, want 2", execs)
	}
}
