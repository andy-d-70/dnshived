// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package instlock

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestAcquire_SecondInstanceRefusedAndNamesHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.lock")
	first, err := acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	pid, _ := os.ReadFile(path)
	if strings.TrimSpace(string(pid)) != strconv.Itoa(os.Getpid()) {
		t.Fatalf("lock file holds %q, want this pid", pid)
	}
	if second, err := acquire(path); err == nil {
		second.Close()
		t.Fatal("second instance acquired the lock")
	} else if !strings.Contains(err.Error(), "already running") {
		t.Fatalf("error %q does not say already running", err)
	}
}
