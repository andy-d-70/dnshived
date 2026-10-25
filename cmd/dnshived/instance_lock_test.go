// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAcquireInstanceLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.lock")

	first, err := acquireInstanceLock(path)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}

	second, err := acquireInstanceLock(path)
	if !errors.Is(err, errInstanceRunning) {
		t.Fatalf("second acquire: want errInstanceRunning, got %v", err)
	}
	if second != nil {
		second.Close()
	}
	holder, _ := os.ReadFile(path)
	if !strings.Contains(err.Error(), strings.TrimSpace(string(holder))) {
		t.Errorf("error %q does not name the holder pid %q", err, holder)
	}

	first.Close()
	third, err := acquireInstanceLock(path)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	third.Close()
}
