// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWriteFileReplacesStaleReadOnlyTemp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dnsmasq-x.conf")
	if err := os.WriteFile(path+".tmp", []byte("stale"), 0o400); err != nil {
		t.Fatal(err)
	}

	if err := atomicWriteFile(path, []byte("new"), 0o640); err != nil {
		t.Fatalf("write over stale temp: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "new" {
		t.Fatalf("content = %q, %v; want %q", got, err, "new")
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file left behind: %v", err)
	}
}

func TestChownToServiceUserNonRootIsNoop(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "f")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := chownToServiceUser(f, 1000); err != nil {
		t.Errorf("non-root: %v", err)
	}
}
