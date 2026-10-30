// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package ownership

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

func TestDnshived_SetsOwnerWhenAccountExists(t *testing.T) {
	u, err := user.Lookup("dnshived")
	if err != nil {
		t.Skip("no dnshived account on this host")
	}
	if os.Geteuid() != 0 {
		t.Skip("changing ownership needs root")
	}
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := Dnshived(path); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strconv.Itoa(int(st.Sys().(*syscall.Stat_t).Uid)); got != u.Uid {
		t.Fatalf("owner uid %s, want %s", got, u.Uid)
	}
}
