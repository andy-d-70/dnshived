// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package repohygiene

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var compiledMagic = [][]byte{
	{0x7f, 'E', 'L', 'F'},
	{0xcf, 0xfa, 0xed, 0xfe},
	{0xce, 0xfa, 0xed, 0xfe},
	{0xfe, 0xed, 0xfa, 0xce},
	{0xfe, 0xed, 0xfa, 0xcf},
}

func TestNoCompiledFileIsTracked(t *testing.T) {
	top, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skip("not inside a git work tree")
	}
	root := strings.TrimSpace(string(top))
	if idx, err := exec.Command("git", "-C", root, "rev-parse", "--path-format=absolute", "--git-path", "index").Output(); err == nil {
		if f, err := os.Open(strings.TrimSpace(string(idx))); err == nil {
			_ = f.Close()
		}
	}
	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		t.Skip("git ls-files failed")
	}
	for _, name := range strings.Split(string(out), "\x00") {
		if name == "" {
			continue
		}
		f, err := os.Open(filepath.Join(root, name))
		if err != nil {
			continue
		}
		head := make([]byte, 4)
		n, _ := f.Read(head)
		_ = f.Close()
		for _, m := range compiledMagic {
			if n == 4 && bytes.Equal(head, m) {
				t.Errorf("%s is a compiled file tracked by git; build outputs are never committed", name)
			}
		}
	}
}
