// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsanswer

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The relay is its own module and cannot import internal packages, so it carries a verbatim copy of this package.
func TestRelayCopyIsIdentical(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, f := range files {
		if len(f) > 8 && f[len(f)-8:] == "_test.go" {
			continue
		}
		want, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join("..", "..", "cmd", "dnshived-dnsrelay", "dnsanswer", f))
		if err != nil {
			t.Fatalf("the relay copy of %s is missing: %v", f, err)
		}
		if !bytes.Equal(want, got) {
			t.Errorf("%s differs from the relay copy; copy it over with: cp internal/dnsanswer/%s cmd/dnshived-dnsrelay/dnsanswer/", f, f)
		}
		checked++
	}
	if checked < 6 {
		t.Fatalf("only %d files compared", checked)
	}
}
