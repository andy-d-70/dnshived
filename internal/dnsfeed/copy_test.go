// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsfeed

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The relay is its own module and carries a copy of the reader side of this package; only the import path of
// dnsanswer differs.
func TestRelayCopyIsIdentical(t *testing.T) {
	for _, f := range []string{"frame.go", "delta.go", "consumer.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		want := bytes.ReplaceAll(src, []byte(`"dnshived/internal/dnsanswer"`), []byte(`"dnsrelay/dnsanswer"`))
		got, err := os.ReadFile(filepath.Join("..", "..", "cmd", "dnshived-dnsrelay", "dnsfeed", f))
		if err != nil {
			t.Fatalf("the relay copy of %s is missing: %v", f, err)
		}
		if !bytes.Equal(want, got) {
			t.Errorf("%s differs from the relay copy; regenerate it with: sed 's#\"dnshived/internal/dnsanswer\"#\"dnsrelay/dnsanswer\"#' internal/dnsfeed/%s > cmd/dnshived-dnsrelay/dnsfeed/%s", f, f, f)
		}
	}
}
