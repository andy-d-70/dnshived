// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsanswer

import (
	"strings"
	"testing"
)

func TestCanonicalName_FastPathAgreesWithTheFullCheck(t *testing.T) {
	for _, s := range []string{
		"a", "a.b", "host-1.example.lan", "_sip._tcp.example.lan", "A.b", "a.b.", ".a", "a..b", "", ".", "*.a", "a.*", "a b",
		strings.Repeat("a", 63), strings.Repeat("a", 64), strings.Repeat("a.", 126) + "a", strings.Repeat("a.", 127) + "a",
		"xn--bcher-kva.de", "bücher.de", "a-.b", "-a.b", "a_b.c", "1.0.0.10.in-addr.arpa",
	} {
		full, ferr := canonicalName(s)
		got, err := CanonicalName(s)
		if got != full || (err == nil) != (ferr == nil) {
			t.Errorf("%q: CanonicalName = %q, %v; full check = %q, %v", s, got, err, full, ferr)
		}
		if canonicalAlready(s) && (ferr != nil || full != s) {
			t.Errorf("%q: the fast path accepts what the full check changes or refuses", s)
		}
	}
}

func FuzzCanonicalName(f *testing.F) {
	for _, s := range []string{"a.b", "A.B.", "*.x", "_a._b.c", "", "xn--a"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		full, ferr := canonicalName(s)
		got, err := CanonicalName(s)
		if got != full || (err == nil) != (ferr == nil) {
			t.Fatalf("%q: %q, %v versus %q, %v", s, got, err, full, ferr)
		}
	})
}
