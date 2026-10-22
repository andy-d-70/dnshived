// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package desired

import (
	"fmt"
	"strings"
	"testing"
)

func TestJoinDiff_ListsAllWhenShort(t *testing.T) {
	lines := []string{"a: here=x peer=y", "b: here=x peer=missing"}
	if got, want := JoinDiff(lines), strings.Join(lines, "; "); got != want {
		t.Fatalf("JoinDiff = %q, want %q", got, want)
	}
}

func TestJoinDiff_CapsLongListAndCountsTheRest(t *testing.T) {
	var lines []string
	for i := 0; i < maxDetailScopes+5; i++ {
		lines = append(lines, fmt.Sprintf("scope%02d: here=a peer=b", i))
	}
	got := JoinDiff(lines)
	if !strings.HasSuffix(got, "; (+5 more)") {
		t.Fatalf("JoinDiff = %q, want suffix %q", got, "; (+5 more)")
	}
	if n := strings.Count(got, "scope"); n != maxDetailScopes {
		t.Fatalf("JoinDiff lists %d scopes, want %d", n, maxDetailScopes)
	}
}
