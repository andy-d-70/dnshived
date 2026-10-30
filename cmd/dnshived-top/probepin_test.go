// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"strings"
	"testing"
)

func TestProbePinFlag_AcceptsHostPortAndValidFingerprint(t *testing.T) {
	saved := probePins
	probePins = map[string]string{}
	t.Cleanup(func() { probePins = saved })

	fp := "sha256:" + strings.Repeat("cd", 32)
	if err := (probePinFlag{}).Set("192.0.2.43:9445=" + fp); err != nil {
		t.Fatalf("valid pin rejected: %v", err)
	}
	if probePins["192.0.2.43:9445"] != fp {
		t.Fatalf("pin not stored: %v", probePins)
	}
	for _, bad := range []string{"192.0.2.43:9445", "=" + fp, "192.0.2.43:9445=sha256:xyz"} {
		if err := (probePinFlag{}).Set(bad); err == nil {
			t.Errorf("Set(%q) accepted, want error", bad)
		}
	}
}
