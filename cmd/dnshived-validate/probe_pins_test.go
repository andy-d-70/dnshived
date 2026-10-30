// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestProbeTargetsPinned_PinnedAddressUsesHTTPS(t *testing.T) {
	fp := "sha256:" + strings.Repeat("ab", 32)
	got := probeTargetsPinned("192.0.2.54:9445", filepath.Join(t.TempDir(), "missing.json"), map[string]string{"192.0.2.54:9445": fp})
	if len(got) != 1 || got[0] != "https://192.0.2.54:9445" {
		t.Fatalf("targets = %v, want [https://192.0.2.54:9445]", got)
	}
}

func TestProbeTargetsPinned_PinAloneAddsProbe(t *testing.T) {
	fp := "sha256:" + strings.Repeat("cd", 32)
	got := probeTargetsPinned("", filepath.Join(t.TempDir(), "missing.json"), map[string]string{"192.0.2.60:9445": fp})
	if !slices.Equal(got, []string{"https://192.0.2.60:9445"}) {
		t.Fatalf("targets = %v", got)
	}
}

func TestWebProbePins_PinnedWebEntryUsesTLSPort(t *testing.T) {
	fp := "sha256:" + strings.Repeat("ef", 32)
	path := filepath.Join(t.TempDir(), "web.json")
	body := `{"probe_hosts":[` +
		`{"addr":"192.0.2.43:9444","tls_port":"9445","tls_fingerprint":"` + fp + `"},` +
		`{"addr":"192.0.2.44:9444"}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := probeTargets("", path); !slices.Equal(got, []string{"https://192.0.2.43:9445", "http://192.0.2.44:9444"}) {
		t.Fatalf("targets = %v", got)
	}
	if got := webProbePins(path); len(got) != 1 || got["192.0.2.43:9445"] != fp {
		t.Fatalf("pins = %v", got)
	}
}
