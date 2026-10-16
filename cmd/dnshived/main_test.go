// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"testing"

	"dnshived/internal/config"
)

func TestMgmtIfaceFromConfig_NilPlatformReturnsEmpty(t *testing.T) {
	cfg := &config.Cluster{Platform: nil}
	if got := mgmtIfaceFromConfig(cfg); got != "" {
		t.Errorf("mgmtIfaceFromConfig = %q, want empty string for a nil Platform", got)
	}
}

// TestMgmtIfaceFromConfig_ReturnsConfiguredMgmtInterface checks the
// normal, non-nil case.
func TestMgmtIfaceFromConfig_ReturnsConfiguredMgmtInterface(t *testing.T) {
	cfg := &config.Cluster{Platform: &config.Platform{Mgmt: "ens18"}}
	if got := mgmtIfaceFromConfig(cfg); got != "ens18" {
		t.Errorf("mgmtIfaceFromConfig = %q, want %q", got, "ens18")
	}
}
