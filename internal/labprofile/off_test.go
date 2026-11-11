// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

//go:build !labprofile

package labprofile

import "testing"

// A normal build carries nothing of the lab tool: no marker string, no suffix,
// and Start installs nothing.
func TestNormalBuildCarriesNothing(t *testing.T) {
	if Enabled || Marker != "" || EnableFile != "" || VersionSuffix() != "" {
		t.Error("a normal build must not carry the lab profile tool")
	}
	Start(func() string { t.Error("the directory function must never be called"); return "" })
}
