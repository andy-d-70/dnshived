// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

//go:build !labprofile

package main

import "testing"

func TestNormalRelayBuildCarriesNoLabTool(t *testing.T) {
	if labEnabled || labMarker != "" || labEnableFile != "" || labVersionSuffix() != "" {
		t.Error("a normal build must not carry the lab profile tool")
	}
	labStart(func() string { t.Error("the directory function must never be called"); return "" })
}
