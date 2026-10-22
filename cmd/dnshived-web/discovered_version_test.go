// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"strings"
	"testing"

	"dnshived/internal/discovery"
)

func TestConfigFormTmpl_DiscoveredVersionMismatchFlaggedWarn(t *testing.T) {
	data := clusterFormData{
		ThisVersion: "0.9.8-63+c313d6a",
		Discovered: []discovery.Candidate{
			{Addr: "192.0.2.50", Hostname: "old-node", Version: "0.9.5-3+abc1234", BootstrapPort: 9080},
		},
	}
	var buf strings.Builder
	if err := configFormTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `class="warn" title="this cluster is on 0.9.8-63`) {
		t.Errorf("expected a warn-class cell with an explanatory tooltip for the mismatched version, got:\n%s", out)
	}
	if !strings.Contains(out, "at your own risk") {
		t.Errorf("expected the explicit go-ahead-at-your-own-risk framing in the tooltip, got:\n%s", out)
	}
	if !strings.Contains(out, "0.9.5-3") || !strings.Contains(out, "abc1234") {
		t.Errorf("expected the candidate's own real version string to still be shown, got:\n%s", out)
	}
}

// TestConfigFormTmpl_DiscoveredSameVersionIsNotFlagged confirms the common
// case (candidate reports the identical version) renders a plain,
// unflagged cell.
func TestConfigFormTmpl_DiscoveredSameVersionIsNotFlagged(t *testing.T) {
	data := clusterFormData{
		ThisVersion: "0.9.8-63+c313d6a",
		Discovered: []discovery.Candidate{
			{Addr: "192.0.2.50", Hostname: "same-version-node", Version: "0.9.8-63+c313d6a", BootstrapPort: 9080},
		},
	}
	var buf strings.Builder
	if err := configFormTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, `class="warn" title="this cluster is on`) {
		t.Errorf("did not expect a version-mismatch warning for a candidate on the identical version, got:\n%s", out)
	}
}
