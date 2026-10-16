// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVlanOnParent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	os.WriteFile(path, []byte("VLAN Dev name\t | VLAN ID\nName-Type: VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD\nens19.110       | 110  | eth1\neth2.150        | 150  | eth2\n"), 0o644)
	orig := vlanConfigPath
	vlanConfigPath = path
	t.Cleanup(func() { vlanConfigPath = orig })

	if got := vlanOnParent("eth1", 110); got != "ens19.110" {
		t.Errorf("vlanOnParent(eth1, 110) = %q, want ens19.110", got)
	}
	if got := vlanOnParent("eth2", 150); got != "eth2.150" {
		t.Errorf("vlanOnParent(eth2, 150) = %q", got)
	}
	if got := vlanOnParent("eth1", 150); got != "" {
		t.Errorf("vlanOnParent(eth1, 150) = %q, want none (other parent)", got)
	}
	if got := vlanOnParent("eth1", 11); got != "" {
		t.Errorf("vlanOnParent(eth1, 11) = %q, want none (prefix of 110)", got)
	}
}
