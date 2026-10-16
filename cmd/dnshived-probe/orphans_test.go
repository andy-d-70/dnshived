// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net"
	"os/exec"
	"path/filepath"
	"testing"
)

func requireRootProbe(t *testing.T) {
	t.Helper()
	if out, err := exec.Command("id", "-u").Output(); err != nil || string(out) != "0\n" {
		t.Skip("requires root")
	}
}

func TestReconcileOrphanVLANs_RemovesRealOrphanKeepsDesiredOne(t *testing.T) {
	requireRootProbe(t)

	trunk := "dnporph0"
	exec.Command("ip", "link", "delete", trunk).Run()
	if err := exec.Command("ip", "link", "add", trunk, "type", "dummy").Run(); err != nil {
		t.Fatalf("create dummy trunk: %v", err)
	}
	t.Cleanup(func() { exec.Command("ip", "link", "delete", trunk).Run() })
	exec.Command("ip", "link", "set", trunk, "up").Run()
	// A "desired" scope's own interface (should survive) and an orphan with no
	// matching desired entry.
	if err := exec.Command("ip", "link", "add", "link", trunk, "name", trunk+".10", "type", "vlan", "id", "10").Run(); err != nil {
		t.Fatalf("create desired vlan: %v", err)
	}
	if err := exec.Command("ip", "link", "add", "link", trunk, "name", trunk+".66", "type", "vlan", "id", "66").Run(); err != nil {
		t.Fatalf("create orphan vlan: %v", err)
	}
	exec.Command("ip", "link", "set", trunk+".10", "up").Run()
	exec.Command("ip", "link", "set", trunk+".66", "up").Run()

	helper := newFakeProbeHelper(t)
	cfg := &ProbeConfig{
		LocalOctet: 42, TrunkParents: []string{trunk},
		ProbeHelperSocket: helper.socketPath,
		KnownVLANsPath:    filepath.Join(t.TempDir(), "known-vlans.json"),
	}
	desired := map[string]knownVLAN{
		vlanKey(trunk, 10): {Parent: trunk, VLANID: 10, VIP: "192.168.10.1/24"},
	}

	removed := reconcileOrphanVLANs(cfg, desired)

	if len(removed) != 1 || removed[0] != "-"+vlanKey(trunk, 66) {
		t.Errorf("removed = %v, want exactly [-%s]", removed, vlanKey(trunk, 66))
	}
	if len(helper.deleted) != 1 || helper.deleted[0] != trunk+".66" {
		t.Errorf("helper.deleted = %v, want [%s.66]", helper.deleted, trunk)
	}
	if _, err := net.InterfaceByName(trunk + ".10"); err != nil {
		t.Errorf("%s.10 (desired) should still exist as a real interface (unaffected by this test)", trunk)
	}
}

// TestReconcileOrphanVLANs_DisabledWhenLocalOctetZero mirrors
// reconcileVLANInterfaces' own identical no-op guard.
func TestReconcileOrphanVLANs_DisabledWhenLocalOctetZero(t *testing.T) {
	cfg := &ProbeConfig{LocalOctet: 0, TrunkParents: []string{"ens19"}}
	if got := reconcileOrphanVLANs(cfg, nil); got != nil {
		t.Errorf("reconcileOrphanVLANs with LocalOctet=0 = %v, want nil", got)
	}
}
