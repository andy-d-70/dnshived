// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"dnshived/internal/config"
	"dnshived/internal/helper"
)

// startIPHelper is a fake dnshived-helper that really deletes interfaces
// (delete-interface-unscoped) and records every request.
func startIPHelper(t *testing.T) (sock string, requests func() []helper.Request) {
	t.Helper()
	var mu sync.Mutex
	var got []helper.Request
	sock = filepath.Join(t.TempDir(), "helper.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req helper.Request
			if json.NewDecoder(conn).Decode(&req) == nil {
				mu.Lock()
				got = append(got, req)
				mu.Unlock()
				resp := helper.Response{OK: true}
				switch req.Command {
				case "delete-interface-unscoped":
					exec.Command("ip", "link", "delete", fmt.Sprintf("%s.%d", req.Parent, req.VLANID)).Run()
				case "dhcp-gate-dump":
					resp.GateDump = map[string]bool{}
				}
				json.NewEncoder(conn).Encode(resp)
			}
			conn.Close()
		}
	}()
	return sock, func() []helper.Request {
		mu.Lock()
		defer mu.Unlock()
		return append([]helper.Request(nil), got...)
	}
}

// requireRoot skips a test that needs real `ip link` privileges.
func requireRoot(t *testing.T) {
	t.Helper()
	if out, err := exec.Command("id", "-u").Output(); err != nil || string(out) != "0\n" {
		t.Skip("requires root")
	}
}

// setupOrphanTestTrunk creates a real dummy "trunk" interface plus two
// real VLAN sub-interfaces on it.
func setupOrphanTestTrunk(t *testing.T) (trunk string) {
	t.Helper()
	requireRoot(t)
	trunk = "dnstorph0"
	exec.Command("ip", "link", "delete", trunk).Run() // best-effort pre-clean
	if err := exec.Command("ip", "link", "add", trunk, "type", "dummy").Run(); err != nil {
		t.Fatalf("create dummy trunk: %v", err)
	}
	exec.Command("ip", "link", "set", trunk, "up").Run()
	t.Cleanup(func() { exec.Command("ip", "link", "delete", trunk).Run() })

	if err := exec.Command("ip", "link", "add", "link", trunk, "name", trunk+".100", "type", "vlan", "id", "100").Run(); err != nil {
		t.Fatalf("create real-scope vlan: %v", err)
	}
	if err := exec.Command("ip", "link", "add", "link", trunk, "name", trunk+".99", "type", "vlan", "id", "99").Run(); err != nil {
		t.Fatalf("create orphan vlan: %v", err)
	}
	exec.Command("ip", "link", "set", trunk+".100", "up").Run()
	exec.Command("ip", "link", "set", trunk+".99", "up").Run()
	return trunk
}

func ifaceExists(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

func TestCheckOrphans_RemovesUnconfiguredInterfaceKeepsConfiguredOne(t *testing.T) {
	trunk := setupOrphanTestTrunk(t)

	scopes := testScopes("office")
	sc := scopes["office"]
	sc.Parent = trunk
	sc.VLANID = 100
	scopes["office"] = sc

	a := New(config.RoleCore1, "test-node", 1, "psk", t.TempDir(), scopes, nil)
	a.SetPlatform(&config.Platform{Workers: []string{trunk}})
	sock, requests := startIPHelper(t)
	a.SetHelper(helper.NewClient(sock))

	if !ifaceExists(trunk + ".99") {
		t.Fatalf("test setup: orphan interface %s.99 should exist before the sweep", trunk)
	}
	if !ifaceExists(trunk + ".100") {
		t.Fatalf("test setup: configured-scope interface %s.100 should exist before the sweep", trunk)
	}

	found := a.checkOrphans(map[string]bool{trunk + ".99": true, trunk + ".100": true})

	var removedGate []string
	for _, r := range requests() {
		if r.Command == "remove-gate-rule-unscoped" {
			removedGate = append(removedGate, r.Iface)
		}
	}
	if len(removedGate) != 1 || removedGate[0] != trunk+".99" {
		t.Errorf("gate rules removed via helper = %v, want only %s.99", removedGate, trunk)
	}

	if ifaceExists(trunk + ".99") {
		t.Errorf("%s.99 (orphan, no matching scope) still exists after checkOrphans — should have been removed", trunk)
	}
	if !ifaceExists(trunk + ".100") {
		t.Errorf("%s.100 (backed by scope \"office\") was removed — checkOrphans must never touch a currently-configured scope's own interface", trunk)
	}

	var sawOrphanFinding bool
	for _, f := range found {
		if f.What == "orphan_interface" {
			sawOrphanFinding = true
		}
	}
	if !sawOrphanFinding {
		t.Errorf("findings = %+v, want at least one orphan_interface finding", found)
	}
}

func TestCheckOrphans_NeverTouchesMgmtInterface(t *testing.T) {
	requireRoot(t)
	mgmt := "dnstestmgmt0"
	exec.Command("ip", "link", "delete", mgmt).Run()
	if err := exec.Command("ip", "link", "add", mgmt, "type", "dummy").Run(); err != nil {
		t.Fatalf("create dummy mgmt iface: %v", err)
	}
	t.Cleanup(func() { exec.Command("ip", "link", "delete", mgmt).Run() })
	exec.Command("ip", "link", "set", mgmt, "up").Run()
	if err := exec.Command("ip", "link", "add", "link", mgmt, "name", mgmt+".55", "type", "vlan", "id", "55").Run(); err != nil {
		t.Fatalf("create vlan on mgmt: %v", err)
	}
	exec.Command("ip", "link", "set", mgmt+".55", "up").Run()

	a := New(config.RoleCore1, "test-node", 1, "psk", t.TempDir(), map[string]config.ScopeConfig{}, nil)
	a.SetPlatform(&config.Platform{Mgmt: mgmt})

	a.checkOrphans(nil)

	if !ifaceExists(mgmt + ".55") {
		t.Errorf("%s.55 was removed — Platform.Mgmt must never be swept, even when it has no matching scope", mgmt)
	}
}

func TestCheckOrphans_NilPlatformDoesNotPanic(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", t.TempDir(), testScopes("office"), nil)
	found := a.checkOrphans(nil)
	if found != nil {
		t.Errorf("findings = %+v, want nil with no Platform configured", found)
	}
}

// TestHostOwnedTrunkInterfaces_IgnoresNonVLANShapedNames confirms the pure
// matching logic doesn't over-match.
func TestHostOwnedTrunkInterfaces_IgnoresNonVLANShapedNames(t *testing.T) {
	requireRoot(t)
	trunk := "dnstorph1"
	exec.Command("ip", "link", "delete", trunk).Run()
	if err := exec.Command("ip", "link", "add", trunk, "type", "dummy").Run(); err != nil {
		t.Fatalf("create dummy trunk: %v", err)
	}
	t.Cleanup(func() { exec.Command("ip", "link", "delete", trunk).Run() })
	exec.Command("ip", "link", "set", trunk, "up").Run()
	// A real but non-VLAN-shaped sibling — must be ignored, never
	// matched as a <parent>.<digits> orphan.
	sibling := trunk + "x"
	exec.Command("ip", "link", "add", sibling, "type", "dummy").Run()
	t.Cleanup(func() { exec.Command("ip", "link", "delete", sibling).Run() })

	a := New(config.RoleCore1, "test-node", 1, "psk", t.TempDir(), map[string]config.ScopeConfig{}, nil)
	a.SetPlatform(&config.Platform{Workers: []string{trunk}})

	got, err := a.hostOwnedTrunkInterfaces()
	if err != nil {
		t.Fatalf("hostOwnedTrunkInterfaces: %v", err)
	}
	if _, ok := got[sibling]; ok {
		t.Errorf("hostOwnedTrunkInterfaces incorrectly matched %q (not a <parent>.<digits> shape)", sibling)
	}
	if _, ok := got[trunk]; ok {
		t.Errorf("hostOwnedTrunkInterfaces incorrectly included the bare trunk %q itself — it must never be a deletion candidate", trunk)
	}
}
