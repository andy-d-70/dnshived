// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManageUnit_RejectsUnknownAction(t *testing.T) {
	err := manageUnit(Request{Action: "restart", Unit: "dnshived-web.service"})
	if err == nil || !strings.Contains(err.Error(), "unknown manage-unit action") {
		t.Fatalf("err = %v, want unknown action", err)
	}
}

func TestManageUnit_RejectsUnitsOutsideTheActionsList(t *testing.T) {
	cases := []Request{
		{Action: "disable-now", Unit: "ssh.service"},
		{Action: "disable-now", Unit: "dnshived.service"},
		{Action: "disable-now", Unit: "dnshived-helper.service"},
		{Action: "enable", Unit: "dnshived-web.service"},
		{Action: "enable-now", Unit: "dnshived-helper.service"},
		{Action: "enable-now", Unit: "dnshived-dnsmasq@office.service"},
		{Action: "disable-now", Unit: "dnshived-dnsmasq@../x.service"},
		{Action: "disable-now", Unit: "dnshived-dnsmasq@office.service --now"},
	}
	for _, req := range cases {
		err := manageUnit(req)
		if err == nil || !strings.Contains(err.Error(), "unit not allowed") {
			t.Errorf("%s %s: err = %v, want unit not allowed", req.Action, req.Unit, err)
		}
	}
}

func TestDnsmasqUnitPattern(t *testing.T) {
	for _, u := range []string{"dnshived-dnsmasq@office.service", "dnshived-dnsmasq@core-dhcp.service", "dnshived-dnsmasq@rw_100.service"} {
		if !dnsmasqUnitPattern.MatchString(u) {
			t.Errorf("%s should match", u)
		}
	}
	for _, u := range []string{"dnshived-dnsmasq@.service", "dnshived-dnsmasq@a b.service", "dnshived-dnsmasq@x.service.d", "xdnshived-dnsmasq@x.service"} {
		if dnsmasqUnitPattern.MatchString(u) {
			t.Errorf("%s should not match", u)
		}
	}
}

func TestLinkUp_RejectsInvalidAndMissingInterfaces(t *testing.T) {
	if err := linkUp(Request{Iface: "eth0; reboot"}); err == nil {
		t.Error("invalid interface name accepted")
	}
	if err := linkUp(Request{Iface: ""}); err == nil {
		t.Error("empty interface name accepted")
	}
	err := linkUp(Request{Iface: "nonexist0x9"})
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("missing interface: err = %v, want does not exist", err)
	}
}

func TestCheckIfaceName_RejectsInvalidNames(t *testing.T) {
	if err := checkIfaceName("a/b"); err == nil {
		t.Error("invalid interface name accepted")
	}
	if err := checkIfaceName("ens19.200"); err != nil {
		t.Errorf("valid interface name refused: %v", err)
	}
}

func TestResetScopeState_ReturnsToFlagListAndRemovesStateDir(t *testing.T) {
	resetAllowlistState(t, map[string]bool{"office": true})
	origFlag := flagScopes
	flagScopes = "office"
	t.Cleanup(func() { flagScopes = origFlag })

	if err := addScopes(Request{Scopes: []string{"rw-100", "rw-101"}}); err != nil {
		t.Fatalf("addScopes: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "allowed-scopes.json")); err != nil {
		t.Fatalf("persisted file missing before reset: %v", err)
	}

	if err := resetScopeState(); err != nil {
		t.Fatalf("resetScopeState: %v", err)
	}
	allowedScopesMu.RLock()
	got := len(allowedScopes)
	office := allowedScopes["office"]
	allowedScopesMu.RUnlock()
	if got != 1 || !office {
		t.Errorf("allowlist after reset has %d entries (office=%v), want only office", got, office)
	}
	if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
		t.Errorf("state dir still present after reset (stat err %v)", err)
	}
	if loaded := loadPersistedScopes(stateDir); len(loaded) != 0 {
		t.Errorf("persisted scopes after reset = %v, want none", loaded)
	}
}

func roundTripCommand(t *testing.T, req Request) Response {
	t.Helper()
	server, client := net.Pipe()
	defer client.Close()
	go handleConn(server)
	if err := json.NewEncoder(client).Encode(req); err != nil {
		t.Fatalf("encode request: %v", err)
	}
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	var resp Response
	if err := json.NewDecoder(client).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

func stubFinishDecommission(t *testing.T, spawnErr error) (spawned, stopped chan struct{}) {
	t.Helper()
	spawned = make(chan struct{}, 1)
	stopped = make(chan struct{}, 1)
	origSpawn, origStop := spawnBootstrapRestart, stopHelperSelf
	spawnBootstrapRestart = func() error { spawned <- struct{}{}; return spawnErr }
	stopHelperSelf = func() error { stopped <- struct{}{}; return nil }
	t.Cleanup(func() { spawnBootstrapRestart, stopHelperSelf = origSpawn, origStop })
	return spawned, stopped
}

func TestFinishDecommission_SchedulesRestartThenStopsSelf(t *testing.T) {
	spawned, stopped := stubFinishDecommission(t, nil)

	resp := roundTripCommand(t, Request{Command: "finish-decommission"})
	if !resp.OK {
		t.Fatalf("resp = %+v, want OK", resp)
	}
	select {
	case <-spawned:
	default:
		t.Fatal("restart into bootstrap was not scheduled before responding")
	}
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("helper never stopped itself after finish-decommission")
	}
}

func TestFinishDecommission_SpawnFailureKeepsHelperRunning(t *testing.T) {
	_, stopped := stubFinishDecommission(t, errors.New("systemd-run failed"))

	resp := roundTripCommand(t, Request{Command: "finish-decommission"})
	if resp.OK || !strings.Contains(resp.Error, "systemd-run failed") {
		t.Fatalf("resp = %+v, want the spawn error", resp)
	}
	select {
	case <-stopped:
		t.Fatal("helper stopped itself although no restart was scheduled")
	case <-time.After(500 * time.Millisecond):
	}
}

func TestHandleConn_NewCommandsAreKnown(t *testing.T) {
	for _, cmd := range []string{"link-up", "manage-unit"} {
		resp := roundTripCommand(t, Request{Command: cmd})
		if strings.Contains(resp.Error, "unknown command") {
			t.Errorf("%s: helper reports unknown command", cmd)
		}
		if resp.OK {
			t.Errorf("%s with empty arguments succeeded, want a validation error", cmd)
		}
	}
}

// TestRemoveLegacyNFT_IsKnownAndIdempotent: the cleanup verb answers ok when the legacy table is already gone.
func TestRemoveLegacyNFT_IsKnownAndIdempotent(t *testing.T) {
	resp := roundTripCommand(t, Request{Command: "remove-legacy-nft"})
	if strings.Contains(resp.Error, "unknown command") {
		t.Fatal("remove-legacy-nft is not a known command")
	}
	if !resp.OK {
		t.Fatalf("remove-legacy-nft with no legacy table = %+v, want ok", resp)
	}
}
