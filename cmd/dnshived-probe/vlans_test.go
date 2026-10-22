// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"dnshived/internal/probehelper"
)

func TestProbeSelfAddr_DerivesFromScopeVIP(t *testing.T) {
	cases := []struct {
		vip           string
		vlanID, octet int
		want          string
	}{
		{"192.168.10.254/23", 42, 42, "192.168.10.42/23"},
		{"172.16.100.1/24", 100, 5, "172.16.100.5/24"},
		{"10.0.0.1/8", 7, 99, "10.0.0.99/8"},
	}
	for _, c := range cases {
		if got := probeSelfAddr(c.vip, c.vlanID, c.octet); got != c.want {
			t.Errorf("probeSelfAddr(%q, %d, %d) = %q, want %q", c.vip, c.vlanID, c.octet, got, c.want)
		}
	}
}

func TestProbeSelfAddr_FallsBackWhenVIPMissingOrInvalid(t *testing.T) {
	if got := probeSelfAddr("", 100, 42); got != "172.16.100.42/24" {
		t.Errorf("probeSelfAddr(\"\", 100, 42) = %q, want fallback 172.16.100.42/24", got)
	}
	if got := probeSelfAddr("not-a-vip", 100, 42); got != "172.16.100.42/24" {
		t.Errorf("probeSelfAddr(\"not-a-vip\", 100, 42) = %q, want fallback 172.16.100.42/24", got)
	}
}

func TestVLANIDFallbackAddr_LowVLANIDMatchesOriginalScheme(t *testing.T) {
	if got := vlanIDFallbackAddr(100, 42); got != "172.16.100.42/24" {
		t.Errorf("vlanIDFallbackAddr(100, 42) = %q, want 172.16.100.42/24", got)
	}
	if got := vlanIDFallbackAddr(1, 1); got != "172.16.1.1/24" {
		t.Errorf("vlanIDFallbackAddr(1, 1) = %q, want 172.16.1.1/24", got)
	}
	if got := vlanIDFallbackAddr(255, 42); got != "172.16.255.42/24" {
		t.Errorf("vlanIDFallbackAddr(255, 42) = %q, want 172.16.255.42/24", got)
	}
}

func TestVLANIDFallbackAddr_HighVLANIDStaysValid(t *testing.T) {
	cases := []struct {
		vlanID, octet int
		want          string
	}{
		{500, 42, "172.17.244.42/24"},
		{4094, 42, "172.31.254.42/24"},
		{256, 1, "172.17.0.1/24"},
	}
	for _, c := range cases {
		got := vlanIDFallbackAddr(c.vlanID, c.octet)
		if got != c.want {
			t.Errorf("vlanIDFallbackAddr(%d, %d) = %q, want %q", c.vlanID, c.octet, got, c.want)
		}
		if _, _, err := net.ParseCIDR(got); err != nil {
			t.Errorf("vlanIDFallbackAddr(%d, %d) = %q, not a valid CIDR: %v", c.vlanID, c.octet, got, err)
		}
	}
}

func TestVLANIDFallbackAddr_EveryVLANIDInRangeIsValid(t *testing.T) {
	for vlanID := 1; vlanID <= 4094; vlanID++ {
		addr := vlanIDFallbackAddr(vlanID, 42)
		if _, _, err := net.ParseCIDR(addr); err != nil {
			t.Fatalf("vlanIDFallbackAddr(%d, 42) = %q, not a valid CIDR: %v", vlanID, addr, err)
		}
	}
}

func TestDesiredVLANs_MergesAcrossNodesAndFiltersByAllowedParent(t *testing.T) {
	byNodeID := map[string]probeConfigResponse{
		"core-1": {Scopes: map[string]remoteScope{
			"office": {Parent: "ens19", VLANID: 104},
			"dante":  {Parent: "ens20", VLANID: 200},
		}},
		"core-2": {Scopes: map[string]remoteScope{
			"office": {Parent: "ens19", VLANID: 104}, // same scope, redundant
			"guest":  {Parent: "eth1", VLANID: 300},  // not on an allowed parent
		}},
	}
	got := desiredVLANs(byNodeID, []string{"ens19", "ens20"})
	if len(got) != 2 {
		t.Fatalf("desiredVLANs = %+v, want exactly 2 entries (office, dante — guest's parent isn't allowed)", got)
	}
	if got["ens19.104"] != (knownVLAN{Parent: "ens19", VLANID: 104}) {
		t.Errorf("ens19.104 = %+v", got["ens19.104"])
	}
	if got["ens20.200"] != (knownVLAN{Parent: "ens20", VLANID: 200}) {
		t.Errorf("ens20.200 = %+v", got["ens20.200"])
	}
	if _, ok := got["eth1.300"]; ok {
		t.Error("guest's eth1.300 should have been filtered out — eth1 is not an allowed parent")
	}
}

func TestDesiredVLANs_IncludesUntaggedScopes(t *testing.T) {
	byNodeID := map[string]probeConfigResponse{
		"core-1": {Scopes: map[string]remoteScope{
			"mgmt-like": {Parent: "ens19", VLANID: 0, VIP: "192.0.2.254/24"},
		}},
	}
	got := desiredVLANs(byNodeID, []string{"ens19"})
	if len(got) != 1 {
		t.Fatalf("desiredVLANs = %+v, want exactly 1 entry (the untagged scope)", got)
	}
	if got["ens19.0"] != (knownVLAN{Parent: "ens19", VLANID: 0, VIP: "192.0.2.254/24"}) {
		t.Errorf("ens19.0 = %+v", got["ens19.0"])
	}
}

func TestRealIfaceName_UntaggedIsBareParent(t *testing.T) {
	if got := realIfaceName("ens19", 0); got != "ens19" {
		t.Errorf("realIfaceName(ens19, 0) = %q, want %q (the bare parent, never \"ens19.0\")", got, "ens19")
	}
	if got := realIfaceName("ens19", 100); got != "ens19.100" {
		t.Errorf("realIfaceName(ens19, 100) = %q, want %q", got, "ens19.100")
	}
}

func TestDesiredVLANs_SkipsScopesWithEmptyParent(t *testing.T) {
	byNodeID := map[string]probeConfigResponse{
		"core-1": {Scopes: map[string]remoteScope{
			"old-style": {Parent: "", VLANID: 100},
		}},
	}
	got := desiredVLANs(byNodeID, []string{"ens19"})
	if len(got) != 0 {
		t.Errorf("expected empty result for a scope with no reported parent, got %+v", got)
	}
}

func TestKnownVLANs_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-vlans.json")
	want := map[string]knownVLAN{
		"ens19.104": {Parent: "ens19", VLANID: 104},
		"ens20.200": {Parent: "ens20", VLANID: 200},
	}
	if err := saveKnownVLANs(path, want); err != nil {
		t.Fatalf("save: %v", err)
	}
	got := loadKnownVLANs(path)
	if len(got) != 2 || got["ens19.104"] != want["ens19.104"] || got["ens20.200"] != want["ens20.200"] {
		t.Errorf("round trip mismatch: got %+v, want %+v", got, want)
	}
}

func TestKnownVLANs_MissingFileReturnsNil(t *testing.T) {
	got := loadKnownVLANs(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if got != nil {
		t.Errorf("expected nil for a missing file, got %+v", got)
	}
}

func TestKnownVLANs_CorruptFileReturnsNilNotError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-vlans.json")
	os.WriteFile(path, []byte("not json"), 0o640)
	got := loadKnownVLANs(path)
	if got != nil {
		t.Errorf("expected nil for a corrupt file, got %+v", got)
	}
}

func TestSaveKnownVLANs_CreatesParentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "known-vlans.json")
	if err := saveKnownVLANs(path, map[string]knownVLAN{}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected file to exist: %v", err)
	}
}

type fakeProbeHelper struct {
	socketPath string
	// denyCreate/denyDelete simulate a helper-side failure (e.g. the allowlist
	// rejecting a parent).
	denyCreate, denyDelete map[string]bool
	created, deleted       []string

	// live simulates which interfaces actually exist on the host right now,
	// backing a test-time override of ifaceExistsFn.
	mu   sync.Mutex
	live map[string]bool
}

func newFakeProbeHelper(t *testing.T) *fakeProbeHelper {
	t.Helper()
	f := &fakeProbeHelper{
		socketPath: filepath.Join(t.TempDir(), "probe-helper.sock"),
		denyCreate: map[string]bool{}, denyDelete: map[string]bool{},
		live: map[string]bool{},
	}
	ln, err := net.Listen("unix", f.socketPath)
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
			go f.handle(conn)
		}
	}()

	origIfaceExistsFn := ifaceExistsFn
	ifaceExistsFn = func(name string) (*net.Interface, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.live[name] {
			return &net.Interface{Name: name}, nil
		}
		return nil, fmt.Errorf("fake: %s does not exist", name)
	}
	t.Cleanup(func() { ifaceExistsFn = origIfaceExistsFn })

	return f
}

// markLive seeds f.live directly.
func (f *fakeProbeHelper) markLive(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.live[key] = true
}

func (f *fakeProbeHelper) handle(conn net.Conn) {
	defer conn.Close()
	var req probehelper.Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return
	}
	key := vlanKey(req.Parent, req.VLANID)
	liveName := realIfaceName(req.Parent, req.VLANID)
	var resp probehelper.Response
	switch req.Command {
	case "create-interface":
		if f.denyCreate[key] {
			resp = probehelper.Response{OK: false, Error: "denied"}
		} else {
			f.created = append(f.created, key)
			f.mu.Lock()
			f.live[liveName] = true
			f.mu.Unlock()
			resp = probehelper.Response{OK: true}
		}
	case "delete-interface":
		if f.denyDelete[key] {
			resp = probehelper.Response{OK: false, Error: "denied"}
		} else {
			f.deleted = append(f.deleted, key)
			f.mu.Lock()
			delete(f.live, liveName)
			f.mu.Unlock()
			resp = probehelper.Response{OK: true}
		}
	default:
		resp = probehelper.Response{OK: false, Error: "unknown command"}
	}
	json.NewEncoder(conn).Encode(resp)
}

func TestReconcileVLANInterfaces_LocalOctetZeroIsNoop(t *testing.T) {
	cfg := &ProbeConfig{} // LocalOctet unset
	byNodeID := map[string]probeConfigResponse{
		"core-1": {Scopes: map[string]remoteScope{"office": {Parent: "ens19", VLANID: 104}}},
	}
	got := reconcileVLANInterfaces(cfg, byNodeID)
	if got != nil {
		t.Errorf("expected no-op when LocalOctet is 0, got %v", got)
	}
}

func TestReconcileVLANInterfaces_CreatesNewAndPersistsKnown(t *testing.T) {
	helper := newFakeProbeHelper(t)
	knownPath := filepath.Join(t.TempDir(), "known-vlans.json")
	cfg := &ProbeConfig{
		LocalOctet: 42, TrunkParents: []string{"ens19"},
		ProbeHelperSocket: helper.socketPath, KnownVLANsPath: knownPath,
	}
	byNodeID := map[string]probeConfigResponse{
		"core-1": {Scopes: map[string]remoteScope{"office": {Parent: "ens19", VLANID: 104}}},
	}

	changed := reconcileVLANInterfaces(cfg, byNodeID)
	if len(changed) != 1 || changed[0] != "+ens19.104" {
		t.Errorf("changed = %v, want [+ens19.104]", changed)
	}
	if len(helper.created) != 1 || helper.created[0] != "ens19.104" {
		t.Errorf("helper.created = %v, want [ens19.104]", helper.created)
	}

	known := loadKnownVLANs(knownPath)
	if len(known) != 1 || known["ens19.104"] != (knownVLAN{Parent: "ens19", VLANID: 104}) {
		t.Errorf("persisted known set = %+v", known)
	}

	// A second reconcile with nothing changed upstream must be a no-op —
	// the scope is already known.
	changed2 := reconcileVLANInterfaces(cfg, byNodeID)
	if len(changed2) != 0 {
		t.Errorf("second reconcile with no changes: changed = %v, want none", changed2)
	}
	if len(helper.created) != 1 {
		t.Errorf("helper.created grew on a no-op reconcile: %v", helper.created)
	}
}

func TestReconcileVLANInterfaces_RecreatesOnVIPDrift(t *testing.T) {
	helper := newFakeProbeHelper(t)
	knownPath := filepath.Join(t.TempDir(), "known-vlans.json")
	saveKnownVLANs(knownPath, map[string]knownVLAN{
		"ens19.42": {Parent: "ens19", VLANID: 42, VIP: "172.16.42.254/24"},
	})
	cfg := &ProbeConfig{
		LocalOctet: 42, TrunkParents: []string{"ens19"},
		ProbeHelperSocket: helper.socketPath, KnownVLANsPath: knownPath,
	}
	// Same scope, same vlan_id, but its VIP is now on a completely
	// different subnet.
	byNodeID := map[string]probeConfigResponse{
		"core-1": {Scopes: map[string]remoteScope{
			"test2": {Parent: "ens19", VLANID: 42, VIP: "192.168.10.254/23"},
		}},
	}

	changed := reconcileVLANInterfaces(cfg, byNodeID)
	sort.Strings(changed)
	if len(changed) != 2 || changed[0] != "+ens19.42" || changed[1] != "-ens19.42" {
		t.Fatalf("changed = %v, want both a delete and a recreate of ens19.42", changed)
	}
	if len(helper.deleted) != 1 || helper.deleted[0] != "ens19.42" {
		t.Errorf("helper.deleted = %v, want [ens19.42]", helper.deleted)
	}
	if len(helper.created) != 1 || helper.created[0] != "ens19.42" {
		t.Errorf("helper.created = %v, want [ens19.42]", helper.created)
	}

	known := loadKnownVLANs(knownPath)
	if got := known["ens19.42"].VIP; got != "192.168.10.254/23" {
		t.Errorf("persisted VIP = %q, want the new one 192.168.10.254/23", got)
	}
}

func TestReconcileVLANInterfaces_RecreatesWhenKnownButMissingLive(t *testing.T) {
	helper := newFakeProbeHelper(t)
	knownPath := filepath.Join(t.TempDir(), "known-vlans.json")
	saveKnownVLANs(knownPath, map[string]knownVLAN{
		"ens19.104": {Parent: "ens19", VLANID: 104, VIP: "172.16.104.42/24"},
	})
	cfg := &ProbeConfig{
		LocalOctet: 42, TrunkParents: []string{"ens19"},
		ProbeHelperSocket: helper.socketPath, KnownVLANsPath: knownPath,
	}
	byNodeID := map[string]probeConfigResponse{
		"core-1": {Scopes: map[string]remoteScope{
			"office": {Parent: "ens19", VLANID: 104, VIP: "172.16.104.42/24"},
		}},
	}

	changed := reconcileVLANInterfaces(cfg, byNodeID)
	if len(changed) != 1 || changed[0] != "+ens19.104" {
		t.Fatalf("changed = %v, want [+ens19.104] (a plain create, no delete needed for something already absent)", changed)
	}
	if len(helper.deleted) != 0 {
		t.Errorf("helper.deleted = %v, want none — an already-missing interface needs no delete-first step", helper.deleted)
	}
	if len(helper.created) != 1 || helper.created[0] != "ens19.104" {
		t.Errorf("helper.created = %v, want [ens19.104]", helper.created)
	}

	changed2 := reconcileVLANInterfaces(cfg, byNodeID)
	if len(changed2) != 0 {
		t.Errorf("reconcile after successful recreate: changed = %v, want none", changed2)
	}
}

func TestReconcileVLANInterfaces_HandlesUntaggedScope(t *testing.T) {
	helper := newFakeProbeHelper(t)
	knownPath := filepath.Join(t.TempDir(), "known-vlans.json")
	cfg := &ProbeConfig{
		LocalOctet: 42, TrunkParents: []string{"ens19"},
		ProbeHelperSocket: helper.socketPath, KnownVLANsPath: knownPath,
	}
	byNodeID := map[string]probeConfigResponse{
		"core-1": {Scopes: map[string]remoteScope{
			"mgmt-like": {Parent: "ens19", VLANID: 0, VIP: "192.0.2.254/24"},
		}},
	}

	changed := reconcileVLANInterfaces(cfg, byNodeID)
	if len(changed) != 1 || changed[0] != "+ens19.0" {
		t.Fatalf("changed = %v, want [+ens19.0]", changed)
	}
	if len(helper.created) != 1 || helper.created[0] != "ens19.0" {
		t.Errorf("helper.created = %v, want [ens19.0]", helper.created)
	}

	// Next tick: must be a true no-op, not a permanent false-positive
	// "missing since reboot" reconstruct loop.
	changed2 := reconcileVLANInterfaces(cfg, byNodeID)
	if len(changed2) != 0 {
		t.Errorf("second reconcile: changed = %v, want none (realIfaceName fix)", changed2)
	}

	// Scope goes away — must tear down cleanly too.
	changed3 := reconcileVLANInterfaces(cfg, map[string]probeConfigResponse{"core-1": {Scopes: map[string]remoteScope{}}})
	if len(changed3) != 1 || changed3[0] != "-ens19.0" {
		t.Fatalf("changed = %v, want [-ens19.0]", changed3)
	}
	if len(helper.deleted) != 1 || helper.deleted[0] != "ens19.0" {
		t.Errorf("helper.deleted = %v, want [ens19.0]", helper.deleted)
	}
}

func TestReconcileVLANInterfaces_RemovesGoneScope(t *testing.T) {
	helper := newFakeProbeHelper(t)
	knownPath := filepath.Join(t.TempDir(), "known-vlans.json")
	saveKnownVLANs(knownPath, map[string]knownVLAN{
		"ens19.104": {Parent: "ens19", VLANID: 104},
	})
	cfg := &ProbeConfig{
		LocalOctet: 42, TrunkParents: []string{"ens19"},
		ProbeHelperSocket: helper.socketPath, KnownVLANsPath: knownPath,
	}
	// No scopes at all now — office was removed from the cluster.
	byNodeID := map[string]probeConfigResponse{"core-1": {Scopes: map[string]remoteScope{}}}

	changed := reconcileVLANInterfaces(cfg, byNodeID)
	if len(changed) != 1 || changed[0] != "-ens19.104" {
		t.Errorf("changed = %v, want [-ens19.104]", changed)
	}
	if len(helper.deleted) != 1 || helper.deleted[0] != "ens19.104" {
		t.Errorf("helper.deleted = %v, want [ens19.104]", helper.deleted)
	}
	known := loadKnownVLANs(knownPath)
	if len(known) != 0 {
		t.Errorf("persisted known set should be empty after removal, got %+v", known)
	}
}

func TestReconcileVLANInterfaces_FailedCreateNotPersistedForRetry(t *testing.T) {
	helper := newFakeProbeHelper(t)
	helper.denyCreate["ens19.104"] = true
	knownPath := filepath.Join(t.TempDir(), "known-vlans.json")
	cfg := &ProbeConfig{
		LocalOctet: 42, TrunkParents: []string{"ens19"},
		ProbeHelperSocket: helper.socketPath, KnownVLANsPath: knownPath,
	}
	byNodeID := map[string]probeConfigResponse{
		"core-1": {Scopes: map[string]remoteScope{"office": {Parent: "ens19", VLANID: 104}}},
	}

	changed := reconcileVLANInterfaces(cfg, byNodeID)
	if len(changed) != 0 {
		t.Errorf("expected no successful change, got %v", changed)
	}
	known := loadKnownVLANs(knownPath)
	if len(known) != 0 {
		t.Errorf("a failed create must not be persisted as known, got %+v", known)
	}

	// Allow it now and reconcile again — must retry and succeed.
	helper.denyCreate["ens19.104"] = false
	changed2 := reconcileVLANInterfaces(cfg, byNodeID)
	if len(changed2) != 1 || changed2[0] != "+ens19.104" {
		t.Errorf("retry: changed = %v, want [+ens19.104]", changed2)
	}
}

// TestReconcileVLANInterfaces_FailedDeleteKeepsRetrying is the removal
// counterpart.
func TestReconcileVLANInterfaces_FailedDeleteKeepsRetrying(t *testing.T) {
	helper := newFakeProbeHelper(t)
	helper.denyDelete["ens19.104"] = true
	knownPath := filepath.Join(t.TempDir(), "known-vlans.json")
	saveKnownVLANs(knownPath, map[string]knownVLAN{"ens19.104": {Parent: "ens19", VLANID: 104}})
	cfg := &ProbeConfig{
		LocalOctet: 42, TrunkParents: []string{"ens19"},
		ProbeHelperSocket: helper.socketPath, KnownVLANsPath: knownPath,
	}
	byNodeID := map[string]probeConfigResponse{"core-1": {Scopes: map[string]remoteScope{}}}

	changed := reconcileVLANInterfaces(cfg, byNodeID)
	if len(changed) != 0 {
		t.Errorf("expected no successful change, got %v", changed)
	}
	known := loadKnownVLANs(knownPath)
	if len(known) != 1 {
		t.Errorf("a failed delete must stay in the known set for retry, got %+v", known)
	}

	helper.denyDelete["ens19.104"] = false
	changed2 := reconcileVLANInterfaces(cfg, byNodeID)
	if len(changed2) != 1 || changed2[0] != "-ens19.104" {
		t.Errorf("retry: changed = %v, want [-ens19.104]", changed2)
	}
}
