// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dnshived/internal/config"
	"dnshived/internal/dhcpprobe"
	"dnshived/internal/dnsprobe"
	"dnshived/internal/eventlog"
)

func TestProbeDHCPOptions_UsesRealInterfaceMAC(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	var target net.Interface
	for _, ifi := range ifaces {
		if len(ifi.HardwareAddr) == 6 {
			target = ifi
			break
		}
	}
	if target.Name == "" {
		t.Skip("no interface with a real 6-byte hardware address on this test host")
	}
	opts := probeDHCPOptions(target.Name)
	if opts.MAC == nil {
		t.Fatal("expected a real MAC from the interface, got nil (falls back to dhcpprobe's own random default)")
	}
	if opts.MAC.String() != target.HardwareAddr.String() {
		t.Errorf("opts.MAC = %v, want the interface's own real hardware address %v", opts.MAC, target.HardwareAddr)
	}
}

// TestProbeDHCPOptions_FallsBackToDefaultWhenInterfaceMissing confirms
// probing is never blocked by this.
func TestProbeDHCPOptions_FallsBackToDefaultWhenInterfaceMissing(t *testing.T) {
	opts := probeDHCPOptions("does-not-exist-999")
	want := dhcpprobe.DefaultOptions()
	if opts.MAC != nil {
		t.Errorf("opts.MAC = %v, want nil (falls back to default)", opts.MAC)
	}
	if opts.Broadcast != want.Broadcast {
		t.Errorf("opts.Broadcast = %v, want %v (default options otherwise unchanged)", opts.Broadcast, want.Broadcast)
	}
}

func TestDHCPOffersToDetails_CapturesOfferedIP(t *testing.T) {
	offers := []dhcpprobe.Offer{
		{ServerID: net.ParseIP("172.16.111.22"), YourIP: net.ParseIP("172.16.111.150")},
	}
	got := dhcpOffersToDetails(offers)
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}
	if got[0].ServerID != "172.16.111.22" || got[0].OfferedIP != "172.16.111.150" {
		t.Errorf("got %+v, want ServerID=172.16.111.22 OfferedIP=172.16.111.150", got[0])
	}
}

// TestDHCPOffersToDetails_DualActiveKeepsBothOffers confirms a genuine
// dual_active case surfaces BOTH conflicting offers, not just one.
func TestDHCPOffersToDetails_DualActiveKeepsBothOffers(t *testing.T) {
	offers := []dhcpprobe.Offer{
		{ServerID: net.ParseIP("172.16.111.22"), YourIP: net.ParseIP("172.16.111.150")},
		{ServerID: net.ParseIP("172.16.111.23"), YourIP: net.ParseIP("172.16.111.151")},
	}
	got := dhcpOffersToDetails(offers)
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}
	if got[1].ServerID != "172.16.111.23" || got[1].OfferedIP != "172.16.111.151" {
		t.Errorf("got[1] = %+v, want ServerID=172.16.111.23 OfferedIP=172.16.111.151", got[1])
	}
}

// TestDHCPOffersToDetails_NoOffersReturnsEmpty confirms a no_answer
// verdict (zero offers) doesn't panic and produces no entries.
func TestDHCPOffersToDetails_NoOffersReturnsEmpty(t *testing.T) {
	got := dhcpOffersToDetails(nil)
	if len(got) != 0 {
		t.Errorf("len(got) = %d, want 0 for no offers", len(got))
	}
}

func TestProbeOneScope_UnreachableVLANLeavesEnabledFalse(t *testing.T) {
	cfg := &ProbeConfig{TrunkParent: "nonexistent-iface-for-test"}
	byNodeID := map[string]probeConfigResponse{
		"node-a": {NodeID: "node-a", Scopes: map[string]remoteScope{
			"rw-100": {VLANID: 100, NodeIP: "172.16.100.22/24"},
		}},
	}
	result := probeOneScope(cfg, "rw-100", byNodeID, nil, nil, false)
	if result.Reachable {
		t.Fatal("expected Reachable=false for a VLAN interface that doesn't exist on this host")
	}
	if result.Enabled {
		t.Error("expected Enabled=false when the scope was never actually reachable/probed")
	}
}

func TestProbeOneScope_ProbeDisabledSkipsChecksButStaysReachable(t *testing.T) {
	origIface := ifaceExistsFn
	ifaceExistsFn = func(name string) (*net.Interface, error) { return &net.Interface{Name: name}, nil }
	defer func() { ifaceExistsFn = origIface }()

	origDNS := dnsProbeFn
	dnsQueried := false
	dnsProbeFn = func(addr, qname, qtype string, timeout time.Duration) (dnsprobe.Result, error) {
		dnsQueried = true
		return dnsprobe.Result{Answered: true}, nil
	}
	defer func() { dnsProbeFn = origDNS }()

	cfg := &ProbeConfig{TrunkParent: "lo"}
	byNodeID := map[string]probeConfigResponse{
		"core-1": {NodeID: "core-1", Role: config.RoleCore1, Scopes: map[string]remoteScope{
			"rw-100": {VLANID: 100, NodeIP: "172.16.100.22/24", ProbeDisabled: true},
		}},
	}

	result := probeOneScope(cfg, "rw-100", byNodeID, nil, nil, false)
	if !result.Reachable {
		t.Error("expected Reachable=true — the (mocked) VLAN interface genuinely exists")
	}
	if result.Enabled {
		t.Error("expected Enabled=false — probe_disabled must suppress checking, not just labeling")
	}
	if dnsQueried {
		t.Error("expected no DNS query at all for a probe_disabled scope")
	}
	if result.DHCP.Verdict != "" || result.DHCP.Error != "" {
		t.Errorf("expected no DHCP probe attempted, got verdict=%q error=%q", result.DHCP.Verdict, result.DHCP.Error)
	}
}

func TestRunProbeSweep_ParallelProbingPopulatesEveryScope(t *testing.T) {
	origIface := ifaceExistsFn
	ifaceExistsFn = func(name string) (*net.Interface, error) { return &net.Interface{Name: name}, nil }
	defer func() { ifaceExistsFn = origIface }()

	const n = 50
	scopes := make(map[string]remoteScope, n)
	for i := 0; i < n; i++ {
		scopes[fmt.Sprintf("rw-%d", 100+i)] = remoteScope{VLANID: 100 + i, NodeIP: "172.16.100.22/24", ProbeDisabled: true}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(probeConfigResponse{NodeID: "core-1", Role: config.RoleCore1, Scopes: scopes, Incarnation: 1})
	}))
	defer srv.Close()

	cfg := &ProbeConfig{
		TrunkParent:     "lo",
		ParallelProbing: true,
		ClusterNodes:    []ClusterNode{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}},
	}
	store := newResultStore()
	tracker := newProbeLogTracker(nil)
	events := eventlog.New(100, "probe")
	incarnations := newIncarnationTracker()

	runProbeSweep(cfg, store, tracker, events, incarnations, newOwnershipDebounce())

	all := store.all()
	if len(all) != n {
		t.Fatalf("store has %d results, want %d — parallel fan-out must reach every scope", len(all), n)
	}
	for name := range scopes {
		r, ok := all[name]
		if !ok {
			t.Errorf("scope %s missing from store after parallel sweep", name)
			continue
		}
		if !r.Reachable {
			t.Errorf("scope %s: Reachable = false, want true (mocked interface exists)", name)
		}
	}
}

func TestRefreshScopeSet_PrunesRemovedScopeIndependentlyOfSweep(t *testing.T) {
	scopes := map[string]remoteScope{
		"rw-100": {VLANID: 100, NodeIP: "172.16.100.22/24", ProbeDisabled: true},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(probeConfigResponse{NodeID: "core-1", Role: config.RoleCore1, Scopes: scopes, Incarnation: 1})
	}))
	defer srv.Close()

	cfg := &ProbeConfig{
		TrunkParent:  "lo",
		ClusterNodes: []ClusterNode{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}},
	}
	store := newResultStore()
	store.set("rw-100", ScopeProbeResult{Scope: "rw-100"})
	store.set("rw-999", ScopeProbeResult{Scope: "rw-999"}) // stale — no longer in the live config above
	tracker := newProbeLogTracker(nil)
	tracker.dhcp["rw-100"] = ""
	tracker.dhcp["rw-999"] = ""

	refreshScopeSet(cfg, store, tracker)

	if _, ok := store.get("rw-100"); !ok {
		t.Error("expected rw-100 (still configured) to survive refreshScopeSet")
	}
	if _, ok := store.get("rw-999"); ok {
		t.Error("expected rw-999 (removed from config) to be pruned by refreshScopeSet alone")
	}
	if _, ok := tracker.dhcp["rw-999"]; ok {
		t.Error("expected probeLogTracker to prune rw-999 too")
	}
}

func TestProbeOneScope_PrefersScopeOwnParentOverTrunkParent(t *testing.T) {
	origIface := ifaceExistsFn
	var seenIface string
	ifaceExistsFn = func(name string) (*net.Interface, error) {
		seenIface = name
		if name == "ens20.130" {
			return &net.Interface{Name: name}, nil
		}
		return nil, fmt.Errorf("no such interface %s", name)
	}
	defer func() { ifaceExistsFn = origIface }()

	cfg := &ProbeConfig{TrunkParent: "ens19"}
	byNodeID := map[string]probeConfigResponse{
		"core-2": {NodeID: "core-2", Scopes: map[string]remoteScope{
			"rw-130": {Parent: "ens20", VLANID: 130, NodeIP: "172.16.130.23/24", ProbeDisabled: true},
		}},
	}

	result := probeOneScope(cfg, "rw-130", byNodeID, nil, nil, false)
	if seenIface != "ens20.130" {
		t.Errorf("checked interface %q, want ens20.130 (the scope's own parent, not cfg.TrunkParent)", seenIface)
	}
	if !result.Reachable {
		t.Error("expected Reachable=true — ens20.130 exists per the mock, only ens19.130 doesn't")
	}
}

func TestProbeOneScope_UntaggedScopeChecksBareParent(t *testing.T) {
	origIface := ifaceExistsFn
	var seenIface string
	ifaceExistsFn = func(name string) (*net.Interface, error) {
		seenIface = name
		if name == "ens19" {
			return &net.Interface{Name: name}, nil
		}
		return nil, fmt.Errorf("no such interface %s", name)
	}
	defer func() { ifaceExistsFn = origIface }()

	cfg := &ProbeConfig{TrunkParent: "ens19"}
	byNodeID := map[string]probeConfigResponse{
		"core-1": {NodeID: "core-1", Scopes: map[string]remoteScope{
			"mgmt-like": {Parent: "ens19", VLANID: 0, NodeIP: "192.168.0.22/24", ProbeDisabled: true},
		}},
	}

	result := probeOneScope(cfg, "mgmt-like", byNodeID, nil, nil, false)
	if seenIface != "ens19" {
		t.Errorf("checked interface %q, want ens19 (the bare parent, never \"ens19.0\")", seenIface)
	}
	if !result.Reachable {
		t.Error("expected Reachable=true — ens19 exists per the mock")
	}
}

func TestProbeOneScope_FallsBackToTrunkParentWhenScopeParentEmpty(t *testing.T) {
	origIface := ifaceExistsFn
	var seenIface string
	ifaceExistsFn = func(name string) (*net.Interface, error) {
		seenIface = name
		return &net.Interface{Name: name}, nil
	}
	defer func() { ifaceExistsFn = origIface }()

	cfg := &ProbeConfig{TrunkParent: "ens19"}
	byNodeID := map[string]probeConfigResponse{
		"core-1": {NodeID: "core-1", Scopes: map[string]remoteScope{
			"rw-100": {VLANID: 100, NodeIP: "172.16.100.22/24", ProbeDisabled: true}, // no Parent set
		}},
	}

	probeOneScope(cfg, "rw-100", byNodeID, nil, nil, false)
	if seenIface != "ens19.100" {
		t.Errorf("checked interface %q, want ens19.100 (fallback to cfg.TrunkParent)", seenIface)
	}
}

func TestProbeOneScope_ChecksEveryCoreRoleInDNSChecks(t *testing.T) {
	origIface := ifaceExistsFn
	ifaceExistsFn = func(name string) (*net.Interface, error) { return &net.Interface{Name: name}, nil }
	defer func() { ifaceExistsFn = origIface }()

	origDNS := dnsProbeFn
	var queried []string
	dnsProbeFn = func(addr, qname, qtype string, timeout time.Duration) (dnsprobe.Result, error) {
		queried = append(queried, addr)
		return dnsprobe.Result{Answered: true}, nil
	}
	defer func() { dnsProbeFn = origDNS }()

	cfg := &ProbeConfig{TrunkParent: "lo"}
	byNodeID := map[string]probeConfigResponse{
		"core-1": {NodeID: "core-1", Role: config.RoleCore1, Scopes: map[string]remoteScope{
			"rw-100": {VLANID: 100, NodeIP: "172.16.100.22/24"},
		}},
		"core-3": {NodeID: "core-3", Role: config.RoleCore3, Scopes: map[string]remoteScope{
			"rw-100": {VLANID: 100, NodeIP: "172.16.100.24/24"},
		}},
	}

	probeOneScope(cfg, "rw-100", byNodeID, nil, nil, false)

	want := map[string]bool{"172.16.100.22": false, "172.16.100.24": false}
	for _, addr := range queried {
		if _, ok := want[addr]; ok {
			want[addr] = true
		}
	}
	for addr, seen := range want {
		if !seen {
			t.Errorf("expected %s to be queried (every core role serves DNS active-active), queried=%v", addr, queried)
		}
	}
}

func TestIsCoreRole_AcceptsAllThreeCoreRoles(t *testing.T) {
	cases := []struct {
		role string
		want bool
	}{
		{config.RoleCore1, true},
		{config.RoleCore2, true},
		{config.RoleCore3, true},
		{"", false},
		{"probe", false},
	}
	for _, c := range cases {
		if got := isCoreRole(c.role); got != c.want {
			t.Errorf("isCoreRole(%q) = %v, want %v", c.role, got, c.want)
		}
	}
}

func TestScopeProbeResult_EnabledIsOnTheWire(t *testing.T) {
	result := ScopeProbeResult{Scope: "rw-100", Reachable: true, Enabled: true}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	enabled, ok := decoded["enabled"]
	if !ok {
		t.Fatal("expected an \"enabled\" key in the JSON output")
	}
	if enabled != true {
		t.Errorf("enabled = %v, want true", enabled)
	}
}

func TestValidateDHCPAnswer_MatchesLiveTokenOwner(t *testing.T) {
	byNodeID := map[string]probeConfigResponse{
		"node-a": {NodeID: "node-a", Scopes: map[string]remoteScope{
			"office": {NodeIP: "172.16.100.22/24"},
		}},
		"node-b": {NodeID: "node-b", Scopes: map[string]remoteScope{
			"office": {NodeIP: "172.16.100.23/24"},
		}},
	}
	tokens := map[string]tokenInfo{"office": {Owner: "node-a"}}

	dhcpResult := dhcpprobe.Result{Verdict: dhcpprobe.VerdictOK, Servers: []string{"172.16.100.22"}}
	valid, reason := validateDHCPAnswer("office", dhcpResult, byNodeID, tokens)
	if !valid {
		t.Fatalf("expected valid, got invalid: %s", reason)
	}
}

func TestValidateDHCPAnswer_WrongServerIsInvalid(t *testing.T) {
	byNodeID := map[string]probeConfigResponse{
		"node-a": {NodeID: "node-a", Scopes: map[string]remoteScope{
			"office": {NodeIP: "172.16.100.22/24"},
		}},
	}
	tokens := map[string]tokenInfo{"office": {Owner: "node-a"}}

	dhcpResult := dhcpprobe.Result{Verdict: dhcpprobe.VerdictOK, Servers: []string{"172.16.100.99"}}
	valid, reason := validateDHCPAnswer("office", dhcpResult, byNodeID, tokens)
	if valid {
		t.Fatal("expected invalid (wrong server), got valid")
	}
	if reason == "" {
		t.Error("expected a non-empty reason")
	}
}

func TestValidateDHCPAnswer_LoopbackServerNeverRogue(t *testing.T) {
	byNodeID := map[string]probeConfigResponse{
		"node-a": {NodeID: "node-a", Scopes: map[string]remoteScope{
			"office": {NodeIP: "10.130.96.22/24"},
		}},
		"node-b": {NodeID: "node-b", Scopes: map[string]remoteScope{
			"office": {NodeIP: "10.130.96.23/24"},
		}},
	}
	tokens := map[string]tokenInfo{"office": {Owner: "node-a"}}

	dhcpResult := dhcpprobe.Result{
		Verdict: dhcpprobe.VerdictOK,
		Servers: []string{"127.0.0.1"},
		Offers:  []dhcpprobe.Offer{{ServerID: net.ParseIP("127.0.0.1"), GIAddr: net.ParseIP("10.130.96.22")}},
	}
	valid, reason := validateDHCPAnswer("office", dhcpResult, byNodeID, tokens)
	if !valid {
		t.Fatalf("expected valid (loopback server-id, correct relay), got invalid: %s", reason)
	}
}

func TestValidateDHCPAnswer_LoopbackWrongRelayStillInvalid(t *testing.T) {
	byNodeID := map[string]probeConfigResponse{
		"node-a": {NodeID: "node-a", Scopes: map[string]remoteScope{
			"office": {NodeIP: "10.130.96.22/24"},
		}},
		"node-b": {NodeID: "node-b", Scopes: map[string]remoteScope{
			"office": {NodeIP: "10.130.96.23/24"},
		}},
	}
	tokens := map[string]tokenInfo{"office": {Owner: "node-a"}}

	dhcpResult := dhcpprobe.Result{
		Verdict: dhcpprobe.VerdictOK,
		Servers: []string{"127.0.0.1"},
		Offers:  []dhcpprobe.Offer{{ServerID: net.ParseIP("127.0.0.1"), GIAddr: net.ParseIP("10.130.96.23")}},
	}
	valid, reason := validateDHCPAnswer("office", dhcpResult, byNodeID, tokens)
	if valid {
		t.Fatal("expected invalid (relay is worker-b, token owner is worker-a), got valid")
	}
	if reason == "" || strings.Contains(reason, "ROGUE") {
		t.Errorf("expected a non-ROGUE ownership-mismatch reason, got %q", reason)
	}
}

// TestValidateDHCPAnswer_UnrelayedServerIDStillMatches pins the fallback
// path.
func TestValidateDHCPAnswer_UnrelayedServerIDStillMatches(t *testing.T) {
	byNodeID := map[string]probeConfigResponse{
		"node-a": {NodeID: "node-a", Scopes: map[string]remoteScope{
			"office": {NodeIP: "172.16.100.22/24"},
		}},
	}
	tokens := map[string]tokenInfo{"office": {Owner: "node-a"}}

	dhcpResult := dhcpprobe.Result{
		Verdict: dhcpprobe.VerdictOK,
		Servers: []string{"172.16.100.22"},
		Offers:  []dhcpprobe.Offer{{ServerID: net.ParseIP("172.16.100.22")}},
	}
	valid, reason := validateDHCPAnswer("office", dhcpResult, byNodeID, tokens)
	if !valid {
		t.Fatalf("expected valid (unrelayed, server-id matches owner directly), got invalid: %s", reason)
	}
}

func TestValidateDHCPAnswer_ExpiredTokenIsInvalid(t *testing.T) {
	byNodeID := map[string]probeConfigResponse{
		"node-a": {NodeID: "node-a", Scopes: map[string]remoteScope{
			"office": {NodeIP: "172.16.100.22/24"},
		}},
	}
	tokens := map[string]tokenInfo{"office": {Owner: "node-a", Expired: true}}

	dhcpResult := dhcpprobe.Result{Verdict: dhcpprobe.VerdictOK, Servers: []string{"172.16.100.22"}}
	valid, _ := validateDHCPAnswer("office", dhcpResult, byNodeID, tokens)
	if valid {
		t.Fatal("expected invalid (expired token), got valid")
	}
}

func TestValidateDHCPAnswer_NoTokenIsInvalid(t *testing.T) {
	byNodeID := map[string]probeConfigResponse{
		"node-a": {NodeID: "node-a", Scopes: map[string]remoteScope{
			"office": {NodeIP: "172.16.100.22/24"},
		}},
	}
	dhcpResult := dhcpprobe.Result{Verdict: dhcpprobe.VerdictOK, Servers: []string{"172.16.100.22"}}
	valid, reason := validateDHCPAnswer("office", dhcpResult, byNodeID, map[string]tokenInfo{})
	if valid {
		t.Fatal("expected invalid (no token), got valid")
	}
	if reason == "" {
		t.Error("expected a non-empty reason")
	}
}

func TestValidateDHCPAnswer_DualActiveNeverValid(t *testing.T) {
	dhcpResult := dhcpprobe.Result{Verdict: dhcpprobe.VerdictDualActive, Servers: []string{"172.16.100.22", "172.16.100.23"}}
	valid, reason := validateDHCPAnswer("office", dhcpResult, nil, map[string]tokenInfo{"office": {Owner: "node-a"}})
	if valid {
		t.Fatal("dual-active must never validate, regardless of token state")
	}
	if reason == "" {
		t.Error("expected a non-empty reason")
	}
}

func TestValidateDHCPAnswer_RogueResponderAmongDualActive(t *testing.T) {
	byNodeID := map[string]probeConfigResponse{
		"node-a": {NodeID: "node-a", Scopes: map[string]remoteScope{
			"office": {NodeIP: "172.16.100.22/24"},
		}},
		"node-b": {NodeID: "node-b", Scopes: map[string]remoteScope{
			"office": {NodeIP: "172.16.100.23/24"},
		}},
	}
	dhcpResult := dhcpprobe.Result{
		Verdict: dhcpprobe.VerdictDualActive,
		Servers: []string{"172.16.100.22", "172.16.100.99"}, // .99 is nobody's node_ip
	}
	valid, reason := validateDHCPAnswer("office", dhcpResult, byNodeID, map[string]tokenInfo{"office": {Owner: "node-a"}})
	if valid {
		t.Fatal("must never validate")
	}
	if !strings.Contains(reason, "ROGUE DHCP") {
		t.Errorf("expected a ROGUE DHCP classification, got: %q", reason)
	}
	if !strings.Contains(reason, "172.16.100.99") {
		t.Errorf("reason should name the unrecognized server, got: %q", reason)
	}
}

func TestValidateDHCPAnswer_OrdinaryDualActiveBetweenKnownWorkersStaysPlain(t *testing.T) {
	byNodeID := map[string]probeConfigResponse{
		"node-a": {NodeID: "node-a", Scopes: map[string]remoteScope{
			"office": {NodeIP: "172.16.100.22/24"},
		}},
		"node-b": {NodeID: "node-b", Scopes: map[string]remoteScope{
			"office": {NodeIP: "172.16.100.23/24"},
		}},
	}
	dhcpResult := dhcpprobe.Result{
		Verdict: dhcpprobe.VerdictDualActive,
		Servers: []string{"172.16.100.22", "172.16.100.23"},
	}
	valid, reason := validateDHCPAnswer("office", dhcpResult, byNodeID, map[string]tokenInfo{"office": {Owner: "node-a"}})
	if valid {
		t.Fatal("must never validate")
	}
	if strings.Contains(reason, "ROGUE") {
		t.Errorf("two known workers overlapping should not be classified ROGUE, got: %q", reason)
	}
	if !strings.Contains(reason, "dual-active") {
		t.Errorf("expected the plain dual-active message, got: %q", reason)
	}
}

func TestValidateDHCPAnswer_SingleRogueResponderIsRogueNotJustWrongOwner(t *testing.T) {
	byNodeID := map[string]probeConfigResponse{
		"node-a": {NodeID: "node-a", Scopes: map[string]remoteScope{
			"office": {NodeIP: "172.16.100.22/24"},
		}},
	}
	dhcpResult := dhcpprobe.Result{Verdict: dhcpprobe.VerdictOK, Servers: []string{"172.16.100.99"}}
	valid, reason := validateDHCPAnswer("office", dhcpResult, byNodeID, map[string]tokenInfo{"office": {Owner: "node-a"}})
	if valid {
		t.Fatal("expected invalid")
	}
	if !strings.Contains(reason, "ROGUE DHCP") {
		t.Errorf("expected ROGUE DHCP classification, got: %q", reason)
	}
}

func TestValidateDHCPAnswer_KnownWorkerWrongOwnerStaysOrdinary(t *testing.T) {
	byNodeID := map[string]probeConfigResponse{
		"node-a": {NodeID: "node-a", Scopes: map[string]remoteScope{
			"office": {NodeIP: "172.16.100.22/24"},
		}},
		"node-b": {NodeID: "node-b", Scopes: map[string]remoteScope{
			"office": {NodeIP: "172.16.100.23/24"},
		}},
	}
	// node-b answers, but the live token owner is node-a.
	dhcpResult := dhcpprobe.Result{Verdict: dhcpprobe.VerdictOK, Servers: []string{"172.16.100.23"}}
	valid, reason := validateDHCPAnswer("office", dhcpResult, byNodeID, map[string]tokenInfo{"office": {Owner: "node-a"}})
	if valid {
		t.Fatal("expected invalid (wrong owner)")
	}
	if strings.Contains(reason, "ROGUE") {
		t.Errorf("a known worker answering (just not the token owner) must not be classified ROGUE, got: %q", reason)
	}
}

func TestValidateDHCPAnswer_NoAnswerNeverValid(t *testing.T) {
	dhcpResult := dhcpprobe.Result{Verdict: dhcpprobe.VerdictNoAnswer}
	valid, _ := validateDHCPAnswer("office", dhcpResult, nil, nil)
	if valid {
		t.Fatal("no-answer must never validate")
	}
}

func TestRunOneDNSCheck_SkipsGenuinelyUnsupportedType(t *testing.T) {
	r := runOneDNSCheck("127.0.0.1", "mail.local.", "BOGUS", nil, true)
	if r.Skipped == "" {
		t.Error("expected an unsupported type to be reported as skipped, not attempted")
	}
	if r.Answered {
		t.Error("a skipped check must not report Answered=true")
	}
}

func TestExpectedDNSData_ARecord(t *testing.T) {
	got, err := expectedDNSData(config.DNSRecord{Type: "A", Value: "192.168.100.50"})
	if err != nil {
		t.Fatalf("expectedDNSData: %v", err)
	}
	if got != "192.168.100.50" {
		t.Errorf("got %q, want %q", got, "192.168.100.50")
	}
}

func TestExpectedDNSData_RejectsInvalidIP(t *testing.T) {
	if _, err := expectedDNSData(config.DNSRecord{Type: "A", Value: "not-an-ip"}); err == nil {
		t.Error("expected an error for an invalid A record value")
	}
}

func TestExpectedDNSData_CNAMEAddsTrailingDot(t *testing.T) {
	got, err := expectedDNSData(config.DNSRecord{Type: "CNAME", Value: "nas.office.lan"})
	if err != nil {
		t.Fatalf("expectedDNSData: %v", err)
	}
	if got != "nas.office.lan." {
		t.Errorf("got %q, want a trailing dot added to match internal/dnsprobe's own decoded form", got)
	}
}

func TestExpectedDNSData_PTRAddsTrailingDot(t *testing.T) {
	got, err := expectedDNSData(config.DNSRecord{Type: "PTR", Value: "nas.office.lan"})
	if err != nil {
		t.Fatalf("expectedDNSData: %v", err)
	}
	if got != "nas.office.lan." {
		t.Errorf("got %q, want a trailing dot added to match internal/dnsprobe's own decoded form", got)
	}
}

func TestExpectedDNSData_SRVFormatsAllFields(t *testing.T) {
	got, err := expectedDNSData(config.DNSRecord{Type: "SRV", Target: "nas.office.lan.", Port: 4440, Priority: 10, Weight: 20})
	if err != nil {
		t.Fatalf("expectedDNSData: %v", err)
	}
	want := "10 20 4440 nas.office.lan."
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDNSDataMatches_CNAMECaseInsensitive(t *testing.T) {
	if !dnsDataMatches("CNAME", "nas.office.lan.", "NAS.OFFICE.LAN.") {
		t.Error("expected CNAME comparison to be case-insensitive (DNS names are, per RFC 1035)")
	}
}

func TestDNSDataMatches_PTRCaseInsensitive(t *testing.T) {
	if !dnsDataMatches("PTR", "nas.office.lan.", "NAS.OFFICE.LAN.") {
		t.Error("expected PTR comparison to be case-insensitive (DNS names are, per RFC 1035)")
	}
}

func TestDNSDataMatches_SRVTargetCaseInsensitiveNumbersExact(t *testing.T) {
	if !dnsDataMatches("SRV", "10 20 4440 nas.office.lan.", "10 20 4440 NAS.OFFICE.LAN.") {
		t.Error("expected SRV target comparison to be case-insensitive")
	}
	if dnsDataMatches("SRV", "10 20 4440 nas.office.lan.", "11 20 4440 nas.office.lan.") {
		t.Error("expected a differing SRV priority to NOT match")
	}
}

func TestDNSDataMatches_ARecordExact(t *testing.T) {
	if !dnsDataMatches("A", "192.168.100.50", "192.168.100.50") {
		t.Error("expected identical A record values to match")
	}
	if dnsDataMatches("A", "192.168.100.50", "192.168.100.51") {
		t.Error("expected a differing A record value to NOT match")
	}
}

func TestExpectedDNSData_MXFormatsFields(t *testing.T) {
	got, err := expectedDNSData(config.DNSRecord{Type: "MX", Target: "mail.office.lan", Priority: 10})
	if err != nil {
		t.Fatalf("expectedDNSData: %v", err)
	}
	want := "10 mail.office.lan."
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestExpectedDNSData_NAPTRFormatsFields(t *testing.T) {
	got, err := expectedDNSData(config.DNSRecord{
		Type: "NAPTR", NAPTROrder: 100, Priority: 10,
		NAPTRFlags: "S", NAPTRService: "SIP+D2U", NAPTRRegexp: "", Target: "_sip._udp.office.lan",
	})
	if err != nil {
		t.Fatalf("expectedDNSData: %v", err)
	}
	want := "100 10 S|SIP+D2U| _sip._udp.office.lan."
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestExpectedDNSData_CAAFormatsFields(t *testing.T) {
	got, err := expectedDNSData(config.DNSRecord{Type: "CAA", CAAFlags: 0, CAATag: "issue", Value: "letsencrypt.org"})
	if err != nil {
		t.Fatalf("expectedDNSData: %v", err)
	}
	want := "0 issue letsencrypt.org"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestExpectedDNSData_RAWNormalizesHexCase(t *testing.T) {
	got, err := expectedDNSData(config.DNSRecord{Type: "RAW", RRType: 65280, RRDataHex: "68656C6C6F"})
	if err != nil {
		t.Fatalf("expectedDNSData: %v", err)
	}
	want := "68656c6c6f"
	if got != want {
		t.Errorf("got %q, want %q (lowercase, matching internal/dnsprobe's own hex.EncodeToString output)", got, want)
	}
}

func TestExpectedDNSData_RAWRejectsInvalidHex(t *testing.T) {
	if _, err := expectedDNSData(config.DNSRecord{Type: "RAW", RRType: 65280, RRDataHex: "not-hex"}); err == nil {
		t.Error("expected an error for invalid rr_data_hex")
	}
}

func TestDNSDataMatches_MXExchangeCaseInsensitiveNumbersExact(t *testing.T) {
	if !dnsDataMatches("MX", "10 mail.office.lan.", "10 MAIL.OFFICE.LAN.") {
		t.Error("expected MX exchange comparison to be case-insensitive")
	}
	if dnsDataMatches("MX", "10 mail.office.lan.", "11 mail.office.lan.") {
		t.Error("expected a differing MX preference to NOT match")
	}
}

func TestDNSDataMatches_NAPTRReplacementCaseInsensitiveRestExact(t *testing.T) {
	want := "100 10 S|SIP+D2U| _sip._udp.office.lan."
	if !dnsDataMatches("NAPTR", want, "100 10 S|SIP+D2U| _SIP._UDP.OFFICE.LAN.") {
		t.Error("expected NAPTR replacement comparison to be case-insensitive")
	}
	if dnsDataMatches("NAPTR", want, "100 10 X|SIP+D2U| _sip._udp.office.lan.") {
		t.Error("expected a differing NAPTR flags field to NOT match")
	}
}

func TestDNSDataMatches_CAAExact(t *testing.T) {
	if !dnsDataMatches("CAA", "0 issue letsencrypt.org", "0 issue letsencrypt.org") {
		t.Error("expected identical CAA values to match")
	}
	if dnsDataMatches("CAA", "0 issue letsencrypt.org", "0 issue example.org") {
		t.Error("expected a differing CAA value to NOT match")
	}
}

func TestDNSDataMatches_RAWHexCaseInsensitive(t *testing.T) {
	if !dnsDataMatches("RAW", "68656c6c6f", "68656C6C6F") {
		t.Error("expected RAW hex comparison to be case-insensitive")
	}
	if dnsDataMatches("RAW", "68656c6c6f", "aabbccdd") {
		t.Error("expected differing RAW hex to NOT match")
	}
}

func TestRunOneDNSCheck_RAWQueriesByNumericType(t *testing.T) {
	var gotQType string
	origFn := dnsProbeFn
	dnsProbeFn = func(target, name, qtype string, timeout time.Duration) (dnsprobe.Result, error) {
		gotQType = qtype
		return dnsprobe.Result{Answered: true, RCode: 0, Data: "68656c6c6f"}, nil
	}
	defer func() { dnsProbeFn = origFn }()

	rec := config.DNSRecord{Name: "raw.office.lan", Type: "RAW", RRType: 65280, RRDataHex: "68656c6c6f"}
	result := runOneDNSCheck("192.168.100.1", rec.Name, rec.Type, &rec, true)

	if gotQType != "65280" {
		t.Errorf("dnsProbeFn was called with qtype %q, want \"65280\" (rec.RRType, not the literal \"RAW\")", gotQType)
	}
	if result.Type != "RAW" {
		t.Errorf("result.Type = %q, want \"RAW\" (display should stay the configured type name)", result.Type)
	}
	if !result.Valid {
		t.Errorf("expected result.Valid = true, got false (Expected=%q Got=%q)", result.Expected, result.Got)
	}
}

// encodeDNSNameForTest mirrors internal/dnsprobe's own unexported
// encodeQName.
func encodeDNSNameForTest(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	var out []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			label := name[start:i]
			out = append(out, byte(len(label)))
			out = append(out, label...)
			start = i + 1
		}
	}
	return append(out, 0)
}

func TestRunOneDNSCheck_ValidatesRealAAnswer(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	qname := "nas.office.lan."
	answerIP := net.ParseIP("192.168.100.50").To4()
	qn := encodeDNSNameForTest(qname)

	go func() {
		buf := make([]byte, 512)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			id := binary.BigEndian.Uint16(buf[:n])
			resp := make([]byte, 12)
			binary.BigEndian.PutUint16(resp[0:2], id)
			binary.BigEndian.PutUint16(resp[2:4], 1<<15) // QR=1, NOERROR
			binary.BigEndian.PutUint16(resp[4:6], 1)     // QDCOUNT
			binary.BigEndian.PutUint16(resp[6:8], 1)     // ANCOUNT
			resp = append(resp, qn...)
			resp = binary.BigEndian.AppendUint16(resp, 1) // QTYPE=A
			resp = binary.BigEndian.AppendUint16(resp, 1) // QCLASS=IN
			resp = append(resp, qn...)                    // answer owner name
			resp = binary.BigEndian.AppendUint16(resp, 1) // TYPE=A
			resp = binary.BigEndian.AppendUint16(resp, 1) // CLASS=IN
			resp = binary.BigEndian.AppendUint32(resp, 300)
			resp = binary.BigEndian.AppendUint16(resp, uint16(len(answerIP)))
			resp = append(resp, answerIP...)
			pc.WriteTo(resp, src)
		}
	}()

	origFn := dnsProbeFn
	dnsProbeFn = func(addr, qname, qtype string, timeout time.Duration) (dnsprobe.Result, error) {
		return dnsprobe.ProbeAddr(pc.LocalAddr().String(), qname, qtype, timeout)
	}
	defer func() { dnsProbeFn = origFn }()

	expected := config.DNSRecord{Name: qname, Type: "A", Value: "192.168.100.50"}
	r := runOneDNSCheck("unused", qname, "A", &expected, true)

	if !r.Answered {
		t.Fatalf("expected Answered=true, got result: %+v", r)
	}
	if r.Got != "192.168.100.50" {
		t.Errorf("Got = %q, want %q", r.Got, "192.168.100.50")
	}
	if r.Expected != "192.168.100.50" {
		t.Errorf("Expected = %q, want %q", r.Expected, "192.168.100.50")
	}
	if !r.Valid {
		t.Error("expected Valid=true when the answer matches the configured value")
	}

	// Now confirm a MISMATCH is correctly reported as invalid, not
	// silently passed.
	wrongExpected := config.DNSRecord{Name: qname, Type: "A", Value: "192.168.100.99"}
	r2 := runOneDNSCheck("unused", qname, "A", &wrongExpected, true)
	if r2.Valid {
		t.Error("expected Valid=false when the answer does NOT match the configured value")
	}
}

func TestRunOneDNSCheck_CapturesAnswerForDefaultCheckWithNoExpected(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	qname := "claude.ai."
	answerIP := net.ParseIP("172.16.200.22").To4()
	qn := encodeDNSNameForTest(qname)

	go func() {
		buf := make([]byte, 512)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			id := binary.BigEndian.Uint16(buf[:n])
			resp := make([]byte, 12)
			binary.BigEndian.PutUint16(resp[0:2], id)
			binary.BigEndian.PutUint16(resp[2:4], 1<<15)
			binary.BigEndian.PutUint16(resp[4:6], 1)
			binary.BigEndian.PutUint16(resp[6:8], 1)
			resp = append(resp, qn...)
			resp = binary.BigEndian.AppendUint16(resp, 1)
			resp = binary.BigEndian.AppendUint16(resp, 1)
			resp = append(resp, qn...)
			resp = binary.BigEndian.AppendUint16(resp, 1)
			resp = binary.BigEndian.AppendUint16(resp, 1)
			resp = binary.BigEndian.AppendUint32(resp, 300)
			resp = binary.BigEndian.AppendUint16(resp, uint16(len(answerIP)))
			resp = append(resp, answerIP...)
			pc.WriteTo(resp, src)
		}
	}()

	origFn := dnsProbeFn
	dnsProbeFn = func(addr, qname, qtype string, timeout time.Duration) (dnsprobe.Result, error) {
		return dnsprobe.ProbeAddr(pc.LocalAddr().String(), qname, qtype, timeout)
	}
	defer func() { dnsProbeFn = origFn }()

	r := runOneDNSCheck("unused", qname, "A", nil, true)

	if !r.Answered {
		t.Fatalf("expected Answered=true, got result: %+v", r)
	}
	if r.Got != "172.16.200.22" {
		t.Errorf("Got = %q, want %q — the default-check path must still capture the real answer", r.Got, "172.16.200.22")
	}
	if r.Expected != "" {
		t.Errorf("Expected = %q, want empty — no config.DNSRecord was passed", r.Expected)
	}
	if !r.Valid {
		t.Error("expected Valid = true for a genuinely successful default-check answer")
	}
}

func TestRunOneDNSCheck_RefusedDefaultCheckReportsInvalidWithReason(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	qname := "claude.ai."

	go func() {
		buf := make([]byte, 512)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			id := binary.BigEndian.Uint16(buf[:n])
			resp := make([]byte, 12)
			binary.BigEndian.PutUint16(resp[0:2], id)
			binary.BigEndian.PutUint16(resp[2:4], (1<<15)|5)
			// QDCOUNT/ANCOUNT both 0 — a REFUSED response carries no
			// answer section.
			pc.WriteTo(resp, src)
		}
	}()

	origFn := dnsProbeFn
	dnsProbeFn = func(addr, qname, qtype string, timeout time.Duration) (dnsprobe.Result, error) {
		return dnsprobe.ProbeAddr(pc.LocalAddr().String(), qname, qtype, timeout)
	}
	defer func() { dnsProbeFn = origFn }()

	noUpstream := runOneDNSCheck("unused", qname, "A", nil, false)
	if !noUpstream.Answered {
		t.Fatalf("expected Answered=true (a real packet came back), got result: %+v", noUpstream)
	}
	if noUpstream.Valid {
		t.Error("expected Valid=false for a REFUSED response — this is the exact bug: a REFUSED answer must never report as a healthy check")
	}
	if !strings.Contains(noUpstream.Reason, "no upstream DNS configured") {
		t.Errorf("Reason = %q, want it to name the actual cause (no upstream DNS configured)", noUpstream.Reason)
	}

	hasUpstream := runOneDNSCheck("unused", qname, "A", nil, true)
	if hasUpstream.Valid {
		t.Error("expected Valid=false for a REFUSED response regardless of hasUpstream")
	}
	if hasUpstream.Reason != "rcode: REFUSED" {
		t.Errorf("Reason = %q, want a bare rcode label when upstream IS configured (REFUSED must mean something else there)", hasUpstream.Reason)
	}
}

func TestDNSRcodeName_KnownAndUnknownCodes(t *testing.T) {
	cases := map[int]string{
		0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
		6: "RCODE6", 99: "RCODE99",
	}
	for rcode, want := range cases {
		if got := dnsRcodeName(rcode); got != want {
			t.Errorf("dnsRcodeName(%d) = %q, want %q", rcode, got, want)
		}
	}
}

func TestMergedScopeNames_UnionsAcrossNodes(t *testing.T) {
	byNodeID := map[string]probeConfigResponse{
		"node-a": {Scopes: map[string]remoteScope{"office": {}, "av-dante": {}}},
		"node-b": {Scopes: map[string]remoteScope{"office": {}}},
	}
	names := mergedScopeNames(byNodeID)
	if len(names) != 2 {
		t.Fatalf("expected 2 unique scope names, got %d: %v", len(names), names)
	}
}

func TestResultStore_PruneRemovesStaleScopes(t *testing.T) {
	s := newResultStore()
	s.set("rw-100", ScopeProbeResult{Scope: "rw-100"})
	s.set("rw-101", ScopeProbeResult{Scope: "rw-101"})

	s.prune(map[string]bool{"rw-100": true})

	if _, ok := s.get("rw-100"); !ok {
		t.Error("rw-100 should survive pruning — it's in the keep set")
	}
	if _, ok := s.get("rw-101"); ok {
		t.Error("rw-101 should be removed by pruning — it's not in the keep set")
	}
}

// TestResultStore_PruneWithEmptyKeepClearsEverything: when the cluster's
// scopes go to zero, the store must too.
func TestResultStore_PruneWithEmptyKeepClearsEverything(t *testing.T) {
	s := newResultStore()
	for i := 100; i <= 119; i++ {
		s.set(fmt.Sprintf("rw-%d", i), ScopeProbeResult{})
	}
	s.prune(map[string]bool{})
	if len(s.all()) != 0 {
		t.Errorf("all() = %d entries, want 0 after pruning with an empty keep set", len(s.all()))
	}
}

func TestResultStore_ClearRevertsEveryScopeToPending(t *testing.T) {
	s := newResultStore()
	s.set("rw-100", ScopeProbeResult{Scope: "rw-100"})
	s.set("rw-101", ScopeProbeResult{Scope: "rw-101"})

	s.clear()

	if len(s.all()) != 0 {
		t.Errorf("all() = %d entries, want 0 after clear()", len(s.all()))
	}
	if _, ok := s.get("rw-100"); ok {
		t.Error("rw-100 should be gone after clear() — get() must report not-found so the API returns pending")
	}
}

func TestIncarnationTracker_FirstSightingNeverInvalidates(t *testing.T) {
	tr := newIncarnationTracker()
	byNode := map[string]probeConfigResponse{
		"dnshived1022": {NodeID: "dnshived1022", Incarnation: 5},
		"dnshived1023": {NodeID: "dnshived1023", Incarnation: 12},
	}
	if tr.restarted(byNode) {
		t.Error("restarted() = true on first sighting, want false")
	}
}

func TestIncarnationTracker_UnchangedIncarnationDoesNotInvalidate(t *testing.T) {
	tr := newIncarnationTracker()
	byNode := map[string]probeConfigResponse{
		"dnshived1022": {NodeID: "dnshived1022", Incarnation: 5},
	}
	tr.restarted(byNode) // first sighting, establishes the baseline
	if tr.restarted(byNode) {
		t.Error("restarted() = true with an unchanged incarnation, want false")
	}
}

func TestIncarnationTracker_ChangedIncarnationInvalidates(t *testing.T) {
	tr := newIncarnationTracker()
	tr.restarted(map[string]probeConfigResponse{
		"dnshived1022": {NodeID: "dnshived1022", Incarnation: 5},
	})
	if !tr.restarted(map[string]probeConfigResponse{
		"dnshived1022": {NodeID: "dnshived1022", Incarnation: 6},
	}) {
		t.Error("restarted() = false after an incarnation bump, want true")
	}
}

func TestIncarnationTracker_OneNodeRestartingIsEnough(t *testing.T) {
	tr := newIncarnationTracker()
	tr.restarted(map[string]probeConfigResponse{
		"dnshived1022": {NodeID: "dnshived1022", Incarnation: 5},
		"dnshived1023": {NodeID: "dnshived1023", Incarnation: 9},
	})
	got := tr.restarted(map[string]probeConfigResponse{
		"dnshived1022": {NodeID: "dnshived1022", Incarnation: 5},  // unchanged
		"dnshived1023": {NodeID: "dnshived1023", Incarnation: 10}, // restarted
	})
	if !got {
		t.Error("restarted() = false, want true — one node's restart must invalidate the whole sweep")
	}
}

func TestProbeLogTracker_LogsOnFailureAndRecovery(t *testing.T) {
	tracker := newProbeLogTracker(nil)
	events := eventlog.New(100, "probe")

	healthy := ScopeProbeResult{Scope: "rw-100", Enabled: true}
	healthy.DHCP.Verdict = "ok"
	healthy.DHCP.Valid = true

	failing := healthy
	failing.DHCP.Verdict = "no_answer"
	failing.DHCP.Valid = false
	failing.DHCP.Reason = "no answer"

	tracker.check(events, "rw-100", healthy) // first observation, already healthy
	tracker.check(events, "rw-100", healthy) // no change
	tracker.check(events, "rw-100", failing) // healthy -> failing
	tracker.check(events, "rw-100", failing) // still failing, no re-log
	tracker.check(events, "rw-100", healthy) // failing -> healthy

	all := events.Last(10)
	if len(all) != 2 {
		t.Fatalf("got %d events, want exactly 2 (one FAIL, one OK): %+v", len(all), all)
	}
	if all[0].Prefix != "PROBE:DHCP_FAIL" || all[0].Message != "rw-100: no answer" {
		t.Errorf("all[0] = %+v, want PROBE:DHCP_FAIL \"rw-100: no answer\"", all[0])
	}
	if all[1].Prefix != "PROBE:DHCP_OK" {
		t.Errorf("all[1].Prefix = %q, want PROBE:DHCP_OK", all[1].Prefix)
	}
}

func TestProbeLogTracker_FirstObservationAlreadyBrokenIsLogged(t *testing.T) {
	tracker := newProbeLogTracker(nil)
	events := eventlog.New(100, "probe")

	broken := ScopeProbeResult{Scope: "rw-101", Enabled: true}
	broken.DHCP.Verdict = "dual_active"
	broken.DHCP.Reason = "dual-active: more than one server answered"

	tracker.check(events, "rw-101", broken)

	all := events.Last(10)
	if len(all) != 1 || all[0].Prefix != "PROBE:DHCP_FAIL" {
		t.Fatalf("events = %+v, want exactly one PROBE:DHCP_FAIL", all)
	}
}

func TestProbeLogTracker_UnreachableScopeNeverLogged(t *testing.T) {
	tracker := newProbeLogTracker(nil)
	events := eventlog.New(100, "probe")

	unreachable := ScopeProbeResult{Scope: "rw-102", Enabled: false}
	tracker.check(events, "rw-102", unreachable)

	if got := events.Last(10); len(got) != 0 {
		t.Errorf("events = %+v, want none for an unreachable (not failing) scope", got)
	}
}

// TestProbeLogTracker_DNSChecksTrackedIndependently pins that two
// different (name, type, against) checks for the SAME scope don't mask
// each other.
func TestProbeLogTracker_DNSChecksTrackedIndependently(t *testing.T) {
	tracker := newProbeLogTracker(nil)
	events := eventlog.New(100, "probe")

	result := ScopeProbeResult{Scope: "rw-103", Enabled: true}
	result.DHCP.Verdict = "ok"
	result.DHCP.Valid = true
	result.DNSChecks = []DNSCheckResult{
		{Name: "a.local.", Type: "A", Against: "172.16.103.22", Answered: true},
		{Name: "b.local.", Type: "A", Against: "172.16.103.22", Answered: false},
	}
	tracker.check(events, "rw-103", result)

	all := events.Last(10)
	if len(all) != 1 {
		t.Fatalf("got %d events, want exactly 1 (only b.local. failed): %+v", len(all), all)
	}
	if all[0].Prefix != "PROBE:DNS_FAIL" {
		t.Errorf("Prefix = %q, want PROBE:DNS_FAIL", all[0].Prefix)
	}
}

// TestProbeLogTracker_PruneRemovesRemovedScopes mirrors resultStore's own
// prune test.
func TestProbeLogTracker_PruneRemovesRemovedScopes(t *testing.T) {
	tracker := newProbeLogTracker(nil)
	events := eventlog.New(100, "probe")

	broken := ScopeProbeResult{Scope: "rw-104", Enabled: true}
	broken.DHCP.Verdict = "no_answer"
	broken.DHCP.Reason = "no answer"
	tracker.check(events, "rw-104", broken)

	tracker.prune(map[string]bool{}) // rw-104 no longer configured

	tracker.check(events, "rw-104", broken)

	all := events.Last(10)
	if len(all) != 2 {
		t.Errorf("got %d events, want 2 (failure logged again after prune forgot it): %+v", len(all), all)
	}
}

// fakeClusterNode spins up an httptest server answering GET
// /api/v1/probe-config and GET /api/v1/token/status the way a real cluster
// node would.
func fakeClusterNode(t *testing.T, resp probeConfigResponse, tokens map[string]tokenInfo) ClusterNode {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/probe-config":
			json.NewEncoder(w).Encode(resp)
		case "/api/v1/token/status":
			json.NewEncoder(w).Encode(tokens)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return ClusterNode{Name: "node-a", Addr: strings.TrimPrefix(srv.URL, "http://")}
}

func TestProbeScopeNow_UnknownScopeReturnsErrorWithoutTouchingStore(t *testing.T) {
	node := fakeClusterNode(t, probeConfigResponse{
		NodeID: "node-a",
		Scopes: map[string]remoteScope{"rw-100": {VLANID: 100, NodeIP: "172.16.100.22/24"}},
	}, map[string]tokenInfo{})

	cfg := &ProbeConfig{TrunkParent: "nonexistent-iface-for-test", ClusterNodes: []ClusterNode{node}, ClusterToken: "tok"}
	store := newResultStore()
	tracker := newProbeLogTracker(nil)
	events := eventlog.New(10, "probe")

	_, _, err := probeScopeNow(cfg, store, tracker, events, newOwnershipDebounce(), "rw-999")
	if err == nil {
		t.Fatal("expected an error for an unknown scope, got nil")
	}
	if _, ok := store.get("rw-999"); ok {
		t.Error("expected no store entry to be created for an unknown scope")
	}
}

func TestProbeScopeNow_KnownScopeUpdatesStore(t *testing.T) {
	node := fakeClusterNode(t, probeConfigResponse{
		NodeID: "node-a",
		Scopes: map[string]remoteScope{"rw-100": {VLANID: 100, NodeIP: "172.16.100.22/24"}},
	}, map[string]tokenInfo{})

	cfg := &ProbeConfig{TrunkParent: "nonexistent-iface-for-test", ClusterNodes: []ClusterNode{node}, ClusterToken: "tok"}
	store := newResultStore()
	tracker := newProbeLogTracker(nil)
	events := eventlog.New(10, "probe")

	result, published, err := probeScopeNow(cfg, store, tracker, events, newOwnershipDebounce(), "rw-100")
	if err != nil {
		t.Fatalf("probeScopeNow: %v", err)
	}
	if result.Reachable {
		t.Error("expected Reachable=false — this test's TrunkParent has no real interface")
	}
	if !published {
		t.Error("published = false, want true — an unreachable-scope result is never an ownership-only failure, so it must never be suppressed")
	}
	stored, ok := store.get("rw-100")
	if !ok {
		t.Fatal("expected resultStore to have an entry for rw-100 after probeScopeNow")
	}
	if stored.Scope != "rw-100" {
		t.Errorf("stored.Scope = %q, want rw-100", stored.Scope)
	}
	if stored.QueueWaitMS != 0 {
		t.Errorf("QueueWaitMS = %d, want 0 — this scope was unreachable, no real DHCP probe ran", stored.QueueWaitMS)
	}
}

func TestQueueWaitMS(t *testing.T) {
	cases := []struct {
		name          string
		elapsed       time.Duration
		expectedFloor time.Duration
		want          int64
	}{
		{"under floor reports zero", 8 * time.Second, 9 * time.Second, 0},
		{"exactly at floor reports zero", 9 * time.Second, 9 * time.Second, 0},
		{"real queueing beyond floor reports the residual", 15 * time.Second, 9 * time.Second, 6000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := queueWaitMS(tc.elapsed, tc.expectedFloor); got != tc.want {
				t.Errorf("queueWaitMS(%v, %v) = %d, want %d", tc.elapsed, tc.expectedFloor, got, tc.want)
			}
		})
	}
}

func TestFetchAllScopes_QueriesClusterNodesConcurrently(t *testing.T) {
	const delay = 150 * time.Millisecond
	var nodes []ClusterNode
	for i := 0; i < 3; i++ {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(delay)
			json.NewEncoder(w).Encode(probeConfigResponse{NodeID: fmt.Sprintf("node-%d", i)})
		}))
		t.Cleanup(srv.Close)
		nodes = append(nodes, ClusterNode{Name: fmt.Sprintf("node-%d", i), Addr: strings.TrimPrefix(srv.URL, "http://")})
	}

	cfg := &ProbeConfig{ClusterNodes: nodes, ClusterToken: "tok"}
	start := time.Now()
	byNodeID, _, err := fetchAllScopes(cfg)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("fetchAllScopes: %v", err)
	}
	if len(byNodeID) != 3 {
		t.Fatalf("got %d nodes, want 3", len(byNodeID))
	}
	if elapsed > 3*delay {
		t.Errorf("fetchAllScopes took %v for 3 nodes each sleeping %v — looks sequential, not concurrent", elapsed, delay)
	}
}

func TestClusterConvergence_UnionsServingAcrossNodes(t *testing.T) {
	workerA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(remoteStatus{ConfiguredScopes: []string{"rw-100", "rw-101"}, Serving: []string{"rw-100"}})
	}))
	defer workerA.Close()
	workerB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(remoteStatus{ConfiguredScopes: []string{"rw-100", "rw-101"}, Serving: []string{"rw-101"}})
	}))
	defer workerB.Close()

	cfg := &ProbeConfig{ClusterNodes: []ClusterNode{
		{Name: "core-1", Addr: strings.TrimPrefix(workerA.URL, "http://")},
		{Name: "core-2", Addr: strings.TrimPrefix(workerB.URL, "http://")},
	}}

	converged, served, total := clusterConvergence(cfg)
	if !converged {
		t.Errorf("converged = false, want true — rw-100 and rw-101 are each served by SOME node (served=%d total=%d)", served, total)
	}
	if served != 2 || total != 2 {
		t.Errorf("served=%d total=%d, want 2/2", served, total)
	}
}

func TestClusterConvergence_NotConvergedWhenAScopeHasNoServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(remoteStatus{ConfiguredScopes: []string{"rw-100", "rw-101"}, Serving: []string{"rw-100"}})
	}))
	defer srv.Close()

	cfg := &ProbeConfig{ClusterNodes: []ClusterNode{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}

	converged, served, total := clusterConvergence(cfg)
	if converged {
		t.Error("converged = true, want false — rw-101 has no server yet")
	}
	if served != 1 || total != 2 {
		t.Errorf("served=%d total=%d, want 1/2", served, total)
	}
}

func TestClusterConvergence_ZeroScopesIsConverged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(remoteStatus{})
	}))
	defer srv.Close()

	cfg := &ProbeConfig{ClusterNodes: []ClusterNode{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}

	converged, _, total := clusterConvergence(cfg)
	if !converged || total != 0 {
		t.Errorf("converged=%v total=%d, want true/0 for an empty cluster", converged, total)
	}
}

// TestClusterConvergence_UnreachableNodeIsExcludedNotFatal confirms one
// unreachable node doesn't crash or permanently block convergence.
func TestClusterConvergence_UnreachableNodeIsExcludedNotFatal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(remoteStatus{ConfiguredScopes: []string{"rw-100"}, Serving: []string{"rw-100"}})
	}))
	defer srv.Close()

	cfg := &ProbeConfig{ClusterNodes: []ClusterNode{
		{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")},
		{Name: "core-2", Addr: "127.0.0.1:1"}, // nothing listens here
	}}

	converged, served, total := clusterConvergence(cfg)
	if !converged || served != 1 || total != 1 {
		t.Errorf("converged=%v served=%d total=%d, want true/1/1 (unreachable node excluded, not fatal)", converged, served, total)
	}
}

func TestClusterConvergence_AllNodesFailingIsNotConverged(t *testing.T) {
	cfg := &ProbeConfig{ClusterNodes: []ClusterNode{
		{Name: "core-1", Addr: "127.0.0.1:1"},
		{Name: "core-2", Addr: "127.0.0.1:1"},
	}}

	converged, served, total := clusterConvergence(cfg)
	if converged {
		t.Errorf("converged = true, want false — every node's fetch failed, this must never read as \"nothing to wait for\" (served=%d total=%d)", served, total)
	}
}

func TestScopeSigTracker_ReportsChangeOnceAndIgnoresFirstSight(t *testing.T) {
	mk := func(disabled bool, vlan int) map[string]probeConfigResponse {
		return map[string]probeConfigResponse{
			"n1": {Scopes: map[string]remoteScope{
				"a": {Parent: "ens19", VLANID: vlan, ProbeDisabled: disabled},
				"b": {Parent: "ens20", VLANID: 5},
			}},
		}
	}
	tr := newScopeSigTracker()
	if got := tr.changed(mk(true, 18)); len(got) != 0 {
		t.Fatalf("first observation reported %v, want nothing (no stale result to clear)", got)
	}
	if got := tr.changed(mk(true, 18)); len(got) != 0 {
		t.Fatalf("unchanged config reported %v", got)
	}
	if got := tr.changed(mk(false, 18)); len(got) != 1 || got[0] != "a" {
		t.Fatalf("re-enable reported %v, want [a]", got)
	}
	if got := tr.changed(mk(false, 18)); len(got) != 0 {
		t.Fatalf("change reported twice: %v", got)
	}
	if got := tr.changed(mk(false, 19)); len(got) != 1 || got[0] != "a" {
		t.Fatalf("vlan move reported %v, want [a]", got)
	}
}

func TestLegitimateScopeServers_AcceptsScopeVIP(t *testing.T) {
	byNodeID := map[string]probeConfigResponse{}
	for i, nodeIP := range []string{"10.19.101.51/24", "10.19.101.52/24", "10.19.101.53/24"} {
		byNodeID[string(rune('a'+i))] = probeConfigResponse{Scopes: map[string]remoteScope{
			"s19-101": {NodeIP: nodeIP, VIP: "10.19.101.254/24"},
		}}
	}
	legit := legitimateScopeServers("s19-101", byNodeID)

	if got := unrecognizedServers([]string{"10.19.101.254"}, legit); len(got) != 0 {
		t.Errorf("an offer from the scope's own VIP was flagged as rogue: %v", got)
	}
	if got := unrecognizedServers([]string{"10.19.101.52"}, legit); len(got) != 0 {
		t.Errorf("an offer from a node IP was flagged as rogue: %v", got)
	}
	if got := unrecognizedServers([]string{"10.19.101.1"}, legit); len(got) != 1 || got[0] != "10.19.101.1" {
		t.Errorf("a foreign server was not flagged: %v", got)
	}
}
