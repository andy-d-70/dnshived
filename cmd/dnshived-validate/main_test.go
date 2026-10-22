// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlaneIntact_NoWarningsIsOK(t *testing.T) {
	snap := ClusterSnapshot{Nodes: []NodeSnapshot{
		{NodeID: "core-1", Reachable: true},
		{NodeID: "core-2", Reachable: true},
	}}
	if err := (PlaneIntact{}).Evaluate(snap); err != nil {
		t.Errorf("Evaluate() = %v, want nil for no drift", err)
	}
}

func TestPlaneIntact_UnreachableNodeIsIgnored(t *testing.T) {
	snap := ClusterSnapshot{Nodes: []NodeSnapshot{
		{NodeID: "core-1", Reachable: false, PlaneWarnings: []string{"scope office: interface ens19.100 no longer exists"}},
	}}
	if err := (PlaneIntact{}).Evaluate(snap); err != nil {
		t.Errorf("Evaluate() = %v, want nil for an unreachable node's stale warnings", err)
	}
}

func TestPlaneIntact_DriftIsAViolation(t *testing.T) {
	snap := ClusterSnapshot{Nodes: []NodeSnapshot{
		{NodeID: "core-1", Reachable: true},
		{NodeID: "core-2", Reachable: true, PlaneWarnings: []string{
			"scope office: interface ens19.100 no longer exists",
		}},
	}}
	err := (PlaneIntact{}).Evaluate(snap)
	if err == nil {
		t.Fatal("Evaluate() = nil, want a violation for reported plane drift")
	}
	if got := err.Error(); got == "" {
		t.Error("violation error message is empty")
	}
}

func TestDHCPDualActive_NoFindingsIsOK(t *testing.T) {
	d := &DHCPDualActive{lastBad: map[string]string{}}
	if err := d.Evaluate(ClusterSnapshot{}); err != nil {
		t.Errorf("Evaluate() = %v, want nil when no dual-active was found", err)
	}
}

func TestDHCPDualActive_FindingIsAViolation(t *testing.T) {
	d := &DHCPDualActive{lastBad: map[string]string{
		"office@192.0.2.22:9443": "servers=[192.168.100.22 192.168.100.23]",
	}}
	err := d.Evaluate(ClusterSnapshot{})
	if err == nil {
		t.Fatal("Evaluate() = nil, want a violation for a real dual-active finding")
	}
	if !strings.Contains(err.Error(), "office@192.0.2.22:9443") {
		t.Errorf("error %q doesn't identify which scope/worker", err.Error())
	}
}

func TestDHCPDualActive_Name(t *testing.T) {
	d := &DHCPDualActive{lastBad: map[string]string{}}
	if got := d.Name(); got != "dhcp_dual_active" {
		t.Errorf("Name() = %q, want %q", got, "dhcp_dual_active")
	}
}

func TestCheckScopeIPCoherence_DistinctAddressesInSubnetIsOK(t *testing.T) {
	byAddr := map[string]probeConfigScope{
		"192.0.2.22:9443": {VIP: "192.168.100.1/24", NodeIP: "192.168.100.22/24"},
		"192.0.2.23:9443": {VIP: "192.168.100.1/24", NodeIP: "192.168.100.23/24"},
	}
	if got := checkScopeIPCoherence(byAddr); got != "" {
		t.Errorf("checkScopeIPCoherence() = %q, want \"\" for distinct in-subnet addresses", got)
	}
}

func TestCheckScopeIPCoherence_DuplicateWorkerAddressIsAViolation(t *testing.T) {
	byAddr := map[string]probeConfigScope{
		"192.0.2.22:9443": {VIP: "192.168.100.1/24", NodeIP: "192.168.100.22/24"},
		"192.0.2.23:9443": {VIP: "192.168.100.1/24", NodeIP: "192.168.100.22/24"}, // same as worker-a's
	}
	got := checkScopeIPCoherence(byAddr)
	if got == "" {
		t.Fatal("checkScopeIPCoherence() = \"\", want a violation for two nodes sharing the same node_ip")
	}
	if !strings.Contains(got, "192.168.100.22") {
		t.Errorf("violation %q doesn't name the duplicated address", got)
	}
}

func TestCheckScopeIPCoherence_NodeIPEqualsVIPIsAViolation(t *testing.T) {
	byAddr := map[string]probeConfigScope{
		"192.0.2.22:9443": {VIP: "192.168.100.1/24", NodeIP: "192.168.100.1/24"}, // collides with the VIP
	}
	got := checkScopeIPCoherence(byAddr)
	if got == "" {
		t.Fatal("checkScopeIPCoherence() = \"\", want a violation when a node_ip equals the VIP")
	}
}

func TestCheckScopeIPCoherence_NodeIPOutsideSubnetIsAViolation(t *testing.T) {
	byAddr := map[string]probeConfigScope{
		"192.0.2.22:9443": {VIP: "192.168.100.1/24", NodeIP: "10.0.0.22/24"}, // wrong subnet entirely
	}
	got := checkScopeIPCoherence(byAddr)
	if got == "" {
		t.Fatal("checkScopeIPCoherence() = \"\", want a violation for a node_ip outside the VIP's subnet")
	}
	if !strings.Contains(got, "subnet") {
		t.Errorf("violation %q doesn't mention the subnet mismatch", got)
	}
}

// TestCheckScopeIPCoherence_UnparsableAddressIsAViolation confirms a
// malformed address fails closed (reported as a violation) rather than
// being silently skipped.
func TestCheckScopeIPCoherence_UnparsableAddressIsAViolation(t *testing.T) {
	byAddr := map[string]probeConfigScope{
		"192.0.2.22:9443": {VIP: "192.168.100.1/24", NodeIP: "not-an-ip"},
	}
	if got := checkScopeIPCoherence(byAddr); got == "" {
		t.Error("checkScopeIPCoherence() = \"\", want a violation for an unparsable node_ip")
	}
}

// TestCheckScopeIPCoherence_EmptyInputIsOK: a scope no reachable worker
// reported anything for has nothing to check yet.
func TestCheckScopeIPCoherence_EmptyInputIsOK(t *testing.T) {
	if got := checkScopeIPCoherence(map[string]probeConfigScope{}); got != "" {
		t.Errorf("checkScopeIPCoherence(empty) = %q, want \"\"", got)
	}
}

func TestNodeIPCoherence_NoFindingsIsOK(t *testing.T) {
	n := &NodeIPCoherence{lastBad: map[string]string{}}
	if err := n.Evaluate(ClusterSnapshot{}); err != nil {
		t.Errorf("Evaluate() = %v, want nil when no coherence violation was found", err)
	}
}

func TestNodeIPCoherence_FindingIsAViolation(t *testing.T) {
	n := &NodeIPCoherence{lastBad: map[string]string{
		"office": "duplicate address 192.168.100.22 used by both 192.0.2.22:9443 and 192.0.2.23:9443",
	}}
	err := n.Evaluate(ClusterSnapshot{})
	if err == nil {
		t.Fatal("Evaluate() = nil, want a violation for a real coherence finding")
	}
	if !strings.Contains(err.Error(), "office") {
		t.Errorf("error %q doesn't identify which scope", err.Error())
	}
}

func TestNodeIPCoherence_Name(t *testing.T) {
	n := &NodeIPCoherence{lastBad: map[string]string{}}
	if got := n.Name(); got != "node_ip_coherence" {
		t.Errorf("Name() = %q, want %q", got, "node_ip_coherence")
	}
}

func TestGroupByField_SingleValueIsOK(t *testing.T) {
	addrs := []string{"a", "b", "c"}
	got := groupByField("version", addrs, func(addr string) (string, bool) {
		return "1.2.3", true
	})
	if got != "" {
		t.Errorf("got %q, want \"\" when every node reports the same value", got)
	}
}

func TestGroupByField_TwoValuesIsAViolationNamingBoth(t *testing.T) {
	got := groupByField("version", []string{"a", "b", "c"}, func(addr string) (string, bool) {
		if addr == "c" {
			return "1.2.4", true
		}
		return "1.2.3", true
	})
	if got == "" {
		t.Fatal("got \"\", want a violation for a real mismatch")
	}
	for _, want := range []string{"version", "1.2.3", "1.2.4", "a,b", "c"} {
		if !strings.Contains(got, want) {
			t.Errorf("violation text %q missing %q", got, want)
		}
	}
}

func TestGroupByField_UnreachableAddrsAreSkippedNotFlagged(t *testing.T) {
	got := groupByField("version", []string{"a", "b"}, func(addr string) (string, bool) {
		if addr == "b" {
			return "", false
		}
		return "1.2.3", true
	})
	if got != "" {
		t.Errorf("got %q, want \"\" — an unreachable node must not count as a distinct value", got)
	}
}

func TestVersionCoherence_NoFindingsIsOK(t *testing.T) {
	v := &VersionCoherence{}
	if err := v.Evaluate(ClusterSnapshot{}); err != nil {
		t.Errorf("Evaluate() = %v, want nil when no version mismatch was found", err)
	}
}

func TestVersionCoherence_FindingIsAViolation(t *testing.T) {
	v := &VersionCoherence{lastBad: "version mismatch across cluster: 1.2.3: a,b; 1.2.4: c"}
	err := v.Evaluate(ClusterSnapshot{})
	if err == nil {
		t.Fatal("Evaluate() = nil, want a violation for a real version mismatch")
	}
	if !strings.Contains(err.Error(), "1.2.4") {
		t.Errorf("error %q doesn't identify the mismatched version", err.Error())
	}
}

func TestVersionCoherence_Name(t *testing.T) {
	v := &VersionCoherence{}
	if got := v.Name(); got != "version_coherence" {
		t.Errorf("Name() = %q, want %q", got, "version_coherence")
	}
}

func TestScopesHashCoherence_NoFindingsIsOK(t *testing.T) {
	s := &ScopesHashCoherence{}
	if err := s.Evaluate(ClusterSnapshot{}); err != nil {
		t.Errorf("Evaluate() = %v, want nil when every node's ScopesHash agrees", err)
	}
}

func TestScopesHashCoherence_FindingIsAViolation(t *testing.T) {
	s := &ScopesHashCoherence{lastBad: "scopes_hash mismatch across cluster: aaa: a,b; bbb: c"}
	err := s.Evaluate(ClusterSnapshot{})
	if err == nil {
		t.Fatal("Evaluate() = nil, want a violation for a real ScopesHash mismatch")
	}
	if !strings.Contains(err.Error(), "bbb") {
		t.Errorf("error %q doesn't identify the mismatched hash", err.Error())
	}
}

func TestScopesHashCoherence_Name(t *testing.T) {
	s := &ScopesHashCoherence{}
	if got := s.Name(); got != "scopes_hash_coherence" {
		t.Errorf("Name() = %q, want %q", got, "scopes_hash_coherence")
	}
}

func TestHeartbeatLine_AllHealthy(t *testing.T) {
	got := heartbeatLine(42, 7, nil)
	want := "[sample 42] 7 invariant(s) checked, all healthy"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestHeartbeatLine_NamesEveryStillViolatedInvariant(t *testing.T) {
	got := heartbeatLine(42, 7, []string{"mutual_exclusion", "dhcp_dual_active"})
	for _, want := range []string{"sample 42", "7 invariant", "2 still violated", "mutual_exclusion", "dhcp_dual_active"} {
		if !strings.Contains(got, want) {
			t.Errorf("heartbeat line %q missing %q", got, want)
		}
	}
}

func TestHeartbeatLine_SortsViolatedNamesForDeterministicOutput(t *testing.T) {
	got := heartbeatLine(1, 3, []string{"zzz", "aaa"})
	if !strings.Contains(got, "aaa, zzz") {
		t.Errorf("got %q, want violated names sorted (aaa before zzz)", got)
	}
}

func TestProbeTargets_FlagThenWebConfig(t *testing.T) {
	web := filepath.Join(t.TempDir(), "web.json")
	os.WriteFile(web, []byte(`{"probe_hosts":[{"addr":"192.0.2.54:9444"},{"addr":"10.0.0.9:9444","tls":true},{"addr":""}]}`), 0o600)

	got := probeTargets(" 192.0.2.54:9444, https://p2:9444/ ", web)
	if strings.Join(got, " ") != "http://192.0.2.54:9444 https://p2:9444" {
		t.Errorf("flag targets = %v", got)
	}
	got = probeTargets("", web)
	if strings.Join(got, " ") != "http://192.0.2.54:9444 https://10.0.0.9:9444" {
		t.Errorf("web.json targets = %v", got)
	}
	if got := probeTargets("", filepath.Join(t.TempDir(), "missing.json")); got != nil {
		t.Errorf("no flag, no web.json = %v, want nil", got)
	}
}

// TestDHCPDualActive_ProbeOnceAsksTheProbeHosts is the regression test for
// the check never firing: probe results live on the probe hosts only.
func TestDHCPDualActive_ProbeOnceAsksTheProbeHosts(t *testing.T) {
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/cluster":
			json.NewEncoder(w).Encode(map[string]any{"self_addr": r.Host})
		case "/api/v1/status":
			json.NewEncoder(w).Encode(map[string]any{"role": "core-1", "configured_scopes": []string{"office", "lab"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer core.Close()
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/probe/office":
			w.Write([]byte(`{"scope":"office","dhcp":{"verdict":"dual_active","servers":["10.0.4.51","10.0.4.52"]}}`))
		case "/api/v1/probe/lab":
			w.Write([]byte(`{"scope":"lab","pending":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer probe.Close()

	d := &DHCPDualActive{lastBad: map[string]string{}, probes: []string{probe.URL}}
	d.probeOnce(strings.TrimPrefix(core.URL, "http://"))
	err := d.Evaluate(ClusterSnapshot{})
	if err == nil || !strings.Contains(err.Error(), "office@"+probe.URL) {
		t.Fatalf("Evaluate() = %v, want a violation for office from the probe host", err)
	}
	if strings.Contains(err.Error(), "lab@") {
		t.Errorf("a pending result was reported: %v", err)
	}
}
