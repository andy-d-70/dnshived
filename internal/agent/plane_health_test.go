// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"dnshived/internal/config"
	"dnshived/internal/netsnap"
	"dnshived/internal/nstest"
)

func TestCheckPlaneHealth_NotYetReadyScopeIsSkipped(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", testScopes("office"), nil)

	found := a.CheckPlaneHealth()
	if found != nil {
		t.Errorf("found = %v, want nil for a scope that was never marked ready", found)
	}
}

func TestCheckPlaneHealth_MissingInterfaceDemotesReady(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", testScopes("office"), nil)
	a.ready["office"] = time.Now()

	found := a.CheckPlaneHealth()
	if len(found) != 1 {
		t.Fatalf("len(found) = %d, want 1", len(found))
	}
	if found[0].Scope != "office" || found[0].What != "interface" {
		t.Errorf("found[0] = %+v, want Scope=office What=interface", found[0])
	}
	if !found[0].Healable {
		t.Error("a missing interface must be Healable — the a.ready-demotion retry path genuinely fixes it")
	}
	if _, ok := a.ready["office"]; ok {
		t.Error("a.ready[\"office\"] still present — CheckPlaneHealth must demote it so Reconcile's retry path reconstructs it")
	}
}

func TestCheckPlaneHealth_ManyScopesStayScopeSortedOrder(t *testing.T) {
	scopes := map[string]config.ScopeConfig{}
	for i, name := range []string{"zzz-scope", "aaa-scope", "mmm-scope"} {
		scopes[name] = config.ScopeConfig{
			Parent: "ens19", VLANID: 200 + i,
			VIP: "192.168.100.1/24", NodeIP: "192.168.100.22/24",
			DHCPRange: [2]string{"192.168.100.100", "192.168.100.200"},
			Gateway:   "192.168.100.1",
		}
	}
	a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", scopes, nil)
	for name := range scopes {
		a.ready[name] = time.Now()
	}

	found := a.CheckPlaneHealth()
	if len(found) != 3 {
		t.Fatalf("len(found) = %d, want 3 (all three interfaces are fake and don't exist)", len(found))
	}
	want := []string{"aaa-scope", "mmm-scope", "zzz-scope"}
	for i, f := range found {
		if f.Scope != want[i] {
			t.Errorf("found[%d].Scope = %q, want %q (deterministic scope-sorted order)", i, f.Scope, want[i])
		}
	}
}

func TestCheckPlaneHealth_KeepalivedSkippedWhenNotReady(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", testScopes("office"), nil)
	a.ready["office"] = time.Now() // avoid the interface-missing finding drowning out the assertion

	found := a.CheckPlaneHealth()
	for _, f := range found {
		if f.What == "keepalived" {
			t.Errorf("got a keepalived finding while keepalivedReady was false: %+v", f)
		}
	}
}

func TestAddrsMatch_TrueWhenCIDRIPPresentRegardlessOfMask(t *testing.T) {
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("172.16.100.22"), Mask: net.CIDRMask(24, 32)},
	}
	if !addrsMatch(addrs, "172.16.100.22/24") {
		t.Error("want true — exact IP present")
	}
	// Mask differences must be ignored (reconcileInterfaceAddrs cares
	// about the address, not exactly how it's expressed).
	if !addrsMatch(addrs, "172.16.100.22/25") {
		t.Error("want true — same IP, different mask must still match")
	}
}

func TestAddrsMatch_FalseWhenIPAbsent(t *testing.T) {
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("172.16.100.22"), Mask: net.CIDRMask(24, 32)},
	}
	if addrsMatch(addrs, "172.16.100.99/24") {
		t.Error("want false — configured node_ip is not among the real addresses")
	}
}

func TestAddrsMatch_MalformedCIDRDoesNotManufactureFinding(t *testing.T) {
	if !addrsMatch(nil, "not-a-cidr") {
		t.Error("want true (no finding) — a malformed node_ip is a config problem, not this check's to flag")
	}
}

func TestAddrsMatch_EmptyAddrListReturnsFalse(t *testing.T) {
	if addrsMatch(nil, "172.16.100.22/24") {
		t.Error("want false — no real addresses at all cannot match a configured one")
	}
}

func TestLastAppliedGate_UnknownUntilRecorded(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", testScopes("office"), nil)
	if _, known := a.lastGate("office"); known {
		t.Error("want known=false before recordAppliedGate is ever called for this scope")
	}
	a.recordAppliedGate("office", "closed")
	state, known := a.lastGate("office")
	if !known || state != "closed" {
		t.Errorf("lastGate() = (%q, %v), want (\"closed\", true) after recordAppliedGate", state, known)
	}
	a.recordAppliedGate("office", "open")
	state, known = a.lastGate("office")
	if !known || state != "open" {
		t.Errorf("lastGate() = (%q, %v), want (\"open\", true) after a second recordAppliedGate", state, known)
	}
}

func TestShouldSkipInterfaceRebuild(t *testing.T) {
	cases := []struct {
		name       string
		gateState  string // "" = never recorded
		iface      string // "lo" always exists on the test runner; this name never does
		wantSkip   bool
		wantReason string
	}{
		{
			name:      "never recorded — genuinely fresh scope, must build",
			gateState: "", iface: "lo", wantSkip: false,
			wantReason: "no lastGate entry at all (first-ever construction) must never skip",
		},
		{
			name:      "recorded closed — standby scope, retry is harmless either way",
			gateState: "closed", iface: "lo", wantSkip: false,
			wantReason: "a standby scope's retry must still go through createInterface (idempotent, no live service at risk)",
		},
		{
			name:      "recorded open, interface exists — the actual bug scenario",
			gateState: "open", iface: "lo", wantSkip: true,
			wantReason: "dnsmasq-crash-triggered retry of an actively-serving scope must not touch the interface/gate at all",
		},
		{
			name:      "recorded open, interface genuinely gone — must still rebuild",
			gateState: "open", iface: "dnshived-test-missing-9x", wantSkip: false,
			wantReason: "an out-of-band-deleted interface must still be rebuilt (with the correct fail-safe-closed gate), even though this node last believed it was open",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", testScopes("office"), nil)
			if tc.gateState != "" {
				a.recordAppliedGate("office", tc.gateState)
			}
			got := a.shouldSkipInterfaceRebuild("office", tc.iface)
			if got != tc.wantSkip {
				t.Errorf("shouldSkipInterfaceRebuild() = %v, want %v — %s", got, tc.wantSkip, tc.wantReason)
			}
		})
	}
}

func loScope(nodeIP string) map[string]config.ScopeConfig {
	return map[string]config.ScopeConfig{"office": {Parent: "lo", VLANID: 0, NodeIP: nodeIP, VIP: "127.0.0.2/8"}}
}

func findingsFor(found []PlaneHealth, scope string) []string {
	var out []string
	for _, f := range found {
		if f.Scope == scope {
			out = append(out, f.What+": "+f.Detail)
		}
	}
	return out
}

func TestCheckPlaneHealth_NodeIPFromTheSnapshot(t *testing.T) {
	ok := New(config.RoleCore1, "n", 1, "psk", "/tmp", loScope("127.0.0.1/8"), nil)
	ok.ready["office"] = time.Now()
	for _, f := range ok.CheckPlaneHealth() {
		if f.Scope == "office" && (f.What == "interface" || f.What == "node_ip") {
			t.Errorf("lo carries 127.0.0.1, got finding %+v", f)
		}
	}
	if _, still := ok.ready["office"]; !still {
		t.Error("a healthy scope must stay ready")
	}

	bad := New(config.RoleCore1, "n", 1, "psk", "/tmp", loScope("10.255.255.1/24"), nil)
	bad.ready["office"] = time.Now()
	var got *PlaneHealth
	for _, f := range bad.CheckPlaneHealth() {
		if f.Scope == "office" && f.What == "node_ip" {
			f := f
			got = &f
		}
	}
	if got == nil || !got.Healable || !strings.Contains(got.Detail, "lo does not carry configured node_ip 10.255.255.1/24") {
		t.Fatalf("want a healable node_ip finding naming lo, got %+v", got)
	}
	if _, still := bad.ready["office"]; still {
		t.Error("a scope with a drifted node_ip must be demoted from ready")
	}
}

// The snapshot path and the per-scope fallback give the same findings.
func TestCheckPlaneHealth_SnapshotAndFallbackAgree(t *testing.T) {
	scopes := map[string]config.ScopeConfig{
		"a-fine":    {Parent: "lo", VLANID: 0, NodeIP: "127.0.0.1/8"},
		"b-drift":   {Parent: "lo", VLANID: 0, NodeIP: "10.255.255.1/24"},
		"c-missing": {Parent: "no-such-nic", VLANID: 0, NodeIP: "10.0.0.1/24"},
		"d-vlan":    {Parent: "no-such-nic", VLANID: 100, NodeIP: "10.0.1.1/24"},
		"e-nonode":  {Parent: "lo", VLANID: 0},
	}
	run := func() []string {
		a := New(config.RoleCore1, "n", 1, "psk", "/tmp", scopes, nil)
		for name := range scopes {
			a.ready[name] = time.Now()
		}
		var out []string
		for _, f := range a.CheckPlaneHealth() {
			out = append(out, fmt.Sprintf("%s|%s|%s|%v", f.Scope, f.What, f.Detail, f.Healable))
		}
		return out
	}
	withSnapshot := run()
	saved := takeNetSnapshot
	takeNetSnapshot = func() (*netsnap.Snapshot, error) { return nil, errors.New("netlink unavailable") }
	defer func() { takeNetSnapshot = saved }()
	fallback := run()
	if strings.Join(withSnapshot, "\n") != strings.Join(fallback, "\n") {
		t.Errorf("snapshot path\n%s\nfallback path\n%s", strings.Join(withSnapshot, "\n"), strings.Join(fallback, "\n"))
	}
	if len(withSnapshot) < 3 {
		t.Errorf("expected findings for the drifted and the missing interfaces, got %v", withSnapshot)
	}
}

func TestCheckPlaneHealth_GateVRRPCoherenceFromOneParse(t *testing.T) {
	dump, err := os.ReadFile("../vrrpstate/testdata/keepalived.data")
	if err != nil {
		t.Fatal(err)
	}
	scopes := map[string]config.ScopeConfig{
		"office":  {Parent: "lo", VLANID: 0}, // fixture: BACKUP
		"avdante": {Parent: "lo", VLANID: 0}, // fixture: MASTER
		"unknown": {Parent: "lo", VLANID: 0}, // not in the dump
		"closed":  {Parent: "lo", VLANID: 0}, // gate not open: never judged
	}
	a := New(config.RoleCore1, "n", 1, "psk", "/tmp", scopes, nil)
	calls := 0
	a.vrrpDumpOverride = func() ([]byte, error) { calls++; return dump, nil }
	for name := range scopes {
		a.ready[name] = time.Now()
	}
	for _, name := range []string{"office", "avdante", "unknown"} {
		a.lastAppliedGate[name] = "open"
	}
	a.lastAppliedGate["closed"] = "closed"
	found := a.CheckPlaneHealth()
	if calls != 1 {
		t.Errorf("one dump per run, got %d", calls)
	}
	if f := findingsFor(found, "office"); len(f) != 1 || !strings.Contains(f[0], "gate_vrrp_coherence: DHCP gate is open but VRRP state is BACKUP, not MASTER") {
		t.Errorf("office = %v", f)
	}
	for _, name := range []string{"avdante", "unknown", "closed"} {
		for _, f := range findingsFor(found, name) {
			if strings.HasPrefix(f, "gate_vrrp_coherence") {
				t.Errorf("%s must not be flagged: %s", name, f)
			}
		}
	}
	for _, f := range found {
		if f.What == "gate_vrrp_coherence" && f.Healable {
			t.Error("gate/VRRP incoherence is report-only")
		}
	}
}

// BenchmarkCheckPlaneHealth102 runs the check for 102 scopes whose interfaces
// exist in a private namespace. The snapshot is taken on the benchmark's own
// thread, which is why the per-scope fallback cannot be measured here: it asks
// the kernel from worker goroutines outside that namespace. The cost of the old
// per-scope calls is measured in internal/netsnap and internal/vrrpstate.
func BenchmarkCheckPlaneHealth102(b *testing.B) {
	const n = 102
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	nstest.WithDummyInterfaces(b, n)
	scopes := make(map[string]config.ScopeConfig, n)
	for i := 0; i < n; i++ {
		scopes[fmt.Sprintf("s%03d", i)] = config.ScopeConfig{Parent: nstest.Name(i), VLANID: 0, NodeIP: nstest.Addr(i) + "/24"}
	}
	a := New(config.RoleCore1, "n", 1, "psk", "/tmp", scopes, nil)
	var dump strings.Builder
	for name := range scopes {
		a.ready[name] = time.Now()
		a.lastAppliedGate[name] = "open"
		fmt.Fprintf(&dump, " VRRP Instance = DNSHIVED_%s\n   VRRP Version = 2\n   State = MASTER\n   Priority = 100\n", name)
	}
	a.vrrpDumpOverride = func() ([]byte, error) { return []byte(dump.String()), nil }
	for b.Loop() {
		for _, f := range a.CheckPlaneHealth() {
			if f.Scope != "" && (f.What == "interface" || f.What == "node_ip" || f.What == "gate_vrrp_coherence") {
				b.Fatalf("unexpected finding %+v", f)
			}
		}
	}
}
