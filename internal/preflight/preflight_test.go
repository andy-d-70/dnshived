// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package preflight

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"dnshived/internal/config"
)

func scope(parent string, vlan, vrrp int, vip string) config.ScopeConfig {
	return config.ScopeConfig{Parent: parent, VLANID: vlan, VRRPID: vrrp, VIP: vip, PreferredWorker: config.RoleCore1}
}

func baseCtx() Context {
	return Context{
		Existing: map[string]config.ScopeConfig{
			"office": scope("ens19", 10, 10, "192.168.10.254/24"),
			"guest":  scope("ens19", 20, 20, "192.168.20.254/24"),
		},
		Workers: []string{"ens19", "ens20"},
		Mgmt:    "ens18",
	}
}

func find(t *testing.T, r Result, kind Kind) Collision {
	t.Helper()
	for _, c := range r.Collisions {
		if c.Kind == kind {
			return c
		}
	}
	t.Fatalf("no %s finding in %+v", kind, r.Collisions)
	return Collision{}
}

func has(r Result, kind Kind) bool {
	for _, c := range r.Collisions {
		if c.Kind == kind {
			return true
		}
	}
	return false
}

func fixOf(c Collision, kind FixKind) (Fix, bool) {
	for _, f := range c.Fixes {
		if f.Kind == kind {
			return f, true
		}
	}
	return Fix{}, false
}

func TestCheck_CleanScope(t *testing.T) {
	in := map[string]config.ScopeConfig{"lab": scope("ens19", 30, 30, "192.168.30.254/24")}
	got := Check(baseCtx(), in)
	if len(got) != 1 || got[0].Verdict != VerdictOK || len(got[0].Collisions) != 0 {
		t.Errorf("a clean scope must come back ok: %+v", got)
	}
}

func TestCheck_NameCollisionSuppressesTheRest(t *testing.T) {
	in := map[string]config.ScopeConfig{"office": scope("ens19", 10, 10, "192.168.10.254/24")}
	r := Check(baseCtx(), in)[0]
	if r.Verdict != VerdictConflicts || len(r.Collisions) != 1 || r.Collisions[0].Kind != KindName {
		t.Fatalf("the same scope again must be one name finding, got %+v", r.Collisions)
	}
	if f, ok := fixOf(r.Collisions[0], FixRename); !ok || f.Name != "office-2" {
		t.Errorf("rename fix = %+v", f)
	}
	if _, ok := fixOf(r.Collisions[0], FixSkip); !ok {
		t.Error("a skip fix is always offered")
	}
}

func TestCheck_Collisions(t *testing.T) {
	tests := []struct {
		name string
		sc   config.ScopeConfig
		want Kind
		sev  Severity
		fix  FixKind
	}{
		{"vlan on the same parent", scope("ens19", 10, 33, "192.168.33.254/24"), KindVLAN, SevError, FixVLAN},
		{"vrrp id", scope("ens19", 33, 10, "192.168.33.254/24"), KindVRRPID, SevError, FixVRRPID},
		{"vip subnet overlap", scope("ens19", 33, 33, "192.168.10.1/25"), KindVIPOverlap, SevError, FixNetwork},
		{"same vip address", scope("ens19", 33, 33, "192.168.10.254/24"), KindVIPOverlap, SevError, FixNetwork},
		{"unknown parent", scope("ens99", 33, 33, "192.168.33.254/24"), KindParent, SevError, FixParent},
		{"tagged scope on the mgmt interface", scope("ens18", 33, 33, "192.168.33.254/24"), KindParent, SevError, FixSkip},
		{"vlan out of range", scope("ens19", 5000, 33, "192.168.33.254/24"), KindVLAN, SevError, FixVLAN},
		{"vrrp out of range", scope("ens19", 33, 300, "192.168.33.254/24"), KindVRRPID, SevError, FixVRRPID},
		{"bad vip", scope("ens19", 33, 33, "nonsense"), KindAddress, SevError, FixSkip},
		{"bad preferred worker", func() config.ScopeConfig {
			s := scope("ens19", 33, 33, "192.168.33.254/24")
			s.PreferredWorker = "core-9"
			return s
		}(), KindPreferredWorker, SevError, FixPreferredWorker},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Check(baseCtx(), map[string]config.ScopeConfig{"new": tt.sc})[0]
			c := find(t, r, tt.want)
			if c.Severity != tt.sev {
				t.Errorf("severity = %s", c.Severity)
			}
			if _, ok := fixOf(c, tt.fix); !ok {
				t.Errorf("no %s fix in %+v", tt.fix, c.Fixes)
			}
			if tt.sev == SevError && r.Verdict != VerdictConflicts {
				t.Errorf("verdict = %s", r.Verdict)
			}
			if c.Detail == "" {
				t.Error("a finding needs a detail")
			}
		})
	}
}

func TestCheck_FixesPointAtFreeValues(t *testing.T) {
	ctx := baseCtx()
	r := Check(ctx, map[string]config.ScopeConfig{"new": scope("ens19", 10, 10, "192.168.10.1/24")})[0]
	if f, _ := fixOf(find(t, r, KindVLAN), FixVLAN); f.VLANID != 11 || f.Parent != "ens19" {
		t.Errorf("vlan fix = %+v, want 11 on ens19", f)
	}
	if f, _ := fixOf(find(t, r, KindVRRPID), FixVRRPID); f.VRRPID != 11 {
		t.Errorf("vrrp fix = %+v, want 11", f)
	}
	net := find(t, r, KindVIPOverlap)
	var grouped Fix
	for _, f := range net.Fixes {
		if f.Kind == FixNetwork && f.VLANID != 0 {
			grouped = f
		}
	}
	if grouped.Network != "192.168.11.0/24" || grouped.VLANID != 11 || grouped.VRRPID != 11 {
		t.Errorf("the network fix must come with a new VLAN and VRRP ID, got %+v", grouped)
	}
}

func TestCheck_CandidatesCollideWithEachOther(t *testing.T) {
	in := map[string]config.ScopeConfig{
		"a": scope("ens19", 40, 40, "192.168.40.254/24"),
		"b": scope("ens19", 40, 41, "192.168.41.254/24"),
		"c": scope("ens20", 42, 40, "192.168.40.1/24"),
	}
	got := Check(baseCtx(), in)
	byName := map[string]Result{}
	for _, r := range got {
		byName[r.Scope] = r
	}
	if c := find(t, byName["a"], KindVLAN); c.Other != "b" {
		t.Errorf("a/b vlan clash other = %q", c.Other)
	}
	if !has(byName["a"], KindVRRPID) || !has(byName["c"], KindVRRPID) {
		t.Error("a and c share VRRP ID 40")
	}
	if !has(byName["a"], KindVIPOverlap) || !has(byName["c"], KindVIPOverlap) || has(byName["b"], KindVIPOverlap) {
		t.Error("a and c overlap, b does not")
	}
	if got[0].Scope != "a" || got[2].Scope != "c" {
		t.Errorf("results are not sorted by name: %v", []string{got[0].Scope, got[1].Scope, got[2].Scope})
	}
}

func TestCheck_DHCPOverlapIsAWarningAndNotRepeatedForOverlappingSubnets(t *testing.T) {
	ctx := baseCtx()
	o := ctx.Existing["office"]
	o.DHCPRange = [2]string{"192.168.10.100", "192.168.10.200"}
	ctx.Existing["office"] = o
	sc := scope("ens20", 50, 50, "192.168.50.254/24")
	sc.DHCPRange = [2]string{"192.168.10.150", "192.168.10.160"}
	r := Check(ctx, map[string]config.ScopeConfig{"new": sc})[0]
	c := find(t, r, KindDHCPOverlap)
	if c.Severity != SevWarning || r.Verdict != VerdictWarnings {
		t.Errorf("dhcp overlap with disjoint subnets is a warning: %+v verdict %s", c, r.Verdict)
	}
	sc = scope("ens20", 50, 50, "192.168.10.1/24")
	sc.DHCPRange = [2]string{"192.168.10.150", "192.168.10.160"}
	r = Check(ctx, map[string]config.ScopeConfig{"new": sc})[0]
	if has(r, KindDHCPOverlap) {
		t.Error("an overlapping subnet already says it; the range overlap must not repeat it")
	}
}

func TestCheck_ManagementVIPIsTaken(t *testing.T) {
	ctx := baseCtx()
	ctx.MgmtVRRPID, ctx.MgmtVIPHost = 60, "192.168.90.254"
	r := Check(ctx, map[string]config.ScopeConfig{"new": scope("ens19", 60, 60, "192.168.90.254/24")})[0]
	if c := find(t, r, KindVRRPID); c.Other != "management VIP" {
		t.Errorf("other = %q", c.Other)
	}
	if c := find(t, r, KindVIPOverlap); c.Other != "management VIP" {
		t.Errorf("other = %q", c.Other)
	}
}

func TestCheck_AddressesInsideTheScope(t *testing.T) {
	sc := scope("ens19", 60, 60, "192.168.60.254/24")
	sc.NodeIP = "192.168.60.254/24"
	sc.NodeIPOverrides = map[string]string{"core-2": "192.168.61.5/24", "core-3": "192.168.61.5/24"}
	sc.Gateway = "192.168.60.255"
	r := Check(baseCtx(), map[string]config.ScopeConfig{"new": sc})[0]
	var node, gw []string
	for _, c := range r.Collisions {
		switch c.Kind {
		case KindNodeIP:
			node = append(node, string(c.Severity)+": "+c.Detail)
		case KindGateway:
			gw = append(gw, c.Detail)
		}
	}
	joined := strings.Join(node, "\n")
	for _, want := range []string{"error: node_ip 192.168.60.254 is the same address as the vip", "warning: node_ip_overrides[core-2] 192.168.61.5 is outside", "error: node_ip_overrides[core-2] and node_ip_overrides[core-3] are the same address"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
	if len(gw) != 1 || !strings.Contains(gw[0], "broadcast") {
		t.Errorf("gateway findings = %v", gw)
	}
}

func TestCheck_Reservations(t *testing.T) {
	ctx := baseCtx()
	o := ctx.Existing["office"]
	o.Reservations = []config.Reservation{{MAC: "AA:BB:CC:00:00:01", IP: "192.168.10.50"}}
	ctx.Existing["office"] = o
	sc := scope("ens19", 70, 70, "192.168.70.254/24")
	sc.Gateway = "192.168.70.1"
	sc.Reservations = []config.Reservation{
		{MAC: "aa:bb:cc:00:00:01", IP: "192.168.70.10"},
		{MAC: "aa:bb:cc:00:00:02", IP: "192.168.70.10"},
		{MAC: "aa:bb:cc:00:00:02", IP: "192.168.70.11"},
		{MAC: "aa:bb:cc:00:00:03", IP: "10.9.9.9"},
		{MAC: "aa:bb:cc:00:00:04", IP: "192.168.70.254"},
		{MAC: "aa:bb:cc:00:00:05", IP: "192.168.70.1"},
		{MAC: "aa:bb:cc:00:00:06", IP: "not-an-ip"},
	}
	r := Check(ctx, map[string]config.ScopeConfig{"new": sc})[0]
	var details []string
	for _, c := range r.Collisions {
		if c.Kind == KindReservation {
			details = append(details, string(c.Severity)+": "+c.Detail)
		}
	}
	joined := strings.Join(details, "\n")
	for _, want := range []string{
		"error: reservations 1 and 2 both use the address 192.168.70.10",
		"error: reservations 2 and 3 both use the MAC aa:bb:cc:00:00:02",
		"warning: reservation 4 (aa:bb:cc:00:00:03): 10.9.9.9 is outside",
		"error: reservation 5 (aa:bb:cc:00:00:04) uses the vip",
		"warning: reservation 6 (aa:bb:cc:00:00:05) uses the gateway",
		"error: reservation 7 (aa:bb:cc:00:00:06): \"not-an-ip\" is not an IPv4",
		"warning: the MAC aa:bb:cc:00:00:01 is also reserved in scope \"office\"",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
}

func TestCheck_TemplateReferences(t *testing.T) {
	ctx := baseCtx()
	ctx.HasSource = func(kind, id string) bool { return kind == "template" && id == "known" }
	sc := scope("ens19", 80, 80, "192.168.80.254/24")
	sc.ContentLinks = map[string]config.ContentLink{
		"dns_records":  {Kind: "template", SourceID: "known"},
		"dhcp_options": {Kind: "option_set", SourceID: "gone"},
	}
	r := Check(ctx, map[string]config.ScopeConfig{"new": sc})[0]
	if r.Verdict != VerdictWarnings || len(r.Collisions) != 1 {
		t.Fatalf("only the missing source is reported, as a warning: %+v", r)
	}
	if f, ok := fixOf(r.Collisions[0], FixUnlink); !ok || f.Link != "dhcp_options" {
		t.Errorf("unlink fix = %+v", f)
	}
	ctx.HasSource = nil
	if r := Check(ctx, map[string]config.ScopeConfig{"new": sc})[0]; has(r, KindTemplateRef) {
		t.Error("without a source lookup the check is skipped")
	}
}

func TestCheck_InvalidScopeName(t *testing.T) {
	r := Check(baseCtx(), map[string]config.ScopeConfig{"my scope!": scope("ens19", 90, 90, "192.168.90.254/24")})[0]
	c := find(t, r, KindScopeName)
	if f, _ := fixOf(c, FixRename); f.Name != "my-scope-" {
		t.Errorf("rename fix = %q", f.Name)
	}
}

func TestCheck_DoesNotChangeItsInputs(t *testing.T) {
	ctx := baseCtx()
	in := map[string]config.ScopeConfig{"office": scope("ens19", 10, 10, "192.168.10.254/24")}
	Check(ctx, in)
	if len(ctx.Existing) != 2 || len(in) != 1 || in["office"].VLANID != 10 {
		t.Error("inputs changed")
	}
}

func TestCheck_TwoHundredScopesStayFast(t *testing.T) {
	ctx := Context{Existing: map[string]config.ScopeConfig{}, Workers: []string{"ens19"}}
	in := map[string]config.ScopeConfig{}
	for i := 0; i < 200; i++ {
		ctx.Existing[fmt.Sprintf("old%d", i)] = scope("ens19", 2+i, 1+i%250, fmt.Sprintf("10.%d.%d.254/24", i/200, i%200))
		in[fmt.Sprintf("new%d", i)] = scope("ens19", 2+i, 1+i%250, fmt.Sprintf("10.%d.%d.254/24", i/200, i%200))
	}
	start := time.Now()
	got := Check(ctx, in)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("200 candidates against 200 scopes took %s", d)
	}
	if len(got) != 200 || got[0].Verdict != VerdictConflicts {
		t.Errorf("results = %d, first verdict %s", len(got), got[0].Verdict)
	}
}

func TestNextFreeVLANAndVRRP(t *testing.T) {
	if id, ok := NextFreeVLAN(map[int]bool{11: true, 12: true}, 10); !ok || id != 13 {
		t.Errorf("vlan = %d %v", id, ok)
	}
	if id, ok := NextFreeVLAN(map[int]bool{}, 4094); !ok || id != 2 {
		t.Errorf("wrap = %d %v", id, ok)
	}
	if id, ok := NextFreeVLAN(map[int]bool{}, 0); !ok || id != 2 {
		t.Errorf("untagged start = %d %v", id, ok)
	}
	full := map[int]bool{}
	for i := 2; i <= 4094; i++ {
		full[i] = true
	}
	if _, ok := NextFreeVLAN(full, 5); ok {
		t.Error("a full range has no free id")
	}
	if id, ok := NextFreeVRRPID(map[int]bool{255: true, 1: true}, 254); !ok || id != 2 {
		t.Errorf("vrrp wrap = %d %v", id, ok)
	}
	allv := map[int]bool{}
	for i := 1; i <= 255; i++ {
		allv[i] = true
	}
	if _, ok := NextFreeVRRPID(allv, 1); ok {
		t.Error("a full range has no free id")
	}
}

func TestNextFreeNetwork(t *testing.T) {
	p := netip.MustParsePrefix
	tests := []struct {
		name string
		used []netip.Prefix
		like netip.Prefix
		want string
		ok   bool
	}{
		{"next /24", []netip.Prefix{p("192.168.10.0/24")}, p("192.168.10.0/24"), "192.168.11.0/24", true},
		{"skips used", []netip.Prefix{p("192.168.10.0/24"), p("192.168.11.0/24"), p("192.168.12.0/23")}, p("192.168.10.0/24"), "192.168.14.0/24", true},
		{"wraps inside the block", []netip.Prefix{p("192.168.255.0/24")}, p("192.168.255.0/24"), "192.168.0.0/24", true},
		{"bigger network", []netip.Prefix{p("10.0.0.0/16")}, p("10.0.0.0/16"), "10.1.0.0/16", true},
		{"172.16 block", []netip.Prefix{p("172.16.0.0/24")}, p("172.16.0.0/24"), "172.16.1.0/24", true},
		{"not a private network", nil, p("8.8.8.0/24"), "", false},
		{"larger than the block", nil, p("192.168.0.0/15"), "", false},
		{"ipv6", nil, p("fd00::/64"), "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := NextFreeNetwork(tt.used, tt.like)
			if ok != tt.ok || (ok && got.String() != tt.want) {
				t.Errorf("got %v %v, want %s %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestGenerateNetworks(t *testing.T) {
	p := netip.MustParsePrefix
	got, err := GenerateNetworks(p("192.168.100.0/24"), 2, 3, nil)
	if err != nil || fmt.Sprint(got) != "[192.168.100.0/24 192.168.102.0/24 192.168.104.0/24]" {
		t.Errorf("got %v %v", got, err)
	}
	got, err = GenerateNetworks(p("192.168.100.0/24"), 1, 2, []netip.Prefix{p("192.168.100.0/24"), p("192.168.101.0/25")})
	if err != nil || fmt.Sprint(got) != "[192.168.102.0/24 192.168.103.0/24]" {
		t.Errorf("a used network must be skipped, got %v %v", got, err)
	}
	if got, err := GenerateNetworks(p("192.168.254.0/24"), 1, 5, nil); err == nil || len(got) != 2 {
		t.Errorf("running out of the block must fail with what fits: %v %v", got, err)
	}
	for _, bad := range []struct {
		start       string
		step, count int
	}{{"192.168.0.0/24", 0, 1}, {"192.168.0.0/24", 1, 0}, {"8.8.8.0/24", 1, 1}, {"fd00::/64", 1, 1}, {"192.168.0.0/31", 1, 1}} {
		if _, err := GenerateNetworks(p(bad.start), bad.step, bad.count, nil); err == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}
}

func TestCheck_ANetworkThatFillsItsBlockOffersOnlySkip(t *testing.T) {
	ctx := baseCtx()
	r := Check(ctx, map[string]config.ScopeConfig{"new": scope("ens19", 33, 33, "192.168.10.254/16")})[0]
	c := find(t, r, KindVIPOverlap)
	if len(c.Fixes) != 1 || c.Fixes[0].Kind != FixSkip {
		t.Errorf("fixes = %+v: there is no other /16 in 192.168.0.0/16", c.Fixes)
	}
}
