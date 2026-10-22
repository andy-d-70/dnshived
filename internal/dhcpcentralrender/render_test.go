// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcpcentralrender

import (
	"strings"
	"testing"

	"dnshived/internal/config"
)

func testCluster() config.Cluster {
	return config.Cluster{
		Platform:           &config.Platform{Workers: []string{"ens19", "ens20"}},
		DefaultDHCPOptions: []string{"option:42,192.0.2.1"},
		Scopes: map[string]config.ScopeConfig{
			"office": {
				Parent:    "ens19",
				VLANID:    42,
				VIP:       "192.168.10.254/24",
				NodeIP:    "192.168.10.22/24",
				Gateway:   "192.168.10.1",
				DHCPRange: [2]string{"192.168.10.100", "192.168.10.200"},
				Reservations: []config.Reservation{
					{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.10.50", Hostname: "nas1"},
				},
			},
			"av-dante": {
				Parent:      "ens20",
				VLANID:      100,
				VIP:         "172.16.100.254/24",
				NodeIP:      "172.16.100.22/24",
				Gateway:     "172.16.100.1",
				DHCPRange:   [2]string{"172.16.100.100", "172.16.100.200"},
				DHCPOptions: []string{"option:66,192.0.2.5"},
			},
			"incomplete": {
				Parent: "ens19",
				VLANID: 200,
				// Missing VIP/NodeIP/Gateway/DHCPRange -- must be skipped.
			},
		},
	}
}

func TestRenderInitial_EmptyAddressResolvesToDefault(t *testing.T) {
	out, err := RenderInitial("", "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("RenderInitial: %v", err)
	}
	if !strings.Contains(out, "listen-address="+DefaultAddress) {
		t.Errorf("expected listen-address=%s; got:\n%s", DefaultAddress, out)
	}
}

func TestRenderInitial_HonorsConfiguredAddress(t *testing.T) {
	out, err := RenderInitial("127.0.0.98", "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("RenderInitial: %v", err)
	}
	if !strings.Contains(out, "listen-address=127.0.0.98") {
		t.Errorf("expected configured address to be honored; got:\n%s", out)
	}
}

func TestRenderInitial_NoDynamicContent(t *testing.T) {
	out, err := RenderInitial("", "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("RenderInitial: %v", err)
	}
	for _, forbidden := range []string{"dhcp-range=", "dhcp-option=", "dhcp-host=", "port=0\ndhcp-range"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("RenderInitial must carry zero scope-derived content; found %q in:\n%s", forbidden, out)
		}
	}
	if !strings.Contains(out, "port=0") {
		t.Errorf("expected port=0 (no DHCP service yet); got:\n%s", out)
	}
}

func TestRender_OneRangePerScopeWithFullAddressing(t *testing.T) {
	out, err := Render(testCluster(), "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "dhcp-range=set:office,192.168.10.100,192.168.10.200,255.255.255.0,12h") {
		t.Errorf("missing office's dhcp-range; got:\n%s", out)
	}
	if !strings.Contains(out, "dhcp-option=tag:office,option:router,192.168.10.1") {
		t.Errorf("missing office's router option; got:\n%s", out)
	}
	if !strings.Contains(out, "dhcp-range=set:av-dante,172.16.100.100,172.16.100.200,255.255.255.0,12h") {
		t.Errorf("missing av-dante's dhcp-range; got:\n%s", out)
	}
}

func TestRender_SkipsIncompleteScope(t *testing.T) {
	out, err := Render(testCluster(), "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(out, "incomplete") {
		t.Errorf("incomplete scope should have been skipped entirely; got:\n%s", out)
	}
}

func TestRender_TagScopesCustomDHCPOptions(t *testing.T) {
	out, err := Render(testCluster(), "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "dhcp-option=tag:av-dante,option:66,192.0.2.5") {
		t.Errorf("av-dante's own DHCPOptions must be tag-scoped to av-dante; got:\n%s", out)
	}
}

func TestRender_ClientDNSServerEmptyRendersConfiguredNodeAddresses(t *testing.T) {
	out, err := Render(testCluster(), "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "dhcp-option=tag:office,option:dns-server,192.168.10.22") {
		t.Errorf("expected office's own node address as the default dns-server; got:\n%s", out)
	}
	if !strings.Contains(out, "dhcp-option=tag:av-dante,option:dns-server,172.16.100.22") {
		t.Errorf("expected av-dante's own node address as the default dns-server; got:\n%s", out)
	}
}

func TestRender_ClientDNSServerEmptyUsesOverridesAndSuffixes(t *testing.T) {
	c := testCluster()
	sc := c.Scopes["office"]
	sc.NodeIPOverrides = map[string]string{config.RoleCore2: "192.168.10.23"}
	c.Scopes["office"] = sc
	c.ScopeDefaults = &config.ScopeDefaults{NodeIPSuffixes: map[string]string{config.RoleCore3: "24"}}

	out, err := Render(c, "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "dhcp-option=tag:office,option:dns-server,192.168.10.22,192.168.10.23,192.168.10.24") {
		t.Errorf("expected own NodeIP + core-2's override + core-3's suffix-derived address, sorted; got:\n%s", out)
	}
}

func TestRender_ClientDNSServerOverride(t *testing.T) {
	c := testCluster()
	sc := c.Scopes["office"]
	sc.ClientDNSServer = "8.8.8.8,1.1.1.1"
	c.Scopes["office"] = sc

	out, err := Render(c, "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "dhcp-option=tag:office,option:dns-server,8.8.8.8,1.1.1.1") {
		t.Errorf("expected office's client DNS server override to render; got:\n%s", out)
	}
	if strings.Contains(out, "tag:office,option:dns-server,192.168.10.22") {
		t.Errorf("office's explicit override must win outright, not merge with the computed default; got:\n%s", out)
	}
	// av-dante still has no ClientDNSServer set — gets its own computed
	// default, unaffected by office's override.
	if !strings.Contains(out, "dhcp-option=tag:av-dante,option:dns-server,172.16.100.22") {
		t.Errorf("av-dante has no ClientDNSServer override — expected its own computed default; got:\n%s", out)
	}
}

func TestRender_ServerIdentifierIsScopeVIP(t *testing.T) {
	out, err := Render(testCluster(), "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "dhcp-option=tag:office,54,192.168.10.254") {
		t.Errorf("expected office's VIP as its server identifier; got:\n%s", out)
	}
	if !strings.Contains(out, "dhcp-option=tag:av-dante,54,172.16.100.254") {
		t.Errorf("expected av-dante's VIP as its server identifier; got:\n%s", out)
	}
}

func TestRender_MultiValueGatewayRendersAsDnsmasqMultiRouterOption(t *testing.T) {
	c := testCluster()
	sc := c.Scopes["office"]
	sc.Gateway = "192.0.2.1,192.0.2.2"
	c.Scopes["office"] = sc

	out, err := Render(c, "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "dhcp-option=tag:office,option:router,192.0.2.1,192.0.2.2") {
		t.Errorf("expected office's multi-value gateway to render verbatim; got:\n%s", out)
	}
}

func TestRender_FallsBackToClusterDefaultDHCPOptionsWhenScopeHasNone(t *testing.T) {
	out, err := Render(testCluster(), "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "dhcp-option=tag:office,option:42,192.0.2.1") {
		t.Errorf("office should inherit tag-scoped DefaultDHCPOptions; got:\n%s", out)
	}
	if strings.Contains(out, "dhcp-option=tag:av-dante,option:42,192.0.2.1") {
		t.Errorf("av-dante has its own DHCPOptions and must NOT also inherit the cluster default; got:\n%s", out)
	}
}

func TestPreamble_AlwaysWiresDHCPScript(t *testing.T) {
	initial, err := RenderInitial("", "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("RenderInitial: %v", err)
	}
	if !strings.Contains(initial, "dhcp-script=/usr/local/bin/dnshived-dhcp-lease-hook") {
		t.Errorf("RenderInitial missing dhcp-script line; got:\n%s", initial)
	}

	full, err := Render(testCluster(), "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(full, "dhcp-script=/usr/local/bin/dnshived-dhcp-lease-hook") {
		t.Errorf("Render missing dhcp-script line; got:\n%s", full)
	}
}

func TestRender_NeverInlinesReservations(t *testing.T) {
	out, err := Render(testCluster(), "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(out, "dhcp-host=") {
		t.Errorf("Render's own output must never inline a dhcp-host line; got:\n%s", out)
	}
	if !strings.Contains(out, "dhcp-hostsfile=/var/lib/dnshived/"+HostsFileName) {
		t.Errorf("Render must reference the separate hosts file; got:\n%s", out)
	}
}

func TestReservations_AggregatesAcrossScopesGlobalNoTag(t *testing.T) {
	reservations := Reservations(testCluster())
	out, err := RenderHostsFile(reservations)
	if err != nil {
		t.Fatalf("RenderHostsFile: %v", err)
	}
	if !strings.Contains(out, "dhcp-host=aa:bb:cc:dd:ee:01,192.168.10.50,nas1") {
		t.Errorf("missing office's reservation; got:\n%s", out)
	}
	// Reservations are global (dhcp-host has no tag: prefix) -- a MAC
	// is already unambiguous across the whole network.
	if strings.Contains(out, "dhcp-host=tag:") {
		t.Error("dhcp-host lines must never be tag-scoped")
	}
}

func TestRender_NetmaskDerivedFromNonSlash24CIDR(t *testing.T) {
	c := config.Cluster{
		Scopes: map[string]config.ScopeConfig{
			"wide": {
				Parent:    "ens19",
				VLANID:    5,
				VIP:       "10.0.0.254/23",
				NodeIP:    "10.0.0.22/23",
				Gateway:   "10.0.0.1",
				DHCPRange: [2]string{"10.0.0.100", "10.0.1.200"},
			},
		},
	}
	out, err := Render(c, "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "dhcp-range=set:wide,10.0.0.100,10.0.1.200,255.255.254.0,12h") {
		t.Errorf("expected a /23 netmask (255.255.254.0); got:\n%s", out)
	}
}

func TestRender_LeaseTimeIoTDefault(t *testing.T) {
	c := config.Cluster{
		Scopes: map[string]config.ScopeConfig{
			"iot": {
				Parent:          "ens19",
				VLANID:          7,
				VIP:             "10.1.0.254/24",
				NodeIP:          "10.1.0.22/24",
				Gateway:         "10.1.0.1",
				DHCPRange:       [2]string{"10.1.0.100", "10.1.0.200"},
				DHCPIoTDefaults: true,
			},
		},
	}
	out, err := Render(c, "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "10.1.0.100,10.1.0.200,255.255.255.0,24h") {
		t.Errorf("IoT-default scope should get the 24h lease time; got:\n%s", out)
	}
}

func TestRender_DeterministicOrder(t *testing.T) {
	c := testCluster()
	out1, err := Render(c, "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	out2, err := Render(c, "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if out1 != out2 {
		t.Errorf("two renders of the identical cluster produced different output")
	}
	if strings.Index(out1, "av-dante") > strings.Index(out1, "office") {
		t.Error("expected av-dante's block before office's (alphabetical scope order)")
	}
}

func TestRender_NeverBindsAVLANInterfaceOrUpstream(t *testing.T) {
	out, err := Render(testCluster(), "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(out, "interface=ens") {
		t.Error("central DHCP config must never bind a real VLAN interface directly")
	}
	if strings.Contains(out, "no-resolv") || strings.Contains(out, "server=") {
		t.Error("central DHCP config has no DNS role at all -- DNS-specific directives don't belong here")
	}
}

func TestPreamble_AlwaysSetsInterfaceLo(t *testing.T) {
	outs := map[string]string{}
	var err error
	outs["RenderInitial"], err = RenderInitial("", "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("RenderInitial: %v", err)
	}
	outs["Render"], err = Render(testCluster(), "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for name, out := range outs {
		if !strings.Contains(out, "interface=lo") {
			t.Errorf("%s must set interface=lo -- required for dnsmasq's DHCP subsystem to receive traffic at all; got:\n%s", name, out)
		}
		if !strings.Contains(out, "bind-interfaces") {
			t.Errorf("%s must still set bind-interfaces; got:\n%s", name, out)
		}
	}
}

// ---- RenderForParent ----

func TestRenderForParent_OnlyIncludesScopesOnThatParent(t *testing.T) {
	out, err := RenderForParent(testCluster(), "ens19", "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("RenderForParent: %v", err)
	}
	if !strings.Contains(out, "dhcp-range=set:office,") {
		t.Errorf("expected office's own range (parent ens19); got:\n%s", out)
	}
	if strings.Contains(out, "dhcp-range=set:av-dante,") {
		t.Errorf("av-dante is on ens20, must not appear in ens19's own render; got:\n%s", out)
	}
}

func TestRenderForParent_DifferentParentGetsOnlyItsOwnScope(t *testing.T) {
	out, err := RenderForParent(testCluster(), "ens20", "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("RenderForParent: %v", err)
	}
	if !strings.Contains(out, "dhcp-range=set:av-dante,") {
		t.Errorf("expected av-dante's own range (parent ens20); got:\n%s", out)
	}
	if strings.Contains(out, "dhcp-range=set:office,") {
		t.Errorf("office is on ens19, must not appear in ens20's own render; got:\n%s", out)
	}
}

func TestRenderForParent_BindsToTrunkSpecificAddress(t *testing.T) {
	outA, err := RenderForParent(testCluster(), "ens19", "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("RenderForParent(ens19): %v", err)
	}
	if !strings.Contains(outA, "listen-address=127.0.1.21") {
		t.Errorf("ens19 (first Worker) should bind 127.0.1.21; got:\n%s", outA)
	}

	outB, err := RenderForParent(testCluster(), "ens20", "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("RenderForParent(ens20): %v", err)
	}
	if !strings.Contains(outB, "listen-address=127.0.2.21") {
		t.Errorf("ens20 (second Worker) should bind 127.0.2.21; got:\n%s", outB)
	}
}

func TestRenderForParent_UsesTrunkSuffixedLeaseAndLogPaths(t *testing.T) {
	out, err := RenderForParent(testCluster(), "ens19", "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("RenderForParent: %v", err)
	}
	if !strings.Contains(out, "dhcp-leasefile=/var/lib/dnshived/leases-central-1") {
		t.Errorf("expected a trunk-suffixed lease file, distinct from Render's own unsuffixed one; got:\n%s", out)
	}
	if !strings.Contains(out, "log-facility=/var/lib/dnshived/dnsmasq-central-dhcp-1.log") {
		t.Errorf("expected a trunk-suffixed log file; got:\n%s", out)
	}
}

func TestRenderForParent_UnknownParentErrors(t *testing.T) {
	if _, err := RenderForParent(testCluster(), "ens99", "/var/lib/dnshived"); err == nil {
		t.Error("RenderForParent(ens99) = nil error, want an error for a parent absent from Platform.Workers")
	}
}

func TestRenderForParent_ZeroScopesOnParentRendersValidMinimalConfig(t *testing.T) {
	c := testCluster()
	c.Platform.Workers = append(c.Platform.Workers, "ens21") // configured, but no scope uses it

	out, err := RenderForParent(c, "ens21", "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("RenderForParent: %v", err)
	}
	if strings.Contains(out, "dhcp-range=") {
		t.Errorf("a parent with zero scopes must carry no dhcp-range content; got:\n%s", out)
	}
	if !strings.Contains(out, "listen-address=127.0.3.21") {
		t.Errorf("ens21 (third Worker) should still bind its own reserved address, 127.0.3.21; got:\n%s", out)
	}
	if !strings.Contains(out, "port=0") {
		t.Errorf("expected port=0 (nothing to serve yet); got:\n%s", out)
	}
}

// TestReservationsForParent_ScopedToThatParentOnly confirms reservations
// don't leak across trunks the way scope ranges/options already don't.
func TestReservationsForParent_ScopedToThatParentOnly(t *testing.T) {
	resA := ReservationsForParent(testCluster(), "ens19")
	foundA := false
	for _, r := range resA {
		if r.Hostname == "nas1" {
			foundA = true
		}
	}
	if !foundA {
		t.Errorf("expected office's own reservation (nas1) for ens19; got:\n%v", resA)
	}

	resB := ReservationsForParent(testCluster(), "ens20")
	for _, r := range resB {
		if r.Hostname == "nas1" {
			t.Errorf("office's reservation belongs to ens19, must not leak into ens20; got:\n%v", resB)
		}
	}
}

func TestRenderForParent_MatchesRenderForASingleTrunkCluster(t *testing.T) {
	c := config.Cluster{
		Platform: &config.Platform{Workers: []string{"ens19"}},
		Scopes: map[string]config.ScopeConfig{
			"office": testCluster().Scopes["office"],
		},
	}

	whole, err := Render(c, "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	perTrunk, err := RenderForParent(c, "ens19", "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("RenderForParent: %v", err)
	}
	if !strings.Contains(whole, "dhcp-range=set:office,") || !strings.Contains(perTrunk, "dhcp-range=set:office,") {
		t.Errorf("both renderers should include the single scope's own range:\nRender:\n%s\nRenderForParent:\n%s", whole, perTrunk)
	}
}
