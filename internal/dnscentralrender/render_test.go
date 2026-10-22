// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnscentralrender

import (
	"strings"
	"testing"

	"dnshived/internal/config"
)

func testCluster() config.Cluster {
	return config.Cluster{
		GlobalDNSRecords: []config.DNSRecord{
			{Name: "cluster.lan", Type: "A", Value: "192.0.2.230"},
		},
		Scopes: map[string]config.ScopeConfig{
			"office": {
				Parent: "ens19",
				VLANID: 42,
				DNSRecords: []config.DNSRecord{
					{Name: "printer.office.lan", Type: "A", Value: "192.168.10.50"},
				},
				Reservations: []config.Reservation{
					{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.10.60", Hostname: "nas1.office.lan"},
					{MAC: "aa:bb:cc:dd:ee:02", IP: "192.168.10.61"}, // no hostname -- must not appear
				},
			},
			"av-dante": {
				Parent: "ens20",
				VLANID: 100,
				Reservations: []config.Reservation{
					{MAC: "11:22:33:44:55:01", IP: "172.16.100.60", Hostname: "mixer1.dante.lan"},
				},
			},
		},
	}
}

func TestRenderInitial_EmptyAddressResolvesToDefault(t *testing.T) {
	out, err := RenderInitial("", []string{"1.1.1.1"})
	if err != nil {
		t.Fatalf("RenderInitial: %v", err)
	}
	if !strings.Contains(out, "listen-address="+DefaultAddress) {
		t.Errorf("expected listen-address=%s; got:\n%s", DefaultAddress, out)
	}
}

func TestRenderInitial_HonorsConfiguredAddress(t *testing.T) {
	out, err := RenderInitial("127.0.0.99", nil)
	if err != nil {
		t.Fatalf("RenderInitial: %v", err)
	}
	if !strings.Contains(out, "listen-address=127.0.0.99") {
		t.Errorf("expected configured address to be honored; got:\n%s", out)
	}
}

func TestRenderInitial_CarriesUpstreamServers(t *testing.T) {
	out, err := RenderInitial("", []string{"1.1.1.1", "9.9.9.9"})
	if err != nil {
		t.Fatalf("RenderInitial: %v", err)
	}
	if !strings.Contains(out, "server=1.1.1.1") || !strings.Contains(out, "server=9.9.9.9") {
		t.Errorf("expected both upstream server lines; got:\n%s", out)
	}
}

func TestRenderInitial_NoDynamicContent(t *testing.T) {
	out, err := RenderInitial("", []string{"1.1.1.1"})
	if err != nil {
		t.Fatalf("RenderInitial: %v", err)
	}
	for _, forbidden := range []string{"host-record=", "cname=", "addn-hosts="} {
		if strings.Contains(out, forbidden) {
			t.Errorf("RenderInitial must carry zero scope-derived content; found %q in:\n%s", forbidden, out)
		}
	}
}

func TestRender_IncludesEveryScopesDNSRecords(t *testing.T) {
	out, err := Render(testCluster(), "", "")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "host-record=printer.office.lan,192.168.10.50") {
		t.Errorf("missing office's own DNS record; got:\n%s", out)
	}
}

func TestRender_NamedReservationsBecomeARecords(t *testing.T) {
	out, err := Render(testCluster(), "", "")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "host-record=nas1.office.lan,192.168.10.60") {
		t.Errorf("office's named reservation missing; got:\n%s", out)
	}
	if !strings.Contains(out, "host-record=mixer1.dante.lan,172.16.100.60") {
		t.Errorf("av-dante's named reservation missing; got:\n%s", out)
	}
}

func TestRender_UnnamedReservationProducesNoRecord(t *testing.T) {
	out, err := Render(testCluster(), "", "")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(out, "192.168.10.61") {
		t.Errorf("a reservation with no hostname must not produce a DNS record; got:\n%s", out)
	}
}

func TestRender_GlobalRecordsIncludedExactlyOnce(t *testing.T) {
	out, err := Render(testCluster(), "", "")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if got := strings.Count(out, "host-record=cluster.lan,192.0.2.230"); got != 1 {
		t.Errorf("GlobalDNSRecords entry appeared %d times (across 2 scopes), want exactly 1", got)
	}
}

func TestRender_BoundToOwnLoopbackAliasOnly(t *testing.T) {
	out, err := Render(testCluster(), "", "")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{
		"listen-address=127.0.0.42",
		"bind-interfaces",
		"no-resolv",
		"user=dnshived",
		"group=dnshived",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "interface=") {
		t.Error("central DNS config must never bind a VLAN interface -- got an interface= line")
	}
	if strings.Contains(out, "dhcp-range") || strings.Contains(out, "dhcp-host") {
		t.Error("central DNS config must never carry DHCP directives -- DHCP stays per-scope/relayed")
	}
}

func TestRender_HonorsExplicitAddress(t *testing.T) {
	out, err := Render(testCluster(), "127.0.5.42", "")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "listen-address=127.0.5.42") {
		t.Errorf("expected the explicit address to be honored; got:\n%s", out)
	}
	if strings.Contains(out, "listen-address=127.0.0.42") {
		t.Error("must not ALSO still emit the hard-coded default address")
	}
}

func TestRender_UpstreamFromScopeDefaultsRenderedAsServerLines(t *testing.T) {
	c := testCluster()
	c.ScopeDefaults = &config.ScopeDefaults{Upstream: []string{"1.1.1.1", "9.9.9.9"}}

	out, err := Render(c, "", "")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "server=1.1.1.1") || !strings.Contains(out, "server=9.9.9.9") {
		t.Errorf("missing explicit server= lines for configured upstream; got:\n%s", out)
	}
	if !strings.Contains(out, "no-resolv") {
		t.Error("no-resolv must remain present even with an explicit upstream configured")
	}
}

func TestRender_NoUpstreamConfiguredProducesNoServerLines(t *testing.T) {
	out, err := Render(testCluster(), "", "") // testCluster sets no ScopeDefaults.Upstream
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(out, "server=") {
		t.Errorf("no upstream was configured; must not render any server= line; got:\n%s", out)
	}
}

func TestRender_EmptyClusterStillProducesValidPreamble(t *testing.T) {
	out, err := Render(config.Cluster{}, "", "")
	if err != nil {
		t.Fatalf("Render on empty cluster: %v", err)
	}
	if !strings.Contains(out, "listen-address=127.0.0.42") {
		t.Errorf("empty cluster should still render a valid preamble; got:\n%s", out)
	}
}

func TestRender_DeterministicAcrossCalls(t *testing.T) {
	c := testCluster()
	out1, err := Render(c, "", "")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	out2, err := Render(c, "", "")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if out1 != out2 {
		t.Errorf("two renders of the identical cluster produced different output:\n---1---\n%s\n---2---\n%s", out1, out2)
	}
}

// TestRender_QueryLoggingOffByDefaultNoLogDirectives pins
// Cluster.CoreDNSQueryLogging's own default-off doc comment.
func TestRender_QueryLoggingOffByDefaultNoLogDirectives(t *testing.T) {
	out, err := Render(testCluster(), "", "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(out, "log-queries") || strings.Contains(out, "log-facility") {
		t.Errorf("query logging is off by default, must not render log-queries/log-facility; got:\n%s", out)
	}
}

func TestRender_QueryLoggingOnEmitsLogQueriesAndFacilityFile(t *testing.T) {
	c := testCluster()
	c.CoreDNSQueryLogging = true
	out, err := Render(c, "", "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "log-queries") {
		t.Errorf("expected log-queries when CoreDNSQueryLogging is on; got:\n%s", out)
	}
	want := "log-facility=/var/lib/dnshived/" + CoreDNSLogFileName
	if !strings.Contains(out, want) {
		t.Errorf("expected %q; got:\n%s", want, out)
	}
}

func TestRender_AlwaysDeclaresAddnHosts(t *testing.T) {
	out, err := Render(testCluster(), "", "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	want := "addn-hosts=/var/lib/dnshived/" + DynamicHostsFileName
	if !strings.Contains(out, want) {
		t.Errorf("expected %q; got:\n%s", want, out)
	}
}

func TestRenderDynamicHosts_ProducesHostsFormatLine(t *testing.T) {
	out, err := RenderDynamicHosts([]DynamicHostEntry{{Hostname: "laptop1", IP: "10.0.0.5"}})
	if err != nil {
		t.Fatalf("RenderDynamicHosts: %v", err)
	}
	if !strings.Contains(out, "10.0.0.5 laptop1") {
		t.Errorf("expected an /etc/hosts-style \"<ip> <hostname>\" line; got:\n%s", out)
	}
}

func TestRenderDynamicHosts_EmptyStillValid(t *testing.T) {
	out, err := RenderDynamicHosts(nil)
	if err != nil {
		t.Fatalf("RenderDynamicHosts(nil): %v", err)
	}
	if !strings.Contains(out, "DO NOT EDIT") {
		t.Errorf("expected a valid header-only file even with zero entries; got:\n%s", out)
	}
}

func TestRenderDynamicHosts_DeterministicSortedByHostname(t *testing.T) {
	entries := []DynamicHostEntry{
		{Hostname: "zeta", IP: "10.0.0.9"},
		{Hostname: "alpha", IP: "10.0.0.1"},
	}
	out, err := RenderDynamicHosts(entries)
	if err != nil {
		t.Fatalf("RenderDynamicHosts: %v", err)
	}
	if strings.Index(out, "alpha") > strings.Index(out, "zeta") {
		t.Errorf("expected alpha before zeta (sorted by hostname); got:\n%s", out)
	}
}

func TestRender_IncludesLocalDomainRecords(t *testing.T) {
	c := testCluster()
	c.LocalDomains = []config.LocalDomain{
		{
			Name: "foo.lan",
			TTL:  3600,
			Records: []config.LocalDomainHost{
				{Host: "nas1", Type: "A", Value: "192.168.10.20"},
			},
		},
	}
	out, err := Render(c, "", "")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "host-record=nas1.foo.lan.,192.168.10.20,3600") {
		t.Errorf("rendered output missing the expanded local-domain host record, got:\n%s", out)
	}
}
