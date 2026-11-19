// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"strings"
	"testing"

	"dnshived/internal/config"
)

func simCluster() config.Cluster {
	return config.Cluster{
		DefaultDHCPOptions: []string{"option:42,192.0.2.1"},
		GlobalDNSRecords:   []config.DNSRecord{{Name: "_dante-ddm-c._tcp.lan.", Type: "SRV", Target: "ddm.lan.", Port: 8443, Priority: 0, Weight: 0}, {Name: "plain.lan.", Type: "A", Value: "192.0.2.9"}},
		Scopes: map[string]config.ScopeConfig{
			"office": {VIP: "192.168.2.254/24", NodeIP: "192.168.2.22/24", Gateway: "192.168.2.1", DHCPRange: [2]string{"192.168.2.200", "192.168.2.250"},
				Reservations: []config.Reservation{{MAC: "aa:bb:cc:00:00:01", IP: "192.168.2.50", Hostname: "mixer", Names: []string{"mixer-ctl"}}},
				DNSRecords:   []config.DNSRecord{{Name: "_nmos-register._tcp.lan.", Type: "SRV", Target: "reg.lan.", Port: 80}}},
			"av":     {VIP: "172.16.9.254/24", NodeIP: "172.16.9.22/24", Gateway: "172.16.9.1", DHCPRange: [2]string{"172.16.9.100", "172.16.9.200"}, DHCPLeaseTime: "2h"},
			"broken": {VIP: "10.9.0.254/24"},
		},
	}
}

func TestResolveClient(t *testing.T) {
	rows := []hostRow{{MAC: "aa:bb:cc:00:00:01", IP: "192.168.2.50", Name: "mixer", Scope: "office", Reserved: true}, {MAC: "aa:bb:cc:00:00:02", IP: "192.168.2.201", Name: "mixer-two", Scope: "office"}}
	if c, note, ok := resolveClient("AA-BB-CC-00-00-01", rows); !ok || c.MAC != "aa:bb:cc:00:00:01" || c.Scope != "office" || note != "" {
		t.Errorf("a typed MAC finds the host: %+v %q", c, note)
	}
	if c, _, ok := resolveClient("11:22:33:44:55:66", rows); !ok || c.Known || c.MAC != "11:22:33:44:55:66" {
		t.Errorf("an unknown MAC is still simulated: %+v", c)
	}
	if c, note, _ := resolveClient("mixer", rows); c.MAC == "" || !strings.Contains(note, "2 clients match") {
		t.Errorf("an ambiguous search says so: %+v %q", c, note)
	}
	if c, note, _ := resolveClient("nothing", rows); c.MAC != "" || !strings.Contains(note, "no known client") {
		t.Errorf("no match: %+v %q", c, note)
	}
	if _, _, ok := resolveClient("  ", rows); ok {
		t.Error("an empty slot is skipped")
	}
}

func TestSimulate_ReservedClientGetsItsAddressAndNames(t *testing.T) {
	got := simulate(simCluster(), "office", simClient{MAC: "aa:bb:cc:00:00:01", Known: true}, nil)
	if got.Address != "192.168.2.50" || got.AddressHow != "reserved" || got.Mask != "255.255.255.0" || got.Gateway != "192.168.2.1" || got.Server != "192.168.2.254" {
		t.Errorf("result = %+v", got)
	}
	if len(got.Names) != 2 || got.Names[0] != "mixer" || got.Names[1] != "mixer-ctl" {
		t.Errorf("names = %v", got.Names)
	}
	if len(got.Records) != 2 || got.Records[0].Name != "_nmos-register._tcp.lan." || got.Records[1].Data != "0 0 8443 ddm.lan." {
		t.Errorf("only the underscore service records show, the scope's first: %+v", got.Records)
	}
	if len(got.Options) != 1 {
		t.Errorf("cluster default options apply: %v", got.Options)
	}
}

func TestSimulate_RoamingIntoAnotherNetworkIgnoresTheReservation(t *testing.T) {
	got := simulate(simCluster(), "av", simClient{MAC: "aa:bb:cc:00:00:01", Known: true}, nil)
	if got.AddressHow != "from the pool" || got.Address != "172.16.9.100 – 172.16.9.200" || got.Lease != "2h" {
		t.Errorf("result = %+v", got)
	}
	if len(got.Notes) != 1 || !strings.Contains(got.Notes[0], "another network") || len(got.Names) != 0 {
		t.Errorf("a reservation for another network is explained and not published here: %+v", got)
	}
}

func TestSimulate_CurrentLeaseAndSentName(t *testing.T) {
	rows := []hostRow{{MAC: "aa:bb:cc:00:00:07", IP: "192.168.2.210", Scope: "office"}}
	got := simulate(simCluster(), "office", simClient{MAC: "aa:bb:cc:00:00:07", Name: "laptop", Known: true}, rows)
	if got.AddressHow != "current lease" || got.Address != "192.168.2.210" {
		t.Errorf("result = %+v", got)
	}
	if len(got.Names) != 1 || !strings.Contains(got.Names[0], "laptop") {
		t.Errorf("a dynamic client is published under the name it sends: %v", got.Names)
	}
}

func TestSimulate_IncompleteAndDisabledScopes(t *testing.T) {
	if got := simulate(simCluster(), "broken", simClient{MAC: "aa:bb:cc:00:00:07"}, nil); got.Error == "" {
		t.Error("an incomplete scope cannot be simulated")
	}
	cl := simCluster()
	sc := cl.Scopes["office"]
	sc.DNSMasqDisabled = true
	cl.Scopes["office"] = sc
	if got := simulate(cl, "office", simClient{MAC: "aa:bb:cc:00:00:07"}, nil); len(got.Notes) == 0 || !strings.Contains(got.Notes[0], "switched off") {
		t.Errorf("a switched-off scope is flagged: %+v", got.Notes)
	}
}

func TestRunSimulation_CompareSameClientInTwoScopes(t *testing.T) {
	hosts := []hostRow{{MAC: "aa:bb:cc:00:00:01", IP: "192.168.2.50", Name: "mixer", Scope: "office", Reserved: true}}
	rows, heads, _ := runSimulation(simCluster(), hosts, []simSlotForm{{N: 1, Client: "aa:bb:cc:00:00:01"}, {N: 2, Client: "aa:bb:cc:00:00:01", Scope: "av"}, {N: 3}})
	if len(heads) != 2 || len(rows) == 0 || len(rows[0].Cells) != 2 {
		t.Fatalf("two filled slots make two columns: heads=%v rows=%d", heads, len(rows))
	}
	var addr simRow
	for _, r := range rows {
		if r.Label == "Address" {
			addr = r
		}
	}
	if addr.Cells[0].Lines[0] != "192.168.2.50" || addr.Cells[1].Lines[1] != "from the pool" {
		t.Errorf("the same client differs per scope: %+v", addr)
	}
}

func TestSimulatorTmpl_RendersAndEscapes(t *testing.T) {
	var b strings.Builder
	rows, heads, notes := runSimulation(simCluster(), nil, []simSlotForm{{N: 1, Client: "aa:bb:cc:00:00:01", Scope: "office"}})
	err := simulatorTmpl.Execute(&b, simulatorPageData{Slots: simulatorSlotsFrom(map[string][]string{"c1": {`"><b>x</b>`}}), Scopes: []string{"office", "av"}, Rows: rows, Heads: heads, Notes: notes})
	if err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, "<b>x</b>") || !strings.Contains(out, "192.168.2.50") || !strings.Contains(out, `name="s1"`) {
		t.Error("the page renders the result and escapes the typed text")
	}
}
