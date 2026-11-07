// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package preflight

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"dnshived/internal/config"
)

func fullScope() config.ScopeConfig {
	return config.ScopeConfig{
		Parent: "ens19", VLANID: 10, VRRPID: 10, PreferredWorker: config.RoleCore1,
		VIP: "192.168.10.254/24", NodeIP: "192.168.10.21/24",
		NodeIPOverrides: map[string]string{"core-2": "192.168.10.22/24"},
		DHCPRange:       [2]string{"192.168.10.100", "192.168.10.200"},
		Gateway:         "192.168.10.1", ClientDNSServer: "192.168.10.254",
		Reservations: []config.Reservation{{MAC: "aa:bb:cc:00:00:01", IP: "192.168.10.50"}, {MAC: "aa:bb:cc:00:00:02", IP: "10.9.9.9"}},
		DNSRecords: []config.DNSRecord{
			{Name: "nas.lan.", Type: "A", Value: "192.168.10.60"},
			{Name: "txt.lan.", Type: "TXT", Value: "gateway 192.168.10.1 and 8.8.8.8"},
		},
		DHCPOptions: []string{"option:ntp-server,192.168.10.254", "option:domain-name,lan"},
	}
}

func TestRemap_MovesEveryAddressInTheNetwork(t *testing.T) {
	in := fullScope()
	out, rep, err := Remap(in, netip.MustParsePrefix("192.168.77.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string][2]string{
		"vip":      {out.VIP, "192.168.77.254/24"},
		"node_ip":  {out.NodeIP, "192.168.77.21/24"},
		"override": {out.NodeIPOverrides["core-2"], "192.168.77.22/24"},
		"start":    {out.DHCPRange[0], "192.168.77.100"},
		"end":      {out.DHCPRange[1], "192.168.77.200"},
		"gateway":  {out.Gateway, "192.168.77.1"},
		"dns":      {out.ClientDNSServer, "192.168.77.254"},
		"res 1":    {out.Reservations[0].IP, "192.168.77.50"},
		"A record": {out.DNSRecords[0].Value, "192.168.77.60"},
		"option":   {out.DHCPOptions[0], "option:ntp-server,192.168.77.254"},
	}
	for name, c := range checks {
		if c[0] != c[1] {
			t.Errorf("%s = %q, want %q", name, c[0], c[1])
		}
	}
	if out.Reservations[1].IP != "10.9.9.9" {
		t.Error("an address outside the old network must stay")
	}
	if out.DNSRecords[1].Value != "gateway 192.168.77.1 and 8.8.8.8" {
		t.Errorf("free text = %q: only exact addresses inside the old network change", out.DNSRecords[1].Value)
	}
	if out.DHCPOptions[1] != "option:domain-name,lan" {
		t.Error("an option without an address changed")
	}
	if in.VIP != "192.168.10.254/24" || in.NodeIPOverrides["core-2"] != "192.168.10.22/24" || in.Reservations[0].IP != "192.168.10.50" || in.DNSRecords[0].Value != "192.168.10.60" {
		t.Error("the input scope was modified")
	}
	keptJoined := strings.Join(rep.Kept, "|")
	if !strings.Contains(keptJoined, "10.9.9.9") || !strings.Contains(keptJoined, "8.8.8.8") {
		t.Errorf("kept = %v: addresses left alone must be listed", rep.Kept)
	}
	if len(rep.Flagged) != 2 {
		t.Errorf("flagged = %v: the TXT record and the ntp option are free text", rep.Flagged)
	}
	if len(rep.Changed) < 10 {
		t.Errorf("changed = %v", rep.Changed)
	}
}

func TestRemap_ResultChecksCleanAgainstTheOriginal(t *testing.T) {
	ctx := baseCtx()
	in := fullScope()
	in.VLANID, in.VRRPID = 33, 33
	if r := Check(ctx, map[string]config.ScopeConfig{"copy": in})[0]; r.Verdict != VerdictConflicts {
		t.Fatalf("setup: the copy must clash before the remap, got %s", r.Verdict)
	}
	out, _, err := Remap(in, netip.MustParsePrefix("192.168.33.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	r := Check(ctx, map[string]config.ScopeConfig{"copy": out})[0]
	for _, c := range r.Collisions {
		if c.Severity == SevError {
			t.Errorf("a remapped copy still has an error: %+v", c)
		}
	}
}

func TestRemap_Refusals(t *testing.T) {
	tests := []struct {
		name string
		sc   func() config.ScopeConfig
		to   string
		want string
	}{
		{"different prefix length", fullScope, "192.168.77.0/25", "same prefix length"},
		{"same network", fullScope, "192.168.10.0/24", "current network"},
		{"ipv6 target", fullScope, "fd00::/24", "IPv4"},
		{"bad vip", func() config.ScopeConfig { s := fullScope(); s.VIP = "x"; return s }, "192.168.77.0/24", "not an IPv4"},
		{"host part becomes the network address", func() config.ScopeConfig {
			s := fullScope()
			s.Gateway = "192.168.10.0"
			return s
		}, "192.168.77.0/24", "network or broadcast"},
		{"host part becomes the broadcast address", func() config.ScopeConfig {
			s := fullScope()
			s.DHCPRange[1] = "192.168.10.255"
			return s
		}, "192.168.77.0/24", "network or broadcast"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := tt.sc()
			before := sc
			out, _, err := Remap(sc, netip.MustParsePrefix(tt.to))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.want)
			}
			if !reflect.DeepEqual(out, before) {
				t.Error("a refused remap must return the scope unchanged")
			}
		})
	}
}

func TestRemap_SmallNetworksKeepTheirEdges(t *testing.T) {
	sc := config.ScopeConfig{VIP: "192.168.10.1/31", Gateway: "192.168.10.0"}
	out, _, err := Remap(sc, netip.MustParsePrefix("192.168.20.0/31"))
	if err != nil || out.VIP != "192.168.20.1/31" || out.Gateway != "192.168.20.0" {
		t.Errorf("a /31 has no network/broadcast address: %+v %v", out, err)
	}
}

func TestRemap_ScopeWithoutOptionalFields(t *testing.T) {
	sc := config.ScopeConfig{VIP: "10.1.2.254/24", DHCPRange: [2]string{"10.1.2.10", "10.1.2.20"}}
	out, rep, err := Remap(sc, netip.MustParsePrefix("10.9.9.0/24"))
	if err != nil || out.VIP != "10.9.9.254/24" || out.DHCPRange != [2]string{"10.9.9.10", "10.9.9.20"} || out.NodeIPOverrides != nil || out.Reservations != nil {
		t.Errorf("%+v %v", out, err)
	}
	if len(rep.Flagged) != 0 {
		t.Errorf("flagged = %v", rep.Flagged)
	}
}
