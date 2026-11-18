// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package access

import (
	"bytes"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestMatcher_Check(t *testing.T) {
	cfg := &Config{
		Mode: ModeEnforce,
		Entries: []Entry{
			{Net: "198.51.100.0/24", Note: "scope"},
			{Net: "100.64.0.0/10", DHCP: Deny, Web: Deny},
			{Net: "10.5.0.0/16", DHCP: Deny},
			{Net: "10.6.0.0/16", Off: true, DNS: Deny},
			{Net: "2001:db8::/32"},
			{Net: "192.0.2.0/24", DNS: Deny},
			{Net: "192.0.2.0/25", DNS: Allow},
		},
		Hosts: []Host{
			{Addr: "172.32.0.5", DNS: true},
			{MAC: "00:11:22:33:44:55", DHCP: true},
			{Addr: "10.5.9.9", DHCP: true, MAC: "aa:bb:cc:dd:ee:ff"},
		},
	}
	m, err := New(cfg, []netip.Addr{addr("192.0.2.22")})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		svc     Service
		src     string
		allowed bool
		rule    string
	}{
		{"private allowed by default", DNS, "192.168.1.5", true, "private networks"},
		{"private ipv6 ula", Web, "fd00::1", true, "private networks"},
		{"public dropped", DNS, "8.8.8.8", false, "none"},
		{"seeded scope network", DHCP, "198.51.100.9", true, "198.51.100.0/24"},
		{"deny per service, other service allowed", DNS, "100.64.1.1", true, "100.64.0.0/10"},
		{"deny dhcp", DHCP, "100.64.1.1", false, "deny 100.64.0.0/10"},
		{"deny web", Web, "100.64.1.1", false, "deny 100.64.0.0/10"},
		{"most specific deny beats wider allow", DHCP, "10.5.1.1", false, "deny 10.5.0.0/16"},
		{"the entry allows dns where it denies dhcp", DNS, "10.5.1.1", true, "10.5.0.0/16"},
		{"switched off entry is ignored", DNS, "10.6.1.1", true, "private networks"},
		{"ipv6 entry", DNS, "2001:db8::5", true, "2001:db8::/32"},
		{"mapped ipv4 is unmapped", DNS, "::ffff:198.51.100.9", true, "198.51.100.0/24"},
		{"smaller allow beats wider deny", DNS, "192.0.2.50", true, "192.0.2.0/25"},
		{"wider deny outside the smaller allow", DNS, "192.0.2.200", false, "deny 192.0.2.0/24"},
		{"whitelisted host outside every network", DNS, "172.32.0.5", true, "host"},
		{"whitelisted for dns only, web dropped", Web, "172.32.0.5", false, "none"},
		{"whitelist beats a deny", DHCP, "10.5.9.9", true, "host"},
		{"always allowed node", Web, "192.0.2.22", true, "always: node or VIP"},
		{"loopback", DNS, "127.0.0.1", true, "always: loopback"},
		{"loopback ipv6", Web, "::1", true, "always: loopback"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := m.Check(tt.svc, addr(tt.src))
			if d.Allowed != tt.allowed || d.Rule != tt.rule {
				t.Errorf("Check(%s, %s) = %+v, want allowed=%v rule=%q", tt.svc, tt.src, d, tt.allowed, tt.rule)
			}
		})
	}
	if !m.CheckMAC([6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) {
		t.Error("the whitelisted MAC must be allowed for DHCP")
	}
	if m.CheckMAC([6]byte{1, 2, 3, 4, 5, 6}) {
		t.Error("an unknown MAC must not be whitelisted")
	}
	if !m.Enforcing() {
		t.Error("mode enforce must enforce")
	}
}

func TestMatcher_PrivateNetworksSwitchedOffOrDenied(t *testing.T) {
	m, err := New(&Config{Mode: ModeEnforce, Private: &Entry{Off: true}, Entries: []Entry{{Net: "203.0.113.0/24"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Check(DNS, addr("192.168.1.1")).Allowed {
		t.Error("private networks switched off must not be allowed")
	}
	if !m.Check(DNS, addr("203.0.113.5")).Allowed {
		t.Error("the listed network must be allowed")
	}
	m2, _ := New(&Config{Private: &Entry{DHCP: Deny}}, nil)
	if m2.Check(DHCP, addr("10.1.1.1")).Allowed || !m2.Check(DNS, addr("10.1.1.1")).Allowed {
		t.Error("private networks denied for DHCP only")
	}
	if m2.Enforcing() {
		t.Error("an empty mode is report, not enforce")
	}
}

func TestMatcher_NilAllowsEverything(t *testing.T) {
	var m *Matcher
	if !m.Check(DNS, addr("8.8.8.8")).Allowed || m.Enforcing() || m.CheckMAC([6]byte{}) {
		t.Error("a nil matcher must allow everything and not enforce")
	}
	m2, err := New(nil, nil)
	if err != nil || m2 != nil {
		t.Errorf("New(nil) = %v, %v; want nil, nil", m2, err)
	}
}

func TestConfig_Validate(t *testing.T) {
	long := strings.Repeat("x", MaxNote+1)
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{"ok", Config{Mode: ModeReport, Entries: []Entry{{Net: "10.0.0.0/8"}}}, ""},
		{"bad mode", Config{Mode: "loud"}, "mode"},
		{"not a cidr", Config{Entries: []Entry{{Net: "10.0.0.1"}}}, "CIDR"},
		{"duplicate network", Config{Entries: []Entry{{Net: "10.0.0.0/8"}, {Net: "10.1.2.3/8"}}}, "twice"},
		{"bad verdict", Config{Entries: []Entry{{Net: "10.0.0.0/8", DNS: "maybe"}}}, "allow or deny"},
		{"long note", Config{Entries: []Entry{{Net: "10.0.0.0/8", Note: long}}}, "longer"},
		{"host without anything", Config{Hosts: []Host{{DNS: true}}}, "neither"},
		{"host bad address", Config{Hosts: []Host{{Addr: "nope", DNS: true}}}, "address"},
		{"host bad mac", Config{Hosts: []Host{{MAC: "zz", DHCP: true}}}, "MAC"},
		{"host eui-64 mac refused", Config{Hosts: []Host{{MAC: "00:11:22:33:44:55:66:77", DHCP: true}}}, "MAC"},
		{"host no service", Config{Hosts: []Host{{Addr: "10.0.0.1"}}}, "no service"},
		{"dhcp host needs a mac", Config{Hosts: []Host{{Addr: "10.0.0.1", DHCP: true}}}, "no MAC"},
		{"dns host needs an address", Config{Hosts: []Host{{MAC: "00:11:22:33:44:55", DNS: true}}}, "no address"},
		{"duplicate host address", Config{Hosts: []Host{{Addr: "10.0.0.1", DNS: true}, {Addr: "::ffff:10.0.0.1", DNS: true}}}, "twice"},
		{"duplicate host mac", Config{Hosts: []Host{{MAC: "00:11:22:33:44:55", DHCP: true}, {MAC: "00-11-22-33-44-55", DHCP: true}}}, "twice"},
		{"private verdict", Config{Private: &Entry{Web: "x"}}, "allow or deny"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want one containing %q", err, tt.want)
			}
		})
	}
	big := Config{}
	for i := 0; i <= MaxEntries; i++ {
		big.Entries = append(big.Entries, Entry{Net: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24).String()})
	}
	if err := big.Validate(); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("a list over the limit must be refused, got %v", err)
	}
	var nilCfg *Config
	if err := nilCfg.Validate(); err != nil || nilCfg.Enforcing() {
		t.Error("a nil config is valid and does not enforce")
	}
}

func BenchmarkMatcher_Check(b *testing.B) {
	cfg := &Config{Mode: ModeEnforce}
	for i := 0; i < 200; i++ {
		cfg.Entries = append(cfg.Entries, Entry{Net: netip.PrefixFrom(netip.AddrFrom4([4]byte{100, byte(i), 0, 0}), 16).String()})
	}
	m, err := New(cfg, nil)
	if err != nil {
		b.Fatal(err)
	}
	a := addr("8.8.8.8")
	for b.Loop() {
		m.Check(DNS, a)
	}
}

func TestCopyInDNSRelayIsIdentical(t *testing.T) {
	for _, name := range []string{"access.go", "report.go"} {
		want, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile("../../cmd/dnshived-dnsrelay/access/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, got) {
			t.Errorf("cmd/dnshived-dnsrelay/access/%s differs from internal/access/%s; copy the file again (the relay is its own module)", name, name)
		}
	}
}
