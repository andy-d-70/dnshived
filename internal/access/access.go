// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package access decides who the cluster serves. One list covers the DNS
// relay, the DHCP relay and the web interface: networks with allow or deny per
// service, whitelisted hosts, and the private networks allowed by default. The
// most specific network decides; on equal size deny wins.
package access

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
)

// Modes. An empty mode means report.
const (
	ModeReport  = "report"
	ModeEnforce = "enforce"
)

// Verdicts of one entry for one service. An empty verdict means allow.
const (
	Allow = "allow"
	Deny  = "deny"
)

type Service int

const (
	DNS Service = iota
	DHCP
	Web
	numServices
)

func (s Service) String() string {
	switch s {
	case DNS:
		return "dns"
	case DHCP:
		return "dhcp"
	case Web:
		return "web"
	}
	return "unknown"
}

// Limits keep a hostile or mistaken list from costing every packet.
const (
	MaxEntries = 1000
	MaxHosts   = 5000
	MaxBlocked = 5000
	MaxNote    = 200
)

type Entry struct {
	Net  string `json:"net,omitempty"`
	Note string `json:"note,omitempty"`
	Off  bool   `json:"off,omitempty"`
	DNS  string `json:"dns,omitempty"`
	DHCP string `json:"dhcp,omitempty"`
	Web  string `json:"web,omitempty"`
}

// Host is one whitelisted host. Addr serves DNS and the web interface, MAC
// serves DHCP (a DHCP client has no source address yet).
type Host struct {
	Addr string `json:"addr,omitempty"`
	MAC  string `json:"mac,omitempty"`
	Note string `json:"note,omitempty"`
	DNS  bool   `json:"dns,omitempty"`
	DHCP bool   `json:"dhcp,omitempty"`
	Web  bool   `json:"web,omitempty"`
}

// Block is one blocked client. Addr blocks DNS, MAC blocks DHCP.
type Block struct {
	Addr string `json:"addr,omitempty"`
	MAC  string `json:"mac,omitempty"`
	Note string `json:"note,omitempty"`
	DNS  bool   `json:"dns,omitempty"`
	DHCP bool   `json:"dhcp,omitempty"`
}

type Config struct {
	Mode string `json:"mode,omitempty"`
	// Private is the built-in entry for the private networks. Nil means on and
	// allowing every service. Only Off, the verdicts and the note are used.
	Private *Entry  `json:"private,omitempty"`
	Entries []Entry `json:"entries,omitempty"`
	Hosts   []Host  `json:"hosts,omitempty"`
	Blocked []Block `json:"blocked,omitempty"`
}

func (c *Config) Enforcing() bool { return c != nil && c.Mode == ModeEnforce }

var privateNets = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

func (c *Config) Validate() error {
	if c == nil {
		return nil
	}
	if c.Mode != "" && c.Mode != ModeReport && c.Mode != ModeEnforce {
		return fmt.Errorf("access: mode %q is not report or enforce", c.Mode)
	}
	if len(c.Entries) > MaxEntries {
		return fmt.Errorf("access: %d networks, at most %d", len(c.Entries), MaxEntries)
	}
	if len(c.Hosts) > MaxHosts {
		return fmt.Errorf("access: %d whitelisted hosts, at most %d", len(c.Hosts), MaxHosts)
	}
	if c.Private != nil {
		if err := checkVerdicts(*c.Private, "private networks"); err != nil {
			return err
		}
		if len(c.Private.Note) > MaxNote {
			return fmt.Errorf("access: the note of the private networks is longer than %d characters", MaxNote)
		}
	}
	if len(c.Blocked) > MaxBlocked {
		return fmt.Errorf("access: %d blocked clients, at most %d", len(c.Blocked), MaxBlocked)
	}
	if err := c.validateBlocked(); err != nil {
		return err
	}
	seen := make(map[netip.Prefix]bool, len(c.Entries))
	for i, e := range c.Entries {
		p, err := netip.ParsePrefix(strings.TrimSpace(e.Net))
		if err != nil {
			return fmt.Errorf("access: network %d (%q) is not a CIDR network: %w", i+1, e.Net, err)
		}
		p = p.Masked()
		if seen[p] {
			return fmt.Errorf("access: network %s is listed twice", p)
		}
		seen[p] = true
		if err := checkVerdicts(e, p.String()); err != nil {
			return err
		}
		if len(e.Note) > MaxNote {
			return fmt.Errorf("access: the note of %s is longer than %d characters", p, MaxNote)
		}
	}
	addrs := map[netip.Addr]bool{}
	macs := map[[6]byte]bool{}
	for i, h := range c.Hosts {
		if h.Addr == "" && h.MAC == "" {
			return fmt.Errorf("access: whitelisted host %d has neither an address nor a MAC", i+1)
		}
		if len(h.Note) > MaxNote {
			return fmt.Errorf("access: the note of whitelisted host %d is longer than %d characters", i+1, MaxNote)
		}
		if !h.DNS && !h.DHCP && !h.Web {
			return fmt.Errorf("access: whitelisted host %d is allowed for no service", i+1)
		}
		if h.Addr != "" {
			a, err := netip.ParseAddr(strings.TrimSpace(h.Addr))
			if err != nil {
				return fmt.Errorf("access: whitelisted host %d (%q) has no valid address: %w", i+1, h.Addr, err)
			}
			a = a.Unmap()
			if addrs[a] {
				return fmt.Errorf("access: address %s is whitelisted twice", a)
			}
			addrs[a] = true
		}
		if h.MAC != "" {
			m, err := ParseMAC(h.MAC)
			if err != nil {
				return fmt.Errorf("access: whitelisted host %d: %w", i+1, err)
			}
			if macs[m] {
				return fmt.Errorf("access: MAC %s is whitelisted twice", h.MAC)
			}
			macs[m] = true
		}
		if h.DHCP && h.MAC == "" {
			return fmt.Errorf("access: whitelisted host %d is allowed for DHCP but has no MAC (DHCP matches by MAC)", i+1)
		}
		if (h.DNS || h.Web) && h.Addr == "" {
			return fmt.Errorf("access: whitelisted host %d is allowed for DNS or the web interface but has no address", i+1)
		}
	}
	return nil
}

func (c *Config) validateBlocked() error {
	addrs := map[netip.Addr]bool{}
	macs := map[[6]byte]bool{}
	for i, b := range c.Blocked {
		if len(b.Note) > MaxNote {
			return fmt.Errorf("access: the note of blocked client %d is longer than %d characters", i+1, MaxNote)
		}
		if !b.DNS && !b.DHCP {
			return fmt.Errorf("access: blocked client %d is blocked for no service", i+1)
		}
		if b.DNS {
			a, err := netip.ParseAddr(strings.TrimSpace(b.Addr))
			if err != nil {
				return fmt.Errorf("access: blocked client %d is blocked for DNS but has no valid address", i+1)
			}
			a = a.Unmap()
			if addrs[a] {
				return fmt.Errorf("access: address %s is blocked twice", a)
			}
			addrs[a] = true
		}
		if b.DHCP {
			m, err := ParseMAC(b.MAC)
			if err != nil {
				return fmt.Errorf("access: blocked client %d is blocked for DHCP: %w", i+1, err)
			}
			if macs[m] {
				return fmt.Errorf("access: MAC %s is blocked twice", b.MAC)
			}
			macs[m] = true
		}
	}
	return nil
}

func checkVerdicts(e Entry, what string) error {
	for _, v := range []string{e.DNS, e.DHCP, e.Web} {
		if v != "" && v != Allow && v != Deny {
			return fmt.Errorf("access: %s: %q is not allow or deny", what, v)
		}
	}
	return nil
}

func ParseMAC(s string) ([6]byte, error) {
	var out [6]byte
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil || len(hw) != 6 {
		return out, fmt.Errorf("%q is not a MAC address like 00:11:22:33:44:55", s)
	}
	copy(out[:], hw)
	return out, nil
}

type Decision struct {
	Allowed bool
	Rule    string
	// Blocked marks a drop by a blocked client, which applies in every mode.
	Blocked bool
}

type rule struct {
	prefix netip.Prefix
	bits   int
	allow  bool
	label  string
}

// Matcher is a compiled list. It is safe for concurrent use. A nil Matcher
// allows everything.
type Matcher struct {
	enforce   bool
	rules     [numServices][]rule
	hosts     [numServices]map[netip.Addr]struct{}
	macs      map[[6]byte]struct{}
	blocked   [numServices]map[netip.Addr]struct{}
	blockMACs map[[6]byte]struct{}
	always    map[netip.Addr]struct{}
}

// New compiles c. always lists addresses that are served no matter what
// (the cluster's own nodes and VIPs); loopback is always allowed as well.
func New(c *Config, always []netip.Addr) (*Matcher, error) {
	if c == nil {
		return nil, nil
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	m := &Matcher{enforce: c.Enforcing(), macs: map[[6]byte]struct{}{}, blockMACs: map[[6]byte]struct{}{}, always: map[netip.Addr]struct{}{}}
	for s := range m.hosts {
		m.hosts[s] = map[netip.Addr]struct{}{}
		m.blocked[s] = map[netip.Addr]struct{}{}
	}
	for _, b := range c.Blocked {
		if b.DNS {
			m.blocked[DNS][netip.MustParseAddr(strings.TrimSpace(b.Addr)).Unmap()] = struct{}{}
		}
		if b.DHCP {
			mac, _ := ParseMAC(b.MAC)
			m.blockMACs[mac] = struct{}{}
		}
	}
	for _, a := range always {
		m.always[a.Unmap()] = struct{}{}
	}
	verdict := func(v string) bool { return v != Deny }
	priv := Entry{}
	if c.Private != nil {
		priv = *c.Private
	}
	add := func(p netip.Prefix, label string, e Entry) {
		vs := [numServices]bool{verdict(e.DNS), verdict(e.DHCP), verdict(e.Web)}
		for s := Service(0); s < numServices; s++ {
			m.rules[s] = append(m.rules[s], rule{prefix: p, bits: p.Bits(), allow: vs[s], label: label})
		}
	}
	if !priv.Off {
		for _, p := range privateNets {
			add(p, "private networks", priv)
		}
	}
	for _, e := range c.Entries {
		if e.Off {
			continue
		}
		p := netip.MustParsePrefix(strings.TrimSpace(e.Net)).Masked()
		add(p, p.String(), e)
	}
	for s := range m.rules {
		rs := m.rules[s]
		sort.SliceStable(rs, func(i, j int) bool {
			if rs[i].bits != rs[j].bits {
				return rs[i].bits > rs[j].bits
			}
			return !rs[i].allow && rs[j].allow
		})
	}
	for _, h := range c.Hosts {
		if h.Addr != "" {
			a := netip.MustParseAddr(strings.TrimSpace(h.Addr)).Unmap()
			if h.DNS {
				m.hosts[DNS][a] = struct{}{}
			}
			if h.Web {
				m.hosts[Web][a] = struct{}{}
			}
			if h.DHCP {
				m.hosts[DHCP][a] = struct{}{}
			}
		}
		if h.MAC != "" && h.DHCP {
			mac, _ := ParseMAC(h.MAC)
			m.macs[mac] = struct{}{}
		}
	}
	return m, nil
}

func (m *Matcher) Enforcing() bool { return m != nil && m.enforce }

// Check answers whether addr is served for svc. The answer says what the list
// decides; whether to drop is up to the caller (see Enforcing).
func (m *Matcher) Check(svc Service, addr netip.Addr) Decision {
	if m == nil {
		return Decision{Allowed: true, Rule: "no list"}
	}
	addr = addr.Unmap()
	if addr.IsLoopback() {
		return Decision{Allowed: true, Rule: "always: loopback"}
	}
	if _, ok := m.always[addr]; ok {
		return Decision{Allowed: true, Rule: "always: node or VIP"}
	}
	if svc < 0 || svc >= numServices {
		return Decision{Allowed: false, Rule: "none"}
	}
	if _, ok := m.blocked[svc][addr]; ok {
		return Decision{Allowed: false, Rule: "blocked client", Blocked: true}
	}
	if _, ok := m.hosts[svc][addr]; ok {
		return Decision{Allowed: true, Rule: "host"}
	}
	for _, r := range m.rules[svc] {
		if r.prefix.Contains(addr) {
			if r.allow {
				return Decision{Allowed: true, Rule: r.label}
			}
			return Decision{Allowed: false, Rule: "deny " + r.label}
		}
	}
	return Decision{Allowed: false, Rule: "none"}
}

func (m *Matcher) CheckMAC(mac [6]byte) bool {
	if m == nil {
		return false
	}
	_, ok := m.macs[mac]
	return ok
}

// BlockedMAC reports whether the DHCP client with this MAC is blocked.
func (m *Matcher) BlockedMAC(mac [6]byte) bool {
	if m == nil {
		return false
	}
	_, ok := m.blockMACs[mac]
	return ok
}
