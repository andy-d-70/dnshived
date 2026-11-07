// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package preflight

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"dnshived/internal/config"
)

// RemapReport lists what Remap did, for the preview.
type RemapReport struct {
	// Changed are the addresses that moved, as "field: old -> new".
	Changed []string `json:"changed,omitempty"`
	// Kept are addresses outside the old network; they stay as they are.
	Kept []string `json:"kept,omitempty"`
	// Flagged are free-text values where an exact address was replaced; the
	// operator should read them.
	Flagged []string `json:"flagged,omitempty"`
}

// Remap moves a scope to another network of the same size: the network part
// of every address inside the scope's current network is swapped and the host
// part is kept. It fails when the prefix lengths differ or an address would
// land on the new network or broadcast address. The input is not modified.
func Remap(sc config.ScopeConfig, to netip.Prefix) (config.ScopeConfig, RemapReport, error) {
	var rep RemapReport
	old := parseVIP(sc.VIP)
	if !old.ok {
		return sc, rep, fmt.Errorf("the scope's vip %q is not an IPv4 address with a prefix length", sc.VIP)
	}
	if !to.Addr().Is4() {
		return sc, rep, errors.New("remap supports IPv4 networks only")
	}
	if to.Bits() != old.subnet.Bits() {
		return sc, rep, fmt.Errorf("the new network %s must have the same prefix length as %s", to.Masked(), old.subnet)
	}
	dst := to.Masked()
	if dst == old.subnet {
		return sc, rep, errors.New("the new network is the scope's current network")
	}

	var errs []string
	mapAddr := func(field string, a netip.Addr) (netip.Addr, bool) {
		if !old.subnet.Contains(a) {
			rep.Kept = append(rep.Kept, fmt.Sprintf("%s: %s", field, a))
			return a, false
		}
		hostBits := 32 - old.subnet.Bits()
		host := toU32(a) & (uint32(1)<<uint(hostBits) - 1)
		n := fromU32(toU32(dst.Addr()) | host)
		if dst.Bits() < 31 && (n == dst.Addr() || n == broadcast(dst)) {
			errs = append(errs, fmt.Sprintf("%s: %s would become %s, the network or broadcast address of %s", field, a, n, dst))
			return a, false
		}
		rep.Changed = append(rep.Changed, fmt.Sprintf("%s: %s -> %s", field, a, n))
		return n, true
	}
	mapPlain := func(field, v string) string {
		if v == "" {
			return v
		}
		a, err := netip.ParseAddr(v)
		if err != nil || !a.Is4() {
			return v
		}
		n, _ := mapAddr(field, a)
		return n.String()
	}
	mapPrefixed := func(field, v string) string {
		if v == "" {
			return v
		}
		p, err := netip.ParsePrefix(v)
		if err != nil || !p.Addr().Is4() {
			return v
		}
		n, _ := mapAddr(field, p.Addr())
		return netip.PrefixFrom(n, p.Bits()).String()
	}

	out := sc
	out.VIP = mapPrefixed("vip", sc.VIP)
	out.NodeIP = mapPrefixed("node_ip", sc.NodeIP)
	if len(sc.NodeIPOverrides) > 0 {
		out.NodeIPOverrides = make(map[string]string, len(sc.NodeIPOverrides))
		roles := make([]string, 0, len(sc.NodeIPOverrides))
		for r := range sc.NodeIPOverrides {
			roles = append(roles, r)
		}
		sort.Strings(roles)
		for _, r := range roles {
			out.NodeIPOverrides[r] = mapPrefixed("node_ip_overrides["+r+"]", sc.NodeIPOverrides[r])
		}
	}
	out.DHCPRange = [2]string{mapPlain("dhcp_range start", sc.DHCPRange[0]), mapPlain("dhcp_range end", sc.DHCPRange[1])}
	out.Gateway = mapPlain("gateway", sc.Gateway)
	out.ClientDNSServer = mapPlain("client_dns_server", sc.ClientDNSServer)
	if len(sc.Reservations) > 0 {
		out.Reservations = make([]config.Reservation, len(sc.Reservations))
		for i, r := range sc.Reservations {
			r.IP = mapPlain(fmt.Sprintf("reservation %d (%s)", i+1, r.MAC), r.IP)
			out.Reservations[i] = r
		}
	}
	if len(sc.DNSRecords) > 0 {
		out.DNSRecords = make([]config.DNSRecord, len(sc.DNSRecords))
		for i, r := range sc.DNSRecords {
			label := fmt.Sprintf("dns record %d (%s %s)", i+1, r.Type, r.Name)
			switch strings.ToUpper(r.Type) {
			case "A":
				r.Value = mapPlain(label, r.Value)
			default:
				r.Value = replaceExact(r.Value, label, mapAddr, &rep)
			}
			out.DNSRecords[i] = r
		}
	}
	if len(sc.DHCPOptions) > 0 {
		out.DHCPOptions = make([]string, len(sc.DHCPOptions))
		for i, o := range sc.DHCPOptions {
			out.DHCPOptions[i] = replaceExact(o, fmt.Sprintf("dhcp option %d", i+1), mapAddr, &rep)
		}
	}
	if len(errs) > 0 {
		return sc, rep, errors.New(strings.Join(errs, "; "))
	}
	return out, rep, nil
}

var dottedAddr = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// replaceExact swaps every dotted address in free text that lies in the old
// network and flags the value; nothing else in the text is touched.
func replaceExact(text, label string, mapAddr func(string, netip.Addr) (netip.Addr, bool), rep *RemapReport) string {
	changed := false
	out := dottedAddr.ReplaceAllStringFunc(text, func(m string) string {
		a, err := netip.ParseAddr(m)
		if err != nil {
			return m
		}
		n, ok := mapAddr(label, a)
		if ok {
			changed = true
			return n.String()
		}
		return m
	})
	if changed {
		rep.Flagged = append(rep.Flagged, fmt.Sprintf("%s: %q -> %q", label, text, out))
	}
	return out
}
