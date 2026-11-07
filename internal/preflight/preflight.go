// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package preflight checks a set of candidate scopes (from a backup, an
// export file, a copy or a generator) against the cluster's scopes and
// against each other, and says for every scope what clashes, how severe it
// is and what could fix it. It changes nothing and never blocks: the
// operator decides, and the normal validation still stops an invalid commit.
package preflight

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"dnshived/internal/config"
)

// Severity of one finding.
type Severity string

const (
	// SevError means a commit with this scope as it is would be refused or would break addressing.
	SevError Severity = "error"
	// SevWarning is worth a look but valid.
	SevWarning Severity = "warning"
)

// Verdict summarises one scope.
type Verdict string

const (
	VerdictOK        Verdict = "ok"
	VerdictWarnings  Verdict = "warnings"
	VerdictConflicts Verdict = "conflicts"
)

// Kind names what clashes.
type Kind string

const (
	KindScopeName       Kind = "scope_name"
	KindName            Kind = "name"
	KindParent          Kind = "parent"
	KindVLAN            Kind = "vlan"
	KindVRRPID          Kind = "vrrp_id"
	KindVIPOverlap      Kind = "vip_overlap"
	KindDHCPOverlap     Kind = "dhcp_overlap"
	KindNodeIP          Kind = "node_ip"
	KindReservation     Kind = "reservation"
	KindPreferredWorker Kind = "preferred_worker"
	KindTemplateRef     Kind = "template_ref"
	KindGateway         Kind = "gateway"
	KindAddress         Kind = "address"
)

// FixKind names a suggested way out.
type FixKind string

const (
	FixRename          FixKind = "rename"
	FixVLAN            FixKind = "vlan"
	FixVRRPID          FixKind = "vrrp_id"
	FixNetwork         FixKind = "network"
	FixParent          FixKind = "parent"
	FixPreferredWorker FixKind = "preferred_worker"
	FixUnlink          FixKind = "unlink"
	FixSkip            FixKind = "skip"
)

// Fix is one suggestion. Which fields are set depends on Kind; a network fix
// normally carries a new VLAN and VRRP ID as well, so the three are offered
// and applied together.
type Fix struct {
	Kind    FixKind `json:"kind"`
	Label   string  `json:"label"`
	Name    string  `json:"name,omitempty"`
	Network string  `json:"network,omitempty"`
	VLANID  int     `json:"vlan_id,omitempty"`
	VRRPID  int     `json:"vrrp_id,omitempty"`
	Parent  string  `json:"parent,omitempty"`
	Link    string  `json:"link,omitempty"`
}

// Collision is one finding about one scope.
type Collision struct {
	Kind     Kind     `json:"kind"`
	Severity Severity `json:"severity"`
	// Other names the scope it clashes with, when there is one.
	Other  string `json:"other,omitempty"`
	Detail string `json:"detail"`
	Fixes  []Fix  `json:"fixes,omitempty"`
}

// Result is the outcome for one candidate scope.
type Result struct {
	Scope      string      `json:"scope"`
	Verdict    Verdict     `json:"verdict"`
	Collisions []Collision `json:"collisions,omitempty"`
}

// Context is what the candidates are checked against.
type Context struct {
	// Existing are the cluster's scopes today.
	Existing map[string]config.ScopeConfig
	// Workers are the interfaces a scope may be built on; empty skips the check.
	Workers []string
	// Mgmt is the protected management interface.
	Mgmt string
	// MgmtVRRPID and MgmtVIPHost are taken by the management VIP; zero/empty when there is none.
	MgmtVRRPID  int
	MgmtVIPHost string
	// HasSource says whether the cluster has the template or option set a
	// content link points at; nil skips the check.
	HasSource func(kind, id string) bool
}

type peer struct {
	name     string
	sc       config.ScopeConfig
	incoming bool
}

type parsed struct {
	prefix netip.Prefix // the VIP with its mask
	subnet netip.Prefix
	ok     bool
}

func parseVIP(vip string) parsed {
	p, err := netip.ParsePrefix(vip)
	if err != nil || !p.Addr().Is4() {
		return parsed{}
	}
	return parsed{prefix: p, subnet: p.Masked(), ok: true}
}

func overlaps(a, b netip.Prefix) bool { return a.Contains(b.Addr()) || b.Contains(a.Addr()) }

type rangeIP struct{ lo, hi netip.Addr }

func parseRange(r [2]string) (rangeIP, bool) {
	lo, e1 := netip.ParseAddr(r[0])
	hi, e2 := netip.ParseAddr(r[1])
	if e1 != nil || e2 != nil || !lo.Is4() || !hi.Is4() || lo.Compare(hi) > 0 {
		return rangeIP{}, false
	}
	return rangeIP{lo, hi}, true
}

func rangesOverlap(a, b rangeIP) bool { return a.lo.Compare(b.hi) <= 0 && b.lo.Compare(a.hi) <= 0 }

// Check examines every scope in incoming. Results are sorted by scope name.
func Check(ctx Context, incoming map[string]config.ScopeConfig) []Result {
	names := make([]string, 0, len(incoming))
	for n := range incoming {
		names = append(names, n)
	}
	sort.Strings(names)

	var all []peer
	for n, sc := range ctx.Existing {
		all = append(all, peer{n, sc, false})
	}
	for _, n := range names {
		all = append(all, peer{n, incoming[n], true})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].name != all[j].name {
			return all[i].name < all[j].name
		}
		return !all[i].incoming && all[j].incoming
	})
	used := newUsage(ctx, all)

	out := make([]Result, 0, len(names))
	for _, n := range names {
		out = append(out, checkOne(ctx, used, all, n, incoming[n]))
	}
	return out
}

func verdictOf(cs []Collision) Verdict {
	v := VerdictOK
	for _, c := range cs {
		if c.Severity == SevError {
			return VerdictConflicts
		}
		v = VerdictWarnings
	}
	return v
}

func checkOne(ctx Context, used *usage, all []peer, name string, sc config.ScopeConfig) Result {
	res := Result{Scope: name}
	add := func(c Collision) { res.Collisions = append(res.Collisions, c) }
	skip := Fix{Kind: FixSkip, Label: "leave this scope out"}

	if !config.ValidScopeName(name) {
		add(Collision{Kind: KindScopeName, Severity: SevError, Detail: fmt.Sprintf("the name %q may only use letters, digits, - and _", name),
			Fixes: []Fix{{Kind: FixRename, Label: "use another name", Name: used.freeName(sanitizeName(name))}, skip}})
	}
	replaces := false
	if _, ok := ctx.Existing[name]; ok {
		replaces = true
		add(Collision{Kind: KindName, Severity: SevError, Other: name, Detail: "a scope with this name already exists and would be replaced",
			Fixes: []Fix{{Kind: FixRename, Label: "import under another name", Name: used.freeName(name)}, skip}})
	}

	if len(ctx.Workers) > 0 && !contains(ctx.Workers, sc.Parent) {
		fixes := make([]Fix, 0, len(ctx.Workers)+1)
		for _, w := range ctx.Workers {
			fixes = append(fixes, Fix{Kind: FixParent, Label: "build it on " + w, Parent: w})
		}
		add(Collision{Kind: KindParent, Severity: SevError, Detail: fmt.Sprintf("parent interface %q is not a worker interface of this cluster", sc.Parent), Fixes: append(fixes, skip)})
	} else if ctx.Mgmt != "" && sc.Parent == ctx.Mgmt && sc.VLANID != 0 {
		add(Collision{Kind: KindParent, Severity: SevError, Detail: fmt.Sprintf("parent %q is the protected management interface; only an untagged scope may use it", sc.Parent), Fixes: []Fix{skip}})
	}
	if sc.VLANID != 0 && (sc.VLANID < 2 || sc.VLANID > 4094) {
		add(Collision{Kind: KindVLAN, Severity: SevError, Detail: fmt.Sprintf("vlan_id %d is outside 2-4094", sc.VLANID), Fixes: used.vlanFixes(sc.Parent, sc.VLANID, skip)})
	}
	if sc.VRRPID < 1 || sc.VRRPID > 255 {
		add(Collision{Kind: KindVRRPID, Severity: SevError, Detail: fmt.Sprintf("vrrp_id %d is outside 1-255", sc.VRRPID), Fixes: used.vrrpFixes(sc.VRRPID, skip)})
	}
	switch sc.PreferredWorker {
	case config.RoleCore1, config.RoleCore2, config.RoleCore3:
	default:
		var fixes []Fix
		for _, r := range []string{config.RoleCore1, config.RoleCore2, config.RoleCore3} {
			fixes = append(fixes, Fix{Kind: FixPreferredWorker, Label: "prefer " + r, Name: r})
		}
		add(Collision{Kind: KindPreferredWorker, Severity: SevError, Detail: fmt.Sprintf("preferred_worker %q is not core-1, core-2 or core-3", sc.PreferredWorker), Fixes: append(fixes, skip)})
	}
	if ctx.MgmtVRRPID != 0 && sc.VRRPID == ctx.MgmtVRRPID {
		add(Collision{Kind: KindVRRPID, Severity: SevError, Other: "management VIP", Detail: fmt.Sprintf("vrrp_id %d is used by the management VIP", sc.VRRPID), Fixes: used.vrrpFixes(sc.VRRPID, skip)})
	}

	me := parseVIP(sc.VIP)
	if !me.ok {
		add(Collision{Kind: KindAddress, Severity: SevError, Detail: fmt.Sprintf("vip %q is not an IPv4 address with a prefix length", sc.VIP), Fixes: []Fix{skip}})
	} else if ctx.MgmtVIPHost != "" && me.prefix.Addr().String() == ctx.MgmtVIPHost {
		add(Collision{Kind: KindVIPOverlap, Severity: SevError, Other: "management VIP", Detail: "the vip is the management VIP's address", Fixes: used.networkFixes(me.subnet, sc, skip)})
	}
	myRange, rangeOK := parseRange(sc.DHCPRange)

	for _, p := range all {
		if p.name == name && (p.incoming || replaces) {
			continue
		}
		if sc.Parent != "" && p.sc.Parent == sc.Parent && p.sc.VLANID == sc.VLANID {
			add(Collision{Kind: KindVLAN, Severity: SevError, Other: p.name, Detail: fmt.Sprintf("vlan_id %d on %q is already used by scope %q", sc.VLANID, sc.Parent, p.name), Fixes: used.vlanFixes(sc.Parent, sc.VLANID, skip)})
		}
		if p.sc.VRRPID == sc.VRRPID && sc.VRRPID != 0 {
			add(Collision{Kind: KindVRRPID, Severity: SevError, Other: p.name, Detail: fmt.Sprintf("vrrp_id %d is already used by scope %q", sc.VRRPID, p.name), Fixes: used.vrrpFixes(sc.VRRPID, skip)})
		}
		vipClash := false
		if other := parseVIP(p.sc.VIP); me.ok && other.ok && overlaps(me.subnet, other.subnet) {
			vipClash = true
			detail := fmt.Sprintf("vip subnet %s overlaps %s of scope %q", me.subnet, other.subnet, p.name)
			if me.prefix.Addr() == other.prefix.Addr() {
				detail = fmt.Sprintf("vip %s is the same address as the vip of scope %q", me.prefix.Addr(), p.name)
			}
			add(Collision{Kind: KindVIPOverlap, Severity: SevError, Other: p.name, Detail: detail, Fixes: used.networkFixes(me.subnet, sc, skip)})
		}
		if !vipClash && rangeOK {
			if r, ok := parseRange(p.sc.DHCPRange); ok && rangesOverlap(myRange, r) {
				add(Collision{Kind: KindDHCPOverlap, Severity: SevWarning, Other: p.name, Detail: fmt.Sprintf("dhcp range %s-%s overlaps %s-%s of scope %q (fine if the segments are isolated)", sc.DHCPRange[0], sc.DHCPRange[1], p.sc.DHCPRange[0], p.sc.DHCPRange[1], p.name)})
			}
		}
	}

	checkAddresses(&res, sc, me)
	checkReservations(&res, all, name, replaces, sc, me)
	if ctx.HasSource != nil {
		keys := make([]string, 0, len(sc.ContentLinks))
		for k := range sc.ContentLinks {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			l := sc.ContentLinks[k]
			if !ctx.HasSource(l.Kind, l.SourceID) {
				add(Collision{Kind: KindTemplateRef, Severity: SevWarning, Detail: fmt.Sprintf("%s is linked to %s %q, which this cluster does not have", k, l.Kind, l.SourceID),
					Fixes: []Fix{{Kind: FixUnlink, Label: "keep the content, drop the link", Link: k}}})
			}
		}
	}
	res.Verdict = verdictOf(res.Collisions)
	return res
}

func checkAddresses(res *Result, sc config.ScopeConfig, me parsed) {
	add := func(c Collision) { res.Collisions = append(res.Collisions, c) }
	if !me.ok {
		return
	}
	if sc.Gateway != "" {
		if g, err := netip.ParseAddr(sc.Gateway); err != nil {
			add(Collision{Kind: KindGateway, Severity: SevWarning, Detail: fmt.Sprintf("gateway %q is not an address", sc.Gateway)})
		} else if !me.subnet.Contains(g) {
			add(Collision{Kind: KindGateway, Severity: SevWarning, Detail: fmt.Sprintf("gateway %s is outside the scope's network %s", g, me.subnet)})
		} else if me.subnet.Bits() < 31 && (g == me.subnet.Addr() || g == broadcast(me.subnet)) {
			add(Collision{Kind: KindGateway, Severity: SevWarning, Detail: fmt.Sprintf("gateway %s is the network or broadcast address of %s", g, me.subnet)})
		}
	}
	seen := map[netip.Addr]string{}
	check := func(label, v string) {
		if v == "" {
			return
		}
		p, err := netip.ParsePrefix(v)
		if err != nil {
			add(Collision{Kind: KindNodeIP, Severity: SevError, Detail: fmt.Sprintf("%s %q is not an address with a prefix length", label, v)})
			return
		}
		if p.Addr() == me.prefix.Addr() {
			add(Collision{Kind: KindNodeIP, Severity: SevError, Detail: fmt.Sprintf("%s %s is the same address as the vip", label, p.Addr())})
		} else if !me.subnet.Contains(p.Addr()) {
			add(Collision{Kind: KindNodeIP, Severity: SevWarning, Detail: fmt.Sprintf("%s %s is outside the scope's network %s", label, p.Addr(), me.subnet)})
		}
		if prev, dup := seen[p.Addr()]; dup {
			add(Collision{Kind: KindNodeIP, Severity: SevError, Detail: fmt.Sprintf("%s and %s are the same address %s", prev, label, p.Addr())})
		}
		seen[p.Addr()] = label
	}
	check("node_ip", sc.NodeIP)
	roles := make([]string, 0, len(sc.NodeIPOverrides))
	for r := range sc.NodeIPOverrides {
		roles = append(roles, r)
	}
	sort.Strings(roles)
	for _, r := range roles {
		check("node_ip_overrides["+r+"]", sc.NodeIPOverrides[r])
	}
}

func checkReservations(res *Result, all []peer, name string, replaces bool, sc config.ScopeConfig, me parsed) {
	add := func(c Collision) { res.Collisions = append(res.Collisions, c) }
	macs := map[string]int{}
	ips := map[netip.Addr]int{}
	gw, _ := netip.ParseAddr(sc.Gateway)
	for i, r := range sc.Reservations {
		mac := strings.ToLower(strings.TrimSpace(r.MAC))
		if j, dup := macs[mac]; dup && mac != "" {
			add(Collision{Kind: KindReservation, Severity: SevError, Detail: fmt.Sprintf("reservations %d and %d both use the MAC %s", j+1, i+1, mac)})
		}
		macs[mac] = i
		ip, err := netip.ParseAddr(r.IP)
		if err != nil || !ip.Is4() {
			add(Collision{Kind: KindReservation, Severity: SevError, Detail: fmt.Sprintf("reservation %d (%s): %q is not an IPv4 address", i+1, r.MAC, r.IP)})
			continue
		}
		if j, dup := ips[ip]; dup {
			add(Collision{Kind: KindReservation, Severity: SevError, Detail: fmt.Sprintf("reservations %d and %d both use the address %s", j+1, i+1, ip)})
		}
		ips[ip] = i
		if me.ok {
			switch {
			case ip == me.prefix.Addr():
				add(Collision{Kind: KindReservation, Severity: SevError, Detail: fmt.Sprintf("reservation %d (%s) uses the vip %s", i+1, r.MAC, ip)})
			case !me.subnet.Contains(ip):
				add(Collision{Kind: KindReservation, Severity: SevWarning, Detail: fmt.Sprintf("reservation %d (%s): %s is outside the scope's network %s and will never be handed out", i+1, r.MAC, ip, me.subnet)})
			case gw.IsValid() && ip == gw:
				add(Collision{Kind: KindReservation, Severity: SevWarning, Detail: fmt.Sprintf("reservation %d (%s) uses the gateway address %s", i+1, r.MAC, ip)})
			}
		}
	}
	reported := map[string]bool{}
	for _, p := range all {
		if p.name == name && (p.incoming || replaces) {
			continue
		}
		for _, r := range p.sc.Reservations {
			mac := strings.ToLower(strings.TrimSpace(r.MAC))
			if _, mine := macs[mac]; mine && mac != "" && !reported[p.name+mac] {
				reported[p.name+mac] = true
				add(Collision{Kind: KindReservation, Severity: SevWarning, Other: p.name, Detail: fmt.Sprintf("the MAC %s is also reserved in scope %q (a device is normally on one network)", mac, p.name)})
			}
		}
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func broadcast(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	host := 32 - p.Bits()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= (1 << uint(host)) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
