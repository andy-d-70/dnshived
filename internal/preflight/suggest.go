// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package preflight

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"dnshived/internal/config"
)

// maxProbe bounds every search for a free value.
const maxProbe = 1 << 16

// usage is what the cluster and the candidates already take.
type usage struct {
	names    map[string]bool
	vlans    map[string]map[int]bool
	vrrp     map[int]bool
	networks []netip.Prefix
}

func newUsage(ctx Context, all []peer) *usage {
	u := &usage{names: map[string]bool{}, vlans: map[string]map[int]bool{}, vrrp: map[int]bool{}}
	for _, p := range all {
		u.names[p.name] = true
		if u.vlans[p.sc.Parent] == nil {
			u.vlans[p.sc.Parent] = map[int]bool{}
		}
		u.vlans[p.sc.Parent][p.sc.VLANID] = true
		u.vrrp[p.sc.VRRPID] = true
		if v := parseVIP(p.sc.VIP); v.ok {
			u.networks = append(u.networks, v.subnet)
		}
	}
	if ctx.MgmtVRRPID != 0 {
		u.vrrp[ctx.MgmtVRRPID] = true
	}
	return u
}

func sanitizeName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "scope"
	}
	return b.String()
}

// freeName returns base-2, base-3, ... or base itself when it is free.
func (u *usage) freeName(base string) string {
	if !u.names[base] {
		return base
	}
	for i := 2; i < maxProbe; i++ {
		if n := fmt.Sprintf("%s-%d", base, i); !u.names[n] {
			return n
		}
	}
	return base
}

// NextFreeVLAN returns the first VLAN id after start (wrapping) that is not in used.
func NextFreeVLAN(used map[int]bool, start int) (int, bool) {
	if start < 1 {
		start = 1
	}
	for i := 1; i <= 4093; i++ {
		id := (start-2+i)%4093 + 2
		if !used[id] {
			return id, true
		}
	}
	return 0, false
}

// NextFreeVRRPID returns the first VRRP id after start (wrapping) that is not in used.
func NextFreeVRRPID(used map[int]bool, start int) (int, bool) {
	if start < 0 {
		start = 0
	}
	for i := 1; i <= 255; i++ {
		id := (start-1+i)%255 + 1
		if !used[id] {
			return id, true
		}
	}
	return 0, false
}

func (u *usage) vlanFixes(parent string, current int, skip Fix) []Fix {
	if id, ok := NextFreeVLAN(u.vlans[parent], current); ok {
		return []Fix{{Kind: FixVLAN, Label: fmt.Sprintf("use VLAN %d on %s", id, parent), VLANID: id, Parent: parent}, skip}
	}
	return []Fix{skip}
}

func (u *usage) vrrpFixes(current int, skip Fix) []Fix {
	if id, ok := NextFreeVRRPID(u.vrrp, current); ok {
		return []Fix{{Kind: FixVRRPID, Label: fmt.Sprintf("use VRRP ID %d", id), VRRPID: id}, skip}
	}
	return []Fix{skip}
}

// networkFixes offers the next free network of the same size, together with
// a new VLAN and VRRP ID, since a new network normally comes with both.
func (u *usage) networkFixes(current netip.Prefix, sc config.ScopeConfig, skip Fix) []Fix {
	n, ok := NextFreeNetwork(u.networks, current)
	if !ok {
		return []Fix{skip}
	}
	fixes := []Fix{{Kind: FixNetwork, Label: "move it to " + n.String(), Network: n.String()}}
	vlan, vok := NextFreeVLAN(u.vlans[sc.Parent], sc.VLANID)
	vrrp, rok := NextFreeVRRPID(u.vrrp, sc.VRRPID)
	if vok && rok {
		fixes = append(fixes, Fix{Kind: FixNetwork, Label: fmt.Sprintf("move it to %s with VLAN %d and VRRP ID %d", n, vlan, vrrp),
			Network: n.String(), VLANID: vlan, VRRPID: vrrp, Parent: sc.Parent})
	}
	return append(fixes, skip)
}

var privateBlocks = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

func privateBlockOf(a netip.Addr) (netip.Prefix, bool) {
	for _, b := range privateBlocks {
		if b.Contains(a) {
			return b, true
		}
	}
	return netip.Prefix{}, false
}

func toU32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func fromU32(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// NextFreeNetwork returns the next network of the same size as like, inside
// the same private block, that overlaps nothing in used. The search starts
// after like and wraps around the block.
func NextFreeNetwork(used []netip.Prefix, like netip.Prefix) (netip.Prefix, bool) {
	if !like.Addr().Is4() || like.Bits() < 8 || like.Bits() > 30 {
		return netip.Prefix{}, false
	}
	block, ok := privateBlockOf(like.Addr())
	if !ok || like.Bits() < block.Bits() {
		return netip.Prefix{}, false
	}
	stride := uint64(1) << uint(32-like.Bits())
	size := uint64(1) << uint(32-block.Bits())
	base := uint64(toU32(block.Masked().Addr()))
	cur := (uint64(toU32(like.Masked().Addr())) - base) / stride
	count := size / stride
	for i := uint64(1); i < count && i < maxProbe; i++ {
		idx := (cur + i) % count
		cand := netip.PrefixFrom(fromU32(uint32(base+idx*stride)), like.Bits())
		if !anyOverlap(used, cand) {
			return cand, true
		}
	}
	return netip.Prefix{}, false
}

func anyOverlap(used []netip.Prefix, c netip.Prefix) bool {
	for _, u := range used {
		if overlaps(u, c) {
			return true
		}
	}
	return false
}

// GenerateNetworks returns count networks of the size of start, beginning at
// start and stepping step networks per run, skipping any that overlap used or
// an earlier result. It fails when the private block runs out.
func GenerateNetworks(start netip.Prefix, step, count int, used []netip.Prefix) ([]netip.Prefix, error) {
	if step < 1 || count < 1 {
		return nil, errors.New("step and count must be at least 1")
	}
	if !start.Addr().Is4() || start.Bits() < 8 || start.Bits() > 30 {
		return nil, errors.New("the start network must be an IPv4 network between /8 and /30")
	}
	block, ok := privateBlockOf(start.Addr())
	if !ok || start.Bits() < block.Bits() {
		return nil, errors.New("the start network must lie in 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16")
	}
	stride := uint64(1) << uint(32-start.Bits())
	end := uint64(toU32(block.Masked().Addr())) + uint64(1)<<uint(32-block.Bits())
	taken := append([]netip.Prefix(nil), used...)
	var out []netip.Prefix
	for pos := uint64(toU32(start.Masked().Addr())); len(out) < count; pos += stride * uint64(step) {
		if pos+stride > end {
			return out, fmt.Errorf("the private block %s has no room for %d networks of /%d from %s in steps of %d", block, count, start.Bits(), start.Masked(), step)
		}
		cand := netip.PrefixFrom(fromU32(uint32(pos)), start.Bits())
		if anyOverlap(taken, cand) {
			continue
		}
		out = append(out, cand)
		taken = append(taken, cand)
	}
	return out, nil
}
