// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package netsnap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"syscall"
	"testing"

	"dnshived/internal/nstest"
)

var ne = binary.NativeEndian

func attr(typ uint16, value []byte) []byte {
	n := 4 + len(value)
	b := make([]byte, (n+3)&^3)
	ne.PutUint16(b[0:], uint16(n))
	ne.PutUint16(b[2:], typ)
	copy(b[4:], value)
	return b
}

func msg(typ uint16, payload []byte) []byte {
	b := make([]byte, 16+len(payload))
	ne.PutUint32(b[0:], uint32(len(b)))
	ne.PutUint16(b[4:], typ)
	copy(b[16:], payload)
	return b
}

func addrMsg(family, prefix byte, index uint32, attrs ...[]byte) []byte {
	p := make([]byte, 8)
	p[0], p[1] = family, prefix
	ne.PutUint32(p[4:], index)
	for _, a := range attrs {
		p = append(p, a...)
	}
	return msg(syscall.RTM_NEWADDR, p)
}

func linkMsg(index int32, name string) []byte {
	p := make([]byte, 16)
	ne.PutUint32(p[4:], uint32(index))
	p = append(p, attr(syscall.IFLA_IFNAME, append([]byte(name), 0))...)
	return msg(syscall.RTM_NEWLINK, p)
}

func done() []byte { return msg(syscall.NLMSG_DONE, make([]byte, 4)) }

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func addrStrings(a []net.Addr) []string {
	var out []string
	for _, x := range a {
		out = append(out, x.String())
	}
	sort.Strings(out)
	return out
}

func TestParseAddrs(t *testing.T) {
	v4 := []byte{10, 1, 2, 3}
	peer := []byte{10, 9, 9, 9}
	v6 := net.ParseIP("fd00::5").To16()
	tests := []struct {
		name string
		raw  []byte
		want map[int][]string
	}{
		{"ipv4 local and address are the same", cat(addrMsg(syscall.AF_INET, 24, 7, attr(syscall.IFA_ADDRESS, v4), attr(syscall.IFA_LOCAL, v4)), done()), map[int][]string{7: {"10.1.2.3/24"}}},
		{"local wins over address (point to point)", cat(addrMsg(syscall.AF_INET, 32, 3, attr(syscall.IFA_ADDRESS, peer), attr(syscall.IFA_LOCAL, v4)), done()), map[int][]string{3: {"10.1.2.3/32"}}},
		{"address only", cat(addrMsg(syscall.AF_INET, 16, 4, attr(syscall.IFA_ADDRESS, v4)), done()), map[int][]string{4: {"10.1.2.3/16"}}},
		{"ipv6", cat(addrMsg(syscall.AF_INET6, 64, 5, attr(syscall.IFA_ADDRESS, v6)), done()), map[int][]string{5: {"fd00::5/64"}}},
		{"several addresses on one interface", cat(
			addrMsg(syscall.AF_INET, 24, 2, attr(syscall.IFA_LOCAL, []byte{10, 0, 0, 1})),
			addrMsg(syscall.AF_INET, 24, 2, attr(syscall.IFA_LOCAL, []byte{10, 0, 0, 2})), done()),
			map[int][]string{2: {"10.0.0.1/24", "10.0.0.2/24"}}},
		{"two interfaces", cat(
			addrMsg(syscall.AF_INET, 24, 2, attr(syscall.IFA_LOCAL, []byte{10, 0, 0, 1})),
			addrMsg(syscall.AF_INET, 24, 9, attr(syscall.IFA_LOCAL, []byte{10, 0, 9, 1})), done()),
			map[int][]string{2: {"10.0.0.1/24"}, 9: {"10.0.9.1/24"}}},
		{"unknown family is skipped", cat(addrMsg(syscall.AF_PACKET, 8, 2, attr(syscall.IFA_ADDRESS, v4)), done()), map[int][]string{}},
		{"short value is skipped", cat(addrMsg(syscall.AF_INET, 24, 2, attr(syscall.IFA_ADDRESS, []byte{1, 2})), done()), map[int][]string{}},
		{"prefix too long is skipped", cat(addrMsg(syscall.AF_INET, 33, 2, attr(syscall.IFA_ADDRESS, v4)), done()), map[int][]string{}},
		{"stops at done", cat(done(), addrMsg(syscall.AF_INET, 24, 2, attr(syscall.IFA_LOCAL, v4))), map[int][]string{}},
		{"no messages", nil, map[int][]string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAddrs(tt.raw)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d interfaces, want %d: %v", len(got), len(tt.want), got)
			}
			for idx, w := range tt.want {
				if g := addrStrings(got[idx]); strings.Join(g, ",") != strings.Join(w, ",") {
					t.Errorf("interface %d = %v, want %v", idx, g, w)
				}
			}
		})
	}
}

func TestParseAddrsAndLinks_Refusals(t *testing.T) {
	if _, err := ParseAddrs(msg(syscall.NLMSG_ERROR, make([]byte, 20))); err == nil {
		t.Error("an error message must be reported")
	}
	if _, err := ParseAddrs(msg(syscall.RTM_NEWADDR, []byte{1, 2, 3})); err == nil {
		t.Error("a short address message must be refused")
	}
	if got, err := ParseAddrs([]byte{1, 2, 3, 4, 5}); err != nil || len(got) != 0 {
		t.Errorf("a tail shorter than a header carries no message and is ignored, got %v %v", got, err)
	}
	if _, err := ParseLinks(msg(syscall.RTM_NEWLINK, make([]byte, 4))); err == nil {
		t.Error("a short link message must be refused")
	}
	if _, err := ParseLinks(msg(syscall.NLMSG_ERROR, make([]byte, 20))); err == nil {
		t.Error("an error message must be reported")
	}
	huge := make([]byte, 16)
	ne.PutUint32(huge, 1<<30)
	if _, err := ParseAddrs(huge); err == nil {
		t.Error("a message longer than the data must be refused")
	}
}

func TestParseLinks(t *testing.T) {
	got, err := ParseLinks(cat(linkMsg(1, "lo"), linkMsg(2, "eth0"), linkMsg(40, "ens19.100"), done()))
	if err != nil {
		t.Fatal(err)
	}
	if got[1] != "lo" || got[2] != "eth0" || got[40] != "ens19.100" || len(got) != 3 {
		t.Errorf("links = %v", got)
	}
	s, err := Build(cat(linkMsg(1, "lo"), linkMsg(2, "eth0"), done()), cat(addrMsg(syscall.AF_INET, 8, 1, attr(syscall.IFA_LOCAL, []byte{127, 0, 0, 1})), done()))
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := s.ByName("lo"); !ok || e.Index != 1 || len(e.Addrs) != 1 {
		t.Errorf("lo = %+v %v", e, ok)
	}
	if e, ok := s.ByIndex(2); !ok || e.Name != "eth0" || len(e.Addrs) != 0 {
		t.Errorf("eth0 = %+v %v", e, ok)
	}
	if _, ok := s.ByName("missing"); ok || s.Len() != 2 {
		t.Error("a missing name must not be found")
	}
}

// Every interface of the test host: same index, same name, same addresses as
// the net package reports.
func TestSnapshotMatchesTheNetPackage(t *testing.T) {
	snap, err := Take()
	if err != nil {
		t.Skipf("netlink not available: %v", err)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(ifaces) == 0 {
		t.Skip("no interfaces")
	}
	for _, ifi := range ifaces {
		e, ok := snap.ByName(ifi.Name)
		if !ok || e.Index != ifi.Index {
			t.Errorf("%s: snapshot %+v %v, net index %d", ifi.Name, e, ok, ifi.Index)
			continue
		}
		want, err := ifi.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		if g, w := strings.Join(addrStrings(e.Addrs), ","), strings.Join(addrStrings(want), ","); g != w {
			t.Errorf("%s: addresses %q, net package %q", ifi.Name, g, w)
		}
		if byIdx, ok := snap.ByIndex(ifi.Index); !ok || byIdx != e {
			t.Errorf("%s: ByIndex disagrees with ByName", ifi.Name)
		}
	}
	got, err := TakeAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifi := range ifaces {
		want, _ := ifi.Addrs()
		if g, w := strings.Join(addrStrings(got[ifi.Index]), ","), strings.Join(addrStrings(want), ","); g != w {
			t.Errorf("TakeAddrs %s: %q, net package %q", ifi.Name, g, w)
		}
	}
}

// The relay ships a copy of this file (its own module); the two must not drift.
func TestRelayCopyIsIdentical(t *testing.T) {
	a, err := os.ReadFile("netsnap.go")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../cmd/dnshived-dnsrelay/netsnap/netsnap.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("cmd/dnshived-dnsrelay/netsnap/netsnap.go differs from internal/netsnap/netsnap.go; copy the file again")
	}
}

func TestSnapshotWithManyInterfaces(t *testing.T) {
	nstest.WithDummyInterfaces(t, 120)
	snap, err := Take()
	if err != nil {
		t.Fatal(err)
	}
	if snap.Len() < 121 {
		t.Fatalf("expected the dummies and lo, got %d interfaces", snap.Len())
	}
	for i := 0; i < 120; i++ {
		name := fmt.Sprintf("d%03d", i)
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			t.Fatal(err)
		}
		e, ok := snap.ByName(name)
		want, _ := ifi.Addrs()
		if !ok || e.Index != ifi.Index || strings.Join(addrStrings(e.Addrs), ",") != strings.Join(addrStrings(want), ",") {
			t.Fatalf("%s differs from the net package: %+v vs %v", name, e, want)
		}
	}
}

// BenchmarkAddrLookup compares what the relay and the plane-health check did
// (a full dump per interface) with one dump for all of them.
func BenchmarkAddrLookup(b *testing.B) {
	const n = 100
	b.Run("per interface (before)", func(b *testing.B) {
		nstest.WithDummyInterfaces(b, n)
		for b.Loop() {
			for i := 0; i < n; i++ {
				ifi, err := net.InterfaceByName(fmt.Sprintf("d%03d", i))
				if err != nil {
					b.Fatal(err)
				}
				if _, err := ifi.Addrs(); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
	b.Run("one snapshot (after)", func(b *testing.B) {
		nstest.WithDummyInterfaces(b, n)
		for b.Loop() {
			snap, err := Take()
			if err != nil {
				b.Fatal(err)
			}
			for i := 0; i < n; i++ {
				if _, ok := snap.ByName(fmt.Sprintf("d%03d", i)); !ok {
					b.Fatal("missing")
				}
			}
		}
	})
	b.Run("addresses only, by index (after, relay)", func(b *testing.B) {
		nstest.WithDummyInterfaces(b, n)
		for b.Loop() {
			if _, err := TakeAddrs(); err != nil {
				b.Fatal(err)
			}
		}
	})
}
