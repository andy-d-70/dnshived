// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package neighbors reads the kernel's IPv4 neighbor table for one interface
// and makes the kernel resolve chosen addresses, so a host that answers ARP
// shows up without any raw socket or extra privilege.
package neighbors

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
)

// MaxProbe bounds one probe call.
const MaxProbe = 16

const arpPath = "/proc/net/arp"

const flagComplete = 0x2

type Neighbor struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac,omitempty"`
	Complete bool   `json:"complete"`
}

// Parse reads /proc/net/arp text and returns the entries of iface.
func Parse(r io.Reader, iface string) ([]Neighbor, error) {
	sc := bufio.NewScanner(r)
	var out []Neighbor
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 6 || f[5] != iface {
			continue
		}
		ip, err := netip.ParseAddr(f[0])
		if err != nil || !ip.Is4() {
			continue
		}
		var flags int
		if _, err := fmt.Sscanf(f[2], "0x%x", &flags); err != nil {
			continue
		}
		n := Neighbor{IP: ip.String(), Complete: flags&flagComplete != 0}
		if n.Complete {
			if hw, err := net.ParseMAC(f[3]); err == nil {
				n.MAC = hw.String()
			}
		}
		out = append(out, n)
	}
	return out, sc.Err()
}

// List returns the neighbor table of iface.
func List(iface string) ([]Neighbor, error) {
	f, err := os.Open(arpPath)
	if err != nil {
		return nil, fmt.Errorf("read neighbor table: %w", err)
	}
	defer f.Close()
	return Parse(f, iface)
}

// CheckTargets refuses addresses that are not usable hosts of network and
// returns them parsed. At most MaxProbe addresses are accepted.
func CheckTargets(network netip.Prefix, ips []string) ([]netip.Addr, error) {
	if len(ips) == 0 {
		return nil, fmt.Errorf("no address given")
	}
	if len(ips) > MaxProbe {
		return nil, fmt.Errorf("%d addresses, at most %d per call", len(ips), MaxProbe)
	}
	network = network.Masked()
	if !network.Addr().Is4() {
		return nil, fmt.Errorf("only IPv4 networks are supported")
	}
	last := lastAddr(network)
	out := make([]netip.Addr, 0, len(ips))
	for _, s := range ips {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil || !a.Is4() {
			return nil, fmt.Errorf("%q is not an IPv4 address", s)
		}
		if !network.Contains(a) || a == network.Addr() || a == last {
			return nil, fmt.Errorf("%s is not a host address of %s", a, network)
		}
		out = append(out, a)
	}
	return out, nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().As4()
	host := 32 - p.Bits()
	for i := 0; i < host; i++ {
		b[3-i/8] |= 1 << (i % 8)
	}
	return netip.AddrFrom4(b)
}

// Probe sends one datagram from local to every target so the kernel resolves
// it, waits up to wait for the answers and returns the entries of iface for
// the targets.
func Probe(ctx context.Context, iface string, local netip.Addr, targets []netip.Addr, wait time.Duration) ([]Neighbor, error) {
	for _, t := range targets {
		d := net.Dialer{LocalAddr: &net.UDPAddr{IP: local.AsSlice()}, Timeout: time.Second}
		c, err := d.DialContext(ctx, "udp4", net.JoinHostPort(t.String(), "9"))
		if err != nil {
			continue
		}
		_, _ = c.Write([]byte{0})
		c.Close()
	}
	want := make(map[string]bool, len(targets))
	for _, t := range targets {
		want[t.String()] = true
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		all, err := List(iface)
		if err != nil {
			return nil, err
		}
		var got []Neighbor
		done := 0
		for _, n := range all {
			if want[n.IP] {
				got = append(got, n)
				if n.Complete {
					done++
				}
			}
		}
		select {
		case <-ctx.Done():
			return got, ctx.Err()
		case <-deadline.C:
			return got, nil
		case <-tick.C:
			if done == len(targets) {
				return got, nil
			}
		}
	}
}
