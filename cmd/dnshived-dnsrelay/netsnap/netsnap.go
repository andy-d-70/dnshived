// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package netsnap reads the kernel's links and addresses with one netlink dump
// each. net.InterfaceByName, net.InterfaceByIndex and Interface.Addrs each ask
// the kernel for the whole table, so calling them once per interface or per
// scope costs interfaces x interfaces; a snapshot answers every lookup of one
// pass from the same two dumps.
//
// cmd/dnshived-dnsrelay/netsnap/netsnap.go is a byte-identical copy (the relay
// is its own module); a test keeps the two equal.
package netsnap

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

// Entry is one interface of a snapshot.
type Entry struct {
	Index int
	Name  string
	Addrs []net.Addr
}

// Snapshot is the links and addresses of one moment.
type Snapshot struct {
	byName  map[string]*Entry
	byIndex map[int]*Entry
}

// Take dumps the links and the addresses once each.
func Take() (*Snapshot, error) {
	links, err := syscall.NetlinkRIB(syscall.RTM_GETLINK, syscall.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("netlink link dump: %w", err)
	}
	addrs, err := syscall.NetlinkRIB(syscall.RTM_GETADDR, syscall.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("netlink address dump: %w", err)
	}
	return Build(links, addrs)
}

// TakeAddrs dumps the addresses once and returns them by interface index.
func TakeAddrs() (map[int][]net.Addr, error) {
	raw, err := syscall.NetlinkRIB(syscall.RTM_GETADDR, syscall.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("netlink address dump: %w", err)
	}
	return ParseAddrs(raw)
}

// Build makes a snapshot from raw link and address dumps.
func Build(links, addrs []byte) (*Snapshot, error) {
	names, err := ParseLinks(links)
	if err != nil {
		return nil, err
	}
	byIndex, err := ParseAddrs(addrs)
	if err != nil {
		return nil, err
	}
	s := &Snapshot{byName: make(map[string]*Entry, len(names)), byIndex: make(map[int]*Entry, len(names))}
	for idx, name := range names {
		e := &Entry{Index: idx, Name: name, Addrs: byIndex[idx]}
		s.byName[name] = e
		s.byIndex[idx] = e
	}
	return s, nil
}

// ByName finds an interface by its kernel name.
func (s *Snapshot) ByName(name string) (*Entry, bool) {
	e, ok := s.byName[name]
	return e, ok
}

// ByIndex finds an interface by its index.
func (s *Snapshot) ByIndex(idx int) (*Entry, bool) {
	e, ok := s.byIndex[idx]
	return e, ok
}

// Len is the number of interfaces.
func (s *Snapshot) Len() int { return len(s.byIndex) }

// ParseLinks returns the interface names by index from a raw RTM_GETLINK dump.
func ParseLinks(raw []byte) (map[int]string, error) {
	msgs, err := syscall.ParseNetlinkMessage(raw)
	if err != nil {
		return nil, fmt.Errorf("parse netlink links: %w", err)
	}
	out := make(map[int]string)
	for _, m := range msgs {
		switch m.Header.Type {
		case syscall.NLMSG_DONE:
			return out, nil
		case syscall.NLMSG_ERROR:
			return nil, fmt.Errorf("netlink link dump failed")
		case syscall.RTM_NEWLINK:
			if len(m.Data) < syscall.SizeofIfInfomsg {
				return nil, fmt.Errorf("short link message (%d bytes)", len(m.Data))
			}
			index := int(int32(binary.NativeEndian.Uint32(m.Data[4:8])))
			attrs, err := syscall.ParseNetlinkRouteAttr(&m)
			if err != nil {
				return nil, fmt.Errorf("parse link attributes: %w", err)
			}
			for _, a := range attrs {
				if a.Attr.Type == syscall.IFLA_IFNAME {
					out[index] = cString(a.Value)
					break
				}
			}
		}
	}
	return out, nil
}

// ParseAddrs returns the addresses by interface index from a raw RTM_GETADDR
// dump. IFA_LOCAL wins over IFA_ADDRESS, as in the net package.
func ParseAddrs(raw []byte) (map[int][]net.Addr, error) {
	msgs, err := syscall.ParseNetlinkMessage(raw)
	if err != nil {
		return nil, fmt.Errorf("parse netlink addresses: %w", err)
	}
	out := make(map[int][]net.Addr)
	for _, m := range msgs {
		switch m.Header.Type {
		case syscall.NLMSG_DONE:
			return out, nil
		case syscall.NLMSG_ERROR:
			return nil, fmt.Errorf("netlink address dump failed")
		case syscall.RTM_NEWADDR:
			if len(m.Data) < syscall.SizeofIfAddrmsg {
				return nil, fmt.Errorf("short address message (%d bytes)", len(m.Data))
			}
			family, prefix := int(m.Data[0]), int(m.Data[1])
			index := int(binary.NativeEndian.Uint32(m.Data[4:8]))
			attrs, err := syscall.ParseNetlinkRouteAttr(&m)
			if err != nil {
				return nil, fmt.Errorf("parse address attributes: %w", err)
			}
			var local, address []byte
			for _, a := range attrs {
				switch a.Attr.Type {
				case syscall.IFA_LOCAL:
					local = a.Value
				case syscall.IFA_ADDRESS:
					address = a.Value
				}
			}
			value := address
			if local != nil {
				value = local
			}
			if a := newAddr(family, prefix, value); a != nil {
				out[index] = append(out[index], a)
			}
		}
	}
	return out, nil
}

func newAddr(family, prefix int, value []byte) net.Addr {
	switch family {
	case syscall.AF_INET:
		if len(value) < net.IPv4len || prefix > 8*net.IPv4len {
			return nil
		}
		return &net.IPNet{IP: net.IPv4(value[0], value[1], value[2], value[3]), Mask: net.CIDRMask(prefix, 8*net.IPv4len)}
	case syscall.AF_INET6:
		if len(value) < net.IPv6len || prefix > 8*net.IPv6len {
			return nil
		}
		ip := make(net.IP, net.IPv6len)
		copy(ip, value)
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(prefix, 8*net.IPv6len)}
	}
	return nil
}

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
