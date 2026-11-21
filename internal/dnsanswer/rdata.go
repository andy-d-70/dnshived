// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsanswer

import (
	"fmt"
	"net/netip"
	"strings"
)

const (
	TypeNS    = 2
	TypeSOA   = 6
	TypePTR   = 12
	TypeMX    = 15
	TypeTXT   = 16
	TypeAAAA  = 28
	TypeSRV   = 33
	TypeNAPTR = 35
	TypeCAA   = 257
)

func RDataA(s string) ([]byte, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() {
		return nil, fmt.Errorf("dnsanswer: %q is not an IPv4 address", s)
	}
	b := a.As4()
	return b[:], nil
}

func RDataAAAA(s string) ([]byte, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is6() || a.Is4In6() {
		return nil, fmt.Errorf("dnsanswer: %q is not an IPv6 address", s)
	}
	b := a.As16()
	return b[:], nil
}

func RDataMX(pref uint16, exchange string) ([]byte, error) {
	w, err := ToWire(exchange)
	if err != nil {
		return nil, err
	}
	return append(be.AppendUint16(nil, pref), w...), nil
}

func RDataSRV(prio, weight, port uint16, target string) ([]byte, error) {
	w, err := ToWire(target)
	if err != nil {
		return nil, err
	}
	out := be.AppendUint16(nil, prio)
	out = be.AppendUint16(out, weight)
	out = be.AppendUint16(out, port)
	return append(out, w...), nil
}

// RDataTXT encodes character strings; a string over 255 bytes is split.
func RDataTXT(parts ...string) ([]byte, error) {
	var out []byte
	for _, p := range parts {
		for {
			n := min(len(p), 255)
			out = append(out, byte(n))
			out = append(out, p[:n]...)
			p = p[n:]
			if len(p) == 0 {
				break
			}
		}
	}
	if len(out) == 0 || len(out) > 65535 {
		return nil, fmt.Errorf("dnsanswer: TXT of %d bytes", len(out))
	}
	return out, nil
}

func charString(s string) ([]byte, error) {
	if len(s) > 255 {
		return nil, fmt.Errorf("dnsanswer: character string over 255 bytes")
	}
	return append([]byte{byte(len(s))}, s...), nil
}

func RDataNAPTR(order, pref uint16, flags, service, regexp, replacement string) ([]byte, error) {
	out := be.AppendUint16(nil, order)
	out = be.AppendUint16(out, pref)
	for _, s := range []string{flags, service, regexp} {
		c, err := charString(s)
		if err != nil {
			return nil, err
		}
		out = append(out, c...)
	}
	if replacement == "" {
		return append(out, 0), nil
	}
	w, err := ToWire(replacement)
	if err != nil {
		return nil, err
	}
	return append(out, w...), nil
}

func RDataCAA(flags uint8, tag, value string) ([]byte, error) {
	if tag == "" || len(tag) > 255 {
		return nil, fmt.Errorf("dnsanswer: CAA tag length")
	}
	out := []byte{flags, byte(len(tag))}
	out = append(out, tag...)
	return append(out, value...), nil
}

// ReverseName returns the canonical in-addr.arpa or ip6.arpa owner name of an address.
func ReverseName(a netip.Addr) string {
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", b[3], b[2], b[1], b[0])
	}
	b := a.As16()
	var sb strings.Builder
	const hex = "0123456789abcdef"
	for i := 15; i >= 0; i-- {
		sb.WriteByte(hex[b[i]&0xF])
		sb.WriteByte('.')
		sb.WriteByte(hex[b[i]>>4])
		sb.WriteByte('.')
	}
	sb.WriteString("ip6.arpa")
	return sb.String()
}
