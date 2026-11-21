// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package dnsanswer answers DNS queries for names held in an immutable table: exact names, wildcards, CNAME chains,
// authoritative negative answers, truncation and EDNS. It has no dependencies, so the DNS relay carries a verbatim copy.
package dnsanswer

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxLabel = 63
	maxName  = 253
)

var ErrName = errors.New("dnsanswer: invalid name")

func nameErr(s, why string) error { return fmt.Errorf("%w %q: %s", ErrName, s, why) }

// CanonicalName lowercases a name, strips one trailing dot, converts non-ASCII labels to punycode and validates it.
// A "*" is allowed only as the whole leftmost label.
func CanonicalName(s string) (string, error) {
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", nameErr(s, "empty")
	}
	s = strings.ToLower(s)
	labels := strings.Split(s, ".")
	for i, l := range labels {
		if l == "" {
			return "", nameErr(s, "empty label")
		}
		if !isASCII(l) {
			p, err := punycode(l)
			if err != nil {
				return "", nameErr(s, err.Error())
			}
			l = "xn--" + p
			labels[i] = l
		}
		if len(l) > maxLabel {
			return "", nameErr(s, "label over 63 bytes")
		}
		if l == "*" {
			if i != 0 {
				return "", nameErr(s, "wildcard only as the leftmost label")
			}
			continue
		}
		for j := 0; j < len(l); j++ {
			c := l[j]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", nameErr(s, "character not allowed in a label")
			}
		}
	}
	out := strings.Join(labels, ".")
	if len(out) > maxName {
		return "", nameErr(s, "name over 253 bytes")
	}
	return out, nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// ToWire encodes a canonical name in uncompressed wire format.
func ToWire(canon string) ([]byte, error) {
	if canon == "" || len(canon) > maxName {
		return nil, nameErr(canon, "length")
	}
	out := make([]byte, 0, len(canon)+2)
	for _, l := range strings.Split(canon, ".") {
		if l == "" || len(l) > maxLabel {
			return nil, nameErr(canon, "label length")
		}
		out = append(out, byte(len(l)))
		out = append(out, l...)
	}
	return append(out, 0), nil
}

// FromWire decodes an uncompressed wire name to its lowercase dotted form.
func FromWire(w []byte) (string, error) {
	var sb strings.Builder
	for i := 0; i < len(w); {
		n := int(w[i])
		if n == 0 {
			return sb.String(), nil
		}
		if n > maxLabel || i+1+n > len(w) {
			return "", ErrName
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		for _, c := range w[i+1 : i+1+n] {
			if c >= 'A' && c <= 'Z' {
				c += 32
			}
			sb.WriteByte(c)
		}
		i += 1 + n
	}
	return "", ErrName
}

const (
	pBase = 36
	pTMin = 1
	pTMax = 26
	pSkew = 38
	pDamp = 700
)

func pAdapt(delta, n int, first bool) int {
	if first {
		delta /= pDamp
	} else {
		delta /= 2
	}
	delta += delta / n
	k := 0
	for delta > ((pBase-pTMin)*pTMax)/2 {
		delta /= pBase - pTMin
		k += pBase
	}
	return k + (pBase-pTMin+1)*delta/(delta+pSkew)
}

func pDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}

func punycode(label string) (string, error) {
	var in []rune
	for _, r := range label {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.IsSpace(r) {
			return "", errors.New("invalid character")
		}
		in = append(in, r)
	}
	var out []byte
	for _, r := range in {
		if r < 0x80 {
			out = append(out, byte(r))
		}
	}
	b := len(out)
	h := b
	if b > 0 {
		out = append(out, '-')
	}
	n, delta, bias := 128, 0, 72
	for h < len(in) {
		m := int(^uint(0) >> 1)
		for _, r := range in {
			if int(r) >= n && int(r) < m {
				m = int(r)
			}
		}
		delta += (m - n) * (h + 1)
		n = m
		for _, r := range in {
			if int(r) < n {
				delta++
			}
			if int(r) == n {
				q := delta
				for k := pBase; ; k += pBase {
					t := k - bias
					if t < pTMin {
						t = pTMin
					} else if t > pTMax {
						t = pTMax
					}
					if q < t {
						break
					}
					out = append(out, pDigit(t+(q-t)%(pBase-t)))
					q = (q - t) / (pBase - t)
				}
				out = append(out, pDigit(q))
				bias = pAdapt(delta, h+1, h == b)
				delta = 0
				h++
			}
		}
		delta++
		n++
	}
	return string(out), nil
}
