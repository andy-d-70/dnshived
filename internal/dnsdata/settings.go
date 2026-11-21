// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsdata

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"dnshived/internal/dnsstore"
)

// TypeSetting is the row type of cluster-wide DNS store settings; the rows replicate like any other row.
const TypeSetting uint8 = 3

const (
	// AuthoritativeKey names the cutover setting: while it is off the table answers only the records it holds and
	// forwards everything else (overlay mode); once on, names inside the served domains that the table lacks get an
	// authoritative negative answer.
	AuthoritativeKey = "authoritative"
	// DNSVIPKey holds the DNS virtual address and its VRRP id as "address/prefix id"; no row means no DNS VIP.
	DNSVIPKey = "dns_vip"
)

type Settings struct {
	Authoritative bool
	DNSVIP        string
	DNSVIPID      int
}

func settingID(key string) dnsstore.ID {
	sum := sha256.Sum256([]byte("dnshived-dnsstore-setting:" + key))
	var id dnsstore.ID
	copy(id[:], sum[:])
	return id
}

// SettingKey reports which setting a row id belongs to.
func SettingKey(id dnsstore.ID) (string, bool) {
	for _, k := range []string{AuthoritativeKey, DNSVIPKey} {
		if id == settingID(k) {
			return k, true
		}
	}
	return "", false
}

func IsSettingID(id dnsstore.ID) bool { _, ok := SettingKey(id); return ok }

// ParseDNSVIP splits and checks the stored form of the DNS VIP setting.
func ParseDNSVIP(s string) (vip string, vrrpID int, err error) {
	f := strings.Fields(s)
	if len(f) != 2 {
		return "", 0, fmt.Errorf("the DNS VIP needs an address with its prefix and a VRRP id")
	}
	p, err := netip.ParsePrefix(f[0])
	if err != nil || !p.Addr().Is4() || p.Addr().IsUnspecified() || p.Addr().IsMulticast() || p.Addr().IsLoopback() {
		return "", 0, fmt.Errorf("%q is not a usable IPv4 address with a prefix length", f[0])
	}
	id, err := strconv.Atoi(f[1])
	if err != nil || id < 1 || id > 255 {
		return "", 0, fmt.Errorf("the VRRP id must be 1 to 255")
	}
	return p.String(), id, nil
}

func ReadSettings(v *dnsstore.View) Settings {
	var s Settings
	body, _, ok := v.Get(TypeSetting, settingID(AuthoritativeKey))
	s.Authoritative = ok && string(body) == "1"
	if body, _, ok := v.Get(TypeSetting, settingID(DNSVIPKey)); ok {
		if vip, id, err := ParseDNSVIP(string(body)); err == nil {
			s.DNSVIP, s.DNSVIPID = vip, id
		}
	}
	return s
}

func SettingOp(key string, on bool) dnsstore.Op {
	val := "0"
	if on {
		val = "1"
	}
	return dnsstore.Op{Kind: dnsstore.OpPut, Type: TypeSetting, ID: settingID(key), Body: []byte(val)}
}

// DNSVIPOp sets the DNS VIP; an empty vip removes it.
func DNSVIPOp(vip string, vrrpID int) dnsstore.Op {
	if vip == "" {
		return dnsstore.Op{Kind: dnsstore.OpDel, Type: TypeSetting, ID: settingID(DNSVIPKey)}
	}
	return dnsstore.Op{Kind: dnsstore.OpPut, Type: TypeSetting, ID: settingID(DNSVIPKey), Body: []byte(fmt.Sprintf("%s %d", vip, vrrpID))}
}
