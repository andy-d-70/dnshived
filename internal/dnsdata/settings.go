// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsdata

import (
	"crypto/sha256"
	"strconv"

	"dnshived/internal/dnsstore"
)

// TypeSetting is the row type of cluster-wide DNS store settings; the rows replicate like any other row.
const TypeSetting uint8 = 3

const (
	// AuthoritativeKey names the cutover setting: while it is off the table answers only the records it holds and
	// forwards everything else (overlay mode); once on, names inside the served domains that the table lacks get an
	// authoritative negative answer.
	AuthoritativeKey = "authoritative"
	// DefaultTTLKey names the TTL of every record without its own TTL and of reservation and lease names, in seconds as
	// decimal text. Without the row it is 0, the TTL the central dnsmasq gives its local data.
	DefaultTTLKey = "default_ttl"
)

var settingKeys = []string{AuthoritativeKey, DefaultTTLKey}

type Settings struct {
	Authoritative bool
	DefaultTTL    uint32
}

func settingID(key string) dnsstore.ID {
	sum := sha256.Sum256([]byte("dnshived-dnsstore-setting:" + key))
	var id dnsstore.ID
	copy(id[:], sum[:])
	return id
}

// SettingKey reports which setting a row id belongs to.
func SettingKey(id dnsstore.ID) (string, bool) {
	for _, k := range settingKeys {
		if id == settingID(k) {
			return k, true
		}
	}
	return "", false
}

func IsSettingID(id dnsstore.ID) bool { _, ok := SettingKey(id); return ok }

func ReadSettings(v *dnsstore.View) Settings {
	var s Settings
	body, _, ok := v.Get(TypeSetting, settingID(AuthoritativeKey))
	s.Authoritative = ok && string(body) == "1"
	if body, _, ok := v.Get(TypeSetting, settingID(DefaultTTLKey)); ok {
		s.DefaultTTL, _ = parseTTLSetting(body)
	}
	return s
}

// parseTTLSetting accepts only the canonical decimal form, so every core stores and compares the same bytes.
func parseTTLSetting(b []byte) (uint32, bool) {
	v, err := strconv.ParseUint(string(b), 10, 32)
	if err != nil || v > maxTTL || strconv.FormatUint(v, 10) != string(b) {
		return 0, false
	}
	return uint32(v), true
}

func DefaultTTLOp(ttl uint32) dnsstore.Op {
	return dnsstore.Op{Kind: dnsstore.OpPut, Type: TypeSetting, ID: settingID(DefaultTTLKey), Body: strconv.AppendUint(nil, uint64(ttl), 10)}
}

func SettingOp(key string, on bool) dnsstore.Op {
	val := "0"
	if on {
		val = "1"
	}
	return dnsstore.Op{Kind: dnsstore.OpPut, Type: TypeSetting, ID: settingID(key), Body: []byte(val)}
}
