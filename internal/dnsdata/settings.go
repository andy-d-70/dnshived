// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsdata

import (
	"crypto/sha256"

	"dnshived/internal/dnsstore"
)

// TypeSetting is the row type of cluster-wide DNS store settings; the rows replicate like any other row.
const TypeSetting uint8 = 3

const (
	// AuthoritativeKey names the cutover setting: while it is off the table answers only the records it holds and
	// forwards everything else (overlay mode); once on, names inside the served domains that the table lacks get an
	// authoritative negative answer.
	AuthoritativeKey = "authoritative"
)

type Settings struct {
	Authoritative bool
}

func settingID(key string) dnsstore.ID {
	sum := sha256.Sum256([]byte("dnshived-dnsstore-setting:" + key))
	var id dnsstore.ID
	copy(id[:], sum[:])
	return id
}

// SettingKey reports which setting a row id belongs to.
func SettingKey(id dnsstore.ID) (string, bool) {
	for _, k := range []string{AuthoritativeKey} {
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
	return s
}

func SettingOp(key string, on bool) dnsstore.Op {
	val := "0"
	if on {
		val = "1"
	}
	return dnsstore.Op{Kind: dnsstore.OpPut, Type: TypeSetting, ID: settingID(key), Body: []byte(val)}
}
