// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"crypto/hmac"
	"crypto/sha256"
)

// vrrpPassword derives keepalived's PASS password for one VRRP instance from the cluster PSK.
// VRRP limits the password to eight characters, so the result is eight characters from a 62-symbol alphabet.
func vrrpPassword(psk, instance string) string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	okm := hkdfSHA256([]byte(psk), []byte("dnshived vrrp auth"), []byte(instance), 8)
	out := make([]byte, len(okm))
	for i, b := range okm {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(out)
}

// hkdfSHA256 is RFC 5869 extract-and-expand with SHA-256, for n <= 32 bytes.
func hkdfSHA256(ikm, salt, info []byte, n int) []byte {
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}
	ext := hmac.New(sha256.New, salt)
	ext.Write(ikm)
	prk := ext.Sum(nil)
	exp := hmac.New(sha256.New, prk)
	exp.Write(info)
	exp.Write([]byte{1})
	return exp.Sum(nil)[:n]
}
