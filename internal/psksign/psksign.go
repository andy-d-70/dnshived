// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package psksign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Sign computes the HMAC-SHA256 of data keyed by psk, hex-encoded.
func Sign(psk []byte, data string) string {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify reports whether signature is the correct HMAC-SHA256 of data
// under psk, using a constant-time comparison.
func Verify(psk []byte, data, signature string) bool {
	return hmac.Equal([]byte(Sign(psk, data)), []byte(signature))
}
