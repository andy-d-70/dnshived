// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package probepin

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// AdoptProof authenticates the fingerprint a probe host reports when it is
// adopted: only a holder of the join code can produce it, so the fingerprint
// is not taken on trust from an unauthenticated reply.
func AdoptProof(otp, fingerprint string) string {
	key := sha256.Sum256([]byte("dnshived-probe-tls-proof|" + otp))
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(fingerprint))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyAdoptProof reports whether proof is AdoptProof(otp, fingerprint).
func VerifyAdoptProof(otp, fingerprint, proof string) bool {
	want, err := hex.DecodeString(AdoptProof(otp, fingerprint))
	if err != nil {
		return false
	}
	got, err := hex.DecodeString(proof)
	if err != nil {
		return false
	}
	return hmac.Equal(want, got)
}

// TokenProof authenticates a probe host's certificate fingerprint with one of
// its API tokens, bound to a nonce the asker chose. The token never leaves
// either side: the holder of the same token can recompute and compare.
func TokenProof(token, fingerprint, nonce string) string {
	key := sha256.Sum256([]byte("dnshived-probe-token-proof|" + token))
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(fingerprint + "|" + nonce))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyTokenProof reports whether proof is TokenProof(token, fingerprint, nonce).
func VerifyTokenProof(token, fingerprint, nonce, proof string) bool {
	want, err := hex.DecodeString(TokenProof(token, fingerprint, nonce))
	if err != nil {
		return false
	}
	got, err := hex.DecodeString(proof)
	if err != nil {
		return false
	}
	return hmac.Equal(want, got)
}
