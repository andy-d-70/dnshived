// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package arbiter

import (
	"fmt"
	"time"

	"dnshived/internal/psksign"
)

// Token is a scope-ownership proof granted by the arbiter.
type Token struct {
	Scope       string    `json:"scope"`
	Owner       string    `json:"owner"`
	Incarnation uint64    `json:"incarnation"`
	GrantedAt   time.Time `json:"granted_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Nonce       string    `json:"nonce"`
	Signature   string    `json:"signature"`
}

// signData returns the canonical string this token's signature covers.
func (t *Token) signData() string {
	return fmt.Sprintf("%s:%s:%d:%d:%d:%s",
		t.Scope, t.Owner, t.Incarnation,
		t.GrantedAt.Unix(), t.ExpiresAt.Unix(), t.Nonce)
}

// Sign computes the HMAC-SHA256 signature over the token's fields.
func (t *Token) Sign(psk []byte) string {
	return psksign.Sign(psk, t.signData())
}

// Verify checks the token's signature against the given PSK.
func (t *Token) Verify(psk []byte) bool {
	return psksign.Verify(psk, t.signData(), t.Signature)
}

// Expired reports whether the token has passed its expiry time.
func (t *Token) Expired() bool {
	return time.Now().After(t.ExpiresAt)
}
