// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

// Purposes bind a sealed push to its receiver, so a core push cannot be replayed to a probe.
const (
	PurposeCoreAdopt  = "core-adopt"
	PurposeProbeAdopt = "probe-adopt"
)

const sealVersion = 1

var ErrSealOpen = errors.New("sealed push does not open with this join code")

// Sealed is the wire form of a push encrypted with a key derived from the receiver's join code.
type Sealed struct {
	Version int    `json:"sealed_v,omitempty"`
	Salt    []byte `json:"salt,omitempty"`
	Nonce   []byte `json:"nonce,omitempty"`
	Box     []byte `json:"box,omitempty"`
}

func (s Sealed) IsSealed() bool { return s.Version != 0 }

func sealKey(code string, salt []byte, purpose string) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, []byte(code), salt, "dnshived-"+purpose, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func Seal(code, purpose string, plaintext []byte) (Sealed, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return Sealed{}, err
	}
	aead, err := sealKey(code, salt, purpose)
	if err != nil {
		return Sealed{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Sealed{}, err
	}
	return Sealed{
		Version: sealVersion,
		Salt:    salt,
		Nonce:   nonce,
		Box:     aead.Seal(nil, nonce, plaintext, []byte(purpose)),
	}, nil
}

func Open(code, purpose string, s Sealed) ([]byte, error) {
	if s.Version != sealVersion || len(s.Salt) == 0 {
		return nil, ErrSealOpen
	}
	aead, err := sealKey(code, s.Salt, purpose)
	if err != nil {
		return nil, err
	}
	if len(s.Nonce) != aead.NonceSize() {
		return nil, ErrSealOpen
	}
	out, err := aead.Open(nil, s.Nonce, s.Box, []byte(purpose))
	if err != nil {
		return nil, ErrSealOpen
	}
	return out, nil
}
