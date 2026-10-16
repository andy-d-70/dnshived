// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package backupcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	saltBytes        = 16
	nonceBytes       = 12 // AES-GCM's own standard nonce size
	keyBytes         = 32 // AES-256
	pbkdf2Iterations = 600_000

	// blobVersion is the first byte of every blob this package writes.
	blobVersion = 1
)

// ErrWrongPasswordOrCorrupt is returned by Decrypt whenever the blob fails
// to authenticate.
var ErrWrongPasswordOrCorrupt = errors.New("backupcrypt: wrong password, or the backup is corrupted/tampered")

func Encrypt(password string, plaintext []byte) ([]byte, error) {
	if password == "" {
		return nil, errors.New("backupcrypt: empty password")
	}

	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("backupcrypt: generate salt: %w", err)
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, keyBytes)
	if err != nil {
		return nil, fmt.Errorf("backupcrypt: derive key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("backupcrypt: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("backupcrypt: new GCM: %w", err)
	}
	nonce := make([]byte, nonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("backupcrypt: generate nonce: %w", err)
	}

	sealed := gcm.Seal(nil, nonce, plaintext, nil)

	out := make([]byte, 0, 1+4+len(salt)+len(nonce)+len(sealed))
	out = append(out, blobVersion)
	out = binary.BigEndian.AppendUint32(out, pbkdf2Iterations)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

// Decrypt reverses Encrypt.
func Decrypt(password string, blob []byte) ([]byte, error) {
	if len(blob) < 1+4+saltBytes+nonceBytes {
		return nil, errors.New("backupcrypt: blob too short to be valid")
	}
	if blob[0] != blobVersion {
		return nil, fmt.Errorf("backupcrypt: unsupported blob version %d (this build only understands %d)", blob[0], blobVersion)
	}
	pos := 1
	iterations := binary.BigEndian.Uint32(blob[pos : pos+4])
	pos += 4
	salt := blob[pos : pos+saltBytes]
	pos += saltBytes
	nonce := blob[pos : pos+nonceBytes]
	pos += nonceBytes
	sealed := blob[pos:]

	key, err := pbkdf2.Key(sha256.New, password, salt, int(iterations), keyBytes)
	if err != nil {
		return nil, fmt.Errorf("backupcrypt: derive key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("backupcrypt: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("backupcrypt: new GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, ErrWrongPasswordOrCorrupt
	}
	return plaintext, nil
}
