// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package backupcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"testing"
)

func sealWith(t *testing.T, password string, iterations uint32, plaintext []byte) []byte {
	t.Helper()
	salt := make([]byte, saltBytes)
	nonce := make([]byte, nonceBytes)
	key, err := pbkdf2.Key(sha256.New, password, salt, int(iterations), keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	out := []byte{blobVersion}
	out = binary.BigEndian.AppendUint32(out, iterations)
	out = append(out, salt...)
	out = append(out, nonce...)
	return append(out, gcm.Seal(nil, nonce, plaintext, nil)...)
}

func TestDecrypt_IterationCountOutsideTheRangeRejected(t *testing.T) {
	tests := []struct {
		name       string
		iterations uint32
	}{
		{"zero", 0},
		{"one above the cap", maxIterations + 1},
		{"largest possible", math.MaxUint32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blob := []byte{blobVersion}
			blob = binary.BigEndian.AppendUint32(blob, tt.iterations)
			blob = append(blob, make([]byte, saltBytes+nonceBytes+32)...)
			_, err := Decrypt("any password", blob)
			if err == nil {
				t.Fatal("blob accepted")
			}
			if errors.Is(err, ErrWrongPasswordOrCorrupt) {
				t.Errorf("rejected as a wrong password, not before key derivation: %v", err)
			}
		})
	}
}

func TestDecrypt_ReadsEveryCountInsideTheRange(t *testing.T) {
	tests := []struct {
		name       string
		iterations uint32
	}{
		{"one", 1},
		{"older, lower count", 100_000},
		{"exactly the cap", maxIterations},
	}
	plaintext := []byte("backup content")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decrypt("a good password", sealWith(t, "a good password", tt.iterations, plaintext))
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Errorf("got %q, want %q", got, plaintext)
			}
		})
	}
}
