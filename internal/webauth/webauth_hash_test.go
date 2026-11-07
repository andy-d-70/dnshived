// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package webauth

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func hashOfSizes(saltBytes int, iterations string, keyBytes int) string {
	return strings.Repeat("ab", saltBytes) + ":" + iterations + ":" + strings.Repeat("cd", keyBytes)
}

func TestValidPasswordHash_Shapes(t *testing.T) {
	written, err := HashPassword("a good password")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		stored string
		want   bool
	}{
		{"what HashPassword writes", written, true},
		{"smallest sizes", hashOfSizes(16, "1", 1), true},
		{"largest sizes", hashOfSizes(64, "1200000", 64), true},
		{"salt one byte short", hashOfSizes(15, "600000", 32), false},
		{"salt one byte long", hashOfSizes(65, "600000", 32), false},
		{"salt not hex", "zz" + strings.Repeat("ab", 15) + ":600000:" + strings.Repeat("cd", 32), false},
		{"empty salt", ":600000:" + strings.Repeat("cd", 32), false},
		{"rounds zero", hashOfSizes(16, "0", 32), false},
		{"rounds one above the cap", hashOfSizes(16, "1200001", 32), false},
		{"rounds in the billions", hashOfSizes(16, "4000000000", 32), false},
		{"rounds negative", hashOfSizes(16, "-5", 32), false},
		{"rounds not digits", hashOfSizes(16, "abc", 32), false},
		{"empty key", strings.Repeat("ab", 16) + ":600000:", false},
		{"key one byte long", hashOfSizes(16, "600000", 65), false},
		{"key not hex", strings.Repeat("ab", 16) + ":600000:xyz", false},
		{"two parts", strings.Repeat("ab", 16) + ":600000", false},
		{"extra part", hashOfSizes(16, "600000", 32) + ":more", false},
		{"empty string", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidPasswordHash(tt.stored); got != tt.want {
				t.Errorf("ValidPasswordHash = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifyPassword_HugeRoundCountIsRefusedWithoutDerivingAKey(t *testing.T) {
	stored := hashOfSizes(16, "4000000000", 32)
	if VerifyPassword("anything", stored) {
		t.Fatal("hash accepted")
	}
	s := &Store{Users: []User{{Name: "u", PasswordHash: stored, Role: RoleAdmin}}}
	if _, ok := s.Verify("u", "anything"); ok {
		t.Fatal("login accepted with an out-of-bounds hash")
	}
}

func TestVerifyPassword_ReadsEverySizeInsideTheRanges(t *testing.T) {
	tests := []struct {
		name       string
		saltBytes  int
		iterations int
		keyBytes   int
	}{
		{"shorter key and fewer rounds", 16, 100_000, 20},
		{"longest salt", 64, 1_000, 32},
		{"exactly the round cap", 16, maxPBKDF2Iterations, 32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			salt := make([]byte, tt.saltBytes)
			key, err := pbkdf2.Key(sha256.New, "correct-password", salt, tt.iterations, tt.keyBytes)
			if err != nil {
				t.Fatal(err)
			}
			stored := fmt.Sprintf("%s:%d:%s", hex.EncodeToString(salt), tt.iterations, hex.EncodeToString(key))
			if !VerifyPassword("correct-password", stored) {
				t.Error("correct password refused")
			}
			if VerifyPassword("wrong-password", stored) {
				t.Error("wrong password accepted")
			}
		})
	}
}
