// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package psksign

import "testing"

func TestSignVerify_RoundTrips(t *testing.T) {
	psk := []byte("test-psk")
	sig := Sign(psk, "hello:world:123")
	if !Verify(psk, "hello:world:123", sig) {
		t.Fatal("Verify should accept its own Sign output")
	}
}

func TestVerify_RejectsWrongData(t *testing.T) {
	psk := []byte("test-psk")
	sig := Sign(psk, "hello:world:123")
	if Verify(psk, "hello:world:124", sig) {
		t.Fatal("Verify should reject a signature computed over different data")
	}
}

func TestVerify_RejectsWrongPSK(t *testing.T) {
	sig := Sign([]byte("psk-a"), "hello:world:123")
	if Verify([]byte("psk-b"), "hello:world:123", sig) {
		t.Fatal("Verify should reject a signature computed under a different PSK")
	}
}

func TestVerify_RejectsGarbageSignature(t *testing.T) {
	if Verify([]byte("psk"), "data", "not-a-real-signature") {
		t.Fatal("Verify should reject a malformed signature")
	}
}

func TestSign_DeterministicForSameInput(t *testing.T) {
	psk := []byte("test-psk")
	if Sign(psk, "x") != Sign(psk, "x") {
		t.Fatal("Sign should be deterministic for identical inputs")
	}
}
