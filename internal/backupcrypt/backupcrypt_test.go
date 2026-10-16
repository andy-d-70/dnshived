// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package backupcrypt

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	plaintext := []byte(`{"cluster_id":"lab01","psk":"deadbeef"}`)
	blob, err := Encrypt("a good password", plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := Decrypt("a good password", blob)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round trip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestDecrypt_WrongPasswordRejected(t *testing.T) {
	blob, err := Encrypt("correct-password", []byte("secret content"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	_, err = Decrypt("wrong-password", blob)
	if !errors.Is(err, ErrWrongPasswordOrCorrupt) {
		t.Errorf("Decrypt with wrong password: err = %v, want ErrWrongPasswordOrCorrupt", err)
	}
}

// TestDecrypt_TamperedCiphertextRejected confirms AES-GCM's own
// authentication actually catches a single flipped byte, not just a wrong
// password.
func TestDecrypt_TamperedCiphertextRejected(t *testing.T) {
	blob, err := Encrypt("correct-password", []byte("secret content"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)-1] ^= 0xFF // flip the last byte of the sealed ciphertext/tag

	_, err = Decrypt("correct-password", tampered)
	if !errors.Is(err, ErrWrongPasswordOrCorrupt) {
		t.Errorf("Decrypt with tampered blob: err = %v, want ErrWrongPasswordOrCorrupt", err)
	}
}

// TestEncrypt_SamePlaintextProducesDifferentCiphertext pins the fresh-
// salt-and-nonce-per-call contract.
func TestEncrypt_SamePlaintextProducesDifferentCiphertext(t *testing.T) {
	plaintext := []byte("identical content, encrypted twice")
	blob1, err := Encrypt("pw", plaintext)
	if err != nil {
		t.Fatalf("Encrypt 1: %v", err)
	}
	blob2, err := Encrypt("pw", plaintext)
	if err != nil {
		t.Fatalf("Encrypt 2: %v", err)
	}
	if bytes.Equal(blob1, blob2) {
		t.Error("two encryptions of the same plaintext/password produced identical blobs — salt/nonce not actually fresh per call")
	}
	// Both must still decrypt correctly despite differing.
	for i, blob := range [][]byte{blob1, blob2} {
		got, err := Decrypt("pw", blob)
		if err != nil {
			t.Fatalf("Decrypt blob%d: %v", i+1, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("blob%d round trip mismatch", i+1)
		}
	}
}

func TestDecrypt_TooShortBlobRejected(t *testing.T) {
	_, err := Decrypt("pw", []byte("short"))
	if err == nil {
		t.Error("expected an error decrypting a too-short blob, got nil")
	}
}

func TestDecrypt_UnsupportedVersionRejected(t *testing.T) {
	blob, err := Encrypt("pw", []byte("content"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	blob[0] = 99 // corrupt the version tag
	_, err = Decrypt("pw", blob)
	if err == nil {
		t.Error("expected an error decrypting a blob with an unsupported version tag, got nil")
	}
}

func TestEncrypt_EmptyPasswordRejected(t *testing.T) {
	_, err := Encrypt("", []byte("content"))
	if err == nil {
		t.Error("expected an error encrypting with an empty password, got nil")
	}
}

// TestEncryptDecrypt_EmptyPlaintextRoundTrips confirms an edge case that
// matters for real use.
func TestEncryptDecrypt_EmptyPlaintextRoundTrips(t *testing.T) {
	blob, err := Encrypt("pw", []byte{})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := Decrypt("pw", blob)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty plaintext, got %q", got)
	}
}
