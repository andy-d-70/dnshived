// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"errors"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	msg := []byte(`{"psk":"secret"}`)
	s, err := Seal("ABCD-EFGH-JKLM-NPQR", PurposeCoreAdopt, msg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(s.Box, []byte("secret")) {
		t.Fatal("plaintext visible in the sealed box")
	}
	got, err := Open("ABCD-EFGH-JKLM-NPQR", PurposeCoreAdopt, s)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("Open = %q, %v; want %q", got, err, msg)
	}
}

func TestOpenRejects(t *testing.T) {
	s, err := Seal("ABCD-EFGH-JKLM-NPQR", PurposeCoreAdopt, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	tampered := s
	tampered.Box = append([]byte(nil), s.Box...)
	tampered.Box[0] ^= 1

	cases := map[string]struct {
		code, purpose string
		s             Sealed
	}{
		"wrong code":    {"ABCD-EFGH-JKLM-NPQS", PurposeCoreAdopt, s},
		"wrong purpose": {"ABCD-EFGH-JKLM-NPQR", PurposeProbeAdopt, s},
		"tampered box":  {"ABCD-EFGH-JKLM-NPQR", PurposeCoreAdopt, tampered},
		"not sealed":    {"ABCD-EFGH-JKLM-NPQR", PurposeCoreAdopt, Sealed{}},
		"bad nonce":     {"ABCD-EFGH-JKLM-NPQR", PurposeCoreAdopt, Sealed{Version: 1, Salt: s.Salt, Nonce: []byte{1}, Box: s.Box}},
	}
	for name, c := range cases {
		if _, err := Open(c.code, c.purpose, c.s); !errors.Is(err, ErrSealOpen) {
			t.Errorf("%s: err = %v, want ErrSealOpen", name, err)
		}
	}
}
