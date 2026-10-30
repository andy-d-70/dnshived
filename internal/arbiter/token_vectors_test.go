// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package arbiter

import (
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"
)

// tests/relay/token-vectors.json holds fixed token vectors generated here. Regenerate with
// DNSHIVED_WRITE_VECTORS=1 go test -run TestWriteTokenVectors.

const vectorFile = "../../tests/relay/token-vectors.json"

const vectorPSK = "test-psk-not-secret"

var vectorNow = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

type tokenVector struct {
	Name   string `json:"name"`
	Token  Token  `json:"token"`
	Valid  bool   `json:"valid"`
	Reason string `json:"reason"`
}

type quorumVector struct {
	Name     string   `json:"name"`
	Arbiters []string `json:"arbiters"`
	Expect   int      `json:"expect"`
}

type vectorFileData struct {
	PSK     string         `json:"psk"`
	Now     string         `json:"now"`
	Vectors []tokenVector  `json:"vectors"`
	Quorum  []quorumVector `json:"quorum"`
}

// relayValid is the relay's check on one token (RELAY_GATE.md §3, checks 1-5 except owner and
// incarnation, which the relay compares with its own state, and scope, compared by the caller).
func relayValid(t Token, psk string, now time.Time) (bool, string) {
	if !t.Verify([]byte(psk)) {
		return false, "signature"
	}
	if !t.ExpiresAt.After(now) {
		return false, "expired"
	}
	if t.ExpiresAt.Sub(now) > 60*time.Second {
		return false, "too far ahead"
	}
	return true, ""
}

func buildVectors() vectorFileData {
	base := func(arbiter string) Token {
		return Token{
			Scope:       "office",
			Owner:       "core-1",
			Incarnation: 7,
			GrantedAt:   vectorNow.Add(-5 * time.Second),
			ExpiresAt:   vectorNow.Add(30 * time.Second),
			Nonce:       "0123456789abcdef",
			Arbiter:     arbiter,
		}
	}
	signed := func(t Token, psk string) Token {
		t.Signature = t.Sign([]byte(psk))
		return t
	}
	var out []tokenVector
	add := func(name string, t Token, valid bool, reason string) {
		out = append(out, tokenVector{Name: name, Token: t, Valid: valid, Reason: reason})
	}

	add("old_form_valid", signed(base(""), vectorPSK), true, "")
	add("new_form_valid", signed(base("arb-core-2"), vectorPSK), true, "")
	add("wrong_psk", signed(base("arb-core-2"), "other-psk"), false, "signature")

	tampers := []struct {
		field  string
		tamper func(*Token)
	}{
		{"scope", func(t *Token) { t.Scope = "dante-" }},
		{"owner", func(t *Token) { t.Owner = "core-2" }},
		{"incarnation", func(t *Token) { t.Incarnation = 8 }},
		{"granted_at", func(t *Token) { t.GrantedAt = t.GrantedAt.Add(time.Second) }},
		{"expires_at", func(t *Token) { t.ExpiresAt = t.ExpiresAt.Add(time.Second) }},
		{"nonce", func(t *Token) { t.Nonce = "fedcba9876543210" }},
		{"arbiter", func(t *Token) { t.Arbiter = "arb-core-3" }},
	}
	for _, tc := range tampers {
		tok := signed(base("arb-core-2"), vectorPSK)
		tc.tamper(&tok)
		add("tampered_"+tc.field, tok, false, "signature")
	}

	stripped := signed(base("arb-core-2"), vectorPSK)
	stripped.Arbiter = ""
	add("arbiter_stripped", stripped, false, "signature")

	expired := base("arb-core-2")
	expired.GrantedAt = vectorNow.Add(-35 * time.Second)
	expired.ExpiresAt = vectorNow.Add(-1 * time.Second)
	add("expired", signed(expired, vectorPSK), false, "expired")

	far := base("arb-core-2")
	far.ExpiresAt = vectorNow.Add(61 * time.Second)
	add("more_than_60s_ahead", signed(far, vectorPSK), false, "too far ahead")

	frac := base("arb-core-2")
	frac.GrantedAt = vectorNow.Add(-5*time.Second + 123456789*time.Nanosecond).In(time.FixedZone("CEST", 2*3600))
	frac.ExpiresAt = vectorNow.Add(30*time.Second + 987654321*time.Nanosecond).In(time.FixedZone("CEST", 2*3600))
	add("nanoseconds_and_zone_offset", signed(frac, vectorPSK), true, "")

	return vectorFileData{
		PSK:     vectorPSK,
		Now:     vectorNow.Format(time.RFC3339),
		Vectors: out,
		Quorum: []quorumVector{
			{Name: "one_arbiter_two_renewals", Arbiters: []string{"arb-core-2", "arb-core-2"}, Expect: 1},
			{Name: "two_arbiters", Arbiters: []string{"arb-core-2", "arb-core-3"}, Expect: 2},
			{Name: "old_form_does_not_count", Arbiters: []string{"", "arb-core-3"}, Expect: 1},
		},
	}
}

func TestWriteTokenVectors(t *testing.T) {
	if os.Getenv("DNSHIVED_WRITE_VECTORS") == "" {
		t.Skip("set DNSHIVED_WRITE_VECTORS=1 to regenerate tests/relay/token-vectors.json")
	}
	data, err := json.MarshalIndent(buildVectors(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vectorFile, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestTokenVectors(t *testing.T) {
	raw, err := os.ReadFile(vectorFile)
	if err != nil {
		t.Fatal(err)
	}
	var file vectorFileData
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339, file.Now)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range file.Vectors {
		valid, reason := relayValid(v.Token, file.PSK, now)
		if valid != v.Valid || reason != v.Reason {
			t.Errorf("%s: got valid=%v reason=%q, want valid=%v reason=%q", v.Name, valid, reason, v.Valid, v.Reason)
		}
	}
	for _, q := range file.Quorum {
		distinct := map[string]bool{}
		for _, a := range q.Arbiters {
			if a != "" {
				distinct[a] = true
			}
		}
		if len(distinct) != q.Expect {
			t.Errorf("%s: %d distinct arbiters, want %d", q.Name, len(distinct), q.Expect)
		}
	}
}

func TestArbiterFieldIsSignedWhenSet(t *testing.T) {
	old := Token{Scope: "s", Owner: "o", Incarnation: 1, GrantedAt: vectorNow, ExpiresAt: vectorNow, Nonce: "n"}
	if old.signData() != "s:o:1:"+strconv.FormatInt(vectorNow.Unix(), 10)+":"+strconv.FormatInt(vectorNow.Unix(), 10)+":n" {
		t.Fatalf("old form changed: %q", old.signData())
	}
	withArb := old
	withArb.Arbiter = "arb"
	if withArb.signData() != old.signData()+":arb" {
		t.Fatalf("arbiter not appended: %q", withArb.signData())
	}
}
