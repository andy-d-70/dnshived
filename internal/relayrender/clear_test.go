// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package relayrender

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"dnshived/internal/dhcprelay"
)

func TestClearRelayConfig_EmptiesInterfacesKeepsRateLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.json")
	before := dhcprelay.Config{
		ServerAddr:      "127.0.0.1:67",
		ServerInterface: "lo",
		RateLimit:       7,
		RateBurst:       9,
		ClientInterfaces: []dhcprelay.ClientInterfaceConfig{
			{Name: "eth1.110", Scope: "office"},
		},
	}
	data, _ := json.Marshal(before)
	if err := os.WriteFile(path, data, 0640); err != nil {
		t.Fatal(err)
	}

	if err := ClearRelayConfig(path); err != nil {
		t.Fatal(err)
	}

	var got dhcprelay.Config
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.ClientInterfaces) != 0 {
		t.Fatalf("client interfaces = %v, want none", got.ClientInterfaces)
	}
	if got.RateLimit != 7 || got.RateBurst != 9 {
		t.Fatalf("rate limits = %d/%d, want 7/9", got.RateLimit, got.RateBurst)
	}
}

func TestClearRelayConfig_AlreadyEmptyIsNotRewritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.json")
	data, _ := json.Marshal(dhcprelay.Config{ServerAddr: "127.0.0.1:67"})
	if err := os.WriteFile(path, data, 0640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := ClearRelayConfig(path); err != nil {
		t.Fatal(err)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("already-empty relay.json was rewritten")
	}
}

func TestClearRelayConfig_MissingFileWrittenEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.json")
	if err := ClearRelayConfig(path); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got dhcprelay.Config
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.ClientInterfaces) != 0 {
		t.Fatalf("client interfaces = %v, want none", got.ClientInterfaces)
	}
}
