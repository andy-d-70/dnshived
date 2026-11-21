// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package leasesync

import (
	"encoding/json"
	"testing"
)

func TestStore_RenewalKeepsTheFirstLeaseTime(t *testing.T) {
	s := NewStore()
	s.Upsert(SyncedLease{MAC: "aa", IP: "10.0.0.5", LeasedAt: 100})
	s.Upsert(SyncedLease{MAC: "aa", IP: "10.0.0.5", ExpiresAt: 900, LeasedAt: 500})
	if l, _ := s.Get("aa"); l.LeasedAt != 100 || l.ExpiresAt != 900 {
		t.Fatalf("a renewal must keep the first lease time: %+v", l)
	}
	s.Upsert(SyncedLease{MAC: "aa", IP: "10.0.0.5"})
	if l, _ := s.Get("aa"); l.LeasedAt != 100 {
		t.Fatalf("an update without a lease time keeps the known one: %+v", l)
	}
	s.Upsert(SyncedLease{MAC: "aa", IP: "10.0.0.6", LeasedAt: 700})
	if l, _ := s.Get("aa"); l.LeasedAt != 700 {
		t.Fatalf("a new address is a new lease: %+v", l)
	}
	s.Upsert(SyncedLease{MAC: "bb", IP: "10.0.0.7"})
	if l, _ := s.Get("bb"); l.LeasedAt != 0 {
		t.Fatalf("unknown stays unknown: %+v", l)
	}
	if _, ok := s.Get("zz"); ok {
		t.Fatal("no such entry")
	}
}

func TestWire_OlderPeersIgnoreTheNewField(t *testing.T) {
	b, _ := json.Marshal(wireMessage{Action: "upsert", MAC: "aa", IP: "10.0.0.5", LeasedAt: 42})
	var old struct {
		Action    string `json:"action"`
		MAC       string `json:"mac"`
		IP        string `json:"ip,omitempty"`
		ExpiresAt int64  `json:"expires_at,omitempty"`
		Hostname  string `json:"hostname,omitempty"`
	}
	if err := json.Unmarshal(b, &old); err != nil || old.MAC != "aa" {
		t.Fatalf("an older core must still read the message: %v", err)
	}
	var back wireMessage
	if err := json.Unmarshal(b, &back); err != nil || back.LeasedAt != 42 {
		t.Fatalf("round trip: %+v %v", back, err)
	}
}
