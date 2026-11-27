// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package webauth

import (
	"bytes"
	"testing"

	"dnshived/internal/notify"
)

func TestItems_RoundTripKeepsEveryFieldAndOrder(t *testing.T) {
	n := notify.Default()
	s := &Store{
		SessionKey: "k", PublicURL: "https://ui.example.org", MinPasswordLength: 14,
		Users:  []User{{Name: "zed", Role: "admin", PasswordHash: "h1"}, {Name: "amy", Role: "readonly", PasswordHash: "h2", Disabled: true, SessionEpoch: 3}},
		Resets: []ResetToken{{User: "amy", Hash: "r1", Expires: "2026-11-28T00:00:00Z"}},
		SMTP:   &SMTPSettings{Host: "mail.example.org", Port: 587, Security: "starttls", Password: "secret", From: "ui@example.org"},
		Notify: &n,
	}
	items, err := s.Items()
	if err != nil {
		t.Fatal(err)
	}
	back, err := s.WithItems(items)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := s.Marshal()
	b, _ := back.Marshal()
	if !bytes.Equal(a, b) {
		t.Fatalf("items rebuild the same document:\n%s\nvs\n%s", a, b)
	}
	delete(items, "user/zed")
	items["user/bea"] = []byte(`{"name":"bea","password_hash":"h3","role":"admin"}`)
	next, err := s.WithItems(items)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Users) != 2 || next.Users[0].Name != "amy" || next.Users[1].Name != "bea" {
		t.Fatalf("kept users keep their order, new ones follow: %+v", next.Users)
	}
	items["user/eve"] = []byte(`{"name":"mallory"}`)
	if _, err := s.WithItems(items); err == nil {
		t.Fatal("an item whose content names another user is refused")
	}
}
