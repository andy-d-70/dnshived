// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package webauth

import (
	"testing"

	"dnshived/internal/notify"
)

func TestNotifySettings_DefaultCopyAndHash(t *testing.T) {
	s := &Store{}
	before := s.Meta().Hash
	if got := s.NotifySettings(); got.Summary.Interval != "daily" || len(got.Destinations) != 0 {
		t.Fatalf("defaults %+v", got)
	}
	if s.Meta().Hash != before {
		t.Fatal("reading the settings must not change the document")
	}

	n := notify.Default()
	n.Destinations = []notify.Destination{{ID: "a", Name: "Ops", Kind: notify.KindEmail, Address: "ops@example.org"}}
	if err := s.Mutate("core-1", func(d *Store) error { d.Notify = &n; return nil }); err != nil {
		t.Fatal(err)
	}
	if s.Meta().Hash == before {
		t.Fatal("saved notify settings must change the replicated hash")
	}

	got := s.NotifySettings()
	got.Destinations[0].Name = "tampered"
	if s.NotifySettings().Destinations[0].Name != "Ops" {
		t.Fatal("the getter must hand out a copy")
	}

	other := &Store{}
	other.replaceWith(s)
	if other.Meta().Hash != s.Meta().Hash || len(other.NotifySettings().Destinations) != 1 {
		t.Fatal("the settings travel with the replicated document")
	}
}
