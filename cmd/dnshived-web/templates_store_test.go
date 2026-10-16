// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTemplates_MissingFileSeedsDDMNMOSNDI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "web-templates.json")
	s, err := LoadTemplates(path)
	if err != nil {
		t.Fatalf("LoadTemplates on missing file should not error, got: %v", err)
	}
	dns := s.ByKind(TemplateKindDNS)
	if len(dns) != 3 {
		t.Fatalf("expected 3 seeded DNS templates, got %d: %+v", len(dns), dns)
	}
	names := map[string]bool{}
	for _, tpl := range dns {
		names[tpl.Name] = true
		if tpl.Color == "" {
			t.Errorf("seeded template %q has no color", tpl.Name)
		}
		if tpl.Body == "" {
			t.Errorf("seeded template %q has no body", tpl.Name)
		}
	}
	for _, want := range []string{"ddm", "nmos", "ndi"} {
		if !names[want] {
			t.Errorf("expected a seeded template named %q, got names: %v", want, names)
		}
	}
	if dhcp := s.ByKind(TemplateKindDHCP); len(dhcp) != 0 {
		t.Errorf("expected no seeded DHCP templates, got %d", len(dhcp))
	}
}

func TestLoadTemplates_CorruptFileErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "web-templates.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadTemplates(path); err == nil {
		t.Error("expected an error loading a corrupt templates file, got nil")
	}
}

func TestTemplateStore_SaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "web-templates.json")
	s := &TemplateStore{}
	id := s.Upsert("", "dante", "#4363d8", TemplateKindDHCP, "6,8.8.8.8\n66,192.168.1.1")
	if id != "dante" {
		t.Errorf("expected slugified id %q, got %q", "dante", id)
	}
	if err := s.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	reloaded, err := LoadTemplates(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got, ok := reloaded.Get("dante")
	if !ok {
		t.Fatal("expected template \"dante\" to survive a save/reload round trip")
	}
	if got.Body != "6,8.8.8.8\n66,192.168.1.1" || got.Color != "#4363d8" || got.Kind != TemplateKindDHCP {
		t.Errorf("round-tripped template mismatch: %+v", got)
	}
}

func TestTemplateStore_UpsertByIDEditsInPlaceNoDuplicate(t *testing.T) {
	s := &TemplateStore{}
	id := s.Upsert("", "avb", "#3cb44b", TemplateKindDHCP, "60,AVB")
	s.Upsert(id, "avb", "#3cb44b", TemplateKindDHCP, "60,AVB-v2")
	all := s.ByKind(TemplateKindDHCP)
	if len(all) != 1 {
		t.Fatalf("editing an existing template by its own id must not create a duplicate, got %d rows: %+v", len(all), all)
	}
	if all[0].Body != "60,AVB-v2" {
		t.Errorf("expected the edit to apply, got body %q", all[0].Body)
	}
}

func TestTemplateStore_UpsertNameCollisionGetsSuffixedID(t *testing.T) {
	s := &TemplateStore{}
	first := s.Upsert("", "dante", "#000", TemplateKindDHCP, "a")
	second := s.Upsert("", "dante", "#000", TemplateKindDNS, "A|x.lan|1.2.3.4")
	if first == second {
		t.Fatalf("two templates named identically must not collide on the same id, got %q and %q", first, second)
	}
	if _, ok := s.Get(first); !ok {
		t.Errorf("original template %q lost after a name-colliding second insert", first)
	}
	if _, ok := s.Get(second); !ok {
		t.Errorf("second template %q not found", second)
	}
}

func TestTemplateStore_Delete(t *testing.T) {
	s := &TemplateStore{}
	id := s.Upsert("", "temp", "#000", TemplateKindDNS, "A|x.lan|1.2.3.4")
	s.Delete(id)
	if _, ok := s.Get(id); ok {
		t.Error("expected template to be gone after Delete")
	}
	// Deleting again (already gone) must not panic — idempotent.
	s.Delete(id)
}

func TestTemplateStore_ByKindSortedByName(t *testing.T) {
	s := &TemplateStore{}
	s.Upsert("", "zeta", "#000", TemplateKindDHCP, "1,1.1.1.1")
	s.Upsert("", "alpha", "#000", TemplateKindDHCP, "2,2.2.2.2")
	rows := s.ByKind(TemplateKindDHCP)
	if len(rows) != 2 || rows[0].Name != "alpha" || rows[1].Name != "zeta" {
		t.Errorf("expected ByKind sorted by name (alpha, zeta), got %+v", rows)
	}
}

func TestOptionSet_UpsertGetSortedDelete(t *testing.T) {
	s := &TemplateStore{}
	id := s.UpsertOptionSet("", "Dante", "#f58231", map[TemplateKind]string{
		TemplateKindDHCP: "dante-dhcp", TemplateKindClientDNS: "dante-cdns",
	})
	if id != "dante" {
		t.Fatalf("expected slugified id %q, got %q", "dante", id)
	}
	got, ok := s.OptionSetByID(id)
	if !ok {
		t.Fatalf("OptionSetByID(%q) not found after Upsert", id)
	}
	if got.Name != "Dante" || got.TemplateRefs[TemplateKindDHCP] != "dante-dhcp" || got.TemplateRefs[TemplateKindClientDNS] != "dante-cdns" {
		t.Errorf("unexpected OptionSet after Upsert: %+v", got)
	}

	// Second Upsert under the same id overwrites, not duplicates.
	s.UpsertOptionSet(id, "Dante v2", "#000000", map[TemplateKind]string{TemplateKindDNS: "dante-dns"})
	if len(s.SortedOptionSets()) != 1 {
		t.Fatalf("expected exactly 1 option set after overwrite-Upsert, got %d", len(s.SortedOptionSets()))
	}
	got2, _ := s.OptionSetByID(id)
	if got2.Name != "Dante v2" || got2.TemplateRefs[TemplateKindDHCP] != "" {
		t.Errorf("expected overwrite to fully replace the set, got: %+v", got2)
	}

	s.UpsertOptionSet("", "AVB", "#0000ff", nil)
	sorted := s.SortedOptionSets()
	if len(sorted) != 2 || sorted[0].Name != "AVB" {
		t.Errorf("expected 2 sets sorted by name (AVB, Dante v2), got: %+v", sorted)
	}

	s.DeleteOptionSet(id)
	if _, ok := s.OptionSetByID(id); ok {
		t.Errorf("expected %q gone after DeleteOptionSet", id)
	}
	s.DeleteOptionSet("does-not-exist") // must not panic
}

func TestScopeGroup_UpsertGetSortedDelete(t *testing.T) {
	s := &TemplateStore{}
	id := s.UpsertScopeGroup("", "Dante", "#f58231", []string{"office", "lab"}, "template:dhcp1")
	if id != "dante" {
		t.Fatalf("expected slugified id %q, got %q", "dante", id)
	}
	got, ok := s.ScopeGroupByID(id)
	if !ok {
		t.Fatalf("ScopeGroupByID(%q) not found after Upsert", id)
	}
	if got.Name != "Dante" || len(got.Members) != 2 || got.AssignedSource != "template:dhcp1" {
		t.Errorf("unexpected ScopeGroup after Upsert: %+v", got)
	}

	s.UpsertScopeGroup(id, "Dante v2", "#000000", []string{"office"}, "")
	if len(s.SortedScopeGroups()) != 1 {
		t.Fatalf("expected exactly 1 group after overwrite-Upsert, got %d", len(s.SortedScopeGroups()))
	}
	got2, _ := s.ScopeGroupByID(id)
	if got2.Name != "Dante v2" || len(got2.Members) != 1 || got2.AssignedSource != "" {
		t.Errorf("expected overwrite to fully replace the group, got: %+v", got2)
	}

	s.UpsertScopeGroup("", "AVB", "#0000ff", nil, "")
	sorted := s.SortedScopeGroups()
	if len(sorted) != 2 || sorted[0].Name != "AVB" {
		t.Errorf("expected 2 groups sorted by name (AVB, Dante v2), got: %+v", sorted)
	}

	s.DeleteScopeGroup(id)
	if _, ok := s.ScopeGroupByID(id); ok {
		t.Errorf("expected %q gone after DeleteScopeGroup", id)
	}
	s.DeleteScopeGroup("does-not-exist") // must not panic
}
