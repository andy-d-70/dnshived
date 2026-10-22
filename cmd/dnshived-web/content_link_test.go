// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"testing"

	"dnshived/internal/config"
)

func storeWithTemplates(t *testing.T) *TemplateStore {
	t.Helper()
	s := &TemplateStore{}
	s.Upsert("dhcp1", "dhcp1", "#111111", TemplateKindDHCP, "option:ntp-server,10.0.0.1")
	s.Upsert("dns1", "dns1", "#222222", TemplateKindDNS, "A|nas.dante.lan|10.0.0.50")
	s.Upsert("cdns1", "cdns1", "#444444", TemplateKindClientDNS, "172.17.42.1")
	return s
}

func TestResolveContentLink_BareTemplate(t *testing.T) {
	s := storeWithTemplates(t)
	body, ok := resolveContentLink(config.ContentLink{Kind: ContentLinkKindTemplate, SourceID: "dhcp1"}, TemplateKindDHCP, s)
	if !ok || body != "option:ntp-server,10.0.0.1" {
		t.Errorf("resolveContentLink template = %q, %v", body, ok)
	}
}

func TestResolveContentLink_TemplateKindMismatchFails(t *testing.T) {
	s := storeWithTemplates(t)
	_, ok := resolveContentLink(config.ContentLink{Kind: ContentLinkKindTemplate, SourceID: "dhcp1"}, TemplateKindDNS, s)
	if ok {
		t.Error("expected resolveContentLink to fail when the linked template's own Kind doesn't match the field's required kind")
	}
}

func TestResolveContentLink_OptionSet(t *testing.T) {
	s := storeWithTemplates(t)
	id := s.UpsertOptionSet("", "Dante", "#000", map[TemplateKind]string{
		TemplateKindDHCP: "dhcp1",
	})
	body, ok := resolveContentLink(config.ContentLink{Kind: ContentLinkKindOptionSet, SourceID: id}, TemplateKindDHCP, s)
	if !ok || body != "option:ntp-server,10.0.0.1" {
		t.Errorf("resolveContentLink optionset/dhcp = %q, %v", body, ok)
	}
	// A kind the set never referenced must not resolve.
	if _, ok := resolveContentLink(config.ContentLink{Kind: ContentLinkKindOptionSet, SourceID: id}, TemplateKindDNS, s); ok {
		t.Error("expected no resolution for a kind the option set never referenced")
	}
}

func TestResolveContentLink_DanglingReferencesFail(t *testing.T) {
	s := storeWithTemplates(t)
	if _, ok := resolveContentLink(config.ContentLink{Kind: ContentLinkKindTemplate, SourceID: "no-such-template"}, TemplateKindDHCP, s); ok {
		t.Error("expected a dangling template reference to fail resolution")
	}
	if _, ok := resolveContentLink(config.ContentLink{Kind: ContentLinkKindOptionSet, SourceID: "no-such-set"}, TemplateKindDHCP, s); ok {
		t.Error("expected a dangling option-set reference to fail resolution")
	}
	if _, ok := resolveContentLink(config.ContentLink{Kind: "bogus", SourceID: "x"}, TemplateKindDHCP, s); ok {
		t.Error("expected an unknown link Kind to fail resolution")
	}
}

func TestPropagateLinkedScopes_ResolvesEveryFieldKind(t *testing.T) {
	s := storeWithTemplates(t)
	id := s.UpsertOptionSet("", "Dante", "#000", map[TemplateKind]string{
		TemplateKindDHCP: "dhcp1",
	})
	scopes := map[string]config.ScopeConfig{
		"rw-1": {
			ContentLinks: map[string]config.ContentLink{
				"dhcp_options":      {Kind: ContentLinkKindOptionSet, SourceID: id},
				"dns_records":       {Kind: ContentLinkKindTemplate, SourceID: "dns1"},
				"client_dns_server": {Kind: ContentLinkKindTemplate, SourceID: "cdns1"},
			},
		},
	}
	updated, changed := propagateLinkedScopes(scopes, s)
	if !changed {
		t.Fatal("expected propagateLinkedScopes to report a change")
	}
	got := updated["rw-1"]
	if len(got.DHCPOptions) != 1 || got.DHCPOptions[0] != "option:ntp-server,10.0.0.1" {
		t.Errorf("DHCPOptions = %v", got.DHCPOptions)
	}
	if len(got.DNSRecords) != 1 || got.DNSRecords[0].Name != "nas.dante.lan" {
		t.Errorf("DNSRecords = %+v", got.DNSRecords)
	}
	if got.ClientDNSServer != "172.17.42.1" {
		t.Errorf("ClientDNSServer = %q", got.ClientDNSServer)
	}
}

// TestPropagateLinkedScopes_DanglingLinkLeavesFieldUntouched checks a link
// that no longer resolves leaves the field as it is.
func TestPropagateLinkedScopes_DanglingLinkLeavesFieldUntouched(t *testing.T) {
	s := storeWithTemplates(t)
	scopes := map[string]config.ScopeConfig{
		"rw-1": {
			DHCPOptions: []string{"option:66,192.0.2.5"},
			ContentLinks: map[string]config.ContentLink{
				"dhcp_options": {Kind: ContentLinkKindTemplate, SourceID: "deleted-template"},
			},
		},
	}
	updated, changed := propagateLinkedScopes(scopes, s)
	if changed {
		t.Error("expected no change when the only link present is dangling")
	}
	if got := updated["rw-1"].DHCPOptions; len(got) != 1 || got[0] != "option:66,192.0.2.5" {
		t.Errorf("expected DHCPOptions left untouched, got %v", got)
	}
}

func TestPropagateLinkedScopes_NoLinksNoChange(t *testing.T) {
	s := storeWithTemplates(t)
	scopes := map[string]config.ScopeConfig{"rw-1": {DHCPOptions: []string{"a"}}}
	updated, changed := propagateLinkedScopes(scopes, s)
	if changed {
		t.Error("expected no change for a scope with zero ContentLinks")
	}
	if len(updated) != 1 {
		t.Errorf("expected the scope map to still round-trip, got %v", updated)
	}
}

// TestPropagateLinkedScopes_ReflectsAnEditedTemplateBody is the direct,
// end-to-end proof of "if we change a template, the data in the scopes
// changes too".
func TestPropagateLinkedScopes_ReflectsAnEditedTemplateBody(t *testing.T) {
	s := storeWithTemplates(t)
	scopes := map[string]config.ScopeConfig{
		"rw-1": {ContentLinks: map[string]config.ContentLink{
			"dhcp_options": {Kind: ContentLinkKindTemplate, SourceID: "dhcp1"},
		}},
	}
	updated, _ := propagateLinkedScopes(scopes, s)
	if got := updated["rw-1"].DHCPOptions; len(got) != 1 || got[0] != "option:ntp-server,10.0.0.1" {
		t.Fatalf("initial resolve = %v", got)
	}

	s.Upsert("dhcp1", "dhcp1", "#111111", TemplateKindDHCP, "option:ntp-server,10.0.0.99")
	updated2, changed2 := propagateLinkedScopes(scopes, s)
	if !changed2 {
		t.Fatal("expected a change once the referenced template's body changed")
	}
	if got := updated2["rw-1"].DHCPOptions; len(got) != 1 || got[0] != "option:ntp-server,10.0.0.99" {
		t.Errorf("expected the NEW template body to resolve, got %v", got)
	}
}
