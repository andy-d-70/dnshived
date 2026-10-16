// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"reflect"
	"strings"

	"dnshived/internal/config"
)

const (
	ContentLinkKindTemplate  = "template"
	ContentLinkKindOptionSet = "optionset"
)

// contentLinkFieldKinds maps a ScopeConfig content field's own JSON key
// (config.ContentLinks' map key) to the TemplateKind it draws from.
var contentLinkFieldKinds = map[string]TemplateKind{
	"dhcp_options":      TemplateKindDHCP,
	"dns_records":       TemplateKindDNS,
	"client_dns_server": TemplateKindClientDNS,
}

// resolveContentLink resolves one config.ContentLink to its current
// effective body text, against the given store.
func resolveContentLink(link config.ContentLink, kind TemplateKind, store *TemplateStore) (body string, ok bool) {
	switch link.Kind {
	case ContentLinkKindTemplate:
		t, found := store.Get(link.SourceID)
		if !found || t.Kind != kind {
			return "", false
		}
		return t.Body, true
	case ContentLinkKindOptionSet:
		set, found := store.OptionSetByID(link.SourceID)
		if !found {
			return "", false
		}
		refID := set.TemplateRefs[kind]
		if refID == "" {
			return "", false
		}
		t, found := store.Get(refID)
		if !found || t.Kind != kind {
			return "", false
		}
		return t.Body, true
	default:
		return "", false
	}
}

func applyResolvedBody(sc *config.ScopeConfig, fieldKey, body string) error {
	switch fieldKey {
	case "dhcp_options":
		sc.DHCPOptions = splitLines(body)
	case "client_dns_server":
		sc.ClientDNSServer = strings.TrimSpace(body)
	case "dns_records":
		records, err := parseDNSRecordLines(body)
		if err != nil {
			return err
		}
		sc.DNSRecords = records
	}
	return nil
}

// propagateLinkedScopes walks every scope's own ContentLinks and
// re-resolves each one against the store's CURRENT content.
func propagateLinkedScopes(scopes map[string]config.ScopeConfig, store *TemplateStore) (map[string]config.ScopeConfig, bool) {
	out := make(map[string]config.ScopeConfig, len(scopes))
	changed := false
	for name, sc := range scopes {
		if len(sc.ContentLinks) == 0 {
			out[name] = sc
			continue
		}
		before := sc
		for fieldKey, link := range sc.ContentLinks {
			kind, known := contentLinkFieldKinds[fieldKey]
			if !known {
				continue
			}
			body, ok := resolveContentLink(link, kind, store)
			if !ok {
				continue
			}
			if err := applyResolvedBody(&sc, fieldKey, body); err != nil {
				continue
			}
		}
		if !reflect.DeepEqual(before, sc) {
			changed = true
		}
		out[name] = sc
	}
	return out, changed
}
