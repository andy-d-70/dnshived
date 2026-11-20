// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"strings"
	"testing"
)

func TestFooterHTML_EveryFieldCarriesItsId(t *testing.T) {
	for _, id := range []string{"title", "upd", "state", "nodes", "dhcp", "rev", "ev"} {
		if !strings.Contains(footerHTML, `data-f="`+id+`"`) {
			t.Errorf("footer field %q has no data-f, the user cannot move, hide or resize it", id)
		}
	}
	if strings.Contains(footerHTML, "ft-tele") {
		t.Error("the DHCP, revision and event fields must be direct children of the footer so each can be moved on its own")
	}
}

func TestFooterLayoutScript_KeepsItsStorageKeyLimitsAndOrder(t *testing.T) {
	for _, want := range []string{"KEY='dnshived-footer'", "MINW=3, MAXW=60", "var DROP=['upd','ev','dhcp','rev','title']", "contextmenu", "window.dnshivedFooter"} {
		if !strings.Contains(footerLayoutScriptHTML, want) {
			t.Errorf("footer layout script lacks %q", want)
		}
	}
	if strings.Contains(footerLayoutScriptHTML, "innerHTML") {
		t.Error("the footer arrangement builds its elements with the DOM API only")
	}
	if !strings.Contains(navHTML, "dnshivedFooter") {
		t.Error("the footer arrangement script must come with the footer on every page")
	}
}

func TestStyleHTML_FooterIsAFlexRowOfFields(t *testing.T) {
	for _, want := range []string{
		"display:flex;align-items:center;gap:1.1em;",
		".appfoot>[data-f]{flex:0 0 auto;",
		".appfoot [data-f].ft-user-off,.appfoot [data-f].ft-auto-off{display:none}",
		".ft-menu{position:fixed;",
		".appfoot .ft-nodes{display:flex;gap:1.2em;flex:1 0 auto}",
	} {
		if !strings.Contains(styleHTML, want) {
			t.Errorf("styleHTML lacks %q", want)
		}
	}
	if strings.Contains(styleHTML, "grid-template-columns:auto auto auto 1fr auto") {
		t.Error("the old five column footer grid must be gone")
	}
}
