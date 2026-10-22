// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"dnshived/internal/config"
)

func TestCollectExistingDNSRecords_GlobalAndPerScope(t *testing.T) {
	c := config.Cluster{
		GlobalDNSRecords: []config.DNSRecord{{Name: "ntp.lan", Type: "A", Value: "192.0.2.10"}},
		Scopes: map[string]config.ScopeConfig{
			"office": {DNSRecords: []config.DNSRecord{{Name: "printer.lan", Type: "A", Value: "192.168.100.50"}}},
		},
	}
	got := collectExistingDNSRecords(c)
	if len(got) != 2 {
		t.Fatalf("expected 2 existing records (1 global + 1 scope), got %d: %+v", len(got), got)
	}
	var sawGlobal, sawScope bool
	for _, r := range got {
		if r.Name == "ntp.lan" && r.Where == "global" {
			sawGlobal = true
		}
		if r.Name == "printer.lan" && r.Where == "scope office" {
			sawScope = true
		}
	}
	if !sawGlobal || !sawScope {
		t.Errorf("expected both global and scope-tagged records, got %+v", got)
	}
}

func TestRecordCollisionValue_PrefersTargetOverValue(t *testing.T) {
	if got := recordCollisionValue(config.DNSRecord{Type: "MX", Target: "mail.lan", Value: ""}); got != "mail.lan" {
		t.Errorf("MX record should compare on Target, got %q", got)
	}
	if got := recordCollisionValue(config.DNSRecord{Type: "A", Value: "10.0.0.1"}); got != "10.0.0.1" {
		t.Errorf("A record should compare on Value, got %q", got)
	}
}

func TestDNSRecordBuilderHTML_ContainsEveryType(t *testing.T) {
	html := string(dnsRecordBuilderHTML("tpl_body", nil))
	for _, spec := range dnsRecordTypeCatalog {
		if !strings.Contains(html, ">"+spec.Type+"<") {
			t.Errorf("expected the type dropdown to offer %q, got: %s", spec.Type, html)
		}
	}
}

func TestDNSRecordBuilderHTML_EscapesExistingNames(t *testing.T) {
	existing := []dnsExistingRecord{{Name: `"><script>alert(1)</script>`, Type: "A", Value: "1.2.3.4", Where: "global"}}
	html := string(dnsRecordBuilderHTML("tpl_body", existing))
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Error("expected an existing record's Name to be HTML-escaped in the datalist, found raw script tag")
	}
}

func TestDHCPOptionBuilderHTML_ContainsCatalog(t *testing.T) {
	html := string(dhcpOptionBuilderHTML("tpl_body"))
	for _, o := range dhcpOptionCatalog {
		if !strings.Contains(html, o.Name) {
			t.Errorf("expected the dropdown to offer option %q, got missing from html", o.Name)
		}
	}
}

func TestHandleTemplateNew_DNSKindRendersWithoutCrashing(t *testing.T) {
	store := &TemplateStore{}
	cfg := &WebConfig{TemplatesFile: templatesTestPath(t)} // no Nodes configured
	h := handleTemplateNew(newConfigRef(cfg), store)

	form := url.Values{"action": {"step2"}, "name": {"office-names"}, "kind": {"dns"}}
	req := httptest.NewRequest(http.MethodPost, "/templates/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "step 2 of 2") {
		t.Fatalf("expected step 2 to render cleanly even with no reachable node, code=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "add record") {
		t.Errorf("expected the DNS record builder to render, body=%s", rec.Body.String())
	}
}
