// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestValidateTemplateBody_DHCPDoesNotFalsePositiveOnUnrelatedClusterFields(t *testing.T) {
	if err := validateTemplateBody(TemplateKindDHCP, "6,8.8.8.8"); err != nil {
		t.Errorf("expected a plain valid DHCP option body to pass, got: %v", err)
	}
}

func TestHandleTemplateNew_TwoStepFlowCreatesTemplate(t *testing.T) {
	store := &TemplateStore{}
	tmpPath := templatesTestPath(t)
	cfg := &WebConfig{TemplatesFile: tmpPath}
	h := handleTemplateNew(newConfigRef(cfg), store)

	get := httptest.NewRequest(http.MethodGet, "/templates/new", nil)
	rec := httptest.NewRecorder()
	h(rec, get)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "step 1 of 2") {
		t.Fatalf("GET /templates/new: code=%d body=%s", rec.Code, rec.Body.String())
	}

	step2Form := url.Values{"action": {"step2"}, "name": {"dante"}, "color": {"#4363d8"}, "kind": {"dhcp"}}
	req2 := httptest.NewRequest(http.MethodPost, "/templates/new", strings.NewReader(step2Form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()
	h(rec2, req2)
	if rec2.Code != http.StatusOK || !strings.Contains(rec2.Body.String(), "step 2 of 2") {
		t.Fatalf("step2: code=%d body=%s", rec2.Code, rec2.Body.String())
	}
	if !strings.Contains(rec2.Body.String(), "raw dnsmasq") {
		t.Errorf("expected DHCP-specific guidance text on step 2, body=%s", rec2.Body.String())
	}

	createForm := url.Values{
		"action": {"create"}, "name": {"dante"}, "color": {"#4363d8"}, "kind": {"dhcp"},
		"body": {"6,8.8.8.8\n66,192.168.1.1"},
	}
	req3 := httptest.NewRequest(http.MethodPost, "/templates/new", strings.NewReader(createForm.Encode()))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec3 := httptest.NewRecorder()
	h(rec3, req3)
	if rec3.Code != http.StatusSeeOther {
		t.Fatalf("expected a redirect after create, got %d: %s", rec3.Code, rec3.Body.String())
	}

	rows := store.ByKind(TemplateKindDHCP)
	if len(rows) != 1 || rows[0].Name != "dante" || rows[0].Body != "6,8.8.8.8\n66,192.168.1.1" {
		t.Errorf("expected the new template in the store, got %+v", rows)
	}
}

// TestHandleTemplateNew_InvalidBodyStaysOnStep2WithError confirms a syntax
// error doesn't silently create a bad template.
func TestHandleTemplateNew_InvalidBodyStaysOnStep2WithError(t *testing.T) {
	store := &TemplateStore{}
	cfg := &WebConfig{TemplatesFile: templatesTestPath(t)}
	h := handleTemplateNew(newConfigRef(cfg), store)

	createForm := url.Values{
		"action": {"create"}, "name": {"bad"}, "kind": {"dns"}, "body": {"NOTVALID"},
	}
	req := httptest.NewRequest(http.MethodPost, "/templates/new", strings.NewReader(createForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "step 2 of 2") {
		t.Fatalf("expected to stay on step 2, got code=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(store.Templates) != 0 {
		t.Errorf("expected no template created on a validation error, got %+v", store.Templates)
	}
}

func templatesTestPath(t *testing.T) string {
	t.Helper()
	return t.TempDir() + "/web-templates.json"
}
