// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestHandleOptionSets_ListsRefLabels(t *testing.T) {
	store := &TemplateStore{}
	store.Upsert("dhcp1", "dhcp1", "#111", TemplateKindDHCP, "option:66,x")
	store.UpsertOptionSet("", "Dante", "#000", map[TemplateKind]string{TemplateKindDHCP: "dhcp1"})

	req := httptest.NewRequest(http.MethodGet, "/optionsets", nil)
	rec := httptest.NewRecorder()
	handleOptionSets(store)(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "Dante") || !strings.Contains(body, "dhcp1") {
		t.Errorf("expected the option set and its referenced template name, body=%s", body)
	}
}

func TestHandleOptionSetNew_CreatesAndRedirects(t *testing.T) {
	cfg := &WebConfig{TemplatesFile: t.TempDir() + "/web-templates.json"}
	store := &TemplateStore{}
	store.Upsert("dhcp1", "dhcp1", "#111", TemplateKindDHCP, "option:66,x")

	form := url.Values{"name": {"Dante"}, "color": {"#123456"}, "ref_dhcp": {"dhcp1"}}
	req := httptest.NewRequest(http.MethodPost, "/optionsets/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleOptionSetNew(newConfigRef(cfg), store)(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected a redirect after create, got %d, body=%s", rec.Code, rec.Body.String())
	}
	sets := store.SortedOptionSets()
	if len(sets) != 1 || sets[0].Name != "Dante" || sets[0].TemplateRefs[TemplateKindDHCP] != "dhcp1" {
		t.Errorf("unexpected stored option set(s): %+v", sets)
	}
}

func TestHandleOptionSetNew_RequiresName(t *testing.T) {
	cfg := &WebConfig{TemplatesFile: t.TempDir() + "/web-templates.json"}
	store := &TemplateStore{}

	form := url.Values{"name": {"  "}}
	req := httptest.NewRequest(http.MethodPost, "/optionsets/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleOptionSetNew(newConfigRef(cfg), store)(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "name is required") {
		t.Errorf("expected a rendered error for a blank name, got %d, body=%s", rec.Code, rec.Body.String())
	}
	if len(store.SortedOptionSets()) != 0 {
		t.Error("expected no option set stored for an invalid submission")
	}
}

func TestHandleOptionSetDelete_RemovesIt(t *testing.T) {
	cfg := &WebConfig{TemplatesFile: t.TempDir() + "/web-templates.json"}
	store := &TemplateStore{}
	id := store.UpsertOptionSet("", "Dante", "#000", nil)

	req := httptest.NewRequest(http.MethodPost, "/optionsets/"+id+"/delete", nil)
	req.SetPathValue("id", id)
	rec := httptest.NewRecorder()
	handleOptionSetDelete(newConfigRef(cfg), store)(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected a redirect after delete, got %d", rec.Code)
	}
	if _, ok := store.OptionSetByID(id); ok {
		t.Error("expected the option set gone after delete")
	}
}

func TestHandleOptionSetEdit_PropagatesRefChangeIntoLinkedScope(t *testing.T) {
	var pushed string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"cluster_id":"test","node_id":"n","role":"core-1","control_addr":"10.0.0.1:9443",
"platform":{"mgmt":"eth0","workers":["ens19"]},
"scopes":{"office":{"vlan_id":100,"vrrp_id":51,"parent":"ens19","preferred_worker":"core-1","vip":"172.16.100.2/24",
"content_links":{"dhcp_options":{"kind":"optionset","source_id":"dante"}}}}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/candidate":
			body, _ := io.ReadAll(r.Body)
			pushed = string(body)
			w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}, TemplatesFile: t.TempDir() + "/web-templates.json"}

	store := &TemplateStore{}
	store.Upsert("dhcp1", "dhcp1", "#111", TemplateKindDHCP, "option:ntp-server,10.0.0.1")
	store.Upsert("dhcp2", "dhcp2", "#222", TemplateKindDHCP, "option:ntp-server,10.0.0.2")
	store.UpsertOptionSet("dante", "Dante", "#000", map[TemplateKind]string{TemplateKindDHCP: "dhcp1"})

	// Re-point "Dante" at dhcp2 instead of dhcp1.
	form := url.Values{"name": {"Dante"}, "color": {"#000"}, "ref_dhcp": {"dhcp2"}}
	req := httptest.NewRequest(http.MethodPost, "/optionsets/dante/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("id", "dante")
	rec := httptest.NewRecorder()
	handleOptionSetEdit(newConfigRef(cfg), store)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected the propagation result page (200), got %d, body=%s", rec.Code, rec.Body.String())
	}
	if pushed == "" {
		t.Fatal("expected a candidate push once the option set's own reference changed")
	}
	if !strings.Contains(pushed, "10.0.0.2") {
		t.Errorf("expected the scope linked to 'Dante' to resolve to dhcp2's NEW content, pushed=%s", pushed)
	}
	if strings.Contains(pushed, "10.0.0.1") {
		t.Errorf("expected NO trace of the old dhcp1 content, pushed=%s", pushed)
	}
}
