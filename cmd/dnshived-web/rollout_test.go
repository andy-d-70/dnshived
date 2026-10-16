// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"dnshived/internal/config"
)

func fakeRolloutNode(t *testing.T, pushedBody *string) *WebConfig {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				ClusterID: "test", NodeID: "worker-a-test", Role: "core-1",
				ControlAddr: "10.0.0.1:9443",
				Platform:    &config.Platform{Mgmt: "eth0", Workers: []string{"ens19"}},
				Scopes: map[string]config.ScopeConfig{
					"office": {VLANID: 100, VRRPID: 51, Parent: "ens19", PreferredWorker: "core-1", VIP: "172.16.100.2/24"},
					"linked": {VLANID: 101, VRRPID: 52, Parent: "ens19", PreferredWorker: "core-1", VIP: "172.16.101.2/24",
						ContentLinks: map[string]config.ContentLink{
							"dhcp_options": {Kind: ContentLinkKindTemplate, SourceID: "dhcp1"},
						}},
					"manual": {VLANID: 102, VRRPID: 53, Parent: "ens19", PreferredWorker: "core-1", VIP: "172.16.102.2/24",
						DHCPOptions: []string{"option:ntp-server,10.0.0.222"}},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/candidate":
			body, _ := io.ReadAll(r.Body)
			*pushedBody = string(body)
			w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)
	return &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}, TemplatesFile: t.TempDir() + "/web-templates.json"}
}

func TestHandleRollout_TemplateAppliedToSelectedScopesOnly(t *testing.T) {
	var pushed string
	cfg := fakeRolloutNode(t, &pushed)
	store := &TemplateStore{}
	store.Upsert("dhcp1", "dhcp1", "#111", TemplateKindDHCP, "option:ntp-server,10.0.0.1")

	form := url.Values{"source": {"template:dhcp1"}, "scopes": {"office"}}
	req := httptest.NewRequest(http.MethodPost, "/rollout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleRollout(newConfigRef(cfg), store)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status %d, body=%s", rec.Code, rec.Body.String())
	}

	var payload configPushPayload
	if err := json.Unmarshal([]byte(pushed), &payload); err != nil {
		t.Fatalf("unmarshal pushed payload: %v, body=%s", err, pushed)
	}
	office := payload.Scopes["office"]
	if office.ContentLinks["dhcp_options"].SourceID != "dhcp1" {
		t.Errorf("expected office linked to dhcp1, got %+v", office.ContentLinks)
	}
	if len(office.DHCPOptions) != 1 || office.DHCPOptions[0] != "option:ntp-server,10.0.0.1" {
		t.Errorf("expected office's DHCPOptions resolved from the template, got %v", office.DHCPOptions)
	}
	// "linked" was NOT selected — must be carried forward untouched.
	linked := payload.Scopes["linked"]
	if linked.ContentLinks["dhcp_options"].SourceID != "dhcp1" {
		t.Errorf("expected the pre-existing scope's own link untouched, got %+v", linked.ContentLinks)
	}
}

func TestHandleRollout_OptionSetLinksEveryReferencedKind(t *testing.T) {
	var pushed string
	cfg := fakeRolloutNode(t, &pushed)
	store := &TemplateStore{}
	store.Upsert("dhcp1", "dhcp1", "#111", TemplateKindDHCP, "option:ntp-server,10.0.0.1")
	store.Upsert("cdns1", "cdns1", "#222", TemplateKindClientDNS, "8.8.8.8")
	setID := store.UpsertOptionSet("", "Dante", "#000", map[TemplateKind]string{
		TemplateKindDHCP: "dhcp1", TemplateKindClientDNS: "cdns1",
	})

	form := url.Values{"source": {"optionset:" + setID}, "scopes": {"office"}}
	req := httptest.NewRequest(http.MethodPost, "/rollout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleRollout(newConfigRef(cfg), store)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status %d, body=%s", rec.Code, rec.Body.String())
	}
	var payload configPushPayload
	if err := json.Unmarshal([]byte(pushed), &payload); err != nil {
		t.Fatalf("unmarshal pushed payload: %v", err)
	}
	office := payload.Scopes["office"]
	if len(office.DHCPOptions) != 1 || office.DHCPOptions[0] != "option:ntp-server,10.0.0.1" {
		t.Errorf("DHCPOptions = %v", office.DHCPOptions)
	}
	if office.ClientDNSServer != "8.8.8.8" {
		t.Errorf("ClientDNSServer = %q", office.ClientDNSServer)
	}
	if office.ContentLinks["dhcp_options"].Kind != ContentLinkKindOptionSet || office.ContentLinks["dhcp_options"].SourceID != setID {
		t.Errorf("expected office's dhcp_options linked to the option set, got %+v", office.ContentLinks)
	}
}

func TestHandleRollout_NoSourceOrNoScopesIsAnError(t *testing.T) {
	cfg := fakeRolloutNode(t, new(string))
	store := &TemplateStore{}

	req := httptest.NewRequest(http.MethodPost, "/rollout", strings.NewReader(url.Values{"source": {""}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleRollout(newConfigRef(cfg), store)(rec, req)
	if !strings.Contains(rec.Body.String(), "pick a template or option set") {
		t.Errorf("expected a no-source error, body=%s", rec.Body.String())
	}

	store.Upsert("dhcp1", "dhcp1", "#111", TemplateKindDHCP, "option:ntp-server,10.0.0.1")
	req2 := httptest.NewRequest(http.MethodPost, "/rollout", strings.NewReader(url.Values{"source": {"template:dhcp1"}}.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()
	handleRollout(newConfigRef(cfg), store)(rec2, req2)
	if !strings.Contains(rec2.Body.String(), "select at least one scope") {
		t.Errorf("expected a no-scopes-selected error, body=%s", rec2.Body.String())
	}
}

func TestHandleTemplateEditPost_PropagatesIntoLinkedScope(t *testing.T) {
	var pushed string
	cfg := fakeRolloutNode(t, &pushed)
	store := &TemplateStore{}
	store.Upsert("dhcp1", "dhcp1", "#111", TemplateKindDHCP, "option:ntp-server,10.0.0.1")

	form := url.Values{"kind": {"dhcp"}, "name": {"dhcp1"}, "color": {"#111"}, "body": {"option:ntp-server,10.0.0.99"}}
	req := httptest.NewRequest(http.MethodPost, "/templates/dhcp1/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("id", "dhcp1")
	rec := httptest.NewRecorder()
	handleTemplateEditPost(newConfigRef(cfg), store)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected the propagation result page (200), got %d, body=%s", rec.Code, rec.Body.String())
	}
	if pushed == "" {
		t.Fatal("expected a candidate push once the linked template's body changed")
	}
	var payload configPushPayload
	if err := json.Unmarshal([]byte(pushed), &payload); err != nil {
		t.Fatalf("unmarshal pushed payload: %v", err)
	}
	if got := payload.Scopes["linked"].DHCPOptions; len(got) != 1 || got[0] != "option:ntp-server,10.0.0.99" {
		t.Errorf("expected scope 'linked' to pick up the edited template's NEW body, got %v", got)
	}
	// The unrelated scope must round-trip untouched.
	if got := payload.Scopes["office"]; got.VIP != "172.16.100.2/24" {
		t.Errorf("expected the unrelated scope untouched, got %+v", got)
	}
}

// TestHandleTemplateEditPost_NoLinkedScopesPlainRedirect confirms the
// common case (a template nobody links to) keeps the original, plain
// redirect-on-save behavior.
func TestHandleTemplateEditPost_NoLinkedScopesPlainRedirect(t *testing.T) {
	var pushed string
	cfg := fakeRolloutNode(t, &pushed)
	store := &TemplateStore{}
	store.Upsert("cdns1", "cdns1", "#111", TemplateKindClientDNS, "8.8.8.8")

	form := url.Values{"kind": {"client-dns"}, "name": {"cdns1"}, "color": {"#111"}, "body": {"9.9.9.9"}}
	req := httptest.NewRequest(http.MethodPost, "/templates/cdns1/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("id", "cdns1")
	rec := httptest.NewRecorder()
	handleTemplateEditPost(newConfigRef(cfg), store)(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected the plain redirect (303) when nothing is linked, got %d", rec.Code)
	}
	if pushed != "" {
		t.Errorf("expected no candidate push when no scope links to the edited template, got: %s", pushed)
	}
}

// TestDetectCollisions covers detectCollisions' three real cases.
func TestDetectCollisions(t *testing.T) {
	store := &TemplateStore{}
	store.Upsert("dhcp1", "dhcp1", "#111", TemplateKindDHCP, "option:ntp-server,10.0.0.1")
	store.Upsert("dhcp2", "dhcp2", "#222", TemplateKindDHCP, "option:ntp-server,10.0.0.2")

	scopes := map[string]config.ScopeConfig{
		"manual":  {DHCPOptions: []string{"option:66,x"}},
		"clean":   {},
		"already": {ContentLinks: map[string]config.ContentLink{"dhcp_options": {Kind: ContentLinkKindTemplate, SourceID: "dhcp1"}}},
		"other":   {ContentLinks: map[string]config.ContentLink{"dhcp_options": {Kind: ContentLinkKindTemplate, SourceID: "dhcp2"}}},
	}
	selected := map[string]bool{"manual": true, "clean": true, "already": true, "other": true}
	links := map[string]config.ContentLink{"dhcp_options": {Kind: ContentLinkKindTemplate, SourceID: "dhcp1"}}

	got := detectCollisions(scopes, selected, links, store)
	byScope := make(map[string]collisionRow, len(got))
	for _, c := range got {
		byScope[c.Scope] = c
	}
	if _, ok := byScope["clean"]; ok {
		t.Error("expected no collision for an empty, unlinked field")
	}
	if _, ok := byScope["already"]; ok {
		t.Error("expected no collision when re-applying the IDENTICAL link (idempotent)")
	}
	if c, ok := byScope["manual"]; !ok || !strings.Contains(c.Detail, "manually set") {
		t.Errorf("expected a manual-content collision for 'manual', got %+v (ok=%v)", byScope["manual"], ok)
	}
	if c, ok := byScope["other"]; !ok || !strings.Contains(c.Detail, "dhcp2") {
		t.Errorf("expected a different-link collision for 'other' naming dhcp2, got %+v (ok=%v)", byScope["other"], ok)
	}
}

func TestHandleRollout_CollisionShowsConfirmPageWithoutApplying(t *testing.T) {
	var pushed string
	cfg := fakeRolloutNode(t, &pushed)
	store := &TemplateStore{}
	store.Upsert("dhcp1", "dhcp1", "#111", TemplateKindDHCP, "option:ntp-server,10.0.0.1")

	form := url.Values{"source": {"template:dhcp1"}, "scopes": {"manual"}}
	req := httptest.NewRequest(http.MethodPost, "/rollout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleRollout(newConfigRef(cfg), store)(rec, req)

	if pushed != "" {
		t.Fatalf("expected NOTHING pushed before explicit confirmation, got: %s", pushed)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "manual") || !strings.Contains(body, "force_overwrite") {
		t.Errorf("expected the collision confirm page naming the scope with a force_overwrite checkbox, body=%s", body)
	}
}

func TestHandleRollout_ConfirmWithoutOverwriteKeepsExistingContent(t *testing.T) {
	var pushed string
	cfg := fakeRolloutNode(t, &pushed)
	store := &TemplateStore{}
	store.Upsert("dhcp1", "dhcp1", "#111", TemplateKindDHCP, "option:ntp-server,10.0.0.1")

	form := url.Values{"source": {"template:dhcp1"}, "scopes": {"manual"}, "confirmed": {"1"}}
	req := httptest.NewRequest(http.MethodPost, "/rollout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleRollout(newConfigRef(cfg), store)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status %d, body=%s", rec.Code, rec.Body.String())
	}
	if pushed == "" {
		t.Fatal("expected a candidate push even with the collision kept (other, non-colliding scopes/behavior still applies)")
	}
	var payload configPushPayload
	if err := json.Unmarshal([]byte(pushed), &payload); err != nil {
		t.Fatalf("unmarshal pushed payload: %v", err)
	}
	got := payload.Scopes["manual"]
	if len(got.DHCPOptions) != 1 || got.DHCPOptions[0] != "option:ntp-server,10.0.0.222" {
		t.Errorf("expected the operator's own DHCPOptions kept untouched, got %v", got.DHCPOptions)
	}
	if _, linked := got.ContentLinks["dhcp_options"]; linked {
		t.Errorf("expected dhcp_options to stay UNLINKED since the collision was kept, got %+v", got.ContentLinks)
	}
}

// TestHandleRollout_ConfirmWithForceOverwriteAppliesIt confirms explicitly
// checking "overwrite" actually applies the new link and resolved content.
func TestHandleRollout_ConfirmWithForceOverwriteAppliesIt(t *testing.T) {
	var pushed string
	cfg := fakeRolloutNode(t, &pushed)
	store := &TemplateStore{}
	store.Upsert("dhcp1", "dhcp1", "#111", TemplateKindDHCP, "option:ntp-server,10.0.0.1")

	form := url.Values{
		"source": {"template:dhcp1"}, "scopes": {"manual"}, "confirmed": {"1"},
		"force_overwrite": {"manual|dhcp_options"},
	}
	req := httptest.NewRequest(http.MethodPost, "/rollout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleRollout(newConfigRef(cfg), store)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status %d, body=%s", rec.Code, rec.Body.String())
	}
	var payload configPushPayload
	if err := json.Unmarshal([]byte(pushed), &payload); err != nil {
		t.Fatalf("unmarshal pushed payload: %v", err)
	}
	got := payload.Scopes["manual"]
	if len(got.DHCPOptions) != 1 || got.DHCPOptions[0] != "option:ntp-server,10.0.0.1" {
		t.Errorf("expected the template's content applied, got %v", got.DHCPOptions)
	}
	if got.ContentLinks["dhcp_options"].SourceID != "dhcp1" {
		t.Errorf("expected dhcp_options linked to dhcp1, got %+v", got.ContentLinks)
	}
}
