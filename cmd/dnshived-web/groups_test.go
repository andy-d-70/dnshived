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

func fakeGroupsNode(t *testing.T, pushedBody *string, scopes map[string]config.ScopeConfig) *WebConfig {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				ClusterID: "test", NodeID: "n", Role: "core-1", ControlAddr: "10.0.0.1:9443",
				Platform: &config.Platform{Mgmt: "eth0", Workers: []string{"ens19"}},
				Scopes:   scopes,
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

func TestHandleScopeGroupNew_CreatesAndPropagatesToMembers(t *testing.T) {
	var pushed string
	scopes := map[string]config.ScopeConfig{
		"office": {VLANID: 100, VRRPID: 51, Parent: "ens19", PreferredWorker: "core-1", VIP: "172.16.100.2/24"},
	}
	cfg := fakeGroupsNode(t, &pushed, scopes)
	store := &TemplateStore{}
	store.Upsert("dhcp1", "dhcp1", "#111", TemplateKindDHCP, "option:ntp-server,10.0.0.1")

	form := url.Values{"name": {"Dante"}, "color": {"#123456"}, "assigned_source": {"template:dhcp1"}, "members": {"office"}}
	req := httptest.NewRequest(http.MethodPost, "/groups/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleScopeGroupNew(newConfigRef(cfg), store)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status %d, body=%s", rec.Code, rec.Body.String())
	}

	groups := store.SortedScopeGroups()
	if len(groups) != 1 || groups[0].Name != "Dante" || len(groups[0].Members) != 1 || groups[0].Members[0] != "office" {
		t.Fatalf("unexpected stored group(s): %+v", groups)
	}
	if pushed == "" {
		t.Fatal("expected a candidate push once the group's own member got linked")
	}
	var payload configPushPayload
	if err := json.Unmarshal([]byte(pushed), &payload); err != nil {
		t.Fatalf("unmarshal pushed payload: %v", err)
	}
	got := payload.Scopes["office"]
	if len(got.DHCPOptions) != 1 || got.DHCPOptions[0] != "option:ntp-server,10.0.0.1" {
		t.Errorf("expected office's DHCPOptions resolved from the group's assignment, got %v", got.DHCPOptions)
	}
	if got.ContentLinks["dhcp_options"].SourceID != "dhcp1" {
		t.Errorf("expected office linked to dhcp1, got %+v", got.ContentLinks)
	}
}

func TestHandleScopeGroupEdit_NewMemberInheritsAssignment(t *testing.T) {
	var pushed string
	scopes := map[string]config.ScopeConfig{
		"office": {VLANID: 100, VRRPID: 51, Parent: "ens19", PreferredWorker: "core-1", VIP: "172.16.100.2/24"},
		"lab":    {VLANID: 101, VRRPID: 52, Parent: "ens19", PreferredWorker: "core-1", VIP: "172.16.101.2/24"},
	}
	cfg := fakeGroupsNode(t, &pushed, scopes)
	store := &TemplateStore{}
	store.Upsert("dhcp1", "dhcp1", "#111", TemplateKindDHCP, "option:ntp-server,10.0.0.1")
	id := store.UpsertScopeGroup("", "Dante", "#000", []string{"office"}, "template:dhcp1")

	// Add "lab" as a second member — this alone must be enough to
	// have it inherit the group's already-assigned template.
	form := url.Values{"name": {"Dante"}, "color": {"#000"}, "assigned_source": {"template:dhcp1"}, "members": {"office", "lab"}}
	req := httptest.NewRequest(http.MethodPost, "/groups/"+id+"/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("id", id)
	rec := httptest.NewRecorder()
	handleScopeGroupEdit(newConfigRef(cfg), store)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status %d, body=%s", rec.Code, rec.Body.String())
	}
	var payload configPushPayload
	if err := json.Unmarshal([]byte(pushed), &payload); err != nil {
		t.Fatalf("unmarshal pushed payload: %v", err)
	}
	got := payload.Scopes["lab"]
	if len(got.DHCPOptions) != 1 || got.DHCPOptions[0] != "option:ntp-server,10.0.0.1" {
		t.Errorf("expected the newly-added member to inherit the group's assignment, got %v", got.DHCPOptions)
	}
	if got.ContentLinks["dhcp_options"].SourceID != "dhcp1" {
		t.Errorf("expected lab linked to dhcp1, got %+v", got.ContentLinks)
	}
}

func TestHandleScopeGroupEdit_NewMemberWithManualContentIsGated(t *testing.T) {
	var pushed string
	scopes := map[string]config.ScopeConfig{
		"office": {VLANID: 100, VRRPID: 51, Parent: "ens19", PreferredWorker: "core-1", VIP: "172.16.100.2/24"},
		"manual": {VLANID: 101, VRRPID: 52, Parent: "ens19", PreferredWorker: "core-1", VIP: "172.16.101.2/24",
			DHCPOptions: []string{"option:66,x"}},
	}
	cfg := fakeGroupsNode(t, &pushed, scopes)
	store := &TemplateStore{}
	store.Upsert("dhcp1", "dhcp1", "#111", TemplateKindDHCP, "option:ntp-server,10.0.0.1")
	id := store.UpsertScopeGroup("", "Dante", "#000", []string{"office"}, "template:dhcp1")

	form := url.Values{"name": {"Dante"}, "color": {"#000"}, "assigned_source": {"template:dhcp1"}, "members": {"office", "manual"}}
	req := httptest.NewRequest(http.MethodPost, "/groups/"+id+"/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("id", id)
	rec := httptest.NewRecorder()
	handleScopeGroupEdit(newConfigRef(cfg), store)(rec, req)

	if pushed != "" {
		t.Fatalf("expected NOTHING pushed before explicit collision confirmation, got: %s", pushed)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "manual") || !strings.Contains(body, "force_overwrite") {
		t.Errorf("expected the collision confirm page naming 'manual', body=%s", body)
	}
	if !strings.Contains(body, `name="group_id" value="`+id+`"`) {
		t.Errorf("expected the confirm page to carry the group id forward, body=%s", body)
	}

	// Confirm without overwriting — the manual scope's content must
	// stay exactly as it was.
	confirmForm := url.Values{"group_id": {id}, "confirmed": {"1"}}
	confirmReq := httptest.NewRequest(http.MethodPost, "/groups/"+id+"/edit", strings.NewReader(confirmForm.Encode()))
	confirmReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	confirmReq.SetPathValue("id", id)
	confirmRec := httptest.NewRecorder()
	handleScopeGroupEdit(newConfigRef(cfg), store)(confirmRec, confirmReq)
	if pushed == "" {
		t.Fatal("expected a push once confirmed, even with the collision kept")
	}
	var payload configPushPayload
	if err := json.Unmarshal([]byte(pushed), &payload); err != nil {
		t.Fatalf("unmarshal pushed payload: %v", err)
	}
	got := payload.Scopes["manual"]
	if len(got.DHCPOptions) != 1 || got.DHCPOptions[0] != "option:66,x" {
		t.Errorf("expected the manual scope's own content kept, got %v", got.DHCPOptions)
	}
	if _, linked := got.ContentLinks["dhcp_options"]; linked {
		t.Errorf("expected dhcp_options to stay unlinked, got %+v", got.ContentLinks)
	}
}

func TestHandleScopeGroupDelete_RemovesIt(t *testing.T) {
	cfg := &WebConfig{TemplatesFile: t.TempDir() + "/web-templates.json"}
	store := &TemplateStore{}
	id := store.UpsertScopeGroup("", "Dante", "#000", nil, "")

	req := httptest.NewRequest(http.MethodPost, "/groups/"+id+"/delete", nil)
	req.SetPathValue("id", id)
	rec := httptest.NewRecorder()
	handleScopeGroupDelete(newConfigRef(cfg), store)(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected a redirect after delete, got %d", rec.Code)
	}
	if _, ok := store.ScopeGroupByID(id); ok {
		t.Error("expected the group gone after delete")
	}
}

func TestHandleScopeGroupNew_RequiresName(t *testing.T) {
	cfg := fakeGroupsNode(t, new(string), map[string]config.ScopeConfig{})
	store := &TemplateStore{}

	form := url.Values{"name": {"  "}}
	req := httptest.NewRequest(http.MethodPost, "/groups/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleScopeGroupNew(newConfigRef(cfg), store)(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "name is required") {
		t.Errorf("expected a rendered error for a blank name, got %d, body=%s", rec.Code, rec.Body.String())
	}
	if len(store.SortedScopeGroups()) != 0 {
		t.Error("expected no group stored for an invalid submission")
	}
}

func TestHandleScopeGroupNew_NoAssignmentOrNoMembersIsANoOp(t *testing.T) {
	var pushed string
	cfg := fakeGroupsNode(t, &pushed, map[string]config.ScopeConfig{
		"office": {VLANID: 100, VRRPID: 51, Parent: "ens19", PreferredWorker: "core-1", VIP: "172.16.100.2/24"},
	})
	store := &TemplateStore{}

	form := url.Values{"name": {"Empty"}, "color": {"#000"}}
	req := httptest.NewRequest(http.MethodPost, "/groups/new", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleScopeGroupNew(newConfigRef(cfg), store)(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected a plain redirect for a group with nothing assigned, got %d, body=%s", rec.Code, rec.Body.String())
	}
	if pushed != "" {
		t.Errorf("expected no push for a group with no members/assignment, got: %s", pushed)
	}
	if len(store.SortedScopeGroups()) != 1 {
		t.Error("expected the group itself still saved")
	}
}
