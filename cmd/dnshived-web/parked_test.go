// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"dnshived/internal/config"
)

func TestMoveParkedScopes(t *testing.T) {
	live := map[string]config.ScopeConfig{"office": {VLANID: 100}}
	parked := map[string]config.ScopeConfig{"guest": {VLANID: 110, NodeIP: "10.0.0.1/24"}, "lab": {VLANID: 120}}

	t.Run("one", func(t *testing.T) {
		l, p, moved, err := moveParkedScopes(live, parked, []string{"guest"}, false)
		if err != nil || len(moved) != 1 || len(l) != 2 || len(p) != 1 {
			t.Fatalf("live %d parked %d moved %v err %v", len(l), len(p), moved, err)
		}
		if l["guest"].NodeIP != "" {
			t.Error("a node address must not travel with the scope")
		}
		if len(live) != 1 || len(parked) != 2 {
			t.Error("the inputs must not be modified")
		}
	})
	t.Run("all", func(t *testing.T) {
		l, p, moved, err := moveParkedScopes(live, parked, nil, true)
		if err != nil || len(moved) != 2 || len(l) != 3 || len(p) != 0 {
			t.Fatalf("live %d parked %d moved %v err %v", len(l), len(p), moved, err)
		}
	})
	t.Run("unknown", func(t *testing.T) {
		if _, _, _, err := moveParkedScopes(live, parked, []string{"nope"}, false); err == nil {
			t.Error("an unknown name must be refused")
		}
	})
	t.Run("name taken", func(t *testing.T) {
		if _, _, _, err := moveParkedScopes(map[string]config.ScopeConfig{"guest": {}}, parked, []string{"guest"}, false); err == nil {
			t.Error("a live scope with the same name must be refused")
		}
	})
}

func TestClusterPushPayloadFrom_CarriesParkedScopes(t *testing.T) {
	c := config.Cluster{ParkedScopes: map[string]config.ScopeConfig{"guest": {VLANID: 110}}}
	p := clusterPushPayloadFrom(c)
	if p.ParkedScopes == nil || len(*p.ParkedScopes) != 1 {
		t.Fatal("parked scopes must be part of every push")
	}
	raw, _ := json.Marshal(clusterPushPayloadFrom(config.Cluster{}))
	if !strings.Contains(string(raw), `"parked_scopes":{}`) {
		t.Errorf("an empty list is sent as an explicit empty map so a push can clear it: %s", raw)
	}
}

func TestParkedScopesPage_ListsAndOffersEnable(t *testing.T) {
	var b strings.Builder
	err := scopesTmpl.Execute(&b, scopesPageData{Parked: buildParkedRows(map[string]config.ScopeConfig{"guest": {VLANID: 110, VIP: "10.1.0.1/24", Reservations: []config.Reservation{{MAC: "aa:bb:cc:00:00:01", IP: "10.1.0.5"}}}})})
	if err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"Parked scopes", `action="/scopes/parked/enable"`, `action="/scopes/parked/remove"`, `name="all"`, ">guest<"} {
		if !strings.Contains(out, want) {
			t.Errorf("page lacks %s", want)
		}
	}
	var none strings.Builder
	if err := scopesTmpl.Execute(&none, scopesPageData{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(none.String(), "Parked scopes") {
		t.Error("no section without parked scopes")
	}
}

func TestHandleParkedEnable_StagesTheMove(t *testing.T) {
	live := testClusterWithScopes()
	live.ParkedScopes = map[string]config.ScopeConfig{"guest": {VLANID: 110, VIP: "192.168.110.1/24"}}
	srv, pushed := fakeCandidateNode(t, live)
	defer srv.Close()
	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}
	r := httptest.NewRequest(http.MethodPost, "/scopes/parked/enable", strings.NewReader(url.Values{"name": {"guest"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleParkedEnable(newConfigRef(cfg))(w, r)
	if w.Code >= 400 {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
	if _, ok := pushed.Scopes["guest"]; !ok {
		t.Error("the scope must be live in the staged candidate")
	}
	if len(pushed.ParkedScopes) != 0 {
		t.Errorf("parked scopes = %v, want none left", pushed.ParkedScopes)
	}
	if len(pushed.Scopes) != 2 {
		t.Errorf("%d live scopes, want the existing one plus guest", len(pushed.Scopes))
	}
}

func TestParkedDiffEntries(t *testing.T) {
	a := map[string]config.ScopeConfig{"x": {VLANID: 1}}
	b := map[string]config.ScopeConfig{"y": {VLANID: 2}}
	got := parkedDiffEntries(a, b)
	if len(got) != 2 {
		t.Fatalf("entries = %v", got)
	}
	if len(parkedDiffEntries(a, a)) != 0 {
		t.Error("no entry for no change")
	}
}
