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

func TestFormatParseDomainHostLine_RoundTrip(t *testing.T) {
	h := config.LocalDomainHost{Host: "nas1", Type: "A", Value: "192.168.10.20", TTL: 60}
	line := formatDomainHostLine(h)
	if line != "A|nas1|192.168.10.20|ttl=60" {
		t.Fatalf("line = %q, want %q", line, "A|nas1|192.168.10.20|ttl=60")
	}
	got, err := parseDomainHostLine(line)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Host != "nas1" || got.TTL != 60 || got.Value != "192.168.10.20" {
		t.Errorf("got %+v, want Host=nas1 TTL=60 Value=192.168.10.20", got)
	}
}

// TestFormatParseDomainHostLine_ApexHostIsEmpty confirms an apex record
// (Host="") round-trips correctly.
func TestFormatParseDomainHostLine_ApexHostIsEmpty(t *testing.T) {
	line := formatDomainHostLine(config.LocalDomainHost{Host: "", Type: "A", Value: "192.168.10.1"})
	if line != "A||192.168.10.1" {
		t.Fatalf("line = %q, want %q", line, "A||192.168.10.1")
	}
	got, err := parseDomainHostLine(line)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Host != "" {
		t.Errorf("Host = %q, want empty", got.Host)
	}
}

func TestParseDomainHostLines_MultipleRecords(t *testing.T) {
	records, err := parseDomainHostLines("A|nas1|192.168.10.20\nA|nas2|192.168.10.21\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(records) != 2 || records[0].Host != "nas1" || records[1].Host != "nas2" {
		t.Errorf("records = %+v, want 2 hosts (nas1, nas2)", records)
	}
}

func TestHandleLocalDomainAddPost_StagesNewDomain(t *testing.T) {
	live := testClusterWithScopes()
	srv, pushed := fakeCandidateNode(t, live)
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}
	form := strings.NewReader("name=foo.lan&ttl=3600")
	r := httptest.NewRequest(http.MethodPost, "/config/domains/new", form)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handleLocalDomainAddPost(newConfigRef(cfg))(w, r)

	if w.Code >= 400 {
		t.Fatalf("handler returned HTTP %d: %s", w.Code, w.Body.String())
	}
	if len(pushed.Scopes) != 1 {
		t.Errorf("pushed candidate has %d scope(s), want 1 (existing scopes must survive)", len(pushed.Scopes))
	}
	if len(pushed.LocalDomains) != 1 || pushed.LocalDomains[0].Name != "foo.lan" || pushed.LocalDomains[0].TTL != 3600 {
		t.Errorf("pushed LocalDomains = %+v, want one entry foo.lan/3600", pushed.LocalDomains)
	}
}

func TestHandleLocalDomainAddPost_RejectsDuplicateName(t *testing.T) {
	live := config.Cluster{LocalDomains: []config.LocalDomain{{Name: "foo.lan"}}}
	srv, _ := fakeCandidateNode(t, live)
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}
	form := strings.NewReader("name=foo.lan")
	r := httptest.NewRequest(http.MethodPost, "/config/domains/new", form)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handleLocalDomainAddPost(newConfigRef(cfg))(w, r)

	if w.Code < 400 {
		t.Fatalf("handler returned HTTP %d, want a 4xx for a duplicate domain name", w.Code)
	}
}

func TestHandleLocalDomainDeletePost_RemovesOnlyThatDomain(t *testing.T) {
	live := testClusterWithScopes()
	live.LocalDomains = []config.LocalDomain{{Name: "foo.lan"}, {Name: "bar.lan"}}
	srv, pushed := fakeCandidateNode(t, live)
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}
	r := httptest.NewRequest(http.MethodPost, "/config/domains/foo.lan/delete", nil)
	r.SetPathValue("name", "foo.lan")
	w := httptest.NewRecorder()

	handleLocalDomainDeletePost(newConfigRef(cfg))(w, r)

	if w.Code >= 400 {
		t.Fatalf("handler returned HTTP %d: %s", w.Code, w.Body.String())
	}
	if len(pushed.Scopes) != 1 {
		t.Errorf("pushed candidate has %d scope(s), want 1 (existing scopes must survive)", len(pushed.Scopes))
	}
	if len(pushed.LocalDomains) != 1 || pushed.LocalDomains[0].Name != "bar.lan" {
		t.Errorf("pushed LocalDomains = %+v, want only bar.lan left", pushed.LocalDomains)
	}
}

func TestCollectExistingDNSRecords_IncludesLocalDomains(t *testing.T) {
	c := config.Cluster{
		LocalDomains: []config.LocalDomain{{
			Name:    "foo.lan",
			Records: []config.LocalDomainHost{{Host: "nas1", Type: "A", Value: "192.168.10.20"}},
		}},
	}
	existing := collectExistingDNSRecords(c)
	found := false
	for _, e := range existing {
		if e.Name == "nas1.foo.lan." && e.Where == "local domain foo.lan" {
			found = true
		}
	}
	if !found {
		t.Errorf("collectExistingDNSRecords = %+v, want an entry for nas1.foo.lan. from local domain foo.lan", existing)
	}
}

func TestHandleLocalDomainForkPost_CreatesLiveLinkedCopy(t *testing.T) {
	live := testClusterWithScopes()
	live.LocalDomains = []config.LocalDomain{{
		Name: "foo.lan", TTL: 3600,
		Records: []config.LocalDomainHost{{Host: "nas1", Type: "A", Value: "192.168.10.20"}},
	}}
	srv, pushed := fakeCandidateNode(t, live)
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}
	form := strings.NewReader("new_name=" + url.QueryEscape("fork.lan"))
	r := httptest.NewRequest(http.MethodPost, "/config/domains/foo.lan/fork", form)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("name", "foo.lan")
	w := httptest.NewRecorder()

	handleLocalDomainForkPost(newConfigRef(cfg))(w, r)

	if w.Code >= 400 {
		t.Fatalf("handler returned HTTP %d: %s", w.Code, w.Body.String())
	}
	if len(pushed.Scopes) != 1 {
		t.Errorf("pushed candidate has %d scope(s), want 1 (existing scopes must survive)", len(pushed.Scopes))
	}
	if len(pushed.LocalDomains) != 2 {
		t.Fatalf("pushed LocalDomains has %d entries, want 2", len(pushed.LocalDomains))
	}
	var fork config.LocalDomain
	for _, d := range pushed.LocalDomains {
		if d.Name == "fork.lan" {
			fork = d
		}
	}
	if fork.ForkedFrom != "foo.lan" {
		t.Errorf("fork.ForkedFrom = %q, want %q", fork.ForkedFrom, "foo.lan")
	}
	if fork.TTL != 3600 || len(fork.Records) != 1 || fork.Records[0].Host != "nas1" {
		t.Errorf("fork = %+v, want an exact copy of foo.lan's own current content", fork)
	}
}

func TestHandleLocalDomainForkPost_RejectsDuplicateName(t *testing.T) {
	live := config.Cluster{LocalDomains: []config.LocalDomain{{Name: "foo.lan"}, {Name: "bar.lan"}}}
	srv, _ := fakeCandidateNode(t, live)
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}
	form := strings.NewReader("new_name=bar.lan")
	r := httptest.NewRequest(http.MethodPost, "/config/domains/foo.lan/fork", form)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("name", "foo.lan")
	w := httptest.NewRecorder()

	handleLocalDomainForkPost(newConfigRef(cfg))(w, r)

	if w.Code < 400 {
		t.Fatalf("handler returned HTTP %d, want a 4xx for a duplicate target name", w.Code)
	}
}

func TestHandleLocalDomainUnlinkPost_ClearsLinkKeepsContent(t *testing.T) {
	live := testClusterWithScopes()
	live.LocalDomains = []config.LocalDomain{
		{Name: "foo.lan"},
		{Name: "fork.lan", ForkedFrom: "foo.lan", TTL: 60, Records: []config.LocalDomainHost{{Host: "x", Type: "A", Value: "1.2.3.4"}}},
	}
	srv, pushed := fakeCandidateNode(t, live)
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}
	r := httptest.NewRequest(http.MethodPost, "/config/domains/fork.lan/unlink", nil)
	r.SetPathValue("name", "fork.lan")
	w := httptest.NewRecorder()

	handleLocalDomainUnlinkPost(newConfigRef(cfg))(w, r)

	if w.Code >= 400 {
		t.Fatalf("handler returned HTTP %d: %s", w.Code, w.Body.String())
	}
	var fork config.LocalDomain
	for _, d := range pushed.LocalDomains {
		if d.Name == "fork.lan" {
			fork = d
		}
	}
	if fork.ForkedFrom != "" {
		t.Errorf("fork.ForkedFrom = %q, want empty after unlink", fork.ForkedFrom)
	}
	if fork.TTL != 60 || len(fork.Records) != 1 {
		t.Errorf("fork content changed by unlink: %+v, want it untouched", fork)
	}
}

func TestHandleLocalDomainUnlinkPost_UnknownDomainReturns404(t *testing.T) {
	live := testClusterWithScopes()
	srv, _ := fakeCandidateNode(t, live)
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}
	r := httptest.NewRequest(http.MethodPost, "/config/domains/nope.lan/unlink", nil)
	r.SetPathValue("name", "nope.lan")
	w := httptest.NewRecorder()

	handleLocalDomainUnlinkPost(newConfigRef(cfg))(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}
