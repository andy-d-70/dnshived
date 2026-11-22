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
	"sync"
	"testing"
)

type dsFake struct {
	name     string
	role     string
	enabled  bool
	srv      *httptest.Server
	mu       sync.Mutex
	posts    []string
	bodies   []string
	reply    int
	replyOut string
}

func newDSFake(t *testing.T, name, role string, enabled bool) *dsFake {
	f := &dsFake{name: name, role: role, enabled: enabled, reply: 200, replyOut: `{"rev":7,"warnings":[]}`}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.URL.Path == "/api/v1/audit":
			w.WriteHeader(200)
		case !f.enabled && strings.HasPrefix(r.URL.Path, "/api/v1/dnsstore"):
			http.NotFound(w, r)
		case r.URL.Path == "/api/v1/dnsstore/status":
			json.NewEncoder(w).Encode(map[string]any{"rev": 7, "commit_index": 7, "head": 7, "authoritative": false, "hosts": 1, "records": 1,
				"published":   map[string]any{"names": 3, "records": 4, "collisions": []any{}},
				"replication": map[string]any{"role": f.role, "leader": "core1", "self": f.name, "term": 3, "voters": []string{"core1", "core2"}}})
		case r.URL.Path == "/api/v1/dnsstore/hosts":
			json.NewEncoder(w).Encode(map[string]any{"total": 1, "items": []any{map[string]any{"id": strings.Repeat("a", 32), "label": "cam-1", "domains": []string{"example.lan"}, "addrs": []any{map[string]any{"ip": "10.0.0.5"}}}}})
		case r.URL.Path == "/api/v1/dnsstore/records":
			json.NewEncoder(w).Encode(map[string]any{"total": 1, "items": []any{map[string]any{"id": strings.Repeat("b", 32), "owner": "info.example.lan", "type": "TXT", "value": "hello <b>x</b>"}}})
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/api/v1/dnsstore/"):
			b, _ := io.ReadAll(r.Body)
			f.posts = append(f.posts, r.URL.Path)
			f.bodies = append(f.bodies, string(b))
			if f.role != "leader" {
				w.WriteHeader(409)
				io.WriteString(w, `{"error":"not_leader","leader":"core1"}`)
				return
			}
			w.WriteHeader(f.reply)
			io.WriteString(w, f.replyOut)
		case r.URL.Path == "/api/v1/config":
			io.WriteString(w, `{"local_domains":[{"name":"example.lan"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func dsRef(t *testing.T, fakes ...*dsFake) *configRef {
	cfg := &WebConfig{}
	for _, f := range fakes {
		n := nodeConfigFor(t, f.srv)
		n.Name = f.name
		cfg.Nodes = append(cfg.Nodes, n)
	}
	return newConfigRef(cfg)
}

func dsGet(t *testing.T, ref *configRef, target string) string {
	t.Helper()
	w := httptest.NewRecorder()
	handleDNSStore(ref)(w, httptest.NewRequest("GET", target, nil))
	if w.Code != 200 {
		t.Fatalf("GET %s: %d", target, w.Code)
	}
	return w.Body.String()
}

func dsPostForm(t *testing.T, h http.HandlerFunc, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", "/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func TestDNSStorePage_ShowsHostsRecordsLeaderAndMode(t *testing.T) {
	a, b := newDSFake(t, "core1", "leader", true), newDSFake(t, "core2", "follower", true)
	ref := dsRef(t, b, a)
	body := dsGet(t, ref, "/dns/store")
	for _, want := range []string{"cam-1", "example.lan", "10.0.0.5", "leader: <b>core1</b>", "overlay", "Go authoritative", "Hosts 1", "Records 1", "core2", "follower"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	rec := dsGet(t, ref, "/dns/store?kind=records")
	if !strings.Contains(rec, "info.example.lan") || strings.Contains(rec, "<b>x</b>") || !strings.Contains(rec, "&lt;b&gt;x&lt;/b&gt;") {
		t.Fatal("records are listed and their data is escaped")
	}
}

func TestDNSStorePage_NotEnabled(t *testing.T) {
	a := newDSFake(t, "core1", "leader", false)
	body := dsGet(t, dsRef(t, a), "/dns/store")
	if !strings.Contains(body, "not running on any core") || strings.Contains(body, "Go authoritative") {
		t.Fatal("a cluster without the store says so and offers no controls")
	}
}

func TestDNSStorePage_BannerTextIsEscaped(t *testing.T) {
	a := newDSFake(t, "core1", "leader", true)
	body := dsGet(t, dsRef(t, a), "/dns/store?err="+url.QueryEscape("<script>alert(1)</script>"))
	if strings.Contains(body, "<script>alert(1)") {
		t.Fatal("a message in the address must be escaped")
	}
}

func TestDNSStorePage_IsNotAnEditor(t *testing.T) {
	a := newDSFake(t, "core1", "leader", true)
	ref := dsRef(t, a)
	for _, target := range []string{"/dns/store", "/dns/store?kind=records"} {
		body := dsGet(t, ref, target)
		for _, gone := range []string{"Add a host", "Add record", "/dns/store/host", "/dns/store/record", "/dns/store/delete", "Delete…", "DNS VIP", "/dns/store/vip"} {
			if strings.Contains(body, gone) {
				t.Errorf("%s still offers %q", target, gone)
			}
		}
		if !strings.Contains(body, "/config/domains") {
			t.Errorf("%s does not point to the Domains page", target)
		}
	}
}

func TestDNSStoreWrites_ImportAndCutoverGoToTheLeaderOnly(t *testing.T) {
	a, b := newDSFake(t, "core1", "leader", true), newDSFake(t, "core2", "follower", true)
	ref := dsRef(t, b, a)
	dsPostForm(t, handleDNSStoreImport(ref), url.Values{"dry": {"1"}})
	dsPostForm(t, handleDNSStoreCutover(ref), url.Values{"authoritative": {"on"}})
	want := []string{"/api/v1/dnsstore/import", "/api/v1/dnsstore/settings"}
	if strings.Join(a.posts, ",") != strings.Join(want, ",") || len(b.posts) != 0 {
		t.Fatalf("leader posts %v, follower posts %v", a.posts, b.posts)
	}
	if !strings.Contains(a.bodies[0], `"dry_run":true`) || !strings.Contains(a.bodies[1], `"authoritative":true`) {
		t.Fatalf("import and settings bodies: %s | %s", a.bodies[0], a.bodies[1])
	}
}

func TestDNSStoreWrites_GateErrorsReachThePage(t *testing.T) {
	a := newDSFake(t, "core1", "leader", true)
	a.reply, a.replyOut = 422, `{"errors":["no local domain is configured, so there is nothing to answer for"],"warnings":[]}`
	w := dsPostForm(t, handleDNSStoreCutover(dsRef(t, a)), url.Values{"authoritative": {"on"}})
	loc, _ := url.Parse(w.Header().Get("Location"))
	if !strings.Contains(loc.Query().Get("err"), "no local domain") {
		t.Fatalf("the core's reason must be shown: %s", w.Header().Get("Location"))
	}
}

func TestDNSStoreWrites_NoCoreRunsTheStore(t *testing.T) {
	a := newDSFake(t, "core1", "leader", false)
	w := dsPostForm(t, handleDNSStoreCutover(dsRef(t, a)), url.Values{"authoritative": {"on"}})
	if loc, _ := url.Parse(w.Header().Get("Location")); !strings.Contains(loc.Query().Get("err"), "not enabled") {
		t.Fatalf("location %s", w.Header().Get("Location"))
	}
}
