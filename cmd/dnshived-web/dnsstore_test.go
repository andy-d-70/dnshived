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

func TestDNSStoreWrites_GoToTheLeaderOnly(t *testing.T) {
	a, b := newDSFake(t, "core1", "leader", true), newDSFake(t, "core2", "follower", true)
	ref := dsRef(t, b, a)
	w := dsPostForm(t, handleDNSStoreHost(ref), url.Values{"label": {"nas"}, "domains": {"example.lan, lab.lan"}, "addrs": {"10.0.0.9 fd00::9"}, "ptr": {"1"}, "ttl": {"600"}})
	if w.Code != 303 || !strings.Contains(w.Header().Get("Location"), "msg=") {
		t.Fatalf("host add: %d %s", w.Code, w.Header().Get("Location"))
	}
	if len(a.posts) != 1 || len(b.posts) != 0 {
		t.Fatalf("the write must go to the leader first and only: leader %d, follower %d", len(a.posts), len(b.posts))
	}
	var sent struct {
		Ops []struct {
			Op   string `json:"op"`
			Kind string `json:"kind"`
			Host struct {
				Label   string   `json:"label"`
				Domains []string `json:"domains"`
				Addrs   []struct {
					IP  string `json:"ip"`
					PTR bool   `json:"ptr"`
				} `json:"addrs"`
				TTL int `json:"ttl"`
			} `json:"host"`
		} `json:"ops"`
	}
	if err := json.Unmarshal([]byte(a.bodies[0]), &sent); err != nil || len(sent.Ops) != 1 {
		t.Fatalf("body %s: %v", a.bodies[0], err)
	}
	h := sent.Ops[0].Host
	if h.Label != "nas" || len(h.Domains) != 2 || len(h.Addrs) != 2 || !h.Addrs[0].PTR || h.TTL != 600 {
		t.Fatalf("host sent: %+v", h)
	}

	if w = dsPostForm(t, handleDNSStoreHost(ref), url.Values{"label": {"x"}}); !strings.Contains(w.Header().Get("Location"), "err=") {
		t.Fatal("a host without a domain is refused before anything is sent")
	}
	if len(a.posts) != 1 {
		t.Fatal("nothing must be sent for an incomplete form")
	}
}

func TestDNSStoreWrites_RecordDeleteImportAndCutover(t *testing.T) {
	a := newDSFake(t, "core1", "leader", true)
	ref := dsRef(t, a)
	dsPostForm(t, handleDNSStoreRecord(ref), url.Values{"type": {"MX"}, "owner": {"example.lan"}, "target": {"mail.example.lan"}, "priority": {"10"}})
	dsPostForm(t, handleDNSStoreRecord(ref), url.Values{"type": {"SRV"}, "owner": {"_sip._tcp.example.lan"}, "target": {"pbx.example.lan"}, "priority": {"1"}, "weight": {"5"}, "port": {"5060"}})
	dsPostForm(t, handleDNSStoreDelete(ref), url.Values{"kind": {"record"}, "id": {strings.Repeat("b", 32)}})
	dsPostForm(t, handleDNSStoreImport(ref), url.Values{"dry": {"1"}})
	dsPostForm(t, handleDNSStoreCutover(ref), url.Values{"authoritative": {"on"}})
	want := []string{"/api/v1/dnsstore/commit", "/api/v1/dnsstore/commit", "/api/v1/dnsstore/commit", "/api/v1/dnsstore/import", "/api/v1/dnsstore/settings"}
	if strings.Join(a.posts, ",") != strings.Join(want, ",") {
		t.Fatalf("posts: %v", a.posts)
	}
	if !strings.Contains(a.bodies[0], `"pref":10`) || !strings.Contains(a.bodies[1], `"priority":1`) || !strings.Contains(a.bodies[1], `"port":5060`) {
		t.Fatalf("MX uses pref, SRV uses priority: %s | %s", a.bodies[0], a.bodies[1])
	}
	if !strings.Contains(a.bodies[3], `"dry_run":true`) || !strings.Contains(a.bodies[4], `"authoritative":true`) {
		t.Fatalf("import and settings bodies: %s | %s", a.bodies[3], a.bodies[4])
	}
	if w := dsPostForm(t, handleDNSStoreDelete(ref), url.Values{"kind": {"host"}, "id": {"short"}}); !strings.Contains(w.Header().Get("Location"), "err=") {
		t.Fatal("a bad id is refused")
	}
}

func TestDNSStoreWrites_GateErrorsReachThePage(t *testing.T) {
	a := newDSFake(t, "core1", "leader", true)
	a.reply, a.replyOut = 422, `{"errors":["cam.example.lan is already used by another host"],"warnings":[]}`
	w := dsPostForm(t, handleDNSStoreHost(dsRef(t, a)), url.Values{"label": {"cam"}, "domains": {"example.lan"}})
	loc, _ := url.Parse(w.Header().Get("Location"))
	if !strings.Contains(loc.Query().Get("err"), "already used by another host") {
		t.Fatalf("the gate's reason must be shown: %s", w.Header().Get("Location"))
	}
}

func TestDNSStoreWrites_NoCoreRunsTheStore(t *testing.T) {
	a := newDSFake(t, "core1", "leader", false)
	w := dsPostForm(t, handleDNSStoreHost(dsRef(t, a)), url.Values{"label": {"a"}, "domains": {"example.lan"}})
	if loc, _ := url.Parse(w.Header().Get("Location")); !strings.Contains(loc.Query().Get("err"), "not enabled") {
		t.Fatalf("location %s", w.Header().Get("Location"))
	}
}

func TestDNSStoreWrites_VIP(t *testing.T) {
	a := newDSFake(t, "core1", "leader", true)
	ref := dsRef(t, a)
	dsPostForm(t, handleDNSStoreVIP(ref), url.Values{"vip": {"192.0.2.53/24"}, "vrrp_id": {"61"}})
	dsPostForm(t, handleDNSStoreVIP(ref), url.Values{"vip": {"192.0.2.53/24"}, "vrrp_id": {"61"}, "remove": {"1"}})
	if len(a.bodies) != 2 || !strings.Contains(a.bodies[0], `"dns_vip":"192.0.2.53/24"`) || !strings.Contains(a.bodies[0], `"vrrp_id":61`) || !strings.Contains(a.bodies[1], `"dns_vip":""`) {
		t.Fatalf("bodies: %v", a.bodies)
	}
	if !strings.Contains(dsGet(t, ref, "/dns/store"), "DNS VIP: not set") {
		t.Fatal("the page shows that no DNS VIP is set")
	}
}
