// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"dnshived/internal/access"
	"dnshived/internal/config"
)

func form(kv ...string) url.Values {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Add(kv[i], kv[i+1])
	}
	return v
}

func TestApplyAccessOp(t *testing.T) {
	base := &access.Config{Mode: access.ModeReport, Entries: []access.Entry{{Net: "203.0.113.0/24", DHCP: access.Deny}}, Hosts: []access.Host{{Addr: "172.32.0.5", DNS: true}}}
	tests := []struct {
		name    string
		f       url.Values
		wantErr string
		check   func(t *testing.T, c *access.Config)
	}{
		{"mode enforce", form("op", "mode", "mode", "enforce"), "", func(t *testing.T, c *access.Config) {
			if c.Mode != access.ModeEnforce {
				t.Errorf("mode = %q", c.Mode)
			}
		}},
		{"bad mode", form("op", "mode", "mode", "loud"), "report or enforce", nil},
		{"add network normalises", form("op", "entry-add", "net", "198.51.100.7/24", "dns", "allow", "dhcp", "deny"), "", func(t *testing.T, c *access.Config) {
			if len(c.Entries) != 2 || c.Entries[1].Net != "198.51.100.0/24" || c.Entries[1].DHCP != access.Deny {
				t.Errorf("entries = %+v", c.Entries)
			}
		}},
		{"add network twice", form("op", "entry-add", "net", "203.0.113.9/24"), "already in the list", nil},
		{"add bad network", form("op", "entry-add", "net", "nope"), "not a network", nil},
		{"add everyone needs a confirmation", form("op", "entry-add", "net", "0.0.0.0/0"), "I understand", nil},
		{"add everyone, confirmed", form("op", "entry-add", "net", "0.0.0.0/0", "confirm", "1"), "", nil},
		{"add wide deny needs no confirmation", form("op", "entry-add", "net", "0.0.0.0/0", "dns", "deny", "dhcp", "deny", "web", "deny"), "", nil},
		{"set entry", form("op", "entry-set", "net", "203.0.113.0/24", "on", "1", "dns", "deny", "dhcp", "allow", "web", "allow", "note", " moved "), "", func(t *testing.T, c *access.Config) {
			e := c.Entries[0]
			if e.DNS != access.Deny || e.DHCP != access.Allow || e.Off || e.Note != "moved" {
				t.Errorf("entry = %+v", e)
			}
		}},
		{"set entry off", form("op", "entry-set", "net", "203.0.113.0/24"), "", func(t *testing.T, c *access.Config) {
			if !c.Entries[0].Off {
				t.Error("an unticked box switches the entry off")
			}
		}},
		{"set missing entry", form("op", "entry-set", "net", "10.9.0.0/16"), "no longer in the list", nil},
		{"remove entry", form("op", "entry-del", "net", "203.0.113.0/24"), "", func(t *testing.T, c *access.Config) {
			if len(c.Entries) != 0 {
				t.Errorf("entries = %+v", c.Entries)
			}
		}},
		{"remove missing entry", form("op", "entry-del", "net", "10.9.0.0/16"), "no longer in the list", nil},
		{"private off", form("op", "private", "dns", "allow", "dhcp", "deny", "web", "allow"), "", func(t *testing.T, c *access.Config) {
			if c.Private == nil || !c.Private.Off || c.Private.DHCP != access.Deny {
				t.Errorf("private = %+v", c.Private)
			}
		}},
		{"add host by mac", form("op", "host-add", "mac", "00-11-22-33-44-55", "hdhcp", "1"), "", func(t *testing.T, c *access.Config) {
			if len(c.Hosts) != 2 || c.Hosts[1].MAC != "00:11:22:33:44:55" || !c.Hosts[1].DHCP {
				t.Errorf("hosts = %+v", c.Hosts)
			}
		}},
		{"add host without service", form("op", "host-add", "addr", "10.0.0.9"), "no service", nil},
		{"add host bad mac", form("op", "host-add", "mac", "zz", "hdhcp", "1"), "MAC", nil},
		{"add host dhcp without mac", form("op", "host-add", "addr", "10.0.0.9", "hdhcp", "1"), "no MAC", nil},
		{"add duplicate host", form("op", "host-add", "addr", "172.32.0.5", "hdns", "1"), "twice", nil},
		{"set host", form("op", "host-set", "key", "172.32.0.5|", "hdns", "1", "hweb", "1"), "", func(t *testing.T, c *access.Config) {
			if !c.Hosts[0].Web || !c.Hosts[0].DNS {
				t.Errorf("host = %+v", c.Hosts[0])
			}
		}},
		{"remove host", form("op", "host-del", "key", "172.32.0.5|"), "", func(t *testing.T, c *access.Config) {
			if len(c.Hosts) != 0 {
				t.Errorf("hosts = %+v", c.Hosts)
			}
		}},
		{"unknown op", form("op", "explode"), "unknown operation", nil},
	}
	before := cloneAccess(base)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := applyAccessOp(base, tt.f)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, got)
			}
		})
	}
	if len(base.Entries) != len(before.Entries) || base.Mode != before.Mode || len(base.Hosts) != len(before.Hosts) {
		t.Error("applyAccessOp must never change the list it started from")
	}
	if c, err := applyAccessOp(nil, form("op", "mode", "mode", "report")); err != nil || c == nil {
		t.Errorf("a first change on a cluster without a list must work: %v", err)
	}
}

func TestAccessLockout(t *testing.T) {
	always := []string{"192.0.2.1"}
	me := netip.MustParseAddr("203.0.113.9")
	enforce := &access.Config{Mode: access.ModeEnforce}
	if err := accessLockout(enforce, always, me); err == nil || !strings.Contains(err.Error(), "locked out") {
		t.Fatalf("enforcing with no entry for the operator must be refused, got %v", err)
	}
	if err := accessLockout(&access.Config{Mode: access.ModeReport}, always, me); err != nil {
		t.Fatalf("report mode never locks anyone out: %v", err)
	}
	covered := &access.Config{Mode: access.ModeEnforce, Entries: []access.Entry{{Net: "203.0.113.0/24"}}}
	if err := accessLockout(covered, always, me); err != nil {
		t.Fatalf("a covered operator must be fine: %v", err)
	}
	deniedWeb := &access.Config{Mode: access.ModeEnforce, Entries: []access.Entry{{Net: "203.0.113.0/24", Web: access.Deny}}}
	if err := accessLockout(deniedWeb, always, me); err == nil {
		t.Fatal("denying the web interface for the operator's own network must be refused")
	}
	whitelisted := &access.Config{Mode: access.ModeEnforce, Hosts: []access.Host{{Addr: "203.0.113.9", Web: true}}}
	if err := accessLockout(whitelisted, always, me); err != nil {
		t.Fatalf("a whitelisted operator is served: %v", err)
	}
	if err := accessLockout(enforce, always, netip.Addr{}); err != nil {
		t.Fatalf("an unknown source address cannot be judged and must not block a save: %v", err)
	}
	if err := accessLockout(enforce, always, netip.MustParseAddr("192.168.1.5")); err != nil {
		t.Fatalf("private networks are allowed by default: %v", err)
	}
}

func TestAccessGuard(t *testing.T) {
	t.Cleanup(func() { webAccessState.m.Store(nil) })
	served := false
	h := accessGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { served = true }))
	call := func(remote string) (aborted bool) {
		defer func() {
			if v := recover(); v == http.ErrAbortHandler {
				aborted = true
			} else if v != nil {
				panic(v)
			}
		}()
		served = false
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = remote
		h.ServeHTTP(httptest.NewRecorder(), req)
		return false
	}
	if call("203.0.113.9:5555"); !served {
		t.Fatal("without a list everyone is served")
	}
	m, err := access.New(&access.Config{Mode: access.ModeEnforce}, nil)
	if err != nil {
		t.Fatal(err)
	}
	webAccessState.m.Store(m)
	if !call("203.0.113.9:5555") || served {
		t.Fatal("enforce must abort the connection of a source that is not allowed")
	}
	if call("192.168.1.5:5555") || !served {
		t.Fatal("a private source must be served")
	}
	if call("not-an-address") || !served {
		t.Fatal("an unparsable source cannot be judged and must be served")
	}
	rep, err := access.New(&access.Config{Mode: access.ModeReport}, nil)
	if err != nil {
		t.Fatal(err)
	}
	webAccessState.m.Store(rep)
	if call("203.0.113.9:5555") || !served {
		t.Fatal("report mode must serve and count")
	}
	if snap := webAccessState.rep.Snapshot(false, time.Now()); len(snap.Items) == 0 {
		t.Error("report mode must have counted the source")
	}
}

func TestAccessDiffEntries(t *testing.T) {
	live := &access.Config{Mode: access.ModeReport, Entries: []access.Entry{{Net: "203.0.113.0/24"}, {Net: "198.51.100.0/24"}}}
	cand := &access.Config{Mode: access.ModeEnforce, Entries: []access.Entry{{Net: "203.0.113.0/24", DHCP: access.Deny}, {Net: "192.0.2.0/24"}}, Hosts: []access.Host{{Addr: "172.32.0.5", DNS: true}}}
	var lines []string
	for _, e := range accessDiffEntries(live, cand) {
		if e.Label != "access" {
			t.Errorf("label = %q", e.Label)
		}
		lines = append(lines, e.Detail)
	}
	joined := strings.Join(lines, "\n")
	for _, want := range []string{"mode report → enforce", "network changed: 203.0.113.0/24", "network added: 192.0.2.0/24", "network removed: 198.51.100.0/24", "whitelisted host added: 172.32.0.5"} {
		if !strings.Contains(joined, want) {
			t.Errorf("diff lacks %q:\n%s", want, joined)
		}
	}
	if got := accessDiffEntries(live, live); len(got) != 0 {
		t.Errorf("no change must give no lines, got %v", got)
	}
}

func TestAccessPageTemplateRenders(t *testing.T) {
	bars := func() (pagerBar, pagerBar) {
		return newPagerBars("/config/access", url.Values{}, "10", 30, 1, 3, 0, 10)
	}
	top, bot := bars()
	common := accessPageData{SourceNode: "core-1", Mode: access.ModeReport, YourAddr: "192.168.1.5", YourWeb: "allowed by private networks", Required: "0.9.9", Private: privateLine(nil), PagerTop: top, PagerBot: bot,
		Tabs: accessTabs("x"), Sub: accessSubTabs("x"), Notice: "<script>alert(1)</script>"}
	pages := map[string]accessPageData{}
	n := common
	n.Section = "networks"
	n.Lines = []accessLine{{Net: "203.0.113.0/24", Note: "<b>x</b>", On: true, DNS: "allow", DHCP: "deny", Web: "allow"}}
	pages["networks"] = n
	h := common
	h.Section = "hosts"
	h.Hosts = []accessHostLine{{Key: "172.32.0.5|", Addr: "172.32.0.5", Note: "\"quoted\"", DNS: true}}
	pages["hosts"] = h
	b := common
	b.Section = "blocked"
	b.PreAddr = "10.0.0.9"
	b.Blocked = []accessBlockLine{{Key: "10.0.0.9|", Addr: "10.0.0.9", Note: "<b>x</b>", DNS: true}}
	pages["blocked"] = b
	r := common
	r.Section = "report"
	r.TestAddr = "203.0.113.9"
	r.Test = []accessTestRow{{Service: "DNS", Verdict: "served", Why: "private networks"}}
	r.Report = []accessReportRow{{Node: "core-1", Service: "DNS", Source: "198.18.0.1", Count: 3, Last: "10:00:00"}}
	pages["report"] = r
	for name, d := range pages {
		var buf bytes.Buffer
		if err := accessPageTmpl.Execute(&buf, d); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out := buf.String()
		if strings.Contains(out, "<script>alert(1)</script>") || strings.Contains(out, "<b>x</b>") {
			t.Errorf("%s: user text must be escaped", name)
		}
	}
}

func TestPushPayloadCarriesAccess(t *testing.T) {
	c := config.Cluster{Access: &access.Config{Mode: access.ModeEnforce}}
	p := clusterPushPayloadFrom(c)
	if !strings.Contains(string(p.Access), `"mode":"enforce"`) {
		t.Errorf("the payload must carry the list, got %q", p.Access)
	}
	if p := clusterPushPayloadFrom(config.Cluster{}); len(p.Access) != 0 {
		t.Errorf("a cluster without a list must leave the key out, got %q", p.Access)
	}
}

func TestApplyAccessOp_Blocked(t *testing.T) {
	c, err := applyAccessOp(nil, form("op", "block-add", "addr", "10.0.0.9", "mac", "00-11-22-33-44-55", "bdns", "1", "bdhcp", "1", "note", " loud "))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Blocked) != 1 || c.Blocked[0].MAC != "00:11:22:33:44:55" || c.Blocked[0].Note != "loud" {
		t.Fatalf("blocked = %+v", c.Blocked)
	}
	if _, err := applyAccessOp(c, form("op", "block-add", "addr", "10.0.0.9", "mac", "00:11:22:33:44:55", "bdns", "1")); err == nil {
		t.Error("the same client twice must be refused")
	}
	if _, err := applyAccessOp(nil, form("op", "block-add", "addr", "10.0.0.9")); err == nil {
		t.Error("a block for no service must be refused")
	}
	key := blockKey(c.Blocked[0])
	c2, err := applyAccessOp(c, form("op", "block-set", "key", key, "bdns", "1"))
	if err != nil || c2.Blocked[0].DHCP {
		t.Fatalf("block-set: %v %+v", err, c2)
	}
	if len(c.Blocked) != 1 || !c.Blocked[0].DHCP {
		t.Error("an edit must not touch the list it started from")
	}
	if d := accessDiffEntries(c, c2); len(d) != 1 || !strings.Contains(d[0].Detail, "blocked client changed") {
		t.Errorf("diff = %+v", d)
	}
	c3, err := applyAccessOp(c2, form("op", "block-del", "key", key))
	if err != nil || len(c3.Blocked) != 0 {
		t.Fatalf("block-del: %v %+v", err, c3)
	}
	if d := accessDiffEntries(c2, c3); len(d) != 1 || !strings.Contains(d[0].Detail, "client unblocked") {
		t.Errorf("diff = %+v", d)
	}
}
