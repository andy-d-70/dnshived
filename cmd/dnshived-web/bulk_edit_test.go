// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"dnshived/internal/config"
)

func bulkDomains() []config.LocalDomain {
	return []config.LocalDomain{
		{Name: "a.lan", Records: []config.LocalDomainHost{
			{Host: "h1", Type: "A", Value: "10.0.0.1", TTL: 60},
			{Host: "h2", Type: "A", Value: "10.0.0.2"},
			{Host: "mail", Type: "MX", Target: "h1.a.lan.", Priority: 10},
		}},
		{Name: "b.lan", Records: []config.LocalDomainHost{{Host: "h1", Type: "A", Value: "10.0.0.1"}}},
		{Name: "c.lan", ForkedFrom: "a.lan"},
	}
}

func lines(h ...config.LocalDomainHost) map[string]bool {
	m := map[string]bool{}
	for _, r := range h {
		m[formatDomainHostLine(r)] = true
	}
	return m
}

func TestApplyBulk_Actions(t *testing.T) {
	in := bulkDomains()
	h1, h2 := in[0].Records[0], in[0].Records[1]
	tests := []struct {
		name    string
		sel     map[string]bool
		spec    bulkSpec
		check   func(t *testing.T, out []config.LocalDomain, ch []bulkChange)
		wantErr string
	}{
		{"set ttl", lines(h1, h2), bulkSpec{Action: "ttl", TTL: 300}, func(t *testing.T, out []config.LocalDomain, ch []bulkChange) {
			if out[0].Records[0].TTL != 300 || out[0].Records[1].TTL != 300 || out[0].Records[2].TTL != 0 || len(ch) != 2 {
				t.Errorf("%+v %v", out[0].Records, ch)
			}
		}, ""},
		{"follow the domain ttl", lines(h1, h2), bulkSpec{Action: "ttlclear"}, func(t *testing.T, out []config.LocalDomain, ch []bulkChange) {
			if out[0].Records[0].TTL != 0 || len(ch) != 1 {
				t.Errorf("only the record with its own TTL changes: %+v %v", out[0].Records, ch)
			}
		}, ""},
		{"exclude from probes", lines(h1), bulkSpec{Action: "probe-off"}, func(t *testing.T, out []config.LocalDomain, ch []bulkChange) {
			if !out[0].Records[0].ProbeDisabled || out[0].Records[1].ProbeDisabled {
				t.Errorf("%+v", out[0].Records)
			}
		}, ""},
		{"set value", lines(h2), bulkSpec{Action: "value", Value: "10.0.0.9"}, func(t *testing.T, out []config.LocalDomain, ch []bulkChange) {
			if out[0].Records[1].Value != "10.0.0.9" || len(ch) != 1 || ch[0].Before != "10.0.0.2" {
				t.Errorf("%+v %v", out[0].Records, ch)
			}
		}, ""},
		{"value onto an existing record", lines(h2), bulkSpec{Action: "value", Value: "10.0.0.1"}, func(t *testing.T, out []config.LocalDomain, ch []bulkChange) {
			if len(out[0].Records) != 3 {
				t.Errorf("a different host is no duplicate: %+v", out[0].Records)
			}
		}, ""},
		{"value for a type without a single value", lines(in[0].Records[2]), bulkSpec{Action: "value", Value: "x"}, nil, "only for A, AAAA"},
		{"delete", lines(h1, h2), bulkSpec{Action: "delete"}, func(t *testing.T, out []config.LocalDomain, ch []bulkChange) {
			if len(out[0].Records) != 1 || out[0].Records[0].Type != "MX" {
				t.Errorf("%+v", out[0].Records)
			}
			if len(out[2].Records) != 1 {
				t.Errorf("the linked domain follows: %+v", out[2].Records)
			}
		}, ""},
		{"move", lines(h2), bulkSpec{Action: "move", Target: "b.lan"}, func(t *testing.T, out []config.LocalDomain, ch []bulkChange) {
			if len(out[0].Records) != 2 || len(out[1].Records) != 2 || out[1].Records[1].Host != "h2" {
				t.Errorf("%+v %+v", out[0].Records, out[1].Records)
			}
		}, ""},
		{"copy", lines(h2), bulkSpec{Action: "copy", Target: "b.lan"}, func(t *testing.T, out []config.LocalDomain, ch []bulkChange) {
			if len(out[0].Records) != 3 || len(out[1].Records) != 2 {
				t.Errorf("%+v %+v", out[0].Records, out[1].Records)
			}
		}, ""},
		{"move onto a duplicate", lines(h1), bulkSpec{Action: "move", Target: "b.lan"}, nil, "already has this record"},
		{"move to a linked domain", lines(h2), bulkSpec{Action: "move", Target: "c.lan"}, nil, "linked"},
		{"move to itself", lines(h2), bulkSpec{Action: "move", Target: "a.lan"}, nil, "different domain"},
		{"move to an unknown domain", lines(h2), bulkSpec{Action: "move", Target: "x.lan"}, nil, "not found"},
		{"selection gone", map[string]bool{"A|gone|1.1.1.1": true}, bulkSpec{Action: "delete"}, nil, "changed in the meantime"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := formatDomainHostLines(in[0].Records)
			out, ch, err := applyBulk(in, 0, tt.sel, tt.spec)
			if formatDomainHostLines(in[0].Records) != before {
				t.Fatal("the input was modified")
			}
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, out, ch)
		})
	}
}

func TestApplyBulk_ValueMakingADuplicateIsRefused(t *testing.T) {
	d := []config.LocalDomain{{Name: "a.lan", Records: []config.LocalDomainHost{
		{Host: "h1", Type: "A", Value: "10.0.0.1"},
		{Host: "h1", Type: "A", Value: "10.0.0.3"},
	}}}
	_, _, err := applyBulk(d, 0, lines(d[0].Records[1]), bulkSpec{Action: "value", Value: "10.0.0.1"})
	if err == nil || !strings.Contains(err.Error(), "already has this record") {
		t.Fatalf("err = %v", err)
	}
	_, _, err = applyBulk(d, 0, lines(d[0].Records...), bulkSpec{Action: "value", Value: "10.0.0.9"})
	if err == nil {
		t.Fatal("two records of one host set to one value are a duplicate")
	}
}

func TestParseBulkSpec(t *testing.T) {
	bad := []string{"", "action=nope", "action=ttl", "action=ttl&ttl=0", "action=ttl&ttl=abc", "action=value", "action=move", "action=copy&target="}
	for _, b := range bad {
		f, _ := url.ParseQuery(b)
		if _, err := parseBulkSpec(f); err == nil {
			t.Errorf("%q must be refused", b)
		}
	}
	f, _ := url.ParseQuery("action=ttl&ttl=300")
	if s, err := parseBulkSpec(f); err != nil || s.TTL != 300 {
		t.Errorf("%+v %v", s, err)
	}
}

func TestBulkSelection_TickedAndAllMatching(t *testing.T) {
	cluster := config.Cluster{LocalDomains: bulkDomains()}
	d := cluster.LocalDomains[0]
	f := url.Values{"line": {"A|h1|10.0.0.1|ttl=60", " "}}
	sel, err := bulkSelection(cluster, d, f)
	if err != nil || len(sel) != 1 {
		t.Fatalf("%v %v", sel, err)
	}
	sel, err = bulkSelection(cluster, d, url.Values{"all": {"1"}, "q": {"h"}})
	if err != nil || len(sel) != 3 {
		t.Fatalf("search h matches h1, h2 and the host names that contain h: %v %v", sel, err)
	}
	sel, err = bulkSelection(cluster, d, url.Values{"all": {"1"}, "q": {"mx"}})
	if err != nil || len(sel) != 1 {
		t.Fatalf("%v %v", sel, err)
	}
	if _, err := bulkSelection(cluster, d, url.Values{}); err == nil {
		t.Error("nothing selected must be refused")
	}
	if _, err := bulkSelection(cluster, d, url.Values{"all": {"1"}, "q": {"zzz"}}); err == nil {
		t.Error("an empty match must be refused")
	}
}

func TestDomainBulkHandlers_PreviewThenStage(t *testing.T) {
	live := validCluster()
	live.LocalDomains = bulkDomains()
	srv, pushed := fakeCandidateNode(t, live)
	defer srv.Close()
	ref := newConfigRef(&WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}})

	body := "action=ttl&ttl=300&line=" + url.QueryEscape("A|h2|10.0.0.2") + "&line=" + url.QueryEscape("A|h1|10.0.0.1|ttl=60")
	w := recordPost(t, handleDomainBulk(ref), "a.lan", "/x", body)
	page := w.Body.String()
	if w.Code != http.StatusOK || len(pushed.LocalDomains) != 0 {
		t.Fatalf("preview: %d, nothing may be staged by it: %s", w.Code, page)
	}
	for _, want := range []string{"Set the TTL", "2 selected record(s)", "Stage 2 change(s)", `name="line" value="A|h2|10.0.0.2"`, `action="/config/domains/a.lan/bulk/stage"`} {
		if !strings.Contains(page, want) {
			t.Errorf("preview lacks %q", want)
		}
	}

	w = recordPost(t, handleDomainBulkStage(ref), "a.lan", "/x", body)
	if w.Code >= 400 || len(pushed.LocalDomains) != 3 {
		t.Fatalf("stage: %d %s %+v", w.Code, w.Body.String(), pushed.LocalDomains)
	}
	if pushed.LocalDomains[0].Records[0].TTL != 300 || pushed.LocalDomains[0].Records[1].TTL != 300 {
		t.Errorf("%+v", pushed.LocalDomains[0].Records)
	}
}

func TestDomainBulkHandlers_RefuseWithAMessage(t *testing.T) {
	live := validCluster()
	live.LocalDomains = bulkDomains()
	srv, pushed := fakeCandidateNode(t, live)
	defer srv.Close()
	ref := newConfigRef(&WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}})
	for _, tc := range []struct{ name, domain, body, want string }{
		{"no selection", "a.lan", "action=delete", "no+record"},
		{"mixed types for a value", "a.lan", "action=value&value=x&line=" + url.QueryEscape("A|h1|10.0.0.1|ttl=60") + "&line=" + url.QueryEscape(formatDomainHostLine(bulkDomains()[0].Records[2])), "only+for"},
		{"linked domain", "c.lan", "action=delete&line=x", "linked"},
	} {
		w := recordPost(t, handleDomainBulkStage(ref), tc.domain, "/x", tc.body)
		if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), tc.want) {
			t.Errorf("%s: %d %q", tc.name, w.Code, w.Header().Get("Location"))
		}
	}
	if len(pushed.LocalDomains) != 0 {
		t.Error("a refused action must stage nothing")
	}
}

func TestDomainEditor_ShowsTheBulkBarOnlyWhereEditable(t *testing.T) {
	cluster := config.Cluster{LocalDomains: bulkDomains()}
	data := buildDomEditor(cluster, false, url.Values{"d": {"a.lan"}})
	if len(data.BulkActions) == 0 || len(data.BulkTargets) != 1 || data.BulkTargets[0] != "b.lan" {
		t.Fatalf("actions %d, targets %v", len(data.BulkActions), data.BulkTargets)
	}
	var b strings.Builder
	if err := domEditorTmpl.Execute(&b, data); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `id="bulk-form"`) || !strings.Contains(b.String(), `class="sel"`) {
		t.Error("the bulk bar and the checkboxes are missing")
	}
	for _, d := range []string{"c.lan", domDHCPNames} {
		data = buildDomEditor(cluster, false, url.Values{"d": {d}})
		b.Reset()
		if err := domEditorTmpl.Execute(&b, data); err != nil {
			t.Fatal(err)
		}
		if len(data.BulkActions) != 0 || strings.Contains(b.String(), `id="bulk-form"`) || strings.Contains(b.String(), `class="sel"`) {
			t.Errorf("%s must not offer bulk edit", d)
		}
	}
}

func TestHandleDomainTTL_RecordsFollow(t *testing.T) {
	live := validCluster()
	live.LocalDomains = bulkDomains()
	srv, pushed := fakeCandidateNode(t, live)
	defer srv.Close()
	ref := newConfigRef(&WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}})
	w := recordPost(t, handleDomainTTL(ref), "a.lan", "/x", "ttl=500&follow=1")
	if w.Code >= 400 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if pushed.LocalDomains[0].TTL != 500 || pushed.LocalDomains[0].Records[0].TTL != 0 {
		t.Errorf("%+v", pushed.LocalDomains[0])
	}
	recordPost(t, handleDomainTTL(ref), "a.lan", "/x", "ttl=500")
	if pushed.LocalDomains[0].Records[0].TTL != 60 {
		t.Errorf("without the option the record keeps its own TTL: %+v", pushed.LocalDomains[0].Records[0])
	}
}

func TestRecordIndexMatchesPrecheckRecord(t *testing.T) {
	existing := []config.LocalDomainHost{
		{Host: "a", Type: "A", Value: "10.0.0.1"},
		{Host: "www", Type: "CNAME", Value: "a.lan."},
		{Host: "b", Type: "A", Value: "10.0.0.2"},
	}
	idx := newRecordIndex()
	for _, h := range existing {
		idx.add(h)
	}
	for _, h := range []config.LocalDomainHost{
		{Host: "A", Type: "a", Value: "10.0.0.1", TTL: 9},
		{Host: "a", Type: "A", Value: "10.0.0.9"},
		{Host: "a", Type: "CNAME", Value: "x.lan."},
		{Host: "www", Type: "A", Value: "10.0.0.5"},
		{Host: "www", Type: "CNAME", Value: "y.lan."},
		{Host: "new", Type: "A", Value: "10.0.0.6"},
		{Host: "new", Type: "CNAME", Value: "z.lan."},
	} {
		want := precheckRecord(existing, h, -1)
		got := idx.conflict(h)
		if (want == nil) != (got == nil) {
			t.Errorf("%+v: precheck %v, index %v", h, want, got)
		}
	}
}

func TestApplyBulk_LargeDomainIsFast(t *testing.T) {
	d := config.LocalDomain{Name: "big.lan"}
	for i := 0; i < 40000; i++ {
		d.Records = append(d.Records, config.LocalDomainHost{Host: "h" + strconv.Itoa(i), Type: "A", Value: "10.1." + strconv.Itoa(i/250) + "." + strconv.Itoa(i%250)})
	}
	sel := map[string]bool{}
	for _, r := range d.Records {
		sel[formatDomainHostLine(r)] = true
	}
	start := time.Now()
	out, ch, err := applyBulk([]config.LocalDomain{d}, 0, sel, bulkSpec{Action: "value", Value: "10.9.9.9"})
	if err != nil || len(ch) != 40000 || len(out[0].Records) != 40000 {
		t.Fatalf("err %v, changes %d", err, len(ch))
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Errorf("took %v for 40000 records", el)
	}
}
