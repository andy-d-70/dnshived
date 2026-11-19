// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"dnshived/internal/config"
)

func TestDomRecordLine(t *testing.T) {
	tests := []struct {
		name string
		form url.Values
		want string
		err  bool
	}{
		{"a", url.Values{"type": {"A"}, "name": {"nas"}, "value": {"10.0.0.5"}}, "A|nas|10.0.0.5", false},
		{"apex default", url.Values{"type": {"TXT"}, "value": {"v=spf1 -all"}}, "TXT|@|v=spf1 -all", false},
		{"mx", url.Values{"type": {"mx"}, "name": {"@"}, "target": {"mail.lan"}, "priority": {"10"}}, "MX|@|mail.lan|10", false},
		{"srv", url.Values{"type": {"SRV"}, "name": {"_x._tcp"}, "target": {"h.lan"}, "port": {"8443"}, "priority": {"1"}, "weight": {"2"}}, "SRV|_x._tcp|h.lan|8443|1|2", false},
		{"caa", url.Values{"type": {"CAA"}, "name": {"@"}, "value": {"letsencrypt.org"}}, "CAA|@|0|issue|letsencrypt.org", false},
		{"ttl", url.Values{"type": {"A"}, "name": {"x"}, "value": {"1.2.3.4"}, "ttl": {"300"}}, "A|x|1.2.3.4|ttl=300", false},
		{"bad ttl", url.Values{"type": {"A"}, "name": {"x"}, "value": {"1.2.3.4"}, "ttl": {"soon"}}, "", true},
		{"pipe", url.Values{"type": {"A"}, "name": {"x|y"}, "value": {"1.2.3.4"}}, "", true},
		{"no value", url.Values{"type": {"A"}, "name": {"x"}}, "", true},
		{"unknown type", url.Values{"type": {"HINFO"}, "name": {"x"}, "value": {"y"}}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := domRecordLine(tt.form)
			if (err != nil) != tt.err || got != tt.want {
				t.Errorf("got %q, %v; want %q (err %v)", got, err, tt.want, tt.err)
			}
		})
	}
}

func TestPrecheckRecord(t *testing.T) {
	ex := []config.LocalDomainHost{{Host: "nas", Type: "A", Value: "10.0.0.5"}, {Host: "www", Type: "CNAME", Value: "nas.lan."}}
	if err := precheckRecord(ex, config.LocalDomainHost{Host: "NAS", Type: "a", Value: "10.0.0.5", TTL: 60}, -1); err == nil || !strings.Contains(err.Error(), "already has this record") {
		t.Errorf("a duplicate is refused whatever the case or TTL: %v", err)
	}
	if err := precheckRecord(ex, config.LocalDomainHost{Host: "www", Type: "A", Value: "10.0.0.9"}, -1); err == nil || !strings.Contains(err.Error(), "CNAME") {
		t.Errorf("data beside a CNAME is refused: %v", err)
	}
	if err := precheckRecord(ex, config.LocalDomainHost{Host: "nas", Type: "CNAME", Value: "x.lan."}, -1); err == nil {
		t.Error("a CNAME beside other data is refused")
	}
	if err := precheckRecord(ex, config.LocalDomainHost{Host: "nas", Type: "A", Value: "10.0.0.6"}, -1); err != nil {
		t.Errorf("a second address at a name is fine: %v", err)
	}
	if err := precheckRecord(ex, config.LocalDomainHost{Host: "nas", Type: "A", Value: "10.0.0.5"}, 0); err != nil {
		t.Errorf("editing a record may keep its own value: %v", err)
	}
}

func editorCluster() config.Cluster {
	recs := []config.LocalDomainHost{{Host: "nas", Type: "A", Value: "10.0.0.5"}, {Host: "www", Type: "CNAME", Value: "nas.office.lan."}, {Host: "@", Type: "MX", Target: "mail.office.lan.", Priority: 10}, {Host: "zeta", Type: "A", Value: "10.0.0.9", TTL: 60}}
	return config.Cluster{
		LocalDomains: []config.LocalDomain{{Name: "office.lan", Records: recs}, {Name: "av.lan"}, {Name: "link.lan", ForkedFrom: "office.lan", Records: recs}},
		Scopes: map[string]config.ScopeConfig{"office": {Reservations: []config.Reservation{
			{MAC: "aa:bb:cc:00:00:01", IP: "10.0.1.50", Hostname: "mixer.office.lan", Names: []string{"mixer-ctl.office.lan", "short"}}}}},
	}
}

func TestBuildDomEditor_ListsSortsFiltersAndShowsDHCPNames(t *testing.T) {
	d := buildDomEditor(editorCluster(), false, url.Values{"d": {"office.lan"}})
	if d.Domain == nil || d.Domain.Name != "office.lan" || d.Domain.Static != 4 || d.Domain.Dynamic != 2 || d.Total != 6 {
		t.Fatalf("header/total wrong: %+v total %d", d.Domain, d.Total)
	}
	if d.Rows[0].Host != "@" {
		t.Errorf("sorted by name, the apex first: %+v", d.Rows)
	}
	var dyn []string
	for _, r := range d.Rows {
		if r.Dynamic {
			dyn = append(dyn, r.Host)
		}
	}
	if len(dyn) != 2 || dyn[0] != "mixer" && dyn[1] != "mixer" {
		t.Errorf("DHCP names ending in the domain are shown relative; short names are not: %v", dyn)
	}
	if got := buildDomEditor(editorCluster(), false, url.Values{"d": {"office.lan"}, "q": {"mail"}}); got.Total != 1 {
		t.Errorf("search finds the MX by its target: %d", got.Total)
	}
	if got := buildDomEditor(editorCluster(), false, url.Values{"d": {"office.lan"}, "show": {"static"}}); got.Total != 4 {
		t.Errorf("Static chip: %d", got.Total)
	}
	if got := buildDomEditor(editorCluster(), false, url.Values{"d": {"office.lan"}, "show": {"dhcp"}}); got.Total != 2 {
		t.Errorf("DHCP chip: %d", got.Total)
	}
	desc := buildDomEditor(editorCluster(), false, url.Values{"d": {"office.lan"}, "sort": {"name"}, "dir": {"desc"}, "show": {"static"}})
	if desc.Rows[0].Host != "zeta" {
		t.Errorf("descending by name starts with zeta: %+v", desc.Rows)
	}
	ttl := buildDomEditor(editorCluster(), false, url.Values{"d": {"office.lan"}, "sort": {"ttl"}, "dir": {"desc"}, "show": {"static"}})
	if ttl.Rows[0].Host != "zeta" {
		t.Errorf("sort by TTL: %+v", ttl.Rows)
	}
	if v := buildDomEditor(editorCluster(), false, url.Values{"d": {domDHCPNames}}); !v.Virtual || v.Total != 3 {
		t.Errorf("the virtual entry lists all DHCP names, short ones too: %+v", v)
	}
	if len(d.Rail) != 4 || !d.Rail[len(d.Rail)-1].Active == false && d.Rail[len(d.Rail)-1].Name != domDHCPNames {
		t.Errorf("rail = %+v", d.Rail)
	}
}

func TestBuildDomEditor_PagesServerSide(t *testing.T) {
	c := config.Cluster{LocalDomains: []config.LocalDomain{{Name: "big.lan"}}}
	for i := 0; i < 23; i++ {
		c.LocalDomains[0].Records = append(c.LocalDomains[0].Records, config.LocalDomainHost{Host: "h" + string(rune('a'+i)), Type: "A", Value: "10.0.0.1"})
	}
	d := buildDomEditor(c, false, url.Values{"d": {"big.lan"}})
	if d.Total != 23 || len(d.Rows) != 10 {
		t.Errorf("default page size is 10: total %d rows %d", d.Total, len(d.Rows))
	}
	if p3 := buildDomEditor(c, false, url.Values{"d": {"big.lan"}, "page": {"3"}}); len(p3.Rows) != 3 {
		t.Errorf("page 3 holds the last 3: %d", len(p3.Rows))
	}
}

func TestDomEditorTmpl_RendersEscapedAndGuardsLinkedDomains(t *testing.T) {
	c := editorCluster()
	c.LocalDomains[0].Records = append(c.LocalDomains[0].Records, config.LocalDomainHost{Host: "x", Type: "TXT", Value: `"><b>hi</b>`})
	var b strings.Builder
	if err := domEditorTmpl.Execute(&b, buildDomEditor(c, false, url.Values{"d": {"office.lan"}, "show": {"static"}})); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, "<b>hi</b>") || !strings.Contains(out, `/config/domains/office.lan/records/add`) || !strings.Contains(out, "rec-edit") {
		t.Error("the editor renders, escapes values and offers add and edit")
	}
	b.Reset()
	if err := domEditorTmpl.Execute(&b, buildDomEditor(c, false, url.Values{"d": {"link.lan"}})); err != nil {
		t.Fatal(err)
	}
	out = b.String()
	if strings.Contains(out, `records/add"`) || strings.Contains(out, "rec-edit\" data-line") || !strings.Contains(out, "linked to office.lan") {
		t.Error("a linked domain is read-only: no add form, no row menu, a note")
	}
}

func recordPost(t *testing.T, h http.HandlerFunc, name, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("name", name)
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func TestDomainRecordHandlers_AddEditDelete(t *testing.T) {
	live := testClusterWithScopes()
	live.LocalDomains = []config.LocalDomain{{Name: "office.lan", Records: []config.LocalDomainHost{{Host: "nas", Type: "A", Value: "10.0.0.5"}}}}
	srv, pushed := fakeCandidateNode(t, live)
	defer srv.Close()
	ref := newConfigRef(&WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}})

	w := recordPost(t, handleDomainRecordAdd(ref), "office.lan", "/x", "type=CNAME&name=files&value=nas.office.lan.")
	if w.Code >= 400 || len(pushed.LocalDomains) != 1 || len(pushed.LocalDomains[0].Records) != 2 || pushed.LocalDomains[0].Records[1].Host != "files" {
		t.Fatalf("add: %d %s %+v", w.Code, w.Body.String(), pushed.LocalDomains)
	}
	w = recordPost(t, handleDomainRecordAdd(ref), "office.lan", "/x", "type=A&name=nas&value=10.0.0.5")
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "err=") {
		t.Errorf("a duplicate goes back to the editor with a message: %d %q", w.Code, w.Header().Get("Location"))
	}
	w = recordPost(t, handleDomainRecordEdit(ref), "office.lan", "/x", "old="+url.QueryEscape("A|nas|10.0.0.5")+"&line="+url.QueryEscape("A|nas|10.0.0.6|ttl=120"))
	if w.Code >= 400 || pushed.LocalDomains[0].Records[0].Value != "10.0.0.6" || pushed.LocalDomains[0].Records[0].TTL != 120 {
		t.Fatalf("edit: %d %s %+v", w.Code, w.Body.String(), pushed.LocalDomains[0].Records)
	}
	w = recordPost(t, handleDomainRecordEdit(ref), "office.lan", "/x", "old="+url.QueryEscape("A|gone|1.1.1.1")+"&line="+url.QueryEscape("A|gone|1.1.1.2"))
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "changed") {
		t.Errorf("an edit of a row that changed meanwhile is refused: %d %q", w.Code, w.Header().Get("Location"))
	}
	w = recordPost(t, handleDomainRecordDelete(ref), "office.lan", "/x", "line="+url.QueryEscape("A|nas|10.0.0.5"))
	if w.Code >= 400 || len(pushed.LocalDomains[0].Records) != 1 {
		t.Fatalf("delete: %d %s %+v", w.Code, w.Body.String(), pushed.LocalDomains[0].Records)
	}
}

func TestDomainRecordAdd_RefusesALinkedDomainAndUnknownOnes(t *testing.T) {
	live := testClusterWithScopes()
	live.LocalDomains = []config.LocalDomain{{Name: "a.lan"}, {Name: "b.lan", ForkedFrom: "a.lan"}}
	srv, _ := fakeCandidateNode(t, live)
	defer srv.Close()
	ref := newConfigRef(&WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}})
	w := recordPost(t, handleDomainRecordAdd(ref), "b.lan", "/x", "type=A&name=x&value=1.2.3.4")
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "linked") {
		t.Errorf("a linked domain is edited on its original: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := recordPost(t, handleDomainRecordAdd(ref), "nope.lan", "/x", "type=A&name=x&value=1.2.3.4"); w.Code != http.StatusNotFound {
		t.Errorf("unknown domain: %d", w.Code)
	}
}

func TestDomainZoneText(t *testing.T) {
	d := config.LocalDomain{Name: "office.lan", TTL: 600, Records: []config.LocalDomainHost{
		{Host: "nas", Type: "A", Value: "10.0.0.5", TTL: 60},
		{Host: "www", Type: "CNAME", Value: "nas.office.lan"},
		{Host: "", Type: "MX", Target: "mail", Priority: 10},
		{Host: "_ddm._tcp", Type: "SRV", Target: "ddm.office.lan.", Port: 8443, Priority: 0, Weight: 0},
		{Host: "@", Type: "TXT", Value: `v=spf1 "x" -all`},
		{Host: "@", Type: "CAA", Value: "letsencrypt.org", CAATag: "issue"},
		{Host: "raw", Type: "RAW", RRType: 99, RRDataHex: "00"},
	}}
	got := domainZoneText(d)
	for _, want := range []string{"$ORIGIN office.lan.\n", "$TTL 600\n", "nas 60 IN A 10.0.0.5\n", "www IN CNAME nas.office.lan.\n", "@ IN MX 10 mail\n", "_ddm._tcp IN SRV 0 0 8443 ddm.office.lan.\n", `@ IN TXT "v=spf1 \"x\" -all"`, `@ IN CAA 0 issue "letsencrypt.org"`, "; RAW record at raw skipped"} {
		if !strings.Contains(got, want) {
			t.Errorf("zone text lacks %q:\n%s", want, got)
		}
	}
	long := zoneText(strings.Repeat("a", 600))
	if strings.Count(long, `"`) != 6 {
		t.Errorf("a long TXT is split into 255-byte strings at most: %d quotes", strings.Count(long, `"`))
	}
}

func TestHandleDomainExport(t *testing.T) {
	live := testClusterWithScopes()
	live.LocalDomains = []config.LocalDomain{{Name: "office.lan", Records: []config.LocalDomainHost{{Host: "nas", Type: "A", Value: "10.0.0.5"}}}}
	srv, _ := fakeCandidateNode(t, live)
	defer srv.Close()
	ref := newConfigRef(&WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}})
	for _, tc := range []struct{ q, want string }{{"", "nas IN A 10.0.0.5"}, {"?format=lines", "A|nas|10.0.0.5"}} {
		r := httptest.NewRequest(http.MethodGet, "/config/domains/office.lan/export"+tc.q, nil)
		r.SetPathValue("name", "office.lan")
		w := httptest.NewRecorder()
		handleDomainExport(ref)(w, r)
		if w.Code != 200 || !strings.Contains(w.Body.String(), tc.want) || !strings.Contains(w.Header().Get("Content-Disposition"), "office.lan.") {
			t.Errorf("export %q: %d %q %q", tc.q, w.Code, w.Body.String(), w.Header().Get("Content-Disposition"))
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.SetPathValue("name", "nope.lan")
	w := httptest.NewRecorder()
	handleDomainExport(ref)(w, r)
	if w.Code != 404 {
		t.Errorf("unknown domain: %d", w.Code)
	}
}

func TestParseImport_ZoneFileAndLines(t *testing.T) {
	existing := []config.LocalDomainHost{{Host: "nas", Type: "A", Value: "10.0.0.5"}, {Host: "www", Type: "CNAME", Value: "nas.office.lan."}}
	text := `$ORIGIN office.lan.
$TTL 300
; comment
nas 60 IN A 10.0.0.5
printer IN A 10.0.0.7
@ IN MX 10 mail.office.lan.
www IN A 10.0.0.9
files.office.lan. IN CNAME nas.office.lan.
other.example. IN A 1.2.3.4
@ IN TXT "v=spf1" " -all"
_ddm._tcp IN SRV 0 0 8443 ddm.office.lan.
@ IN HINFO "x" "y"
A|extra|10.0.0.11
`
	rows := parseImport("office.lan", existing, text)
	got := map[string]string{}
	for _, r := range rows {
		key := r.Line
		if key == "" {
			key = r.Raw
		}
		got[key] = r.Status
	}
	want := map[string]string{
		"A|nas|10.0.0.5|ttl=60": "duplicate", "A|printer|10.0.0.7|ttl=300": "new", "MX|@|mail.office.lan.|10|ttl=300": "new",
		"A|www|10.0.0.9|ttl=300": "conflict", "CNAME|files|nas.office.lan.|ttl=300": "new", "other.example. IN A 1.2.3.4": "skipped",
		"TXT|@|v=spf1 -all|ttl=300": "new", "SRV|_ddm._tcp|ddm.office.lan.|8443|0|0|ttl=300": "new", `@ IN HINFO "x" "y"`: "skipped", "A|extra|10.0.0.11": "new",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%q: status %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
}

func TestParseImport_TheSameRecordTwiceInTheTextIsADuplicate(t *testing.T) {
	rows := parseImport("a.lan", nil, "A|x|1.1.1.1\nA|x|1.1.1.1\n")
	if len(rows) != 2 || rows[0].Status != "new" || rows[1].Status != "duplicate" {
		t.Errorf("rows = %+v", rows)
	}
}

func TestDomainImportHandlers_PreviewThenStage(t *testing.T) {
	live := testClusterWithScopes()
	live.LocalDomains = []config.LocalDomain{{Name: "office.lan", Records: []config.LocalDomainHost{{Host: "nas", Type: "A", Value: "10.0.0.5"}}}}
	srv, pushed := fakeCandidateNode(t, live)
	defer srv.Close()
	ref := newConfigRef(&WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}})

	w := recordPost(t, handleDomainImportPreview(ref), "office.lan", "/x", "text="+url.QueryEscape("A|nas|10.0.0.5\nA|new1|10.0.0.8\nCNAME|nas|x.lan."))
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "1 new, 1 duplicate, 1 in conflict") || len(pushed.LocalDomains) != 0 {
		t.Fatalf("preview: %d, nothing may be staged by it: %s", w.Code, body)
	}
	if !strings.Contains(body, "Stage 1 new record(s)") || !strings.Contains(body, `name="lines" value="A|new1|10.0.0.8"`) {
		t.Errorf("the stage button carries only the new line: %s", body)
	}
	w = recordPost(t, handleDomainImportStage(ref), "office.lan", "/x", "lines="+url.QueryEscape("A|new1|10.0.0.8\nA|new2|10.0.0.9"))
	if w.Code >= 400 || len(pushed.LocalDomains[0].Records) != 3 {
		t.Fatalf("stage: %d %s %+v", w.Code, w.Body.String(), pushed.LocalDomains)
	}
	w = recordPost(t, handleDomainImportStage(ref), "office.lan", "/x", "lines=")
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "nothing") {
		t.Errorf("staging nothing is refused: %d %q", w.Code, w.Header().Get("Location"))
	}
}

func TestExpandRecordSet(t *testing.T) {
	got := expandRecordSet("office.lan", "A|ddm.fake.lan|203.0.113.10\nSRV|default._dante-ddm-c._tcp.ddm.fake.lan|ddm.fake.lan|8443|0|0\n\nTXT|{domain}|v=x\nA|other.example.com|1.1.1.1\n")
	want := []string{"A|ddm|203.0.113.10", "SRV|default._dante-ddm-c._tcp.ddm|ddm.office.lan|8443|0|0", "TXT|@|v=x", "A|other.example.com|1.1.1.1"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("expanded =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	rows := parseImport("office.lan", []config.LocalDomainHost{{Host: "ddm", Type: "A", Value: "203.0.113.10"}}, strings.Join(expandRecordSet("office.lan", dnsTemplateDDM), "\n"))
	if rows[0].Status != "duplicate" || rows[1].Status != "new" {
		t.Errorf("the shipped Dante set against a domain that has its host: %+v", rows)
	}
}

func TestHandleDomainApplyPreview(t *testing.T) {
	live := testClusterWithScopes()
	live.LocalDomains = []config.LocalDomain{{Name: "office.lan", Records: []config.LocalDomainHost{{Host: "ddm", Type: "A", Value: "203.0.113.10"}}}}
	srv, pushed := fakeCandidateNode(t, live)
	defer srv.Close()
	ref := newConfigRef(&WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}})
	store := &TemplateStore{Templates: seedTemplates()}
	w := recordPost(t, handleDomainApplyPreview(ref, store), "office.lan", "/x", "set=ddm")
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "Apply &#34;ddm&#34; to office.lan") || !strings.Contains(body, "1 duplicate") || len(pushed.LocalDomains) != 0 {
		t.Fatalf("preview: %d %s", w.Code, body)
	}
	if w := recordPost(t, handleDomainApplyPreview(ref, store), "office.lan", "/x", "set=nope"); w.Code != http.StatusSeeOther {
		t.Errorf("an unknown set goes back with a message: %d", w.Code)
	}
}

func ddmDomain() config.LocalDomain {
	return config.LocalDomain{Name: "office.lan", Records: []config.LocalDomainHost{
		{Host: "ddm", Type: "A", Value: "10.0.0.20"},
		{Host: "other", Type: "A", Value: "10.0.0.99"},
		{Host: "manager", Type: "CNAME", Value: "ddm.office.lan."},
		{Host: "default._dante-ddm-c._tcp.ddm", Type: "SRV", Target: "ddm.office.lan.", Port: 8443},
		{Host: "default._dante-ddm-c._tcp.ddm", Type: "TXT", Value: "-"},
		{Host: "_dante-ddm-c._tcp", Type: "PTR", Value: "default._dante-ddm-c._tcp.ddm.office.lan."},
		{Host: "x._other._tcp", Type: "SRV", Target: "other.office.lan.", Port: 1},
		{Host: "x._other._tcp", Type: "TXT", Value: "no"},
	}}
}

func TestRecordsForHost_CollectsTheHostItsServicesAndAliases(t *testing.T) {
	d := ddmDomain()
	got := recordsForHost(d, "ddm")
	var lines []string
	for _, r := range got {
		lines = append(lines, formatDomainHostLine(r))
	}
	want := "A|ddm|10.0.0.20\nCNAME|manager|ddm.office.lan.\nSRV|default._dante-ddm-c._tcp.ddm|ddm.office.lan.|8443|0|0\nTXT|default._dante-ddm-c._tcp.ddm|-\nPTR|_dante-ddm-c._tcp|default._dante-ddm-c._tcp.ddm.office.lan."
	if strings.Join(lines, "\n") != want {
		t.Errorf("collected:\n%s\nwant:\n%s", strings.Join(lines, "\n"), want)
	}
	if len(recordsForHost(d, "nothing")) != 0 {
		t.Error("an unknown host collects nothing")
	}
}

func TestRecordSetBody_UsesTheExampleDomainAndAppliesBack(t *testing.T) {
	d := ddmDomain()
	body := recordSetBody(d, recordsForHost(d, "ddm"))
	if strings.Contains(body, "office.lan") || !strings.Contains(body, "A|ddm.fake.lan|10.0.0.20") || !strings.Contains(body, "SRV|default._dante-ddm-c._tcp.ddm.fake.lan|ddm.fake.lan.|8443|0|0") {
		t.Errorf("body =\n%s", body)
	}
	if err := validateTemplateBody(TemplateKindDNS, body); err != nil {
		t.Errorf("the body is a valid record set: %v", err)
	}
	rows := parseImport("new.lan", nil, strings.Join(expandRecordSet("new.lan", body), "\n"))
	for _, r := range rows {
		if r.Status != "new" {
			t.Errorf("applying to a fresh domain adds everything: %+v", r)
		}
	}
	if len(rows) != 5 || !strings.HasPrefix(rows[0].Line, "A|ddm|") {
		t.Errorf("rows = %+v", rows)
	}
}

func TestHandleDomainMakeTemplate(t *testing.T) {
	live := testClusterWithScopes()
	live.LocalDomains = []config.LocalDomain{ddmDomain()}
	srv, _ := fakeCandidateNode(t, live)
	defer srv.Close()
	file := t.TempDir() + "/templates.json"
	ref := newConfigRef(&WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}, TemplatesFile: file})
	store := &TemplateStore{}
	w := recordPost(t, handleDomainMakeTemplate(ref, store), "office.lan", "/x", "host=ddm&set_name=My+DDM")
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "done=") {
		t.Fatalf("make: %d %q", w.Code, w.Header().Get("Location"))
	}
	if sets := store.ByKind(TemplateKindDNS); len(sets) != 1 || sets[0].Name != "My DDM" || !strings.Contains(sets[0].Body, "fake.lan") {
		t.Errorf("the set is stored: %+v", sets)
	}
	if w := recordPost(t, handleDomainMakeTemplate(ref, store), "office.lan", "/x", "host=ghost&set_name=x"); !strings.Contains(w.Header().Get("Location"), "err=") {
		t.Errorf("a host without records is refused: %q", w.Header().Get("Location"))
	}
	if w := recordPost(t, handleDomainMakeTemplate(ref, store), "office.lan", "/x", "host=ddm&set_name="); !strings.Contains(w.Header().Get("Location"), "err=") {
		t.Errorf("a set needs a name: %q", w.Header().Get("Location"))
	}
}

func TestMailRecordLines(t *testing.T) {
	got, err := mailRecordLines(url.Values{"spf": {"1"}, "spf_mx": {"1"}, "spf_include": {"_spf.example.com, mail.example.net"}, "spf_end": {"-all"},
		"dmarc": {"1"}, "dmarc_policy": {"quarantine"}, "dmarc_rua": {"dmarc@example.com"}, "dmarc_pct": {"50"}, "dmarc_adkim": {"s"}, "dmarc_aspf": {"r"},
		"dkim_selector": {"mail"}, "dkim_key": {"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx\n yz0123456789abcdef"}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"TXT|@|v=spf1 mx include:_spf.example.com include:mail.example.net -all",
		"TXT|_dmarc|v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; pct=50; adkim=s",
		"TXT|mail._domainkey|v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxyz0123456789abcdef",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("lines =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for name, f := range map[string]url.Values{
		"nothing":       {},
		"bad policy":    {"dmarc": {"1"}, "dmarc_policy": {"maybe"}},
		"rua list":      {"dmarc": {"1"}, "dmarc_policy": {"none"}, "dmarc_rua": {"a@b.c,d@e.f"}},
		"pct":           {"dmarc": {"1"}, "dmarc_policy": {"none"}, "dmarc_pct": {"150"}},
		"spf host":      {"spf": {"1"}, "spf_include": {"bad host;"}},
		"dkim no key":   {"dkim_selector": {"mail"}, "dkim_key": {"short"}},
		"dkim selector": {"dkim_selector": {"bad selector"}, "dkim_key": {strings.Repeat("A", 60)}},
	} {
		if _, err := mailRecordLines(f); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	whole, err := mailRecordLines(url.Values{"dkim_selector": {"s1"}, "dkim_key": {`"v=DKIM1; k=rsa; p=ABCD"`}})
	if err != nil || whole[0] != "TXT|s1._domainkey|v=DKIM1; k=rsa; p=ABCD" {
		t.Errorf("a whole record is kept as pasted: %v %v", whole, err)
	}
}

func TestHandleDomainMailPreview_FlagsASecondSPFAndDMARC(t *testing.T) {
	live := testClusterWithScopes()
	live.LocalDomains = []config.LocalDomain{{Name: "office.lan", Records: []config.LocalDomainHost{{Host: "@", Type: "TXT", Value: "v=spf1 -all"}}}}
	srv, pushed := fakeCandidateNode(t, live)
	defer srv.Close()
	ref := newConfigRef(&WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}})
	w := recordPost(t, handleDomainMailPreview(ref), "office.lan", "/x", "spf=1&spf_mx=1&dmarc=1&dmarc_policy=none")
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "Mail records for office.lan") || !strings.Contains(body, "1 new, 0 duplicate, 1 in conflict") || !strings.Contains(body, "only one") || len(pushed.LocalDomains) != 0 {
		t.Fatalf("preview: %d %s", w.Code, body)
	}
	if w := recordPost(t, handleDomainMailPreview(ref), "office.lan", "/x", ""); w.Code != http.StatusSeeOther {
		t.Errorf("an empty form goes back with a message: %d", w.Code)
	}
}

func TestLocalDomainOf(t *testing.T) {
	doms := []string{"lan", "office.lan"}
	for name, want := range map[string][3]string{
		"nas.office.lan.": {"office.lan", "nas", "true"},
		"a.b.office.lan":  {"office.lan", "a.b", "true"},
		"office.lan":      {"office.lan", "@", "true"},
		"x.lan.":          {"lan", "x", "true"},
		"example.com.":    {"", "", "false"},
		"notoffice.lan.":  {"lan", "notoffice", "true"},
	} {
		d, h, ok := localDomainOf(doms, name)
		if d != want[0] || h != want[1] || fmt.Sprint(ok) != want[2] {
			t.Errorf("%s: got %q %q %v, want %v", name, d, h, ok, want)
		}
	}
}

func TestProbeDetail_AddLinkForAFailedNameInALocalDomain(t *testing.T) {
	d := probeDetailData{Scope: "office", LocalDomains: []string{"office.lan"}}
	if got := d.AddLink("nas.office.lan.", "A"); got != "/config/domains?addname=nas&addtype=A&d=office.lan#quickadd" {
		t.Errorf("link = %q", got)
	}
	if d.AddLink("example.com.", "A") != "" || d.AddLink("nas.office.lan.", "MX") != "" {
		t.Error("no link for a name outside the local domains or for a type an address record cannot answer")
	}
	d.DNSChecks = []probeDNSCheck{{Name: "nas.office.lan.", Type: "A"}, {Name: "ok.office.lan.", Type: "A", Valid: true}, {Name: "x.example.com.", Type: "A"}}
	var b strings.Builder
	if err := probeDetailFragmentTmpl.ExecuteTemplate(&b, "fragment", d); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Count(out, "Add to office.lan…") != 1 || !strings.Contains(out, "addname=nas") {
		t.Errorf("only the failed name inside a local domain offers the link: %s", out)
	}
}

func TestDomEditor_PrefillsFromAFailedCheck(t *testing.T) {
	d := buildDomEditor(editorCluster(), false, url.Values{"d": {"office.lan"}})
	d.AddName, d.AddType = "newhost", "CNAME"
	var b strings.Builder
	if err := domEditorTmpl.Execute(&b, d); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, `value="newhost"`) || !strings.Contains(out, `<option selected>CNAME</option>`) {
		t.Error("the add row is filled from the link")
	}
}

func TestHandleDomainTTL(t *testing.T) {
	tests := []struct {
		name     string
		ttl      string
		wantTTL  int
		wantPush bool
	}{
		{"set", "3600", 3600, true},
		{"empty clears", "", 0, true},
		{"not a number", "abc", 100, false},
		{"negative", "-5", 100, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			live := testClusterWithScopes()
			recs := []config.LocalDomainHost{{Host: "x", Type: "A", Value: "10.0.0.9"}}
			live.LocalDomains = []config.LocalDomain{
				{Name: "foo.lan", TTL: 100, Records: recs},
				{Name: "link.lan", TTL: 100, ForkedFrom: "foo.lan", Records: recs},
				{Name: "bar.lan", TTL: 7},
			}
			srv, pushed := fakeCandidateNode(t, live)
			defer srv.Close()
			cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}
			r := httptest.NewRequest(http.MethodPost, "/config/domains/foo.lan/ttl", strings.NewReader("ttl="+url.QueryEscape(tt.ttl)))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.SetPathValue("name", "foo.lan")
			w := httptest.NewRecorder()
			handleDomainTTL(newConfigRef(cfg))(w, r)
			if !tt.wantPush {
				if w.Code != http.StatusSeeOther || len(pushed.LocalDomains) != 0 {
					t.Fatalf("code %d, pushed %d domains; want a redirect with nothing staged", w.Code, len(pushed.LocalDomains))
				}
				return
			}
			if w.Code >= 400 {
				t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
			}
			got := map[string]int{}
			for _, d := range pushed.LocalDomains {
				got[d.Name] = d.TTL
			}
			if got["foo.lan"] != tt.wantTTL || got["link.lan"] != tt.wantTTL || got["bar.lan"] != 7 {
				t.Errorf("TTLs = %v, want foo and its link %d, bar 7", got, tt.wantTTL)
			}
		})
	}
}
