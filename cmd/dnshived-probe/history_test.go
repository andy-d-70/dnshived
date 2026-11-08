// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"dnshived/internal/dhcpprobe"
)

func testRecorder(t *testing.T, cfg HistoryConfig) (*historyRecorder, string, *[]string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "history")
	var mu sync.Mutex
	var lines []string
	h := newHistoryRecorder(dir, func(l string) { mu.Lock(); lines = append(lines, l); mu.Unlock() })
	h.SetConfig(cfg)
	return h, dir, &lines
}

func rec(scope, leg string, at time.Time) HistoryRecord {
	return HistoryRecord{Time: at, Scope: scope, Leg: leg}
}

func readAll(t *testing.T, dir string) []HistoryRecord {
	t.Helper()
	recs, _, err := readHistory(dir, historyQuery{Limit: historyMaxLimit})
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func TestValidateHistory(t *testing.T) {
	tests := []struct {
		name string
		h    HistoryConfig
		ok   bool
	}{
		{"empty is none", HistoryConfig{}, true},
		{"modes", HistoryConfig{DHCP: "all", DNS: "failures"}, true},
		{"bad mode", HistoryConfig{DHCP: "everything"}, false},
		{"file size too big", HistoryConfig{MaxFileMB: 2000}, false},
		{"negative", HistoryConfig{MaxFiles: -1}, false},
		{"files too many", HistoryConfig{MaxFiles: 51}, false},
		{"age too long", HistoryConfig{MaxAgeDays: 366}, false},
		{"overrides", HistoryConfig{MaxFileMB: 10, MaxFiles: 8, MaxAgeDays: 30}, true},
	}
	for _, tt := range tests {
		if err := validateHistory(tt.h); (err == nil) != tt.ok {
			t.Errorf("%s: err = %v, want ok=%v", tt.name, err, tt.ok)
		}
	}
}

func TestHistoryConfig_DefaultsAndOverrides(t *testing.T) {
	b, f, a := HistoryConfig{}.limits()
	if b != 25<<20 || f != 4 || a != 7*24*time.Hour {
		t.Errorf("defaults = %d %d %v, want 25 MB, 4 files, 7 days", b, f, a)
	}
	b, f, a = HistoryConfig{MaxFileMB: 10, MaxFiles: 8, MaxAgeDays: 30}.limits()
	if b != 10<<20 || f != 8 || a != 30*24*time.Hour {
		t.Errorf("overrides = %d %d %v, want what the operator set", b, f, a)
	}
	if (HistoryConfig{}).enabled() || !(HistoryConfig{DNS: "all"}).enabled() {
		t.Error("enabled must follow the modes")
	}
	if !(HistoryConfig{}).syslogOn() {
		t.Error("syslog follows history by default")
	}
}

func TestRecorder_NoneRecordsNothingAndFailuresKeepsFailuresAndTheRecovery(t *testing.T) {
	h, dir, _ := testRecorder(t, HistoryConfig{})
	now := time.Now()
	h.Record(rec("a", "dhcp", now), true)
	h.Close()
	if got := readAll(t, dir); len(got) != 0 {
		t.Fatalf("mode none wrote %v", got)
	}

	h, dir, _ = testRecorder(t, HistoryConfig{DHCP: "failures", DNS: "none"})
	h.Record(rec("a", "dhcp", now), false)
	h.Record(rec("a", "dhcp", now.Add(1*time.Second)), true)
	h.Record(rec("a", "dhcp", now.Add(2*time.Second)), true)
	h.Record(rec("a", "dhcp", now.Add(5*time.Second)), false)
	h.Record(rec("a", "dhcp", now.Add(6*time.Second)), false)
	h.Record(rec("a", "dns", now), true)
	h.Close()
	got := readAll(t, dir)
	var out []string
	for _, r := range got {
		out = append(out, r.Outcome)
	}
	if strings.Join(out, ",") != "recovered,failed,failed" {
		t.Fatalf("outcomes (newest first) %v, want recovered, failed, failed: ok lines are not kept and DNS is off", out)
	}
	if got[0].FailingForMS != 4000 {
		t.Errorf("failing_for_ms = %d, want 4000 (from the first failure to the recovery)", got[0].FailingForMS)
	}
}

func TestRecorder_AllKeepsEverythingAndMarksTheRecovery(t *testing.T) {
	h, dir, _ := testRecorder(t, HistoryConfig{DHCP: "all", DNS: "all"})
	now := time.Now()
	h.Record(rec("a", "dns", now), false)
	h.Record(rec("a", "dns", now.Add(time.Second)), true)
	h.Record(rec("a", "dns", now.Add(2*time.Second)), false)
	h.Record(rec("a", "dhcp", now), false)
	h.Close()
	got := readAll(t, dir)
	if len(got) != 4 {
		t.Fatalf("got %d records, want all 4", len(got))
	}
	counts := map[string]int{}
	for _, r := range got {
		counts[r.Leg+"/"+r.Outcome]++
	}
	if counts["dns/ok"] != 1 || counts["dns/failed"] != 1 || counts["dns/recovered"] != 1 || counts["dhcp/ok"] != 1 {
		t.Errorf("counts %v: a failure is tracked per leg, so the DHCP ok is not a recovery", counts)
	}
}

func TestRecorder_ManualProbesFollowTheDHCPSetting(t *testing.T) {
	h, dir, _ := testRecorder(t, HistoryConfig{DHCP: "failures", DNS: "all"})
	now := time.Now()
	h.Record(rec("seg", "watch", now), false)
	h.Record(rec("seg", "watch", now.Add(time.Second)), true)
	h.Close()
	got := readAll(t, dir)
	if len(got) != 1 || got[0].Outcome != "failed" || got[0].Leg != "watch" {
		t.Fatalf("got %+v, want only the rogue finding: the DHCP setting is failures, the DNS setting does not apply", got)
	}
}

func TestRecorder_SyslogGetsEachWrittenLineUnlessSwitchedOff(t *testing.T) {
	h, _, lines := testRecorder(t, HistoryConfig{DHCP: "all"})
	h.Record(rec("a", "dhcp", time.Now()), false)
	h.Close()
	if len(*lines) != 1 || !strings.Contains((*lines)[0], `"scope":"a"`) {
		t.Fatalf("syslog lines %v, want the record as one JSON line", *lines)
	}
	off := false
	h, _, lines = testRecorder(t, HistoryConfig{DHCP: "all", Syslog: &off})
	h.Record(rec("a", "dhcp", time.Now()), false)
	h.Close()
	if len(*lines) != 0 {
		t.Errorf("syslog lines %v, want none when syslog is switched off", *lines)
	}
}

func TestRecorder_FullQueueDropsTheOldestAndCountsIt(t *testing.T) {
	h := &historyRecorder{ch: make(chan HistoryRecord, 2), failing: map[string]time.Time{}}
	h.cfg.Store(&HistoryConfig{DHCP: "all"})
	for i := 0; i < 5; i++ {
		h.Record(HistoryRecord{Time: time.Now(), Scope: "s" + string(rune('a'+i)), Leg: "dhcp"}, false)
	}
	if h.Dropped() != 3 {
		t.Errorf("dropped = %d, want 3: the writer was never given time and Record must not block", h.Dropped())
	}
	first, second := <-h.ch, <-h.ch
	if first.Scope != "sd" || second.Scope != "se" {
		t.Errorf("kept %s,%s, want the two newest", first.Scope, second.Scope)
	}
}

func TestRecorder_SizeCapRotatesAndKeepsAtMostTheConfiguredFiles(t *testing.T) {
	h, dir, _ := testRecorder(t, HistoryConfig{DHCP: "all", MaxFileMB: 1, MaxFiles: 3})
	big := strings.Repeat("x", 4000)
	for i := 0; i < 1000; i++ {
		r := rec("s", "dhcp", time.Now())
		r.Reason = big
		h.Record(r, false)
		if i%200 == 199 {
			time.Sleep(50 * time.Millisecond)
		}
	}
	h.Close()
	files := historyFilesNewestFirst(dir)
	if len(files) != 3 {
		t.Fatalf("files %v, want exactly 3 (the cap): about 4 MB were written", files)
	}
	for _, f := range files {
		if st, _ := os.Stat(f); st.Size() > 1<<20+8000 {
			t.Errorf("%s is %d bytes, over the 1 MB cap", f, st.Size())
		}
		if st, _ := os.Stat(f); st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v, want 0600", f, st.Mode().Perm())
		}
	}
}

func TestRecorder_SweepRemovesFilesOlderThanTheAgeCap(t *testing.T) {
	h, dir, _ := testRecorder(t, HistoryConfig{DHCP: "all", MaxAgeDays: 2, MaxFiles: 5})
	h.Record(rec("a", "dhcp", time.Now()), false)
	h.Close()
	os.WriteFile(filepath.Join(dir, "history.1.ndjson"), []byte("{}\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "history.2.ndjson"), []byte("{}\n"), 0o600)
	old := time.Now().Add(-72 * time.Hour)
	os.Chtimes(filepath.Join(dir, "history.2.ndjson"), old, old)

	h.sweep(time.Now())

	if _, err := os.Stat(filepath.Join(dir, "history.2.ndjson")); err == nil {
		t.Error("a file older than the age cap must be removed")
	}
	if _, err := os.Stat(filepath.Join(dir, "history.1.ndjson")); err != nil {
		t.Error("a younger file must stay")
	}
}

func TestReadHistory_FiltersNewestFirstAndLimit(t *testing.T) {
	h, dir, _ := testRecorder(t, HistoryConfig{DHCP: "all", DNS: "all"})
	base := time.Now().Add(-time.Hour)
	h.Record(rec("b", "dns", base.Add(-time.Minute)), false)
	for i := 0; i < 6; i++ {
		h.Record(rec("a", "dhcp", base.Add(time.Duration(i)*time.Minute)), i%2 == 1)
	}
	h.Close()

	all, _, _ := readHistory(dir, historyQuery{Limit: 100})
	if len(all) != 7 || !all[0].Time.After(all[1].Time) {
		t.Fatalf("got %d records, newest first expected", len(all))
	}
	lim, _, _ := readHistory(dir, historyQuery{Limit: 2})
	if len(lim) != 2 || !lim[0].Time.Equal(all[0].Time) {
		t.Errorf("limit gave %d records starting with %v", len(lim), lim[0].Time)
	}
	sc, _, _ := readHistory(dir, historyQuery{Scope: "b", Limit: 100})
	if len(sc) != 1 || sc[0].Leg != "dns" {
		t.Errorf("scope filter gave %+v", sc)
	}
	fl, _, _ := readHistory(dir, historyQuery{FailuresOnly: true, Limit: 100})
	for _, r := range fl {
		if r.Outcome == "ok" {
			t.Errorf("failures only returned an ok record: %+v", r)
		}
	}
	win, _, _ := readHistory(dir, historyQuery{Since: base.Add(2 * time.Minute), Until: base.Add(4 * time.Minute), Limit: 100})
	if len(win) != 2 {
		t.Errorf("time window gave %d records, want the two inside [since, until)", len(win))
	}
}

func TestParseHistoryQuery_RefusesWhatIsNotValid(t *testing.T) {
	bad := []url.Values{
		{"scope": {"../etc/passwd"}}, {"scope": {"a b"}}, {"leg": {"x"}}, {"outcome": {"some"}},
		{"since": {"yesterday"}}, {"until": {"2026-13-01"}}, {"limit": {"0"}}, {"limit": {"abc"}},
	}
	for _, v := range bad {
		if _, err := parseHistoryQuery(v); err == nil {
			t.Errorf("%v must be refused", v)
		}
	}
	q, err := parseHistoryQuery(url.Values{"scope": {"scope-001"}, "leg": {"dns"}, "outcome": {"failures"}, "limit": {"99999"}})
	if err != nil || q.Limit != historyMaxLimit || !q.FailuresOnly || q.Leg != "dns" {
		t.Errorf("q = %+v err %v, want the limit capped at %d", q, err, historyMaxLimit)
	}
}

func TestRecordScopeLeg_ResultsBecomeRecordsWithFlagsAndOnlyForProbedScopes(t *testing.T) {
	h, dir, _ := testRecorder(t, HistoryConfig{DHCP: "all", DNS: "all"})
	orig := histRec
	histRec = h
	t.Cleanup(func() { histRec = orig })
	tgt := scopeProbeTarget{name: "s1", parent: "ens19", vlanID: 100}

	dhcp := ScopeProbeResult{Scope: "s1", Reachable: true, Enabled: true, DNSPending: true, DHCPProbedAt: time.Now(), Flags: []string{"retried"}}
	dhcp.DHCP.Verdict, dhcp.DHCP.Valid, dhcp.DHCP.OfferMS = "no_answer", false, 0
	recordScopeLeg("dhcp", "s1", tgt, dhcp, []string{"held_by_debounce"})

	dns := ScopeProbeResult{Scope: "s1", Reachable: true, Enabled: true, DHCPPending: true, DNSProbedAt: time.Now()}
	dns.DNSChecks = []DNSCheckResult{{Name: "a.", Type: "A", Against: "10.0.0.22", Answered: true, Valid: true, LatencyMS: 3}, {Name: "b.", Type: "A", Against: "10.0.0.23", Error: "timeout"}}
	recordScopeLeg("dns", "s1", tgt, dns, nil)

	recordScopeLeg("dhcp", "off", tgt, ScopeProbeResult{Scope: "off", Reachable: true}, nil)
	recordScopeLeg("dhcp", "gone", tgt, ScopeProbeResult{Scope: "gone"}, nil)
	h.Close()

	got := readAll(t, dir)
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2: a scope with probing off or no interface was never probed", len(got))
	}
	byLeg := map[string]HistoryRecord{}
	for _, r := range got {
		byLeg[r.Leg] = r
	}
	d, n := byLeg["dhcp"], byLeg["dns"]
	if d.Outcome != "failed" || d.Verdict != "no_answer" || d.Interface != "ens19" || d.VLANID != 100 || strings.Join(d.Flags, ",") != "held_by_debounce,retried" {
		t.Errorf("dhcp record %+v", d)
	}
	if n.Outcome != "failed" || len(n.Checks) != 2 || n.Checks[1].Error != "timeout" {
		t.Errorf("dns record %+v, want a failure carrying both checks", n)
	}
}

func TestHistoryHandler_AnswersWithSettingsAndRefusesBadQueries(t *testing.T) {
	h, dir, _ := testRecorder(t, HistoryConfig{DHCP: "all"})
	origRec, origDir := histRec, historyDir
	histRec, historyDir = h, dir
	t.Cleanup(func() { histRec, historyDir = origRec, origDir })
	h.Record(rec("a", "dhcp", time.Now()), true)
	h.Close()

	rr := httptest.NewRecorder()
	historyHandler(rr, httptest.NewRequest(http.MethodGet, "/api/v1/history?leg=dhcp", nil))
	var out struct {
		Records  []HistoryRecord        `json:"records"`
		Dropped  uint64                 `json:"dropped"`
		Size     int64                  `json:"size_bytes"`
		Settings map[string]interface{} `json:"settings"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || rr.Code != 200 {
		t.Fatalf("status %d err %v", rr.Code, err)
	}
	if len(out.Records) != 1 || out.Size == 0 || out.Settings["dhcp"] != "all" || out.Settings["dns"] != "none" || out.Settings["max_files"].(float64) != 4 {
		t.Errorf("answer %+v, want the record, the size and the settings with their defaults", out)
	}
	rr = httptest.NewRecorder()
	historyHandler(rr, httptest.NewRequest(http.MethodGet, "/api/v1/history?scope=../x", nil))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400 for an invalid scope", rr.Code)
	}
}

func TestRunDHCPLeg_FlagsWhatTheRunnerDid(t *testing.T) {
	var calls int
	stubDHCP(t, func(iface string, wait time.Duration, o dhcpprobe.Options) (dhcpprobe.Result, error) {
		calls++
		return dhcpprobe.Result{Verdict: dhcpprobe.VerdictNoAnswer}, nil
	})
	tgt := scopeProbeTarget{name: "s1", parent: "ens19", iface: "ens19.100", vlanID: 100}
	res, _ := runDHCPLeg(&ProbeConfig{}, tgt, legitByNodeID(), nil, dhcpHint{})
	if strings.Join(res.Flags, ",") != "retried" {
		t.Errorf("flags %v, want retried", res.Flags)
	}
}
