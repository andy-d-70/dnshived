// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"dnshived/internal/cfgjournal"
	"dnshived/internal/config"
)

type candidateView struct {
	Exists    bool              `json:"exists"`
	Candidate config.Cluster    `json:"candidate"`
	Authors   map[string]string `json:"authors"`
}

func readCandidate(t *testing.T, j *cfgJournalRuntime) candidateView {
	t.Helper()
	rec := httptest.NewRecorder()
	j.handleCandidateGet(func() string { return j.dataDir })(rec, httptest.NewRequest(http.MethodGet, "/api/v1/candidate", nil))
	var v candidateView
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &v) != nil {
		t.Fatalf("candidate: %d %s", rec.Code, rec.Body.String())
	}
	return v
}

// updFrom is the push the web builds: every editable field of c.
func updFrom(c config.Cluster, author string) configUpdate {
	return configUpdate{
		PSK: c.PSK, TrustedHosts: c.TrustedHosts, TLSCert: c.TLSCert, TLSKey: c.TLSKey, APITokens: c.APITokens,
		LogLevel: c.LogLevel, HelperSocket: c.HelperSocket, Platform: c.Platform, Scopes: c.Scopes,
		ProbeIntervalMS: c.ProbeIntervalMS, MgmtVIP: c.MgmtVIP, DefaultDNSChecks: c.DefaultDNSChecks,
		GlobalDNSRecords: c.GlobalDNSRecords, LocalDomains: c.LocalDomains, ScopeDefaults: c.ScopeDefaults,
		DefaultDHCPOptions: c.DefaultDHCPOptions, Author: author,
	}
}

func pendingItems(t *testing.T, j *cfgJournalRuntime) cfgjournal.Pending {
	t.Helper()
	cfgWriteMu.Lock()
	defer cfgWriteMu.Unlock()
	pd, err := j.pendingLocked()
	if err != nil {
		t.Fatal(err)
	}
	return pd
}

func TestJournalPending_StageMergeCommitAndPrune(t *testing.T) {
	path := writeBaseConfig(t)
	j := singleCoreJournal(t, path)
	live, _ := config.Load(path)

	ann := *live
	ann.LogLevel = "debug"
	if st, body := applyCandidateUpdate(j.dataDir, path, updFrom(ann, "ann")); st != http.StatusOK {
		t.Fatalf("ann stages: %d %v", st, body)
	}
	v := readCandidate(t, j)
	if !v.Exists || v.Candidate.LogLevel != "debug" || v.Authors["log_level"] != "ann" {
		t.Fatalf("after ann: %+v", v)
	}

	bob := v.Candidate
	bob.GlobalDNSRecords = []config.DNSRecord{{Name: "ntp.lan", Type: "A", Value: "10.0.0.9"}}
	if st, body := applyCandidateUpdate(j.dataDir, path, updFrom(bob, "bob")); st != http.StatusOK {
		t.Fatalf("bob stages: %d %v", st, body)
	}
	if pd := pendingItems(t, j); len(pd) != 2 || pd["log_level"].Author != "ann" {
		t.Fatalf("both staged items, each with its author: %+v", pd)
	}

	v = readCandidate(t, j)
	if st, body := applyConfigUpdate(path, updFrom(v.Candidate, "ann"), nil, nil, nil); st != http.StatusOK {
		t.Fatalf("commit: %d %v", st, body)
	}
	after, _ := config.Load(path)
	if after.LogLevel != "debug" || len(after.GlobalDNSRecords) != 1 {
		t.Fatalf("committed configuration: %+v", after)
	}
	if pd := pendingItems(t, j); len(pd) != 0 {
		t.Fatalf("committed items leave Pending: %+v", pd)
	}
	if readCandidate(t, j).Exists {
		t.Fatal("nothing is staged after the commit")
	}
}

func TestJournalPending_SecretsNeverEnterTheJournal(t *testing.T) {
	path := writeBaseConfig(t)
	j := singleCoreJournal(t, path)
	live, _ := config.Load(path)
	next := *live
	next.APITokens = []config.APIToken{{Name: "ops", Token: "super-secret-token-value-0123456789abcdef", Role: "admin"}}
	if st, body := applyCandidateUpdate(j.dataDir, path, updFrom(next, "ann")); st != http.StatusOK {
		t.Fatalf("stage: %d %v", st, body)
	}
	if pd := pendingItems(t, j); len(pd) != 0 {
		t.Fatalf("a secret must not become a staged journal item: %+v", pd)
	}
	raw, _ := os.ReadFile(j.pendingDoc.Path)
	recs, err := cfgjournal.Since(j.store.View(), 0)
	if err != nil {
		t.Fatal(err)
	}
	const secret = "super-secret-token"
	leaked := bytes.Contains(raw, []byte(secret))
	for _, r := range recs {
		leaked = leaked || bytes.Contains(r.Old, []byte(secret)) || bytes.Contains(r.New, []byte(secret))
	}
	if leaked {
		t.Fatal("the token value reached the journal or the pending document")
	}
	v := readCandidate(t, j)
	if !v.Exists || len(v.Candidate.APITokens) != 1 {
		t.Fatalf("the staged token shows in the candidate: %+v", v)
	}
	if st, body := applyConfigUpdate(path, updFrom(v.Candidate, "ann"), nil, nil, nil); st != http.StatusOK {
		t.Fatalf("commit: %d %v", st, body)
	}
	if c, _ := config.Load(path); len(c.APITokens) != 1 {
		t.Fatal("the committed token must be saved")
	}
}

func TestJournalPending_DiscardAll(t *testing.T) {
	path := writeBaseConfig(t)
	j := singleCoreJournal(t, path)
	live, _ := config.Load(path)
	next := *live
	next.LogLevel = "debug"
	if st, _ := applyCandidateUpdate(j.dataDir, path, updFrom(next, "ann")); st != http.StatusOK {
		t.Fatal(st)
	}
	cfgWriteMu.Lock()
	err := j.discardLocked(j.dataDir, func(string, cfgjournal.Staged) bool { return true }, true)
	cfgWriteMu.Unlock()
	if err != nil || readCandidate(t, j).Exists {
		t.Fatalf("discard: %v", err)
	}
}

func post(t *testing.T, h http.HandlerFunc, body any) (int, string) {
	t.Helper()
	raw, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw)))
	return rec.Code, rec.Body.String()
}

// itemChanges is what the web sends: the items it changed between the document it read and the one it wants.
func itemChanges(t *testing.T, base, want config.Cluster) []cfgjournal.Entry {
	t.Helper()
	bt, _ := cfgjournal.Replicated(&base)
	wt, _ := cfgjournal.Replicated(&want)
	es, err := cfgjournal.FromChange(cfgJournalDoc, bt, wt, 0)
	if err != nil {
		t.Fatal(err)
	}
	return es
}

func TestPendingStage_TwoOperatorsAtTheSameMomentBothKeepTheirChange(t *testing.T) {
	path := writeBaseConfig(t)
	j := singleCoreJournal(t, path)
	stage := j.handlePendingStage(func() string { return j.dataDir })
	base, _ := config.Load(path)
	a, b := *base, *base
	a.LogLevel = "debug"
	b.GlobalDNSRecords = []config.DNSRecord{{Name: "ntp.lan", Type: "A", Value: "10.0.0.9"}}
	if code, body := post(t, stage, stageRequest{Author: "ann", Changes: itemChanges(t, *base, a)}); code != http.StatusOK {
		t.Fatalf("ann: %d %s", code, body)
	}
	if code, body := post(t, stage, stageRequest{Author: "bob", Changes: itemChanges(t, *base, b)}); code != http.StatusOK {
		t.Fatalf("bob read the same base as ann and changed another item: %d %s", code, body)
	}
	v := readCandidate(t, j)
	if v.Candidate.LogLevel != "debug" || len(v.Candidate.GlobalDNSRecords) != 1 {
		t.Fatalf("both changes must stay: %+v", v.Candidate)
	}
	c := *base
	c.LogLevel = "warning"
	if code, _ := post(t, stage, stageRequest{Author: "cy", Changes: itemChanges(t, *base, c)}); code != http.StatusConflict {
		t.Fatalf("cy changed log_level on a view without ann's change: %d", code)
	}
	if v := readCandidate(t, j); v.Candidate.LogLevel != "debug" {
		t.Fatal("ann's change must survive cy's refused one")
	}
}

func TestPendingCommit_ItemsOnlyAndNeverOverAnotherCommit(t *testing.T) {
	path := writeBaseConfig(t)
	j := singleCoreJournal(t, path)
	stage := j.handlePendingStage(func() string { return j.dataDir })
	commit := j.handlePendingCommit(func() string { return j.dataDir })
	base, _ := config.Load(path)
	a := *base
	a.LogLevel = "debug"
	if code, body := post(t, stage, stageRequest{Author: "ann", Changes: itemChanges(t, *base, a)}); code != http.StatusOK {
		t.Fatalf("stage: %d %s", code, body)
	}
	other := *base
	other.GlobalDNSRecords = []config.DNSRecord{{Name: "x.lan", Type: "A", Value: "10.0.0.7"}}
	if st, body := applyConfigUpdate(path, updFrom(other, "bob"), nil, nil, nil); st != http.StatusOK {
		t.Fatalf("bob commits another item directly: %d %v", st, body)
	}
	if code, body := post(t, commit, commitRequest{Author: "ann"}); code != http.StatusOK {
		t.Fatalf("commit: %d %s", code, body)
	}
	c, _ := config.Load(path)
	if c.LogLevel != "debug" || len(c.GlobalDNSRecords) != 1 {
		t.Fatalf("ann's item committed and bob's record kept: %+v", c)
	}
	if readCandidate(t, j).Exists {
		t.Fatal("Pending is empty after committing everything")
	}

	b2 := *c
	b2.LogLevel = "warning"
	if code, _ := post(t, stage, stageRequest{Author: "ann", Changes: itemChanges(t, *c, b2)}); code != http.StatusOK {
		t.Fatal(code)
	}
	moved := *c
	moved.LogLevel = "auto"
	if st, _ := applyConfigUpdate(path, updFrom(moved, "bob"), nil, nil, nil); st != http.StatusOK {
		t.Fatal(st)
	}
	if code, _ := post(t, commit, commitRequest{Author: "ann"}); code != http.StatusConflict {
		t.Fatalf("the staged item moved since it was staged: commit must be refused, got %d", code)
	}
	if c, _ := config.Load(path); c.LogLevel != "auto" {
		t.Fatalf("the refused commit must not touch the configuration: %q", c.LogLevel)
	}
}

func TestPendingCommit_MineLeavesOthersStaged(t *testing.T) {
	path := writeBaseConfig(t)
	j := singleCoreJournal(t, path)
	stage := j.handlePendingStage(func() string { return j.dataDir })
	base, _ := config.Load(path)
	a, b := *base, *base
	a.LogLevel = "debug"
	b.GlobalDNSRecords = []config.DNSRecord{{Name: "ntp.lan", Type: "A", Value: "10.0.0.9"}}
	post(t, stage, stageRequest{Author: "ann", Changes: itemChanges(t, *base, a)})
	post(t, stage, stageRequest{Author: "bob", Changes: itemChanges(t, *base, b)})
	if code, body := post(t, j.handlePendingCommit(func() string { return j.dataDir }), commitRequest{Author: "ann", Mine: true}); code != http.StatusOK {
		t.Fatalf("%d %s", code, body)
	}
	c, _ := config.Load(path)
	pd := pendingItems(t, j)
	if c.LogLevel != "debug" || len(c.GlobalDNSRecords) != 0 || len(pd) != 1 || pd["global_dns_records/[ntp.lan|A]"].Author != "bob" {
		t.Fatalf("live %+v pending %+v", c, pd)
	}
}

func TestPendingStage_SecretsTravelOnlyAsOwnFields(t *testing.T) {
	path := writeBaseConfig(t)
	j := singleCoreJournal(t, path)
	stage := j.handlePendingStage(func() string { return j.dataDir })
	bad := []cfgjournal.Entry{{Path: "psk", New: []byte(`"x"`)}}
	if code, _ := post(t, stage, stageRequest{Author: "ann", Changes: bad}); code != http.StatusBadRequest {
		t.Fatalf("a secret as a change must be refused: %d", code)
	}
	base, _ := config.Load(path)
	own := *base
	own.APITokens = []config.APIToken{{Name: "ops", Token: "super-secret-token-value-0123456789abcdef", Role: "admin"}}
	if code, body := post(t, stage, stageRequest{Author: "ann", Own: &own}); code != http.StatusOK {
		t.Fatalf("%d %s", code, body)
	}
	if code, body := post(t, j.handlePendingCommit(func() string { return j.dataDir }), commitRequest{Author: "ann"}); code != http.StatusOK {
		t.Fatalf("%d %s", code, body)
	}
	if c, _ := config.Load(path); len(c.APITokens) != 1 {
		t.Fatal("the own field must be committed on this core")
	}
}

func TestPendingStage_AnInvalidResultIsRefused(t *testing.T) {
	path := writeBaseConfig(t)
	j := singleCoreJournal(t, path)
	base, _ := config.Load(path)
	bad := *base
	bad.LogLevel = "loud"
	if code, _ := post(t, j.handlePendingStage(func() string { return j.dataDir }), stageRequest{Author: "ann", Changes: itemChanges(t, *base, bad)}); code == http.StatusOK {
		t.Fatal("an invalid staged configuration must be refused")
	}
	if len(pendingItems(t, j)) != 0 {
		t.Fatal("nothing may be staged")
	}
}

func withBase(t *testing.T, u configUpdate, base config.Cluster) configUpdate {
	t.Helper()
	bt, err := cfgjournal.Replicated(&base)
	if err != nil {
		t.Fatal(err)
	}
	u.Base, _ = json.Marshal(bt)
	return u
}

func TestJournalPending_WholeDocumentSavesWithABaseNeverUndoEachOther(t *testing.T) {
	path := writeBaseConfig(t)
	j := singleCoreJournal(t, path)
	base, _ := config.Load(path)
	a, b := *base, *base
	a.LogLevel = "debug"
	b.GlobalDNSRecords = []config.DNSRecord{{Name: "ntp.lan", Type: "A", Value: "10.0.0.9"}}
	if st, body := applyCandidateUpdate(j.dataDir, path, withBase(t, updFrom(a, "ann"), *base)); st != http.StatusOK {
		t.Fatalf("ann: %d %v", st, body)
	}
	if st, body := applyCandidateUpdate(j.dataDir, path, withBase(t, updFrom(b, "bob"), *base)); st != http.StatusOK {
		t.Fatalf("bob: %d %v", st, body)
	}
	v := readCandidate(t, j)
	if v.Candidate.LogLevel != "debug" || len(v.Candidate.GlobalDNSRecords) != 1 {
		t.Fatalf("bob's whole document still held log_level info, but only his item may count: %+v", v.Candidate)
	}
}
