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
