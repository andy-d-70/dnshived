// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"dnshived/internal/config"
	"dnshived/internal/webauth"
)

type scopeFake struct {
	mu        sync.Mutex
	live      config.Cluster
	cand      *config.Cluster
	authors   map[string]string
	pushed    []configPushPayload
	restaged  []configPushPayload
	discarded int
	srv       *httptest.Server
}

func validCluster() config.Cluster {
	return config.Cluster{
		ClusterID: "c1", NodeID: "n1", Role: "core-1", ControlAddr: "192.0.2.1:9443",
		PSK:      "0123456789abcdef0123456789abcdef",
		Platform: &config.Platform{Mgmt: "eth0", Workers: []string{"eth1"}},
		LogLevel: "info",
	}
}

func newScopeFake(t *testing.T, live config.Cluster, cand config.Cluster, authors map[string]string) (*scopeFake, *WebConfig) {
	t.Helper()
	f := &scopeFake{live: live, cand: &cand, authors: authors}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(f.live)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			if f.cand == nil {
				w.Write([]byte(`{"exists":false}`))
				return
			}
			json.NewEncoder(w).Encode(candidateResponse{Exists: true, Candidate: *f.cand, Authors: f.authors})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/config":
			var p configPushPayload
			body, _ := io.ReadAll(r.Body)
			json.Unmarshal(body, &p)
			f.pushed = append(f.pushed, p)
			f.live.LogLevel, f.live.LocalDomains = p.LogLevel, p.LocalDomains
			w.Write([]byte(`{"ok":true,"warnings":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/candidate":
			var p configPushPayload
			body, _ := io.ReadAll(r.Body)
			json.Unmarshal(body, &p)
			f.restaged = append(f.restaged, p)
			w.Write([]byte(`{"ok":true,"warnings":[]}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/candidate":
			f.discarded++
			f.cand = nil
			w.Write([]byte(`{"status":"discarded"}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f, &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(f.srv.URL, "http://")}}}
}

func formPost(path string, kv ...string) *http.Request {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return withAuthedUser(req, webauth.User{Name: "alice", Role: webauth.RoleAdmin})
}

func twoAdmins(t *testing.T) (*scopeFake, *WebConfig) {
	live := validCluster()
	cand := validCluster()
	cand.LogLevel = "debug"
	cand.LocalDomains = []config.LocalDomain{{Name: "demo.lan", TTL: 60}}
	return newScopeFake(t, live, cand, map[string]string{
		"log_level":                "alice",
		"local_domains/[demo.lan]": "bob",
	})
}

func TestHandlePending_ShowsWhoChangedWhat(t *testing.T) {
	_, cfg := twoAdmins(t)
	req := withAuthedUser(httptest.NewRequest(http.MethodGet, "/pending", nil), webauth.User{Name: "alice", Role: webauth.RoleAdmin})
	rec := httptest.NewRecorder()
	handlePending(newConfigRef(cfg))(rec, req)
	body := rec.Body.String()
	for _, want := range []string{"Who changed what", "Commit my 1 change(s)", "Commit everyone's", "bob", "demo.lan"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
}

func TestHandlePending_OnlyOwnChangesKeepsPlainButtons(t *testing.T) {
	live := validCluster()
	cand := validCluster()
	cand.LogLevel = "debug"
	_, cfg := newScopeFake(t, live, cand, map[string]string{"log_level": "alice"})
	req := withAuthedUser(httptest.NewRequest(http.MethodGet, "/pending", nil), webauth.User{Name: "alice", Role: webauth.RoleAdmin})
	rec := httptest.NewRecorder()
	handlePending(newConfigRef(cfg))(rec, req)
	body := rec.Body.String()
	if strings.Contains(body, "Who changed what") || !strings.Contains(body, "Commit all 1 change(s)") {
		t.Errorf("unexpected page:\n%s", body)
	}
}

func TestHandlePending_OldDaemonKeepsPlainButtons(t *testing.T) {
	live := validCluster()
	cand := validCluster()
	cand.LogLevel = "debug"
	_, cfg := newScopeFake(t, live, cand, nil)
	req := withAuthedUser(httptest.NewRequest(http.MethodGet, "/pending", nil), webauth.User{Name: "alice", Role: webauth.RoleAdmin})
	rec := httptest.NewRecorder()
	handlePending(newConfigRef(cfg))(rec, req)
	if body := rec.Body.String(); strings.Contains(body, "Who changed what") || !strings.Contains(body, "Commit all 1 change(s)") {
		t.Errorf("unexpected page:\n%s", body)
	}
}

func TestCommitMine_PushesOnlyOwnChangesAndKeepsTheRest(t *testing.T) {
	f, cfg := twoAdmins(t)
	rec := httptest.NewRecorder()
	handlePendingCommit(filepath.Join(t.TempDir(), "web.json"), newConfigRef(cfg))(rec, formPost("/pending/commit", "scope", "mine"))

	if len(f.pushed) != 1 {
		t.Fatalf("pushes = %d, body %s", len(f.pushed), rec.Body)
	}
	if f.pushed[0].LogLevel != "debug" {
		t.Errorf("own change not pushed: %q", f.pushed[0].LogLevel)
	}
	if len(f.pushed[0].LocalDomains) != 0 {
		t.Errorf("another admin's domain went live: %+v", f.pushed[0].LocalDomains)
	}
	if len(f.restaged) != 1 || len(f.restaged[0].LocalDomains) != 1 {
		t.Fatalf("the other admin's change was not kept staged: %+v", f.restaged)
	}
	if f.restaged[0].Author != "" {
		t.Errorf("re-stage must not claim an author, got %q", f.restaged[0].Author)
	}
	if f.discarded != 0 {
		t.Errorf("the candidate was discarded although others' changes remain")
	}
}

func TestCommitMine_NothingOwnIsRefused(t *testing.T) {
	f, cfg := twoAdmins(t)
	req := formPost("/pending/commit", "scope", "mine")
	req = withAuthedUser(req, webauth.User{Name: "carol", Role: webauth.RoleAdmin})
	rec := httptest.NewRecorder()
	handlePendingCommit(filepath.Join(t.TempDir(), "web.json"), newConfigRef(cfg))(rec, req)
	if rec.Code != http.StatusConflict || len(f.pushed) != 0 {
		t.Fatalf("status %d, pushes %d", rec.Code, len(f.pushed))
	}
}

func TestCommitMine_AllOwnClearsCandidate(t *testing.T) {
	live := validCluster()
	cand := validCluster()
	cand.LogLevel = "debug"
	f, cfg := newScopeFake(t, live, cand, map[string]string{"log_level": "alice"})
	handlePendingCommit(filepath.Join(t.TempDir(), "web.json"), newConfigRef(cfg))(httptest.NewRecorder(), formPost("/pending/commit", "scope", "mine"))
	if len(f.pushed) != 1 || f.discarded != 1 || len(f.restaged) != 0 {
		t.Fatalf("pushed %d, discarded %d, restaged %d", len(f.pushed), f.discarded, len(f.restaged))
	}
}

func TestCommitMine_NeedsAnOldDaemonToReportAuthors(t *testing.T) {
	live := validCluster()
	cand := validCluster()
	cand.LogLevel = "debug"
	f, cfg := newScopeFake(t, live, cand, nil)
	rec := httptest.NewRecorder()
	handlePendingCommit(filepath.Join(t.TempDir(), "web.json"), newConfigRef(cfg))(rec, formPost("/pending/commit", "scope", "mine"))
	if rec.Code != http.StatusConflict || len(f.pushed) != 0 {
		t.Fatalf("status %d, pushes %d", rec.Code, len(f.pushed))
	}
}

func TestCommitAll_WithOthersNeedsTheTypedPhrase(t *testing.T) {
	f, cfg := twoAdmins(t)
	h := handlePendingCommit(filepath.Join(t.TempDir(), "web.json"), newConfigRef(cfg))

	rec := httptest.NewRecorder()
	h(rec, formPost("/pending/commit"))
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "/pending/confirm") || len(f.pushed) != 0 {
		t.Fatalf("without the phrase: status %d, location %q, pushes %d", rec.Code, rec.Header().Get("Location"), len(f.pushed))
	}

	rec = httptest.NewRecorder()
	h(rec, formPost("/pending/commit", "confirm", "commit all"))
	if len(f.pushed) != 0 {
		t.Fatal("a wrong phrase must not commit")
	}

	rec = httptest.NewRecorder()
	h(rec, formPost("/pending/commit", "confirm", confirmCommitAll))
	if len(f.pushed) != 1 || len(f.pushed[0].LocalDomains) != 1 || f.discarded != 1 {
		t.Fatalf("pushed %d, discarded %d", len(f.pushed), f.discarded)
	}
}

func TestDiscardMine_KeepsOthers(t *testing.T) {
	f, cfg := twoAdmins(t)
	rec := httptest.NewRecorder()
	handlePendingDiscard(newConfigRef(cfg))(rec, formPost("/pending/discard", "scope", "mine"))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if f.discarded != 0 || len(f.restaged) != 1 {
		t.Fatalf("discarded %d, restaged %d", f.discarded, len(f.restaged))
	}
	if f.restaged[0].LogLevel != "info" || len(f.restaged[0].LocalDomains) != 1 {
		t.Errorf("restaged = %+v", f.restaged[0])
	}
}

func TestDiscardAll_WithOthersNeedsTheTypedPhrase(t *testing.T) {
	f, cfg := twoAdmins(t)
	h := handlePendingDiscard(newConfigRef(cfg))
	rec := httptest.NewRecorder()
	h(rec, formPost("/pending/discard"))
	if !strings.Contains(rec.Header().Get("Location"), "/pending/confirm?action=discard") || f.discarded != 0 {
		t.Fatalf("location %q, discarded %d", rec.Header().Get("Location"), f.discarded)
	}
	h(httptest.NewRecorder(), formPost("/pending/discard", "confirm", confirmDiscardAll))
	if f.discarded != 1 {
		t.Fatalf("discarded %d", f.discarded)
	}
}

func TestConfirmPage_WarnsAndListsOthers(t *testing.T) {
	_, cfg := twoAdmins(t)
	req := withAuthedUser(httptest.NewRequest(http.MethodGet, "/pending/confirm?action=commit", nil), webauth.User{Name: "alice", Role: webauth.RoleAdmin})
	rec := httptest.NewRecorder()
	handlePendingConfirm(newConfigRef(cfg))(rec, req)
	body := rec.Body.String()
	for _, want := range []string{"WARNING", "bob", "demo.lan", confirmCommitAll} {
		if !strings.Contains(body, want) {
			t.Errorf("confirm page lacks %q", want)
		}
	}
}

func TestConfirmPage_RedirectsWhenNobodyElseHasChanges(t *testing.T) {
	live := validCluster()
	cand := validCluster()
	cand.LogLevel = "debug"
	_, cfg := newScopeFake(t, live, cand, map[string]string{"log_level": "alice"})
	req := withAuthedUser(httptest.NewRequest(http.MethodGet, "/pending/confirm?action=commit", nil), webauth.User{Name: "alice", Role: webauth.RoleAdmin})
	rec := httptest.NewRecorder()
	handlePendingConfirm(newConfigRef(cfg))(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestUnknownAuthorCountsAsOthers(t *testing.T) {
	live := validCluster()
	cand := validCluster()
	cand.LogLevel = "debug"
	f, cfg := newScopeFake(t, live, cand, map[string]string{})
	rec := httptest.NewRecorder()
	handlePendingCommit(filepath.Join(t.TempDir(), "web.json"), newConfigRef(cfg))(rec, formPost("/pending/commit"))
	if rec.Code != http.StatusSeeOther || len(f.pushed) != 0 {
		t.Fatalf("status %d, pushes %d", rec.Code, len(f.pushed))
	}
}
