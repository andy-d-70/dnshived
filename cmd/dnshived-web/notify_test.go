// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"dnshived/internal/notify"
	"dnshived/internal/webauth"
)

type sentMsg struct{ dest, subject, body string }

type notifyRig struct {
	mu    sync.Mutex
	sent  []sentMsg
	rows  []statusRow
	evs   map[string][]event
	now   time.Time
	deps  notifyDeps
	state string
}

func newNotifyRig(t *testing.T, s notify.Settings, self string) *notifyRig {
	t.Helper()
	r := &notifyRig{evs: map[string][]event{}, now: time.Date(2026, 11, 20, 6, 0, 0, 0, time.UTC), state: filepath.Join(t.TempDir(), "state.json")}
	for _, n := range []string{"core-1", "core-2", "core-3"} {
		r.rows = append(r.rows, statusRow{Node: NodeConfig{Name: n}, Status: nodeStatus{ClusterID: "c1", State: "STABLE"}})
	}
	r.deps = notifyDeps{
		settings: func() notify.Settings { return s },
		nodes:    func() []statusRow { return r.rows },
		events: func(n NodeConfig) ([]event, error) {
			return r.evs[n.Name], nil
		},
		self: func() string { return self },
		send: func(d notify.Destination, subject, body string) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.sent = append(r.sent, sentMsg{d.ID, subject, body})
			return nil
		},
		now:   func() time.Time { return r.now },
		loc:   time.UTC,
		state: r.state,
	}
	return r
}

func notifySettings() notify.Settings {
	s := notify.Default()
	s.Destinations = []notify.Destination{
		{ID: "a", Name: "Ops", Kind: notify.KindEmail, Address: "ops@example.org"},
		{ID: "b", Name: "Hook", Kind: notify.KindWebhook, Address: "https://example.org/h"},
	}
	s.Summary.Enabled, s.Summary.Targets = true, []string{"a"}
	s.Matrix = map[string][]string{"2": {"a", "b"}, "3": {"b"}, "1": {"a", "b"}}
	return s
}

func TestIsSender(t *testing.T) {
	rows := []statusRow{{Node: NodeConfig{Name: "core-1"}, FetchError: "down"}, {Node: NodeConfig{Name: "core-2"}}, {Node: NodeConfig{Name: "core-3"}}}
	if isSender(rows, "core-1") || !isSender(rows, "core-2") || isSender(rows, "core-3") {
		t.Error("only the first reachable core sends")
	}
	if isSender(nil, "core-1") {
		t.Error("nothing reachable, nobody sends")
	}
}

func TestNotifyTick_OnlyTheSenderActs(t *testing.T) {
	r := newNotifyRig(t, notifySettings(), "core-3")
	r.deps.tick()
	r.rows[1].FetchError = "down"
	r.deps.tick()
	if len(r.sent) != 0 {
		t.Fatalf("a non-sender must stay quiet: %+v", r.sent)
	}
}

func TestNotifyTick_NodeLossIsOneMessageAndRecoveryToo(t *testing.T) {
	r := newNotifyRig(t, notifySettings(), "core-1")
	r.deps.tick()
	if len(r.sent) != 0 {
		t.Fatalf("a healthy cluster sends nothing: %+v", r.sent)
	}
	r.rows[1].FetchError = "down"
	r.deps.tick()
	r.deps.tick()
	if len(r.sent) != 2 || !strings.Contains(r.sent[0].subject, "node lost") {
		t.Fatalf("one loss goes to both destinations of impact 2, once: %+v", r.sent)
	}
	r.rows[2].FetchError = "down"
	r.deps.tick()
	if got := r.sent[len(r.sent)-1].subject; !strings.Contains(got, "cluster at risk") {
		t.Fatalf("two lost is impact 1: %q", got)
	}
	r.sent = nil
	r.rows[1].FetchError, r.rows[2].FetchError = "", ""
	r.deps.tick()
	if len(r.sent) != 0 {
		t.Fatalf("recovery is Info and nothing routes Info here: %+v", r.sent)
	}
}

func TestNotifyTick_EventsAreGroupedByImpactAndSentOnce(t *testing.T) {
	r := newNotifyRig(t, notifySettings(), "core-1")
	r.deps.tick()
	for i := 0; i < 30; i++ {
		r.evs["core-2"] = append(r.evs["core-2"], event{Timestamp: r.now.Add(time.Duration(i+1) * time.Second), Level: "ERROR", Prefix: "AGENT:UNSERVED", Message: "scope x"})
	}
	r.evs["core-1"] = []event{{Timestamp: r.now.Add(time.Second), Level: "INFO", Prefix: "AGENT:START", Message: "started"}}
	r.now = r.now.Add(time.Minute)
	r.deps.tick()
	if len(r.sent) != 1 || r.sent[0].dest != "b" || !strings.Contains(r.sent[0].body, " 30x ") {
		t.Fatalf("30 equal events are one message to the one destination routed for impact 3: %+v", r.sent)
	}
	r.sent = nil
	r.now = r.now.Add(time.Minute)
	r.deps.tick()
	if len(r.sent) != 0 {
		t.Fatalf("an event is announced once: %+v", r.sent)
	}
}

func TestNotifyTick_SummaryWaitsForTheChosenHourThenRepeats(t *testing.T) {
	r := newNotifyRig(t, notifySettings(), "core-1")
	r.deps.tick()
	r.now = r.now.Add(30 * time.Minute)
	r.deps.tick()
	if len(r.sent) != 0 {
		t.Fatalf("before 07:00: %+v", r.sent)
	}
	r.now = time.Date(2026, 11, 20, 7, 1, 0, 0, time.UTC)
	r.deps.tick()
	if len(r.sent) != 1 || r.sent[0].dest != "a" || !strings.Contains(r.sent[0].subject, "summary") {
		t.Fatalf("summary at 07:00: %+v", r.sent)
	}
	r.deps.tick()
	if len(r.sent) != 1 {
		t.Fatalf("one summary per interval: %+v", r.sent)
	}
	r.now = time.Date(2026, 11, 21, 7, 1, 0, 0, time.UTC)
	r.deps.tick()
	if len(r.sent) != 2 {
		t.Fatalf("next day: %+v", r.sent)
	}
}

func TestNotifyTick_NoDestinationsNothingHappens(t *testing.T) {
	r := newNotifyRig(t, notify.Default(), "core-1")
	r.rows[0].FetchError = "down"
	r.deps.tick()
	if len(r.sent) != 0 {
		t.Fatal("no destinations")
	}
}

func TestSendWebhook(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 4096)
		n, _ := r.Body.Read(b)
		got = string(b[:n])
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/ok", http.StatusFound)
			return
		}
		if r.URL.Path == "/fail" {
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	if err := sendWebhook(ctx, srv.URL+"/ok", "subject", "body"); err != nil || !strings.Contains(got, `"text":"subject\n\nbody"`) {
		t.Fatalf("%v %q", err, got)
	}
	if err := sendWebhook(ctx, srv.URL+"/fail", "s", "b"); err == nil {
		t.Error("an error status must fail")
	}
	if err := sendWebhook(ctx, srv.URL+"/redirect", "s", "b"); err == nil {
		t.Error("a redirect must not be followed or counted as success")
	}
	if err := sendWebhook(ctx, "file:///etc/passwd", "s", "b"); err == nil {
		t.Error("only http(s)")
	}
}

func TestNotifyState_RoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	st := notifyState{LastSummary: time.Unix(100, 0).UTC(), Lost: []string{"core-2"}}
	if err := saveNotifyState(p, st); err != nil {
		t.Fatal(err)
	}
	if got := loadNotifyState(p); !got.LastSummary.Equal(st.LastSummary) || len(got.Lost) != 1 {
		t.Fatalf("%+v", got)
	}
	if got := loadNotifyState(filepath.Join(t.TempDir(), "none")); !got.LastSummary.IsZero() {
		t.Fatal("a missing file is an empty state")
	}
}

func postNotify(t *testing.T, store *webauth.Store, repl *authSync, cfg *WebConfig, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/notify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withAuthedUser(req, webauth.User{Name: "admin", Role: "admin"})
	rec := httptest.NewRecorder()
	statePath := func() string { return filepath.Join(t.TempDir(), "state.json") }
	handleNotifyPost(store, repl, repl.ref, statePath)(rec, req)
	return rec
}

func TestHandleNotifyPost_DestinationsMatrixAndSummary(t *testing.T) {
	store, usersFile := newTestStore(t, "admin", "correct-horse", "admin")
	cfg := &WebConfig{UsersFile: usersFile}
	repl := testRepl(store, cfg)

	if rec := postNotify(t, store, repl, cfg, url.Values{"action": {"add"}, "name": {"Ops"}, "kind": {"email"}, "address": {"ops@example.org"}}); rec.Code != 200 {
		t.Fatalf("add: %d %s", rec.Code, rec.Body.String())
	}
	if rec := postNotify(t, store, repl, cfg, url.Values{"action": {"add"}, "name": {"Bad"}, "kind": {"email"}, "address": {"nope"}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("an invalid address must be refused: %d", rec.Code)
	}
	s := store.NotifySettings()
	if len(s.Destinations) != 1 {
		t.Fatalf("only the valid destination is kept: %+v", s.Destinations)
	}
	id := s.Destinations[0].ID

	form := url.Values{"action": {"save_matrix"}, "m_2_" + id: {"on"}, "m_9_" + id: {"on"}}
	if rec := postNotify(t, store, repl, cfg, form); rec.Code != 200 {
		t.Fatalf("matrix: %d %s", rec.Code, rec.Body.String())
	}
	if got := store.NotifySettings().Route(notify.NodeLost); len(got) != 1 {
		t.Fatalf("impact 2 routes to the destination: %+v", got)
	}

	form = url.Values{"action": {"save_summary"}, "enabled": {"on"}, "interval": {"weekly"}, "hour": {"9"}, "target": {id, "ghost"}}
	if rec := postNotify(t, store, repl, cfg, form); rec.Code != http.StatusBadRequest {
		t.Fatalf("a summary to an unknown destination must be refused: %d", rec.Code)
	}
	form["target"] = []string{id}
	if rec := postNotify(t, store, repl, cfg, form); rec.Code != 200 {
		t.Fatalf("summary: %d %s", rec.Code, rec.Body.String())
	}
	if got := store.NotifySettings().Summary; got.Interval != "weekly" || got.Hour != 9 || !got.Enabled {
		t.Fatalf("%+v", got)
	}

	if rec := postNotify(t, store, repl, cfg, url.Values{"action": {"remove"}, "id": {id}}); rec.Code != 200 {
		t.Fatalf("remove: %d", rec.Code)
	}
	if got := store.NotifySettings(); len(got.Destinations) != 0 || len(got.Matrix) != 0 || len(got.Summary.Targets) != 0 {
		t.Fatalf("a removed destination leaves no route behind: %+v", got)
	}
}

func TestNotifyPage_NeverShowsAWebhookAddress(t *testing.T) {
	store, _ := newTestStore(t, "admin", "correct-horse", "admin")
	s := notify.Default()
	s.Destinations = []notify.Destination{{ID: "h", Name: "Hook", Kind: notify.KindWebhook, Address: "https://example.org/secret-token-123"}}
	store.Mutate("t", func(d *webauth.Store) error { d.Notify = &s; return nil })
	rec := httptest.NewRecorder()
	handleNotifyGet(store, func() string { return filepath.Join(t.TempDir(), "x") })(rec, httptest.NewRequest("GET", "/notify", nil))
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "secret-token-123") || !strings.Contains(rec.Body.String(), "Hook") {
		t.Fatalf("%d, the secret must not reach the page", rec.Code)
	}
}
