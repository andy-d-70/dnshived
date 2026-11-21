// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"encoding/json"
	"errors"
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
		send: func(d notify.Destination, m notify.Message) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.sent = append(r.sent, sentMsg{d.ID, m.Subject(), m.Text(time.UTC)})
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
	if len(r.sent) != 2 || !strings.Contains(r.sent[0].subject, "Node lost") {
		t.Fatalf("one loss goes to both destinations of impact 2, once: %+v", r.sent)
	}
	r.rows[2].FetchError = "down"
	r.deps.tick()
	if got := r.sent[len(r.sent)-1].subject; !strings.Contains(got, "Cluster at risk") {
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
	if len(r.sent) != 1 || r.sent[0].dest != "b" || !strings.Contains(r.sent[0].body, "30x ") {
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
	if len(r.sent) != 1 || r.sent[0].dest != "a" || !strings.Contains(r.sent[0].subject, "Summary") {
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

	form = url.Values{"action": {"save_summary"}, "enabled": {"on"}, "interval": {"weekly"}, "time": {"09:15"}, "target": {id, "ghost"}}
	if rec := postNotify(t, store, repl, cfg, form); rec.Code != http.StatusBadRequest {
		t.Fatalf("a summary to an unknown destination must be refused: %d", rec.Code)
	}
	form["target"] = []string{id}
	if rec := postNotify(t, store, repl, cfg, form); rec.Code != 200 {
		t.Fatalf("summary: %d %s", rec.Code, rec.Body.String())
	}
	if got := store.NotifySettings().Summary; got.Interval != "daily" || got.Hour != 9 || got.Minute != 15 || !got.Enabled {
		t.Fatalf("%+v", got)
	}

	form["time"] = []string{"09:20"}
	if rec := postNotify(t, store, repl, cfg, form); rec.Code != http.StatusBadRequest {
		t.Fatalf("a minute off the 15 minute grid must be refused: %d", rec.Code)
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
	handleNotifyGet(store, nil, func() string { return filepath.Join(t.TempDir(), "x") })(rec, httptest.NewRequest("GET", "/notify", nil))
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "secret-token-123") || !strings.Contains(rec.Body.String(), "Hook") {
		t.Fatalf("%d, the secret must not reach the page", rec.Code)
	}
}

func TestNotifyTick_QuietScheduleDropsAlarmsForItsDestinationsOnly(t *testing.T) {
	s := notifySettings()
	s.Schedules = []notify.Schedule{{ID: "q", Name: "night", Start: "05:00", End: "07:00", Targets: []string{"b"}}}
	s.Matrix = map[string][]string{"3": {"a", "b"}, "2": {"a", "b"}}
	s.Summary.Enabled = false
	r := newNotifyRig(t, s, "core-1")
	r.deps.tick()
	r.evs["core-2"] = []event{{Timestamp: r.now.Add(time.Second), Level: "ERROR", Prefix: "AGENT:UNSERVED", Message: "scope x"}}
	r.now = r.now.Add(time.Minute)
	r.deps.tick()
	if len(r.sent) != 1 || r.sent[0].dest != "a" {
		t.Fatalf("only the destination outside a quiet window is told: %+v", r.sent)
	}
	r.sent = nil
	r.rows[2].FetchError = "down"
	r.now = r.now.Add(time.Minute)
	r.deps.tick()
	if len(r.sent) != 1 || r.sent[0].dest != "a" {
		t.Fatalf("a node loss obeys the schedule too: %+v", r.sent)
	}
	r.sent = nil
	r.now = time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)
	r.evs["core-2"] = append(r.evs["core-2"], event{Timestamp: r.now.Add(time.Second), Level: "ERROR", Prefix: "AGENT:UNSERVED", Message: "scope y"})
	r.deps.tick()
	if len(r.sent) != 2 {
		t.Fatalf("after the window both are told, and the dropped alert is not replayed: %+v", r.sent)
	}
}

func TestHandleNotifyPost_Schedules(t *testing.T) {
	store, usersFile := newTestStore(t, "admin", "correct-horse", "admin")
	cfg := &WebConfig{UsersFile: usersFile}
	repl := testRepl(store, cfg)
	postNotify(t, store, repl, cfg, url.Values{"action": {"add"}, "name": {"Ops"}, "kind": {"email"}, "address": {"ops@example.org"}})
	id := store.NotifySettings().Destinations[0].ID

	bad := url.Values{"action": {"add_schedule"}, "name": {"x"}, "start": {"10:00"}, "end": {"10:00"}}
	if rec := postNotify(t, store, repl, cfg, bad); rec.Code != http.StatusBadRequest {
		t.Fatalf("equal from and to must be refused: %d", rec.Code)
	}
	ok := url.Values{"action": {"add_schedule"}, "name": {"Nights"}, "start": {"22:00"}, "end": {"06:00"}, "day": {"5", "1"}, "target": {id}}
	if rec := postNotify(t, store, repl, cfg, ok); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Nights") {
		t.Fatalf("add: %d %s", rec.Code, rec.Body.String())
	}
	sc := store.NotifySettings().Schedules
	if len(sc) != 1 || sc[0].Days[0] != 1 || sc[0].Days[1] != 5 || sc[0].Targets[0] != id {
		t.Fatalf("%+v", sc)
	}
	form := url.Values{"action": {"save_summary"}, "interval": {"daily"}, "hour": {"7"}, "minute": {"45"}}
	if rec := postNotify(t, store, repl, cfg, form); rec.Code != 200 || store.NotifySettings().Summary.Minute != 45 {
		t.Fatalf("minute: %d", rec.Code)
	}
	form["minute"] = []string{"20"}
	if rec := postNotify(t, store, repl, cfg, form); rec.Code != http.StatusBadRequest {
		t.Fatalf("minute 20 must be refused: %d", rec.Code)
	}
	if rec := postNotify(t, store, repl, cfg, url.Values{"action": {"remove_schedule"}, "id": {sc[0].ID}}); rec.Code != 200 || len(store.NotifySettings().Schedules) != 0 {
		t.Fatalf("remove: %d", rec.Code)
	}
}

func TestRecordSend_FormatAndLogRoundTrip(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var b struct{ Action, Summary string }
			json.NewDecoder(r.Body).Decode(&b)
			got = append(got, b.Action+"\t"+b.Summary)
			w.Write([]byte(`{"ok":true}`))
			return
		}
		var out strings.Builder
		for _, g := range got {
			p := strings.SplitN(g, "\t", 2)
			j, _ := json.Marshal(map[string]string{"ts": "2026-11-20T10:00:00Z", "action": p[0], "summary": p[1]})
			out.Write(j)
			out.WriteString("\n")
		}
		out.WriteString(`{"ts":"2026-11-20T10:00:01Z","action":"config.commit","summary":"x"}` + "\n")
		w.Write([]byte(out.String()))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	n := NodeConfig{Name: "core-1", Addr: u.Host}
	cfg := &WebConfig{Nodes: []NodeConfig{n}}
	d := notify.Destination{ID: "a", Name: "Ops", Kind: notify.KindEmail, Address: "secret@example.org"}

	recordSend(cfg, "alert: Node lost", d, "subj 1", "", nil)
	recordSend(cfg, "recover", d, "subj 2", "", errors.New("smtp down"))
	recordSend(cfg, "alert: Warning", d, "subj 3", "dropped, quiet schedule Nights", nil)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(got) < 3 {
		time.Sleep(20 * time.Millisecond)
	}
	rows := fetchNotifyLog([]NodeConfig{n, n}, 10)
	if len(rows) != 3 {
		t.Fatalf("rows: %+v (got %v)", rows, got)
	}
	if !rows[0].Bad && rows[0].Subject != "subj 2" {
		t.Logf("order is newest first: %+v", rows)
	}
	for _, r := range rows {
		if strings.Contains(r.To+r.Result+r.Subject+r.Reason, "secret@example.org") {
			t.Errorf("address leaked: %+v", r)
		}
	}
}

func TestNotifyTick_SummaryCountsTheRoutineBackups(t *testing.T) {
	r := newNotifyRig(t, notifySettings(), "core-1")
	r.deps.backups = func() time.Duration { return 30 * time.Minute }
	r.deps.tick()
	at := func(m int) time.Time { return time.Date(2026, 11, 20, 6, m, 0, 0, time.UTC) }
	r.evs["core-3"] = []event{
		{Timestamp: at(10), Level: "INFO", Prefix: "AGENT:BACKUP", Message: "automated backup written: backup-a.enc, 1.0 KB, on 3 of 3 cores, checked"},
		{Timestamp: at(40), Level: "WARNING", Prefix: "AGENT:BACKUP", Message: "automated backup written: backup-b.enc, 1.0 KB, only 2 of 3 cores, missing on: x"},
	}
	r.now = at(45)
	r.deps.tick()
	r.sent = nil
	r.now = time.Date(2026, 11, 20, 7, 1, 0, 0, time.UTC)
	r.deps.tick()
	var sum *sentMsg
	for i := range r.sent {
		if strings.Contains(r.sent[i].subject, "Summary") {
			sum = &r.sent[i]
		}
	}
	if sum == nil {
		t.Fatalf("no summary: %+v", r.sent)
	}
	if !strings.Contains(sum.body, "Backups") || !strings.Contains(sum.body, "2 of 2 written, 1 not on every core") || !strings.Contains(sum.subject, "warning") {
		t.Errorf("%s\n%s", sum.subject, sum.body)
	}
}
