// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package notify

import (
	"strings"
	"testing"
	"time"
)

func sample() Settings {
	s := Default()
	s.Destinations = []Destination{
		{ID: "a", Name: "Ops", Kind: KindEmail, Address: "ops@example.org"},
		{ID: "b", Name: "Teams", Kind: KindWebhook, Address: "https://example.org/hook/abc"},
	}
	return s
}

func TestSettings_Validate(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Settings)
		want string
	}{
		{"valid", func(s *Settings) {}, ""},
		{"bad email", func(s *Settings) { s.Destinations[0].Address = "Ops <ops@example.org>" }, "plain email"},
		{"header injection", func(s *Settings) { s.Destinations[0].Address = "a@example.org\r\nBcc: x@y" }, "plain email"},
		{"webhook ftp", func(s *Settings) { s.Destinations[1].Address = "ftp://example.org/x" }, "http(s)"},
		{"webhook login", func(s *Settings) { s.Destinations[1].Address = "https://u:p@example.org/x" }, "login"},
		{"duplicate id", func(s *Settings) { s.Destinations[1].ID = "a" }, "duplicate"},
		{"unknown kind", func(s *Settings) { s.Destinations[1].Kind = "sms" }, "unknown kind"},
		{"hour range", func(s *Settings) { s.Summary.Hour = 24 }, "hour"},
		{"summary target", func(s *Settings) { s.Summary.Targets = []string{"zz"} }, "unknown destination"},
		{"matrix target", func(s *Settings) { s.Matrix = map[string][]string{"1": {"zz"}} }, "unknown destination"},
		{"matrix impact", func(s *Settings) { s.Matrix = map[string][]string{"9": {"a"}} }, "unknown impact"},
		{"too many", func(s *Settings) {
			for i := 0; i < MaxDestinations; i++ {
				s.Destinations = append(s.Destinations, Destination{ID: string(rune('c'+i%20)) + strings.Repeat("x", i), Name: "n", Kind: KindEmail, Address: "x@example.org"})
			}
		}, "at most"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := sample()
			tt.edit(&s)
			err := s.Validate()
			if tt.want == "" && err != nil {
				t.Fatalf("unexpected: %v", err)
			}
			if tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("want %q, got %v", tt.want, err)
			}
		})
	}
}

func TestSettings_ToggleRouteAndRemove(t *testing.T) {
	s := sample()
	if !s.Toggle(NodeLost, "a") || !s.Toggle(NodeLost, "b") {
		t.Fatal("toggle on")
	}
	if got := s.Route(NodeLost); len(got) != 2 || got[0].ID != "a" {
		t.Fatalf("route %+v", got)
	}
	if got := s.Route(Info); len(got) != 0 {
		t.Fatalf("an unrouted impact goes nowhere: %+v", got)
	}
	if s.Toggle(NodeLost, "a") {
		t.Fatal("toggle off")
	}
	s.Summary.Targets = []string{"b"}
	s.RemoveDestination("b")
	if len(s.Matrix) != 0 || len(s.Summary.Targets) != 0 || len(s.Destinations) != 1 {
		t.Fatalf("a removed destination leaves nothing behind: %+v", s)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSettings_CloneIsIndependent(t *testing.T) {
	s := sample()
	s.Toggle(Warning, "a")
	c := s.Clone()
	c.Toggle(Warning, "b")
	c.Destinations[0].Name = "x"
	if len(s.Matrix["4"]) != 1 || s.Destinations[0].Name != "Ops" {
		t.Fatal("clone shares state")
	}
}

func TestSummary_NextDueAndDue(t *testing.T) {
	loc := time.FixedZone("x", 3600)
	at := func(d string) time.Time { v, _ := time.ParseInLocation("2006-01-02 15:04", d, loc); return v }
	sum := Summary{Enabled: true, Interval: "daily", Hour: 7, Targets: []string{"a"}}

	if got := sum.NextDue(at("2026-11-20 07:00"), loc); !got.Equal(at("2026-11-21 07:00")) {
		t.Errorf("daily after the send: %v", got)
	}
	if got := sum.NextDue(at("2026-11-20 09:30"), loc); !got.Equal(at("2026-11-21 07:00")) {
		t.Errorf("a late send does not shift the hour: %v", got)
	}
	if got := sum.NextDue(at("2026-11-20 03:00"), loc); !got.Equal(at("2026-11-20 07:00")) {
		t.Errorf("before the hour: %v", got)
	}
	sum.Minute = 45
	if got := sum.NextDue(at("2026-11-20 07:50"), loc); !got.Equal(at("2026-11-21 07:45")) {
		t.Errorf("daily on the minute: %v", got)
	}
	sum.Minute = 0
	for _, old := range []string{"hourly", "6h", "weekly", ""} {
		sum.Interval = old
		if got := sum.NextDue(at("2026-11-20 07:00"), loc); !got.Equal(at("2026-11-21 07:00")) {
			t.Errorf("stored interval %q reads as daily: %v", old, got)
		}
	}

	sum.Interval = "daily"
	if sum.Due(time.Time{}, at("2026-11-20 08:00"), loc) {
		t.Error("never due before a baseline exists")
	}
	if sum.Due(at("2026-11-20 07:00"), at("2026-11-20 20:00"), loc) {
		t.Error("not due the same day")
	}
	if !sum.Due(at("2026-11-20 07:00"), at("2026-11-21 07:00"), loc) {
		t.Error("due at the next chosen hour")
	}
	sum.Targets = nil
	if sum.Due(at("2026-11-20 07:00"), at("2026-11-22 07:00"), loc) {
		t.Error("no destination, nothing to send")
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		level, prefix string
		want          Impact
	}{
		{"INFO", "AGENT:START", Info},
		{"DEBUG", "AGENT:ERROR", Info},
		{"ERROR", "AGENT:ERROR", ServiceDegraded},
		{"ERROR", "AGENT:UNSERVED", ServiceDegraded},
		{"WARNING", "AGENT:DRIFT", Warning},
		{"INFO", "AGENT:TOKEN_DENY", ServiceDegraded},
		{"WARNING", "SOMETHING:NEW", Warning},
		{"CRITICAL", "FSM:TRANSITION", ServiceDegraded},
	}
	for _, tt := range tests {
		if got := Classify(tt.level, tt.prefix); got != tt.want {
			t.Errorf("%s %s = %v, want %v", tt.level, tt.prefix, got, tt.want)
		}
	}
}

func TestLost(t *testing.T) {
	tests := []struct {
		lost, total int
		want        Impact
		ok          bool
	}{
		{0, 3, Info, false},
		{1, 3, NodeLost, true},
		{2, 3, ClusterAtRisk, true},
		{3, 3, ClusterAtRisk, true},
		{1, 2, ClusterAtRisk, true},
		{1, 4, NodeLost, true},
	}
	for _, tt := range tests {
		if got, ok := Lost(tt.lost, tt.total); got != tt.want || ok != tt.ok {
			t.Errorf("Lost(%d,%d) = %v,%v", tt.lost, tt.total, got, ok)
		}
	}
}

func TestBuildSummary_GroupsEqualEvents(t *testing.T) {
	loc := time.UTC
	now := time.Date(2026, 11, 20, 7, 0, 0, 0, loc)
	var ev []Event
	for i := 0; i < 40; i++ {
		ev = append(ev, Event{Time: now.Add(-time.Duration(i) * time.Minute), Level: "ERROR", Prefix: "AGENT:ERROR", Message: "render failed\nfor scope " + string(rune('a'+i%3))})
	}
	ev = append(ev, Event{Time: now, Level: "INFO", Prefix: "AGENT:START", Message: "started"})
	m := BuildSummary(Facts{
		Cluster: "c1", From: now.Add(-24 * time.Hour), To: now,
		Nodes:  []NodeLine{{"core-1", true, "stable"}, {"core-2", false, ""}, {"core-3", true, "stable"}},
		Events: ev,
	}, loc)
	body := m.Text(time.UTC)
	if m.Class != ClassSummary || !strings.Contains(m.Subject(), "node lost") || !strings.Contains(body, "2 of 3") {
		t.Errorf("subject %q\n%s", m.Subject(), body)
	}
	if len(m.Details) != 0 || !strings.Contains(body, "40 service degraded") {
		t.Errorf("a summary has facts and counts, no technical details, and forty equal events are one count:\n%s", body)
	}
}

func TestBuildSummary_AllClear(t *testing.T) {
	now := time.Now()
	m := BuildSummary(Facts{Cluster: "c", From: now, To: now, LeasesTotal: -1, Nodes: []NodeLine{{"core-1", true, "stable"}}}, time.UTC)
	if !strings.Contains(m.Subject(), "all clear") || !strings.HasPrefix(m.Subject(), "[c] Summary: ") {
		t.Errorf("subject %q", m.Subject())
	}
}

func TestAlert_OneMessageForManyEvents(t *testing.T) {
	var ev []Event
	for i := 0; i < 25; i++ {
		ev = append(ev, Event{Time: time.Unix(int64(1000+i), 0), Level: "ERROR", Prefix: "AGENT:UNSERVED", Message: "scope x"})
	}
	am := Alert(ServiceDegraded, "c1", ev, time.UTC, "https://x")
	subject, body := am.Subject(), am.Text(time.UTC)
	if !strings.HasPrefix(subject, "[c1] Error: ") || !strings.Contains(body, "https://x") || strings.Count(body, "AGENT:UNSERVED") != 1 || !strings.Contains(body, "25x A scope is not being served") {
		t.Errorf("%q\n%s", subject, body)
	}
}

func TestSchedule_ActiveAndQuiet(t *testing.T) {
	loc := time.FixedZone("x", 3600)
	at := func(d string) time.Time { v, _ := time.ParseInLocation("2006-01-02 15:04", d, loc); return v }
	night := Schedule{ID: "n", Name: "night", Start: "22:00", End: "06:00", Days: []int{5}}
	cases := []struct {
		when string
		want bool
	}{
		{"2026-11-20 21:59", false},
		{"2026-11-20 22:00", true},
		{"2026-11-21 05:59", true},
		{"2026-11-21 06:00", false},
		{"2026-11-21 22:30", false},
		{"2026-11-19 23:00", false},
	}
	for _, c := range cases {
		if got := night.Active(at(c.when)); got != c.want {
			t.Errorf("night window at %s = %v, want %v", c.when, got, c.want)
		}
	}
	day := Schedule{ID: "d", Name: "lunch", Start: "12:00", End: "13:00"}
	if !day.Active(at("2026-11-22 12:30")) || day.Active(at("2026-11-22 13:00")) {
		t.Error("same-day window with every day")
	}
	if (Schedule{Start: "10:00", End: "10:00"}).Active(at("2026-11-20 10:00")) {
		t.Error("equal from and to is never active")
	}

	s := Default()
	s.Destinations = []Destination{{ID: "a", Name: "A", Kind: KindEmail, Address: "a@example.org"}, {ID: "b", Name: "B", Kind: KindEmail, Address: "b@example.org"}}
	s.Schedules = []Schedule{{ID: "s1", Name: "one", Start: "22:00", End: "06:00", Targets: []string{"a"}}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if !s.Quiet("a", at("2026-11-20 23:00")) || s.Quiet("b", at("2026-11-20 23:00")) {
		t.Error("a schedule covers only its targets")
	}
	s.Schedules[0].Targets = nil
	if !s.Quiet("b", at("2026-11-20 23:00")) {
		t.Error("no targets means every destination")
	}
	s.Schedules[0].Targets = []string{"a"}
	s.RemoveDestination("a")
	if len(s.Schedules) != 0 {
		t.Errorf("a schedule of a removed destination must go, not widen to all: %+v", s.Schedules)
	}
}

func TestSettings_ValidateScheduleAndMinute(t *testing.T) {
	base := Default()
	bad := []func(*Settings){
		func(s *Settings) { s.Summary.Minute = 20 },
		func(s *Settings) { s.Schedules = []Schedule{{ID: "x", Name: "n", Start: "25:00", End: "06:00"}} },
		func(s *Settings) { s.Schedules = []Schedule{{ID: "x", Name: "n", Start: "06:00", End: "06:00"}} },
		func(s *Settings) {
			s.Schedules = []Schedule{{ID: "x", Name: "n", Start: "01:00", End: "06:00", Days: []int{7}}}
		},
		func(s *Settings) {
			s.Schedules = []Schedule{{ID: "x", Name: "n", Start: "01:00", End: "06:00", Targets: []string{"ghost"}}}
		},
	}
	for i, f := range bad {
		s := base.Clone()
		f(&s)
		if s.Validate() == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

func TestAlert_SaysItInPlainWords(t *testing.T) {
	ev := []Event{{Time: time.Unix(1000, 0), Level: "WARNING", Prefix: "AGENT:DRIFT", Node: "core-2",
		Message: "scope dante-099: gate_vrrp_coherence DHCP gate is open but VRRP state is BACKUP, not MASTER"}}
	body := Alert(Warning, "c1", ev, time.UTC, "").Text(time.UTC)
	for _, want := range []string{"What runs differs from what is configured", "does not hold the scope's address (VRRP state BACKUP, expected MASTER)", "on core-2", "Event      AGENT:DRIFT"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in\n%s", want, body)
		}
	}
	if strings.Contains(body, "gate_vrrp_coherence") {
		t.Errorf("internal check name leaked:\n%s", body)
	}
}

func TestMessage_SubjectIsOneLine(t *testing.T) {
	m := Message{Class: ClassError, Cluster: "c", Title: "a\r\nBcc: x@example.org"}
	if got := m.Subject(); strings.ContainsAny(got, "\r\n") {
		t.Errorf("%q", got)
	}
}

func TestRoutine_OKAndSummaryHeadline(t *testing.T) {
	for _, c := range []struct {
		r  Routine
		ok bool
	}{{Routine{Got: 24, Expected: 24}, true}, {Routine{Got: 22, Expected: 24}, true}, {Routine{Got: 19, Expected: 24}, false},
		{Routine{Got: 0, Expected: 1}, false}, {Routine{Got: 24, Expected: 24, Flagged: 1}, false}} {
		if c.r.OK() != c.ok {
			t.Errorf("%+v", c.r)
		}
	}
	now := time.Unix(100000, 0)
	m := BuildSummary(Facts{Cluster: "c", From: now.Add(-24 * time.Hour), To: now, LeasesTotal: -1,
		Nodes:    []NodeLine{{"core-1", true, "STABLE"}},
		Routines: []Routine{{Name: "Backups", Verb: "written", Got: 19, Expected: 24}}}, time.UTC)
	if !strings.Contains(m.Headline, "Warning: backups 19 of 24 written") || len(m.Details) != 0 {
		t.Errorf("%q", m.Headline)
	}
	m = BuildSummary(Facts{Cluster: "c", From: now.Add(-24 * time.Hour), To: now, LeasesTotal: -1,
		Nodes:    []NodeLine{{"core-1", true, "STABLE"}},
		Routines: []Routine{{Name: "Backups", Verb: "written", Got: 24, Expected: 24}}}, time.UTC)
	if !strings.Contains(m.Headline, "All clear") || !strings.Contains(m.Text(time.UTC), "24 of 24 written, all as usual") {
		t.Errorf("%q\n%s", m.Headline, m.Text(time.UTC))
	}
}

func TestAlert_BackupIsOneStraightLine(t *testing.T) {
	ev := []Event{{Time: time.Unix(1000, 0), Level: "INFO", Prefix: "AGENT:BACKUP", Node: "core-3",
		Message: "automated backup written: backup-1.enc, 48.2 KB, on 3 of 3 cores, checked"}}
	m := Alert(Info, "c1", ev, time.UTC, "")
	if m.Headline != "Notify: Backup written" || m.Subject() != "[c1] Notify: Backup written" {
		t.Errorf("%q %q", m.Headline, m.Subject())
	}
	if len(m.Details) != 1 || m.Details[0].Title != "Backup written: backup-1.enc, 48.2 KB, on 3 of 3 cores, checked" || len(m.Details[0].Rows) != 0 {
		t.Errorf("%+v", m.Details)
	}
}
