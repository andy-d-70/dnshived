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
		{"unknown interval", func(s *Settings) { s.Summary.Interval = "yearly" }, "interval"},
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
	sum.Interval = "weekly"
	if got := sum.NextDue(at("2026-11-20 07:00"), loc); !got.Equal(at("2026-11-27 07:00")) {
		t.Errorf("weekly: %v", got)
	}
	sum.Interval = "6h"
	if got := sum.NextDue(at("2026-11-20 07:10"), loc); !got.Equal(at("2026-11-20 13:10")) {
		t.Errorf("6h follows the last: %v", got)
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
	subject, body := BuildSummary(Facts{
		Cluster: "c1", From: now.Add(-24 * time.Hour), To: now,
		Nodes:  []NodeLine{{"core-1", true, "stable"}, {"core-2", false, ""}, {"core-3", true, "stable"}},
		Events: ev,
	}, loc)
	if !strings.Contains(subject, "node lost") || !strings.Contains(subject, "2 of 3") {
		t.Errorf("subject %q", subject)
	}
	if strings.Count(body, "AGENT:ERROR") != 1 || !strings.Contains(body, " 40x ") {
		t.Errorf("forty equal events must be one line:\n%s", body)
	}
	if strings.Contains(body, "\nfor scope") || !strings.Contains(body, "NOT REACHABLE") {
		t.Errorf("a newline in a message must not break the report:\n%s", body)
	}
}

func TestBuildSummary_AllClear(t *testing.T) {
	now := time.Now()
	subject, _ := BuildSummary(Facts{Cluster: "c", From: now, To: now, Nodes: []NodeLine{{"core-1", true, "stable"}}}, time.UTC)
	if !strings.Contains(subject, "all clear") {
		t.Errorf("subject %q", subject)
	}
}

func TestAlert_OneMessageForManyEvents(t *testing.T) {
	var ev []Event
	for i := 0; i < 25; i++ {
		ev = append(ev, Event{Time: time.Unix(int64(1000+i), 0), Level: "ERROR", Prefix: "AGENT:UNSERVED", Message: "scope x"})
	}
	subject, body := Alert(ServiceDegraded, "c1", ev, time.UTC)
	if !strings.Contains(subject, "service degraded") || strings.Count(body, "AGENT:UNSERVED") != 1 || !strings.Contains(body, " 25x ") {
		t.Errorf("%q\n%s", subject, body)
	}
}
