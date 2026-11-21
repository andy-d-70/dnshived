// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package notify holds the settings and the rules of the operator notifications:
// which events count as which impact, which destinations get which impact, and
// when the periodic summary is due. It does no I/O.
package notify

import (
	"fmt"
	"net/mail"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Impact orders what an event means for the cluster; 1 is the worst. Events of
// equal impact are routed together, so one click in the matrix covers them all.
type Impact int

const (
	ClusterAtRisk Impact = 1 + iota
	NodeLost
	ServiceDegraded
	Warning
	Info
)

// Impacts lists every impact class, worst first.
var Impacts = []Impact{ClusterAtRisk, NodeLost, ServiceDegraded, Warning, Info}

func (i Impact) String() string {
	switch i {
	case ClusterAtRisk:
		return "Cluster at risk"
	case NodeLost:
		return "Node lost"
	case ServiceDegraded:
		return "Service degraded"
	case Warning:
		return "Warning"
	case Info:
		return "Info"
	}
	return fmt.Sprintf("Impact %d", int(i))
}

// Describe says what lands in each class, for the matrix tooltips.
func (i Impact) Describe() string {
	switch i {
	case ClusterAtRisk:
		return "Two or more cores are lost, or the cluster has no quorum: the next failure takes the service down."
	case NodeLost:
		return "One core is lost; the others carry the service."
	case ServiceDegraded:
		return "A scope is not served, a node runs apart from the cluster, or a service reports errors."
	case Warning:
		return "Something needs a look but nothing is down: failed commits, expiring tokens, drift that healed."
	case Info:
		return "Routine events: commits, restarts, failovers that completed."
	}
	return ""
}

// Destination kinds.
const (
	KindEmail   = "email"
	KindWebhook = "webhook"
)

// Destination is one place a notification can go. A webhook receives a JSON
// body {"text": "..."} that Teams, Slack and Mattermost incoming webhooks accept.
type Destination struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Address string `json:"address"`
}

// Summary is the daily report, sent at Hour:Minute local time. Interval is
// kept as "daily" for cores that still read it; any stored value means daily.
type Summary struct {
	Enabled  bool     `json:"enabled"`
	Interval string   `json:"interval"`
	Hour     int      `json:"hour"`
	Minute   int      `json:"minute,omitempty"`
	Targets  []string `json:"targets,omitempty"`
}

// Schedule is a quiet time: between Start and End (local, "15:04") on Days
// (0 = Sunday, none = every day) no alarm goes to Targets (none = every
// destination). A window that ends before it starts runs past midnight and
// belongs to the day it starts on.
type Schedule struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Days    []int    `json:"days,omitempty"`
	Start   string   `json:"start"`
	End     string   `json:"end"`
	Targets []string `json:"targets,omitempty"`
}

// Settings is the whole notification configuration.
type Settings struct {
	ClusterName  string              `json:"cluster_name,omitempty"`
	Summary      Summary             `json:"summary"`
	Destinations []Destination       `json:"destinations,omitempty"`
	Matrix       map[string][]string `json:"matrix,omitempty"`
	Schedules    []Schedule          `json:"schedules,omitempty"`
}

var Minutes = []int{0, 15, 30, 45}

const MaxSchedules = 16

func clockMinutes(s string) (int, bool) {
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0, false
	}
	return t.Hour()*60 + t.Minute(), true
}

func (sc Schedule) onDay(d int) bool {
	if len(sc.Days) == 0 {
		return true
	}
	for _, v := range sc.Days {
		if v == d {
			return true
		}
	}
	return false
}

func (sc Schedule) Active(t time.Time) bool {
	a, ok1 := clockMinutes(sc.Start)
	b, ok2 := clockMinutes(sc.End)
	if !ok1 || !ok2 || a == b {
		return false
	}
	m := t.Hour()*60 + t.Minute()
	day := int(t.Weekday())
	if a < b {
		return m >= a && m < b && sc.onDay(day)
	}
	if m >= a {
		return sc.onDay(day)
	}
	return m < b && sc.onDay((day+6)%7)
}

func (sc Schedule) Covers(id string) bool {
	if len(sc.Targets) == 0 {
		return true
	}
	for _, t := range sc.Targets {
		if t == id {
			return true
		}
	}
	return false
}

func (s Settings) Quiet(id string, t time.Time) bool {
	_, quiet := s.QuietBy(id, t)
	return quiet
}

// QuietBy is Quiet that also names the schedule that holds the alarm back.
func (s Settings) QuietBy(id string, t time.Time) (string, bool) {
	for _, sc := range s.Schedules {
		if sc.Covers(id) && sc.Active(t) {
			return sc.Name, true
		}
	}
	return "", false
}

const (
	MaxDestinations = 32
	DefaultInterval = "daily"
	DefaultHour     = 7
)

// Default is what a cluster starts with: a daily summary at 07:00 to nobody
// until a destination exists.
func Default() Settings {
	return Settings{Summary: Summary{Interval: DefaultInterval, Hour: DefaultHour}}
}

// ClusterLabel is the name subjects carry: the operator's, else the cluster id.
func (s Settings) ClusterLabel(id string) string {
	if s.ClusterName != "" {
		return s.ClusterName
	}
	return id
}

// Clone returns a copy that shares nothing with s.
func (s Settings) Clone() Settings {
	out := s
	out.Summary.Targets = append([]string(nil), s.Summary.Targets...)
	out.Destinations = append([]Destination(nil), s.Destinations...)
	out.Schedules = make([]Schedule, len(s.Schedules))
	for i, sc := range s.Schedules {
		sc.Days = append([]int(nil), sc.Days...)
		sc.Targets = append([]string(nil), sc.Targets...)
		out.Schedules[i] = sc
	}
	if len(out.Schedules) == 0 {
		out.Schedules = nil
	}
	out.Matrix = make(map[string][]string, len(s.Matrix))
	for k, v := range s.Matrix {
		out.Matrix[k] = append([]string(nil), v...)
	}
	return out
}

// Key is the matrix key of an impact.
func Key(i Impact) string { return fmt.Sprintf("%d", int(i)) }

// Validate checks s and returns the first problem in words an operator can act on.
func (s Settings) Validate() error {
	if len(s.ClusterName) > 64 || strings.ContainsAny(s.ClusterName, "\r\n\t[]<>\"") {
		return fmt.Errorf("the cluster name is at most 64 characters, without brackets, quotes or line breaks")
	}
	if len(s.Destinations) > MaxDestinations {
		return fmt.Errorf("at most %d destinations", MaxDestinations)
	}
	ids := make(map[string]bool, len(s.Destinations))
	for _, d := range s.Destinations {
		if d.ID == "" || strings.ContainsAny(d.ID, " \t\r\n\"<>&") || len(d.ID) > 32 {
			return fmt.Errorf("invalid destination id %q", d.ID)
		}
		if ids[d.ID] {
			return fmt.Errorf("duplicate destination id %q", d.ID)
		}
		ids[d.ID] = true
		if strings.TrimSpace(d.Name) == "" || len(d.Name) > 60 || strings.ContainsAny(d.Name, "\r\n") {
			return fmt.Errorf("destination %s needs a name of up to 60 characters", d.ID)
		}
		switch d.Kind {
		case KindEmail:
			a, err := mail.ParseAddress(d.Address)
			if err != nil || a.Address != d.Address || strings.ContainsAny(d.Address, "\r\n") {
				return fmt.Errorf("%s: %q is not a plain email address", d.Name, d.Address)
			}
		case KindWebhook:
			if err := ValidateWebhookURL(d.Address); err != nil {
				return fmt.Errorf("%s: %w", d.Name, err)
			}
		default:
			return fmt.Errorf("%s: unknown kind %q", d.Name, d.Kind)
		}
	}
	if s.Summary.Hour < 0 || s.Summary.Hour > 23 {
		return fmt.Errorf("summary hour %d is not between 0 and 23", s.Summary.Hour)
	}
	if s.Summary.Minute < 0 || s.Summary.Minute > 59 || s.Summary.Minute%15 != 0 {
		return fmt.Errorf("summary minute %d is not 0, 15, 30 or 45", s.Summary.Minute)
	}
	for _, t := range s.Summary.Targets {
		if !ids[t] {
			return fmt.Errorf("the summary goes to an unknown destination %q", t)
		}
	}
	if len(s.Schedules) > MaxSchedules {
		return fmt.Errorf("at most %d schedules", MaxSchedules)
	}
	sids := make(map[string]bool, len(s.Schedules))
	for _, sc := range s.Schedules {
		if sc.ID == "" || strings.ContainsAny(sc.ID, " \t\r\n\"<>&") || len(sc.ID) > 32 || sids[sc.ID] {
			return fmt.Errorf("invalid or duplicate schedule id %q", sc.ID)
		}
		sids[sc.ID] = true
		if strings.TrimSpace(sc.Name) == "" || len(sc.Name) > 60 || strings.ContainsAny(sc.Name, "\r\n") {
			return fmt.Errorf("schedule %s needs a name of up to 60 characters", sc.ID)
		}
		a, ok1 := clockMinutes(sc.Start)
		b, ok2 := clockMinutes(sc.End)
		if !ok1 || !ok2 {
			return fmt.Errorf("schedule %s: times must look like 22:00", sc.Name)
		}
		if a == b {
			return fmt.Errorf("schedule %s: from and to must differ", sc.Name)
		}
		for _, d := range sc.Days {
			if d < 0 || d > 6 {
				return fmt.Errorf("schedule %s: unknown weekday %d", sc.Name, d)
			}
		}
		for _, t := range sc.Targets {
			if !ids[t] {
				return fmt.Errorf("schedule %s covers an unknown destination %q", sc.Name, t)
			}
		}
	}
	for k, list := range s.Matrix {
		known := false
		for _, i := range Impacts {
			if Key(i) == k {
				known = true
			}
		}
		if !known {
			return fmt.Errorf("unknown impact %q in the matrix", k)
		}
		for _, t := range list {
			if !ids[t] {
				return fmt.Errorf("the matrix routes impact %s to an unknown destination %q", k, t)
			}
		}
	}
	return nil
}

// ValidateWebhookURL accepts an http(s) URL with a host and no credentials.
func ValidateWebhookURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("%q is not an http(s) URL", raw)
	}
	if u.User != nil {
		return fmt.Errorf("the URL must not contain a login; use the token the service puts in the path")
	}
	if strings.ContainsAny(raw, "\r\n") {
		return fmt.Errorf("invalid URL")
	}
	return nil
}

// Route returns the destinations that take notifications of impact i, in
// the order the destinations are listed.
func (s Settings) Route(i Impact) []Destination {
	want := make(map[string]bool)
	for _, id := range s.Matrix[Key(i)] {
		want[id] = true
	}
	var out []Destination
	for _, d := range s.Destinations {
		if want[d.ID] {
			out = append(out, d)
		}
	}
	return out
}

// SummaryTargets returns the destinations of the periodic summary.
func (s Settings) SummaryTargets() []Destination {
	want := make(map[string]bool)
	for _, id := range s.Summary.Targets {
		want[id] = true
	}
	var out []Destination
	for _, d := range s.Destinations {
		if want[d.ID] {
			out = append(out, d)
		}
	}
	return out
}

// Toggle flips one cell of the matrix and returns the new state.
func (s *Settings) Toggle(i Impact, id string) bool {
	if s.Matrix == nil {
		s.Matrix = map[string][]string{}
	}
	k := Key(i)
	list := s.Matrix[k]
	for n, v := range list {
		if v == id {
			s.Matrix[k] = append(list[:n:n], list[n+1:]...)
			if len(s.Matrix[k]) == 0 {
				delete(s.Matrix, k)
			}
			return false
		}
	}
	s.Matrix[k] = append(list, id)
	sort.Strings(s.Matrix[k])
	return true
}

// RemoveDestination drops a destination and every reference to it.
func (s *Settings) RemoveDestination(id string) {
	kept := s.Destinations[:0:0]
	for _, d := range s.Destinations {
		if d.ID != id {
			kept = append(kept, d)
		}
	}
	s.Destinations = kept
	drop := func(list []string) []string {
		out := list[:0:0]
		for _, v := range list {
			if v != id {
				out = append(out, v)
			}
		}
		return out
	}
	s.Summary.Targets = drop(s.Summary.Targets)
	keep := s.Schedules[:0:0]
	for _, sc := range s.Schedules {
		had := len(sc.Targets)
		sc.Targets = drop(sc.Targets)
		if had > 0 && len(sc.Targets) == 0 {
			continue
		}
		keep = append(keep, sc)
	}
	s.Schedules = keep
	for k, list := range s.Matrix {
		if l := drop(list); len(l) == 0 {
			delete(s.Matrix, k)
		} else {
			s.Matrix[k] = l
		}
	}
}

// NextDue returns when the summary after the one sent at last is due: the
// chosen local time of day, so a restart or a late start never shifts it.
func (s Summary) NextDue(last time.Time, loc *time.Location) time.Time {
	l := last.In(loc)
	next := time.Date(l.Year(), l.Month(), l.Day(), s.Hour, s.Minute, 0, 0, loc)
	for !next.After(l) {
		next = next.AddDate(0, 0, 1)
	}
	return next
}

// Due reports whether a summary should go out now. Without a previous one the
// first goes at the next chosen hour, never straight at start.
func (s Summary) Due(last, now time.Time, loc *time.Location) bool {
	if !s.Enabled || len(s.Targets) == 0 {
		return false
	}
	if last.IsZero() {
		return false
	}
	return !now.Before(s.NextDue(last, loc))
}
