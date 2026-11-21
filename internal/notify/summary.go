// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package notify

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Event is the part of a daemon event a report needs.
type Event struct {
	Time    time.Time
	Level   string
	Prefix  string
	Message string
	Node    string
}

// NodeLine is one core's state in a report.
type NodeLine struct {
	Name      string
	Reachable bool
	State     string
}

// Facts is what a report is built from. A negative LeasesTotal means the
// number is not known; HasDelta says LeasesDelta is meaningful.
type Facts struct {
	Cluster     string
	From        time.Time
	To          time.Time
	Link        string
	Nodes       []NodeLine
	Events      []Event
	Uptime      time.Duration
	StableSince time.Time
	LeasesTotal int
	LeasesDelta int
	HasDelta    bool
	Routines    []Routine
	Version     string
	Latest      string
	LatestURL   string
	UpdateState string
}

// Routine is something that happens on a schedule: Got of Expected happened,
// Flagged of them not as intended (a backup missing on a core, for example).
type Routine struct {
	Name     string
	Verb     string
	Got      int
	Expected int
	Flagged  int
}

// OK reports whether the routine happened as usual: at most a tenth of the
// expected runs missing and none flagged.
func (r Routine) OK() bool {
	return r.Flagged == 0 && r.Got >= r.Expected-r.Expected/10
}

func (r Routine) text() string {
	t := fmt.Sprintf("%d of %d %s", r.Got, r.Expected, r.Verb)
	if r.Flagged > 0 {
		t += fmt.Sprintf(", %d not on every core", r.Flagged)
	} else if r.OK() {
		t += ", all as usual"
	}
	return t
}

// BuildSummary builds the periodic report. It carries no technical details:
// the state of the cluster in a few facts, events only as counts per impact.
func BuildSummary(f Facts, loc *time.Location) Message {
	up := 0
	for _, n := range f.Nodes {
		if n.Reachable {
			up++
		}
	}
	byImpact := map[Impact][]Event{}
	for _, e := range f.Events {
		i := Classify(e.Level, e.Prefix)
		byImpact[i] = append(byImpact[i], e)
	}
	worst := Info
	for _, i := range Impacts {
		if len(byImpact[i]) > 0 && i != Info {
			worst = i
			break
		}
	}
	if lost := len(f.Nodes) - up; lost > 0 {
		if i, ok := Lost(lost, len(f.Nodes)); ok && i < worst {
			worst = i
		}
	}
	var short []string
	for _, r := range f.Routines {
		if !r.OK() {
			short = append(short, strings.ToLower(r.Name)+" "+r.text())
		}
	}
	routineOnly := worst == Info && len(short) > 0
	if routineOnly {
		worst = Warning
	}
	m := Message{Class: ClassSummary, Cluster: f.Cluster, At: f.To, Link: f.Link}
	if routineOnly {
		m.Title = "routine fell short"
		m.Headline = fmt.Sprintf("%s: %s. %d of %d cores up.", worst, strings.Join(short, "; "), up, len(f.Nodes))
	} else if worst == Info {
		m.Title = "all clear"
		m.Headline = fmt.Sprintf("All clear: %d of %d cores up.", up, len(f.Nodes))
	} else {
		m.Title = strings.ToLower(worst.String())
		m.Headline = fmt.Sprintf("%s in this period, %d of %d cores up.", worst, up, len(f.Nodes))
	}

	m.Facts = append(m.Facts, Fact{Label: "Period", Value: f.From.In(loc).Format("2006-01-02 15:04") + " to " + f.To.In(loc).Format("2006-01-02 15:04 MST")},
		Fact{Label: "Cores up", Value: fmt.Sprintf("%d of %d", up, len(f.Nodes))})
	if f.Uptime > 0 {
		m.Facts = append(m.Facts, Fact{Label: "Uptime (shortest core)", Value: Duration(f.Uptime)})
	}
	if !f.StableSince.IsZero() {
		m.Facts = append(m.Facts, Fact{Label: "Stable since", Value: f.StableSince.In(loc).Format("2006-01-02 15:04 MST")})
	}
	if f.LeasesTotal >= 0 {
		m.Facts = append(m.Facts, Fact{Label: "DHCP leases", Value: fmt.Sprintf("%d", f.LeasesTotal)})
		if f.HasDelta {
			m.Facts = append(m.Facts, Fact{Label: "Change since last report", Value: fmt.Sprintf("%+d", f.LeasesDelta)})
		}
	}
	for _, r := range f.Routines {
		m.Facts = append(m.Facts, Fact{Label: r.Name, Value: r.text()})
	}
	m.Facts = append(m.Facts, Fact{Label: "Events", Value: eventCounts(byImpact)})
	switch f.UpdateState {
	case "new":
		m.Facts = append(m.Facts, Fact{Label: "New version available", Value: f.Latest + " (running " + f.Version + ")", Link: f.LatestURL})
	case "current":
		m.Facts = append(m.Facts, Fact{Label: "Version", Value: f.Version + ", up to date"})
	default:
		if f.Version != "" {
			m.Facts = append(m.Facts, Fact{Label: "Version", Value: f.Version})
		}
	}
	return m
}

func eventCounts(by map[Impact][]Event) string {
	var parts []string
	for _, i := range Impacts {
		if n := len(by[i]); n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ToLower(i.String())))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// Duration is d in the two largest units, for example "3d 4h" or "12m".
func Duration(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
	case d >= time.Hour:
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dm", int(d.Minutes()))
}

type group struct {
	prefix  string
	count   int
	example string
	last    time.Time
	first   time.Time
	nodes   map[string]bool
}

func groupEvents(events []Event) []group {
	by := map[string]*group{}
	for _, e := range events {
		g := by[e.Prefix]
		if g == nil {
			g = &group{prefix: e.Prefix, first: e.Time, nodes: map[string]bool{}}
			by[e.Prefix] = g
		}
		g.count++
		if e.Time.Before(g.first) {
			g.first = e.Time
		}
		if e.Node != "" {
			g.nodes[e.Node] = true
		}
		if !e.Time.Before(g.last) {
			g.last, g.example = e.Time, trim(e.Message, 110)
		}
	}
	out := make([]group, 0, len(by))
	for _, g := range by {
		out = append(out, *g)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].count != out[b].count {
			return out[a].count > out[b].count
		}
		return out[a].prefix < out[b].prefix
	})
	if len(out) > 12 {
		out = out[:12]
	}
	return out
}

func trim(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, s)
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// Alert builds one grouped notification of an impact class. The headline is
// the plain sentence for the class; the groups below it say what happened and
// how often, an example, where and when, what it means, and the technical event
// kind last for searching the logs.
func Alert(i Impact, cluster string, events []Event, loc *time.Location, link string) Message {
	groups := groupEvents(events)
	m := Message{Class: ClassOf(i), Cluster: cluster, Headline: i.String() + ": " + i.Lead(), Link: link}
	if len(events) > 0 {
		m.At = events[len(events)-1].Time
	}
	clock := func(t time.Time) string { return t.In(loc).Format("15:04:05") }
	for n, g := range groups {
		title, meaning, ex := Plain(g.prefix, g.example)
		if n == 0 {
			m.Title = title
			if len(groups) > 1 {
				m.Title += fmt.Sprintf(" and %d more", len(groups)-1)
			}
		}
		var nodes []string
		for n := range g.nodes {
			nodes = append(nodes, n)
		}
		sort.Strings(nodes)
		where := "between"
		if len(nodes) > 0 {
			where = "on " + strings.Join(nodes, ", ") + ", between"
		}
		seen := Fact{Label: "Seen", Value: fmt.Sprintf("%s %s and %s", where, clock(g.first), clock(g.last))}
		if cut, ok := compactKinds[g.prefix]; ok {
			d := Detail{Title: title + ": " + strings.TrimPrefix(ex, cut)}
			if g.count > 1 {
				d.Title = fmt.Sprintf("%dx %s, latest: %s", g.count, title, strings.TrimPrefix(ex, cut))
			}
			m.Details = append(m.Details, d)
			continue
		}
		d := Detail{Title: fmt.Sprintf("%dx %s", g.count, title)}
		d.Rows = append(d.Rows, Fact{Label: "Example", Value: ex}, seen)
		if meaning != "" {
			d.Rows = append(d.Rows, Fact{Label: "Meaning", Value: meaning})
		}
		d.Rows = append(d.Rows, Fact{Label: "Event", Value: g.prefix})
		m.Details = append(m.Details, d)
	}
	if m.Title == "" {
		m.Title = i.String()
	}
	if i == Info {
		m.Headline = m.Class + ": " + m.Title
	}
	return m
}
