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

// Facts is what a report is built from.
type Facts struct {
	Cluster string
	From    time.Time
	To      time.Time
	Nodes   []NodeLine
	Events  []Event
}

// BuildSummary renders the periodic report as plain text. Events are grouped by
// impact class and, inside a class, by event kind with a count, so a flood of
// the same event is one line.
func BuildSummary(f Facts, loc *time.Location) (subject, body string) {
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

	status := "all clear"
	if worst != Info {
		status = strings.ToLower(worst.String())
	}
	subject = fmt.Sprintf("dnshived summary: %s (%d of %d cores up)", status, up, len(f.Nodes))

	var b strings.Builder
	fmt.Fprintf(&b, "Cluster %s, %s to %s\n\n", f.Cluster, f.From.In(loc).Format("2006-01-02 15:04"), f.To.In(loc).Format("2006-01-02 15:04 MST"))
	b.WriteString("Cores\n")
	for _, n := range f.Nodes {
		state := n.State
		if !n.Reachable {
			state = "NOT REACHABLE"
		}
		fmt.Fprintf(&b, "  %-14s %s\n", n.Name, state)
	}
	b.WriteString("\nEvents by impact\n")
	for _, i := range Impacts {
		list := byImpact[i]
		fmt.Fprintf(&b, "  %-17s %d\n", i.String(), len(list))
	}
	for _, i := range Impacts {
		if i == Info || len(byImpact[i]) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n%s\n", i)
		groups := groupEvents(byImpact[i])
		for _, g := range groups {
			fmt.Fprintf(&b, "  %3dx %-22s %s\n", g.count, g.prefix, g.example)
		}
	}
	return subject, b.String()
}

type group struct {
	prefix  string
	count   int
	example string
	last    time.Time
}

func groupEvents(events []Event) []group {
	by := map[string]*group{}
	for _, e := range events {
		g := by[e.Prefix]
		if g == nil {
			g = &group{prefix: e.Prefix}
			by[e.Prefix] = g
		}
		g.count++
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

// Alert renders one grouped notification of an impact class: a count per event
// kind with the latest example, never one message per event.
func Alert(i Impact, cluster string, events []Event, loc *time.Location) (subject, body string) {
	subject = fmt.Sprintf("dnshived %s: %s", strings.ToLower(i.String()), cluster)
	var b strings.Builder
	fmt.Fprintf(&b, "%s on %s\n%s\n\n", i, cluster, i.Describe())
	for _, g := range groupEvents(events) {
		fmt.Fprintf(&b, "  %3dx %-22s %s\n", g.count, g.prefix, g.example)
	}
	if len(events) > 0 {
		fmt.Fprintf(&b, "\nLatest at %s\n", events[len(events)-1].Time.In(loc).Format("2006-01-02 15:04:05 MST"))
	}
	return subject, b.String()
}
