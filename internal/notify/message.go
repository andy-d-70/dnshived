// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package notify

import (
	"fmt"
	"strings"
	"time"
)

// Message classes, the second word of every subject.
const (
	ClassNotify  = "Notify"
	ClassSummary = "Summary"
	ClassWarning = "Warning"
	ClassError   = "Error"
)

// Fact is one labelled value; Link, when set, makes the value a link.
type Fact struct {
	Label, Value, Link string
}

// Detail is a titled block of technical facts.
type Detail struct {
	Title string
	Rows  []Fact
}

// Message is what every channel renders: an email, a webhook, whatever comes
// next. The headline says it all in a line or two; the facts of a summary and
// the details of an alert come below a separator.
type Message struct {
	Class    string
	Cluster  string
	At       time.Time
	Title    string
	Headline string
	Link     string
	Facts    []Fact
	Details  []Detail
}

// ClassOf is the message class of an impact.
func ClassOf(i Impact) string {
	switch i {
	case ClusterAtRisk, NodeLost, ServiceDegraded:
		return ClassError
	case Warning:
		return ClassWarning
	}
	return ClassNotify
}

// Subject reads "[cluster] Class: title".
func (m Message) Subject() string {
	return oneLine(fmt.Sprintf("[%s] %s: %s", m.Cluster, m.Class, m.Title))
}

func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

const separator = "----------------------------------------"

// Text renders the message as plain text.
func (m Message) Text(loc *time.Location) string {
	var b strings.Builder
	fmt.Fprintf(&b, "dnshived · %s\n%s\n\n%s\n", m.Cluster, m.At.In(loc).Format("2006-01-02 15:04:05 MST"), m.Headline)
	if m.Link != "" {
		fmt.Fprintf(&b, "%s\n", m.Link)
	}
	if len(m.Facts) > 0 || len(m.Details) > 0 {
		b.WriteString("\n" + separator + "\n")
	}
	for _, f := range m.Facts {
		fmt.Fprintf(&b, "%-22s %s\n", f.Label, factValue(f))
	}
	for _, d := range m.Details {
		if d.Title != "" {
			fmt.Fprintf(&b, "\n%s\n", d.Title)
		}
		for _, f := range d.Rows {
			fmt.Fprintf(&b, "  %-10s %s\n", f.Label, factValue(f))
		}
	}
	return b.String()
}

func factValue(f Fact) string {
	if f.Link != "" {
		return f.Value + " " + f.Link
	}
	return f.Value
}
