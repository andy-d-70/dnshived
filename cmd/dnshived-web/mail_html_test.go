// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"dnshived/internal/notify"
)

func TestMailLevel(t *testing.T) {
	for class, want := range map[string]string{
		notify.ClassError: "crit", notify.ClassWarning: "warn", notify.ClassSummary: "ok", notify.ClassNotify: "info",
	} {
		if got := mailLevel(class); got != want {
			t.Errorf("%s: %s, want %s", class, got, want)
		}
	}
}

func TestRenderMailHTML_HeadlineLinkSeparatorThenDetails(t *testing.T) {
	at := time.Date(2026, 11, 21, 6, 0, 40, 0, time.UTC)
	m := notify.Alert(notify.Warning, "lab", []notify.Event{{Time: at, Level: "WARNING", Prefix: "AGENT:WARN", Message: "disk <b>full</b>", Node: "core-3"}}, time.UTC, "https://dns.example.org:8443")
	out := renderMailHTML(m, time.UTC)
	for _, want := range []string{"cid:" + mailLogoCID, ">dnshived<", "Warning</div>", "lab", "2026-11-21 06:00:40 UTC", "#955806", "Open dnshived", "https://dns.example.org:8443", "disk &lt;b&gt;full&lt;/b&gt;", "[lab] Warning: "} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(out, "<b>full</b>") {
		t.Error("event text must be escaped")
	}
	if strings.Index(out, "Open dnshived") > strings.Index(out, "Example") {
		t.Error("the link belongs above the technical details")
	}
	if p := os.Getenv("MAIL_PREVIEW_DIR"); p != "" {
		for _, k := range []string{"summary", "notify", "warning", "error"} {
			sm, _ := sampleMessage(k, "lab", "https://dns.example.org:8443", "tester", at, time.UTC)
			_ = os.WriteFile(p+"/"+k+".html", []byte(renderMailHTML(sm, time.UTC)), 0o644)
		}
	}
}

func TestSampleMessage_EveryClassHasItsSubject(t *testing.T) {
	at := time.Date(2026, 11, 21, 6, 0, 40, 0, time.UTC)
	for kind, class := range map[string]string{"notify": "Notify", "": "Notify", "summary": "Summary", "warning": "Warning", "error": "Error"} {
		m, ok := sampleMessage(kind, "lab", "", "x", at, time.UTC)
		if !ok || !strings.HasPrefix(m.Subject(), "[lab] "+class+": ") {
			t.Errorf("%q: %v %q", kind, ok, m.Subject())
		}
	}
	if _, ok := sampleMessage("bogus", "lab", "", "x", at, time.UTC); ok {
		t.Error("unknown kind accepted")
	}
	m, _ := sampleMessage("summary", "lab", "", "x", at, time.UTC)
	if len(m.Details) != 0 || len(m.Facts) == 0 {
		t.Error("a summary carries facts, no technical details")
	}
}
