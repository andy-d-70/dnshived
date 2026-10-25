package loglevel

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"
)

func reset(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(new(bytes.Buffer)) })
	mu.Lock()
	escalated = map[string]time.Time{}
	suppressed = map[string]int{}
	lastValue = map[string]string{}
	mu.Unlock()
	now = time.Now
	if err := Set("auto"); err != nil {
		t.Fatal(err)
	}
	return &buf
}

func TestSetValidatesAndReportsCurrent(t *testing.T) {
	reset(t)
	for _, v := range []string{"", "auto", "debug", "info", "warning"} {
		if err := Set(v); err != nil {
			t.Fatalf("Set(%q): %v", v, err)
		}
	}
	if err := Set("verbose"); err == nil {
		t.Fatal("Set(verbose) accepted an invalid value")
	}
	if err := Set("info"); err != nil {
		t.Fatal(err)
	}
	if got := Current(); got != "info" {
		t.Fatalf("Current() = %q, want info", got)
	}
	if err := Set(""); err != nil {
		t.Fatal(err)
	}
	if got := Current(); got != "auto" {
		t.Fatalf("Current() after \"\" = %q, want auto", got)
	}
}

func TestExplicitLevelsFilter(t *testing.T) {
	buf := reset(t)
	cases := []struct {
		level               string
		wantD, wantI, wantW bool
	}{
		{"debug", true, true, true},
		{"info", false, true, true},
		{"warning", false, false, true},
	}
	for _, c := range cases {
		buf.Reset()
		if err := Set(c.level); err != nil {
			t.Fatal(err)
		}
		Debugf("[AGENT:D] d")
		Infof("[AGENT:I] i")
		Warnf("[AGENT:W] w")
		out := buf.String()
		if strings.Contains(out, "[AGENT:D]") != c.wantD || strings.Contains(out, "[AGENT:I]") != c.wantI || strings.Contains(out, "[AGENT:W]") != c.wantW {
			t.Errorf("level %s logged %q", c.level, out)
		}
	}
}

func TestAutoSuppressesDebugAndCountsIt(t *testing.T) {
	buf := reset(t)
	Infof("[AGENT:STATE] gate open")
	Debugf("[AGENT:TOKEN_ACQ] witness confirmed")
	Debugf("[AGENT:TOKEN_ACQ] witness confirmed")
	if strings.Contains(buf.String(), "TOKEN_ACQ") {
		t.Fatalf("auto logged debug detail: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "[AGENT:STATE] gate open") {
		t.Fatalf("auto dropped info: %q", buf.String())
	}
	buf.Reset()
	flushSummary()
	if !strings.Contains(buf.String(), "[LOG:SUMMARY]") || !strings.Contains(buf.String(), "AGENT:TOKEN_ACQ x2") {
		t.Fatalf("summary = %q", buf.String())
	}
	buf.Reset()
	flushSummary()
	if buf.Len() != 0 {
		t.Fatalf("empty window still summarised: %q", buf.String())
	}
}

func TestWarningEscalatesSubsystemForFiveMinutes(t *testing.T) {
	buf := reset(t)
	t0 := time.Now()
	now = func() time.Time { return t0 }
	Warnf("[AGENT:ERROR] something failed")
	Debugf("[AGENT:TOKEN_ACQ] witness confirmed")
	if !strings.Contains(buf.String(), "[AGENT:TOKEN_ACQ] witness confirmed") {
		t.Fatalf("debug not escalated after warning: %q", buf.String())
	}
	Debugf("[DESIRED:STICKY] other subsystem")
	if strings.Contains(buf.String(), "DESIRED:STICKY") {
		t.Fatalf("escalation leaked to another subsystem: %q", buf.String())
	}
	now = func() time.Time { return t0.Add(escalateFor + time.Second) }
	buf.Reset()
	Debugf("[AGENT:TOKEN_ACQ] witness confirmed")
	if buf.Len() != 0 {
		t.Fatalf("escalation did not expire: %q", buf.String())
	}
}

func TestInfoOnChangeLogsOnlyChanges(t *testing.T) {
	buf := reset(t)
	InfoOnChange("token:office", "2/3", "[AGENT:TOKEN_ACQ] agreed %s", "2/3")
	InfoOnChange("token:office", "2/3", "[AGENT:TOKEN_ACQ] agreed %s", "2/3")
	InfoOnChange("token:office", "3/3", "[AGENT:TOKEN_ACQ] agreed %s", "3/3")
	if n := strings.Count(buf.String(), "[AGENT:TOKEN_ACQ]"); n != 2 {
		t.Fatalf("logged %d lines, want 2 (first and changed): %q", n, buf.String())
	}
}

func TestDebugModeLogsEverythingUnsummarised(t *testing.T) {
	buf := reset(t)
	if err := Set("debug"); err != nil {
		t.Fatal(err)
	}
	Debugf("[AGENT:TOKEN_ACQ] witness confirmed")
	flushSummary()
	if !strings.Contains(buf.String(), "TOKEN_ACQ") || strings.Contains(buf.String(), "SUMMARY") {
		t.Fatalf("debug mode output = %q", buf.String())
	}
}

func TestStepfLevelFollowsOutcome(t *testing.T) {
	buf := reset(t)
	if err := Set("warning"); err != nil {
		t.Fatal(err)
	}
	Stepf(true, "[DECOMMISSION] ok step")
	if buf.Len() != 0 {
		t.Fatalf("successful step logged at warning: %q", buf.String())
	}
	Stepf(false, "[DECOMMISSION] failed step")
	if !strings.Contains(buf.String(), "failed step") {
		t.Fatalf("failed step not logged at warning: %q", buf.String())
	}
}
