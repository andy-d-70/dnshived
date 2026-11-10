// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"dnshived/internal/config"
)

func TestParseDNSCheckInput_AcceptedSpellings(t *testing.T) {
	tests := []struct {
		name, in string
		want     config.DNSCheck
	}{
		{"pipe", "orf.at|A", config.DNSCheck{Name: "orf.at", Type: "A"}},
		{"slash", "orf.at/A", config.DNSCheck{Name: "orf.at", Type: "A"}},
		{"space", "orf.at AAAA", config.DNSCheck{Name: "orf.at", Type: "AAAA"}},
		{"tab", "orf.at\tmx", config.DNSCheck{Name: "orf.at", Type: "MX"}},
		{"bare name means A", "orf.at", config.DNSCheck{Name: "orf.at", Type: "A"}},
		{"lower case type", "orf.at|txt", config.DNSCheck{Name: "orf.at", Type: "TXT"}},
		{"trailing dot kept", "claude.ai.|A", config.DNSCheck{Name: "claude.ai.", Type: "A"}},
		{"padding around the separator", "  orf.at  |  a  ", config.DNSCheck{Name: "orf.at", Type: "A"}},
		{"srv style underscore labels", "_sip._tcp.example.com|SRV", config.DNSCheck{Name: "_sip._tcp.example.com", Type: "SRV"}},
		{"windows line ending", "orf.at/A\r", config.DNSCheck{Name: "orf.at", Type: "A"}},
		{"caa", "example.com|CAA", config.DNSCheck{Name: "example.com", Type: "CAA"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checks, finds := parseDNSCheckInput(tt.in)
			if len(finds) != 0 || len(checks) != 1 || checks[0] != tt.want {
				t.Errorf("parse(%q) = %+v, %+v, want %+v", tt.in, checks, finds, tt.want)
			}
		})
	}
}

func TestParseDNSCheckInput_Refusals(t *testing.T) {
	long := strings.Repeat("a", 64)
	tests := []struct {
		name, in, line, contains string
	}{
		{"unknown type", "orf.at|AX", "1", "unknown type"},
		{"RAW", "orf.at|RAW", "1", "RAW is for records"},
		{"missing type", "orf.at|", "1", "type is missing"},
		{"missing type slash", "orf.at/", "1", "type is missing"},
		{"too many parts", "orf.at A B", "1", "too many parts"},
		{"space in name", "or f.at|A", "1", "contains a space"},
		{"comma", "or,f.at|A", "1", "not allowed"},
		{"newline injection kept out of names", "a\x00b|A", "1", "not allowed"},
		{"empty label", "orf..at|A", "1", "empty label"},
		{"leading dot", ".orf.at|A", "1", "empty label"},
		{"label too long", long + ".at|A", "1", "63"},
		{"name too long", strings.Repeat("a.", 130) + "at|A", "1", "253"},
		{"hyphen edge", "-orf.at|A", "1", "hyphen"},
		{"international", "bücher.at|A", "1", "punycode"},
		{"root only", ".|A", "1", "name is empty"},
		{"line number counts blank lines", "orf.at|A\n\nbad|ZZ", "3", "unknown type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, finds := parseDNSCheckInput(tt.in)
			var got *dnsCheckFinding
			for i := range finds {
				if finds[i].Level == "error" {
					got = &finds[i]
				}
			}
			if got == nil {
				t.Fatalf("parse(%q): no error, finds=%+v", tt.in, finds)
			}
			if !strings.Contains(got.Message, tt.contains) || got.Line != atoiOr0(tt.line) {
				t.Errorf("parse(%q) = line %d %q, want line %s containing %q", tt.in, got.Line, got.Message, tt.line, tt.contains)
			}
		})
	}
}

func atoiOr0(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

func TestParseDNSCheckInput_AllErrorsAtOnceAndDuplicates(t *testing.T) {
	checks, finds := parseDNSCheckInput("a.at|ZZ\norf.at|A\nORF.AT./a\nb b|A\nx.at\nx.at|a")
	if len(checks) != 2 {
		t.Fatalf("checks = %+v", checks)
	}
	var errs, warns int
	for _, f := range finds {
		if f.Level == "error" {
			errs++
		} else {
			warns++
		}
	}
	if errs != 2 || warns != 2 {
		t.Errorf("want 2 errors and 2 duplicate warnings, got %+v", finds)
	}
}

func TestParseDNSCheckInput_LimitAndEmpty(t *testing.T) {
	var b strings.Builder
	for i := 0; i <= maxDNSChecks; i++ {
		b.WriteString("h")
		b.WriteString(strings.Repeat("x", i%7))
		b.WriteString(strings.Repeat("y", i/7))
		b.WriteString(".example|A\n")
	}
	if _, finds := parseDNSCheckInput(b.String()); len(finds) == 0 || finds[len(finds)-1].Line != 0 || !strings.Contains(finds[len(finds)-1].Message, "at most") {
		t.Errorf("more than %d checks must be refused, finds=%+v", maxDNSChecks, finds)
	}
	if checks, finds := parseDNSCheckInput(" \n\n"); len(checks) != 0 || len(finds) != 0 {
		t.Errorf("blank input is fine (built-in default), got %+v %+v", checks, finds)
	}
}

func TestDefaultCheckHelpExampleParsesToTheBuiltInDefault(t *testing.T) {
	checks, finds := parseDNSCheckInput(config.DefaultDNSCheckName + "|" + config.DefaultDNSCheckType)
	if len(finds) != 0 || len(checks) != 1 || checks[0].Name != config.DefaultDNSCheckName || checks[0].Type != config.DefaultDNSCheckType {
		t.Fatalf("the help text example claude.ai.|A must equal the built-in default, got %+v %+v", checks, finds)
	}
	var b strings.Builder
	if err := probesTmpl.Execute(&b, probesPageData{ProbeHostNames: []string{"probe"}, Page: 1, TotalPages: 1}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"<code>claude.ai.|A</code>", "orf.at/A", `id="dnscheck_status"`, `class="lint-slot dim"`, "/probes/dns-checks/lint"} {
		if !strings.Contains(out, want) {
			t.Errorf("Behavior tab lacks %q", want)
		}
	}
	if strings.Contains(out, "claude.ai./A") {
		t.Error("the old slash example must be gone")
	}
}

func TestFormatDNSCheckLines_RoundTrip(t *testing.T) {
	in := []config.DNSCheck{{Name: "claude.ai.", Type: "A"}, {Name: "orf.at", Type: "MX"}}
	got, finds := parseDNSCheckInput(formatDNSCheckLines(in))
	if len(finds) != 0 || len(got) != 2 || got[0] != in[0] || got[1] != in[1] {
		t.Errorf("round trip = %+v %+v", got, finds)
	}
}

func TestDNSChecksLint_Endpoint(t *testing.T) {
	h := handleDNSChecksLint()
	post := func(text string) (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/probes/dns-checks/lint", strings.NewReader(url.Values{"text": {text}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec.Code, rec.Body.String()
	}
	if code, body := post("orf.at/A\nbad|ZZ"); code != 200 || !strings.Contains(body, `"count":1`) || !strings.Contains(body, `"line":2`) || !strings.Contains(body, `"level":"error"`) {
		t.Errorf("lint = %d %s", code, body)
	}
	if code, body := post(""); code != 200 || !strings.Contains(body, `"findings":[]`) {
		t.Errorf("blank must give an empty list, not null: %d %s", code, body)
	}
	if code, _ := post(strings.Repeat("a", maxDNSCheckInput+10)); code != http.StatusBadRequest {
		t.Errorf("an oversized body must be refused, got %d", code)
	}
}

func TestProbeChecksErrTmpl_KeepsTypedTextAndShowsEachReason(t *testing.T) {
	typed := "orf.at|AX\n<script>alert(1)</script>|A"
	_, finds := parseDNSCheckInput(typed)
	var b strings.Builder
	if err := probeChecksErrTmpl.Execute(&b, probeChecksErrData{Findings: finds, Text: typed, IntervalMS: "5000"}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"Nothing was saved.", "line 1: unknown type", "line 2: ", `name="probe_interval_ms" value="5000"`, "orf.at|AX", "#tab-behavior"} {
		if !strings.Contains(out, want) {
			t.Errorf("error page lacks %q", want)
		}
	}
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Error("typed text must be escaped on the error page")
	}
}

func TestParseDNSCheckInput_BoundedWork(t *testing.T) {
	_, finds := parseDNSCheckInput(strings.Repeat("x|ZZ\n", 3000))
	if len(finds) > maxDNSFindings+1 {
		t.Errorf("findings must be capped, got %d", len(finds))
	}
	if _, finds := parseDNSCheckInput(strings.Repeat("a", maxDNSCheckInput+1)); len(finds) != 1 || !strings.Contains(finds[0].Message, "longer than") {
		t.Errorf("an oversized input is refused before parsing, got %+v", finds)
	}
	if _, finds := parseDNSCheckInput(strings.Repeat("a\n", maxDNSCheckInput/2)); len(finds) > maxDNSFindings+1 {
		t.Errorf("duplicate warnings must be capped, got %d", len(finds))
	}
}

func BenchmarkParseDNSCheckInput(b *testing.B) {
	in := strings.Repeat("host-1.example.com|A\nbad name|A\norf.at/MX\n", 300)
	for b.Loop() {
		parseDNSCheckInput(in)
	}
}
