// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"net/http"
	"strings"

	"dnshived/internal/config"
)

const (
	maxDNSChecks      = 100
	maxDNSCheckLabel  = 63
	maxDNSCheckName   = 253
	maxDNSCheckInput  = 16 << 10
	maxDNSFindings    = 50
	probeCheckTypeSet = "A, AAAA, CNAME, PTR, TXT, MX, SRV, NAPTR, CAA"
)

// probeCheckTypes are the names internal/dnsprobe can query. config also
// accepts RAW, which the probe cannot query by name.
var probeCheckTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "PTR": true, "TXT": true,
	"MX": true, "SRV": true, "NAPTR": true, "CAA": true,
}

type dnsCheckFinding struct {
	Line    int    `json:"line"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

// parseDNSCheckInput reads the DNS checks box. A line is NAME|TYPE, NAME/TYPE
// or NAME TYPE; a bare name means A. Errors block a save, warnings do not.
func parseDNSCheckInput(s string) ([]config.DNSCheck, []dnsCheckFinding) {
	if len(s) > maxDNSCheckInput {
		return nil, []dnsCheckFinding{{Level: "error", Message: fmt.Sprintf("the input is longer than %d KiB", maxDNSCheckInput>>10)}}
	}
	var checks []config.DNSCheck
	finds := []dnsCheckFinding{}
	seen := map[string]int{}
	for i, raw := range strings.Split(s, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		n := i + 1
		name, typ, msg := splitDNSCheckLine(line)
		if msg == "" {
			msg = dnsCheckNameProblem(name)
		}
		if msg == "" {
			msg = dnsCheckTypeProblem(typ)
		}
		if msg != "" {
			if len(finds) < maxDNSFindings {
				finds = append(finds, dnsCheckFinding{Line: n, Level: "error", Message: msg})
			} else if len(finds) == maxDNSFindings {
				finds = append(finds, dnsCheckFinding{Level: "error", Message: "more problems follow, fix these first"})
			}
			continue
		}
		key := strings.ToLower(strings.TrimSuffix(name, ".")) + "|" + typ
		if first, dup := seen[key]; dup {
			if len(finds) < maxDNSFindings {
				finds = append(finds, dnsCheckFinding{Line: n, Level: "warn", Message: fmt.Sprintf("repeats line %d, ignored", first)})
			}
			continue
		}
		seen[key] = n
		checks = append(checks, config.DNSCheck{Name: name, Type: typ})
	}
	if len(checks) > maxDNSChecks {
		finds = append(finds, dnsCheckFinding{Level: "error", Message: fmt.Sprintf("%d checks, at most %d are allowed", len(checks), maxDNSChecks)})
	}
	return checks, finds
}

func splitDNSCheckLine(line string) (name, typ, problem string) {
	switch {
	case strings.Contains(line, "|"):
		name, typ, _ = strings.Cut(line, "|")
	case strings.Contains(line, "/"):
		i := strings.LastIndex(line, "/")
		name, typ = line[:i], line[i+1:]
	default:
		f := strings.Fields(line)
		switch len(f) {
		case 1:
			return f[0], "A", ""
		case 2:
			name, typ = f[0], f[1]
		default:
			return "", "", "too many parts, expected a name and a type, for example orf.at|A"
		}
	}
	name, typ = strings.TrimSpace(name), strings.ToUpper(strings.TrimSpace(typ))
	if typ == "" {
		return "", "", "the type is missing after the separator, for example orf.at|A"
	}
	return name, typ, ""
}

func dnsCheckNameProblem(name string) string {
	n := strings.TrimSuffix(name, ".")
	if n == "" {
		return "the name is empty"
	}
	if len(n) > maxDNSCheckName {
		return fmt.Sprintf("the name is longer than %d characters", maxDNSCheckName)
	}
	for _, r := range n {
		switch {
		case r > 127:
			return "write international names in punycode (xn--…), this form does not convert them"
		case r == '.', r == '-', r == '_', r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case r == ' ':
			return "the name contains a space"
		default:
			return fmt.Sprintf("the character %q is not allowed in a name", r)
		}
	}
	for _, label := range strings.Split(n, ".") {
		switch {
		case label == "":
			return "empty label (a leading dot or two dots in a row)"
		case len(label) > maxDNSCheckLabel:
			return fmt.Sprintf("a label is longer than %d characters", maxDNSCheckLabel)
		case label[0] == '-' || label[len(label)-1] == '-':
			return "a label must not start or end with a hyphen"
		}
	}
	return ""
}

func dnsCheckTypeProblem(typ string) string {
	switch {
	case probeCheckTypes[typ]:
		return ""
	case typ == "RAW":
		return "RAW is for records, not for checks; use one of " + probeCheckTypeSet
	}
	return fmt.Sprintf("unknown type %q, use one of %s", typ, probeCheckTypeSet)
}

// handleDNSChecksLint (POST /probes/dns-checks/lint) judges the box for the
// live status line under it; the save path runs the same parser.
func handleDNSChecksLint() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxDNSCheckInput)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		checks, finds := parseDNSCheckInput(r.PostForm.Get("text"))
		writeJSONWeb(w, http.StatusOK, map[string]any{"count": len(checks), "findings": finds})
	}
}
