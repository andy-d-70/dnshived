// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"strconv"
	"strings"

	"dnshived/internal/config"
)

// formatDNSRecordLine encodes one config.DNSRecord as a single
// pipe-delimited line: TYPE|NAME|...type-specific fields...[|ttl=N]
// [|disabled].
func formatDNSRecordLine(r config.DNSRecord) string {
	var fields []string
	switch r.Type {
	case "MX":
		fields = []string{r.Type, r.Name, r.Target, strconv.Itoa(r.Priority)}
	case "SRV":
		fields = []string{r.Type, r.Name, r.Target, strconv.Itoa(r.Port), strconv.Itoa(r.Priority), strconv.Itoa(r.Weight)}
	case "NAPTR":
		fields = []string{r.Type, r.Name, r.Target, strconv.Itoa(r.NAPTROrder), strconv.Itoa(r.Priority), r.NAPTRFlags, r.NAPTRService, r.NAPTRRegexp}
	case "CAA":
		fields = []string{r.Type, r.Name, strconv.Itoa(r.CAAFlags), r.CAATag, r.Value}
	case "RAW":
		fields = []string{r.Type, r.Name, strconv.Itoa(r.RRType), r.RRDataHex}
	default: // A, AAAA, CNAME, TXT, PTR — all just Name+Value
		fields = []string{r.Type, r.Name, r.Value}
	}
	line := strings.Join(fields, "|")
	if r.TTL != 0 {
		line += "|ttl=" + strconv.Itoa(r.TTL)
	}
	if r.ProbeDisabled {
		line += "|disabled"
	}
	return line
}

// formatDNSRecordLines is formatDNSRecordLine applied to a whole list,
// newline-joined — a textarea's initial value.
func formatDNSRecordLines(records []config.DNSRecord) string {
	lines := make([]string, len(records))
	for i, r := range records {
		lines[i] = formatDNSRecordLine(r)
	}
	return strings.Join(lines, "\n")
}

// parseDNSRecordLine decodes one text-mode line back into a
// config.DNSRecord — see formatDNSRecordLine for the exact format.
func parseDNSRecordLine(line string) (config.DNSRecord, error) {
	parts := strings.Split(strings.TrimRight(line, "\r"), "|")
	disabled := false
	ttl := 0
	for len(parts) > 0 {
		last := strings.TrimSpace(parts[len(parts)-1])
		if strings.EqualFold(last, "disabled") {
			disabled = true
			parts = parts[:len(parts)-1]
			continue
		}
		if strings.HasPrefix(strings.ToLower(last), "ttl=") {
			n, err := strconv.Atoi(strings.TrimSpace(last[4:]))
			if err != nil {
				return config.DNSRecord{}, fmt.Errorf("%q: invalid %s (expected ttl=<seconds>)", line, last)
			}
			ttl = n
			parts = parts[:len(parts)-1]
			continue
		}
		break
	}
	if len(parts) < 3 {
		return config.DNSRecord{}, fmt.Errorf("%q: expected at least TYPE|NAME|... (got %d field(s))", line, len(parts))
	}
	typ := strings.ToUpper(strings.TrimSpace(parts[0]))
	name := strings.TrimSpace(parts[1])
	rest := parts[2:]
	r := config.DNSRecord{Type: typ, Name: name, ProbeDisabled: disabled, TTL: ttl}

	atoi := func(s string) int {
		n, _ := strconv.Atoi(strings.TrimSpace(s))
		return n
	}

	switch typ {
	case "A", "AAAA", "CNAME", "TXT", "PTR":
		r.Value = strings.Join(rest, "|")
	case "MX":
		if len(rest) != 2 {
			return config.DNSRecord{}, fmt.Errorf("%q: MX expects TYPE|NAME|TARGET|PRIORITY", line)
		}
		r.Target, r.Priority = strings.TrimSpace(rest[0]), atoi(rest[1])
	case "SRV":
		if len(rest) != 4 {
			return config.DNSRecord{}, fmt.Errorf("%q: SRV expects TYPE|NAME|TARGET|PORT|PRIORITY|WEIGHT", line)
		}
		r.Target, r.Port, r.Priority, r.Weight = strings.TrimSpace(rest[0]), atoi(rest[1]), atoi(rest[2]), atoi(rest[3])
	case "NAPTR":
		if len(rest) != 6 {
			return config.DNSRecord{}, fmt.Errorf("%q: NAPTR expects TYPE|NAME|TARGET|ORDER|PRIORITY|FLAGS|SERVICE|REGEXP", line)
		}
		r.Target, r.NAPTROrder, r.Priority = strings.TrimSpace(rest[0]), atoi(rest[1]), atoi(rest[2])
		r.NAPTRFlags, r.NAPTRService, r.NAPTRRegexp = strings.TrimSpace(rest[3]), strings.TrimSpace(rest[4]), strings.TrimSpace(rest[5])
	case "CAA":
		if len(rest) != 3 {
			return config.DNSRecord{}, fmt.Errorf("%q: CAA expects TYPE|NAME|FLAGS|TAG|VALUE", line)
		}
		r.CAAFlags, r.CAATag, r.Value = atoi(rest[0]), strings.TrimSpace(rest[1]), rest[2]
	case "RAW":
		if len(rest) != 2 {
			return config.DNSRecord{}, fmt.Errorf("%q: RAW expects TYPE|NAME|RR_TYPE|RR_DATA_HEX", line)
		}
		r.RRType, r.RRDataHex = atoi(rest[0]), strings.TrimSpace(rest[1])
	default:
		return config.DNSRecord{}, fmt.Errorf("%q: unknown record type %q", line, typ)
	}
	return r, nil
}

// parseDNSRecordLines parses a whole textarea's worth of lines, one record
// per non-blank line.
func parseDNSRecordLines(s string) ([]config.DNSRecord, error) {
	var records []config.DNSRecord
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		r, err := parseDNSRecordLine(line)
		if err != nil {
			return nil, err
		}
		records = append(records, r)
	}
	return records, nil
}
