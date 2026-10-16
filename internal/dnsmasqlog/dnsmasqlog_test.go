// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsmasqlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClassify_RoutineDHCPTransactionsAreNotNoteworthy(t *testing.T) {
	routine := []string{
		"Aug  9 18:30:01 dnsmasq-dhcp[1234]: DHCPDISCOVER(ens19.100) 00:11:22:33:44:55",
		"Aug  9 18:30:01 dnsmasq-dhcp[1234]: DHCPOFFER(ens19.100) 172.16.100.150 00:11:22:33:44:55",
		"Aug  9 18:30:01 dnsmasq-dhcp[1234]: DHCPREQUEST(ens19.100) 172.16.100.150 00:11:22:33:44:55",
		"Aug  9 18:30:01 dnsmasq-dhcp[1234]: DHCPACK(ens19.100) 172.16.100.150 00:11:22:33:44:55 myhost",
		"Aug  9 18:30:01 dnsmasq[1234]: reading /etc/resolv.conf",
	}
	for _, line := range routine {
		if _, ok := Classify(line); ok {
			t.Errorf("Classify(%q) = noteworthy, want routine (skipped)", line)
		}
	}
}

func TestClassify_DHCPNAKIsNoteworthy(t *testing.T) {
	line := "Aug  9 18:30:01 dnsmasq-dhcp[1234]: DHCPNAK(ens19.100) 172.16.100.150 00:11:22:33:44:55 wrong network"
	level, ok := Classify(line)
	if !ok || level != "WARNING" {
		t.Errorf("Classify(DHCPNAK line) = (%q, %v), want (WARNING, true)", level, ok)
	}
}

func TestClassify_AddressConflictIsNoteworthy(t *testing.T) {
	line := "Aug  9 18:30:01 dnsmasq-dhcp[1234]: not using configured address 172.16.100.150 (in use by 172.16.100.99)"
	level, ok := Classify(line)
	if !ok || level != "WARNING" {
		t.Errorf("Classify(conflict line) = (%q, %v), want (WARNING, true)", level, ok)
	}
}

func TestClassify_DNSRebindWarningIsNoteworthy(t *testing.T) {
	line := "Aug  9 18:30:01 dnsmasq[1234]: possible DNS-rebind attack detected: evil.example.com"
	level, ok := Classify(line)
	if !ok || level != "WARNING" {
		t.Errorf("Classify(rebind line) = (%q, %v), want (WARNING, true)", level, ok)
	}
}

func TestClassify_StartupErrorsAreNoteworthy(t *testing.T) {
	errors := []string{
		"Aug  9 18:30:01 dnsmasq[1234]: failed to create listening socket for port 53: Address already in use",
		"Aug  9 18:30:01 dnsmasq[1234]: bad address at line 5 of /etc/dnshived/reservations-rw-100.conf",
	}
	for _, line := range errors {
		level, ok := Classify(line)
		if !ok || level != "ERROR" {
			t.Errorf("Classify(%q) = (%q, %v), want (ERROR, true)", line, level, ok)
		}
	}
}

func TestTailer_FirstCallEstablishesOffsetWithoutReplayingHistory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsmasq-rw-100.log")
	preExisting := "Aug  9 10:00:00 dnsmasq-dhcp[1]: DHCPNAK(ens19.100) 172.16.100.5 aa:bb wrong network\n"
	if err := os.WriteFile(path, []byte(preExisting), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	tailer := New()
	findings := tailer.CheckScope(path, "rw-100")
	if len(findings) != 0 {
		t.Errorf("first call found %d findings, want 0 — pre-existing content must not be replayed as new", len(findings))
	}
}

func TestTailer_SecondCallFindsNewNoteworthyLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsmasq-rw-100.log")
	if err := os.WriteFile(path, []byte("Aug  9 10:00:00 dnsmasq-dhcp[1]: DHCPDISCOVER(ens19.100) aa:bb\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	tailer := New()
	tailer.CheckScope(path, "rw-100") // establishes baseline offset

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	f.WriteString("Aug  9 10:00:05 dnsmasq-dhcp[1]: DHCPDISCOVER(ens19.100) cc:dd\n")
	f.WriteString("Aug  9 10:00:06 dnsmasq-dhcp[1]: DHCPNAK(ens19.100) 172.16.100.5 cc:dd wrong network\n")
	f.Close()

	findings := tailer.CheckScope(path, "rw-100")
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want exactly 1 (the DHCPNAK line, not the routine DHCPDISCOVER)", len(findings))
	}
	if findings[0].Level != "WARNING" || !strings.Contains(findings[0].Line, "DHCPNAK") {
		t.Errorf("findings[0] = %+v, want a WARNING DHCPNAK finding", findings[0])
	}
}

func TestTailer_NoNewDataReturnsNoFindings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsmasq-rw-100.log")
	os.WriteFile(path, []byte("Aug  9 10:00:00 dnsmasq-dhcp[1]: DHCPDISCOVER(ens19.100) aa:bb\n"), 0o644)

	tailer := New()
	tailer.CheckScope(path, "rw-100")

	if findings := tailer.CheckScope(path, "rw-100"); findings != nil {
		t.Errorf("findings = %v, want nil when nothing new was appended", findings)
	}
}

func TestTailer_MissingFileIsNotAnError(t *testing.T) {
	tailer := New()
	findings := tailer.CheckScope("/nonexistent/path/dnsmasq-rw-100.log", "rw-100")
	if findings != nil {
		t.Errorf("findings = %v, want nil for a missing file (arbiter/not-yet-constructed)", findings)
	}
}

func TestTailer_RotationResetsToBeginningOfNewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsmasq-rw-100.log")
	longContent := strings.Repeat("Aug  9 10:00:00 dnsmasq-dhcp[1]: DHCPDISCOVER(ens19.100) aa:bb\n", 50)
	os.WriteFile(path, []byte(longContent), 0o644)

	tailer := New()
	tailer.CheckScope(path, "rw-100") // baseline offset = len(longContent)

	// Simulate rotation: a new, much shorter file replaces the old one.
	rotated := "Aug  9 11:00:00 dnsmasq-dhcp[1]: DHCPNAK(ens19.100) 172.16.100.5 aa:bb wrong network\n"
	os.WriteFile(path, []byte(rotated), 0o644)

	findings := tailer.CheckScope(path, "rw-100")
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 after rotation (read from the new file's own beginning)", len(findings))
	}
}

func TestTailLines_ReturnsLastNInOriginalOrder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsmasq-rw-100.log")
	content := "line1\nline2\nline3\nline4\nline5\n"
	os.WriteFile(path, []byte(content), 0o644)

	lines, err := TailLines(path, 3)
	if err != nil {
		t.Fatalf("TailLines: %v", err)
	}
	want := []string{"line3", "line4", "line5"}
	if len(lines) != len(want) {
		t.Fatalf("lines = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("lines[%d] = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestTailLines_FewerLinesThanRequestedReturnsAll(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsmasq-rw-100.log")
	os.WriteFile(path, []byte("only\ntwo\n"), 0o644)

	lines, err := TailLines(path, 20)
	if err != nil {
		t.Fatalf("TailLines: %v", err)
	}
	if len(lines) != 2 || lines[0] != "only" || lines[1] != "two" {
		t.Errorf("lines = %v, want [only two]", lines)
	}
}

func TestTailLines_MissingFileReturnsNilNoError(t *testing.T) {
	lines, err := TailLines("/nonexistent/dnsmasq-rw-100.log", 20)
	if err != nil {
		t.Errorf("err = %v, want nil for a missing file", err)
	}
	if lines != nil {
		t.Errorf("lines = %v, want nil", lines)
	}
}

func TestTailLines_EmptyFileReturnsNil(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsmasq-rw-100.log")
	os.WriteFile(path, []byte(""), 0o644)

	lines, err := TailLines(path, 20)
	if err != nil {
		t.Fatalf("TailLines: %v", err)
	}
	if lines != nil {
		t.Errorf("lines = %v, want nil for an empty file", lines)
	}
}
