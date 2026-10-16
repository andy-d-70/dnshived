// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package daemonstatus

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestParseShow(t *testing.T) {
	out := "LoadState=loaded\nActiveState=active\nSubState=running\nActiveEnterTimestampMonotonic=12345678\n"
	props := parseShow(out)
	want := map[string]string{
		"LoadState":                     "loaded",
		"ActiveState":                   "active",
		"SubState":                      "running",
		"ActiveEnterTimestampMonotonic": "12345678",
	}
	for k, v := range want {
		if props[k] != v {
			t.Errorf("props[%q] = %q, want %q", k, props[k], v)
		}
	}
}

func TestParseShow_IgnoresMalformedLines(t *testing.T) {
	out := "LoadState=loaded\nnot a key value line\nSubState=running\n"
	props := parseShow(out)
	if len(props) != 2 {
		t.Errorf("len(props) = %d, want 2 (malformed line skipped)", len(props))
	}
}

func TestUptimeSeconds_ComputesElapsedSinceActivation(t *testing.T) {
	// Unit went active at 10s (monotonic), host has been up 130s ->
	// 120s of uptime for the unit.
	got := uptimeSeconds(10*1_000_000, 130)
	if got != 120 {
		t.Errorf("uptimeSeconds = %d, want 120", got)
	}
}

func TestUptimeSeconds_ZeroTimestampMeansNeverActivated(t *testing.T) {
	if got := uptimeSeconds(0, 130); got != 0 {
		t.Errorf("uptimeSeconds = %d, want 0 for a zero/never-active timestamp", got)
	}
}

func TestUptimeSeconds_NegativeTimestampMeansNeverActivated(t *testing.T) {
	if got := uptimeSeconds(-5, 130); got != 0 {
		t.Errorf("uptimeSeconds = %d, want 0 for a negative timestamp", got)
	}
}

func TestUptimeSeconds_ClampsNegativeElapsedToZero(t *testing.T) {
	// Shouldn't happen in practice (activation can't be after "now"),
	// but a clock/measurement wobble must never surface as negative.
	got := uptimeSeconds(200*1_000_000, 130)
	if got != 0 {
		t.Errorf("uptimeSeconds = %d, want 0 clamped, not negative", got)
	}
}

func TestParseVersionOutput_NameAndVersion(t *testing.T) {
	got := parseVersionOutput("dnshived 0.9.7-dev+a4134d0\n")
	if got != "0.9.7-dev+a4134d0" {
		t.Errorf("parseVersionOutput = %q, want %q", got, "0.9.7-dev+a4134d0")
	}
}

func TestParseVersionOutput_NoSpaceReturnsWholeLine(t *testing.T) {
	got := parseVersionOutput("justoneword\n")
	if got != "justoneword" {
		t.Errorf("parseVersionOutput = %q, want %q", got, "justoneword")
	}
}

func TestParseVersionOutput_FutureCleanReleaseTag(t *testing.T) {
	got := parseVersionOutput("dnshived 1.0.0")
	if got != "1.0.0" {
		t.Errorf("parseVersionOutput = %q, want %q", got, "1.0.0")
	}
}

func TestParseVersionOutput_MultiLineSystemPackageOutput(t *testing.T) {
	got := parseVersionOutput("Keepalived v2.3.3 (03/30,2025)\n\nCopyright(C) 2001-2025 Alexandre Cassen, <acassen@gmail.com>\n")
	if got != "v2.3.3 (03/30,2025)" {
		t.Errorf("parseVersionOutput = %q, want %q", got, "v2.3.3 (03/30,2025)")
	}
}

func TestParseVersionOutput_DnsmasqShapeStaysOnOneLine(t *testing.T) {
	got := parseVersionOutput("Dnsmasq version 2.91  Copyright (c) 2000-2025 Simon Kelley\nCompile time options: IPv6 GNU-getopt\n")
	if strings.Contains(got, "\n") {
		t.Errorf("parseVersionOutput = %q, must not include a second line", got)
	}
	if got != "version 2.91  Copyright (c) 2000-2025 Simon Kelley" {
		t.Errorf("parseVersionOutput = %q, want %q", got, "version 2.91  Copyright (c) 2000-2025 Simon Kelley")
	}
}

func TestQuery_UnknownUnitReportsNotFoundNotError(t *testing.T) {
	s := Query("totally-bogus-unit-for-testing.service", "")
	if s.Error != "" {
		t.Errorf("Error = %q, want empty for a merely-nonexistent unit", s.Error)
	}
	if s.LoadState != "not-found" {
		t.Errorf("LoadState = %q, want %q", s.LoadState, "not-found")
	}
	if s.ActiveState != "inactive" {
		t.Errorf("ActiveState = %q, want %q", s.ActiveState, "inactive")
	}
}

func TestQuery_DashPrefixedUnitTreatedAsLiteralNotFlag(t *testing.T) {
	s := Query("-Hnonexistent-host-for-testing", "")
	if s.Error != "" {
		t.Errorf("Error = %q, want empty — a dash-prefixed value must be treated as a literal (nonexistent) unit name", s.Error)
	}
	if s.LoadState != "not-found" {
		t.Errorf("LoadState = %q, want %q (confirms systemctl parsed it as a unit name, not a flag)", s.LoadState, "not-found")
	}
}

func TestQueryMany_MatchesQueryPerUnit(t *testing.T) {
	units := []string{"totally-bogus-unit-for-testing.service", "totally-bogus-unit-2-for-testing.service"}
	got := QueryMany(units)

	if len(got) != len(units) {
		t.Fatalf("QueryMany returned %d entries, want %d: %+v", len(got), len(units), got)
	}
	for _, u := range units {
		want := Query(u, "")
		s, ok := got[u]
		if !ok {
			t.Errorf("QueryMany result missing unit %q", u)
			continue
		}
		if s.Unit != want.Unit || s.LoadState != want.LoadState || s.ActiveState != want.ActiveState || s.SubState != want.SubState {
			t.Errorf("QueryMany(%q) = %+v, want %+v (matching Query's own result)", u, s, want)
		}
	}
}

func TestQueryActiveGlob_NoMatchesReturnsEmptyMap(t *testing.T) {
	got := QueryActiveGlob("totally-bogus-unit-glob-for-testing-*.service")
	if len(got) != 0 {
		t.Errorf("QueryActiveGlob(no-match) = %+v, want an empty map", got)
	}
}

// TestQueryActiveGlob_MatchesRealLoadedUnit confirms the glob path
// actually finds a real, currently-loaded unit and reports its true state.
func TestQueryActiveGlob_MatchesRealLoadedUnit(t *testing.T) {
	got := QueryActiveGlob("systemd-journal*.service")
	s, ok := got["systemd-journald.service"]
	if !ok {
		t.Fatalf("QueryActiveGlob(systemd-journal*.service) = %+v, want an entry for systemd-journald.service", got)
	}
	if s.ActiveState != "active" {
		t.Errorf("systemd-journald.service ActiveState = %q, want %q", s.ActiveState, "active")
	}
}

func TestQueryMany_EmptyInputReturnsEmptyMap(t *testing.T) {
	got := QueryMany(nil)
	if len(got) != 0 {
		t.Errorf("QueryMany(nil) = %+v, want an empty map", got)
	}
}

// TestQueryMany_DashPrefixedUnitTreatedAsLiteralNotFlag mirrors
// TestQuery_DashPrefixedUnitTreatedAsLiteralNotFlag for the batched path.
func TestQueryMany_DashPrefixedUnitTreatedAsLiteralNotFlag(t *testing.T) {
	got := QueryMany([]string{"-Hnonexistent-host-for-testing.service"})
	s, ok := got["-Hnonexistent-host-for-testing.service"]
	if !ok {
		t.Fatalf("QueryMany result missing the dash-prefixed unit: %+v", got)
	}
	if s.LoadState != "not-found" {
		t.Errorf("LoadState = %q, want %q (confirms systemctl parsed it as a unit name, not a flag)", s.LoadState, "not-found")
	}
}

func TestQuery_EmptyVersionBinLeavesVersionEmpty(t *testing.T) {
	s := Query("totally-bogus-unit-for-testing.service", "")
	if s.Version != "" {
		t.Errorf("Version = %q, want empty when versionBin is not given", s.Version)
	}
}

func TestQueryVersion_CapturesStderrToo(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-keepalived")
	script := "#!/bin/sh\necho 'Keepalived v2.2.7 (01/16,2022)' >&2\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	got := queryVersion(ctx, bin)
	if got != "v2.2.7 (01/16,2022)" {
		t.Errorf("queryVersion = %q, want %q", got, "v2.2.7 (01/16,2022)")
	}
}

func TestProcessIdentity_RealRunningProcessResolvesActualUser(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skipf("user.Current(): %v (no real user in this sandbox)", err)
	}
	pid, gotUser := processIdentity(strconv.Itoa(os.Getpid()))
	if pid != os.Getpid() {
		t.Errorf("pid = %d, want %d", pid, os.Getpid())
	}
	if gotUser != me.Username {
		t.Errorf("user = %q, want %q (this test process's own real user)", gotUser, me.Username)
	}
}

// TestProcessIdentity_InactiveUnitReturnsZeroPIDEmptyUser pins the "unit
// not running" case — systemctl reports MainPID=0 for an inactive unit.
func TestProcessIdentity_InactiveUnitReturnsZeroPIDEmptyUser(t *testing.T) {
	for _, in := range []string{"0", ""} {
		pid, gotUser := processIdentity(in)
		if pid != 0 || gotUser != "" {
			t.Errorf("processIdentity(%q) = (%d, %q), want (0, \"\")", in, pid, gotUser)
		}
	}
}

func TestProcessIdentity_VanishedProcessReturnsPIDWithEmptyUser(t *testing.T) {
	const fakePID = 999999999 // never a real PID on any real Linux system
	pid, gotUser := processIdentity(strconv.Itoa(fakePID))
	if pid != fakePID {
		t.Errorf("pid = %d, want %d (reported even though /proc read failed)", pid, fakePID)
	}
	if gotUser != "" {
		t.Errorf("user = %q, want empty for a vanished process", gotUser)
	}
}
