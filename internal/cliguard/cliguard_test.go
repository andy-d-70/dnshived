// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package cliguard

import (
	"flag"
	"os/user"
	"strconv"
	"strings"
	"testing"
)

func testFlags() *flag.FlagSet {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.Bool("v", false, "")
	return fs
}

func TestParseArgs_RejectsUnknownAndPositional(t *testing.T) {
	if err := parseArgs(testFlags(), []string{"-x"}, false); err == nil {
		t.Fatal("unknown flag accepted")
	}
	if err := parseArgs(testFlags(), []string{"stray"}, false); err == nil {
		t.Fatal("positional argument accepted")
	}
	if err := parseArgs(testFlags(), []string{"stray"}, true); err != nil {
		t.Fatalf("positional allowed but rejected: %v", err)
	}
	if err := parseArgs(testFlags(), []string{"-v"}, false); err != nil {
		t.Fatalf("valid flag rejected: %v", err)
	}
}

func TestCheckUser_RoleRules(t *testing.T) {
	nobody, err := user.Lookup("nobody")
	if err != nil {
		t.Skip("no nobody account on this host")
	}
	nobodyUID, _ := strconv.Atoi(nobody.Uid)

	cases := []struct {
		name    string
		role    Role
		service string
		uid     int
		wantErr bool
	}{
		{"daemon as its user", Daemon, "nobody", nobodyUID, false},
		{"daemon as root", Daemon, "nobody", 0, true},
		{"daemon as another user", Daemon, "nobody", nobodyUID + 1, true},
		{"daemon, missing account", Daemon, "no-such-dnshived-user", 1000, true},
		{"root helper as root", RootHelper, "", 0, false},
		{"root helper as user", RootHelper, "", 1000, true},
		{"user tool as user", UserTool, "", 1000, false},
		{"user tool as root", UserTool, "", 0, true},
		{"root tool as root", RootTool, "", 0, false},
		{"root tool as user", RootTool, "", 1000, false},
		{"exempt as root", Exempt, "", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkUser(tc.role, tc.service, tc.uid)
			if (err != nil) != tc.wantErr {
				t.Fatalf("checkUser = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestParseArgs_ReportsUnknownFlagWithoutExiting(t *testing.T) {
	err := parseArgs(testFlags(), []string{"-nope"}, false)
	if err == nil || !strings.Contains(err.Error(), "-nope") {
		t.Fatalf("parseArgs = %v, want an error naming -nope", err)
	}
}
