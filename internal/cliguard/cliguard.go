// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package cliguard checks a binary's command line and the user it runs as.
package cliguard

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
)

// Role says who may run a binary.
type Role int

const (
	// Daemon runs as its service user and refuses root.
	Daemon Role = iota
	// RootHelper must run as root.
	RootHelper
	// RootTool may run as any user, root included.
	RootTool
	// UserTool must not run as root.
	UserTool
	// Exempt skips the user check (dnsmasq's lease hook).
	Exempt
)

// Parse parses flags for name. An unknown flag or a positional argument prints one line,
// a usage line and "run -h", and exits 2. -h prints the full flag list and exits 0.
func Parse(name string, positional bool) {
	usage := shortUsage(name)
	err := parseArgs(flag.CommandLine, os.Args[1:], positional)
	if errors.Is(err, flag.ErrHelp) {
		usage()
		os.Exit(0)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
		usage()
		os.Exit(2)
	}
}

// parseArgs parses args into fs without exiting. With positional false, a leftover argument is an error.
func parseArgs(fs *flag.FlagSet, args []string, positional bool) error {
	fs.Init(fs.Name(), flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !positional && fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return nil
}

func shortUsage(name string) func() {
	return func() {
		fmt.Fprintf(os.Stderr, "usage: %s [flags]\nrun '%s -h' for the list of flags\n", name, name)
		if wantsHelp(os.Args[1:]) {
			flag.CommandLine.SetOutput(os.Stderr)
			flag.PrintDefaults()
		}
	}
}

func wantsHelp(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == "-h" || a == "-help" || a == "--h" || a == "--help" {
			return true
		}
	}
	return false
}

// CheckUser exits 1 with one line when the invoking user does not match role.
func CheckUser(name string, role Role, service string) {
	if err := checkUser(role, service, os.Geteuid()); err != nil {
		Exit(name, err)
	}
}

// Exit prints name and err on one line to stderr and exits 1.
func Exit(name string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
	os.Exit(1)
}

func checkUser(role Role, service string, uid int) error {
	switch role {
	case Daemon:
		u, err := user.Lookup(service)
		if err != nil {
			return fmt.Errorf("service user %q not found: %w", service, err)
		}
		if uid == 0 {
			return fmt.Errorf("refuses to run as root; run as %s", service)
		}
		want, _ := strconv.Atoi(u.Uid)
		if uid != want {
			return fmt.Errorf("must run as %s (uid %d), not uid %d", service, want, uid)
		}
	case RootHelper:
		if uid != 0 {
			return fmt.Errorf("must run as root, not uid %d", uid)
		}
	case UserTool:
		if uid == 0 {
			return errors.New("must not run as root")
		}
	}
	return nil
}
