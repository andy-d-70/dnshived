// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

// This module is standalone, so it carries its own copy of the command-line, user and
// single-instance checks from internal/cliguard and internal/instlock.

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

func guardParse(name string) {
	usage := func() {
		fmt.Fprintf(os.Stderr, "usage: %s [flags]\nrun '%s -h' for the list of flags\n", name, name)
		if guardWantsHelp(os.Args[1:]) {
			flag.CommandLine.SetOutput(os.Stderr)
			flag.PrintDefaults()
		}
	}
	flag.CommandLine.Init(name, flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	flag.CommandLine.Usage = func() {}
	err := flag.CommandLine.Parse(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		usage()
		os.Exit(0)
	}
	if err == nil && flag.NArg() > 0 {
		err = fmt.Errorf("unexpected argument %q", flag.Arg(0))
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
		usage()
		os.Exit(2)
	}
}

func guardWantsHelp(args []string) bool {
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

func guardExit(name string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
	os.Exit(1)
}

func guardCheckDaemonUser(service string) {
	u, err := user.Lookup(service)
	if err != nil {
		guardExit("dnshived-dnsrelay", fmt.Errorf("service user %q not found: %w", service, err))
	}
	uid := os.Geteuid()
	if uid == 0 {
		guardExit("dnshived-dnsrelay", fmt.Errorf("refuses to run as root; run as %s", service))
	}
	if want, _ := strconv.Atoi(u.Uid); uid != want {
		guardExit("dnshived-dnsrelay", fmt.Errorf("must run as %s (uid %d), not uid %d", service, want, uid))
	}
}

// guardHeld keeps the lock file open for the life of the process.
var guardHeld *os.File

func guardHold(path string) {
	if err := os.MkdirAll(dirOf(path), 0o755); err != nil {
		guardExit("dnshived-dnsrelay", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		guardExit("dnshived-dnsrelay", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		holder, _ := os.ReadFile(path)
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			guardExit("dnshived-dnsrelay", fmt.Errorf("already running (pid %s, lock %s)", strings.TrimSpace(string(holder)), path))
		}
		guardExit("dnshived-dnsrelay", err)
	}
	if err := f.Truncate(0); err != nil {
		guardExit("dnshived-dnsrelay", err)
	}
	if _, err := f.WriteString(strconv.Itoa(os.Getpid()) + "\n"); err != nil {
		guardExit("dnshived-dnsrelay", err)
	}
	guardHeld = f
}

func dirOf(path string) string {
	if i := strings.LastIndex(path, "/"); i > 0 {
		return path[:i]
	}
	return "."
}
