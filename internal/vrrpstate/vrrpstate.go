// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package vrrpstate

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// DataFile is keepalived's hardcoded SIGDATA dump path — not
// configurable in this build (no --data-dump-file equivalent found).
const DataFile = "/tmp/keepalived.data"

// waitForDump is how long to wait for the dump file to reappear after
// signaling, polling at a short interval.
const waitForDump = 5 * time.Second

var (
	sigOnce sync.Once
	sigNum  syscall.Signal
	sigErr  error
)

// dataSignal returns keepalived's SIGDATA signal number, queried once via
// `keepalived --signum=DATA` and cached.
func dataSignal() (syscall.Signal, error) {
	sigOnce.Do(func() {
		out, err := exec.Command("keepalived", "--signum=DATA").Output()
		if err != nil {
			sigErr = fmt.Errorf("query --signum=DATA: %w", err)
			return
		}
		n, err := strconv.Atoi(strings.TrimSpace(string(out)))
		if err != nil {
			sigErr = fmt.Errorf("parse signum: %w", err)
			return
		}
		sigNum = syscall.Signal(n)
	})
	return sigNum, sigErr
}

func InstanceState(pidFile, instanceName string) (string, error) {
	data, err := Dump(pidFile)
	if err != nil {
		return "", err
	}
	return ParseInstanceState(data, instanceName)
}

// Dump triggers a fresh SIGDATA dump from the consolidated keepalived
// process identified by pidFile and returns the raw dump bytes, with no
// per-instance parsing.
func Dump(pidFile string) ([]byte, error) {
	pidData, err := os.ReadFile(pidFile)
	if err != nil {
		return nil, fmt.Errorf("read pid file: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
	if err != nil {
		return nil, fmt.Errorf("parse pid: %w", err)
	}

	sig, err := dataSignal()
	if err != nil {
		return nil, err
	}

	if err := verifyProcessIsKeepalived(pid); err != nil {
		return nil, err
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil, fmt.Errorf("find process %d: %w", pid, err)
	}

	// Remove any previous dump before signaling, then wait for it to reappear.
	os.Remove(DataFile)

	if err := proc.Signal(sig); err != nil {
		return nil, fmt.Errorf("signal pid %d: %w", pid, err)
	}

	deadline := time.Now().Add(waitForDump)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(DataFile)
		if err != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		// keepalived's write may not be atomic — a read landing mid-write can
		// look truncated.
		if bytes.Contains(data, []byte("VRRP Instance = ")) {
			return data, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil, fmt.Errorf("dump file %s did not reappear within %s", DataFile, waitForDump)
}

func verifyProcessIsKeepalived(pid int) error {
	comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return fmt.Errorf("verify pid %d: %w", pid, err)
	}
	name := strings.TrimSpace(string(comm))
	if name != "keepalived" {
		return fmt.Errorf("pid %d is %q, not keepalived — pid file stale or reused, refusing to signal", pid, name)
	}
	return nil
}

// ParseInstanceState extracts one vrrp_instance's State from a raw dump
// previously obtained via Dump.
func ParseInstanceState(data []byte, instanceName string) (string, error) {
	pattern := `(?m)^\s*VRRP Instance = ` + regexp.QuoteMeta(instanceName) + `\s*$\n(?:.*\n)*?\s*State = (\S+)`
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("build pattern: %w", err)
	}
	m := re.FindSubmatch(data)
	if m == nil {
		return "", fmt.Errorf("instance %q not found in dump", instanceName)
	}
	return string(m[1]), nil
}
