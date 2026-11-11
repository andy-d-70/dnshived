// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package nstest gives tests and benchmarks a private network namespace with
// many dummy interfaces, so code that walks interfaces can be measured at the
// size of a real cluster. It needs root and the ip tool and skips otherwise.
package nstest

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// WithDummyInterfaces moves the calling goroutine's thread into a new network
// namespace holding n dummy interfaces d000, d001, ... that each carry
// 10.<100+i/250>.<i%250>.1/24 and are up. The thread is never unlocked: it
// ends with the goroutine and takes the namespace with it, so call this from
// the test or sub-benchmark that uses the interfaces, not from its parent.
func WithDummyInterfaces(tb testing.TB, n int) {
	tb.Helper()
	if os.Geteuid() != 0 {
		tb.Skip("needs root for a private network namespace")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		tb.Skip("needs the ip tool")
	}
	runtime.LockOSThread()
	if err := syscall.Unshare(syscall.CLONE_NEWNET); err != nil {
		tb.Skipf("cannot create a network namespace: %v", err)
	}
	var script strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&script, "link add d%03d type dummy\naddr add %s/24 dev d%03d\nlink set d%03d up\n", i, Addr(i), i, i)
	}
	cmd := exec.Command("ip", "-batch", "-")
	cmd.Stdin = strings.NewReader(script.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		tb.Skipf("cannot create dummy interfaces: %v %s", err, out)
	}
}

// Name is the name of dummy interface i.
func Name(i int) string { return fmt.Sprintf("d%03d", i) }

// Addr is the address (without prefix length) dummy interface i carries.
func Addr(i int) string { return fmt.Sprintf("10.%d.%d.1", 100+i/250, i%250) }
