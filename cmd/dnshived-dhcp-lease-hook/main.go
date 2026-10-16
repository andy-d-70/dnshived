// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"os"
	"strconv"

	"dnshived/internal/leasesync"
)

var version = "0.9.8-dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println("dnshived-dhcp-lease-hook", version)
		os.Exit(0)
	}

	if len(os.Args) < 4 {
		os.Exit(0)
	}
	action := os.Args[1]
	if action != "add" && action != "old" && action != "del" {
		os.Exit(0)
	}

	expiresAt, _ := strconv.ParseInt(os.Getenv("DNSMASQ_LEASE_EXPIRES"), 10, 64)

	// Hostname is the optional 4th positional arg — absent when the client
	// sent none.
	var hostname string
	if len(os.Args) >= 5 && os.Args[4] != "*" {
		hostname = os.Args[4]
	}

	ev := leasesync.LocalEvent{
		Action:    action,
		MAC:       os.Args[2],
		IP:        os.Args[3],
		ExpiresAt: expiresAt,
		Hostname:  hostname,
	}
	_ = leasesync.WriteLocalEvent(leasesync.SocketPath, ev)
}
