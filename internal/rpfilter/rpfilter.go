// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package rpfilter turns off reverse-path filtering on an address-less
// trunk parent.
package rpfilter

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// procRoot is overridden in tests.
var procRoot = "/proc/sys/net/ipv4/conf"

// interfaceExists is overridden in tests.
var interfaceExists = func(name string) error {
	_, err := net.InterfaceByName(name)
	return err
}

// DisableOnTrunk sets rp_filter=0 on parent.
func DisableOnTrunk(parent string) error {
	if parent == "" || parent == "." || parent == ".." || strings.Contains(parent, "/") {
		return fmt.Errorf("rp_filter: refusing invalid interface name %q", parent)
	}
	if err := interfaceExists(parent); err != nil {
		return fmt.Errorf("rp_filter: %s: %w", parent, err)
	}
	if err := os.WriteFile(filepath.Join(procRoot, parent, "rp_filter"), []byte("0"), 0o644); err != nil {
		return fmt.Errorf("rp_filter: set 0 on %s: %w", parent, err)
	}
	if all, err := os.ReadFile(filepath.Join(procRoot, "all", "rp_filter")); err == nil {
		if v := strings.TrimSpace(string(all)); v != "0" {
			return fmt.Errorf("rp_filter: net.ipv4.conf.all.rp_filter=%s overrides %s's 0 — trunk beacons from peers will be dropped until it is 0", v, parent)
		}
	}
	return nil
}

// Value returns iface's current rp_filter setting, or "unknown".
func Value(iface string) string {
	if iface == "" || iface == "." || iface == ".." || strings.Contains(iface, "/") {
		return "unknown"
	}
	b, err := os.ReadFile(filepath.Join(procRoot, iface, "rp_filter"))
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(b))
}
