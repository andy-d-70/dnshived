// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"os"
	"sync"
	"time"

	"dnshived/internal/config"
	"dnshived/internal/dhcplease"
)

var leaseCountCache struct {
	mu     sync.Mutex
	path   string
	mod    time.Time
	size   int64
	leases []dhcplease.Lease
}

// cachedLeases parses the lease file again only when it changed.
func cachedLeases(path string) []dhcplease.Lease {
	st, err := os.Stat(path)
	if err != nil {
		return nil
	}
	c := &leaseCountCache
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.path == path && c.mod.Equal(st.ModTime()) && c.size == st.Size() {
		return c.leases
	}
	leases, err := dhcplease.ParseFile(path)
	if err != nil {
		return nil
	}
	c.path, c.mod, c.size, c.leases = path, st.ModTime(), st.Size(), leases
	return leases
}

// dhcpClientCounts returns the active leases whose address lies in a scope
// this node serves, and the number of reservations the configuration holds.
func dhcpClientCounts(cfg *config.Cluster, serving []string, leasePath string, now time.Time) (active, reserved int) {
	for _, sc := range cfg.Scopes {
		reserved += len(sc.Reservations)
	}
	var ranges [][2]string
	for _, name := range serving {
		if sc, ok := cfg.Scopes[name]; ok && sc.DHCPRange[0] != "" && sc.DHCPRange[1] != "" {
			ranges = append(ranges, sc.DHCPRange)
		}
	}
	if len(ranges) == 0 {
		return 0, reserved
	}
	for _, l := range cachedLeases(leasePath) {
		if !l.NeverExpires && !l.Expiry.After(now) {
			continue
		}
		for _, r := range ranges {
			if dhcplease.InRange(l.IP, r[0], r[1]) {
				active++
				break
			}
		}
	}
	return active, reserved
}
