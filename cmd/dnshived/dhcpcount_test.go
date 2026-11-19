// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dnshived/internal/config"
)

func TestDHCPClientCounts(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	path := filepath.Join(t.TempDir(), "leases")
	body := fmt.Sprintf("%d aa:bb:cc:00:00:01 10.0.1.50 a *\n%d aa:bb:cc:00:00:02 10.0.1.51 b *\n0 aa:bb:cc:00:00:03 10.0.1.52 c *\n%d aa:bb:cc:00:00:04 10.0.2.50 d *\n",
		now.Add(time.Hour).Unix(), now.Add(-time.Hour).Unix(), now.Add(time.Hour).Unix())
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Cluster{Scopes: map[string]config.ScopeConfig{
		"a": {DHCPRange: [2]string{"10.0.1.10", "10.0.1.99"}, Reservations: []config.Reservation{{MAC: "aa:bb:cc:00:00:09", IP: "10.0.1.5"}}},
		"b": {DHCPRange: [2]string{"10.0.2.10", "10.0.2.99"}, Reservations: []config.Reservation{{MAC: "aa:bb:cc:00:00:08", IP: "10.0.2.5"}, {MAC: "aa:bb:cc:00:00:07", IP: "10.0.2.6"}}},
	}}
	active, reserved := dhcpClientCounts(cfg, []string{"a"}, path, now)
	if active != 2 || reserved != 3 {
		t.Errorf("a node that serves scope a counts its live and never-expiring leases only: active %d reserved %d", active, reserved)
	}
	if active, _ := dhcpClientCounts(cfg, []string{"a", "b"}, path, now); active != 3 {
		t.Errorf("serving both scopes: %d", active)
	}
	if active, reserved := dhcpClientCounts(cfg, nil, path, now); active != 0 || reserved != 3 {
		t.Errorf("serving nothing: %d %d", active, reserved)
	}
	if err := os.WriteFile(path, []byte(fmt.Sprintf("%d aa:bb:cc:00:00:01 10.0.1.50 a *\n", now.Add(time.Hour).Unix())), 0o644); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(2 * time.Second)
	os.Chtimes(path, later, later)
	if active, _ := dhcpClientCounts(cfg, []string{"a"}, path, now); active != 1 {
		t.Errorf("a changed file is read again: %d", active)
	}
	if active, _ := dhcpClientCounts(cfg, []string{"a"}, filepath.Join(t.TempDir(), "missing"), now); active != 0 {
		t.Errorf("a missing file counts zero: %d", active)
	}
}
