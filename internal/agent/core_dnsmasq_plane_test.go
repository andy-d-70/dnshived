// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"os"
	"path/filepath"
	"testing"

	"dnshived/internal/config"
	"dnshived/internal/dhcpcentralrender"
	"dnshived/internal/dnscentralrender"
)

func TestConstructCoreDNSPlane_ArbiterRoleAttemptsRealConstructionToo(t *testing.T) {
	worker := New(config.RoleCore1, "test-worker-a", 1, "psk", "/tmp", testScopes("office"), nil)
	arb := New(config.RoleCore3, "test-arbiter", 1, "psk", "/tmp", testScopes("office"), nil)

	if got, want := arb.constructCoreDNSPlane(), worker.constructCoreDNSPlane(); got != want {
		t.Errorf("constructCoreDNSPlane(): arbiter = %v, worker = %v — every core role must behave identically now", got, want)
	}
}

func TestConstructCoreDHCPPlane_ArbiterRoleAttemptsRealConstructionToo(t *testing.T) {
	worker := New(config.RoleCore1, "test-worker-a", 1, "psk", "/tmp", testScopes("office"), nil)
	arb := New(config.RoleCore3, "test-arbiter", 1, "psk", "/tmp", testScopes("office"), nil)

	if got, want := arb.constructCoreDHCPPlane(), worker.constructCoreDHCPPlane(); got != want {
		t.Errorf("constructCoreDHCPPlane(): arbiter = %v, worker = %v — every core role must behave identically now", got, want)
	}
}

func TestRotateCoreDHCPLogIfNeeded(t *testing.T) {
	writeLog := func(t *testing.T, dir string, size int) string {
		t.Helper()
		path := filepath.Join(dir, dhcpcentralrender.CoreDHCPLogFileName)
		if err := os.WriteFile(path, make([]byte, size), 0640); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		return path
	}

	t.Run("no file is a no-op, not an error", func(t *testing.T) {
		a := &Agent{dataDir: t.TempDir(), role: config.RoleCore1}
		if err := a.RotateCoreDHCPLogIfNeeded(); err != nil {
			t.Errorf("RotateCoreDHCPLogIfNeeded() with no file = %v, want nil", err)
		}
	})

	t.Run("below threshold stays untouched", func(t *testing.T) {
		dir := t.TempDir()
		path := writeLog(t, dir, 1024)
		a := &Agent{dataDir: dir, role: config.RoleCore1}
		if err := a.RotateCoreDHCPLogIfNeeded(); err != nil {
			t.Fatalf("RotateCoreDHCPLogIfNeeded() = %v", err)
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}
		if fi.Size() != 1024 {
			t.Errorf("size = %d, want unchanged 1024", fi.Size())
		}
	})

	t.Run("above threshold gets truncated", func(t *testing.T) {
		dir := t.TempDir()
		path := writeLog(t, dir, coreDHCPLogRotateThreshold+1)
		a := &Agent{dataDir: dir, role: config.RoleCore2}
		if err := a.RotateCoreDHCPLogIfNeeded(); err != nil {
			t.Fatalf("RotateCoreDHCPLogIfNeeded() = %v", err)
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}
		if fi.Size() != 0 {
			t.Errorf("size = %d, want 0 (truncated)", fi.Size())
		}
	})

	t.Run("arbiter rotates too", func(t *testing.T) {
		dir := t.TempDir()
		path := writeLog(t, dir, coreDHCPLogRotateThreshold+1)
		a := &Agent{dataDir: dir, role: config.RoleCore3}
		if err := a.RotateCoreDHCPLogIfNeeded(); err != nil {
			t.Fatalf("RotateCoreDHCPLogIfNeeded() = %v", err)
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}
		if fi.Size() != 0 {
			t.Errorf("arbiter (now runs core DHCP like any other role) must truncate too, size = %d", fi.Size())
		}
	})
}

func TestRotateCoreDNSLogIfNeeded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, dnscentralrender.CoreDNSLogFileName)
	if err := os.WriteFile(path, make([]byte, coreDHCPLogRotateThreshold+1), 0640); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	a := &Agent{dataDir: dir, role: config.RoleCore1}
	if err := a.RotateCoreDNSLogIfNeeded(); err != nil {
		t.Fatalf("RotateCoreDNSLogIfNeeded() = %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Size() != 0 {
		t.Errorf("size = %d, want 0 (truncated)", fi.Size())
	}
}
