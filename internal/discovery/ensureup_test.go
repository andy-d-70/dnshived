// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package discovery

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnsureUp_BringsLinkUpAndWaitsForCarrier(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "ens19"), 0o755)
	carrier := filepath.Join(dir, "ens19", "carrier")
	os.WriteFile(carrier, []byte("0\n"), 0o644)
	origSys, origUp := sysClassNet, LinkUp
	sysClassNet = dir + "/"
	var upCalls []string
	LinkUp = func(iface string) error {
		upCalls = append(upCalls, iface)
		go func() {
			time.Sleep(200 * time.Millisecond)
			os.WriteFile(carrier, []byte("1\n"), 0o644)
		}()
		return nil
	}
	t.Cleanup(func() { sysClassNet, LinkUp = origSys, origUp })

	start := time.Now()
	EnsureUp("ens19")
	if len(upCalls) != 1 || upCalls[0] != "ens19" {
		t.Errorf("link-up calls = %v, want [ens19]", upCalls)
	}
	if d := time.Since(start); d < 150*time.Millisecond || d > 3*time.Second {
		t.Errorf("EnsureUp returned after %s, want it to wait for carrier (~200 ms)", d)
	}

	upCalls = nil
	EnsureUp("does-not-exist0")
	if len(upCalls) != 0 {
		t.Errorf("link-up attempted for a missing interface: %v", upCalls)
	}
}
