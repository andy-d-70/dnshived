// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net"
	"testing"

	"dnsrelay/access"
)

func TestAccessPermits(t *testing.T) {
	t.Cleanup(func() { accessM.Store(nil) })
	stranger := net.ParseIP("203.0.113.9")
	private := net.ParseIP("192.168.1.5")

	applyAccess(Config{})
	if !accessPermits(stranger, "t0") {
		t.Fatal("without a list everyone is served")
	}

	droppedBefore := accessDropped.Load()
	applyAccess(Config{Access: &access.Config{Mode: access.ModeEnforce}})
	if accessPermits(stranger, "t0") {
		t.Fatal("enforce must drop a public source that is not listed")
	}
	if accessDropped.Load() != droppedBefore+1 {
		t.Errorf("accessDropped = %d, want %d", accessDropped.Load(), droppedBefore+1)
	}
	if !accessPermits(private, "t0") {
		t.Fatal("private networks are allowed by default")
	}

	applyAccess(Config{Access: &access.Config{Mode: access.ModeEnforce, Entries: []access.Entry{{Net: "203.0.113.0/24", DNS: access.Deny}}}})
	if accessPermits(stranger, "t0") {
		t.Fatal("DNS denied for the network must drop")
	}

	applyAccess(Config{Access: &access.Config{Mode: access.ModeEnforce, Hosts: []access.Host{{Addr: "203.0.113.9", DNS: true}}}})
	if !accessPermits(stranger, "t0") {
		t.Fatal("a whitelisted host is served")
	}

	wouldBefore := accessWouldDrop.Load()
	applyAccess(Config{Access: &access.Config{Mode: access.ModeReport}})
	if !accessPermits(net.ParseIP("198.18.0.1"), "t0") {
		t.Fatal("report mode must not drop")
	}
	if accessWouldDrop.Load() != wouldBefore+1 {
		t.Error("report mode must count the would-be drop")
	}

	applyAccess(Config{Access: &access.Config{Mode: access.ModeEnforce}, AccessAlways: []string{"198.18.0.7"}})
	if !accessPermits(net.ParseIP("198.18.0.7"), "t0") {
		t.Fatal("an always-allowed address is served")
	}
	applyAccess(Config{Access: &access.Config{Mode: "loud"}})
	if accessM.Load() != nil {
		t.Fatal("an invalid list must be ignored, not half applied")
	}
	if !accessPermits(stranger, "t0") {
		t.Fatal("an ignored list serves everyone")
	}
}
