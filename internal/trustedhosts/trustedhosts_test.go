// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package trustedhosts

import "testing"

func TestEmptySetAllowsEverything(t *testing.T) {
	var s Set
	if !s.Allowed("10.0.0.99:12345") {
		t.Fatal("empty set should fail open (allow everyone)")
	}
	s2 := New(nil)
	if !s2.Allowed("10.0.0.99:12345") {
		t.Fatal("New(nil) should fail open (allow everyone)")
	}
}

func TestConfiguredSetOnlyAllowsListedHosts(t *testing.T) {
	s := New([]string{"192.168.0.22", "192.168.0.23"})
	if !s.Allowed("192.168.0.22:9443") {
		t.Fatal("listed host with port should be allowed")
	}
	if !s.Allowed("192.168.0.23:54321") {
		t.Fatal("listed host with different port should be allowed")
	}
	if s.Allowed("192.168.0.43:9443") {
		t.Fatal("unlisted host must be denied")
	}
}

func TestAllowedHandlesBareHostWithoutPort(t *testing.T) {
	s := New([]string{"192.168.0.22"})
	if !s.Allowed("192.168.0.22") {
		t.Fatal("bare host (no port) should still match")
	}
}
