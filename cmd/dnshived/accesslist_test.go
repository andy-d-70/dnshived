// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"dnshived/internal/access"
	"dnshived/internal/activation"
	"dnshived/internal/config"
)

func TestParseAccessUpdate(t *testing.T) {
	t.Run("absent key leaves the list alone", func(t *testing.T) {
		u, err := parseAccessUpdate(nil)
		if err != nil || u.present {
			t.Fatalf("got %+v, %v", u, err)
		}
		c := &config.Cluster{Access: &access.Config{Mode: access.ModeEnforce}}
		u.applyTo(c)
		if c.Access == nil || c.Access.Mode != access.ModeEnforce {
			t.Fatal("an older web interface that does not send the key must not wipe the list")
		}
	})
	t.Run("null clears it", func(t *testing.T) {
		u, err := parseAccessUpdate(json.RawMessage("null"))
		if err != nil || !u.present {
			t.Fatalf("got %+v, %v", u, err)
		}
		c := &config.Cluster{Access: &access.Config{}}
		u.applyTo(c)
		if c.Access != nil {
			t.Fatal("null must clear the list")
		}
	})
	t.Run("an object replaces it", func(t *testing.T) {
		u, err := parseAccessUpdate(json.RawMessage(`{"mode":"enforce","entries":[{"net":"203.0.113.0/24","dhcp":"deny"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		c := &config.Cluster{}
		u.applyTo(c)
		if c.Access == nil || c.Access.Mode != access.ModeEnforce || len(c.Access.Entries) != 1 {
			t.Fatalf("got %+v", c.Access)
		}
	})
	t.Run("an invalid list is refused", func(t *testing.T) {
		if _, err := parseAccessUpdate(json.RawMessage(`{"entries":[{"net":"nope"}]}`)); err == nil {
			t.Fatal("an invalid network must be refused")
		}
		if _, err := parseAccessUpdate(json.RawMessage(`{"mode":`)); err == nil || !strings.Contains(err.Error(), "access") {
			t.Fatalf("broken JSON must be refused with a clear error, got %v", err)
		}
	})
}

func TestAccessGateLatchesWhenEveryCoreQualifies(t *testing.T) {
	g := &outageRules{}
	required := activation.AccessListVersion
	old := []peerView{{Addr: "a", Known: true, Version: "0.9.8.9"}, {Addr: "b", Known: true, Version: required}}
	if g.refreshAt(required, required, 2, old, nil) {
		t.Fatal("a core on an older version must hold the latch off")
	}
	missing := []peerView{{Addr: "a", Known: true, Version: required}}
	if g.refreshAt(required, required, 2, missing, nil) {
		t.Fatal("a configured core that was never seen must hold the latch off")
	}
	ok := []peerView{{Addr: "a", Known: true, Version: required}, {Addr: "b", Known: true, Version: "0.9.8.10"}}
	persisted := 0
	if !g.refreshAt(required, required, 2, ok, func() error { persisted++; return nil }) {
		t.Fatal("every core qualifies: the latch must set")
	}
	if persisted != 1 || !g.Active() {
		t.Fatalf("persisted %d times, active=%v", persisted, g.Active())
	}
	if g.refreshAt(required, required, 2, old, nil) {
		t.Fatal("an active latch stays and reports no change")
	}
}
