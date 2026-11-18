// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"strings"
	"testing"
)

func TestOUIIcon(t *testing.T) {
	icon, title, ok := ouiIcon("00:1d:c1:12:34:56")
	if !ok || icon == "" || !strings.Contains(title, "Audinate") {
		t.Fatalf("an Audinate prefix is an audio device: %q %q %v", icon, title, ok)
	}
	if _, _, ok := ouiIcon("02:1d:c1:12:34:56"); ok {
		t.Error("a locally administered (private) MAC says nothing about the device")
	}
	if _, _, ok := ouiIcon("ff:ff:ff:12:34:56"); ok {
		t.Error("an unknown prefix gives no guess")
	}
	if _, _, ok := ouiIcon("not a mac"); ok {
		t.Error("garbage gives no guess")
	}
}

func TestOUITableIsConsistent(t *testing.T) {
	for oui, e := range ouiTable {
		if len(oui) != 6 || int(e[0]) >= len(ouiVendors) || int(e[1]) >= len(ouiKinds) {
			t.Fatalf("bad entry %s: %v", oui, e)
		}
		if _, ok := ouiKindIcons[ouiKinds[e[1]]]; !ok {
			t.Fatalf("kind %q has no icon", ouiKinds[e[1]])
		}
	}
}
