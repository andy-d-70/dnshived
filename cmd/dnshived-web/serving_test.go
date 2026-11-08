// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/url"
	"strings"
	"testing"

	"dnshived/internal/config"
)

func TestParseServingSwitches_OnlyDeviationsFromTheDefaultAreKept(t *testing.T) {
	workers := []string{"ens19", "ens20"}
	f := url.Values{
		"platform_serve_seen": {"ens19", "ens20", "ens18"},
		"platform_serve":      {"ens19", "ens18"},
	}

	got := parseServingSwitches(f, "ens18", workers)

	if len(got) != 2 || got["ens20"] != false || !got["ens18"] {
		t.Fatalf("got %v, want ens20 off and ens18 on, ens19 left at its default", got)
	}
	if _, kept := got["ens19"]; kept {
		t.Error("ens19 is at its default and must not be stored")
	}
}

func TestParseServingSwitches_AnInterfaceWithoutASwitchOnTheFormKeepsItsDefault(t *testing.T) {
	f := url.Values{"platform_serve_seen": {"ens19"}, "platform_serve": {"ens19"}}
	if got := parseServingSwitches(f, "ens18", []string{"ens19", "ens20"}); got != nil {
		t.Errorf("got %v, want nothing stored: ens20 had no switch in this form", got)
	}
}

func TestServingRows_ListWorkersThenManagementWithItsOwnDefault(t *testing.T) {
	rows := servingRows(&config.Platform{Mgmt: "ens18", Workers: []string{"ens19"}})
	if len(rows) != 2 || rows[0].Name != "ens19" || !rows[0].On || rows[1].Name != "ens18" || rows[1].On || !rows[1].Mgmt {
		t.Fatalf("rows = %+v, want ens19 on then ens18 (management) off", rows)
	}
}

func TestParentChoices_KeepAParentAScopeAlreadyUsesEvenWhenItDoesNotServe(t *testing.T) {
	c := config.Cluster{
		Platform: &config.Platform{Mgmt: "ens18", Workers: []string{"ens19"}},
		Scopes:   map[string]config.ScopeConfig{"legacy": {Parent: "ens18"}},
	}
	if got := strings.Join(parentChoices(c), ","); got != "ens19,ens18" {
		t.Fatalf("parentChoices = %s, want ens19,ens18 so editing the scope never moves it", got)
	}
	c.Scopes = nil
	if got := strings.Join(parentChoices(c), ","); got != "ens19" {
		t.Fatalf("parentChoices = %s, want only ens19 while the management interface is off", got)
	}
}
