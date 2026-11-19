// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"dnshived/internal/config"
)

func TestLeaseDuration(t *testing.T) {
	tests := []struct {
		in   string
		want time.Duration
	}{
		{"", hostsDefaultLeaseTime}, {"90s", 90 * time.Second}, {"30m", 30 * time.Minute},
		{"2h", 2 * time.Hour}, {"1d", 24 * time.Hour}, {"3600", time.Hour},
		{"infinite", 0}, {"junk", hostsDefaultLeaseTime},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := leaseDuration(tt.in); got != tt.want {
				t.Errorf("leaseDuration(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestHostTimes(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	if got := hostTTL(now, now.Add(2*time.Hour+14*time.Minute), false); got != "2h 14m" {
		t.Errorf("ttl = %q", got)
	}
	if got := hostTTL(now, now.Add(-time.Second), false); got != "expired" {
		t.Errorf("ttl = %q", got)
	}
	if got := hostTTL(now, time.Time{}, true); got != "static" {
		t.Errorf("ttl = %q", got)
	}
	if got := hostRenewed(now, now.Add(11*time.Hour+50*time.Minute), false, 12*time.Hour); got != "10m 00s ago" {
		t.Errorf("renewed = %q", got)
	}
	if got := hostRenewed(now, now, true, 12*time.Hour); got != "—" {
		t.Errorf("renewed = %q", got)
	}
}

func TestPrivateMAC(t *testing.T) {
	if !privateMAC("da:a1:19:00:00:01") || privateMAC("00:11:22:33:44:55") || privateMAC("") {
		t.Error("the locally administered bit decides")
	}
}

func TestBuildHostRows_MergesLeasesAndReservations(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	sc := config.ScopeConfig{Reservations: []config.Reservation{
		{MAC: "AA:BB:CC:00:00:01", IP: "10.0.0.5", Hostname: "mixer-01"},
		{MAC: "aa:bb:cc:00:00:02", IP: "10.0.0.6", Hostname: "silent"},
	}}
	leases := []dnsmasqLease{
		{MAC: "aa:bb:cc:00:00:01", IP: "10.0.0.5", NeverExpires: true},
		{MAC: "aa:bb:cc:00:00:09", IP: "10.0.0.50", Hostname: "iPhone-of-x", Expiry: now.Add(time.Hour)},
	}
	rows := buildHostRows("office", sc, leases, now)
	sortHostRows(rows)
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3: %+v", len(rows), rows)
	}
	if !rows[0].Reserved || rows[0].Name != "mixer-01" || !rows[0].Seen || rows[0].TTL != "static" {
		t.Errorf("reserved lease row wrong: %+v", rows[0])
	}
	if !rows[1].Reserved || rows[1].Seen || rows[1].IP != "10.0.0.6" {
		t.Errorf("reservation without lease wrong: %+v", rows[1])
	}
	if rows[2].Reserved || rows[2].Icon == "□" || rows[2].TTL != "1h 00m" {
		t.Errorf("dynamic row wrong: %+v", rows[2])
	}
	if got := filterHostRows(rows, "iphone", ""); len(got) != 1 {
		t.Errorf("search found %d rows", len(got))
	}
	if got := filterHostRows(rows, "", "dynamic"); len(got) != 1 {
		t.Errorf("dynamic chip found %d rows", len(got))
	}
	if got := filterHostRows(rows, "", "reserved"); len(got) != 2 {
		t.Errorf("reserved chip found %d rows", len(got))
	}
}

func TestHostsTemplate_RendersRowsAndMenu(t *testing.T) {
	var b strings.Builder
	err := hostsTmpl.Execute(&b, hostsPageData{
		Total: 3,
		Rows: []hostRow{
			{Scope: "office", MAC: "da:a1:19:00:00:01", IP: "10.0.0.50", Name: "iPhone", Icon: "i", Private: true, Seen: true, TTL: "1h 00m", Renewed: "5m 00s ago"},
			{Scope: "office", MAC: "aa:bb:cc:00:00:02", IP: "10.0.0.6", Name: "<b>x</b>", Reserved: true, TTL: "—", Renewed: "—"},
			{Scope: "office", MAC: "aa:bb:cc:00:00:03", IP: "10.0.0.77", Unknown: true, Seen: true, TTL: "—", Renewed: "—"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Count(out, ">Reserve<") != 1 || !strings.Contains(out, "static?") {
		t.Error("an unknown static host offers Reserve and shows static?")
	}
	if strings.Count(out, "data-check") < 3 {
		t.Error("every row with a menu offers Check now")
	}
	if strings.Count(out, "Make static") != 1 {
		t.Error("only the dynamic, seen host offers Make static")
	}
	if strings.Contains(out, "<b>x</b>") || !strings.Contains(out, "&lt;b&gt;x&lt;/b&gt;") {
		t.Error("host names must be escaped")
	}
	if strings.Count(out, "Rename…") != 1 || strings.Count(out, "Client ID…") != 1 || strings.Count(out, "Names…") != 1 || strings.Count(out, "Block…") != 3 {
		t.Error("a reserved host offers Rename and Client ID, every host with a menu offers Block")
	}
	if !strings.Contains(out, "private (randomized) MAC") {
		t.Error("a private MAC carries its explanation")
	}
}

func TestUpsertReservation_MatchesMACIgnoringCase(t *testing.T) {
	got := upsertReservation([]config.Reservation{{MAC: "AA:BB:CC:00:00:02", IP: "10.0.0.6", ClientID: "01:aa"}}, config.Reservation{MAC: "aa:bb:cc:00:00:02", IP: "10.0.0.6", Hostname: "nas", ClientID: "01:aa"})
	if len(got) != 1 || got[0].Hostname != "nas" {
		t.Fatalf("a rename must replace the reservation, not add a second one: %+v", got)
	}
}

func TestAddUnknownStatic(t *testing.T) {
	rows := []hostRow{{MAC: "aa:aa:aa:00:00:01", IP: "10.0.0.50"}, {MAC: "aa:aa:aa:00:00:02", IP: "10.0.0.6", Reserved: true}}
	neigh := []scopeNeighbor{
		{IP: "10.0.0.50", MAC: "aa:aa:aa:00:00:01", Complete: true},
		{IP: "10.0.0.77", MAC: "AA:AA:AA:00:00:77", Complete: true},
		{IP: "10.0.0.78", Complete: false},
		{IP: "10.0.0.51", MAC: "aa:aa:aa:00:00:51", Complete: true},
		{IP: "10.0.0.99", MAC: "aa:aa:aa:00:00:02", Complete: true},
	}
	got := addUnknownStatic(rows, "office", neigh, map[string]bool{"10.0.0.51": true})
	if len(got) != 3 || got[2].IP != "10.0.0.77" || !got[2].Unknown || got[2].MAC != "aa:aa:aa:00:00:77" {
		t.Fatalf("rows = %+v", got)
	}
}

func TestFilterHostRows_UnknownStatic(t *testing.T) {
	rows := []hostRow{{IP: "1"}, {IP: "2", Reserved: true}, {IP: "3", Unknown: true}}
	if got := filterHostRows(rows, "", "static"); len(got) != 1 || got[0].IP != "3" {
		t.Errorf("static = %+v", got)
	}
	if got := filterHostRows(rows, "", "dynamic"); len(got) != 1 || got[0].IP != "1" {
		t.Errorf("dynamic must not include unknown static: %+v", got)
	}
}

func TestBuildHostRows_KeepsReservationNameApartFromLeaseName(t *testing.T) {
	sc := config.ScopeConfig{Reservations: []config.Reservation{{MAC: "aa:bb:cc:00:00:02", IP: "10.0.0.6", Hostname: "nas", Names: []string{"files", "backup"}}}}
	rows := buildHostRows("office", sc, []dnsmasqLease{{MAC: "AA:BB:CC:00:00:02", IP: "10.0.0.6", Hostname: "lease-name"}}, time.Unix(1_800_000_000, 0))
	if len(rows) != 1 || rows[0].Name != "lease-name" || rows[0].ResName != "nas" || rows[0].Names != "files, backup" {
		t.Fatalf("rows = %+v", rows)
	}
}

func hostSortFixture() []hostRow {
	mk := func(scope, mac, ip, name string, ttl int64, res bool) hostRow {
		r := hostRow{Scope: scope, MAC: mac, IP: ip, Name: name, ttlSec: ttl, Reserved: res}
		r.addr, _ = netip.ParseAddr(ip)
		return r
	}
	return []hostRow{
		mk("b", "aa:00:00:00:00:03", "10.0.0.10", "zulu", 300, false),
		mk("a", "aa:00:00:00:00:02", "10.0.0.9", "Alpha", 7200, false),
		mk("a", "aa:00:00:00:00:01", "10.0.0.100", "mike", math.MaxInt64, true),
	}
}

func hostIPs(rows []hostRow) string {
	var s []string
	for _, r := range rows {
		s = append(s, r.IP)
	}
	return strings.Join(s, " ")
}

func TestSortHostRowsBy(t *testing.T) {
	tests := []struct {
		key  string
		desc bool
		want string
	}{
		{"", false, "10.0.0.9 10.0.0.100 10.0.0.10"},
		{"scope", true, "10.0.0.10 10.0.0.100 10.0.0.9"},
		{"ip", false, "10.0.0.9 10.0.0.10 10.0.0.100"},
		{"ip", true, "10.0.0.100 10.0.0.10 10.0.0.9"},
		{"name", false, "10.0.0.9 10.0.0.100 10.0.0.10"},
		{"mac", false, "10.0.0.100 10.0.0.9 10.0.0.10"},
		{"ttl", false, "10.0.0.10 10.0.0.9 10.0.0.100"},
		{"ttl", true, "10.0.0.100 10.0.0.9 10.0.0.10"},
		{"kind", false, "10.0.0.9 10.0.0.10 10.0.0.100"},
	}
	for _, tt := range tests {
		t.Run(tt.key+fmt.Sprint(tt.desc), func(t *testing.T) {
			rows := hostSortFixture()
			sortHostRowsBy(rows, tt.key, tt.desc)
			if got := hostIPs(rows); got != tt.want {
				t.Errorf("order = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestFilterHostScopeAndHeaders(t *testing.T) {
	rows := hostSortFixture()
	if got := filterHostScope(rows, "a"); len(got) != 2 {
		t.Errorf("scope a: %d rows", len(got))
	}
	if got := filterHostScope(rows, ""); len(got) != 3 {
		t.Errorf("no scope keeps all: %d", len(got))
	}
	if names := hostScopeNames(rows); strings.Join(names, ",") != "a,b" {
		t.Errorf("scope names = %v", names)
	}
	h := hostSortHeaders(url.Values{"scope": {"a"}, "q": {"x"}}, "ip", false)
	if len(h) != 5 || h[2].Arrow != "▲" || !strings.Contains(h[2].URL, "dir=desc") || !strings.Contains(h[2].URL, "scope=a") || h[0].AriaSort != "none" {
		t.Errorf("headers = %+v", h)
	}
	if h := hostSortHeaders(url.Values{}, "", false); h[0].Arrow != "▲" {
		t.Errorf("the default sort is by scope: %+v", h[0])
	}
}
