// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
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
		Total: 2,
		Rows: []hostRow{
			{Scope: "office", MAC: "da:a1:19:00:00:01", IP: "10.0.0.50", Name: "iPhone", Icon: "i", Private: true, Seen: true, TTL: "1h 00m", Renewed: "5m 00s ago"},
			{Scope: "office", MAC: "aa:bb:cc:00:00:02", IP: "10.0.0.6", Name: "<b>x</b>", Reserved: true, TTL: "—", Renewed: "—"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Count(out, "Make static") != 1 {
		t.Error("only the dynamic, seen host offers Make static")
	}
	if strings.Contains(out, "<b>x</b>") || !strings.Contains(out, "&lt;b&gt;x&lt;/b&gt;") {
		t.Error("host names must be escaped")
	}
	if !strings.Contains(out, "private (randomized) MAC") {
		t.Error("a private MAC carries its explanation")
	}
}
