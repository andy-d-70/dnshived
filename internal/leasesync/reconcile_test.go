// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package leasesync

import (
	"testing"
	"time"
)

func TestFingerprint_StableForIdenticalContentRegardlessOfOrder(t *testing.T) {
	a := []SyncedLease{
		{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: 1000},
		{MAC: "cc:dd", IP: "10.0.0.6", ExpiresAt: 2000},
	}
	b := []SyncedLease{
		{MAC: "cc:dd", IP: "10.0.0.6", ExpiresAt: 2000},
		{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: 1000},
	}
	if Fingerprint(a) != Fingerprint(b) {
		t.Fatalf("Fingerprint() differs for the same content in a different order")
	}
}

func TestFingerprint_SensitiveToIPChange(t *testing.T) {
	a := []SyncedLease{{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: 1000}}
	b := []SyncedLease{{MAC: "aa:bb", IP: "10.0.0.9", ExpiresAt: 1000}}
	if Fingerprint(a) == Fingerprint(b) {
		t.Fatalf("Fingerprint() identical despite a real IP difference")
	}
}

func TestFingerprint_IgnoresHostname(t *testing.T) {
	a := []SyncedLease{{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: 1000, Hostname: "one"}}
	b := []SyncedLease{{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: 1000, Hostname: "two"}}
	if Fingerprint(a) != Fingerprint(b) {
		t.Fatalf("Fingerprint() differs on hostname alone — it should only cover MAC/IP/expiry")
	}
}

func TestDiff_IdenticalViewsNoFindings(t *testing.T) {
	now := time.Now()
	entries := []SyncedLease{{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: now.Add(time.Hour).Unix()}}
	conflicts, gaps := Diff(entries, entries, now, 2*time.Minute)
	if len(conflicts) != 0 || len(gaps) != 0 {
		t.Fatalf("Diff() on identical views = (%v, %v), want no findings", conflicts, gaps)
	}
}

func TestDiff_SameMACDifferentIPIsConflict(t *testing.T) {
	now := time.Now()
	local := []SyncedLease{{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: now.Add(time.Hour).Unix()}}
	remote := []SyncedLease{{MAC: "aa:bb", IP: "10.0.0.9", ExpiresAt: now.Add(time.Hour).Unix()}}
	conflicts, gaps := Diff(local, remote, now, 2*time.Minute)
	if len(gaps) != 0 {
		t.Fatalf("Diff() found gaps %v, want none", gaps)
	}
	if len(conflicts) != 1 || conflicts[0].MAC != "aa:bb" || conflicts[0].LocalIP != "10.0.0.5" || conflicts[0].RemoteIP != "10.0.0.9" {
		t.Fatalf("Diff() conflicts = %v, want one aa:bb 10.0.0.5-vs-10.0.0.9", conflicts)
	}
}

func TestDiff_MACPresentRemoteAbsentLocalIsGap(t *testing.T) {
	now := time.Now()
	local := []SyncedLease{}
	remote := []SyncedLease{{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: now.Add(time.Hour).Unix()}}
	conflicts, gaps := Diff(local, remote, now, 2*time.Minute)
	if len(conflicts) != 0 {
		t.Fatalf("Diff() found conflicts %v, want none", conflicts)
	}
	if len(gaps) != 1 || gaps[0].MAC != "aa:bb" {
		t.Fatalf("Diff() gaps = %v, want one aa:bb", gaps)
	}
}

func TestDiff_RecentlyExpiredEntryExcludedFromComparison(t *testing.T) {
	now := time.Now()
	local := []SyncedLease{}
	remote := []SyncedLease{{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: now.Add(-30 * time.Second).Unix()}}
	conflicts, gaps := Diff(local, remote, now, 2*time.Minute)
	if len(conflicts) != 0 || len(gaps) != 0 {
		t.Fatalf("Diff() = (%v, %v), want the recently-expired entry excluded entirely", conflicts, gaps)
	}
}

func TestDiff_LongExpiredEntryStillIgnoredNotTreatedAsGap(t *testing.T) {
	now := time.Now()
	local := []SyncedLease{}
	remote := []SyncedLease{{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: now.Add(-time.Hour).Unix()}}
	_, gaps := Diff(local, remote, now, 2*time.Minute)
	if len(gaps) != 0 {
		t.Fatalf("Diff() gaps = %v, a long-expired remote entry must never be reported as a gap", gaps)
	}
}
