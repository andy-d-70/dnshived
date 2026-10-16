// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package leasesync

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandler_UpsertAppliesAndCallsOnChange(t *testing.T) {
	h := NewHandler()
	h.SetTrustedHosts(nil)
	changed := false
	h.OnChange = func() { changed = true }
	mux := http.NewServeMux()
	h.AddRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := srv.Client()
	err := Push(client, "http", srv.Listener.Addr().String(), SyncedLease{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: 1000}, "upsert")
	if err != nil {
		t.Fatalf("Push() error: %v", err)
	}
	if !changed {
		t.Error("OnChange was not called after a successful upsert")
	}
	got := h.Store.Snapshot()
	if len(got) != 1 || got[0].MAC != "aa:bb" {
		t.Errorf("Store.Snapshot() = %v, want one entry for aa:bb", got)
	}
}

func TestHandler_RemoveClearsEntry(t *testing.T) {
	h := NewHandler()
	h.SetTrustedHosts(nil)
	h.Store.Upsert(SyncedLease{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: 1000})
	mux := http.NewServeMux()
	h.AddRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	if err := Push(srv.Client(), "http", srv.Listener.Addr().String(), SyncedLease{MAC: "aa:bb"}, "remove"); err != nil {
		t.Fatalf("Push() error: %v", err)
	}
	if got := h.Store.Snapshot(); len(got) != 0 {
		t.Errorf("Store.Snapshot() = %v, want empty after remove", got)
	}
}

// TestHandler_RejectsUntrustedHost is the direct regression for this
// endpoint being reachable by anything other than a genuine cluster peer.
func TestHandler_RejectsUntrustedHost(t *testing.T) {
	h := NewHandler()
	h.SetTrustedHosts([]string{"192.0.2.1"})
	mux := http.NewServeMux()
	h.AddRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	err := Push(srv.Client(), "http", srv.Listener.Addr().String(), SyncedLease{MAC: "aa:bb", IP: "10.0.0.5"}, "upsert")
	if err == nil {
		t.Fatal("Push() succeeded against an untrusted-host-only allowlist, want a forbidden error")
	}
	if got := h.Store.Snapshot(); len(got) != 0 {
		t.Errorf("Store.Snapshot() = %v, want empty — the untrusted request must never be applied", got)
	}
}

func TestHandler_RejectsUnknownAction(t *testing.T) {
	h := NewHandler()
	h.SetTrustedHosts(nil)
	mux := http.NewServeMux()
	h.AddRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	err := Push(srv.Client(), "http", srv.Listener.Addr().String(), SyncedLease{MAC: "aa:bb"}, "bogus")
	if err == nil {
		t.Fatal("Push() with an unknown action succeeded, want an error")
	}
}

func TestHandler_RejectsEmptyMAC(t *testing.T) {
	h := NewHandler()
	h.SetTrustedHosts(nil)
	mux := http.NewServeMux()
	h.AddRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	err := Push(srv.Client(), "http", srv.Listener.Addr().String(), SyncedLease{IP: "10.0.0.5"}, "upsert")
	if err == nil {
		t.Fatal("Push() with an empty MAC succeeded, want an error")
	}
}

func TestHandler_FetchFingerprint_UsesMergedSnapshotFuncNotStoreAlone(t *testing.T) {
	h := NewHandler()
	h.SetTrustedHosts(nil)
	h.Store.Upsert(SyncedLease{MAC: "peer-only", IP: "10.0.0.5", ExpiresAt: 9999999999})
	merged := []SyncedLease{
		{MAC: "peer-only", IP: "10.0.0.5", ExpiresAt: 9999999999},
		{MAC: "local-only", IP: "10.0.0.6", ExpiresAt: 9999999999},
	}
	h.MergedSnapshotFunc = func() []SyncedLease { return merged }
	mux := http.NewServeMux()
	h.AddRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	got, err := FetchFingerprint(srv.Client(), "http", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("FetchFingerprint() error: %v", err)
	}
	want := Fingerprint(merged)
	if got != want {
		t.Errorf("FetchFingerprint() = %q, want the MergedSnapshotFunc-derived fingerprint %q (not the peer-only Store's own)", got, want)
	}
}

func TestHandler_FetchFingerprint_FallsBackToStoreWhenMergedSnapshotFuncUnset(t *testing.T) {
	h := NewHandler()
	h.SetTrustedHosts(nil)
	h.Store.Upsert(SyncedLease{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: 9999999999})
	mux := http.NewServeMux()
	h.AddRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	got, err := FetchFingerprint(srv.Client(), "http", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("FetchFingerprint() error: %v", err)
	}
	want := Fingerprint(h.Store.Snapshot())
	if got != want {
		t.Errorf("FetchFingerprint() = %q, want Store.Snapshot()'s own fingerprint %q", got, want)
	}
}

func TestHandler_FetchSnapshot_ReturnsMergedView(t *testing.T) {
	h := NewHandler()
	h.SetTrustedHosts(nil)
	merged := []SyncedLease{{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: 9999999999, Hostname: "host1"}}
	h.MergedSnapshotFunc = func() []SyncedLease { return merged }
	mux := http.NewServeMux()
	h.AddRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	got, err := FetchSnapshot(srv.Client(), "http", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("FetchSnapshot() error: %v", err)
	}
	if len(got) != 1 || got[0].MAC != "aa:bb" || got[0].Hostname != "host1" {
		t.Errorf("FetchSnapshot() = %v, want the one merged entry", got)
	}
}

func TestHandler_FetchFingerprint_RejectsUntrustedHost(t *testing.T) {
	h := NewHandler()
	h.SetTrustedHosts([]string{"192.0.2.1"})
	mux := http.NewServeMux()
	h.AddRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	if _, err := FetchFingerprint(srv.Client(), "http", srv.Listener.Addr().String()); err == nil {
		t.Fatal("FetchFingerprint() succeeded against an untrusted-host-only allowlist, want an error")
	}
}
