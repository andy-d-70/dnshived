// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"dnshived/internal/backup"
	"dnshived/internal/config"
)

func TestReadBackupLastRun_MissingFileReturnsZeroTime(t *testing.T) {
	got := readBackupLastRun(t.TempDir())
	if !got.IsZero() {
		t.Errorf("readBackupLastRun() on a fresh dataDir = %v, want zero time", got)
	}
}

func TestWriteReadBackupLastRun_RoundTrips(t *testing.T) {
	dir := t.TempDir()
	want := time.Date(2026, 9, 13, 8, 46, 17, 0, time.UTC)
	if err := writeBackupLastRun(dir, want); err != nil {
		t.Fatalf("writeBackupLastRun: %v", err)
	}
	got := readBackupLastRun(dir)
	if !got.Equal(want) {
		t.Errorf("readBackupLastRun() after write = %v, want %v", got, want)
	}
}

func TestReadBackupLastRun_CorruptFileReturnsZeroNotError(t *testing.T) {
	dir := t.TempDir()
	if err := writeBackupLastRun(dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backupLastRunPath(dir), []byte("not a timestamp"), 0o640); err != nil {
		t.Fatal(err)
	}
	got := readBackupLastRun(dir)
	if !got.IsZero() {
		t.Errorf("readBackupLastRun() on corrupt file = %v, want zero time", got)
	}
}

func TestAdminAPIToken_ReturnsFirstAdminRoleToken(t *testing.T) {
	c := &config.Cluster{APITokens: []config.APIToken{
		{Name: "ro", Token: "readtok", Role: "readonly"},
		{Name: "probe-host", Token: "probetok", Role: "probe"},
		{Name: "admin1", Token: "admintok", Role: "admin"},
	}}
	if got := adminAPIToken(c); got != "admintok" {
		t.Errorf("adminAPIToken() = %q, want %q", got, "admintok")
	}
}

func TestAdminAPIToken_NoAdminTokenReturnsEmpty(t *testing.T) {
	c := &config.Cluster{APITokens: []config.APIToken{{Name: "ro", Token: "readtok", Role: "readonly"}}}
	if got := adminAPIToken(c); got != "" {
		t.Errorf("adminAPIToken() = %q, want empty", got)
	}
}

func TestReplicateBackupToPeers_PutsRawBytesWithAuthToEveryPeer(t *testing.T) {
	var gotMethod, gotPath, gotAuth string
	var gotBody []byte
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer peer.Close()
	u, err := url.Parse(peer.URL)
	if err != nil {
		t.Fatal(err)
	}

	dataDirPath := t.TempDir()
	raw := []byte("encrypted-backup-content")
	if _, err := backup.Import(dataDirPath, "backup-20260101-000000.enc", raw, "", false); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Cluster{
		Peers:     []string{u.Host},
		APITokens: []config.APIToken{{Name: "admin1", Token: "s3cr3t", Role: "admin"}},
	}
	replicateBackupToPeers(cfg, dataDirPath, "backup-20260101-000000.enc")

	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	if gotPath != "/api/v1/backups/backup-20260101-000000.enc" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "Bearer s3cr3t" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer s3cr3t")
	}
	if string(gotBody) != string(raw) {
		t.Errorf("body = %q, want %q (bytes must travel verbatim, never re-encrypted)", gotBody, raw)
	}
}

func TestReplicateBackupToPeers_CarriesCommentHeader(t *testing.T) {
	var gotHeader string
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Backup-Comment")
		w.WriteHeader(http.StatusOK)
	}))
	defer peer.Close()
	u, err := url.Parse(peer.URL)
	if err != nil {
		t.Fatal(err)
	}

	dataDirPath := t.TempDir()
	if _, err := backup.Import(dataDirPath, "backup-20260101-000000.enc", []byte("x"), "before cutover", false); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Cluster{
		Peers:     []string{u.Host},
		APITokens: []config.APIToken{{Name: "admin1", Token: "s3cr3t", Role: "admin"}},
	}
	replicateBackupToPeers(cfg, dataDirPath, "backup-20260101-000000.enc")

	decoded, err := base64.StdEncoding.DecodeString(gotHeader)
	if err != nil {
		t.Fatalf("X-Backup-Comment header %q is not valid base64: %v", gotHeader, err)
	}
	if string(decoded) != "before cutover" {
		t.Errorf("decoded comment = %q, want %q", decoded, "before cutover")
	}
}

// TestReplicateBackupToPeers_NoCommentSendsNoHeader confirms the common
// case (no comment) doesn't send an empty/meaningless header.
func TestReplicateBackupToPeers_NoCommentSendsNoHeader(t *testing.T) {
	headerPresent := false
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, headerPresent = r.Header["X-Backup-Comment"]
		w.WriteHeader(http.StatusOK)
	}))
	defer peer.Close()
	u, _ := url.Parse(peer.URL)

	dataDirPath := t.TempDir()
	if _, err := backup.Import(dataDirPath, "backup-20260101-000000.enc", []byte("x"), "", false); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Cluster{
		Peers:     []string{u.Host},
		APITokens: []config.APIToken{{Name: "admin1", Token: "s3cr3t", Role: "admin"}},
	}
	replicateBackupToPeers(cfg, dataDirPath, "backup-20260101-000000.enc")

	if headerPresent {
		t.Error("X-Backup-Comment header was sent despite no comment existing")
	}
}

func TestReplicateBackupToPeers_CarriesAutomatedHeader(t *testing.T) {
	var gotHeader string
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Backup-Automated")
		w.WriteHeader(http.StatusOK)
	}))
	defer peer.Close()
	u, err := url.Parse(peer.URL)
	if err != nil {
		t.Fatal(err)
	}

	dataDirPath := t.TempDir()
	if _, err := backup.Import(dataDirPath, "backup-20260101-000000.enc", []byte("x"), "", true); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Cluster{
		Peers:     []string{u.Host},
		APITokens: []config.APIToken{{Name: "admin1", Token: "s3cr3t", Role: "admin"}},
	}
	replicateBackupToPeers(cfg, dataDirPath, "backup-20260101-000000.enc")

	if gotHeader != "true" {
		t.Errorf("X-Backup-Automated header = %q, want %q", gotHeader, "true")
	}
}

// TestReplicateBackupToPeers_NotAutomatedSendsNoHeader confirms the common
// case (a manual backup) doesn't send a meaningless header.
func TestReplicateBackupToPeers_NotAutomatedSendsNoHeader(t *testing.T) {
	headerPresent := false
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, headerPresent = r.Header["X-Backup-Automated"]
		w.WriteHeader(http.StatusOK)
	}))
	defer peer.Close()
	u, _ := url.Parse(peer.URL)

	dataDirPath := t.TempDir()
	if _, err := backup.Import(dataDirPath, "backup-20260101-000000.enc", []byte("x"), "", false); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Cluster{
		Peers:     []string{u.Host},
		APITokens: []config.APIToken{{Name: "admin1", Token: "s3cr3t", Role: "admin"}},
	}
	replicateBackupToPeers(cfg, dataDirPath, "backup-20260101-000000.enc")

	if headerPresent {
		t.Error("X-Backup-Automated header was sent despite the backup not being automated")
	}
}

// TestReplicateBackupToPeers_NoAdminTokenLogsAndSkips confirms a missing
// admin-role token doesn't panic or block.
func TestReplicateBackupToPeers_NoAdminTokenLogsAndSkips(t *testing.T) {
	called := false
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer peer.Close()
	u, _ := url.Parse(peer.URL)

	dataDirPath := t.TempDir()
	if _, err := backup.Import(dataDirPath, "backup-20260101-000000.enc", []byte("x"), "", false); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Cluster{Peers: []string{u.Host}} // no api_tokens configured at all
	replicateBackupToPeers(cfg, dataDirPath, "backup-20260101-000000.enc")

	if called {
		t.Error("peer was called despite no admin token being available to authenticate with")
	}
}

// TestReplicateBackupToPeers_UnreachablePeerDoesNotPanic confirms a
// down/unreachable peer is handled gracefully.
func TestReplicateBackupToPeers_UnreachablePeerDoesNotPanic(t *testing.T) {
	dataDirPath := t.TempDir()
	if _, err := backup.Import(dataDirPath, "backup-20260101-000000.enc", []byte("x"), "", false); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Cluster{
		Peers:     []string{"127.0.0.1:1"}, // nothing listens here
		APITokens: []config.APIToken{{Name: "a", Token: "t", Role: "admin"}},
	}
	// Must simply return, not panic or hang.
	replicateBackupToPeers(cfg, dataDirPath, "backup-20260101-000000.enc")
}

func TestReplicateBackupToPeers_NoPeersIsNoop(t *testing.T) {
	dataDirPath := t.TempDir()
	cfg := &config.Cluster{}
	// No file exists at all, and no peers — must not error/panic trying
	// to read a backup that was never created.
	replicateBackupToPeers(cfg, dataDirPath, "backup-20260101-000000.enc")
}

func TestResolveBackupInterval(t *testing.T) {
	cases := []struct {
		hours int
		want  time.Duration
	}{
		{0, 24 * time.Hour},
		{-5, 24 * time.Hour},
		{1, time.Hour},
		{2, 2 * time.Hour},
	}
	for _, c := range cases {
		if got := resolveBackupInterval(c.hours); got != c.want {
			t.Errorf("resolveBackupInterval(%d) = %v, want %v", c.hours, got, c.want)
		}
	}
}

// TestBackupDue_NeverRunBeforeIsAlwaysDue checks a backup that never ran
// is always due.
func TestIsBackupCoordinator_NoMgmtVIPFallsBackToCore3Only(t *testing.T) {
	if !isBackupCoordinator(config.RoleCore3, nil, "") {
		t.Error("isBackupCoordinator(core-3, nil, \"\") = false, want true (unchanged fallback behavior)")
	}
	if isBackupCoordinator(config.RoleCore1, nil, "") {
		t.Error("isBackupCoordinator(core-1, nil, \"\") = true, want false (unchanged fallback behavior)")
	}
	if isBackupCoordinator(config.RoleCore2, nil, "") {
		t.Error("isBackupCoordinator(core-2, nil, \"\") = true, want false (unchanged fallback behavior)")
	}
}

func TestIsBackupCoordinator_WithMgmtVIPFollowsVIPHolderNotRole(t *testing.T) {
	vip := &config.MgmtVIPConfig{VIP: "192.168.0.230/24", VRRPID: 60}

	if isBackupCoordinator(config.RoleCore3, vip, "BACKUP") {
		t.Error("isBackupCoordinator(core-3, vip, BACKUP) = true, want false — core-3 no longer holds the VIP")
	}
	if !isBackupCoordinator(config.RoleCore1, vip, "MASTER") {
		t.Error("isBackupCoordinator(core-1, vip, MASTER) = false, want true — a worker holding the VIP must become the backup origin")
	}
	if isBackupCoordinator(config.RoleCore1, vip, "") {
		t.Error(`isBackupCoordinator(core-1, vip, "") = true, want false — an unresolved/stale cache must never claim coordinator status`)
	}
}

func TestBackupDue_NeverRunBeforeIsAlwaysDue(t *testing.T) {
	if !backupDue(time.Time{}, 2*time.Hour, time.Now()) {
		t.Error("backupDue() with zero lastRun = false, want true")
	}
}

// TestBackupDue_SameSlotIsNotDue confirms two times inside the same fixed
// UTC slot (2h interval -> 12:00-13:59:59) never fire twice.
func TestBackupDue_SameSlotIsNotDue(t *testing.T) {
	lastRun := time.Date(2026, 9, 13, 12, 22, 26, 0, time.UTC) // slot 12:00
	now := time.Date(2026, 9, 13, 13, 59, 0, 0, time.UTC)      // still slot 12:00
	if backupDue(lastRun, 2*time.Hour, now) {
		t.Error("backupDue() within the same 2h slot as lastRun = true, want false")
	}
}

func TestBackupDue_NewSlotIsDue(t *testing.T) {
	lastRun := time.Date(2026, 9, 13, 12, 22, 26, 0, time.UTC) // slot 12:00
	now := time.Date(2026, 9, 13, 14, 0, 30, 0, time.UTC)      // slot 14:00
	if !backupDue(lastRun, 2*time.Hour, now) {
		t.Error("backupDue() in a new 2h slot after lastRun's own slot = false, want true")
	}
}

// TestBackupDue_JustBeforeSlotBoundaryIsNotDue confirms slot comparison
// doesn't fire early.
func TestBackupDue_JustBeforeSlotBoundaryIsNotDue(t *testing.T) {
	lastRun := time.Date(2026, 9, 13, 12, 22, 26, 0, time.UTC)
	now := time.Date(2026, 9, 13, 13, 59, 59, 0, time.UTC) // 1s before the 14:00 boundary
	if backupDue(lastRun, 2*time.Hour, now) {
		t.Error("backupDue() 1s before the next slot boundary = true, want false")
	}
}

// TestBackupDue_JustAfterSlotBoundaryIsDue confirms the flip side.
func TestBackupDue_JustAfterSlotBoundaryIsDue(t *testing.T) {
	lastRun := time.Date(2026, 9, 13, 12, 22, 26, 0, time.UTC)
	now := time.Date(2026, 9, 13, 14, 0, 1, 0, time.UTC) // 1s after the 14:00 boundary
	if !backupDue(lastRun, 2*time.Hour, now) {
		t.Error("backupDue() 1s after the next slot boundary = false, want true")
	}
}
