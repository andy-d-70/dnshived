// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package backup

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dnshived/internal/backupcrypt"
)

func TestList_MissingDirectoryReturnsEmptyNotError(t *testing.T) {
	dir := t.TempDir()
	got, err := List(filepath.Join(dir, "does-not-exist"))
	if err != nil {
		t.Fatalf("List() error = %v, want nil", err)
	}
	if len(got) != 0 {
		t.Fatalf("List() = %v, want empty", got)
	}
}

// TestList_EmptyResultMarshalsAsJSONArrayNotNull guards a real API
// wire-format concern: GET /api/v1/backups returns List's result directly
// as JSON.
func TestList_EmptyResultMarshalsAsJSONArrayNotNull(t *testing.T) {
	dir := t.TempDir()
	got, err := List(dir) // real, existing, but empty backups/ dir
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if string(b) != "[]" {
		t.Errorf("json.Marshal(List()) = %s, want []", b)
	}

	// Also true for a directory that doesn't exist at all yet.
	got2, err := List(filepath.Join(dir, "never-created"))
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	b2, err := json.Marshal(got2)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if string(b2) != "[]" {
		t.Errorf("json.Marshal(List()) for a missing dir = %s, want []", b2)
	}
}

func TestCreate_WritesReadableEncryptedFileMatchingPattern(t *testing.T) {
	dataDir := t.TempDir()
	plaintext := []byte(`{"cluster_id":"lab01"}`)

	info, err := Create(dataDir, "hunter2", plaintext, "", false)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !filenamePattern.MatchString(info.Name) {
		t.Fatalf("Create() name = %q, does not match expected pattern", info.Name)
	}
	if info.Size == 0 {
		t.Fatalf("Create() reported zero size")
	}

	raw, err := Read(dataDir, info.Name)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	decrypted, err := backupcrypt.Decrypt("hunter2", raw)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	got, err := Decompress(decrypted)
	if err != nil {
		t.Fatalf("Decompress() error = %v (Create must gzip-compress before encrypting)", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("round-tripped plaintext = %q, want %q", got, plaintext)
	}

	// Wrong password must fail closed, not return garbage.
	if _, err := backupcrypt.Decrypt("wrong", raw); err != backupcrypt.ErrWrongPasswordOrCorrupt {
		t.Fatalf("Decrypt() with wrong password error = %v, want ErrWrongPasswordOrCorrupt", err)
	}
}

// TestCreate_CommentPersistsThroughList confirms a comment is readable
// from a plain List() call.
func TestCreate_CommentPersistsThroughList(t *testing.T) {
	dataDir := t.TempDir()
	info, err := Create(dataDir, "pw", []byte("data"), "before DNS relay cutover", false)
	if err != nil {
		t.Fatal(err)
	}
	if info.Comment != "before DNS relay cutover" {
		t.Errorf("Create() Info.Comment = %q, want %q", info.Comment, "before DNS relay cutover")
	}
	got, err := List(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Comment != "before DNS relay cutover" {
		t.Errorf("List() = %+v, want one entry with the comment", got)
	}
}

// TestCreate_EmptyCommentWritesNoSidecarFile confirms the common case (no
// comment) never litters the backups directory with empty sidecar files.
func TestCreate_EmptyCommentWritesNoSidecarFile(t *testing.T) {
	dataDir := t.TempDir()
	info, err := Create(dataDir, "pw", []byte("data"), "", false)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(Dir(dataDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != info.Name {
		t.Errorf("backups dir = %v, want exactly the one .enc file, no sidecar", entries)
	}
}

// TestDelete_RemovesCommentSidecarToo confirms deleting a commented backup
// cleans up its sidecar file, not just the .enc.
func TestDelete_RemovesCommentSidecarToo(t *testing.T) {
	dataDir := t.TempDir()
	info, err := Create(dataDir, "pw", []byte("data"), "a real comment", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := Delete(dataDir, info.Name); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(Dir(dataDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("backups dir after Delete = %v, want empty (sidecar should be gone too)", entries)
	}
}

func TestCreate_AutomatedPersistsThroughList(t *testing.T) {
	dataDir := t.TempDir()
	info, err := Create(dataDir, "pw", []byte("data"), "", true)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Automated {
		t.Error("Create(automated=true).Automated = false, want true")
	}
	got, err := List(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].Automated {
		t.Errorf("List() = %+v, want exactly one entry with Automated=true", got)
	}
}

func TestCreate_ManualHasNoAutomatedMarkerFile(t *testing.T) {
	dataDir := t.TempDir()
	info, err := Create(dataDir, "pw", []byte("data"), "", false)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(Dir(dataDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != info.Name {
		t.Errorf("backups dir = %v, want exactly the one .enc file, no .auto marker", entries)
	}
	if info.Automated {
		t.Error("Create(automated=false).Automated = true, want false")
	}
}

// TestDelete_RemovesAutomatedMarkerToo mirrors
// TestDelete_RemovesCommentSidecarToo for the automated marker.
func TestDelete_RemovesAutomatedMarkerToo(t *testing.T) {
	dataDir := t.TempDir()
	info, err := Create(dataDir, "pw", []byte("data"), "", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := Delete(dataDir, info.Name); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(Dir(dataDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("backups dir after Delete = %v, want empty (automated marker should be gone too)", entries)
	}
}

// TestImport_AutomatedPersistsThroughList mirrors
// TestImport_CommentPersistsThroughList for the automated marker.
func TestImport_AutomatedPersistsThroughList(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := Import(dataDir, "backup-20260101-000000.enc", []byte("x"), "", true); err != nil {
		t.Fatal(err)
	}
	got, err := List(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].Automated {
		t.Errorf("List() = %+v, want exactly one entry with Automated=true", got)
	}
}

// TestIsAutomated_MissingMarkerReturnsFalseNotError mirrors
// TestReadComment_MissingSidecarReturnsEmptyNotError.
func TestIsAutomated_MissingMarkerReturnsFalseNotError(t *testing.T) {
	dataDir := t.TempDir()
	info, err := Create(dataDir, "pw", []byte("data"), "", false)
	if err != nil {
		t.Fatal(err)
	}
	if got := IsAutomated(dataDir, info.Name); got {
		t.Errorf("IsAutomated() = %v, want false (no marker file)", got)
	}
}

// TestIsAutomated_RejectsInvalidName mirrors ReadComment's own
// path-traversal-safety check.
func TestIsAutomated_RejectsInvalidName(t *testing.T) {
	if got := IsAutomated(t.TempDir(), "../../../etc/passwd"); got {
		t.Error("IsAutomated() = true for a path-traversal name, want false")
	}
}

func TestImport_CommentPersistsThroughList(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := Import(dataDir, "backup-20260101-000000.enc", []byte("x"), "replicated comment", false); err != nil {
		t.Fatal(err)
	}
	got, err := List(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Comment != "replicated comment" {
		t.Errorf("List() = %+v, want the replicated comment", got)
	}
}

// TestReadComment_MissingSidecarReturnsEmptyNotError confirms the common
// case (a backup with no comment at all) is silent, not an error.
func TestReadComment_MissingSidecarReturnsEmptyNotError(t *testing.T) {
	dataDir := t.TempDir()
	info, err := Create(dataDir, "pw", []byte("data"), "", false)
	if err != nil {
		t.Fatal(err)
	}
	if got := ReadComment(dataDir, info.Name); got != "" {
		t.Errorf("ReadComment() = %q, want empty", got)
	}
}

func TestCompressPlaintext_Decompress_RoundTrips(t *testing.T) {
	original := []byte(`{"cluster_id":"lab01","scopes":{"office":{"parent":"ens19"}}}`)
	compressed, err := compressPlaintext(original)
	if err != nil {
		t.Fatalf("compressPlaintext() error = %v", err)
	}
	if len(compressed) == 0 {
		t.Fatal("compressPlaintext() returned empty output")
	}
	got, err := Decompress(compressed)
	if err != nil {
		t.Fatalf("Decompress() error = %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("round trip = %q, want %q", got, original)
	}
}

func TestDecompress_RejectsNonGzipInput(t *testing.T) {
	if _, err := Decompress([]byte("not gzip data at all")); err == nil {
		t.Fatal("Decompress() on non-gzip input returned no error, want one")
	}
}

func TestList_NewestFirst(t *testing.T) {
	dataDir := t.TempDir()
	dir := Dir(dataDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	older := "backup-20260101-000000.enc"
	newer := "backup-20260102-000000.enc"
	if err := os.WriteFile(filepath.Join(dir, older), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(dir, older), oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, newer), []byte("y"), 0o640); err != nil {
		t.Fatal(err)
	}

	got, err := List(dataDir)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(got) != 2 || got[0].Name != newer || got[1].Name != older {
		t.Fatalf("List() = %+v, want [%s, %s]", got, newer, older)
	}
}

func TestList_IgnoresNonMatchingFiles(t *testing.T) {
	dataDir := t.TempDir()
	dir := Dir(dataDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "..evil.enc"), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	got, err := List(dataDir)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("List() = %+v, want empty (both files should be filtered)", got)
	}
}

func TestRead_RejectsPathTraversalName(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := Read(dataDir, "../../../etc/passwd"); err != ErrInvalidName {
		t.Fatalf("Read() error = %v, want ErrInvalidName", err)
	}
	if _, err := Read(dataDir, "backup-20260101-000000.enc/../../etc/passwd"); err != ErrInvalidName {
		t.Fatalf("Read() error = %v, want ErrInvalidName", err)
	}
}

func TestDelete_RejectsPathTraversalName(t *testing.T) {
	dataDir := t.TempDir()
	if err := Delete(dataDir, "../../../etc/passwd"); err != ErrInvalidName {
		t.Fatalf("Delete() error = %v, want ErrInvalidName", err)
	}
}

func TestDelete_MissingFileErrorUnwrapsToIsNotExist(t *testing.T) {
	dataDir := t.TempDir()
	err := Delete(dataDir, "backup-20260101-000000.enc")
	if err == nil {
		t.Fatal("Delete() on a nonexistent file returned nil, want an error")
	}
	if !os.IsNotExist(errors.Unwrap(err)) {
		t.Errorf("errors.Unwrap(Delete() error) = %v, want it to satisfy os.IsNotExist", errors.Unwrap(err))
	}
}

func TestDelete_RemovesRealFile(t *testing.T) {
	dataDir := t.TempDir()
	info, err := Create(dataDir, "pw", []byte("data"), "", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := Delete(dataDir, info.Name); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	got, err := List(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("List() after Delete = %+v, want empty", got)
	}
}

func TestImport_WritesBytesVerbatim(t *testing.T) {
	dataDir := t.TempDir()
	raw := []byte("already-encrypted-blob-content")

	info, err := Import(dataDir, "backup-20260101-000000.enc", raw, "", false)
	if err != nil {
		t.Fatalf("Import() error = %v", err)
	}
	if info.Size != int64(len(raw)) {
		t.Errorf("Import() size = %d, want %d", info.Size, len(raw))
	}
	got, err := Read(dataDir, info.Name)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if string(got) != string(raw) {
		t.Errorf("Import()+Read() round trip = %q, want %q", got, raw)
	}
}

func TestImport_RejectsPathTraversalName(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := Import(dataDir, "../../../etc/passwd", []byte("x"), "", false); err != ErrInvalidName {
		t.Fatalf("Import() error = %v, want ErrInvalidName", err)
	}
}

func TestPrune_KeepsOnlyNewestRetainCount(t *testing.T) {
	dataDir := t.TempDir()
	dir := Dir(dataDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	names := []string{
		"backup-20260101-000000.enc",
		"backup-20260102-000000.enc",
		"backup-20260103-000000.enc",
	}
	for i, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o640); err != nil {
			t.Fatal(err)
		}
		ts := time.Now().Add(time.Duration(i) * time.Hour)
		if err := os.Chtimes(filepath.Join(dir, n), ts, ts); err != nil {
			t.Fatal(err)
		}
		if err := writeAutomatedMarker(dataDir, n); err != nil {
			t.Fatal(err)
		}
	}

	if err := Prune(dataDir, 2); err != nil {
		t.Fatalf("Prune() error = %v", err)
	}
	got, err := List(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("List() after Prune = %+v, want 2 entries", got)
	}
	for _, info := range got {
		if info.Name == names[0] {
			t.Fatalf("Prune() kept the oldest file %q, should have removed it", names[0])
		}
	}
}

func TestPrune_NeverDeletesManualBackups(t *testing.T) {
	dataDir := t.TempDir()
	dir := Dir(dataDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}

	write := func(name string, hoursAgo int, automated bool) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o640); err != nil {
			t.Fatal(err)
		}
		ts := time.Now().Add(-time.Duration(hoursAgo) * time.Hour)
		if err := os.Chtimes(filepath.Join(dir, name), ts, ts); err != nil {
			t.Fatal(err)
		}
		if automated {
			if err := writeAutomatedMarker(dataDir, name); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Oldest of all, manual — must survive regardless of rank.
	write("backup-20260101-000000.enc", 100, false)
	// Three automated backups, newest-first when hoursAgo shrinks.
	write("backup-20260102-000000.enc", 3, true)
	write("backup-20260103-000000.enc", 2, true)
	write("backup-20260104-000000.enc", 1, true)

	if err := Prune(dataDir, 2); err != nil {
		t.Fatalf("Prune() error = %v", err)
	}
	got, err := List(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	names := make(map[string]bool, len(got))
	for _, info := range got {
		names[info.Name] = true
	}
	if !names["backup-20260101-000000.enc"] {
		t.Error("Prune() removed the manual backup — manual backups must never be pruned")
	}
	if !names["backup-20260103-000000.enc"] || !names["backup-20260104-000000.enc"] {
		t.Errorf("Prune() should have kept the 2 newest automated backups, got: %+v", got)
	}
	if names["backup-20260102-000000.enc"] {
		t.Error("Prune() should have removed the 3rd-newest automated backup (beyond retain=2)")
	}
	if len(got) != 3 {
		t.Errorf("List() after Prune = %+v, want exactly 3 entries (1 manual + 2 kept automated)", got)
	}
}

func TestPrune_NonPositiveRetainIsNoop(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := Create(dataDir, "pw", []byte("data"), "", false); err != nil {
		t.Fatal(err)
	}
	if err := Prune(dataDir, 0); err != nil {
		t.Fatalf("Prune(0) error = %v", err)
	}
	got, err := List(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("List() after Prune(0) = %+v, want unchanged 1 entry", got)
	}
}
