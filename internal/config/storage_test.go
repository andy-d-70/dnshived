// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSingle(t *testing.T, c *Cluster) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cluster.json")
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMigrateToSplit_KeepsTheDocumentAndALegacyCopy(t *testing.T) {
	c := splitFixture()
	path := writeSingle(t, c)
	before, _ := Load(path)

	moved, err := MigrateToSplit(path)
	if err != nil || !moved {
		t.Fatalf("moved %v, err %v", moved, err)
	}
	if fileExists(path) {
		t.Error("the single file must be gone after a verified migration")
	}
	if !fileExists(path + ".pre-split") {
		t.Error("the one-time copy of the single file is missing")
	}
	if got := StorageFormat(path); got != StorageSplit {
		t.Errorf("format = %s", got)
	}
	after, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.ConfigDocumentHashV2() != before.ConfigDocumentHashV2() || after.ConfigDocumentHash() != before.ConfigDocumentHash() {
		t.Error("the configuration hashes changed by the migration")
	}
	if again, err := MigrateToSplit(path); err != nil || again {
		t.Errorf("a second migration must do nothing: %v %v", again, err)
	}
}

func TestSave_WritesOnlyTheChangedPartOnceSplit(t *testing.T) {
	path := writeSingle(t, splitFixture())
	if _, err := MigrateToSplit(path); err != nil {
		t.Fatal(err)
	}
	scopeFile := filepath.Join(SplitDir(path), "scopes", "lab.json")
	domainFile := filepath.Join(SplitDir(path), "domains", "av.lan.json")
	infoBefore, _ := os.Stat(scopeFile)

	c, _ := Load(path)
	c.LocalDomains[1].TTL = 120
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	if fileExists(path) {
		t.Error("a save of a split configuration must not recreate the single file")
	}
	infoAfter, _ := os.Stat(scopeFile)
	if !infoAfter.ModTime().Equal(infoBefore.ModTime()) {
		t.Error("an untouched scope part was rewritten")
	}
	raw, _ := os.ReadFile(domainFile)
	if !strings.Contains(string(raw), "120") {
		t.Errorf("the changed domain part was not written: %s", raw)
	}
	back, _ := Load(path)
	if back.LocalDomains[1].TTL != 120 {
		t.Error("the change did not come back")
	}
}

func TestSave_RemovesPartsAndKeepsSplitWhenAScopeIsDeleted(t *testing.T) {
	path := writeSingle(t, splitFixture())
	MigrateToSplit(path)
	c, _ := Load(path)
	delete(c.Scopes, "lab")
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	if fileExists(filepath.Join(SplitDir(path), "scopes", "lab.json")) {
		t.Error("the part of the deleted scope must be removed")
	}
	if StorageFormat(path) != StorageSplit {
		t.Error("still split")
	}
}

func TestMigrateToSplit_CrashBeforeTheSingleFileIsRemovedLoadsTheSingleFile(t *testing.T) {
	path := writeSingle(t, splitFixture())
	if err := SaveSplit(SplitDir(path), mustLoad(t, path)); err != nil {
		t.Fatal(err)
	}
	if StorageFormat(path) != StorageSingle || splitActive(path) {
		t.Fatal("with both present the single file wins")
	}
	c := mustLoad(t, path)
	c.LogLevel = "debug"
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	if !fileExists(path) {
		t.Fatal("a save with both present writes the single file")
	}
	if moved, err := MigrateToSplit(path); err != nil || !moved {
		t.Fatalf("the next start migrates again: %v %v", moved, err)
	}
	if mustLoad(t, path).LogLevel != "debug" {
		t.Error("the newer single file was lost to the stale directory")
	}
}

func mustLoad(t *testing.T, path string) *Cluster {
	t.Helper()
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestMigrateToSingle_IsTheWayBack(t *testing.T) {
	path := writeSingle(t, splitFixture())
	want := mustLoad(t, path).ConfigDocumentHashV2()
	MigrateToSplit(path)
	moved, err := MigrateToSingle(path)
	if err != nil || !moved {
		t.Fatalf("%v %v", moved, err)
	}
	if StorageFormat(path) != StorageSingle || fileExists(SplitDir(path)) {
		t.Error("the single file must be back and the directory gone")
	}
	if mustLoad(t, path).ConfigDocumentHashV2() != want {
		t.Error("the way back changed the document")
	}
	if again, _ := MigrateToSingle(path); again {
		t.Error("a second way back does nothing")
	}
}

func TestStampPathAndExists_FollowTheStorageFormat(t *testing.T) {
	path := writeSingle(t, splitFixture())
	if StampPath(path) != path || !Exists(path) {
		t.Error("single")
	}
	MigrateToSplit(path)
	if StampPath(path) != filepath.Join(SplitDir(path), "manifest.json") || !Exists(path) {
		t.Errorf("split: %s", StampPath(path))
	}
	empty := filepath.Join(t.TempDir(), "cluster.json")
	if Exists(empty) || StorageFormat(empty) != StorageNone {
		t.Error("none")
	}
	if moved, err := MigrateToSplit(empty); moved || err != nil {
		t.Error("nothing to migrate is not an error")
	}
}

func TestLoad_SplitRetriesWhenAPartIsOutOfStep(t *testing.T) {
	path := writeSingle(t, splitFixture())
	MigrateToSplit(path)
	part := filepath.Join(SplitDir(path), "scopes", "office.json")
	good, _ := os.ReadFile(part)
	os.WriteFile(part, []byte(`{"tampered":true}`), 0o600)
	go func() {
		os.WriteFile(part, good, 0o600)
	}()
	if _, err := Load(path); err != nil {
		t.Logf("a part that never settles is refused: %v", err)
	}
	os.WriteFile(part, []byte(`{"tampered":true}`), 0o600)
	if _, err := Load(path); err == nil {
		t.Error("a tampered part must be refused after the retries")
	}
}

func TestDocument_IsTheSameForBothFormats(t *testing.T) {
	path := writeSingle(t, splitFixture())
	a, err := Document(path)
	if err != nil {
		t.Fatal(err)
	}
	MigrateToSplit(path)
	b, err := Document(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Error("print-config must answer the same document before and after the migration")
	}
}

func TestSave_RevisionAndNodeFieldsAreStoredEvenThoughTheyAreNotHashed(t *testing.T) {
	path := writeSingle(t, splitFixture())
	if _, err := MigrateToSplit(path); err != nil {
		t.Fatal(err)
	}
	c := mustLoad(t, path)
	c.ConfigRevision = 99
	c.ConfigRevisionOrigin = "core-9"
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	back := mustLoad(t, path)
	if back.ConfigRevision != 99 || back.ConfigRevisionOrigin != "core-9" {
		t.Errorf("a revision only change must reach the disk: revision %d origin %q", back.ConfigRevision, back.ConfigRevisionOrigin)
	}

	office := c.Scopes["office"]
	office.NodeIP = "192.168.100.77/24"
	c.Scopes["office"] = office
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	if got := mustLoad(t, path).Scopes["office"].NodeIP; got != "192.168.100.77/24" {
		t.Errorf("a node address only change must reach the disk, got %q", got)
	}
}

func TestLoad_ManifestRevisionWinsOverAStaleBasePart(t *testing.T) {
	path := writeSingle(t, splitFixture())
	MigrateToSplit(path)
	c := mustLoad(t, path)
	m, files, err := c.Split()
	if err != nil {
		t.Fatal(err)
	}
	m.Revision = c.ConfigRevision + 5
	got, err := Assemble(m, func(p string) ([]byte, error) { return files[p], nil })
	if err != nil {
		t.Fatal(err)
	}
	if got.ConfigRevision != c.ConfigRevision+5 {
		t.Errorf("revision %d, want the manifest's %d", got.ConfigRevision, c.ConfigRevision+5)
	}
}
