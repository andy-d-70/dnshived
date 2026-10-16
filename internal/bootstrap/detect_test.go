// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package bootstrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectExisting_FreshNodeReportsNoFindings(t *testing.T) {
	dataDir := t.TempDir()

	f := DetectExisting(Paths{
		ClusterConfigPath: filepath.Join(t.TempDir(), "cluster.json"),
		ProbeConfigPath:   filepath.Join(t.TempDir(), "probe.json"),
		WebUsersPath:      filepath.Join(t.TempDir(), "webui-users.json"),
		DataDir:           dataDir,
		Units:             []string{"dnshived-bootstrap-test-nonexistent.service"},
	})

	if !f.Fresh() {
		t.Errorf("Fresh() = false, want true for a node with no configured evidence: %+v", f)
	}
}

// TestDetectExisting_MissingDataDirIsAsFreshAsEmpty covers the case where
// a fresh install hasn't even created data_dir yet.
func TestDetectExisting_MissingDataDirIsAsFreshAsEmpty(t *testing.T) {
	f := DetectExisting(Paths{DataDir: filepath.Join(t.TempDir(), "does-not-exist")})

	if len(f.DataDirEntries) != 0 {
		t.Errorf("DataDirEntries = %v, want empty for a data_dir that was never created", f.DataDirEntries)
	}
	if !f.Fresh() {
		t.Errorf("Fresh() = false, want true — a missing data_dir is not evidence of prior config")
	}
}

func TestDetectExisting_ClusterConfigPresentIsNotFresh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	if err := os.WriteFile(path, []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}

	f := DetectExisting(Paths{ClusterConfigPath: path})

	if f.ClusterConfigPath != path {
		t.Errorf("ClusterConfigPath = %q, want %q", f.ClusterConfigPath, path)
	}
	if f.Fresh() {
		t.Error("Fresh() = true, want false — cluster.json exists")
	}
}

// TestDetectExisting_ProbeConfigPresentIsNotFresh covers the probe-host
// case specifically.
func TestDetectExisting_ProbeConfigPresentIsNotFresh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "probe.json")
	if err := os.WriteFile(path, []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}

	f := DetectExisting(Paths{ProbeConfigPath: path})

	if f.ProbeConfigPath != path {
		t.Errorf("ProbeConfigPath = %q, want %q", f.ProbeConfigPath, path)
	}
	if f.Fresh() {
		t.Error("Fresh() = true, want false — probe.json exists")
	}
}

// TestDetectExisting_WebUsersPresentIsNotFresh covers a node that only
// ever had the web UI's credentials file set up.
func TestDetectExisting_WebUsersPresentIsNotFresh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "webui-users.json")
	if err := os.WriteFile(path, []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}

	f := DetectExisting(Paths{WebUsersPath: path})

	if f.WebUsersPath != path {
		t.Errorf("WebUsersPath = %q, want %q", f.WebUsersPath, path)
	}
	if f.Fresh() {
		t.Error("Fresh() = true, want false — webui-users.json exists")
	}
}

func TestDetectExisting_NonEmptyDataDirIsNotFresh(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "known-scopes.json"), []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}

	f := DetectExisting(Paths{DataDir: dataDir})

	if len(f.DataDirEntries) != 1 || f.DataDirEntries[0] != "known-scopes.json" {
		t.Errorf("DataDirEntries = %v, want [known-scopes.json]", f.DataDirEntries)
	}
	if f.Fresh() {
		t.Error("Fresh() = true, want false — data_dir has real state in it")
	}
}

// TestDetectExisting_ChecksAreAdditiveNotShortCircuited confirms every
// signal is captured independently.
func TestDetectExisting_ChecksAreAdditiveNotShortCircuited(t *testing.T) {
	dir := t.TempDir()
	clusterPath := filepath.Join(dir, "cluster.json")
	webPath := filepath.Join(dir, "webui-users.json")
	if err := os.WriteFile(clusterPath, []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(webPath, []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "fencing"), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}

	f := DetectExisting(Paths{
		ClusterConfigPath: clusterPath,
		WebUsersPath:      webPath,
		DataDir:           dataDir,
	})

	if f.ClusterConfigPath == "" || f.WebUsersPath == "" || len(f.DataDirEntries) == 0 {
		t.Errorf("expected all three signals captured together, got %+v", f)
	}
}

func TestDetectExisting_ActiveUnitIsNotFresh(t *testing.T) {
	f := DetectExisting(Paths{Units: []string{"cron.service"}})

	if len(f.ActiveUnits) == 0 {
		t.Skip("cron.service not active in this test environment — can't exercise the true-positive path here")
	}
	if f.Fresh() {
		t.Error("Fresh() = true, want false — an active unit was found")
	}
}

// TestFindings_StringMentionsEachFindingSpecifically pins that a refusal
// message actually names what was found.
func TestFindings_StringMentionsEachFindingSpecifically(t *testing.T) {
	f := Findings{
		ClusterConfigPath: "/etc/dnshived/cluster.json",
		DataDirEntries:    []string{"known-scopes.json"},
		ActiveUnits:       []string{"dnshived.service"},
	}

	s := f.String()
	for _, want := range []string{"/etc/dnshived/cluster.json", "known-scopes.json", "dnshived.service"} {
		if !strings.Contains(s, want) {
			t.Errorf("String() = %q, want it to mention %q", s, want)
		}
	}
}

func TestFindings_StringOnFreshSaysSo(t *testing.T) {
	if got := (Findings{}).String(); got != "no findings" {
		t.Errorf("String() on empty Findings = %q, want \"no findings\"", got)
	}
}
