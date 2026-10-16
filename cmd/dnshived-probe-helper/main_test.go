// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// requireDnshivedGroup mirrors internal/agent's own identical skip
// precedent.
func requireDnshivedGroup(t *testing.T) {
	t.Helper()
	if _, err := user.LookupGroup("dnshived"); err != nil {
		t.Skipf("no \"dnshived\" group on this host, skipping: %v", err)
	}
}

// TestRestartSelf_Throttled pins the same "throttled means not applied"
// contract dnshived-helper's own rate-limited verbs use.
func TestRestartSelf_Throttled(t *testing.T) {
	restartMu.Lock()
	lastRestartAt = time.Now()
	restartMu.Unlock()

	throttled, err := restartSelf()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !throttled {
		t.Errorf("throttled = false, want true — a restart within 10s of the last one must be reported as suppressed")
	}
}

// TestRestartSelf_NotThrottledAfterWindow verifies the rate limit doesn't
// fire once the 10s window has passed.
func TestRestartSelf_NotThrottledAfterWindow(t *testing.T) {
	restartMu.Lock()
	lastRestartAt = time.Now().Add(-11 * time.Second)
	restartMu.Unlock()

	throttled, _ := restartSelf()
	if throttled {
		t.Errorf("throttled = true, want false — restart should not be rate-limited once the 10s window has passed")
	}
}

func TestWriteConfig_WritesExactContentAtomically(t *testing.T) {
	orig := probeConfigPath
	dir := t.TempDir()
	probeConfigPath = dir + "/probe.json"
	defer func() { probeConfigPath = orig }()

	content := []byte(`{"listen_addr":"0.0.0.0:9444"}`)
	if err := writeConfig(content); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := os.ReadFile(probeConfigPath)
	if err != nil {
		t.Fatalf("expected file to exist: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("written content = %q, want %q", got, content)
	}
	if _, err := os.Stat(probeConfigPath + ".tmp"); err == nil {
		t.Error("temp file left behind after a successful write")
	}
}

func TestWriteConfig_ChownsToDnshivedGroup(t *testing.T) {
	requireDnshivedGroup(t)

	orig := probeConfigPath
	dir := t.TempDir()
	probeConfigPath = dir + "/probe.json"
	defer func() { probeConfigPath = orig }()

	if err := writeConfig([]byte(`{"listen_addr":"0.0.0.0:9444"}`)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	fi, err := os.Stat(probeConfigPath)
	if err != nil {
		t.Fatalf("expected file to exist: %v", err)
	}
	gid := fi.Sys().(*syscall.Stat_t).Gid
	g, err := user.LookupGroup("dnshived")
	if err != nil {
		t.Fatalf("lookup dnshived group: %v", err)
	}
	wantGid, _ := strconv.Atoi(g.Gid)
	if int(gid) != wantGid {
		t.Errorf("group = %d, want %d (dnshived)", gid, wantGid)
	}
}

func TestChownToDnshivedGroup_DirectCall(t *testing.T) {
	requireDnshivedGroup(t)

	f, err := os.CreateTemp(t.TempDir(), "chown-test")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	f.Close()

	if err := chownToDnshivedGroup(f.Name()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestParseTrunkParents_ParsesTrimsAndDropsBlanks mirrors
// dnshived-helper's own TestParseScopeAllowlist coverage exactly, for the
// identical parsing logic.
func TestParseTrunkParents_ParsesTrimsAndDropsBlanks(t *testing.T) {
	got := parseTrunkParents(" ens19 , ens20,, ")
	if len(got) != 2 || !got["ens19"] || !got["ens20"] {
		t.Errorf("parseTrunkParents = %v, want {ens19, ens20}", got)
	}
}

func TestParseTrunkParents_EmptyInputYieldsEmptyNotNilMap(t *testing.T) {
	got := parseTrunkParents("")
	if got == nil {
		t.Fatal("expected a non-nil empty map for empty input")
	}
	if len(got) != 0 {
		t.Errorf("expected empty map, got %v", got)
	}
}

func TestTrunkParentsFromContent_ParsesField(t *testing.T) {
	got := trunkParentsFromContent([]byte(`{"trunk_parents": ["ens19", " ens20 ", ""]}`))
	if len(got) != 2 || !got["ens19"] || !got["ens20"] {
		t.Errorf("trunkParentsFromContent = %v, want {ens19, ens20}", got)
	}
}

func TestTrunkParentsFromContent_ToleratesMissingOrMalformed(t *testing.T) {
	for _, content := range [][]byte{nil, []byte(""), []byte("not json"), []byte(`{"trunk_parents": []}`), []byte(`{}`)} {
		if got := trunkParentsFromContent(content); len(got) != 0 {
			t.Errorf("trunkParentsFromContent(%q) = %v, want empty/nil, not an error", content, got)
		}
	}
}

func TestRefreshAllowedTrunkParents_UnionsFlagAndFile(t *testing.T) {
	origFlag, origAllowed := flagTrunkParents, allowedTrunkParents
	defer func() { flagTrunkParents, allowedTrunkParents = origFlag, origAllowed }()

	flagTrunkParents = map[string]bool{"ens18": true}
	names := refreshAllowedTrunkParents(map[string]bool{"ens19": true, "ens20": true})

	if len(names) != 3 {
		t.Fatalf("refreshAllowedTrunkParents returned %v, want 3 names (ens18 from the flag, ens19/ens20 from the file)", names)
	}
	for _, want := range []string{"ens18", "ens19", "ens20"} {
		if !isTrunkParentAllowed(want) {
			t.Errorf("isTrunkParentAllowed(%q) = false, want true after refresh", want)
		}
	}
}

// TestValidateInterfaceReq_RejectsUnallowedParent pins the actual security
// boundary this command pair exists to enforce.
func TestValidateInterfaceReq_RejectsUnallowedParent(t *testing.T) {
	orig := allowedTrunkParents
	allowedTrunkParents = map[string]bool{"ens19": true}
	defer func() { allowedTrunkParents = orig }()

	if err := validateInterfaceReq(Request{Parent: "eth0", VLANID: 100}); err == nil {
		t.Error("expected an error for a parent not in the allowlist")
	}
	if err := validateInterfaceReq(Request{Parent: "ens19", VLANID: 100}); err != nil {
		t.Errorf("unexpected error for an allowed parent: %v", err)
	}
}

func TestValidateInterfaceReq_RejectsOutOfRangeVLANID(t *testing.T) {
	orig := allowedTrunkParents
	allowedTrunkParents = map[string]bool{"ens19": true}
	defer func() { allowedTrunkParents = orig }()

	for _, vlan := range []int{-1, 4095, 100000} {
		if err := validateInterfaceReq(Request{Parent: "ens19", VLANID: vlan}); err == nil {
			t.Errorf("vlan_id %d: expected an error, got nil", vlan)
		}
	}
	if err := validateInterfaceReq(Request{Parent: "ens19", VLANID: 0}); err != nil {
		t.Errorf("vlan_id 0 (untagged, boundary): unexpected error: %v", err)
	}
	if err := validateInterfaceReq(Request{Parent: "ens19", VLANID: 1}); err != nil {
		t.Errorf("vlan_id 1 (boundary): unexpected error: %v", err)
	}
	if err := validateInterfaceReq(Request{Parent: "ens19", VLANID: 4094}); err != nil {
		t.Errorf("vlan_id 4094 (boundary): unexpected error: %v", err)
	}
}

func TestWriteConfig_RejectsEmptyContent(t *testing.T) {
	orig := probeConfigPath
	dir := t.TempDir()
	probeConfigPath = dir + "/probe.json"
	defer func() { probeConfigPath = orig }()

	if err := writeConfig(nil); err == nil {
		t.Error("writeConfig(nil) returned nil error, want a rejection")
	}
	if _, err := os.Stat(probeConfigPath); err == nil {
		t.Error("probe.json was created despite empty content — must never happen")
	}
}

// TestGetJournalTail_RejectsUnlistedUnit mirrors dnshived-helper's own
// identical guard (cmd/dnshived-helper/main_test.go).
func TestGetJournalTail_RejectsUnlistedUnit(t *testing.T) {
	_, err := getJournalTail(Request{Command: "journal-tail", Unit: "sshd.service"})
	if err == nil {
		t.Fatal("expected an error for a unit outside allowedJournalUnits, got nil")
	}
}

// TestGetJournalTail_AllowsRealUnits confirms both units this probe helper
// actually manages are in the allowlist.
func TestGetJournalTail_AllowsRealUnits(t *testing.T) {
	for _, u := range []string{"dnshived-probe.service", "dnshived-probe-helper.service"} {
		if !allowedJournalUnits[u] {
			t.Errorf("expected %s in allowedJournalUnits", u)
		}
	}
}

func TestDecommissionProbe_WipesConfigAndStateDirs(t *testing.T) {
	origCfg, origState, origParents := probeConfigPath, probeStateDir, allowedTrunkParents
	t.Cleanup(func() {
		probeConfigPath, probeStateDir, allowedTrunkParents = origCfg, origState, origParents
	})

	cfgDir := t.TempDir()
	stateDir := t.TempDir()
	probeConfigPath = cfgDir + "/probe.json"
	probeStateDir = stateDir
	allowedTrunkParents = map[string]bool{"nosuchtrunk-zzz": true}

	for _, f := range []string{cfgDir + "/probe.json", cfgDir + "/probe.json.tmp", cfgDir + "/leftover.bak"} {
		if err := os.WriteFile(f, []byte("secret"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(stateDir+"/backups", 0o750); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{stateDir + "/known-vlans.json", stateDir + "/events.ndjson", stateDir + "/backups/old.enc"} {
		if err := os.WriteFile(f, []byte("x"), 0o640); err != nil {
			t.Fatal(err)
		}
	}

	summary := decommissionProbe()
	if summary == "" {
		t.Error("expected a non-empty summary line")
	}

	for _, dir := range []string{cfgDir, stateDir} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("directory %s must still exist after decommission: %v", dir, err)
		}
		if len(entries) != 0 {
			t.Errorf("directory %s not emptied — still holds %d entry(ies)", dir, len(entries))
		}
	}
}
