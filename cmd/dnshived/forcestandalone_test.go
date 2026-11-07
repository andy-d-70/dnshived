// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dnshived/internal/config"
)

func standaloneFixture(t *testing.T) (path string, dataDir string) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, "cluster.json")
	c := &config.Cluster{
		SchemaVersion: 2, ClusterID: "lab-cluster", NodeID: "core-1-abc", Role: config.RoleCore1,
		ControlAddr: "192.0.2.1:9443", DataDir: dir, PSK: testPSK,
		Peers: []string{"192.0.2.2:9443", "192.0.2.3:9443"}, Platform: testPlatform(),
		MembershipEpoch: 2, ConfigRevision: 7,
	}
	if err := config.Save(path, c); err != nil {
		t.Fatal(err)
	}
	return path, dir
}

func withRootAndChown(t *testing.T, chown func(string) error) {
	t.Helper()
	oldEuid, oldChown := geteuid, chownConfig
	geteuid, chownConfig = func() int { return 0 }, chown
	t.Cleanup(func() { geteuid, chownConfig = oldEuid, oldChown })
}

func TestStandaloneConfig(t *testing.T) {
	in := &config.Cluster{Peers: []string{"a", "b"}, MembershipEpoch: 4, ConfigRevision: 9, ClusterID: "c"}
	out := standaloneConfig(in)
	if len(out.Peers) != 0 || out.MembershipEpoch != 5 || out.ConfigRevision != 9 || out.ClusterID != "c" {
		t.Errorf("out = %+v", out)
	}
	if len(in.Peers) != 2 || in.MembershipEpoch != 4 {
		t.Error("the input was changed")
	}
}

func TestRunForceStandalone_ConfirmedChangesTheNode(t *testing.T) {
	path, dir := standaloneFixture(t)
	var chowned string
	withRootAndChown(t, func(p string) error { chowned = p; return nil })
	var out bytes.Buffer
	if err := runForceStandalone(path, strings.NewReader("lab-cluster\n"), &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	got, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Peers) != 0 || got.MembershipEpoch != 3 || got.ConfigRevision != 7 || got.PSK != testPSK {
		t.Errorf("config after = peers %v epoch %d rev %d", got.Peers, got.MembershipEpoch, got.ConfigRevision)
	}
	if chowned != path {
		t.Errorf("chown called for %q, want %q: the daemon could not read the file otherwise", chowned, path)
	}
	audit, err := os.ReadFile(filepath.Join(dir, "audit.log"))
	if err != nil || !strings.Contains(string(audit), "cluster.force_standalone") {
		t.Errorf("no audit line: %v %q", err, audit)
	}
	for _, want := range []string{"FORCE STANDALONE", "192.0.2.2:9443", "epoch goes from 2 to 3", "systemctl restart dnshived"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q", want)
		}
	}
}

func TestRunForceStandalone_RefusesWithoutTheClusterID(t *testing.T) {
	path, _ := standaloneFixture(t)
	withRootAndChown(t, func(string) error { t.Error("chown called"); return nil })
	before, _ := os.ReadFile(path)
	for _, answer := range []string{"\n", "yes\n", "LAB-CLUSTER\n", ""} {
		if err := runForceStandalone(path, strings.NewReader(answer), &bytes.Buffer{}); err == nil {
			t.Errorf("answer %q was accepted", answer)
		}
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Error("the config changed without a confirmation")
	}
}

func TestRunForceStandalone_NeedsRoot(t *testing.T) {
	path, _ := standaloneFixture(t)
	oldEuid := geteuid
	geteuid = func() int { return 1000 }
	defer func() { geteuid = oldEuid }()
	if err := runForceStandalone(path, strings.NewReader("lab-cluster\n"), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "root") {
		t.Errorf("err = %v", err)
	}
	if got, _ := config.Load(path); len(got.Peers) != 2 {
		t.Error("the config changed for a non-root caller")
	}
}

func TestRunForceStandalone_ReportsAChownFailure(t *testing.T) {
	path, _ := standaloneFixture(t)
	withRootAndChown(t, func(string) error { return errors.New("no such user") })
	err := runForceStandalone(path, strings.NewReader("lab-cluster\n"), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "dnshived account") {
		t.Errorf("err = %v: a file the daemon cannot read must be reported", err)
	}
}

func TestRunForceStandalone_MissingConfig(t *testing.T) {
	withRootAndChown(t, func(string) error { return nil })
	if err := runForceStandalone(filepath.Join(t.TempDir(), "none.json"), strings.NewReader("x\n"), &bytes.Buffer{}); err == nil {
		t.Error("no error for a missing config")
	}
}

func TestOutageStateEvaluate(t *testing.T) {
	s := &outageState{startedAt: time.Now().Add(-time.Minute)}
	cur := &config.Cluster{ConfigRevision: 3, Peers: []string{"a:1"}, MembershipEpoch: 1}
	ahead := []peerView{{Addr: "a:1", Reachable: true, Known: true, Revision: 5, Hash: "h5", MembershipEpoch: 2}}
	start, member := s.evaluate(cur, "h3", "", ahead, time.Now())
	if start != "" || member != "" {
		t.Errorf("holds returned while the rules are off: %q %q", start, member)
	}
	if st, _, m := s.view(); st != cfgBehind || m == "" {
		t.Errorf("the verdicts must still be published for display: %q %q", st, m)
	}
	s.rules.active.Store(true)
	start, member = s.evaluate(cur, "h3", "", ahead, time.Now())
	if start == "" || member == "" || !s.membershipHeld() {
		t.Errorf("holds missing with the rules on: %q %q", start, member)
	}
	agree := []peerView{{Addr: "a:1", Reachable: true, Known: true, Revision: 3, Hash: "h3", MembershipEpoch: 1}}
	start, member = s.evaluate(cur, "h3", "", agree, time.Now())
	if start != "" || member != "" || s.membershipHeld() {
		t.Errorf("holds not released: %q %q", start, member)
	}
}
