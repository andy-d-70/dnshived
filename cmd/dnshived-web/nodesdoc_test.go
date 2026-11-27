// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func nodesInstance(t *testing.T, name string, nodes []NodeConfig, version int64) (*listDoc, *configRef, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "web.json")
	cfg := &WebConfig{Nodes: append([]NodeConfig(nil), nodes...), NodesVersion: version, NodesUpdatedAt: "2026-11-27T10:00:00Z", NodesOrigin: "seed"}
	cfg.NodesHash = listHash(nodesSpec, cfg.Nodes)
	if err := saveWebConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	ref := newConfigRef(cfg)
	return newNodesDoc(ref, path, func() string { return name }), ref, path
}

func useNodesDoc(t *testing.T, d *listDoc) {
	t.Helper()
	prev, prevP := nodesShared, probeHostsShared
	nodesShared, probeHostsShared = d, nil
	t.Cleanup(func() { nodesShared, probeHostsShared = prev, prevP })
}

var seedNodes = []NodeConfig{
	{Name: "core1", Addr: "10.0.0.1:9443", TLS: true, AdminToken: "tok"},
	{Name: "core2", Addr: "10.0.0.2:9443", TLS: true, AdminToken: "tok"},
	{Name: "core3", Addr: "10.0.0.3:9443", TLS: true, AdminToken: "tok"},
}

func addrOf(ref *configRef, role string) string {
	for _, n := range ref.Load().Nodes {
		if n.Name == role {
			return n.Addr
		}
	}
	return "<absent>"
}

func replaced(cfg *WebConfig, role, addr string) *WebConfig {
	next := *cfg
	next.Nodes = append([]NodeConfig(nil), cfg.Nodes...)
	for i := range next.Nodes {
		if next.Nodes[i].Name == role {
			next.Nodes[i].Addr = addr
		}
	}
	return &next
}

func TestNodesDoc_AnInstanceThatMissedAReplacementCatchesUp(t *testing.T) {
	a, refA, pathA := nodesInstance(t, "core1", seedNodes, 1)
	b, refB, _ := nodesInstance(t, "core2", seedNodes, 1)
	useNodesDoc(t, a)
	if err := saveWebChange(pathA, refA, refA.Load(), replaced(refA.Load(), "core3", "10.0.0.33:9443")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Drift("core1"); err != nil {
		t.Fatal(err)
	}
	raw, _ := a.Marshal()
	if ok, _, err := b.Adopt(raw, "core1"); err != nil || !ok {
		t.Fatalf("the newer node list is taken: %v %v", ok, err)
	}
	if addrOf(refB, "core3") != "10.0.0.33:9443" {
		t.Fatalf("core2 now knows the replacement: %s", addrOf(refB, "core3"))
	}
	disk, err := loadWebConfig2(b.cfgPath)
	if err != nil || len(disk.Nodes) != 3 || disk.NodesVersion != refB.Load().NodesVersion {
		t.Fatalf("saved to web.json: %+v %v", disk, err)
	}
}

func TestNodesDoc_TheFirstJoinKeepsNodesOnlyThisInstanceKnew(t *testing.T) {
	a, _, _ := nodesInstance(t, "core1", seedNodes[:2], 1)
	b, refB, _ := nodesInstance(t, "core2", []NodeConfig{seedNodes[0], seedNodes[2]}, 0)
	raw, _ := a.Marshal()
	_, spread, err := b.Adopt(raw, "core1")
	if err != nil {
		t.Fatal(err)
	}
	if addrOf(refB, "core3") == "<absent>" || addrOf(refB, "core2") == "<absent>" || !spread {
		t.Fatalf("both lists are merged and the result spreads: %+v %v", refB.Load().Nodes, spread)
	}
}

func TestNodesDoc_StrictFirstWinsAndAFailedLocalSaveStaysPending(t *testing.T) {
	idx := newFakeIndex()
	a, refA, pathA := nodesInstance(t, "core1", seedNodes, 1)
	b, refB, pathB := nodesInstance(t, "core2", seedNodes, 1)
	for _, d := range []*listDoc{a, b} {
		d.strict = &usersStrict{latched: true, refresh: func() {}, getIndex: idx.get, post: idx.post, now: time.Now}
	}
	useNodesDoc(t, a)
	if err := saveWebChange(pathA, refA, refA.Load(), replaced(refA.Load(), "core3", "10.0.0.33:9443")); err != nil {
		t.Fatal(err)
	}
	useNodesDoc(t, b)
	err := saveWebChange(pathB, refB, refB.Load(), replaced(refB.Load(), "core3", "10.0.0.34:9443"))
	if err == nil || !strings.Contains(err.Error(), "node core3 was changed on core1") || addrOf(refB, "core3") != "10.0.0.3:9443" {
		t.Fatalf("the second version is refused: %v %s", err, addrOf(refB, "core3"))
	}

	useNodesDoc(t, a)
	webConfigWriter = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
	err = saveWebChange(pathA, refA, refA.Load(), replaced(refA.Load(), "core2", "10.0.0.22:9443"))
	webConfigWriter = writeFileAtomic
	if err == nil || addrOf(refA, "core2") != "10.0.0.2:9443" {
		t.Fatalf("the local save failed: %v", err)
	}
	if _, err := os.Stat(a.pendingPath()); err != nil {
		t.Fatal("ordered but not saved: the change stays pending")
	}
	a.settle()
	if addrOf(refA, "core2") != "10.0.0.22:9443" {
		t.Fatal("the next settle applies the ordered change")
	}
}

func TestSaveWebChange_RefusesOneSaveOfBothLists(t *testing.T) {
	a, refA, pathA := nodesInstance(t, "core1", seedNodes, 1)
	useNodesDoc(t, a)
	probeHostsShared = newProbeHostsDoc(refA, pathA, func() string { return "core1" })
	next := replaced(refA.Load(), "core3", "10.0.0.33:9443")
	next.ProbeHosts = []NodeConfig{{Name: "probe", Addr: "10.0.0.9:9443"}}
	if err := saveWebChange(pathA, refA, refA.Load(), next); err == nil {
		t.Fatal("a save that changes both replicated lists is refused")
	}
}

func TestWriteFileAtomic_ReplacesWholeAndLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "web.json")
	if err := os.WriteFile(path, []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(path, []byte("new content"), 0o640); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	fi, _ := os.Stat(path)
	if string(got) != "new content" || fi.Mode().Perm() != 0o640 {
		t.Fatalf("content %q mode %v", got, fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("no temp file left behind: %v", entries)
	}
	if err := writeFileAtomic(filepath.Join(dir, "missing", "web.json"), []byte("x"), 0o640); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a failed write reports it: %v", err)
	}
}
