// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestStatusTmpl_RendersTopoGraphAndSightingRows(t *testing.T) {
	data := overviewData{
		ClusterState: "STABLE",
		ClusterClass: "ok",
		PathRows: []clusterPathRow{
			{From: "core-1", To: "core-2", Trunk: "ens19", Class: "ok", Text: "reachable"},
		},
		TopoGraphSVG:     topoBeaconGraphSVG([]statusRow{rowWithTopology("core-1", "", []nodeTopoSighting{{MyIface: "ens19", MyKind: "trunk", PeerRole: "core-2", PeerIface: "ens19", PeerKind: "trunk"}})}, nil),
		TopoSightingRows: []topoSightingRow{{From: "core-1", MyIface: "ens19", MyKind: "trunk", PeerRole: "core-2", PeerIface: "ens19", PeerKind: "trunk", Count: 42, Age: "3s ago"}},
	}
	var buf bytes.Buffer
	if err := statusTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("statusTmpl.Execute failed: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "<svg") {
		t.Error("expected the connection graph's <svg> to render")
	}
	if !strings.Contains(out, "Physical topology (live)") {
		t.Error("expected the graph section heading to render")
	}
	if !strings.Contains(out, "Topology detail (debug)") {
		t.Error("expected the debug table section heading to render")
	}
	if !strings.Contains(out, "42") || !strings.Contains(out, "3s ago") {
		t.Error("expected the debug table's Count/Age columns to render")
	}
}

// TestStatusTmpl_NoTopoDataRendersNeitherSection confirms both new
// sections stay silent (no empty heading, no empty table) when there's
// simply nothing to show yet.
func TestStatusTmpl_NoTopoDataRendersNeitherSection(t *testing.T) {
	data := overviewData{
		ClusterState: "STABLE",
		ClusterClass: "ok",
		PathRows: []clusterPathRow{
			{From: "core-1", To: "core-2", Trunk: "ens19", Class: "ok", Text: "reachable"},
		},
	}
	var buf bytes.Buffer
	if err := statusTmpl.Execute(&buf, data); err != nil {
		t.Fatalf("statusTmpl.Execute failed: %v", err)
	}
	out := buf.String()

	if strings.Contains(out, "Physical topology (live)") {
		t.Error("graph section heading rendered despite empty TopoGraphSVG")
	}
	if strings.Contains(out, "Topology detail (debug)") {
		t.Error("debug table heading rendered despite empty TopoSightingRows")
	}
}
