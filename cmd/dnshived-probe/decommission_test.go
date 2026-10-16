// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// fakeDecommHelperSock stands up a one-shot Unix-socket server that
// accepts exactly one connection, records the command it received, and
// replies OK.
func fakeDecommHelperSock(t *testing.T, gotCmd chan<- string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "probe-helper.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var req struct {
			Command string `json:"command"`
		}
		json.NewDecoder(conn).Decode(&req)
		gotCmd <- req.Command
		json.NewEncoder(conn).Encode(map[string]bool{"ok": true})
	}()
	return sock
}

func TestProbeSelfDecommission_NoHelperSocket_DoesNotReExec(t *testing.T) {
	orig := probeReExecFunc
	reExecCalled := false
	probeReExecFunc = func() { reExecCalled = true }
	t.Cleanup(func() { probeReExecFunc = orig })

	probeSelfDecommission(&ProbeConfig{}, "test") // ProbeHelperSocket == ""

	if reExecCalled {
		t.Error("probeSelfDecommission re-exec'd despite having no probe_helper_socket — it should abort with nothing changed")
	}
}

func TestProbeSelfDecommission_DialsHelperThenReExecs(t *testing.T) {
	gotCmd := make(chan string, 1)
	sock := fakeDecommHelperSock(t, gotCmd)

	orig := probeReExecFunc
	reExecCalled := make(chan struct{}, 1)
	probeReExecFunc = func() { reExecCalled <- struct{}{} }
	t.Cleanup(func() { probeReExecFunc = orig })

	probeSelfDecommission(&ProbeConfig{ProbeHelperSocket: sock}, "test")

	select {
	case c := <-gotCmd:
		if c != "decommission" {
			t.Errorf("helper received %q, want %q", c, "decommission")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("helper never received a command")
	}
	select {
	case <-reExecCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("probeReExecFunc was never called — a decommissioned probe must re-enter bootstrap mode")
	}
}
