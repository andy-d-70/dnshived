// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package probehelper

import (
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
)

// fakeHelperServer stands up a one-shot Unix-socket server that decodes
// exactly one Request, hands it to reply, and writes reply's return value
// back.
func fakeHelperServer(t *testing.T, reply func(Request) Response) string {
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
		var req Request
		if err := json.NewDecoder(conn).Decode(&req); err != nil {
			return
		}
		json.NewEncoder(conn).Encode(reply(req))
	}()
	return sock
}

func TestDecommission_SendsCommandAndSucceeds(t *testing.T) {
	var got Request
	sock := fakeHelperServer(t, func(r Request) Response {
		got = r
		return Response{OK: true}
	})

	if err := NewClient(sock).Decommission(); err != nil {
		t.Fatalf("Decommission: %v", err)
	}
	if got.Command != "decommission" {
		t.Errorf("helper received command %q, want %q", got.Command, "decommission")
	}
}

func TestDecommission_SurfacesHelperError(t *testing.T) {
	sock := fakeHelperServer(t, func(Request) Response {
		return Response{OK: false, Error: "delete-interface ens19.150: permission denied"}
	})

	err := NewClient(sock).Decommission()
	if err == nil {
		t.Fatal("expected an error when the helper reports OK=false")
	}
	if !contains(err.Error(), "permission denied") {
		t.Errorf("error does not surface the helper's own message: %v", err)
	}
}

func TestDecommission_ConnectErrorIsReturned(t *testing.T) {
	err := NewClient(filepath.Join(t.TempDir(), "does-not-exist.sock")).Decommission()
	if err == nil {
		t.Fatal("expected a connect error for a missing socket")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
