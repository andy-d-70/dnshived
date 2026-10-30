// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package relaygate

import (
	"encoding/json"
	"net"
	"path/filepath"
	"testing"

	"dnshived/internal/unixsock"
)

// fakeRelay answers each request with reply and records the requests it received.
func fakeRelay(t *testing.T, reply string) (string, *[]map[string]any) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gate.sock")
	srv, err := unixsock.Listen(path, 0o660, unixsock.Limits{MaxConns: 4, Deadline: 5e9, MaxRequest: 1 << 16, DrainTimeout: 5e9})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	var seen []map[string]any
	go srv.Serve(func(c net.Conn) {
		var req map[string]any
		json.NewDecoder(c).Decode(&req)
		seen = append(seen, req)
		c.Write([]byte(reply + "\n"))
	}, func(unixsock.Peer, error) {})
	return path, &seen
}

func TestAuthorizeSendsTokensAndReturnsDeadline(t *testing.T) {
	path, seen := fakeRelay(t, `{"ok":true,"deadline":"2026-10-25T12:00:00Z"}`)
	c := &Client{Path: path}
	tokens := []json.RawMessage{json.RawMessage(`{"scope":"office"}`), json.RawMessage(`{"scope":"office","arbiter":"core-2"}`)}
	deadline, err := c.Authorize("office", 7, tokens, "witness renewed")
	if err != nil || deadline != "2026-10-25T12:00:00Z" {
		t.Fatalf("authorize = %q, %v", deadline, err)
	}
	req := (*seen)[0]
	if req["command"] != "authorize" || req["scope"] != "office" || req["incarnation"] != float64(7) {
		t.Fatalf("request = %v", req)
	}
	if len(req["tokens"].([]any)) != 2 {
		t.Fatalf("tokens = %v", req["tokens"])
	}
}

func TestRelayErrorIsReturned(t *testing.T) {
	path, _ := fakeRelay(t, `{"ok":false,"error":"quorum"}`)
	c := &Client{Path: path}
	if _, err := c.Authorize("office", 7, nil, ""); err == nil || err.Error() != "quorum" {
		t.Fatalf("err = %v, want quorum", err)
	}
}

func TestSetPSKRevokeAndRevokeAll(t *testing.T) {
	path, seen := fakeRelay(t, `{"ok":true}`)
	c := &Client{Path: path}
	if err := c.SetPSK("secret"); err != nil {
		t.Fatal(err)
	}
	if err := c.Revoke("office"); err != nil {
		t.Fatal(err)
	}
	if err := c.RevokeAll(); err != nil {
		t.Fatal(err)
	}
	cmds := []any{(*seen)[0]["command"], (*seen)[1]["command"], (*seen)[2]["command"]}
	if cmds[0] != "set-psk" || cmds[1] != "revoke" || cmds[2] != "revoke-all" {
		t.Fatalf("commands = %v", cmds)
	}
}

func TestMissingSocketIsAnError(t *testing.T) {
	c := &Client{Path: filepath.Join(t.TempDir(), "absent.sock")}
	if err := c.Revoke("office"); err == nil {
		t.Fatal("no error for a missing socket")
	}
}
