// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package helper

import (
	"encoding/json"
	"net"
	"path/filepath"
	"testing"

	"dnshived/internal/unixsock"
)

// TestCreateInterfaceSendsTheVIP covers F3: the VIP reaches the helper, so it keeps keepalived's address.
func TestCreateInterfaceSendsTheVIP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "helper.sock")
	srv, err := unixsock.Listen(path, 0o660, unixsock.Limits{MaxConns: 4, Deadline: 5e9, MaxRequest: 1 << 16, DrainTimeout: 5e9})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	got := make(chan Request, 1)
	go srv.Serve(func(c net.Conn) {
		var req Request
		json.NewDecoder(c).Decode(&req)
		got <- req
		c.Write([]byte(`{"ok":true}` + "\n"))
	}, func(unixsock.Peer, error) {})

	c := NewClient(path)
	if err := c.CreateInterface("office", "ens19", 2, "192.168.2.51/24", "192.168.2.254/24"); err != nil {
		t.Fatal(err)
	}
	req := <-got
	if req.VIP != "192.168.2.254/24" || req.NodeIP != "192.168.2.51/24" {
		t.Fatalf("request = %+v, want the VIP and node IP", req)
	}
}
