package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPrepareSocket_MissingPathIsFine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "helper.sock")
	if err := prepareSocket(path); err != nil {
		t.Fatalf("prepareSocket: %v", err)
	}
}

func TestPrepareSocket_RefusesRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "helper.sock")
	if err := os.WriteFile(path, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareSocket(path); err == nil {
		t.Fatal("prepareSocket returned nil for a regular file, want an error")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("regular file was removed: %v", err)
	}
}

func TestPrepareSocket_RemovesStaleSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "helper.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("stale socket not left behind: %v", err)
	}
	if err := prepareSocket(path); err != nil {
		t.Fatalf("prepareSocket: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("stale socket still present: %v", err)
	}
}

func TestHandleConn_OversizeRequestRejected(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	go handleConn(server)

	go func() {
		oversize := `{"command":"` + strings.Repeat("a", int(helperMaxRequestSize)+1024) + `"}`
		client.Write([]byte(oversize))
	}()

	var resp Response
	if err := json.NewDecoder(client).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.OK || !strings.HasPrefix(resp.Error, "invalid request") {
		t.Fatalf("resp = %+v, want an invalid-request error", resp)
	}
}

func TestHandleConn_IdleClientTimesOut(t *testing.T) {
	old := helperConnDeadline
	helperConnDeadline = 100 * time.Millisecond
	defer func() { helperConnDeadline = old }()

	server, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		handleConn(server)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleConn still blocked on an idle client after its deadline")
	}
}

func TestPeerCred_NonUnixConnIsUnknown(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	if got := peerCred(server); got != "unknown" {
		t.Fatalf("peerCred(pipe) = %q, want unknown", got)
	}
}

func TestPeerCred_UnixConnNamesThisProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := net.Dial("unix", path)
		if err == nil {
			defer c.Close()
			time.Sleep(200 * time.Millisecond)
		}
	}()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	got := peerCred(conn)
	if !strings.Contains(got, "uid=") || !strings.Contains(got, "pid=") {
		t.Fatalf("peerCred(unix) = %q, want uid= and pid=", got)
	}
}
