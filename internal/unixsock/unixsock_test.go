// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package unixsock

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func limits() Limits {
	return Limits{MaxConns: 4, Deadline: 2 * time.Second, MaxRequest: 64, DrainTimeout: 2 * time.Second}
}

func TestListen_MissingPathIsFine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "helper.sock")
	srv, err := Listen(path, 0o660, limits())
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	srv.Close()
}

func TestListen_RefusesRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "helper.sock")
	if err := os.WriteFile(path, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path, 0o660, limits()); err == nil {
		t.Fatal("Listen returned nil for a regular file, want an error")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("regular file was removed: %v", err)
	}
}

func TestListen_ReplacesStaleSocketWithMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "helper.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()
	srv, err := Listen(path, 0o660, limits())
	if err != nil {
		t.Fatalf("Listen over a stale socket: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode = %v, err %v, want 0660", st.Mode().Perm(), err)
	}
	srv.Close()
}

func serve(t *testing.T, lim Limits, handler func(net.Conn), onDeny func(Peer, error)) (string, *Server) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s.sock")
	srv, err := Listen(path, 0o660, lim)
	if err != nil {
		t.Fatal(err)
	}
	if onDeny == nil {
		onDeny = func(Peer, error) {}
	}
	go srv.Serve(handler, onDeny)
	return path, srv
}

func TestServe_RequestIsCutAtTheSizeLimit(t *testing.T) {
	got := make(chan int, 1)
	path, srv := serve(t, limits(), func(c net.Conn) {
		b, _ := io.ReadAll(c)
		got <- len(b)
	}, nil)
	defer srv.Close()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte(strings.Repeat("a", 200)))
	c.(*net.UnixConn).CloseWrite()
	if n := <-got; n != 64 {
		t.Fatalf("handler read %d bytes, want 64", n)
	}
	c.Close()
}

func TestServe_IdleClientHitsTheDeadline(t *testing.T) {
	lim := limits()
	lim.Deadline = 150 * time.Millisecond
	done := make(chan struct{})
	path, srv := serve(t, lim, func(c net.Conn) {
		io.ReadAll(c)
		close(done)
	}, nil)
	defer srv.Close()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("idle connection still held after its deadline")
	}
}

func TestPeerCred_NonUnixConnIsAnError(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	if _, err := PeerCred(server); err == nil {
		t.Fatal("PeerCred(pipe) returned no error")
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
		if c, err := net.Dial("unix", path); err == nil {
			defer c.Close()
			time.Sleep(200 * time.Millisecond)
		}
	}()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer, err := PeerCred(conn)
	if err != nil || peer.PID != int32(os.Getpid()) {
		t.Fatalf("PeerCred = %v, %v; want pid %d", peer, err, os.Getpid())
	}
}

func TestServe_PeerOutsideAllowUIDsIsDenied(t *testing.T) {
	lim := limits()
	lim.AllowUIDs = []uint32{uint32(os.Getuid()) + 1}
	denied := make(chan Peer, 1)
	ran := make(chan struct{}, 1)
	path, srv := serve(t, lim, func(c net.Conn) { ran <- struct{}{} }, func(p Peer, err error) { denied <- p })
	defer srv.Close()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case <-denied:
	case <-time.After(2 * time.Second):
		t.Fatal("peer outside AllowUIDs not denied")
	}
	select {
	case <-ran:
		t.Fatal("handler ran for a denied peer")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestClose_LeavesAForeignSocketAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sock")
	srv, err := Listen(path, 0o660, limits())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	other, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	srv.Close()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("a socket that is not ours was removed: %v", err)
	}
}

func TestClose_RemovesOwnSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sock")
	srv, err := Listen(path, 0o660, limits())
	if err != nil {
		t.Fatal(err)
	}
	srv.Close()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("own socket still present after Close: %v", err)
	}
}

func TestClose_WaitsForRunningHandlers(t *testing.T) {
	started := make(chan struct{})
	path, srv := serve(t, limits(), func(c net.Conn) {
		close(started)
		time.Sleep(200 * time.Millisecond)
	}, nil)
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	<-started
	if left := srv.Close(); left != 0 {
		t.Fatalf("Close left %d handler(s) running after they finished", left)
	}
}

func TestRemoveStale_RefusesLiveSocketRemovesStale(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sock")
	live, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := RemoveStale(path); err == nil {
		t.Fatal("RemoveStale removed a socket that still accepts connections")
	}
	live.Close()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	ln.Close()
	if err := RemoveStale(path); err != nil {
		t.Fatalf("RemoveStale on a stale socket: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("stale socket not removed")
	}
}

func TestRemoveStale_RefusesRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveStale(path); err == nil {
		t.Fatal("RemoveStale removed a regular file")
	}
}
