// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dnshived/internal/dnsfeed"
)

func TestStartDNSFeed_ReplacesAStaleSocketAndRefusesOtherFiles(t *testing.T) {
	dir, err := os.MkdirTemp("", "feed")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "dnsfeed.sock")
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = stale.Close()

	ctx, cancel := context.WithCancel(context.Background())
	pub := dnsfeed.NewPublisher(dnsfeed.Options{})
	if err := startDNSFeed(ctx, path, pub); err != nil {
		t.Fatalf("a stale socket is replaced: %v", err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o660 {
		t.Fatalf("the socket is reachable for the service group only: %v %v", fi, err)
	}
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("the feed accepts connections: %v", err)
	}
	c.Close()
	cancel()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(path); err != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Lstat(path); err == nil {
		t.Fatal("the socket file is removed when the feed stops")
	}

	other := filepath.Join(dir, "precious")
	if err := os.WriteFile(other, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := startDNSFeed(context.Background(), other, pub); err == nil {
		t.Fatal("a regular file at the path is not replaced")
	}
	if b, _ := os.ReadFile(other); string(b) != "data" {
		t.Fatal("the file is untouched")
	}
}
