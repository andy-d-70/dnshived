// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"dnsrelay/dnsanswer"
)

func feedBlob(t *testing.T, owner, ip string) []byte {
	t.Helper()
	spec := &dnsanswer.Spec{Zones: []dnsanswer.Zone{{Name: "example.lan"}}, Serial: 1, NegTTL: 60}
	rd, err := dnsanswer.RDataA(ip)
	if err != nil {
		t.Fatal(err)
	}
	spec.RRs = []dnsanswer.RR{{Owner: owner, Type: dnsanswer.TypeA, TTL: 60, RData: rd}}
	tb, err := spec.Build()
	if err != nil {
		t.Fatal(err)
	}
	return dnsanswer.EncodeTable(spec, tb.Digest())
}

type fakeFeed struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func (f *fakeFeed) stop() {
	_ = f.ln.Close()
	f.mu.Lock()
	for _, c := range f.conns {
		_ = c.Close()
	}
	f.mu.Unlock()
}

// startFakeFeed answers every reader's hello with one snapshot, the way the daemon's publisher does for a new reader.
func startFakeFeed(t *testing.T, path string, epoch uint64, blob []byte) *fakeFeed {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeFeed{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.conns = append(f.conns, c)
			f.mu.Unlock()
			go func() {
				defer c.Close()
				var h [4]byte
				if _, err := io.ReadFull(c, h[:]); err != nil {
					return
				}
				body := make([]byte, binary.LittleEndian.Uint32(h[:]))
				if _, err := io.ReadFull(c, body); err != nil {
					return
				}
				payload := binary.LittleEndian.AppendUint64([]byte{2}, epoch)
				payload = append(payload, blob...)
				frame := binary.LittleEndian.AppendUint32(nil, uint32(len(payload)))
				_, _ = c.Write(append(frame, payload...))
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

func shortSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "relayfeed")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "f.sock")
}

func answersFrom(t *testing.T, name string) (an int, ok bool) {
	tb := localTable.Load()
	if tb == nil {
		return 0, false
	}
	out, st := tb.Respond(tableQuery(name, dnsanswer.TypeA), nil, false)
	if st != dnsanswer.Answered {
		return 0, false
	}
	return int(binary.BigEndian.Uint16(out[6:])), true
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestFeed_ATableFromTheFeedIsServedAndTheFileIsLeftAlone(t *testing.T) {
	localTable.Store(nil)
	t.Cleanup(func() { localTable.Store(nil); setFeedSocket(context.Background(), ""); setTablePath("") })
	file := filepath.Join(t.TempDir(), "dnstable.bin")
	if err := os.WriteFile(file, feedBlob(t, "file.example.lan", "10.0.0.1"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setTablePath(file)
	go tableLoop(ctx)
	waitFor(t, "the table file", func() bool { n, ok := answersFrom(t, "file.example.lan"); return ok && n == 1 })

	sock := shortSocket(t)
	startFakeFeed(t, sock, 1, feedBlob(t, "feed.example.lan", "10.0.0.2"))
	setFeedSocket(ctx, sock)
	waitFor(t, "the table from the feed", func() bool { n, ok := answersFrom(t, "feed.example.lan"); return ok && n == 1 })
	if !feedActive() {
		t.Fatal("a table arrived through the feed")
	}
	if err := os.WriteFile(file, feedBlob(t, "file2.example.lan", "10.0.0.3"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1600 * time.Millisecond)
	if n, _ := answersFrom(t, "file2.example.lan"); n > 0 {
		t.Fatal("while the feed delivers, a changed table file is not read")
	}
	if n, ok := answersFrom(t, "feed.example.lan"); !ok || n != 1 {
		t.Fatal("the feed's table stays in use")
	}
}

func TestFeed_StoppingTheFeedDropsItsTableUnlessAFileIsConfigured(t *testing.T) {
	localTable.Store(nil)
	t.Cleanup(func() { localTable.Store(nil); setFeedSocket(context.Background(), ""); setTablePath("") })
	setTablePath("")
	sock := shortSocket(t)
	startFakeFeed(t, sock, 1, feedBlob(t, "feed.example.lan", "10.0.0.2"))
	setFeedSocket(context.Background(), sock)
	waitFor(t, "the table from the feed", func() bool { n, _ := answersFrom(t, "feed.example.lan"); return n == 1 })
	setFeedSocket(context.Background(), "")
	if localTable.Load() != nil || feedActive() {
		t.Fatal("without a table file the table goes away with the feed")
	}
}

func TestFeed_ARestartedPublisherIsFollowedAgain(t *testing.T) {
	localTable.Store(nil)
	t.Cleanup(func() { localTable.Store(nil); setFeedSocket(context.Background(), ""); setTablePath("") })
	setTablePath("")
	sock := shortSocket(t)
	first := startFakeFeed(t, sock, 1, feedBlob(t, "one.example.lan", "10.0.0.2"))
	setFeedSocket(context.Background(), sock)
	waitFor(t, "the first table", func() bool { n, _ := answersFrom(t, "one.example.lan"); return n == 1 })
	first.stop()
	_ = os.Remove(sock)
	if n, ok := answersFrom(t, "one.example.lan"); !ok || n != 1 {
		t.Fatal("the last table stays in use while the publisher is away")
	}
	startFakeFeed(t, sock, 2, feedBlob(t, "two.example.lan", "10.0.0.3"))
	waitFor(t, "the table of the restarted publisher", func() bool { n, _ := answersFrom(t, "two.example.lan"); return n == 1 })
}

func TestFeed_OnlyShortAbsolutePathsAreFollowed(t *testing.T) {
	t.Cleanup(func() { setFeedSocket(context.Background(), "") })
	setFeedSocket(context.Background(), "relative.sock")
	if feedState.path != "" || feedState.cancel != nil {
		t.Fatal("a relative path is refused")
	}
	long := "/" + string(make([]byte, 120))
	setFeedSocket(context.Background(), long)
	if feedState.path != "" {
		t.Fatal("a path too long for a socket is refused")
	}
}
