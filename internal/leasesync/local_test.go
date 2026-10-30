// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package leasesync

import (
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestListenLocal_ReceivesWrittenEvent(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "dhcp-lease.sock")

	var mu sync.Mutex
	var got []LocalEvent
	ln, err := ListenLocal(sock, func(ev LocalEvent) {
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("ListenLocal() error: %v", err)
	}
	defer ln.Close()

	if err := WriteLocalEvent(sock, LocalEvent{Action: "add", MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: 1234}); err != nil {
		t.Fatalf("WriteLocalEvent() error: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("received %d events, want 1", len(got))
	}
	if got[0].Action != "add" || got[0].MAC != "aa:bb" || got[0].IP != "10.0.0.5" || got[0].ExpiresAt != 1234 {
		t.Errorf("received event = %+v, want the exact values written", got[0])
	}
}

func TestListenLocal_RefusesLiveSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "dhcp-lease.sock")

	ln1, err := ListenLocal(sock, func(LocalEvent) {})
	if err != nil {
		t.Fatalf("first ListenLocal() error: %v", err)
	}
	defer ln1.Close()

	if ln2, err := ListenLocal(sock, func(LocalEvent) {}); err == nil {
		ln2.Close()
		t.Fatal("second ListenLocal() took over a live socket")
	}
}

func TestListenLocal_ReplacesStaleSocketFile(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "dhcp-lease.sock")
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	stale.Close()

	ln, err := ListenLocal(sock, func(LocalEvent) {})
	if err != nil {
		t.Fatalf("ListenLocal() over a stale socket file error: %v", err)
	}
	defer ln.Close()
}

func TestWriteLocalEvent_NoListenerReturnsError(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "nothing-here.sock")
	if err := WriteLocalEvent(sock, LocalEvent{Action: "add", MAC: "aa:bb"}); err == nil {
		t.Fatal("WriteLocalEvent() succeeded against a socket with nothing listening, want an error")
	}
}
