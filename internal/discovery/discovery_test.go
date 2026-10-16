// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package discovery

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"
)

func TestAnnouncement_RoundTrips(t *testing.T) {
	a := Announcement{Magic: Magic, ProtoVersion: ProtoVersion, Hostname: "rogue", Version: "0.9.8-12+abc", BootstrapPort: 9443}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Announcement
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != a {
		t.Errorf("got %+v, want %+v", got, a)
	}
}

func TestListener_ReceivesRealUDPAnnouncement(t *testing.T) {
	l := NewListener()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ready := make(chan struct{})
	go func() {
		close(ready)
		if err := l.Run(ctx); err != nil {
			t.Errorf("Run: %v", err)
		}
	}()
	<-ready
	time.Sleep(50 * time.Millisecond) // let the socket actually bind

	payload, _ := json.Marshal(Announcement{Magic: Magic, ProtoVersion: ProtoVersion, Hostname: "rogue-test", Version: "0.9.8-99+test", BootstrapPort: 9443})
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: Port})
	if err != nil {
		t.Fatalf("dial loopback: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		snap := l.Snapshot()
		for _, c := range snap {
			if c.Hostname == "rogue-test" && c.Version == "0.9.8-99+test" && c.BootstrapPort == 9443 {
				return // found it, real end-to-end round trip confirmed
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("never saw the loopback announcement in Snapshot() within the deadline; last snapshot: %+v", l.Snapshot())
}

func TestListener_IgnoresWrongMagicAndVersion(t *testing.T) {
	l := NewListener()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	go func() {
		close(ready)
		l.Run(ctx)
	}()
	<-ready
	time.Sleep(50 * time.Millisecond)

	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: Port})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	bad := []Announcement{
		{Magic: "SOMETHING-ELSE", ProtoVersion: ProtoVersion, Hostname: "x", Version: "1"},
		{Magic: Magic, ProtoVersion: 99, Hostname: "x", Version: "1"},
	}
	for _, a := range bad {
		raw, _ := json.Marshal(a)
		conn.Write(raw)
	}
	conn.Write([]byte("not even json"))
	time.Sleep(200 * time.Millisecond)

	if got := l.Snapshot(); len(got) != 0 {
		t.Errorf("Snapshot() = %+v, want empty — malformed/foreign packets must never be recorded", got)
	}
}

func TestSnapshot_PrunesEntriesOlderThanTTL(t *testing.T) {
	l := NewListener()
	l.seen["10.0.0.1"] = Candidate{Addr: "10.0.0.1", Hostname: "stale", LastSeen: time.Now().Add(-ttl - time.Second)}
	l.seen["10.0.0.2"] = Candidate{Addr: "10.0.0.2", Hostname: "fresh", LastSeen: time.Now()}

	got := l.Snapshot()
	if len(got) != 1 || got[0].Hostname != "fresh" {
		t.Fatalf("Snapshot() = %+v, want exactly the fresh entry", got)
	}
	if _, stillThere := l.seen["10.0.0.1"]; stillThere {
		t.Error("stale entry was not actually pruned from the live map")
	}
}

func TestSnapshot_SortedByAddr(t *testing.T) {
	l := NewListener()
	l.seen["10.0.0.9"] = Candidate{Addr: "10.0.0.9", LastSeen: time.Now()}
	l.seen["10.0.0.2"] = Candidate{Addr: "10.0.0.2", LastSeen: time.Now()}
	l.seen["10.0.0.5"] = Candidate{Addr: "10.0.0.5", LastSeen: time.Now()}

	got := l.Snapshot()
	if len(got) != 3 || got[0].Addr != "10.0.0.2" || got[1].Addr != "10.0.0.5" || got[2].Addr != "10.0.0.9" {
		t.Errorf("Snapshot() not sorted by address: %+v", got)
	}
}

func TestPortFromAddr(t *testing.T) {
	cases := []struct {
		addr     string
		fallback int
		want     int
	}{
		{":9443", 0, 9443},
		{"0.0.0.0:9444", 0, 9444},
		{"192.168.0.22:9443", 0, 9443},
		{"not-an-addr", 9443, 9443},
		{"", 9444, 9444},
	}
	for _, c := range cases {
		if got := PortFromAddr(c.addr, c.fallback); got != c.want {
			t.Errorf("PortFromAddr(%q, %d) = %d, want %d", c.addr, c.fallback, got, c.want)
		}
	}
}

func TestBroadcastAddrs_ExcludesLoopback(t *testing.T) {
	for _, ip := range broadcastAddrs() {
		if ip.IsLoopback() {
			t.Errorf("broadcastAddrs() included a loopback address: %v", ip)
		}
	}
}

func TestBroadcastOnInterface_RealRoundTripOnLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go BroadcastOnInterface(ctx, "lo", "candidate-host")

	probe, ok := ListenOnInterface(context.Background(), "lo", 2*time.Second)
	if !ok {
		t.Fatal("ListenOnInterface = ok=false, want a real probe received on lo")
	}
	if probe.Hostname != "candidate-host" {
		t.Errorf("probe.Hostname = %q, want %q", probe.Hostname, "candidate-host")
	}
	if probe.LocalInterface != "lo" {
		t.Errorf("probe.LocalInterface = %q, want %q", probe.LocalInterface, "lo")
	}
}

// TestListenOnInterface_TimesOutWithNothingSent confirms a real, bounded
// timeout.
func TestListenOnInterface_TimesOutWithNothingSent(t *testing.T) {
	start := time.Now()
	_, ok := ListenOnInterface(context.Background(), "lo", 500*time.Millisecond)
	elapsed := time.Since(start)
	if ok {
		t.Error("ListenOnInterface = ok=true, want false — nothing was ever sent")
	}
	if elapsed > 2*time.Second {
		t.Errorf("ListenOnInterface took %v, want it to respect the ~500ms timeout", elapsed)
	}
}

// TestListenOnInterface_IgnoresWrongMagic confirms a stray/foreign UDP
// packet on the same port never counts as a real probe.
func TestListenOnInterface_IgnoresWrongMagic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		lc := bindToDeviceUDP4("lo")
		pc, err := lc.ListenPacket(ctx, "udp4", ":0")
		if err != nil {
			return
		}
		defer pc.Close()
		bogus, _ := json.Marshal(map[string]string{"magic": "SOMETHING-ELSE"})
		dst := &net.UDPAddr{IP: net.IPv4bcast, Port: InterfaceProbePort}
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pc.WriteTo(bogus, dst)
			}
		}
	}()

	_, ok := ListenOnInterface(context.Background(), "lo", 1*time.Second)
	if ok {
		t.Error("ListenOnInterface accepted a packet with the wrong magic")
	}
}
