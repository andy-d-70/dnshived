// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcprelay

import (
	"bytes"
	"io"
	"log"
	"net"
	"testing"
)

func silenceLog(tb testing.TB) {
	tb.Helper()
	w := log.Writer()
	log.SetOutput(io.Discard)
	tb.Cleanup(func() { log.SetOutput(w) })
}

func fuzzSeeds(f *testing.F, giaddr net.IP) {
	f.Helper()
	f.Add(benchPacket(bootpOpRequest, net.IPv4zero))
	f.Add(benchPacket(bootpOpReply, giaddr))
	f.Add(buildTestPacket(bootpOpRequest, 1, [6]byte{1}, net.IPv4zero, net.IPv4zero, maxHops-1, false, false))
	truncated := benchPacket(bootpOpReply, giaddr)
	f.Add(append(truncated[:dhcpOptionsOffset:dhcpOptionsOffset], optServerIdentifier, 200, 1, 2))
	f.Add(make([]byte, dhcpMinBOOTPLen-1))
}

func newFuzzRelay(t *testing.T) (*Relay, *fakeUDPConn, *clientInterface) {
	r, serverConn, ci := newTestRelay(t)
	sid := net.IPv4(192, 168, 200, 1).To4()
	ci.serverIdentifier.Store(&sid)
	return r, serverConn, ci
}

func FuzzHandleClientRequest(f *testing.F) {
	fuzzSeeds(f, net.IPv4(192, 168, 200, 22))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxPacketLen {
			return
		}
		silenceLog(t)
		r, serverConn, ci := newFuzzRelay(t)
		pkt := append([]byte(nil), data...)
		r.handleClientRequest(ci, pkt, &net.UDPAddr{IP: net.IPv4(192, 168, 200, 50), Port: dhcpClientPort})

		w, ok := serverConn.lastWrite()
		if !ok {
			return
		}
		if len(w.data) != len(data) {
			t.Fatalf("forwarded length %d, received %d", len(w.data), len(data))
		}
		if w.data[bootpOpOffset] != bootpOpRequest {
			t.Fatalf("forwarded op %d, want request", w.data[bootpOpOffset])
		}
		if !extractGIAddr(w.data).Equal(ci.giaddr) {
			t.Fatalf("forwarded giaddr %v, want %v", extractGIAddr(w.data), ci.giaddr)
		}
		if w.data[bootpHopsOffset] != data[bootpHopsOffset]+1 || w.data[bootpHopsOffset] > maxHops {
			t.Fatalf("hops %d -> %d", data[bootpHopsOffset], w.data[bootpHopsOffset])
		}
		if !w.addr.IP.Equal(ci.serverAddr.IP) || w.addr.Port != ci.serverAddr.Port {
			t.Fatalf("forwarded to %v, want %v", w.addr, ci.serverAddr)
		}
	})
}

func FuzzHandleServerReply(f *testing.F) {
	giaddr := net.IPv4(192, 168, 200, 22).To4()
	fuzzSeeds(f, giaddr)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxPacketLen {
			return
		}
		silenceLog(t)
		r, _, ci := newFuzzRelay(t)
		if len(data) >= dhcpMinBOOTPLen {
			if key, ok := makeTransactionKey(data, ci.giaddr); ok {
				r.pending.add(key)
			}
		}
		pkt := append([]byte(nil), data...)
		r.handleServerReply(ci, pkt, &net.UDPAddr{IP: ci.serverAddr.IP, Port: dhcpServerPort})

		w, ok := ci.conn.(*fakeUDPConn).lastWrite()
		if !ok {
			return
		}
		if len(w.data) != len(data) {
			t.Fatalf("forwarded length %d, received %d", len(w.data), len(data))
		}
		if !extractGIAddr(w.data).Equal(ci.giaddr) {
			t.Fatalf("forwarded a reply for giaddr %v on %s", extractGIAddr(w.data), ci.name)
		}
		if w.addr.Port != dhcpClientPort {
			t.Fatalf("reply sent to port %d", w.addr.Port)
		}
		if r.pending.has(mustKey(t, w.data, ci.giaddr)) {
			t.Fatal("pending entry kept after the reply was delivered")
		}
	})
}

func mustKey(t *testing.T, p []byte, giaddr net.IP) txKey {
	t.Helper()
	k, ok := makeTransactionKey(p, giaddr)
	if !ok {
		t.Fatal("no transaction key")
	}
	return k
}

func FuzzRewriteServerIdentifier(f *testing.F) {
	fuzzSeeds(f, net.IPv4(192, 168, 200, 22))
	id := net.IPv4(192, 168, 200, 1).To4()
	f.Fuzz(func(t *testing.T, data []byte) {
		pkt := append([]byte(nil), data...)
		found := rewriteServerIdentifier(pkt, id)
		if len(pkt) != len(data) {
			t.Fatalf("length changed %d -> %d", len(data), len(pkt))
		}
		changed := 0
		for i := range pkt {
			if pkt[i] != data[i] {
				changed++
			}
		}
		if changed > 4 {
			t.Fatalf("%d bytes changed, at most the 4-byte option value may change", changed)
		}
		if found && !bytes.Contains(pkt[dhcpOptionsOffset:], append([]byte{optServerIdentifier, 4}, id...)) {
			t.Fatal("reported a rewrite but the option does not carry the new identifier")
		}
	})
}
