// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcprelay

import (
	"net"
	"testing"
)

type discardUDPConn struct{}

func (discardUDPConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error)  { select {} }
func (discardUDPConn) WriteToUDP(b []byte, _ *net.UDPAddr) (int, error) { return len(b), nil }
func (discardUDPConn) Close() error                                     { return nil }

func newBenchRelay(b *testing.B) (*Relay, *clientInterface) {
	b.Helper()
	r, err := New(Config{
		ServerAddr:       "127.0.0.21:67",
		ClientInterfaces: []ClientInterfaceConfig{{Name: "ens19.200", GIAddr: "192.168.200.22", ServerIdentifier: "192.168.200.1"}},
	})
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	r.setServerConn(discardUDPConn{})
	ci := r.clientIfaces[0]
	ci.conn = discardUDPConn{}
	ci.reply = discardUDPConn{}
	ci.rateLimit.Store(1 << 30)
	ci.rateBurst.Store(1 << 30)
	ci.limiter = newTokenBucket(1 << 30)
	r.clientRateLimit.Store(1 << 30)
	r.clientRateBurst.Store(1 << 30)
	openTestGates(r)
	return r, ci
}

func benchPacket(op byte, giaddr net.IP) []byte {
	p := buildTestPacket(op, 0x1234, [6]byte{2, 0, 0, 0, 0, 1}, net.IPv4zero, giaddr, 0, true, true)
	return append(p, 53, 1, 1, optServerIdentifier, 4, 10, 0, 0, 1, optEnd)
}

func BenchmarkHandleClientRequest(b *testing.B) {
	r, ci := newBenchRelay(b)
	tmpl := benchPacket(bootpOpRequest, net.IPv4zero)
	pkt := make([]byte, len(tmpl))
	from := &net.UDPAddr{IP: net.IPv4(192, 168, 200, 50), Port: dhcpClientPort}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(pkt, tmpl)
		r.handleClientRequest(ci, pkt, from)
	}
	if got := r.Snapshot().RequestsForwarded; got != int64(b.N) {
		b.Fatalf("forwarded %d of %d", got, b.N)
	}
}

func BenchmarkRequestReplyCycle(b *testing.B) {
	r, ci := newBenchRelay(b)
	reqTmpl := benchPacket(bootpOpRequest, net.IPv4zero)
	repTmpl := benchPacket(bootpOpReply, ci.giaddr)
	req := make([]byte, len(reqTmpl))
	rep := make([]byte, len(repTmpl))
	client := &net.UDPAddr{IP: net.IPv4(192, 168, 200, 50), Port: dhcpClientPort}
	server := &net.UDPAddr{IP: ci.serverAddr.IP, Port: dhcpServerPort}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(req, reqTmpl)
		copy(rep, repTmpl)
		r.handleClientRequest(ci, req, client)
		r.handleServerReply(ci, rep, server)
	}
	if got := r.Snapshot().RepliesForwarded; got != int64(b.N) {
		b.Fatalf("replies forwarded %d of %d", got, b.N)
	}
}

func BenchmarkHandleClientRequest_Parallel(b *testing.B) {
	r, ci := newBenchRelay(b)
	tmpl := benchPacket(bootpOpRequest, net.IPv4zero)
	from := &net.UDPAddr{IP: net.IPv4(192, 168, 200, 50), Port: dhcpClientPort}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		pkt := make([]byte, len(tmpl))
		for pb.Next() {
			copy(pkt, tmpl)
			r.handleClientRequest(ci, pkt, from)
		}
	})
}

func BenchmarkRateLimitedDrop(b *testing.B) {
	r, ci := newBenchRelay(b)
	ci.rateLimit.Store(1)
	ci.rateBurst.Store(1)
	ci.limiter = newTokenBucket(1)
	tmpl := benchPacket(bootpOpRequest, net.IPv4zero)
	pkt := make([]byte, len(tmpl))
	from := &net.UDPAddr{IP: net.IPv4(192, 168, 200, 50), Port: dhcpClientPort}
	silenceLog(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(pkt, tmpl)
		r.handleClientRequest(ci, pkt, from)
	}
}

func BenchmarkRewriteServerIdentifier(b *testing.B) {
	pkt := benchPacket(bootpOpReply, net.IPv4(192, 168, 200, 22))
	id := net.IPv4(192, 168, 200, 1)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rewriteServerIdentifier(pkt, id)
	}
}

func BenchmarkPendingAddDelete(b *testing.B) {
	t := newPendingTable()
	k := txKey{xid: 7, chaddr: [6]byte{2, 0, 0, 0, 0, 1}, giaddr: [4]byte{192, 168, 200, 22}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		k.xid = uint32(i)
		t.add(k)
		t.delete(k)
	}
}
