// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcpprobe

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestBuildDiscover_ShapeAndFields(t *testing.T) {
	chaddr := []byte{0x02, 1, 2, 3, 4, 5}
	xid := uint32(0xdeadbeef)
	p := buildDiscover(xid, chaddr, true)

	if len(p) < 300 {
		t.Fatalf("packet too short: %d bytes, want >= 300 (BOOTP minimum)", len(p))
	}
	if p[0] != bootRequest {
		t.Errorf("op = %d, want bootRequest (%d)", p[0], bootRequest)
	}
	if got := binary.BigEndian.Uint32(p[4:8]); got != xid {
		t.Errorf("xid = %#x, want %#x", got, xid)
	}
	if flags := binary.BigEndian.Uint16(p[10:12]); flags != 0x8000 {
		t.Errorf("broadcast flag not set: flags = %#x", flags)
	}
	if string(p[28:34]) != string(chaddr) {
		t.Error("chaddr not embedded correctly")
	}
	if string(p[236:240]) != string(magicCookie) {
		t.Error("magic cookie missing")
	}
}

func TestBuildDiscover_NoBroadcastFlag(t *testing.T) {
	p := buildDiscover(1, []byte{0x02, 1, 2, 3, 4, 5}, false)
	if flags := binary.BigEndian.Uint16(p[10:12]); flags != 0 {
		t.Errorf("flags = %#x, want 0 (broadcast flag cleared)", flags)
	}
}

// buildOfferPacket constructs a minimal, valid DHCPOFFER reply matching
// what parseOffer expects.
func buildOfferPacket(xid uint32, chaddr []byte, serverID, yourIP net.IP, lease uint32) []byte {
	p := make([]byte, 240, 260)
	p[0] = bootReply
	p[1] = htypeEther
	p[2] = hlenEther
	binary.BigEndian.PutUint32(p[4:8], xid)
	copy(p[16:20], yourIP.To4())
	copy(p[28:34], chaddr)
	copy(p[236:240], magicCookie)

	p = append(p, optMessageType, 1, dhcpOffer)
	p = append(p, optServerID, 4)
	p = append(p, serverID.To4()...)
	leaseBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(leaseBytes, lease)
	p = append(p, optLeaseTime, 4)
	p = append(p, leaseBytes...)
	p = append(p, optEnd)
	return p
}

func TestParseOffer_ValidOffer(t *testing.T) {
	xid := uint32(42)
	chaddr := []byte{0x02, 1, 2, 3, 4, 5}
	pkt := buildOfferPacket(xid, chaddr, net.ParseIP("192.168.100.1"), net.ParseIP("192.168.100.50"), 3600)

	o, ok := parseOffer(pkt, xid, chaddr)
	if !ok {
		t.Fatal("parseOffer rejected a valid offer packet")
	}
	if !o.ServerID.Equal(net.ParseIP("192.168.100.1")) {
		t.Errorf("ServerID = %v, want 192.168.100.1", o.ServerID)
	}
	if !o.YourIP.Equal(net.ParseIP("192.168.100.50")) {
		t.Errorf("YourIP = %v, want 192.168.100.50", o.YourIP)
	}
	if o.Lease != 3600 {
		t.Errorf("Lease = %d, want 3600", o.Lease)
	}
}

func TestParseOffer_WrongXIDRejected(t *testing.T) {
	chaddr := []byte{0x02, 1, 2, 3, 4, 5}
	pkt := buildOfferPacket(42, chaddr, net.ParseIP("192.168.100.1"), net.ParseIP("192.168.100.50"), 3600)

	_, ok := parseOffer(pkt, 43, chaddr) // different xid — not our transaction
	if ok {
		t.Error("parseOffer accepted a packet with a mismatched xid")
	}
}

func TestParseOffer_WrongChaddrRejected(t *testing.T) {
	xid := uint32(42)
	pkt := buildOfferPacket(xid, []byte{0x02, 1, 2, 3, 4, 5}, net.ParseIP("192.168.100.1"), net.ParseIP("192.168.100.50"), 3600)

	_, ok := parseOffer(pkt, xid, []byte{0x02, 9, 9, 9, 9, 9}) // different chaddr
	if ok {
		t.Error("parseOffer accepted a packet with a mismatched chaddr — could misattribute another client's offer")
	}
}

func TestParseOffer_TooShortRejected(t *testing.T) {
	_, ok := parseOffer([]byte{1, 2, 3}, 42, []byte{0x02, 1, 2, 3, 4, 5})
	if ok {
		t.Error("parseOffer accepted a packet shorter than the BOOTP fixed header")
	}
}

func TestParseOffer_NotAnOfferRejected(t *testing.T) {
	xid := uint32(42)
	chaddr := []byte{0x02, 1, 2, 3, 4, 5}
	pkt := buildOfferPacket(xid, chaddr, net.ParseIP("192.168.100.1"), net.ParseIP("192.168.100.50"), 3600)
	// Flip the message-type option (offset: 240 fixed header start, +0=code, +1=len, +2=value)
	pkt[242] = 5 // DHCPACK, not DHCPOFFER

	_, ok := parseOffer(pkt, xid, chaddr)
	if ok {
		t.Error("parseOffer accepted a non-OFFER message type")
	}
}

func TestDistinctServers_DedupesAndSorts(t *testing.T) {
	offers := []Offer{
		{ServerID: net.ParseIP("192.168.100.2")},
		{ServerID: net.ParseIP("192.168.100.1")},
		{ServerID: net.ParseIP("192.168.100.1")}, // duplicate — same server via two relays
	}
	got := distinctServers(offers)
	want := []string{"192.168.100.1", "192.168.100.2"}
	if len(got) != len(want) {
		t.Fatalf("distinctServers = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("distinctServers[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestDistinctServers_EmptyForNoOffers(t *testing.T) {
	if got := distinctServers(nil); len(got) != 0 {
		t.Errorf("distinctServers(nil) = %v, want empty", got)
	}
}

// TestVerdictClassification pins the exact verdict-selection logic Probe
// uses, independent of real sockets.
func TestVerdictClassification(t *testing.T) {
	cases := []struct {
		name   string
		offers []Offer
		want   Verdict
	}{
		{"no offers", nil, VerdictNoAnswer},
		{"one server, one offer", []Offer{{ServerID: net.ParseIP("10.0.0.1")}}, VerdictOK},
		{"one server, two relays", []Offer{
			{ServerID: net.ParseIP("10.0.0.1")},
			{ServerID: net.ParseIP("10.0.0.1")},
		}, VerdictOK},
		{"two distinct servers", []Offer{
			{ServerID: net.ParseIP("10.0.0.1")},
			{ServerID: net.ParseIP("10.0.0.2")},
		}, VerdictDualActive},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			servers := distinctServers(c.offers)
			got := VerdictOK
			switch {
			case len(c.offers) == 0:
				got = VerdictNoAnswer
			case len(servers) > 1:
				got = VerdictDualActive
			}
			if got != c.want {
				t.Errorf("verdict = %s, want %s", got, c.want)
			}
		})
	}
}

func TestResourceFor(t *testing.T) {
	cases := []struct{ iface, want string }{
		{"ens19.104", "ens19"},
		{"ens20.999", "ens20"},
		{"ens19", "ens19"},     // no VLAN suffix — the interface is its own resource
		{"eth0.5.6", "eth0.5"}, // last dot only, not first
		{".104", ".104"},       // leading dot: LastIndexByte > 0 guard means no split
	}
	for _, c := range cases {
		if got := resourceFor(c.iface); got != c.want {
			t.Errorf("resourceFor(%q) = %q, want %q", c.iface, got, c.want)
		}
	}
}

func TestLockFor_SameResourceReturnsSameMutex(t *testing.T) {
	a := lockFor("ens19-test-a")
	b := lockFor("ens19-test-a")
	if a != b {
		t.Error("lockFor returned different mutexes for the same resource key")
	}
}

func TestLockFor_DifferentResourcesReturnIndependentMutexes(t *testing.T) {
	a := lockFor("ens19-test-b")
	b := lockFor("ens20-test-b")
	if a == b {
		t.Error("lockFor returned the SAME mutex for two different resource keys")
	}
}

func TestPerResourceLocking_DifferentResourcesRunConcurrently(t *testing.T) {
	const hold = 100 * time.Millisecond

	run := func(resource string, done chan<- struct{}) {
		mu := lockFor(resource)
		mu.Lock()
		time.Sleep(hold)
		mu.Unlock()
		done <- struct{}{}
	}

	start := time.Now()
	done := make(chan struct{}, 2)
	go run("ens19-concurrency-test", done)
	go run("ens20-concurrency-test", done)
	<-done
	<-done
	elapsed := time.Since(start)

	// Concurrent: both finish in ~1x hold, not 2x. Generous margin
	// (1.5x) for scheduler jitter on a loaded CI host.
	if elapsed >= 2*hold {
		t.Errorf("elapsed = %v, want well under %v — different resources must run concurrently, not serialize", elapsed, 2*hold)
	}
}

func TestPerResourceLocking_SameResourceStillSerializes(t *testing.T) {
	const hold = 100 * time.Millisecond
	resource := "ens19-serialize-test"

	run := func(done chan<- struct{}) {
		mu := lockFor(resource)
		mu.Lock()
		time.Sleep(hold)
		mu.Unlock()
		done <- struct{}{}
	}

	start := time.Now()
	done := make(chan struct{}, 2)
	go run(done)
	go run(done)
	<-done
	<-done
	elapsed := time.Since(start)

	// Serialized: must take at least ~2x hold, never less.
	if elapsed < 2*hold {
		t.Errorf("elapsed = %v, want at least %v — the same resource must still fully serialize", elapsed, 2*hold)
	}
}
