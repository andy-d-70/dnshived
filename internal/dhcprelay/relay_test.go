// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcprelay

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// ---- relay.go: diffClientInterfaces ----

const testDefaultServerAddr = "127.0.0.21:67"

func ciNamed(name, giaddr string) *clientInterface {
	addr, _ := net.ResolveUDPAddr("udp4", testDefaultServerAddr)
	return &clientInterface{name: name, giaddr: net.ParseIP(giaddr).To4(), serverAddr: addr}
}

func ciNamedWithServer(name, giaddr, serverAddr string) *clientInterface {
	addr, _ := net.ResolveUDPAddr("udp4", serverAddr)
	return &clientInterface{name: name, giaddr: net.ParseIP(giaddr).To4(), serverAddr: addr}
}

func TestDiffClientInterfaces_UnchangedStaysUntouched(t *testing.T) {
	old := []*clientInterface{ciNamed("ens19.100", "192.168.100.22")}
	newIfaces := []ClientInterfaceConfig{{Name: "ens19.100", GIAddr: "192.168.100.22"}}

	toRemove, toAdd, unchanged := diffClientInterfaces(old, newIfaces, testDefaultServerAddr)
	if len(toRemove) != 0 || len(toAdd) != 0 {
		t.Errorf("toRemove=%v toAdd=%v, want both empty for a genuinely unchanged interface", toRemove, toAdd)
	}
	if unchanged != 1 {
		t.Errorf("unchanged = %d, want 1", unchanged)
	}
}

func TestDiffClientInterfaces_AddedScopeOnlyAddsNewOne(t *testing.T) {
	old := []*clientInterface{ciNamed("ens19.100", "192.168.100.22")}
	newIfaces := []ClientInterfaceConfig{
		{Name: "ens19.100", GIAddr: "192.168.100.22"},
		{Name: "ens20.50", GIAddr: "172.16.50.22"},
	}

	toRemove, toAdd, unchanged := diffClientInterfaces(old, newIfaces, testDefaultServerAddr)
	if len(toRemove) != 0 {
		t.Errorf("toRemove = %v, want empty — the existing scope must never be touched by adding a new one", toRemove)
	}
	if len(toAdd) != 1 || toAdd[0].Name != "ens20.50" {
		t.Errorf("toAdd = %v, want exactly [ens20.50]", toAdd)
	}
	if unchanged != 1 {
		t.Errorf("unchanged = %d, want 1", unchanged)
	}
}

// TestDiffClientInterfaces_RemovedScopeOnlyRemovesThatOne mirrors the add
// case for removal.
func TestDiffClientInterfaces_RemovedScopeOnlyRemovesThatOne(t *testing.T) {
	old := []*clientInterface{
		ciNamed("ens19.100", "192.168.100.22"),
		ciNamed("ens20.50", "172.16.50.22"),
	}
	newIfaces := []ClientInterfaceConfig{{Name: "ens19.100", GIAddr: "192.168.100.22"}}

	toRemove, toAdd, unchanged := diffClientInterfaces(old, newIfaces, testDefaultServerAddr)
	if len(toAdd) != 0 {
		t.Errorf("toAdd = %v, want empty", toAdd)
	}
	if len(toRemove) != 1 || toRemove[0].name != "ens20.50" {
		t.Errorf("toRemove = %v, want exactly [ens20.50]", toRemove)
	}
	if unchanged != 1 {
		t.Errorf("unchanged = %d, want 1", unchanged)
	}
}

func TestDiffClientInterfaces_GIAddrChangeIsRemoveThenAdd(t *testing.T) {
	old := []*clientInterface{ciNamed("ens19.100", "192.168.100.22")}
	newIfaces := []ClientInterfaceConfig{{Name: "ens19.100", GIAddr: "192.168.100.99"}}

	toRemove, toAdd, unchanged := diffClientInterfaces(old, newIfaces, testDefaultServerAddr)
	if len(toRemove) != 1 || toRemove[0].name != "ens19.100" {
		t.Errorf("toRemove = %v, want exactly [ens19.100]", toRemove)
	}
	if len(toAdd) != 1 || toAdd[0].GIAddr != "192.168.100.99" {
		t.Errorf("toAdd = %v, want exactly [{ens19.100 192.168.100.99}]", toAdd)
	}
	if unchanged != 0 {
		t.Errorf("unchanged = %d, want 0 — a giaddr change is not unchanged", unchanged)
	}
}

func TestDiffClientInterfaces_MultiScopeMixedChange(t *testing.T) {
	old := []*clientInterface{
		ciNamed("ens19.10", "192.168.10.22"),
		ciNamed("ens19.11", "192.168.11.22"),
		ciNamed("ens19.12", "192.168.12.22"), // will be removed
	}
	newIfaces := []ClientInterfaceConfig{
		{Name: "ens19.10", GIAddr: "192.168.10.22"},
		{Name: "ens19.11", GIAddr: "192.168.11.22"},
		{Name: "ens19.13", GIAddr: "192.168.13.22"}, // newly added
	}

	toRemove, toAdd, unchanged := diffClientInterfaces(old, newIfaces, testDefaultServerAddr)
	if len(toRemove) != 1 || toRemove[0].name != "ens19.12" {
		t.Errorf("toRemove = %v, want exactly [ens19.12]", toRemove)
	}
	if len(toAdd) != 1 || toAdd[0].Name != "ens19.13" {
		t.Errorf("toAdd = %v, want exactly [ens19.13]", toAdd)
	}
	if unchanged != 2 {
		t.Errorf("unchanged = %d, want 2 (ens19.10, ens19.11)", unchanged)
	}
}

func TestDiffClientInterfaces_ServerAddrChangeIsRemoveThenAdd(t *testing.T) {
	old := []*clientInterface{ciNamedWithServer("ens19.100", "192.168.100.22", "127.0.0.21:67")}
	newIfaces := []ClientInterfaceConfig{{Name: "ens19.100", GIAddr: "192.168.100.22", ServerAddr: "127.0.1.21:67"}}

	toRemove, toAdd, unchanged := diffClientInterfaces(old, newIfaces, testDefaultServerAddr)
	if len(toRemove) != 1 || toRemove[0].name != "ens19.100" {
		t.Errorf("toRemove = %v, want exactly [ens19.100]", toRemove)
	}
	if len(toAdd) != 1 || toAdd[0].ServerAddr != "127.0.1.21:67" {
		t.Errorf("toAdd = %v, want exactly [{ens19.100 ... 127.0.1.21:67}]", toAdd)
	}
	if unchanged != 0 {
		t.Errorf("unchanged = %d, want 0 — a server_addr change is not unchanged", unchanged)
	}
}

func TestDiffClientInterfaces_ClusterWideDefaultChangeAffectsUnoverriddenInterfaces(t *testing.T) {
	old := []*clientInterface{ciNamedWithServer("ens19.100", "192.168.100.22", "127.0.0.21:67")}
	newIfaces := []ClientInterfaceConfig{{Name: "ens19.100", GIAddr: "192.168.100.22"}} // no ServerAddr override

	toRemove, toAdd, unchanged := diffClientInterfaces(old, newIfaces, "127.0.9.21:67")
	if len(toRemove) != 1 || len(toAdd) != 1 {
		t.Errorf("toRemove=%v toAdd=%v, want exactly one remove and one add when the relied-upon default changes", toRemove, toAdd)
	}
	if unchanged != 0 {
		t.Errorf("unchanged = %d, want 0", unchanged)
	}
}

func TestDiffClientInterfaces_OwnServerAddrOverrideStaysUnchangedDespiteDefaultDrift(t *testing.T) {
	old := []*clientInterface{ciNamedWithServer("ens20.50", "172.16.50.22", "127.0.2.21:67")}
	newIfaces := []ClientInterfaceConfig{{Name: "ens20.50", GIAddr: "172.16.50.22", ServerAddr: "127.0.2.21:67"}}

	toRemove, toAdd, unchanged := diffClientInterfaces(old, newIfaces, "127.0.9.21:67")
	if len(toRemove) != 0 || len(toAdd) != 0 {
		t.Errorf("toRemove=%v toAdd=%v, want both empty — this interface's own override never changed", toRemove, toAdd)
	}
	if unchanged != 1 {
		t.Errorf("unchanged = %d, want 1", unchanged)
	}
}

// ---- packet.go ----

func buildTestPacket(op byte, xid uint32, chaddr [6]byte, ciaddr, giaddr net.IP, hops byte, broadcast bool, dhcp bool) []byte {
	p := make([]byte, dhcpOptionsOffset)
	p[bootpOpOffset] = op
	p[bootpHtypeOffset] = bootpHtypeEthernet
	p[bootpHlenOffset] = bootpHlenEthernet
	p[bootpHopsOffset] = hops
	binary.BigEndian.PutUint32(p[bootpXIDOffset:], xid)
	if broadcast {
		binary.BigEndian.PutUint16(p[bootpFlagsOffset:], 0x8000)
	}
	copy(p[bootpCIAddrOffset:bootpCIAddrOffset+4], ciaddr.To4())
	copy(p[bootpGIAddrOffset:bootpGIAddrOffset+4], giaddr.To4())
	copy(p[bootpCHAddrOffset:], chaddr[:])
	if dhcp {
		copy(p[dhcpMagicCookieOffset:], dhcpMagicCookie[:])
	}
	return p
}

func TestExtractFields(t *testing.T) {
	chaddr := [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	p := buildTestPacket(bootpOpRequest, 0x12345678, chaddr, net.IPv4(10, 0, 0, 5), net.IPv4(192, 168, 1, 1), 2, true, true)

	if got := extractXID(p); got != 0x12345678 {
		t.Errorf("extractXID = %#x, want 0x12345678", got)
	}
	if got := extractCHAddr(p); got != chaddr {
		t.Errorf("extractCHAddr = %v, want %v", got, chaddr)
	}
	if got := extractCIAddr(p); !got.Equal(net.IPv4(10, 0, 0, 5)) {
		t.Errorf("extractCIAddr = %v, want 10.0.0.5", got)
	}
	if got := extractGIAddr(p); !got.Equal(net.IPv4(192, 168, 1, 1)) {
		t.Errorf("extractGIAddr = %v, want 192.168.1.1", got)
	}
	if !isBroadcastFlagSet(p) {
		t.Error("isBroadcastFlagSet = false, want true")
	}
	if !isDHCPPacket(p) {
		t.Error("isDHCPPacket = false, want true")
	}
}

func TestIsBroadcastFlagSet_ClearWhenNotSet(t *testing.T) {
	p := buildTestPacket(bootpOpRequest, 1, [6]byte{}, net.IPv4zero, net.IPv4zero, 0, false, true)
	if isBroadcastFlagSet(p) {
		t.Error("isBroadcastFlagSet = true, want false")
	}
}

func TestIsDHCPPacket_FalseForShortOrWrongCookie(t *testing.T) {
	if isDHCPPacket(make([]byte, 100)) {
		t.Error("short packet: want false")
	}
	p := buildTestPacket(bootpOpRequest, 1, [6]byte{}, net.IPv4zero, net.IPv4zero, 0, false, false)
	if isDHCPPacket(p) {
		t.Error("no magic cookie: want false")
	}
}

func TestDetermineClientDestination(t *testing.T) {
	unicast := buildTestPacket(bootpOpReply, 1, [6]byte{}, net.IPv4(10, 0, 0, 9), net.IPv4zero, 0, false, true)
	if got := determineClientDestination(unicast); !got.Equal(net.IPv4(10, 0, 0, 9)) {
		t.Errorf("ciaddr set: got %v, want 10.0.0.9", got)
	}

	broadcast := buildTestPacket(bootpOpReply, 1, [6]byte{}, net.IPv4zero, net.IPv4zero, 0, true, true)
	if got := determineClientDestination(broadcast); !got.Equal(net.IPv4bcast) {
		t.Errorf("broadcast-flag reply: got %v, want 255.255.255.255", got)
	}

	noFlagNoCiaddr := buildTestPacket(bootpOpReply, 1, [6]byte{}, net.IPv4zero, net.IPv4zero, 0, false, true)
	if got := determineClientDestination(noFlagNoCiaddr); !got.Equal(net.IPv4bcast) {
		t.Errorf("ciaddr zero, no broadcast flag: got %v, want 255.255.255.255 (relay always broadcasts here)", got)
	}
}

// ---- pending.go ----

func TestMakeTransactionKey(t *testing.T) {
	chaddr := [6]byte{1, 2, 3, 4, 5, 6}
	p := buildTestPacket(bootpOpRequest, 42, chaddr, net.IPv4zero, net.IPv4zero, 0, false, true)

	k1, ok := makeTransactionKey(p, net.IPv4(192, 168, 1, 1))
	if !ok {
		t.Fatal("makeTransactionKey: ok = false")
	}
	k2, ok := makeTransactionKey(p, net.IPv4(192, 168, 1, 1))
	if !ok {
		t.Fatal("makeTransactionKey: ok = false")
	}
	if k1 != k2 {
		t.Error("identical inputs produced different keys")
	}

	k3, ok := makeTransactionKey(p, net.IPv4(192, 168, 2, 1))
	if !ok {
		t.Fatal("makeTransactionKey: ok = false")
	}
	if k1 == k3 {
		t.Error("different giaddr produced the same key -- would let two VLANs' transactions collide")
	}

	if _, ok := makeTransactionKey(p, net.ParseIP("::1")); ok {
		t.Error("makeTransactionKey accepted a non-IPv4 giaddr")
	}
}

func TestPendingTable_AddHasDelete(t *testing.T) {
	pt := newPendingTable()
	k := txKey{xid: 1, giaddr: [4]byte{1, 1, 1, 1}}

	if pt.has(k) {
		t.Fatal("has = true before add")
	}
	if !pt.add(k) {
		t.Fatal("add = false")
	}
	if !pt.has(k) {
		t.Fatal("has = false after add")
	}
	if pt.globalCnt.Load() != 1 {
		t.Fatalf("globalCnt = %d, want 1", pt.globalCnt.Load())
	}
	pt.delete(k)
	if pt.has(k) {
		t.Fatal("has = true after delete")
	}
	if pt.globalCnt.Load() != 0 {
		t.Fatalf("globalCnt = %d, want 0", pt.globalCnt.Load())
	}
}

func TestPendingTable_RetransmitRefreshesWithoutDoubleCounting(t *testing.T) {
	pt := newPendingTable()
	k := txKey{xid: 7, giaddr: [4]byte{2, 2, 2, 2}}

	pt.add(k)
	pt.add(k) // simulated client retransmit before any reply arrived
	if pt.globalCnt.Load() != 1 {
		t.Fatalf("globalCnt = %d, want 1 (retransmit must not double-count)", pt.globalCnt.Load())
	}
}

func TestPendingTable_MaxPendingEnforced(t *testing.T) {
	pt := newPendingTable()
	for i := 0; i < MaxPending; i++ {
		k := txKey{xid: uint32(i)}
		if !pt.add(k) {
			t.Fatalf("add refused before reaching MaxPending, at i=%d", i)
		}
	}
	if pt.add(txKey{xid: MaxPending}) {
		t.Fatal("add succeeded past MaxPending")
	}
	if pt.globalCnt.Load() != MaxPending {
		t.Fatalf("globalCnt = %d, want %d", pt.globalCnt.Load(), MaxPending)
	}
}

func TestPendingTable_SweepRemovesOnlyExpired(t *testing.T) {
	pt := newPendingTable()
	fresh := txKey{xid: 1}
	stale := txKey{xid: 2}

	pt.add(fresh)
	pt.add(stale)

	// Force "stale" into the past directly, without waiting EntryTTL.
	s := pt.shard(stale)
	s.mu.Lock()
	s.entries[stale] = pendingEntry{expiresAt: time.Now().Add(-time.Second)}
	s.mu.Unlock()

	pt.sweepShard(int(stale.xid % ShardCount))
	pt.sweepShard(int(fresh.xid % ShardCount))

	if pt.has(stale) {
		t.Error("stale entry survived sweep")
	}
	if !pt.has(fresh) {
		t.Error("fresh entry was incorrectly removed by sweep")
	}
	if pt.globalCnt.Load() != 1 {
		t.Errorf("globalCnt = %d, want 1", pt.globalCnt.Load())
	}
}

func TestSweepInterval_IsSane(t *testing.T) {
	got := sweepInterval()
	if got <= 0 || got > EntryTTL {
		t.Fatalf("sweepInterval() = %v, want a small positive fraction of EntryTTL (%v)", got, EntryTTL)
	}
	if got > time.Minute {
		t.Fatalf("sweepInterval() = %v, suspiciously large -- looks like the EntryTTL/ShardCount*time.Second regression", got)
	}
}

// ---- config.go ----

func TestConfig_Validate(t *testing.T) {
	valid := func() Config {
		return Config{
			ServerAddr: "127.0.0.21:67",
			ClientInterfaces: []ClientInterfaceConfig{
				{Name: "ens19.200", GIAddr: "192.168.200.22"},
				{Name: "ens20.200", GIAddr: "172.16.200.22"},
			},
		}
	}

	vc := valid()
	if err := vc.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"empty client_interfaces", func(c *Config) { c.ClientInterfaces = nil }},
		{"empty server_addr", func(c *Config) { c.ServerAddr = "" }},
		{"unparseable server_addr", func(c *Config) { c.ServerAddr = "not-an-addr" }},
		{"empty interface name", func(c *Config) { c.ClientInterfaces[0].Name = "" }},
		{"duplicate interface name", func(c *Config) { c.ClientInterfaces[1].Name = c.ClientInterfaces[0].Name }},
		{"invalid giaddr", func(c *Config) { c.ClientInterfaces[0].GIAddr = "not-an-ip" }},
		{"unspecified giaddr", func(c *Config) { c.ClientInterfaces[0].GIAddr = "0.0.0.0" }},
		{"duplicate giaddr", func(c *Config) { c.ClientInterfaces[1].GIAddr = c.ClientInterfaces[0].GIAddr }},
		{"unparseable per-interface server_addr", func(c *Config) { c.ClientInterfaces[0].ServerAddr = "not-an-addr" }},
		{"invalid server_identifier", func(c *Config) { c.ClientInterfaces[0].ServerIdentifier = "not-an-ip" }},
		{"unspecified server_identifier", func(c *Config) { c.ClientInterfaces[0].ServerIdentifier = "0.0.0.0" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := valid()
			tc.mutate(&c)
			if err := c.Validate(); err == nil {
				t.Errorf("Validate() = nil, want an error")
			}
		})
	}
}

func TestConfig_Validate_PerInterfaceServerAddrOverrideAccepted(t *testing.T) {
	c := Config{
		ServerAddr: "127.0.0.21:67",
		ClientInterfaces: []ClientInterfaceConfig{
			{Name: "ens19.200", GIAddr: "192.168.200.22", ServerAddr: "127.0.1.21:67"},
		},
	}
	if err := c.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil for a valid per-interface server_addr override", err)
	}
}

func TestConfig_Validate_ServerIdentifierAccepted(t *testing.T) {
	c := Config{
		ServerAddr: "127.0.0.21:67",
		ClientInterfaces: []ClientInterfaceConfig{
			{Name: "ens19.200", GIAddr: "192.168.200.22", ServerIdentifier: "192.168.200.1"},
		},
	}
	if err := c.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil for a valid server_identifier", err)
	}
}

// ---- relay.go / client.go / server.go: fake transport ----

type fakeUDPConn struct {
	mu       sync.Mutex
	writes   []fakeWrite
	writeErr error
	closed   bool
	inbound  chan fakePacket // queued packets for ReadFromUDP; unset -> blocks forever
}

type fakeWrite struct {
	data []byte
	addr *net.UDPAddr
}

type fakePacket struct {
	data []byte
	from *net.UDPAddr
}

func newFakeUDPConn() *fakeUDPConn { return &fakeUDPConn{} }

// newFakeUDPConnWithInbound returns a fakeUDPConn whose ReadFromUDP yields
// each of packets in order, then blocks forever.
func newFakeUDPConnWithInbound(packets ...fakePacket) *fakeUDPConn {
	ch := make(chan fakePacket, len(packets))
	for _, p := range packets {
		ch <- p
	}
	return &fakeUDPConn{inbound: ch}
}

func (f *fakeUDPConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	if f.inbound == nil {
		<-make(chan struct{}) // never returns; tests drive handlers directly
		return 0, nil, nil
	}
	pkt := <-f.inbound
	n := copy(b, pkt.data)
	return n, pkt.from, nil
}

func (f *fakeUDPConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	f.writes = append(f.writes, fakeWrite{data: append([]byte(nil), b...), addr: addr})
	return len(b), nil
}

func (f *fakeUDPConn) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeUDPConn) lastWrite() (fakeWrite, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.writes) == 0 {
		return fakeWrite{}, false
	}
	return f.writes[len(f.writes)-1], true
}

func newTestRelay(t *testing.T) (*Relay, *fakeUDPConn, *clientInterface) {
	t.Helper()
	cfg := Config{
		ServerAddr: "127.0.0.21:67",
		ClientInterfaces: []ClientInterfaceConfig{
			{Name: "ens19.200", GIAddr: "192.168.200.22"},
		},
	}
	r, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	serverConn := newFakeUDPConn()
	r.setServerConn(serverConn)
	openTestGates(r)
	ci := r.clientIfaces[0]
	ci.conn = newFakeUDPConn()
	ci.reply = newFakeUDPConn()
	return r, serverConn, ci
}

// newTestRelayTwoBackends builds a relay with two client interfaces whose
// ServerAddr overrides point at two DIFFERENT backends.
func newTestRelayTwoBackends(t *testing.T) (r *Relay, serverConn *fakeUDPConn, ciA, ciB *clientInterface) {
	t.Helper()
	cfg := Config{
		ServerAddr: "127.0.0.21:67",
		ClientInterfaces: []ClientInterfaceConfig{
			{Name: "ens19.200", GIAddr: "192.168.200.22", ServerAddr: "127.0.1.21:67"},
			{Name: "ens20.50", GIAddr: "172.16.50.22", ServerAddr: "127.0.2.21:67"},
		},
	}
	relay, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	serverConn = newFakeUDPConn()
	relay.setServerConn(serverConn)
	openTestGates(relay)
	for _, cif := range relay.clientIfaces {
		cif.conn = newFakeUDPConn()
		cif.reply = newFakeUDPConn()
		switch cif.name {
		case "ens19.200":
			ciA = cif
		case "ens20.50":
			ciB = cif
		}
	}
	return relay, serverConn, ciA, ciB
}

func TestHandleClientRequest_RoutesToOwnBackendNotAnotherInterfacesOrTheDefault(t *testing.T) {
	r, serverConn, ciA, ciB := newTestRelayTwoBackends(t)

	reqA := buildTestPacket(bootpOpRequest, 1, [6]byte{1}, net.IPv4zero, net.IPv4zero, 0, true, true)
	r.handleClientRequest(ciA, reqA, &net.UDPAddr{IP: net.IPv4(192, 168, 200, 50), Port: 68})
	wA, ok := serverConn.lastWrite()
	if !ok {
		t.Fatal("ens19.200's request was never forwarded")
	}
	if !wA.addr.IP.Equal(net.IPv4(127, 0, 1, 21)) {
		t.Errorf("ens19.200 forwarded to %v, want 127.0.1.21 (its own backend)", wA.addr)
	}

	reqB := buildTestPacket(bootpOpRequest, 2, [6]byte{2}, net.IPv4zero, net.IPv4zero, 0, true, true)
	r.handleClientRequest(ciB, reqB, &net.UDPAddr{IP: net.IPv4(172, 16, 50, 50), Port: 68})
	wB, ok := serverConn.lastWrite()
	if !ok {
		t.Fatal("ens20.50's request was never forwarded")
	}
	if !wB.addr.IP.Equal(net.IPv4(127, 0, 2, 21)) {
		t.Errorf("ens20.50 forwarded to %v, want 127.0.2.21 (its own backend, not ens19.200's or the cluster default)", wB.addr)
	}
}

func TestHandleServerReply_RejectsReplyClaimingToBeFromAnotherInterfacesBackend(t *testing.T) {
	r, _, ciA, _ := newTestRelayTwoBackends(t)
	chaddr := [6]byte{5, 5, 5, 5, 5, 5}
	key, _ := makeTransactionKey(
		buildTestPacket(bootpOpRequest, 42, chaddr, net.IPv4zero, ciA.giaddr, 1, true, true), ciA.giaddr)
	r.pending.add(key)

	reply := buildTestPacket(bootpOpReply, 42, chaddr, net.IPv4zero, ciA.giaddr, 1, true, true)
	otherInterfacesBackend := &net.UDPAddr{IP: net.IPv4(127, 0, 2, 21), Port: 67} // ciB's backend, not ciA's
	r.handleServerReply(ciA, reply, otherInterfacesBackend)

	if _, ok := ciA.conn.(*fakeUDPConn).lastWrite(); ok {
		t.Error("accepted a reply on ciA's socket claiming to be from ciB's own backend address")
	}
}

// ---- client.go ----

func TestHandleClientRequest_StampsGIAddrHopsAndForwards(t *testing.T) {
	r, serverConn, ci := newTestRelay(t)
	chaddr := [6]byte{1, 2, 3, 4, 5, 6}
	req := buildTestPacket(bootpOpRequest, 99, chaddr, net.IPv4zero, net.IPv4zero, 3, true, true)

	r.handleClientRequest(ci, req, &net.UDPAddr{IP: net.IPv4(192, 168, 200, 50), Port: 68})

	sc := serverConn
	w, ok := sc.lastWrite()
	if !ok {
		t.Fatal("nothing forwarded to server")
	}
	if got := extractGIAddr(w.data); !got.Equal(ci.giaddr) {
		t.Errorf("forwarded giaddr = %v, want %v", got, ci.giaddr)
	}
	if got := w.data[bootpHopsOffset]; got != 4 {
		t.Errorf("hops = %d, want 4 (incremented from 3)", got)
	}
	if !w.addr.IP.Equal(r.serverAddr.IP) || w.addr.Port != r.serverAddr.Port {
		t.Errorf("forwarded to %v, want %v", w.addr, r.serverAddr)
	}

	key, _ := makeTransactionKey(w.data, ci.giaddr)
	if !r.pending.has(key) {
		t.Error("no pending transaction recorded")
	}
	if got := r.Snapshot().RequestsForwarded; got != 1 {
		t.Errorf("RequestsForwarded = %d, want 1", got)
	}
}

func TestHandleClientRequest_DropsWhenGIAddrAlreadySet(t *testing.T) {
	r, serverConn, ci := newTestRelay(t)
	req := buildTestPacket(bootpOpRequest, 1, [6]byte{}, net.IPv4zero, net.IPv4(10, 9, 9, 9), 0, true, true)

	r.handleClientRequest(ci, req, &net.UDPAddr{})

	if _, ok := serverConn.lastWrite(); ok {
		t.Error("forwarded a packet that already carried a foreign giaddr")
	}
	if got := r.Snapshot().RequestsDropped; got != 1 {
		t.Errorf("RequestsDropped = %d, want 1", got)
	}
}

func TestHandleClientRequest_DropsAtHopLimit(t *testing.T) {
	r, serverConn, ci := newTestRelay(t)
	req := buildTestPacket(bootpOpRequest, 1, [6]byte{}, net.IPv4zero, net.IPv4zero, maxHops, true, true)

	r.handleClientRequest(ci, req, &net.UDPAddr{})

	if _, ok := serverConn.lastWrite(); ok {
		t.Error("forwarded a packet at the hop limit")
	}
}

func TestHandleClientRequest_DropsNonRequestOp(t *testing.T) {
	r, serverConn, ci := newTestRelay(t)
	notARequest := buildTestPacket(bootpOpReply, 1, [6]byte{}, net.IPv4zero, net.IPv4zero, 0, true, true)

	r.handleClientRequest(ci, notARequest, &net.UDPAddr{})

	if _, ok := serverConn.lastWrite(); ok {
		t.Error("forwarded a non-request BOOTP op")
	}
}

func TestHandleClientRequest_DropsNonEthernetHtypeHlen(t *testing.T) {
	r, serverConn, ci := newTestRelay(t)
	badHtype := buildTestPacket(bootpOpRequest, 1, [6]byte{}, net.IPv4zero, net.IPv4zero, 0, true, true)
	badHtype[bootpHtypeOffset] = 6 // e.g. IEEE 802 Token Ring, not Ethernet

	r.handleClientRequest(ci, badHtype, &net.UDPAddr{})

	if _, ok := serverConn.lastWrite(); ok {
		t.Error("forwarded a packet claiming a non-Ethernet htype")
	}
	if got := r.Snapshot().RequestsDropped; got != 1 {
		t.Errorf("RequestsDropped = %d, want 1", got)
	}
}

func TestHandleClientRequest_DropsOverlongHlen(t *testing.T) {
	r, serverConn, ci := newTestRelay(t)
	badHlen := buildTestPacket(bootpOpRequest, 1, [6]byte{}, net.IPv4zero, net.IPv4zero, 0, true, true)
	badHlen[bootpHlenOffset] = 8 // longer than a real Ethernet MAC

	r.handleClientRequest(ci, badHlen, &net.UDPAddr{})

	if _, ok := serverConn.lastWrite(); ok {
		t.Error("forwarded a packet claiming hlen > 6")
	}
}

func TestHandleServerReplies_ReadsFromDedicatedReplySocket(t *testing.T) {
	r, _, ci := newTestRelay(t)
	chaddr := [6]byte{4, 4, 4, 4, 4, 4}
	key, _ := makeTransactionKey(
		buildTestPacket(bootpOpRequest, 321, chaddr, net.IPv4zero, ci.giaddr, 1, true, true), ci.giaddr)
	r.pending.add(key)

	reply := buildTestPacket(bootpOpReply, 321, chaddr, net.IPv4zero, ci.giaddr, 1, true, true)
	ci.reply = newFakeUDPConnWithInbound(fakePacket{data: reply, from: r.serverAddr})

	go r.handleServerReplies(ci)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if r.Snapshot().RepliesForwarded > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if snap := r.Snapshot(); snap.RepliesForwarded != 1 {
		t.Fatalf("RepliesForwarded = %d, want 1", snap.RepliesForwarded)
	}
	if _, ok := ci.conn.(*fakeUDPConn).lastWrite(); !ok {
		t.Error("reply was never written back out ci.conn (the client-facing socket)")
	}
}

// ---- server.go ----

func TestHandleServerReply_ForwardsToCorrectClientInterfaceAndClearsPending(t *testing.T) {
	r, _, ci := newTestRelay(t)
	chaddr := [6]byte{9, 9, 9, 9, 9, 9}

	key, _ := makeTransactionKey(
		buildTestPacket(bootpOpRequest, 55, chaddr, net.IPv4zero, ci.giaddr, 1, true, true), ci.giaddr)
	r.pending.add(key)

	reply := buildTestPacket(bootpOpReply, 55, chaddr, net.IPv4zero, ci.giaddr, 1, true, true)
	r.handleServerReply(ci, reply, r.serverAddr)

	cc := ci.conn.(*fakeUDPConn)
	w, ok := cc.lastWrite()
	if !ok {
		t.Fatal("nothing forwarded to the client interface")
	}
	if !w.addr.IP.Equal(net.IPv4bcast) || w.addr.Port != dhcpClientPort {
		t.Errorf("forwarded to %v, want broadcast:%d", w.addr, dhcpClientPort)
	}
	if r.pending.has(key) {
		t.Error("pending transaction not cleared after successful forward")
	}
	if got := r.Snapshot().RepliesForwarded; got != 1 {
		t.Errorf("RepliesForwarded = %d, want 1", got)
	}
}

func TestHandleServerReply_DropsUntrustedSource(t *testing.T) {
	r, _, ci := newTestRelay(t)
	reply := buildTestPacket(bootpOpReply, 1, [6]byte{}, net.IPv4zero, ci.giaddr, 0, true, true)

	spoofed := &net.UDPAddr{IP: net.IPv4(6, 6, 6, 6), Port: 67}
	r.handleServerReply(ci, reply, spoofed)

	if _, ok := ci.conn.(*fakeUDPConn).lastWrite(); ok {
		t.Error("forwarded a reply from an untrusted source")
	}
}

func TestHandleServerReply_AcceptsSelfAddressedSameHostSource(t *testing.T) {
	r, _, ci := newTestRelay(t)
	chaddr := [6]byte{7, 7, 7, 7, 7, 7}
	key, _ := makeTransactionKey(
		buildTestPacket(bootpOpRequest, 88, chaddr, net.IPv4zero, ci.giaddr, 1, true, true), ci.giaddr)
	r.pending.add(key)

	reply := buildTestPacket(bootpOpReply, 88, chaddr, net.IPv4zero, ci.giaddr, 1, true, true)
	selfAddressed := &net.UDPAddr{IP: ci.giaddr, Port: 67} // NOT r.serverAddr.IP
	r.handleServerReply(ci, reply, selfAddressed)

	if _, ok := ci.conn.(*fakeUDPConn).lastWrite(); !ok {
		t.Error("dropped a reply whose source was ci.giaddr itself -- the real, expected same-host symptom")
	}
}

func TestHandleServerReply_DropsWhenNoPendingTransaction(t *testing.T) {
	r, _, ci := newTestRelay(t)
	// Never registered as pending.
	reply := buildTestPacket(bootpOpReply, 123, [6]byte{}, net.IPv4zero, ci.giaddr, 0, true, true)

	r.handleServerReply(ci, reply, r.serverAddr)

	if _, ok := ci.conn.(*fakeUDPConn).lastWrite(); ok {
		t.Error("forwarded a reply with no matching pending transaction")
	}
}

func TestHandleServerReply_KeepsPendingOnWriteFailure(t *testing.T) {
	r, _, ci := newTestRelay(t)
	chaddr := [6]byte{1, 1, 1, 1, 1, 1}
	key, _ := makeTransactionKey(
		buildTestPacket(bootpOpRequest, 77, chaddr, net.IPv4zero, ci.giaddr, 1, true, true), ci.giaddr)
	r.pending.add(key)

	ci.conn.(*fakeUDPConn).writeErr = errors.New("simulated send failure")

	reply := buildTestPacket(bootpOpReply, 77, chaddr, net.IPv4zero, ci.giaddr, 1, true, true)
	r.handleServerReply(ci, reply, r.serverAddr)

	if !r.pending.has(key) {
		t.Error("pending transaction was cleared despite a failed downstream write -- a retry can no longer complete it")
	}
}

// TestEndToEndEmulatedRoundTrip drives both legs back-to-back through the
// real handler methods (no goroutines, no real sockets).
func TestEndToEndEmulatedRoundTrip(t *testing.T) {
	r, serverConn, ci := newTestRelay(t)
	chaddr := [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	discover := buildTestPacket(bootpOpRequest, 0xabcd1234, chaddr, net.IPv4zero, net.IPv4zero, 0, true, true)
	r.handleClientRequest(ci, discover, &net.UDPAddr{IP: net.IPv4(192, 168, 200, 77), Port: 68})

	forwarded, ok := serverConn.lastWrite()
	if !ok {
		t.Fatal("request never reached the server leg")
	}

	offer := append([]byte(nil), forwarded.data...)
	offer[bootpOpOffset] = bootpOpReply
	binary.BigEndian.PutUint32(offer[bootpYIAddrOffset:], binary.BigEndian.Uint32(net.IPv4(192, 168, 200, 100).To4()))

	r.handleServerReply(ci, offer, r.serverAddr)

	delivered, ok := ci.conn.(*fakeUDPConn).lastWrite()
	if !ok {
		t.Fatal("reply never reached the client leg")
	}
	if got := extractXID(delivered.data); got != 0xabcd1234 {
		t.Errorf("delivered xid = %#x, want 0xabcd1234", got)
	}
	if got := extractCHAddr(delivered.data); got != chaddr {
		t.Errorf("delivered chaddr = %v, want %v", got, chaddr)
	}

	snap := r.Snapshot()
	if snap.RequestsForwarded != 1 || snap.RepliesForwarded != 1 || snap.Pending != 0 {
		t.Errorf("snapshot = %+v, want RequestsForwarded=1 RepliesForwarded=1 Pending=0", snap)
	}
}

// ---- packet.go: rewriteServerIdentifier ----

// appendOption appends one DHCP option TLV (code, length byte, value) to
// p, matching the on-wire shape rewriteServerIdentifier walks.
func appendOption(p []byte, code byte, value []byte) []byte {
	p = append(p, code, byte(len(value)))
	p = append(p, value...)
	return p
}

func TestRewriteServerIdentifier_RewritesInPlaceWhenPresent(t *testing.T) {
	p := buildTestPacket(bootpOpReply, 1, [6]byte{}, net.IPv4zero, net.IPv4(192, 168, 200, 22), 1, true, true)
	p = appendOption(p, optServerIdentifier, net.IPv4(127, 0, 0, 1).To4())
	p = append(p, optEnd)

	origLen := len(p)
	if !rewriteServerIdentifier(p, net.IPv4(192, 168, 200, 22)) {
		t.Fatal("rewriteServerIdentifier = false, want true — option 54 is genuinely present")
	}
	if len(p) != origLen {
		t.Fatalf("packet length changed: got %d, want %d — this must be a same-length in-place overwrite", len(p), origLen)
	}

	got := findOption(t, p, optServerIdentifier)
	if !net.IP(got).Equal(net.IPv4(192, 168, 200, 22)) {
		t.Errorf("option 54 = %v, want 192.168.200.22 (this interface's own giaddr, not the backend's stale loopback identity)", net.IP(got))
	}
}

func TestRewriteServerIdentifier_LeavesSurroundingOptionsUntouched(t *testing.T) {
	p := buildTestPacket(bootpOpReply, 1, [6]byte{}, net.IPv4zero, net.IPv4(10, 0, 0, 1), 1, true, true)
	p = appendOption(p, 53, []byte{2}) // DHCP-Message: Offer
	p = appendOption(p, optServerIdentifier, net.IPv4(127, 0, 0, 1).To4())
	p = appendOption(p, 51, []byte{0, 0, 168, 192}) // Lease-Time, arbitrary bytes
	p = append(p, optEnd)

	if !rewriteServerIdentifier(p, net.IPv4(10, 0, 0, 1)) {
		t.Fatal("rewriteServerIdentifier = false, want true")
	}
	if got := findOption(t, p, 53); !bytesEqual(got, []byte{2}) {
		t.Errorf("option 53 (before) changed: got %v, want [2]", got)
	}
	if got := findOption(t, p, 51); !bytesEqual(got, []byte{0, 0, 168, 192}) {
		t.Errorf("option 51 (after) changed: got %v, want [0 0 168 192]", got)
	}
}

func TestRewriteServerIdentifier_NoOpWhenAbsent(t *testing.T) {
	p := buildTestPacket(bootpOpReply, 1, [6]byte{}, net.IPv4zero, net.IPv4zero, 0, true, true)
	p = appendOption(p, 53, []byte{2})
	p = append(p, optEnd)
	orig := append([]byte(nil), p...)

	if rewriteServerIdentifier(p, net.IPv4(10, 0, 0, 1)) {
		t.Error("rewriteServerIdentifier = true, want false — no option 54 present")
	}
	if !bytesEqual(p, orig) {
		t.Error("packet was modified despite option 54 being absent")
	}
}

func TestRewriteServerIdentifier_NoOpWhenWrongLength(t *testing.T) {
	p := buildTestPacket(bootpOpReply, 1, [6]byte{}, net.IPv4zero, net.IPv4zero, 0, true, true)
	p = appendOption(p, optServerIdentifier, []byte{1, 2, 3})
	p = append(p, optEnd)
	orig := append([]byte(nil), p...)

	if rewriteServerIdentifier(p, net.IPv4(10, 0, 0, 1)) {
		t.Error("rewriteServerIdentifier = true, want false — length 3, not the real 4-byte shape")
	}
	if !bytesEqual(p, orig) {
		t.Error("packet was modified despite the malformed option 54")
	}
}

func TestRewriteServerIdentifier_NoOpOnTruncatedOptionsList(t *testing.T) {
	p := buildTestPacket(bootpOpReply, 1, [6]byte{}, net.IPv4zero, net.IPv4zero, 0, true, true)
	// A length byte claiming more data than actually follows — must not
	// panic (an out-of-range slice) or read past the real packet.
	p = append(p, optServerIdentifier, 4, 1, 2) // claims 4 bytes, only 2 present

	if rewriteServerIdentifier(p, net.IPv4(10, 0, 0, 1)) {
		t.Error("rewriteServerIdentifier = true, want false — the options list is truncated/malformed")
	}
}

func TestRewriteServerIdentifier_ReturnsFalseForNonIPv4Target(t *testing.T) {
	p := buildTestPacket(bootpOpReply, 1, [6]byte{}, net.IPv4zero, net.IPv4zero, 0, true, true)
	p = appendOption(p, optServerIdentifier, net.IPv4(1, 2, 3, 4).To4())
	p = append(p, optEnd)

	if rewriteServerIdentifier(p, net.IPv6loopback) {
		t.Error("rewriteServerIdentifier = true, want false — an IPv6 target has no 4-byte form to write")
	}
}

func findOption(t *testing.T, p []byte, code byte) []byte {
	t.Helper()
	for i := dhcpOptionsOffset; i+1 < len(p); {
		c := p[i]
		if c == optEnd {
			break
		}
		if c == optPad {
			i++
			continue
		}
		length := int(p[i+1])
		valStart := i + 2
		valEnd := valStart + length
		if valEnd > len(p) {
			t.Fatalf("truncated options list while scanning for option %d", code)
		}
		if c == code {
			return p[valStart:valEnd]
		}
		i = valEnd
	}
	t.Fatalf("option %d not found", code)
	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestHandleServerReply_RewritesServerIdentifierToOwnGIAddr(t *testing.T) {
	r, _, ci := newTestRelay(t)
	chaddr := [6]byte{4, 4, 4, 4, 4, 4}
	key, _ := makeTransactionKey(
		buildTestPacket(bootpOpRequest, 42, chaddr, net.IPv4zero, ci.giaddr, 1, true, true), ci.giaddr)
	r.pending.add(key)

	reply := buildTestPacket(bootpOpReply, 42, chaddr, net.IPv4zero, ci.giaddr, 1, true, true)
	reply = appendOption(reply, optServerIdentifier, net.IPv4(127, 0, 0, 1).To4())
	reply = append(reply, optEnd)

	r.handleServerReply(ci, reply, r.serverAddr)

	delivered, ok := ci.conn.(*fakeUDPConn).lastWrite()
	if !ok {
		t.Fatal("reply never reached the client leg")
	}
	got := findOption(t, delivered.data, optServerIdentifier)
	if net.IP(got).Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatal("client received the backend's own confusing loopback address as server-id — a real client can never reach that on renewal")
	}
	if !net.IP(got).Equal(ci.giaddr) {
		t.Errorf("delivered option 54 = %v, want this interface's own giaddr %v", net.IP(got), ci.giaddr)
	}
}

func TestHandleServerReply_RewritesServerIdentifierToConfiguredVIP(t *testing.T) {
	cfg := Config{
		ServerAddr: "127.0.0.21:67",
		ClientInterfaces: []ClientInterfaceConfig{
			{Name: "ens19.200", GIAddr: "192.168.200.22", ServerIdentifier: "192.168.200.1"},
		},
	}
	r, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.setServerConn(newFakeUDPConn())
	openTestGates(r)
	ci := r.clientIfaces[0]
	ci.conn = newFakeUDPConn()
	ci.reply = newFakeUDPConn()

	chaddr := [6]byte{7, 7, 7, 7, 7, 7}
	key, _ := makeTransactionKey(
		buildTestPacket(bootpOpRequest, 55, chaddr, net.IPv4zero, ci.giaddr, 1, true, true), ci.giaddr)
	r.pending.add(key)

	reply := buildTestPacket(bootpOpReply, 55, chaddr, net.IPv4zero, ci.giaddr, 1, true, true)
	reply = appendOption(reply, optServerIdentifier, net.IPv4(127, 0, 0, 1).To4())
	reply = append(reply, optEnd)

	r.handleServerReply(ci, reply, r.serverAddr)

	delivered, ok := ci.conn.(*fakeUDPConn).lastWrite()
	if !ok {
		t.Fatal("reply never reached the client leg")
	}
	got := findOption(t, delivered.data, optServerIdentifier)
	want := net.IPv4(192, 168, 200, 1).To4()
	if !net.IP(got).Equal(want) {
		t.Errorf("delivered option 54 = %v, want the configured VIP %v, not giaddr %v", net.IP(got), want, ci.giaddr)
	}
}

// TestResolveServerIdentifier_FallsBackToGIAddrWhenUnset checks a scope
// with no VIP falls back to GIAddr.
func TestResolveServerIdentifier_FallsBackToGIAddrWhenUnset(t *testing.T) {
	giaddr := net.IPv4(192, 168, 200, 22).To4()
	got := resolveServerIdentifier("", giaddr)
	if !got.Equal(giaddr) {
		t.Errorf("resolveServerIdentifier(\"\", %v) = %v, want giaddr unchanged", giaddr, got)
	}
}

// TestResolveServerIdentifier_UsesConfiguredValueWhenSet is the mirror
// positive case.
func TestResolveServerIdentifier_UsesConfiguredValueWhenSet(t *testing.T) {
	giaddr := net.IPv4(192, 168, 200, 22).To4()
	got := resolveServerIdentifier("192.168.200.1", giaddr)
	want := net.IPv4(192, 168, 200, 1).To4()
	if !got.Equal(want) {
		t.Errorf("resolveServerIdentifier = %v, want configured VIP %v", got, want)
	}
}

func TestHandleClientRequest_RewritesServerIdentifierToDnsmasqSelfIdentity(t *testing.T) {
	r, serverConn, ci := newTestRelay(t)
	chaddr := [6]byte{5, 5, 5, 5, 5, 5}
	req := buildTestPacket(bootpOpRequest, 99, chaddr, net.IPv4zero, net.IPv4zero, 0, true, true)
	req = appendOption(req, optServerIdentifier, ci.giaddr.To4()) // exactly what a real client legitimately echoes back
	req = append(req, optEnd)

	r.handleClientRequest(ci, req, &net.UDPAddr{IP: net.IPv4(192, 168, 200, 50), Port: 68})

	forwarded, ok := serverConn.lastWrite()
	if !ok {
		t.Fatal("request never reached the server leg")
	}
	got := findOption(t, forwarded.data, optServerIdentifier)
	if net.IP(got).Equal(ci.giaddr) {
		t.Fatal("dnsmasq received the relay's own giaddr as server-id — it silently rejects this per RFC 2131 (confirmed live, this exact bug silently dropped every client's first-ever DHCP request)")
	}
	if !net.IP(got).Equal(dnsmasqSelfIdentity) {
		t.Errorf("forwarded option 54 = %v, want dnsmasq's own real identity %v", net.IP(got), dnsmasqSelfIdentity)
	}
}

func TestHandleClientRequest_NoServerIdentifierIsUnaffected(t *testing.T) {
	r, serverConn, ci := newTestRelay(t)
	chaddr := [6]byte{6, 6, 6, 6, 6, 6}
	req := buildTestPacket(bootpOpRequest, 100, chaddr, net.IPv4(192, 168, 200, 77), net.IPv4zero, 0, false, true)
	req = append(req, optEnd)

	r.handleClientRequest(ci, req, &net.UDPAddr{IP: net.IPv4(192, 168, 200, 77), Port: 68})

	forwarded, ok := serverConn.lastWrite()
	if !ok {
		t.Fatal("request never reached the server leg")
	}
	if rewriteServerIdentifier(forwarded.data, net.IPv4(9, 9, 9, 9)) {
		t.Error("a request with no server-identifier option must stay that way — rewriteServerIdentifier found one to rewrite, want none present")
	}
}

func TestCurrentIfIndex_RealLoopbackAndBogusName(t *testing.T) {
	if idx := currentIfIndex("lo"); idx == 0 {
		t.Error("currentIfIndex(\"lo\") = 0, want a real, nonzero ifindex — lo always exists")
	}
	if idx := currentIfIndex("dnshived-test-bogus-iface-xyz"); idx != 0 {
		t.Errorf("currentIfIndex(bogus name) = %d, want 0", idx)
	}
}
