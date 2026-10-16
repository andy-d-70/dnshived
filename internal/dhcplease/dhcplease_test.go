// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcplease

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseFile_ParsesRealLeaseFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leases-rw-100")
	content := "1754760000 02:ad:55:28:0e:e5 172.16.100.153 myhost 01:02:ad:55:28:0e:e5\n"
	os.WriteFile(path, []byte(content), 0o644)

	leases, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("leases = %d, want 1", len(leases))
	}
	l := leases[0]
	if l.MAC != "02:ad:55:28:0e:e5" || l.IP != "172.16.100.153" {
		t.Errorf("MAC/IP = %q/%q, want 02:ad:55:28:0e:e5/172.16.100.153", l.MAC, l.IP)
	}
	if l.Hostname != "myhost" {
		t.Errorf("Hostname = %q, want myhost", l.Hostname)
	}
	if l.ClientID != "01:02:ad:55:28:0e:e5" {
		t.Errorf("ClientID = %q", l.ClientID)
	}
	if l.NeverExpires {
		t.Error("NeverExpires = true, want false for a normal timed lease")
	}
	if !l.Expiry.Equal(time.Unix(1754760000, 0)) {
		t.Errorf("Expiry = %v, want %v", l.Expiry, time.Unix(1754760000, 0))
	}
}

func TestParseFile_AsteriskFieldsAreEmptyNotLiteral(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leases-rw-100")
	os.WriteFile(path, []byte("1754760000 aa:bb:cc:dd:ee:ff 172.16.100.100 * *\n"), 0o644)

	leases, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if leases[0].Hostname != "" {
		t.Errorf("Hostname = %q, want empty (not literal *)", leases[0].Hostname)
	}
	if leases[0].ClientID != "" {
		t.Errorf("ClientID = %q, want empty (not literal *)", leases[0].ClientID)
	}
}

func TestParseFile_ZeroExpirySetsNeverExpires(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leases-rw-100")
	os.WriteFile(path, []byte("0 aa:bb:cc:dd:ee:ff 172.16.100.100 reserved-host *\n"), 0o644)

	leases, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if !leases[0].NeverExpires {
		t.Error("NeverExpires = false, want true for expiry=0")
	}
}

func TestParseFile_MalformedLineSkippedNotFatal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leases-rw-100")
	content := "not-a-valid-line\n1754760000 aa:bb:cc:dd:ee:ff 172.16.100.100 host *\n\ntoo few\n"
	os.WriteFile(path, []byte(content), 0o644)

	leases, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(leases) != 1 {
		t.Fatalf("leases = %d, want 1 (malformed lines skipped, not fatal)", len(leases))
	}
	if leases[0].IP != "172.16.100.100" {
		t.Errorf("got the wrong lease: %+v", leases[0])
	}
}

func TestParseFile_MissingFileReturnsNilNoError(t *testing.T) {
	leases, err := ParseFile("/nonexistent/leases-rw-100")
	if err != nil {
		t.Errorf("err = %v, want nil for a missing file", err)
	}
	if leases != nil {
		t.Errorf("leases = %v, want nil", leases)
	}
}

func TestPoolSize_ComputesInclusiveRange(t *testing.T) {
	n, err := PoolSize("172.16.100.100", "172.16.100.200")
	if err != nil {
		t.Fatalf("PoolSize: %v", err)
	}
	if n != 101 {
		t.Errorf("PoolSize = %d, want 101 (inclusive of both ends)", n)
	}
}

func TestPoolSize_SingleAddressRange(t *testing.T) {
	n, err := PoolSize("172.16.100.100", "172.16.100.100")
	if err != nil {
		t.Fatalf("PoolSize: %v", err)
	}
	if n != 1 {
		t.Errorf("PoolSize = %d, want 1", n)
	}
}

func TestPoolSize_RejectsEndBeforeStart(t *testing.T) {
	if _, err := PoolSize("172.16.100.200", "172.16.100.100"); err == nil {
		t.Error("expected an error when end precedes start")
	}
}

func TestPoolSize_RejectsInvalidAddresses(t *testing.T) {
	if _, err := PoolSize("not-an-ip", "172.16.100.100"); err == nil {
		t.Error("expected an error for an invalid start address")
	}
	if _, err := PoolSize("172.16.100.100", "not-an-ip"); err == nil {
		t.Error("expected an error for an invalid end address")
	}
}

func TestInRange_InsideBounds(t *testing.T) {
	if !InRange("10.77.59.150", "10.77.59.100", "10.77.59.200") {
		t.Error("InRange() = false for an address strictly inside the range")
	}
}

func TestInRange_AtBothEndsInclusive(t *testing.T) {
	if !InRange("10.77.59.100", "10.77.59.100", "10.77.59.200") {
		t.Error("InRange() = false at the start address, want inclusive")
	}
	if !InRange("10.77.59.200", "10.77.59.100", "10.77.59.200") {
		t.Error("InRange() = false at the end address, want inclusive")
	}
}

func TestInRange_OutsideBounds(t *testing.T) {
	if InRange("10.77.59.99", "10.77.59.100", "10.77.59.200") {
		t.Error("InRange() = true just below the start address")
	}
	if InRange("10.77.59.201", "10.77.59.100", "10.77.59.200") {
		t.Error("InRange() = true just above the end address")
	}
	if InRange("172.17.43.150", "10.77.59.100", "10.77.59.200") {
		t.Error("InRange() = true for an address in a completely different subnet — the real case this fix exists for (another scope's own lease)")
	}
}

func TestInRange_MalformedInputIsFalseNotPanic(t *testing.T) {
	if InRange("not-an-ip", "10.77.59.100", "10.77.59.200") {
		t.Error("InRange() = true for a malformed ip, want false")
	}
	if InRange("10.77.59.150", "not-an-ip", "10.77.59.200") {
		t.Error("InRange() = true for a malformed start, want false")
	}
}

// TestBuildReleasePacket_FieldsMatchRFC2131 checks the release packet's
// fields against RFC 2131.
func TestBuildReleasePacket_FieldsMatchRFC2131(t *testing.T) {
	pkt, err := BuildReleasePacket("aa:bb:cc:dd:ee:01", "10.0.0.5")
	if err != nil {
		t.Fatalf("BuildReleasePacket: %v", err)
	}
	if pkt[0] != 1 {
		t.Errorf("op = %d, want 1 (BOOTREQUEST)", pkt[0])
	}
	if pkt[1] != 1 || pkt[2] != 6 {
		t.Errorf("htype/hlen = %d/%d, want 1/6 (Ethernet)", pkt[1], pkt[2])
	}
	wantCiaddr := net.ParseIP("10.0.0.5").To4()
	if !bytesEqual(pkt[12:16], wantCiaddr) {
		t.Errorf("ciaddr = %v, want %v (RFC 2131: RELEASE fills ciaddr, not yiaddr/requested-ip)", pkt[12:16], wantCiaddr)
	}
	wantMAC, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	if !bytesEqual(pkt[28:34], wantMAC) {
		t.Errorf("chaddr = %v, want %v", pkt[28:34], wantMAC)
	}
	// magic cookie at 236:240, options start at 240.
	opts := pkt[240:]
	if opts[0] != 53 || opts[1] != 1 || opts[2] != 7 {
		t.Fatalf("option 53 (message-type) = %v, want [53 1 7] (DHCPRELEASE)", opts[:3])
	}
	if opts[3] != 54 || opts[4] != 4 {
		t.Fatalf("option 54 (server-identifier) header = %v, want [54 4 ...] — required by dnsmasq's own real source (rfc2131.c), silently dropped without it", opts[3:5])
	}
	wantServerID := dnsmasqServerIdentity.To4()
	if !bytesEqual(opts[5:9], wantServerID) {
		t.Errorf("server-identifier = %v, want %v (dnsmasq's own self-identity, not its real bind address)", opts[5:9], wantServerID)
	}
	if opts[9] != 255 {
		t.Errorf("last byte = %d, want 255 (end option)", opts[9])
	}
}

func TestBuildReleasePacket_RejectsMalformedInput(t *testing.T) {
	if _, err := BuildReleasePacket("not-a-mac", "10.0.0.5"); err == nil {
		t.Error("expected an error for a malformed MAC")
	}
	if _, err := BuildReleasePacket("aa:bb:cc:dd:ee:01", "not-an-ip"); err == nil {
		t.Error("expected an error for a malformed IP")
	}
}

func TestSendRelease_DeliversAValidPacketToARealListener(t *testing.T) {
	ln, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.LocalAddr().String())

	pkt, err := BuildReleasePacket("aa:bb:cc:dd:ee:02", "10.0.0.9")
	if err != nil {
		t.Fatalf("BuildReleasePacket: %v", err)
	}
	conn, err := net.Dial("udp4", "127.0.0.1:"+port)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(pkt); err != nil {
		t.Fatalf("Write: %v", err)
	}

	buf := make([]byte, 400)
	ln.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := ln.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if n != len(pkt) {
		t.Fatalf("received %d bytes, want %d", n, len(pkt))
	}
	if !bytesEqual(buf[:n], pkt) {
		t.Error("received packet doesn't match what was sent")
	}
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
