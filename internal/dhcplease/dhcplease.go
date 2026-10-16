// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcplease

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Lease struct {
	Expiry       time.Time `json:"expiry"`
	NeverExpires bool      `json:"never_expires"`
	MAC          string    `json:"mac"`
	IP           string    `json:"ip"`
	// Hostname is empty when dnsmasq wrote "*" (client sent none).
	Hostname string `json:"hostname,omitempty"`
	// ClientID is empty when dnsmasq wrote "*" (client sent none).
	ClientID string `json:"client_id,omitempty"`
}

// ParseFile reads and parses a dnsmasq lease file.
func ParseFile(path string) ([]Lease, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var leases []Lease
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		if l, ok := parseLine(line); ok {
			leases = append(leases, l)
		}
	}
	return leases, nil
}

func parseLine(line string) (Lease, bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return Lease{}, false
	}
	expirySec, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return Lease{}, false
	}
	l := Lease{MAC: fields[1], IP: fields[2]}
	if expirySec == 0 {
		l.NeverExpires = true
	} else {
		l.Expiry = time.Unix(expirySec, 0)
	}
	if len(fields) >= 4 && fields[3] != "*" {
		l.Hostname = fields[3]
	}
	if len(fields) >= 5 && fields[4] != "*" {
		l.ClientID = fields[4]
	}
	return l, true
}

// PoolSize returns the number of usable addresses in [start, end] (both
// inclusive) — the denominator for the scope detail page's pool-usage
// figure.
func PoolSize(start, end string) (int, error) {
	s := net.ParseIP(start).To4()
	e := net.ParseIP(end).To4()
	if s == nil {
		return 0, fmt.Errorf("invalid pool start address %q", start)
	}
	if e == nil {
		return 0, fmt.Errorf("invalid pool end address %q", end)
	}
	sInt := binary.BigEndian.Uint32(s)
	eInt := binary.BigEndian.Uint32(e)
	if eInt < sInt {
		return 0, fmt.Errorf("pool end %q is before start %q", end, start)
	}
	return int(eInt-sInt) + 1, nil
}

// InRange reports whether ip falls within [start, end] (both inclusive).
func InRange(ip, start, end string) bool {
	ipN := net.ParseIP(ip).To4()
	s := net.ParseIP(start).To4()
	e := net.ParseIP(end).To4()
	if ipN == nil || s == nil || e == nil {
		return false
	}
	ipInt := binary.BigEndian.Uint32(ipN)
	sInt := binary.BigEndian.Uint32(s)
	eInt := binary.BigEndian.Uint32(e)
	return ipInt >= sInt && ipInt <= eInt
}

// dnsmasqServerIdentity is central DHCP's own structurally-fixed
// self-identity.
var dnsmasqServerIdentity = net.IPv4(127, 0, 0, 1)

// BuildReleasePacket builds a real DHCPRELEASE message (RFC 2131 §4.4.4)
// on behalf of the client identified by mac/ip.
func BuildReleasePacket(mac, ip string) ([]byte, error) {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return nil, fmt.Errorf("invalid MAC %q", mac)
	}
	ciaddr := net.ParseIP(ip).To4()
	if ciaddr == nil {
		return nil, fmt.Errorf("invalid IP %q", ip)
	}

	buf := make([]byte, 236, 300)
	buf[0] = 1 // op = BOOTREQUEST
	buf[1] = 1 // htype = Ethernet
	buf[2] = 6 // hlen
	binary.BigEndian.PutUint32(buf[4:8], rand.Uint32())
	copy(buf[12:16], ciaddr)
	copy(buf[28:34], hw)
	// magic cookie
	buf = append(buf, 0x63, 0x82, 0x53, 0x63)
	buf = append(buf, 53, 1, 7) // option 53: DHCPRELEASE
	buf = append(buf, 54, 4)
	buf = append(buf, dnsmasqServerIdentity.To4()...) // option 54: REQUIRED, see doc comment
	buf = append(buf, 255)                            // end
	return buf, nil
}

// SendRelease builds and sends a DHCPRELEASE for mac/ip directly to
// centralDHCPAddr's own port 67 (dhcpcentralrender.DefaultAddress in
// practice).
func SendRelease(centralDHCPAddr, mac, ip string) error {
	pkt, err := BuildReleasePacket(mac, ip)
	if err != nil {
		return err
	}
	conn, err := net.Dial("udp4", net.JoinHostPort(centralDHCPAddr, "67"))
	if err != nil {
		return fmt.Errorf("dial central DHCP: %w", err)
	}
	defer conn.Close()
	if _, err := conn.Write(pkt); err != nil {
		return fmt.Errorf("send DHCPRELEASE: %w", err)
	}
	return nil
}
