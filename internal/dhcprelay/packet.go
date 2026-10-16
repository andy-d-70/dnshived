// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcprelay

import (
	"encoding/binary"
	"net"
)

// BOOTP/DHCP wire-format offsets (RFC 951, extended by RFC 2131).
const (
	bootpOpOffset     = 0
	bootpHtypeOffset  = 1
	bootpHlenOffset   = 2
	bootpHopsOffset   = 3
	bootpXIDOffset    = 4
	bootpFlagsOffset  = 10
	bootpCIAddrOffset = 12
	bootpYIAddrOffset = 16
	bootpGIAddrOffset = 24
	bootpCHAddrOffset = 28

	dhcpMagicCookieOffset = 236
	dhcpOptionsOffset     = 240

	optServerIdentifier = 54
	optEnd              = 0xff
	optPad              = 0x00

	bootpOpRequest = 1
	bootpOpReply   = 2

	// bootpHtypeEthernet/bootpHlenEthernet are the only hardware-type/
	// address-length combination this relay ever expects on a real
	// client-facing VLAN interface.
	bootpHtypeEthernet = 1
	bootpHlenEthernet  = 6

	dhcpServerPort = 67
	dhcpClientPort = 68

	// dhcpMinBOOTPLen is the fixed BOOTP header length.
	dhcpMinBOOTPLen = 236

	// maxHops matches the BOOTP/DHCP relay-agent convention (most
	// implementations, including ISC's, default to 16).
	maxHops = 16

	maxPacketLen = 1500
)

var dhcpMagicCookie = [4]byte{0x63, 0x82, 0x53, 0x63}

func extractGIAddr(p []byte) net.IP {
	return net.IP(append([]byte(nil), p[bootpGIAddrOffset:bootpGIAddrOffset+4]...))
}

func extractCIAddr(p []byte) net.IP {
	return net.IP(append([]byte(nil), p[bootpCIAddrOffset:bootpCIAddrOffset+4]...))
}

func extractXID(p []byte) uint32 {
	return binary.BigEndian.Uint32(p[bootpXIDOffset : bootpXIDOffset+4])
}

// extractCHAddr returns the client hardware address, clamped to 6 bytes.
func extractCHAddr(p []byte) [6]byte {
	hlen := int(p[bootpHlenOffset])
	if hlen > 6 {
		hlen = 6
	}
	var mac [6]byte
	copy(mac[:], p[bootpCHAddrOffset:bootpCHAddrOffset+hlen])
	return mac
}

// isBroadcastFlagSet reports the client's BOOTP broadcast flag (RFC 2131
// §2, the top bit of the flags field).
func isBroadcastFlagSet(p []byte) bool {
	flags := binary.BigEndian.Uint16(p[bootpFlagsOffset : bootpFlagsOffset+2])
	return flags&0x8000 != 0
}

// isDHCPPacket reports whether p carries the DHCP magic cookie, as opposed
// to being plain pre-DHCP BOOTP.
func isDHCPPacket(p []byte) bool {
	if len(p) < dhcpOptionsOffset {
		return false
	}
	var cookie [4]byte
	copy(cookie[:], p[dhcpMagicCookieOffset:dhcpMagicCookieOffset+4])
	return cookie == dhcpMagicCookie
}

// determineClientDestination decides where to send a relayed reply on the
// client segment.
func determineClientDestination(p []byte) net.IP {
	ciaddr := extractCIAddr(p)
	if !ciaddr.Equal(net.IPv4zero) {
		return ciaddr
	}
	return net.IPv4bcast
}

// rewriteServerIdentifier overwrites option 54 (server identifier) in
// place with newID, and reports whether it found (and rewrote) one.
var dnsmasqSelfIdentity = net.IPv4(127, 0, 0, 1)

func rewriteServerIdentifier(p []byte, newID net.IP) bool {
	newID4 := newID.To4()
	if newID4 == nil {
		return false
	}
	for i := dhcpOptionsOffset; i+1 < len(p); {
		code := p[i]
		if code == optEnd {
			return false
		}
		if code == optPad {
			i++
			continue
		}
		length := int(p[i+1])
		valStart := i + 2
		valEnd := valStart + length
		if valEnd > len(p) {
			return false // truncated/malformed options list -- stop, don't guess
		}
		if code == optServerIdentifier && length == 4 {
			copy(p[valStart:valEnd], newID4)
			return true
		}
		i = valEnd
	}
	return false
}
