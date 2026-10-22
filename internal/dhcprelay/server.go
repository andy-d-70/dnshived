// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcprelay

import (
	"bytes"
	"net"
)

func (r *Relay) handleServerReplies(ci *clientInterface) {
	buf := make([]byte, maxPacketLen)
	for {
		n, from, err := ci.reply.ReadFromUDP(buf)
		if err != nil {
			if r.closing.Load() || ci.removing.Load() {
				return
			}
			r.logThrottled(throttleKey{"reply_read_error", ci.name}, "read reply socket for %s: %v", ci.name, err)
			continue
		}
		r.handleServerReply(ci, buf[:n], from)
	}
}

func (r *Relay) handleServerReply(ci *clientInterface, packet []byte, from *net.UDPAddr) {
	r.metrics.repliesSeen.Add(1)

	if !r.isValidServerSource(from, ci) {
		r.metrics.repliesDropped.Add(1)
		return
	}
	if len(packet) < dhcpMinBOOTPLen {
		r.metrics.repliesDropped.Add(1)
		return
	}

	if !bytes.Equal(packet[bootpGIAddrOffset:bootpGIAddrOffset+4], ci.giaddr.To4()) {
		r.metrics.repliesDropped.Add(1)
		return
	}

	key, ok := makeTransactionKey(packet, ci.giaddr)
	if !ok {
		r.metrics.repliesDropped.Add(1)
		return
	}

	if !r.pending.has(key) {
		r.metrics.repliesDropped.Add(1)
		return
	}

	rewriteServerIdentifier(packet, ci.effectiveServerIdentifier())

	dst := clientDestination(packet)

	if _, err := ci.conn.WriteToUDP(packet, dst); err != nil {
		r.logThrottled(throttleKey{"downstream_write_error", ci.name}, "forward reply to %s via %s: %v", dst, ci.name, err)
		return
	}

	r.pending.delete(key)
	r.metrics.repliesForwarded.Add(1)
}
