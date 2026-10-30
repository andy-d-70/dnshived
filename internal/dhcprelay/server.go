// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcprelay

import (
	"bytes"
	"net"
	"time"
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
	ci.stats.repliesSeen.Add(1)
	if !r.gates.allows(ci.gate, time.Now()) {
		r.metrics.repliesDropped.Add(1)
		r.metrics.gateClosedReplies.Add(1)
		ci.stats.drop(dropGateClosed)
		return
	}

	if !r.isValidServerSource(from, ci) {
		r.metrics.repliesDropped.Add(1)
		ci.stats.drop(dropBadSource)
		return
	}
	if len(packet) < dhcpMinBOOTPLen {
		r.metrics.repliesDropped.Add(1)
		ci.stats.drop(dropMalformed)
		return
	}

	if !bytes.Equal(packet[bootpGIAddrOffset:bootpGIAddrOffset+4], ci.giaddr.To4()) {
		r.metrics.repliesDropped.Add(1)
		ci.stats.drop(dropGIAddr)
		return
	}

	key, ok := makeTransactionKey(packet, ci.giaddr)
	if !ok {
		r.metrics.repliesDropped.Add(1)
		ci.stats.drop(dropTransactionKey)
		return
	}

	if !r.pending.has(key) {
		r.metrics.repliesDropped.Add(1)
		ci.stats.drop(dropUnknownTransaction)
		return
	}

	rewriteServerIdentifier(packet, ci.effectiveServerIdentifier())

	dst := clientDestination(packet)

	if _, err := ci.conn.WriteToUDP(packet, dst); err != nil {
		r.metrics.repliesDropped.Add(1)
		ci.stats.drop(dropDownstreamWrite)
		r.logThrottled(throttleKey{"downstream_write_error", ci.name}, "forward reply to %s via %s: %v", dst, ci.name, err)
		return
	}

	r.pending.delete(key)
	r.metrics.repliesForwarded.Add(1)
	ci.stats.repliesForwarded.Add(1)
}
