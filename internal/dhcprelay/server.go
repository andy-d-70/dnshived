// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcprelay

import "net"

func (r *Relay) handleServerReplies(ci *clientInterface) {
	buf := make([]byte, maxPacketLen)
	for {
		n, from, err := ci.reply.ReadFromUDP(buf)
		if err != nil {
			if r.closing.Load() || ci.removing.Load() {
				return
			}
			r.logThrottled("reply_read_error:"+ci.name, "read reply socket for %s: %v", ci.name, err)
			continue
		}
		packet := append([]byte(nil), buf[:n]...)
		r.handleServerReply(ci, packet, from)
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

	giaddr := extractGIAddr(packet)
	if !giaddr.Equal(ci.giaddr) {
		r.metrics.repliesDropped.Add(1)
		return
	}

	key, ok := makeTransactionKey(packet, giaddr)
	if !ok {
		r.metrics.repliesDropped.Add(1)
		return
	}

	if !r.pending.has(key) {
		r.metrics.repliesDropped.Add(1)
		return
	}

	rewriteServerIdentifier(packet, ci.effectiveServerIdentifier())

	dst := &net.UDPAddr{IP: determineClientDestination(packet), Port: dhcpClientPort}

	if _, err := ci.conn.WriteToUDP(packet, dst); err != nil {
		r.logThrottled("downstream_write_error:"+ci.name, "forward reply to %s via %s: %v", dst, ci.name, err)
		return
	}

	r.pending.delete(key)
	r.metrics.repliesForwarded.Add(1)
}
