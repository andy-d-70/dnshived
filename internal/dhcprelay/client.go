// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcprelay

import "net"

func (r *Relay) handleClientRequests(ci *clientInterface) {
	buf := make([]byte, maxPacketLen)
	for {
		n, from, err := ci.conn.ReadFromUDP(buf)
		if err != nil {
			if r.closing.Load() || ci.removing.Load() {
				return
			}
			r.logThrottled("client_read_error:"+ci.name, "read from %s: %v", ci.name, err)
			continue
		}
		packet := append([]byte(nil), buf[:n]...)
		r.handleClientRequest(ci, packet, from)
	}
}

func (r *Relay) handleClientRequest(ci *clientInterface, packet []byte, from *net.UDPAddr) {
	r.metrics.requestsSeen.Add(1)

	rate, burst := int(ci.rateLimit.Load()), int(ci.rateBurst.Load())
	if !ci.limiter.allow(rate, burst) {
		r.metrics.requestsDropped.Add(1)
		r.metrics.requestsRateLimited.Add(1)
		r.logThrottled("rate_limit:"+ci.name, "[RATELIMIT] dropped DHCP request from %s on %s: rate limit exceeded (%d/s burst %d)", from, ci.name, rate, burst)
		return
	}

	if len(packet) < dhcpMinBOOTPLen {
		r.metrics.requestsDropped.Add(1)
		return
	}
	if packet[bootpOpOffset] != bootpOpRequest {
		r.metrics.requestsDropped.Add(1)
		return
	}

	if packet[bootpHtypeOffset] != bootpHtypeEthernet || packet[bootpHlenOffset] != bootpHlenEthernet {
		r.metrics.requestsDropped.Add(1)
		r.logThrottled("bad_htype:"+ci.name, "dropping request from %s on %s: non-Ethernet htype=%d hlen=%d", from, ci.name, packet[bootpHtypeOffset], packet[bootpHlenOffset])
		return
	}

	if existing := extractGIAddr(packet); !existing.Equal(net.IPv4zero) {
		r.metrics.requestsDropped.Add(1)
		return
	}

	hops := packet[bootpHopsOffset]
	if hops >= maxHops {
		r.metrics.requestsDropped.Add(1)
		r.logThrottled("hop_limit:"+ci.name, "dropping request from %s on %s: hop limit reached", from, ci.name)
		return
	}
	packet[bootpHopsOffset] = hops + 1
	copy(packet[bootpGIAddrOffset:bootpGIAddrOffset+4], ci.giaddr.To4())

	rewriteServerIdentifier(packet, dnsmasqSelfIdentity)

	key, ok := makeTransactionKey(packet, ci.giaddr)
	if !ok {
		r.metrics.requestsDropped.Add(1)
		return
	}
	if !r.pending.add(key) {
		r.metrics.requestsDropped.Add(1)
		r.logThrottled("pending_full", "pending-transaction table full (max %d); dropping request from %s on %s", MaxPending, from, ci.name)
		return
	}

	if _, err := r.serverConn.WriteToUDP(packet, ci.serverAddr); err != nil {
		r.pending.delete(key)
		r.metrics.requestsDropped.Add(1)
		r.logThrottled("upstream_write_error", "forward request to server: %v", err)
		return
	}
	r.metrics.requestsForwarded.Add(1)
}
