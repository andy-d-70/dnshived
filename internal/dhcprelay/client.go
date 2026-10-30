// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcprelay

import (
	"log"
	"net"
	"time"
)

func (r *Relay) handleClientRequests(ci *clientInterface) {
	buf := make([]byte, maxPacketLen)
	for {
		n, from, err := ci.conn.ReadFromUDP(buf)
		if err != nil {
			if r.closing.Load() || ci.removing.Load() {
				return
			}
			r.logThrottled(throttleKey{"client_read_error", ci.name}, "read from %s: %v", ci.name, err)
			continue
		}
		r.handleClientRequest(ci, buf[:n], from)
	}
}

func (r *Relay) handleClientRequest(ci *clientInterface, packet []byte, from *net.UDPAddr) {
	r.metrics.requestsSeen.Add(1)
	ci.stats.requestsSeen.Add(1)
	now := time.Now()
	if !r.gates.allows(ci.gate, now) {
		r.metrics.requestsDropped.Add(1)
		r.metrics.gateClosedRequests.Add(1)
		ci.stats.drop(dropGateClosed)
		return
	}

	rate, burst := int(ci.rateLimit.Load()), int(ci.rateBurst.Load())
	if !ci.limiter.allow(now, rate, burst) {
		r.metrics.requestsDropped.Add(1)
		r.metrics.requestsRateLimited.Add(1)
		ci.stats.drop(dropRateLimited)
		if r.shouldLog(now, throttleKey{"rate_limit", ci.name}) {
			log.Printf("[RELAY] [RATELIMIT] dropped DHCP request from %s on %s: rate limit exceeded (%d/s burst %d)", from, ci.name, rate, burst)
		}
		return
	}

	if len(packet) < dhcpMinBOOTPLen {
		r.metrics.requestsDropped.Add(1)
		ci.stats.drop(dropMalformed)
		return
	}
	if packet[bootpOpOffset] != bootpOpRequest {
		r.metrics.requestsDropped.Add(1)
		ci.stats.drop(dropMalformed)
		return
	}

	if packet[bootpHtypeOffset] != bootpHtypeEthernet || packet[bootpHlenOffset] != bootpHlenEthernet {
		r.metrics.requestsDropped.Add(1)
		ci.stats.drop(dropMalformed)
		r.logThrottled(throttleKey{"bad_htype", ci.name}, "dropping request from %s on %s: non-Ethernet htype=%d hlen=%d", from, ci.name, packet[bootpHtypeOffset], packet[bootpHlenOffset])
		return
	}

	if !ip4IsZero(packet[bootpGIAddrOffset:]) {
		r.metrics.requestsDropped.Add(1)
		ci.stats.drop(dropMalformed)
		return
	}

	hops := packet[bootpHopsOffset]
	if hops >= maxHops {
		r.metrics.requestsDropped.Add(1)
		ci.stats.drop(dropHopLimit)
		r.logThrottled(throttleKey{"hop_limit", ci.name}, "dropping request from %s on %s: hop limit reached", from, ci.name)
		return
	}
	packet[bootpHopsOffset] = hops + 1
	copy(packet[bootpGIAddrOffset:bootpGIAddrOffset+4], ci.giaddr.To4())

	rewriteServerIdentifier(packet, dnsmasqSelfIdentity)

	key, ok := makeTransactionKey(packet, ci.giaddr)
	if !ok {
		r.metrics.requestsDropped.Add(1)
		ci.stats.drop(dropTransactionKey)
		return
	}

	if crate := int(r.clientRateLimit.Load()); crate > 0 {
		cburst := int(r.clientRateBurst.Load())
		switch ci.clients.allow(now, key.chaddr, crate, cburst) {
		case clientLimited:
			r.metrics.requestsDropped.Add(1)
			r.metrics.requestsClientLimit.Add(1)
			ci.stats.drop(dropClientLimited)
			if r.shouldLog(now, throttleKey{"client_rate_limit", ci.name}) {
				mac := key.chaddr
				log.Printf("[RELAY] [RATELIMIT] WARNING dropped DHCP request from client %s on %s: client rate limit exceeded (%d/s burst %d)",
					net.HardwareAddr(mac[:]), ci.name, crate, cburst)
			}
			return
		case clientTableFull:
			ci.stats.clientTableFull.Add(1)
			if r.shouldLog(now, throttleKey{"client_table_full", ci.name}) {
				mac := key.chaddr
				log.Printf("[RELAY] [RATELIMIT] WARNING client table for %s full (%d per VLAN, %d relay-wide); request from %s not limited per client",
					ci.name, maxTrackedClients, maxTrackedClientsTotal, net.HardwareAddr(mac[:]))
			}
		}
	}

	switch r.pending.addAt(key, now, &ci.pending, int(r.pendingPerVLAN.Load())) {
	case addGlobalFull:
		r.metrics.requestsDropped.Add(1)
		r.metrics.requestsPendingFull.Add(1)
		ci.stats.drop(dropPendingFull)
		r.logThrottled(throttleKey{kind: "pending_full"}, "WARNING pending-transaction table full (max %d); dropping request from %s on %s", MaxPending, from, ci.name)
		return
	case addVLANFull:
		r.metrics.requestsDropped.Add(1)
		r.metrics.requestsPendingFull.Add(1)
		ci.stats.drop(dropPendingFull)
		r.logThrottled(throttleKey{"pending_vlan_full", ci.name}, "WARNING pending-transaction limit for %s reached (%d unanswered requests); dropping request from %s",
			ci.name, r.pendingPerVLAN.Load(), from)
		return
	}

	if _, err := r.serverConn.Load().WriteToUDP(packet, ci.serverAddr); err != nil {
		r.pending.delete(key)
		r.metrics.requestsDropped.Add(1)
		ci.stats.drop(dropUpstreamWrite)
		r.logThrottled(throttleKey{kind: "upstream_write_error"}, "forward request to server: %v", err)
		return
	}
	r.metrics.requestsForwarded.Add(1)
	ci.stats.requestsForwarded.Add(1)
}
