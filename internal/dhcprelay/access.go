// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcprelay

import (
	"log"
	"net/netip"
	"time"

	"dnshived/internal/access"
)

type accessState struct {
	m    *access.Matcher
	nets map[string]netip.Addr
}

func (r *Relay) applyAccess(cfg Config) {
	if cfg.Access == nil {
		r.access.Store(nil)
		return
	}
	var always []netip.Addr
	for _, a := range cfg.AccessAlways {
		if ip, err := netip.ParseAddr(a); err == nil {
			always = append(always, ip)
		}
	}
	m, err := access.New(cfg.Access, always)
	if err != nil {
		log.Printf("[RELAY] access list ignored: %v", err)
		r.access.Store(nil)
		return
	}
	nets := make(map[string]netip.Addr, len(cfg.ClientInterfaces))
	for _, ci := range cfg.ClientInterfaces {
		if p, err := netip.ParsePrefix(ci.Network); err == nil {
			nets[ci.Name] = p.Masked().Addr()
		}
	}
	r.access.Store(&accessState{m: m, nets: nets})
}

func (r *Relay) AccessReporter() *access.Reporter { return r.accessReport }

func (r *Relay) AccessEnforcing() bool {
	st := r.access.Load()
	return st != nil && st.m.Enforcing()
}

// accessAllows judges one client request by the client's network and, for a whitelisted client, by its MAC.
// In report mode it counts and lets the request through.
func (r *Relay) accessAllows(ci *clientInterface, packet []byte, now time.Time) bool {
	st := r.access.Load()
	if st == nil || st.m == nil {
		return true
	}
	netAddr, ok := st.nets[ci.name]
	if !ok {
		return true
	}
	if st.m.Check(access.DHCP, netAddr).Allowed {
		return true
	}
	var mac [6]byte
	copy(mac[:], packet[bootpCHAddrOffset:bootpCHAddrOffset+6])
	if st.m.CheckMAC(mac) {
		return true
	}
	r.accessReport.Add(access.DHCP, netAddr, now)
	if !st.m.Enforcing() {
		r.metrics.accessWouldDrop.Add(1)
		return true
	}
	r.metrics.accessDropped.Add(1)
	r.logThrottled(throttleKey{"access_list", ci.name}, "dropping DHCP requests on %s: the access list does not allow the network %s", ci.name, netAddr)
	return false
}
