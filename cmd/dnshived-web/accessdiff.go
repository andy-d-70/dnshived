// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"sort"
	"strings"

	"dnshived/internal/access"
)

func verdictLine(e access.Entry) string {
	state := ""
	if e.Off {
		state = ", off"
	}
	return fmt.Sprintf("%s (dns %s, dhcp %s, web %s%s)", e.Net, verdictOf(e.DNS), verdictOf(e.DHCP), verdictOf(e.Web), state)
}

func hostLine(h access.Host) string {
	var svc []string
	if h.DNS {
		svc = append(svc, "dns")
	}
	if h.DHCP {
		svc = append(svc, "dhcp")
	}
	if h.Web {
		svc = append(svc, "web")
	}
	id := h.Addr
	if h.MAC != "" {
		if id != "" {
			id += " / "
		}
		id += h.MAC
	}
	return fmt.Sprintf("%s (%s)", id, strings.Join(svc, ", "))
}

// accessDiffEntries describes what a staged change does to the access list, one line per change.
func accessDiffEntries(live, cand *access.Config) []clusterDiffEntry {
	l, c := cloneAccess(live), cloneAccess(cand)
	var out []clusterDiffEntry
	add := func(s string) { out = append(out, clusterDiffEntry{Label: "access", Detail: s}) }
	lm, cm := l.Mode, c.Mode
	if lm == "" {
		lm = access.ModeReport
	}
	if cm == "" {
		cm = access.ModeReport
	}
	if lm != cm {
		add(fmt.Sprintf("mode %s → %s", lm, cm))
	}
	lp, cp := privateLine(l), privateLine(c)
	if lp != cp {
		add(fmt.Sprintf("private networks: on=%v dns=%s dhcp=%s web=%s → on=%v dns=%s dhcp=%s web=%s", lp.On, lp.DNS, lp.DHCP, lp.Web, cp.On, cp.DNS, cp.DHCP, cp.Web))
	}
	byNet := func(es []access.Entry) map[string]access.Entry {
		m := map[string]access.Entry{}
		for _, e := range es {
			m[e.Net] = e
		}
		return m
	}
	ln, cn := byNet(l.Entries), byNet(c.Entries)
	keys := map[string]bool{}
	for k := range ln {
		keys[k] = true
	}
	for k := range cn {
		keys[k] = true
	}
	var names []string
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		a, aok := ln[k]
		b, bok := cn[k]
		switch {
		case !aok:
			add("network added: " + verdictLine(b))
		case !bok:
			add("network removed: " + verdictLine(a))
		case a != b:
			add("network changed: " + verdictLine(a) + " → " + verdictLine(b))
		}
	}
	byHost := func(hs []access.Host) map[string]access.Host {
		m := map[string]access.Host{}
		for _, h := range hs {
			m[hostKey(h)] = h
		}
		return m
	}
	lh, ch := byHost(l.Hosts), byHost(c.Hosts)
	var hk []string
	seen := map[string]bool{}
	for k := range lh {
		seen[k] = true
		hk = append(hk, k)
	}
	for k := range ch {
		if !seen[k] {
			hk = append(hk, k)
		}
	}
	sort.Strings(hk)
	for _, k := range hk {
		a, aok := lh[k]
		b, bok := ch[k]
		switch {
		case !aok:
			add("whitelisted host added: " + hostLine(b))
		case !bok:
			add("whitelisted host removed: " + hostLine(a))
		case a != b:
			add("whitelisted host changed: " + hostLine(a) + " → " + hostLine(b))
		}
	}
	byBlock := func(bs []access.Block) map[string]access.Block {
		m := map[string]access.Block{}
		for _, b := range bs {
			m[blockKey(b)] = b
		}
		return m
	}
	lb, cb := byBlock(l.Blocked), byBlock(c.Blocked)
	var bk []string
	for k := range lb {
		bk = append(bk, k)
	}
	for k := range cb {
		if _, ok := lb[k]; !ok {
			bk = append(bk, k)
		}
	}
	sort.Strings(bk)
	for _, k := range bk {
		a, aok := lb[k]
		b, bok := cb[k]
		switch {
		case !aok:
			add("client blocked: " + blockLine(b))
		case !bok:
			add("client unblocked: " + blockLine(a))
		case a != b:
			add("blocked client changed: " + blockLine(a) + " → " + blockLine(b))
		}
	}
	return out
}

func blockLine(b access.Block) string {
	var svc []string
	if b.DNS {
		svc = append(svc, "dns")
	}
	if b.DHCP {
		svc = append(svc, "dhcp")
	}
	id := b.Addr
	if b.MAC != "" {
		if id != "" {
			id += " / "
		}
		id += b.MAC
	}
	return fmt.Sprintf("%s (%s)", id, strings.Join(svc, ", "))
}
