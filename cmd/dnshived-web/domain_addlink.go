// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/url"
	"sort"
	"strings"
)

func localDomainNames(nodes []NodeConfig) []string {
	var out []string
	for _, d := range fetchLocalDomains(nodes) {
		if d.ForkedFrom == "" {
			out = append(out, d.Name)
		}
	}
	return out
}

// localDomainOf finds the longest local domain that holds a name and the
// host part under it; ok is false for a name outside every local domain.
func localDomainOf(domains []string, name string) (domain, host string, ok bool) {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	sorted := append([]string(nil), domains...)
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i]) > len(sorted[j]) })
	for _, d := range sorted {
		dl := strings.ToLower(strings.TrimSuffix(d, "."))
		switch {
		case n == dl:
			return d, "@", true
		case strings.HasSuffix(n, "."+dl):
			return d, n[:len(n)-len(dl)-1], true
		}
	}
	return "", "", false
}

// AddLink is the DNS editor address that adds a failed name as a record in
// the local domain that holds it; empty for a name outside every local
// domain and for types a plain address or alias record cannot answer.
func (d probeDetailData) AddLink(name, typ string) string {
	typ = strings.ToUpper(typ)
	if typ != "A" && typ != "AAAA" && typ != "CNAME" {
		return ""
	}
	dom, host, ok := localDomainOf(d.LocalDomains, name)
	if !ok {
		return ""
	}
	v := url.Values{"d": {dom}, "addname": {host}, "addtype": {typ}}
	return "/config/domains?" + v.Encode() + "#quickadd"
}

// AddDomain names the local domain AddLink would use.
func (d probeDetailData) AddDomain(name string) string {
	dom, _, _ := localDomainOf(d.LocalDomains, name)
	return dom
}
