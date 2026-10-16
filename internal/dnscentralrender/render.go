// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package dnscentralrender derives dnsmasq.central's own config text from
// a live cluster config.
package dnscentralrender

import (
	"fmt"
	"sort"
	"strings"

	"dnshived/internal/config"
	"dnshived/internal/dnsmasqrender"
)

const DefaultAddress = "127.0.0.42"

// CoreDNSLogFileName is the real, on-disk filename central DNS's own
// preamble points its log-facility at when Cluster.CoreDNSQueryLogging is
// on.
const CoreDNSLogFileName = "dnsmasq-central-dns.log"

// DynamicHostsFileName is the separate, SIGHUP-reload-capable file central
// DNS's own addn-hosts= line points at.
const DynamicHostsFileName = "dnsmasq-dynamic-hosts-central.conf"

// RenderInitial returns dnsmasq.central's minimal bootstrap config.
func RenderInitial(address string, upstream []string) (string, error) {
	if address == "" {
		address = DefaultAddress
	}

	var buf strings.Builder
	buf.WriteString("# dnshived managed — central DNS (dnsmasq.central)\n")
	buf.WriteString("# DO NOT EDIT — this file is rendered by dnshived and will be overwritten.\n")
	buf.WriteString("user=dnshived\n")
	buf.WriteString("group=dnshived\n")
	buf.WriteString("listen-address=" + address + "\n")
	buf.WriteString("bind-interfaces\n")
	buf.WriteString("port=53\n")
	buf.WriteString("no-resolv\n")
	for _, s := range upstream {
		buf.WriteString("server=" + s + "\n")
	}
	return buf.String(), nil
}

func Render(cluster config.Cluster, address string, dataDir string) (string, error) {
	if address == "" {
		address = DefaultAddress
	}
	names := make([]string, 0, len(cluster.Scopes))
	for name := range cluster.Scopes {
		names = append(names, name)
	}
	sort.Strings(names)

	var records []config.DNSRecord
	for _, name := range names {
		sc := cluster.Scopes[name]
		records = append(records, sc.DNSRecords...)
		for _, r := range sc.Reservations {
			if r.Hostname == "" {
				continue
			}
			records = append(records, config.DNSRecord{Name: r.Hostname, Type: "A", Value: r.IP})
		}
	}
	records = append(records, cluster.GlobalDNSRecords...)
	records = append(records, config.ExpandedLocalDomainRecords(cluster.LocalDomains)...)

	lines, err := dnsmasqrender.RenderDNSRecords(records)
	if err != nil {
		return "", err
	}

	var upstream strings.Builder
	if cluster.ScopeDefaults != nil {
		for _, s := range cluster.ScopeDefaults.Upstream {
			upstream.WriteString("\nserver=")
			upstream.WriteString(s)
		}
	}

	return preamble(address, dataDir, cluster.CoreDNSQueryLogging) + upstream.String() + lines + "\n", nil
}

type DynamicHostEntry struct {
	Hostname string
	IP       string
}

// RenderDynamicHosts renders DynamicHostsFileName's own content.
func RenderDynamicHosts(entries []DynamicHostEntry) (string, error) {
	sorted := make([]DynamicHostEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Hostname < sorted[j].Hostname })

	var buf strings.Builder
	buf.WriteString("# dnshived managed — dynamic DHCP-lease hostnames (SIGHUP-reloadable)\n")
	buf.WriteString("# DO NOT EDIT — this file is rendered by dnshived and will be overwritten.\n")
	for _, e := range sorted {
		fmt.Fprintf(&buf, "%s %s\n", e.IP, e.Hostname)
	}
	return buf.String(), nil
}

// RenderScopePreview renders the DNS-record lines this ONE scope
// contributes to the shared dnsmasq.central config.
func RenderScopePreview(sc config.ScopeConfig) (string, error) {
	var records []config.DNSRecord
	records = append(records, sc.DNSRecords...)
	for _, r := range sc.Reservations {
		if r.Hostname == "" {
			continue
		}
		records = append(records, config.DNSRecord{Name: r.Hostname, Type: "A", Value: r.IP})
	}
	return dnsmasqrender.RenderDNSRecords(records)
}

func preamble(address string, dataDir string, queryLogging bool) string {
	base := fmt.Sprintf(`# dnshived managed — central DNS (dnsmasq.central)
# DO NOT EDIT — this file is rendered by dnshived and will be overwritten.
user=dnshived
group=dnshived
listen-address=%s
bind-interfaces
port=53
no-resolv
addn-hosts=%s/%s`, address, dataDir, DynamicHostsFileName)
	if queryLogging {
		base += fmt.Sprintf("\nlog-queries\nlog-facility=%s/%s", dataDir, CoreDNSLogFileName)
	}
	return base
}
