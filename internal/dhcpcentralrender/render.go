// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package dhcpcentralrender derives the central per-worker dnsmasq-dhcp
// instance's own config text from a live cluster config.
package dhcpcentralrender

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"dnshived/internal/config"
	"dnshived/internal/dnsmasqrender"
	"dnshived/internal/trunkaddr"
)

const DefaultAddress = "127.0.0.21"

// CoreDHCPLogFileName is the real, on-disk filename central DHCP's
// preamble (below) points its own log-facility at.
const CoreDHCPLogFileName = "dnsmasq-central-dhcp.log"

// CoreDHCPLeaseFileName is the real, on-disk filename central DHCP's
// dhcp-leasefile= line points at.
const CoreDHCPLeaseFileName = "leases-central"

// HostsFileName is the separate, SIGHUP-reload-capable file central DHCP's
// own dhcp-hostsfile= line points at.
const HostsFileName = "dnsmasq-hosts-central.conf"

// dhcpScriptPath is cmd/dnshived-dhcp-lease-hook's own frozen install path
// (matches this project's own /usr/local/bin/dnshived-<name> convention,
// docs/FREEZE.md).
const dhcpScriptPath = "/usr/local/bin/dnshived-dhcp-lease-hook"

const defaultLeaseTime = "12h"

// iotDefaultLeaseTime mirrors internal/dnsmasqrender's own constant of the
// same name.
const iotDefaultLeaseTime = "24h"

// RenderInitial returns central DHCP's minimal bootstrap config.
func RenderInitial(address string, dataDir string) (string, error) {
	if address == "" {
		address = DefaultAddress
	}
	return preamble(dataDir, address, CoreDHCPLeaseFileName, CoreDHCPLogFileName, HostsFileName), nil
}

// Render aggregates every scope's own DHCP addressing (dhcp-range + router
// option, tag-scoped per scope) into dnsmasq-dhcp's own main config text.
func Render(cluster config.Cluster, dataDir string) (string, error) {
	var buf strings.Builder
	buf.WriteString(preamble(dataDir, DefaultAddress, CoreDHCPLeaseFileName, CoreDHCPLogFileName, HostsFileName))

	renderScopes(&buf, cluster, sortedScopeNames(cluster), nil)
	buf.WriteString("\n")
	return buf.String(), nil
}

// Reservations returns every configured scope's own Reservations, same
// scope set and same "skip an incomplete scope" gating Render itself
// applies.
func Reservations(cluster config.Cluster) []config.Reservation {
	var buf strings.Builder
	return renderScopes(&buf, cluster, sortedScopeNames(cluster), nil)
}

// ReservationsForParent is Reservations' RenderForParent counterpart.
func ReservationsForParent(cluster config.Cluster, parent string) []config.Reservation {
	var buf strings.Builder
	include := func(sc config.ScopeConfig) bool { return sc.Parent == parent }
	return renderScopes(&buf, cluster, sortedScopeNames(cluster), include)
}

func RenderHostsFile(reservations []config.Reservation) (string, error) {
	body, err := dnsmasqrender.RenderReservations(reservations)
	if err != nil {
		return "", err
	}
	return "# dnshived managed — central DHCP reservations (SIGHUP-reloadable)\n" +
		"# DO NOT EDIT — this file is rendered by dnshived and will be overwritten.\n" +
		body, nil
}

func RenderForParent(cluster config.Cluster, parent string, dataDir string) (string, error) {
	idx, err := trunkaddr.Index(cluster, parent)
	if err != nil {
		return "", fmt.Errorf("render for parent %q: %w", parent, err)
	}

	var buf strings.Builder
	leaseFile := fmt.Sprintf("leases-central-%d", idx)
	logFile := fmt.Sprintf("dnsmasq-central-dhcp-%d.log", idx)
	hostsFile := fmt.Sprintf("dnsmasq-hosts-central-%d.conf", idx)
	buf.WriteString(preamble(dataDir, trunkaddr.DHCPAddress(idx), leaseFile, logFile, hostsFile))

	include := func(sc config.ScopeConfig) bool { return sc.Parent == parent }
	renderScopes(&buf, cluster, sortedScopeNames(cluster), include)
	buf.WriteString("\n")
	return buf.String(), nil
}

// RenderScopePreview renders just the dhcp-range/dhcp-option/dhcp-host
// lines this ONE scope contributes to the shared central DHCP config.
func RenderScopePreview(cluster config.Cluster, scopeName string) (string, error) {
	var buf strings.Builder
	allReservations := renderScopes(&buf, cluster, []string{scopeName}, nil)
	if buf.Len() == 0 && len(allReservations) == 0 {
		return "", nil
	}
	return finishRender(&buf, allReservations)
}

// sortedScopeNames returns cluster's own scope names in deterministic
// order.
func sortedScopeNames(cluster config.Cluster) []string {
	names := make([]string, 0, len(cluster.Scopes))
	for name := range cluster.Scopes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func renderScopes(buf *strings.Builder, cluster config.Cluster, names []string, include func(config.ScopeConfig) bool) []config.Reservation {
	var allReservations []config.Reservation

	for _, name := range names {
		sc := cluster.Scopes[name]
		if include != nil && !include(sc) {
			continue
		}
		if sc.NodeIP == "" || sc.VIP == "" || sc.Gateway == "" || sc.DHCPRange[0] == "" || sc.DHCPRange[1] == "" {
			continue
		}
		netmask, err := netmaskFromCIDR(sc.VIP)
		if err != nil {
			continue
		}

		leaseTime := sc.DHCPLeaseTime
		if leaseTime == "" {
			if sc.DHCPIoTDefaults {
				leaseTime = iotDefaultLeaseTime
			} else {
				leaseTime = defaultLeaseTime
			}
		}

		fmt.Fprintf(buf, "dhcp-range=set:%s,%s,%s,%s,%s\n", name, sc.DHCPRange[0], sc.DHCPRange[1], netmask, leaseTime)
		fmt.Fprintf(buf, "dhcp-option=tag:%s,option:router,%s\n", name, sc.Gateway)

		// Option 54 (server identifier) — the scope's own VIP, bare IP.
		if vipHost := bareHost(sc.VIP); vipHost != "" {
			fmt.Fprintf(buf, "dhcp-option=tag:%s,54,%s\n", name, vipHost)
		}

		dnsServer := sc.ClientDNSServer
		if dnsServer == "" {
			dnsServer = effectiveDNSServers(cluster, sc)
		}
		if dnsServer != "" {
			fmt.Fprintf(buf, "dhcp-option=tag:%s,option:dns-server,%s\n", name, dnsServer)
		}

		dhcpOptions := sc.DHCPOptions
		if len(dhcpOptions) == 0 {
			dhcpOptions = cluster.DefaultDHCPOptions
		}
		for _, opt := range dhcpOptions {
			fmt.Fprintf(buf, "dhcp-option=tag:%s,%s\n", name, opt)
		}

		allReservations = append(allReservations, sc.Reservations...)
	}

	return allReservations
}

// finishRender appends allReservations' own dhcp-host lines to buf and
// returns the complete rendered text.
func finishRender(buf *strings.Builder, allReservations []config.Reservation) (string, error) {
	reservationLines, err := dnsmasqrender.RenderReservations(allReservations)
	if err != nil {
		return "", err
	}
	buf.WriteString(reservationLines)
	buf.WriteString("\n")
	return buf.String(), nil
}

// preamble sets interface=lo alongside listen-address/bind-interfaces.
func preamble(dataDir string, address string, leaseFileName string, logFileName string, hostsFileName string) string {
	return fmt.Sprintf(`# dnshived managed — central DHCP (dnsmasq-dhcp)
# DO NOT EDIT — this file is rendered by dnshived and will be overwritten.
user=dnshived
group=dnshived
interface=lo
bind-interfaces
listen-address=%s
port=0
dhcp-leasefile=%s/%s
dhcp-hostsfile=%s/%s
dhcp-script=%s
log-facility=%s/%s
log-dhcp
`, address, dataDir, leaseFileName, dataDir, hostsFileName, dhcpScriptPath, dataDir, logFileName)
}

func netmaskFromCIDR(cidr string) (string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}
	mask := ipnet.Mask
	if len(mask) != 4 {
		return "", fmt.Errorf("CIDR %q is not IPv4", cidr)
	}
	return net.IP(mask).String(), nil
}

// bareHost strips a "/prefix" suffix from a CIDR-shaped address field
// (VIP, NodeIP, NodeIPOverrides entries all share this shape).
func bareHost(cidr string) string {
	host, _, _ := strings.Cut(cidr, "/")
	return host
}

// coreRoles is config.RoleCore1/2/3 as a fixed, iterable slice.
var coreRoles = []string{config.RoleCore1, config.RoleCore2, config.RoleCore3}

func effectiveDNSServers(cluster config.Cluster, sc config.ScopeConfig) string {
	seen := make(map[string]bool, 3)
	var out []string
	add := func(host string) {
		if host == "" || seen[host] {
			return
		}
		seen[host] = true
		out = append(out, host)
	}

	add(bareHost(sc.NodeIP))

	vipHost := bareHost(sc.VIP)
	idx := strings.LastIndexByte(vipHost, '.')
	var subnetBase string
	if idx >= 0 {
		subnetBase = vipHost[:idx+1]
	}

	var suffixes map[string]string
	if cluster.ScopeDefaults != nil {
		suffixes = cluster.ScopeDefaults.NodeIPSuffixes
	}

	for _, role := range coreRoles {
		if override := bareHost(sc.NodeIPOverrides[role]); override != "" {
			add(override)
			continue
		}
		if subnetBase != "" {
			if suffix := suffixes[role]; suffix != "" {
				add(subnetBase + suffix)
			}
		}
	}

	sort.Strings(out)
	return strings.Join(out, ",")
}
