// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package config loads the static cluster configuration.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var dhcpLeaseTimePattern = regexp.MustCompile(`^\d+[smhd]?$`)

// scopeColorPattern matches ScopeConfig.Color's only accepted shape.
var scopeColorPattern = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// domainNamePattern is a conservative DNS domain-name syntax check —
// dot-separated labels of letters/digits/hyphens, no leading/trailing
// hyphen per label.
var domainNamePattern = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

var scopeNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// Core role names.
const (
	RoleCore1 = "core-1"
	RoleCore2 = "core-2"
	RoleCore3 = "core-3"
)

// LegacyRoleAliases maps each old worker-a/worker-b/arbiter role value to
// its current equivalent.
var LegacyRoleAliases = map[string]string{
	"worker-a": RoleCore1,
	"worker-b": RoleCore2,
	"arbiter":  RoleCore3,
}

// CurrentSchemaVersion is the config schema version this build
// understands.
const CurrentSchemaVersion = 2

// Platform describes the physical network interfaces on this node.
type Platform struct {
	Mgmt    string   `json:"mgmt"`              // management interface — PROTECTED, never touched
	Workers []string `json:"workers,omitempty"` // parent interfaces for VLAN sub-interfaces

	// InterfaceLabels is a purely cosmetic, optional operator-chosen display
	// name per entry in Workers (e.g. "ens19" -> "Interface Office").
	InterfaceLabels map[string]string `json:"interface_labels,omitempty"`

	WorkerOverrides map[string]map[string]string `json:"worker_overrides,omitempty"`

	// MgmtOverrides is a role's own management interface name where it
	// differs from Mgmt.
	MgmtOverrides map[string]string `json:"mgmt_overrides,omitempty"`
}

// LocalName maps a configured name to this host's kernel name; dnshived
// sets it to follow kernel altnames.
var LocalName = func(name string) string { return name }

// ResolveParent returns the LOCAL interface name role should use for the
// given canonical parent (a value straight out of Workers, or a scope's
// own Parent field).
func (p *Platform) ResolveParent(role, canonical string) string {
	if p == nil {
		return LocalName(canonical)
	}
	if local, ok := p.WorkerOverrides[role][canonical]; ok && local != "" {
		return LocalName(local)
	}
	return LocalName(canonical)
}

// ResolveMgmt returns the LOCAL management interface name for role.
func (p *Platform) ResolveMgmt(role string) string {
	if p == nil {
		return ""
	}
	if local := p.MgmtOverrides[role]; local != "" {
		return LocalName(local)
	}
	return LocalName(p.Mgmt)
}

// ScopeConfig defines a single scope (maps to a VLAN + VIP + DHCP
// service).
type ScopeConfig struct {
	Parent string `json:"parent"`            // worker interface (e.g. "ens19")
	VLANID int    `json:"vlan_id"`           // 802.1Q VLAN tag
	VIP    string `json:"vip"`               // virtual IP with prefix (e.g. "192.168.100.1/24")
	NodeIP string `json:"node_ip,omitempty"` // per-node base address on the VLAN (e.g. "192.168.100.22/24")
	// NodeIPOverrides is this scope's per-node node_ip override table, keyed
	// by role (core-1/core-2/core-3).
	NodeIPOverrides map[string]string `json:"node_ip_overrides,omitempty"`
	DHCPRange       [2]string         `json:"dhcp_range"` // [start, end]
	// Gateway is DHCP option 3 (router).
	Gateway string `json:"gateway"`
	// ClientDNSServer is the DNS server DHCP clients on this scope are told to
	// use (DHCP option 6).
	ClientDNSServer string `json:"client_dns_server,omitempty"`
	VRRPID          int    `json:"vrrp_id"`          // VRRP virtual router ID (unique per scope)
	PreferredWorker string `json:"preferred_worker"` // "core-1", "core-2", or "core-3"

	// VRRP timing.
	AdvertIntMS int `json:"advert_int_ms,omitempty"` // milliseconds
	VRRPVersion int `json:"vrrp_version,omitempty"`  // 2 (default) or 3

	// DHCPNoPing disables dnsmasq's default duplicate-address ARP-ping check
	// before offering a NEW (never-before-leased-to-this-client) address.
	DHCPNoPing bool `json:"dhcp_no_ping,omitempty"`

	// DHCPIoTDefaults bundles a set of IoT-friendly dnsmasq behaviors behind
	// ONE per-scope switch.
	DHCPIoTDefaults bool `json:"dhcp_iot_defaults,omitempty"`

	// DHCPBroadcast forces dnsmasq to send every DHCP reply for this scope as
	// a broadcast, never unicast.
	DHCPBroadcast *bool `json:"dhcp_broadcast,omitempty"`

	DHCPAuthoritative *bool `json:"dhcp_authoritative,omitempty"`

	// DHCPLeaseTime overrides the lease duration for this scope, in dnsmasq's
	// own duration syntax (e.g. "12h", "7d", "30m", or "infinite").
	DHCPLeaseTime string `json:"dhcp_lease_time,omitempty"`

	// Reservations are this scope's static DHCP reservations (dhcp-host
	// entries — a fixed MAC->IP mapping, with an optional DNS hostname).
	Reservations []Reservation `json:"reservations,omitempty"`

	// DNSRecords are this scope's custom static DNS records.
	DNSRecords []DNSRecord `json:"dns_records,omitempty"`

	// ProbeDisabled opts this ENTIRE scope out of external probe-host
	// checking.
	ProbeDisabled bool `json:"probe_disabled,omitempty"`

	// DNSMasqDisabled stops JUST this scope's DNS+DHCP serving while leaving
	// its VLAN interface and VRRP/VIP participation fully running.
	DNSMasqDisabled bool `json:"dnsmasq_disabled,omitempty"`

	// RebalanceApprovedAt is a Unix-seconds marker set by an explicit operator
	// action ("Rebalance to preferred now", cmd/dnshived-web).
	RebalanceApprovedAt int64 `json:"rebalance_approved_at,omitempty"`

	// Color is a purely cosmetic, operator-chosen tag for this scope.
	Color string `json:"color,omitempty"`

	DHCPOptions []string `json:"dhcp_options,omitempty"`

	ContentLinks map[string]ContentLink `json:"content_links,omitempty"`
}

// ContentLink names the live source (a cmd/dnshived-web Template or
// OptionSet) one of a ScopeConfig's own content fields currently mirrors.
type ContentLink struct {
	Kind     string `json:"kind"`
	SourceID string `json:"source_id"`
}

// Reservation is one static DHCP reservation (dnsmasq's own dhcp-host
// directive).
type Reservation struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
}

// DNSRecord is one custom static DNS record for a scope.
type DNSRecord struct {
	Name string `json:"name"` // fully-qualified, e.g. "dante._sub._dns-sd._udp.office.lan."
	Type string `json:"type"`

	// Value holds the record data for A/AAAA/CNAME/TXT/PTR/CAA (an address, a
	// target name, free text, a reverse-lookup target name, or the CAA value,
	// respectively).
	Value string `json:"value,omitempty"`

	// SRV fields (RFC 2782): the service instance's target host and port, plus
	// its priority/weight for clients choosing among several.
	Target   string `json:"target,omitempty"`
	Port     int    `json:"port,omitempty"`
	Priority int    `json:"priority,omitempty"`
	Weight   int    `json:"weight,omitempty"`

	// NAPTR-only fields (RFC 3403).
	NAPTROrder   int    `json:"naptr_order,omitempty"`
	NAPTRFlags   string `json:"naptr_flags,omitempty"`
	NAPTRService string `json:"naptr_service,omitempty"`
	NAPTRRegexp  string `json:"naptr_regexp,omitempty"`

	// CAA-only fields (RFC 6844): Value above holds the CAA value itself (e.g.
	// a CA's domain name for an "issue" tag).
	CAAFlags int    `json:"caa_flags,omitempty"`
	CAATag   string `json:"caa_tag,omitempty"`

	// RAW is dnsmasq's own escape hatch (--dns-rr) for any record type with no
	// dedicated directive.
	RRType    int    `json:"rr_type,omitempty"`
	RRDataHex string `json:"rr_data_hex,omitempty"`

	// ProbeDisabled opts this one record out of an external probe host's
	// default check set, without removing it from the rendered dnsmasq config.
	ProbeDisabled bool `json:"probe_disabled,omitempty"`

	// TTL (seconds), 0 = dnsmasq's own default (--local-ttl, or zero).
	TTL int `json:"ttl,omitempty"`
}

// LocalDomain is one named local DNS zone (e.g. "foo.lan") holding a real
// host+domain split entry list.
type LocalDomain struct {
	// Name is the domain itself, e.g. "foo.lan" — no trailing dot (one is
	// added at render/FQDN time, matching every other DNSRecord.Name in this
	// codebase).
	Name string `json:"name"`

	// TTL (seconds) is this domain's own default.
	TTL int `json:"ttl,omitempty"`

	Records []LocalDomainHost `json:"records,omitempty"`

	// ForkedFrom names the domain this one was forked from, or "" for an
	// independent (original, or unlinked) domain.
	ForkedFrom string `json:"forked_from,omitempty"`
}

// LocalDomainHost is one record under a LocalDomain.
type LocalDomainHost struct {
	Host string `json:"host,omitempty"`
	Type string `json:"type"`

	Value string `json:"value,omitempty"`

	Target   string `json:"target,omitempty"`
	Port     int    `json:"port,omitempty"`
	Priority int    `json:"priority,omitempty"`
	Weight   int    `json:"weight,omitempty"`

	NAPTROrder   int    `json:"naptr_order,omitempty"`
	NAPTRFlags   string `json:"naptr_flags,omitempty"`
	NAPTRService string `json:"naptr_service,omitempty"`
	NAPTRRegexp  string `json:"naptr_regexp,omitempty"`

	CAAFlags int    `json:"caa_flags,omitempty"`
	CAATag   string `json:"caa_tag,omitempty"`

	RRType    int    `json:"rr_type,omitempty"`
	RRDataHex string `json:"rr_data_hex,omitempty"`

	TTL int `json:"ttl,omitempty"`

	ProbeDisabled bool `json:"probe_disabled,omitempty"`
}

// fqdn joins a LocalDomainHost's own bare Host label with the owning
// domain's Name into a real, trailing-dot-terminated FQDN.
func (d LocalDomain) fqdn(host string) string {
	domain := strings.TrimSuffix(d.Name, ".") + "."
	host = strings.TrimSpace(host)
	if host == "" || host == "@" {
		return domain
	}
	return strings.TrimSuffix(host, ".") + "." + domain
}

// ExpandedRecords resolves every host under this domain into a real,
// fully-qualified DNSRecord.
func (d LocalDomain) ExpandedRecords() []DNSRecord {
	records := make([]DNSRecord, 0, len(d.Records))
	for _, h := range d.Records {
		ttl := h.TTL
		if ttl == 0 {
			ttl = d.TTL
		}
		records = append(records, DNSRecord{
			Name:          d.fqdn(h.Host),
			Type:          h.Type,
			Value:         h.Value,
			Target:        h.Target,
			Port:          h.Port,
			Priority:      h.Priority,
			Weight:        h.Weight,
			NAPTROrder:    h.NAPTROrder,
			NAPTRFlags:    h.NAPTRFlags,
			NAPTRService:  h.NAPTRService,
			NAPTRRegexp:   h.NAPTRRegexp,
			CAAFlags:      h.CAAFlags,
			CAATag:        h.CAATag,
			RRType:        h.RRType,
			RRDataHex:     h.RRDataHex,
			TTL:           ttl,
			ProbeDisabled: h.ProbeDisabled,
		})
	}
	return records
}

func PropagateForkedDomains(domains []LocalDomain, changedName string) []LocalDomain {
	byName := make(map[string]LocalDomain, len(domains))
	for _, d := range domains {
		byName[d.Name] = d
	}
	var resolve func(name string) (LocalDomain, bool)
	resolve = func(name string) (LocalDomain, bool) {
		d, ok := byName[name]
		return d, ok
	}
	for pass := 0; pass < len(domains)+1; pass++ {
		for name, d := range byName {
			if d.ForkedFrom == "" {
				continue
			}
			parent, ok := resolve(d.ForkedFrom)
			if !ok {
				continue
			}
			d.TTL = parent.TTL
			d.Records = append([]LocalDomainHost(nil), parent.Records...)
			byName[name] = d
		}
	}
	out := make([]LocalDomain, len(domains))
	for i, d := range domains {
		out[i] = byName[d.Name]
	}
	return out
}

// ExpandedLocalDomainRecords applies LocalDomain.ExpandedRecords across
// every configured domain, in order.
func ExpandedLocalDomainRecords(domains []LocalDomain) []DNSRecord {
	var records []DNSRecord
	for _, d := range domains {
		records = append(records, d.ExpandedRecords()...)
	}
	return records
}

// DNSCheck is one generic (name, record type) DNS query.
type DNSCheck struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// DefaultDNSCheckName/Type is the built-in check when
// Cluster.DefaultDNSChecks is unset.
const (
	DefaultDNSCheckName = "claude.ai."
	DefaultDNSCheckType = "A"
)

// EffectiveDefaultDNSChecks returns c.DefaultDNSChecks, or the built-in
// default when unset.
func (c *Cluster) EffectiveDefaultDNSChecks() []DNSCheck {
	if len(c.DefaultDNSChecks) > 0 {
		return c.DefaultDNSChecks
	}
	return []DNSCheck{{Name: DefaultDNSCheckName, Type: DefaultDNSCheckType}}
}

// validDNSRecordTypes is shared by DNSRecord and DNSCheck validation.
var validDNSRecordTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "TXT": true, "SRV": true, "PTR": true,
	"MX": true, "NAPTR": true, "CAA": true, "RAW": true,
}

const dnsRecordTypesList = "A, AAAA, CNAME, TXT, SRV, PTR, MX, NAPTR, CAA, RAW"

func validateDNSRecords(records []DNSRecord, errPrefix string) error {
	for i, rec := range records {
		if rec.Name == "" {
			return fmt.Errorf("%s: dns_records[%d]: name is required", errPrefix, i)
		}
		if !validDNSRecordTypes[rec.Type] {
			return fmt.Errorf("%s: dns_records[%d]: type must be one of %s (got %q)", errPrefix, i, dnsRecordTypesList, rec.Type)
		}
		if containsLineBreak(rec.Name) || strings.Contains(rec.Name, ",") {
			return fmt.Errorf("%s: dns_records[%d]: name must not contain a newline or comma", errPrefix, i)
		}

		switch rec.Type {
		case "A", "AAAA":
			if rec.Value == "" {
				return fmt.Errorf("%s: dns_records[%d]: %s records require value", errPrefix, i, rec.Type)
			}
			if net.ParseIP(rec.Value) == nil {
				return fmt.Errorf("%s: dns_records[%d]: %s record value %q is not a valid IP address", errPrefix, i, rec.Type, rec.Value)
			}
		case "CNAME", "PTR":
			if rec.Value == "" {
				return fmt.Errorf("%s: dns_records[%d]: %s records require value", errPrefix, i, rec.Type)
			}
			if containsLineBreak(rec.Value) || strings.Contains(rec.Value, ",") {
				return fmt.Errorf("%s: dns_records[%d]: %s value must not contain a newline or comma", errPrefix, i, rec.Type)
			}
		case "TXT":
			if rec.Value == "" {
				return fmt.Errorf("%s: dns_records[%d]: TXT records require value", errPrefix, i)
			}
			// Only the line-break injection vector is rejected.
			if containsLineBreak(rec.Value) {
				return fmt.Errorf("%s: dns_records[%d]: TXT value must not contain a newline", errPrefix, i)
			}
		case "SRV":
			if rec.Target == "" || rec.Port == 0 {
				return fmt.Errorf("%s: dns_records[%d]: SRV records require target and port", errPrefix, i)
			}
			if containsLineBreak(rec.Target) || strings.Contains(rec.Target, ",") {
				return fmt.Errorf("%s: dns_records[%d]: target must not contain a newline or comma", errPrefix, i)
			}
		case "MX":
			if rec.Target == "" {
				return fmt.Errorf("%s: dns_records[%d]: MX records require target", errPrefix, i)
			}
			if containsLineBreak(rec.Target) || strings.Contains(rec.Target, ",") {
				return fmt.Errorf("%s: dns_records[%d]: target must not contain a newline or comma", errPrefix, i)
			}
		case "NAPTR":
			if rec.Target == "" {
				return fmt.Errorf("%s: dns_records[%d]: NAPTR records require target (replacement)", errPrefix, i)
			}
			for _, field := range []struct{ label, value string }{
				{"target", rec.Target}, {"naptr_flags", rec.NAPTRFlags},
				{"naptr_service", rec.NAPTRService}, {"naptr_regexp", rec.NAPTRRegexp},
			} {
				if containsLineBreak(field.value) || strings.Contains(field.value, ",") {
					return fmt.Errorf("%s: dns_records[%d]: %s must not contain a newline or comma", errPrefix, i, field.label)
				}
			}
		case "CAA":
			if rec.CAATag == "" || rec.Value == "" {
				return fmt.Errorf("%s: dns_records[%d]: CAA records require caa_tag and value", errPrefix, i)
			}
			if containsLineBreak(rec.CAATag) || strings.Contains(rec.CAATag, ",") {
				return fmt.Errorf("%s: dns_records[%d]: caa_tag must not contain a newline or comma", errPrefix, i)
			}
			if containsLineBreak(rec.Value) || strings.Contains(rec.Value, ",") {
				return fmt.Errorf("%s: dns_records[%d]: CAA value must not contain a newline or comma", errPrefix, i)
			}
		case "RAW":
			if rec.RRType <= 0 {
				return fmt.Errorf("%s: dns_records[%d]: RAW records require a positive rr_type", errPrefix, i)
			}
			if rec.RRDataHex != "" {
				if _, err := hex.DecodeString(rec.RRDataHex); err != nil {
					return fmt.Errorf("%s: dns_records[%d]: rr_data_hex is not valid hex: %v", errPrefix, i, err)
				}
			}
		}
	}
	return nil
}

// validateLocalDomains checks Cluster.LocalDomains.
func validateLocalDomains(domains []LocalDomain) error {
	seen := make(map[string]bool, len(domains))
	for i, d := range domains {
		if d.Name == "" {
			return fmt.Errorf("local_domains[%d]: name is required", i)
		}
		if !domainNamePattern.MatchString(d.Name) {
			return fmt.Errorf("local_domains[%d]: name %q is not a valid domain name", i, d.Name)
		}
		key := strings.ToLower(d.Name)
		if seen[key] {
			return fmt.Errorf("local_domains[%d]: domain %q is configured more than once", i, d.Name)
		}
		seen[key] = true
		if d.TTL < 0 {
			return fmt.Errorf("local_domains[%d] (%s): ttl must not be negative", i, d.Name)
		}
		for j, h := range d.Records {
			if h.TTL < 0 {
				return fmt.Errorf("local_domains[%d] (%s): records[%d]: ttl must not be negative", i, d.Name, j)
			}
		}
		if err := validateDNSRecords(d.ExpandedRecords(), fmt.Sprintf("local domain %q", d.Name)); err != nil {
			return err
		}
	}
	return nil
}

var reservationHostnameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]*$`)

// validateReservations checks one scope's static DHCP reservations —
// same per-scope hard-Error convention as validateDNSRecords/
// ValidateDHCPOptions above.
func validateReservations(reservations []Reservation, errPrefix string) error {
	seen := make(map[string]bool, len(reservations))
	for i, res := range reservations {
		if _, err := net.ParseMAC(res.MAC); err != nil {
			return fmt.Errorf("%s: reservations[%d]: mac %q is not a valid MAC address", errPrefix, i, res.MAC)
		}
		if net.ParseIP(res.IP) == nil {
			return fmt.Errorf("%s: reservations[%d]: ip %q is not a valid IP address", errPrefix, i, res.IP)
		}
		if !reservationHostnameRe.MatchString(res.Hostname) {
			return fmt.Errorf("%s: reservations[%d]: hostname %q must contain only letters, digits, dot, hyphen, underscore", errPrefix, i, res.Hostname)
		}
		if seen[res.MAC] {
			return fmt.Errorf("%s: reservations[%d]: mac %q already reserved earlier in this scope", errPrefix, i, res.MAC)
		}
		seen[res.MAC] = true
	}
	return nil
}

// coreAddressReservedConflicts are loopback aliases already claimed by
// something else on a real deployment of this project.
var coreAddressReservedConflicts = map[string]bool{
	"127.0.0.1":  true,
	"127.0.0.53": true,
	"127.0.0.54": true,
}

func validateCoreAddress(field, value string) string {
	if value == "" {
		return ""
	}
	ip := net.ParseIP(value).To4()
	if ip == nil {
		return fmt.Sprintf("%s %q is not a valid IPv4 address", field, value)
	}
	if ip[0] != 127 {
		return fmt.Sprintf("%s %q must be a loopback address (127.0.0.0/8) — this instance only ever binds locally", field, value)
	}
	if coreAddressReservedConflicts[value] {
		return fmt.Sprintf("%s %q is already reserved by another well-known local service (systemd-resolved or the loopback default) — pick a different loopback alias", field, value)
	}
	return ""
}

// containsLineBreak reports whether s could terminate a dnsmasq config
// line early and start a new, attacker/typo-controlled directive.
func containsLineBreak(s string) bool {
	return strings.ContainsAny(s, "\r\n")
}

func ValidateDHCPOptions(opts []string, errPrefix string) error {
	for i, opt := range opts {
		if containsLineBreak(opt) {
			return fmt.Errorf("%s: dhcp_options[%d]: must not contain a newline", errPrefix, i)
		}
	}
	return nil
}

// dhcpOptionOverridesClientDNS reports whether opts contains a raw dnsmasq
// dhcp-option value that overrides DHCP option 6.
func dhcpOptionOverridesClientDNS(opts []string) bool {
	for _, o := range opts {
		lower := strings.ToLower(strings.TrimSpace(o))
		if strings.HasPrefix(lower, "6,") ||
			strings.HasPrefix(lower, "option:dns-server,") ||
			strings.HasPrefix(lower, "option6:dns-server,") {
			return true
		}
	}
	return false
}

// Cluster is the static configuration.
type Cluster struct {
	SchemaVersion int      `json:"schema_version,omitempty"`
	ClusterID     string   `json:"cluster_id"`
	NodeID        string   `json:"node_id"`
	Role          string   `json:"role"`
	ControlAddr   string   `json:"control_addr"`
	BindAddr      string   `json:"bind_addr"`
	DataDir       string   `json:"data_dir"`
	PSK           string   `json:"psk,omitempty"`
	Peers         []string `json:"peers"`

	TrustedHosts []string `json:"trusted_hosts,omitempty"`

	// LegacyDryRun is set by Load when the file still carries the removed
	// dry_run key; Save never writes it back.
	LegacyDryRun bool `json:"-"`

	// TLS configuration.
	TLSCert string `json:"tls_cert,omitempty"` // path to PEM certificate
	TLSKey  string `json:"tls_key,omitempty"`  // path to PEM private key

	// API authentication.
	APITokens []APIToken `json:"api_tokens,omitempty"`

	LogLevel string `json:"log_level,omitempty"`

	// Privilege separation.
	HelperSocket string `json:"helper_socket,omitempty"`

	// Platform describes physical interfaces.
	Platform *Platform `json:"platform,omitempty"`

	// Scopes defines the VLAN/DHCP/VIP scopes this cluster manages.
	Scopes map[string]ScopeConfig `json:"scopes,omitempty"`

	// ProbeIntervalMS is how often the observer probes peers, in milliseconds.
	ProbeIntervalMS int `json:"probe_interval_ms,omitempty"`

	MgmtVIP *MgmtVIPConfig `json:"mgmt_vip,omitempty"`

	CoreDNSAddress  string `json:"core_dns_address,omitempty"`
	CoreDHCPAddress string `json:"core_dhcp_address,omitempty"`

	CoreDNSQueryLogging bool `json:"core_dns_query_logging,omitempty"`

	// DNSRelayCacheSize/DNSRelayCacheMaxBytes are cluster-managed overrides
	// for the standalone dnshived-dnsrelay binary's own
	// cache_size/cache_max_bytes fields.
	DNSRelayCacheSize     int `json:"dnsrelay_cache_size,omitempty"`
	DNSRelayCacheMaxBytes int `json:"dnsrelay_cache_max_bytes,omitempty"`

	SanityCheckDisabled bool `json:"sanity_check_disabled,omitempty"`

	DefaultDNSChecks []DNSCheck `json:"default_dns_checks,omitempty"`

	// GlobalDNSRecords are DNS records
	// rendered into EVERY scope's own dnsmasq instance in addition to that
	// scope's own DNSRecords.
	GlobalDNSRecords []DNSRecord `json:"global_dns_records,omitempty"`

	LocalDomains []LocalDomain `json:"local_domains,omitempty"`

	ScopeDefaults *ScopeDefaults `json:"scope_defaults,omitempty"`

	DefaultDHCPOptions []string `json:"default_dhcp_options,omitempty"`

	BackupEnabled        bool   `json:"backup_enabled,omitempty"`
	BackupIntervalHours  int    `json:"backup_interval_hours,omitempty"`  // 0 with BackupEnabled true resolves to 24
	BackupRetentionCount int    `json:"backup_retention_count,omitempty"` // 0 with BackupEnabled true resolves to 14
	BackupPassword       string `json:"backup_password,omitempty"`

	BackupReplicateToPeers bool `json:"backup_replicate_to_peers,omitempty"`
}

// ScopeDefaults holds cluster-wide suggested defaults for creating a new
// scope.
type ScopeDefaults struct {
	GatewaySuffix   string `json:"gateway_suffix,omitempty"`
	VIPSuffix       string `json:"vip_suffix,omitempty"`
	DHCPStartSuffix string `json:"dhcp_start_suffix,omitempty"`
	DHCPEndSuffix   string `json:"dhcp_end_suffix,omitempty"`
	// NodeIPSuffixes replaces a would-be single NodeIPSuffix.
	NodeIPSuffixes map[string]string `json:"node_ip_suffixes,omitempty"`
	Upstream       []string          `json:"upstream,omitempty"`
	// AdvertIntMS/VRRPVersion pre-fill a new scope's own VRRP tuning fields.
	AdvertIntMS int `json:"advert_int_ms,omitempty"`
	VRRPVersion int `json:"vrrp_version,omitempty"`
}

// MgmtVIPConfig defines the management-plane VIP.
type MgmtVIPConfig struct {
	VIP    string `json:"vip"`     // virtual IP with prefix (e.g. "192.0.2.100/24")
	VRRPID int    `json:"vrrp_id"` // VRRP virtual router ID — must not collide with any scope's vrrp_id
}

// DefaultProbeInterval is the observer probe cadence when ProbeIntervalMS
// is unset.
const DefaultProbeInterval = 5 * time.Second

// ProbeInterval resolves the configured probe interval, falling back to
// DefaultProbeInterval when unset.
func (c *Cluster) ProbeInterval() time.Duration {
	if c.ProbeIntervalMS <= 0 {
		return DefaultProbeInterval
	}
	return time.Duration(c.ProbeIntervalMS) * time.Millisecond
}

// APIToken defines a named bearer token for API access.
type APIToken struct {
	Name    string `json:"name"`
	Token   string `json:"token"`
	Role    string `json:"role"`              // "readonly", "admin", or "probe"
	Expires string `json:"expires,omitempty"` // RFC3339 timestamp, empty = never expires
}

// TLSEnabled returns true if both cert and key paths are configured.
func (c *Cluster) TLSEnabled() bool {
	return c.TLSCert != "" && c.TLSKey != ""
}

// EffectiveLogLevel returns the configured log level or "auto" as default.
func (c *Cluster) EffectiveLogLevel() string {
	if c.LogLevel == "" {
		return "auto"
	}
	return c.LogLevel
}

// ScopesHash returns a short, deterministic fingerprint of the scopes map.
func (c *Cluster) ScopesHash() string {
	normalized := make(map[string]ScopeConfig, len(c.Scopes))
	for name, sc := range c.Scopes {
		sc.NodeIP = ""
		normalized[name] = sc
	}
	data, err := json.Marshal(normalized)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])[:12]
}

// ConfigDocumentHash returns a stable, truncated SHA-256 digest over every
// field a coordination-plane config push actually distributes.
func (c *Cluster) ConfigDocumentHash() string {
	normalizedScopes := make(map[string]ScopeConfig, len(c.Scopes))
	for name, sc := range c.Scopes {
		sc.NodeIP = ""
		normalizedScopes[name] = sc
	}
	doc := struct {
		PSK                   string                 `json:"psk"`
		TrustedHosts          []string               `json:"trusted_hosts"`
		TLSCert               string                 `json:"tls_cert"`
		TLSKey                string                 `json:"tls_key"`
		APITokens             []APIToken             `json:"api_tokens"`
		LogLevel              string                 `json:"log_level"`
		HelperSocket          string                 `json:"helper_socket"`
		Platform              *Platform              `json:"platform"`
		Scopes                map[string]ScopeConfig `json:"scopes"`
		ProbeIntervalMS       int                    `json:"probe_interval_ms"`
		MgmtVIP               *MgmtVIPConfig         `json:"mgmt_vip"`
		DefaultDNSChecks      []DNSCheck             `json:"default_dns_checks"`
		GlobalDNSRecords      []DNSRecord            `json:"global_dns_records"`
		LocalDomains          []LocalDomain          `json:"local_domains"`
		ScopeDefaults         *ScopeDefaults         `json:"scope_defaults"`
		DefaultDHCPOptions    []string               `json:"default_dhcp_options"`
		CoreDNSAddress        string                 `json:"core_dns_address"`
		CoreDHCPAddress       string                 `json:"core_dhcp_address"`
		CoreDNSQueryLogging   bool                   `json:"core_dns_query_logging"`
		DNSRelayCacheSize     int                    `json:"dnsrelay_cache_size"`
		DNSRelayCacheMaxBytes int                    `json:"dnsrelay_cache_max_bytes"`
	}{
		PSK: c.PSK, TrustedHosts: c.TrustedHosts,
		TLSCert: c.TLSCert, TLSKey: c.TLSKey, APITokens: c.APITokens,
		LogLevel: c.LogLevel, HelperSocket: c.HelperSocket, Platform: c.Platform,
		Scopes: normalizedScopes, ProbeIntervalMS: c.ProbeIntervalMS, MgmtVIP: c.MgmtVIP,
		DefaultDNSChecks: c.DefaultDNSChecks, GlobalDNSRecords: c.GlobalDNSRecords,
		LocalDomains:  c.LocalDomains,
		ScopeDefaults: c.ScopeDefaults, DefaultDHCPOptions: c.DefaultDHCPOptions,
		CoreDNSAddress: c.CoreDNSAddress, CoreDHCPAddress: c.CoreDHCPAddress,
		CoreDNSQueryLogging:   c.CoreDNSQueryLogging,
		DNSRelayCacheSize:     c.DNSRelayCacheSize,
		DNSRelayCacheMaxBytes: c.DNSRelayCacheMaxBytes,
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])[:12]
}

// ScopeNames returns the scope names sorted for deterministic iteration.
func (c *Cluster) ScopeNames() []string {
	names := make([]string, 0, len(c.Scopes))
	for name := range c.Scopes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// IoTScopeNames returns the sorted names of every scope with
// DHCPIoTDefaults set.
func (c *Cluster) IoTScopeNames() []string {
	var names []string
	for name, sc := range c.Scopes {
		if sc.DHCPIoTDefaults {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// DisabledScopeNames returns the sorted names of every scope with
// DNSMasqDisabled set.
func (c *Cluster) DisabledScopeNames() []string {
	var names []string
	for name, sc := range c.Scopes {
		if sc.DNSMasqDisabled {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// HasScopes reports whether scope definitions are present.
func (c *Cluster) HasScopes() bool {
	return len(c.Scopes) > 0
}

func Load(path string) (*Cluster, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cluster config %s: %w", path, err)
	}
	var c Cluster
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse cluster config: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(data, &keys) == nil {
		_, c.LegacyDryRun = keys["dry_run"]
	}
	return &c, nil
}

// Save validates c and writes it to path atomically (temp file + rename,
// so a process dying mid-write never leaves a corrupt or partial file on
// disk).
func Save(path string, c *Cluster) error {
	if err := c.validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal cluster config: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write cluster config: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename cluster config into place: %w", err)
	}
	return nil
}

func (c *Cluster) validate() error {
	effective := c.SchemaVersion
	if effective == 0 {
		effective = 1
	}
	if effective > CurrentSchemaVersion {
		return fmt.Errorf("config schema_version %d is newer than supported %d — upgrade dnshived",
			effective, CurrentSchemaVersion)
	}

	if c.ClusterID == "" {
		return fmt.Errorf("cluster_id is required")
	}
	if c.NodeID == "" {
		return fmt.Errorf("node_id is required")
	}
	switch c.Role {
	case RoleCore1, RoleCore2, RoleCore3:
	default:
		return fmt.Errorf("role must be core-1, core-2, or core-3 (got %q)", c.Role)
	}
	if c.ControlAddr == "" {
		return fmt.Errorf("control_addr is required")
	}
	if c.ProbeIntervalMS < 0 {
		return fmt.Errorf("probe_interval_ms must not be negative (got %d)", c.ProbeIntervalMS)
	}
	if c.ProbeIntervalMS > 0 && c.ProbeIntervalMS < 100 {
		return fmt.Errorf("probe_interval_ms %d too low (min 100ms) — risks a probe busy-loop", c.ProbeIntervalMS)
	}

	// Validate platform + scopes if present.
	if c.Platform != nil {
		if c.Platform.Mgmt == "" {
			return fmt.Errorf("platform.mgmt is required")
		}
	}

	// A scope can only be built on a known trunk, so platform is required
	// as soon as one exists. A zero-scope cluster runs without it.
	if len(c.Scopes) > 0 && c.Platform == nil {
		return fmt.Errorf("platform is required once scopes are configured")
	}

	// An empty PSK disables the witness/fencing protocol cluster-wide:
	// WitnessRequired is psk != "" and tokens HMAC against an empty key.
	if c.PSK == "" {
		return fmt.Errorf("psk is required — an empty psk silently disables the witness/fencing protocol cluster-wide, not just weakens it")
	}

	workerSet := make(map[string]bool)
	if c.Platform != nil {
		workerSet[c.Platform.Mgmt] = true // mgmt is "known" but not a worker
		for _, w := range c.Platform.Workers {
			workerSet[w] = true
		}
		for iface := range c.Platform.InterfaceLabels {
			if !workerSet[iface] || iface == c.Platform.Mgmt {
				return fmt.Errorf("platform.interface_labels: %q is not a configured worker interface", iface)
			}
		}
	}

	vlanIDs := make(map[string]string)
	vrrpIDs := make(map[int]string)
	vipHosts := make(map[string]string)

	if c.MgmtVIP != nil {
		if c.MgmtVIP.VIP == "" {
			return fmt.Errorf("mgmt_vip.vip is required when mgmt_vip is set")
		}
		if c.MgmtVIP.VRRPID < 1 || c.MgmtVIP.VRRPID > 255 {
			return fmt.Errorf("mgmt_vip: vrrp_id %d out of range (1-255)", c.MgmtVIP.VRRPID)
		}
		vrrpIDs[c.MgmtVIP.VRRPID] = "mgmt_vip"
		mgmtHost, _, _ := strings.Cut(c.MgmtVIP.VIP, "/")
		vipHosts[mgmtHost] = "mgmt_vip"
	}

	for name, sc := range c.Scopes {
		if !scopeNamePattern.MatchString(name) {
			return fmt.Errorf("scope %q: name must match %s (used to build filenames, systemd unit names, and VLAN interface names)", name, scopeNamePattern.String())
		}
		if c.Platform != nil {
			if sc.Parent == c.Platform.Mgmt && sc.VLANID != 0 {
				return fmt.Errorf("scope %q: parent %q is the protected mgmt interface — only an untagged scope (vlan_id omitted) may use it", name, sc.Parent)
			}
			if !workerSet[sc.Parent] {
				return fmt.Errorf("scope %q: parent %q is not a configured worker interface", name, sc.Parent)
			}
		}
		if sc.VLANID != 0 && (sc.VLANID < 2 || sc.VLANID > 4094) {
			return fmt.Errorf("scope %q: vlan_id %d out of range (2-4094, or omitted entirely for an untagged scope) — VLAN 1 is conventionally reserved as the native/untagged VLAN and is not usable for a tagged scope interface", name, sc.VLANID)
		}
		vlanKey := fmt.Sprintf("%s|%d", sc.Parent, sc.VLANID)
		if prev, dup := vlanIDs[vlanKey]; dup {
			return fmt.Errorf("scope %q: vlan_id %d on parent %q conflicts with scope %q", name, sc.VLANID, sc.Parent, prev)
		}
		vlanIDs[vlanKey] = name
		if sc.VRRPID < 1 || sc.VRRPID > 255 {
			return fmt.Errorf("scope %q: vrrp_id %d out of range (1-255)", name, sc.VRRPID)
		}
		if prev, dup := vrrpIDs[sc.VRRPID]; dup {
			return fmt.Errorf("scope %q: vrrp_id %d conflicts with scope %q", name, sc.VRRPID, prev)
		}
		vrrpIDs[sc.VRRPID] = name
		if host, _, _ := strings.Cut(sc.VIP, "/"); host != "" {
			if prev, dup := vipHosts[host]; dup {
				return fmt.Errorf("scope %q: vip %s is already used by %s", name, host, prev)
			}
			vipHosts[host] = fmt.Sprintf("scope %q", name)
		}
		switch sc.PreferredWorker {
		case RoleCore1, RoleCore2, RoleCore3:
		default:
			return fmt.Errorf("scope %q: preferred_worker must be core-1, core-2, or core-3 (got %q)", name, sc.PreferredWorker)
		}
		if sc.VRRPVersion != 0 && sc.VRRPVersion != 2 && sc.VRRPVersion != 3 {
			return fmt.Errorf("scope %q: vrrp_version must be 2 or 3 (got %d)", name, sc.VRRPVersion)
		}
		if sc.AdvertIntMS < 0 {
			return fmt.Errorf("scope %q: advert_int_ms must not be negative (got %d)", name, sc.AdvertIntMS)
		}
		if sc.AdvertIntMS > 0 && sc.AdvertIntMS%1000 != 0 && sc.VRRPVersion != 3 {
			return fmt.Errorf("scope %q: advert_int_ms %d is sub-second, which requires vrrp_version=3 "+
				"(VRRPv2's wire format only supports whole-second advertisement intervals)", name, sc.AdvertIntMS)
		}
		if sc.AdvertIntMS > 255000 {
			return fmt.Errorf("scope %q: advert_int_ms %d out of range (max 255000ms, keepalived's own limit)", name, sc.AdvertIntMS)
		}
		if sc.DHCPLeaseTime != "" && sc.DHCPLeaseTime != "infinite" && !dhcpLeaseTimePattern.MatchString(sc.DHCPLeaseTime) {
			return fmt.Errorf("scope %q: dhcp_lease_time %q is not a valid dnsmasq duration (expected a number optionally suffixed with s/m/h/d, or \"infinite\")", name, sc.DHCPLeaseTime)
		}
		if sc.Color != "" && !scopeColorPattern.MatchString(sc.Color) {
			return fmt.Errorf("scope %q: color %q is not a valid 6-digit hex color (expected #rrggbb)", name, sc.Color)
		}
		if err := validateDNSRecords(sc.DNSRecords, fmt.Sprintf("scope %q", name)); err != nil {
			return err
		}
		if err := ValidateDHCPOptions(sc.DHCPOptions, fmt.Sprintf("scope %q", name)); err != nil {
			return err
		}
		if err := validateReservations(sc.Reservations, fmt.Sprintf("scope %q", name)); err != nil {
			return err
		}
	}

	if err := validateDNSRecords(c.GlobalDNSRecords, "global_dns_records"); err != nil {
		return err
	}
	if err := validateLocalDomains(c.LocalDomains); err != nil {
		return err
	}
	if err := ValidateDHCPOptions(c.DefaultDHCPOptions, "default_dhcp_options"); err != nil {
		return err
	}

	for i, chk := range c.DefaultDNSChecks {
		if chk.Name == "" {
			return fmt.Errorf("default_dns_checks[%d]: name is required", i)
		}
		if !validDNSRecordTypes[chk.Type] {
			return fmt.Errorf("default_dns_checks[%d]: type must be one of %s (got %q)", i, dnsRecordTypesList, chk.Type)
		}
	}

	return nil
}

func (c *Cluster) ListenAddr() string {
	if c.BindAddr != "" {
		return c.BindAddr
	}
	if p := portOf(c.ControlAddr); p != "" {
		return ":" + p
	}
	return ":9443"
}

func portOf(addr string) string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[i+1:]
		}
	}
	return ""
}

// ValidationResult holds all validation findings.
type ValidationResult struct {
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// OK returns true if there are no errors.
func (v ValidationResult) OK() bool { return len(v.Errors) == 0 }

// ValidateExtended runs comprehensive validation and collects ALL findings
// (not just the first error).
func (c *Cluster) ValidateExtended() ValidationResult {
	var r ValidationResult

	// Basic validation first.
	if err := c.validate(); err != nil {
		r.Errors = append(r.Errors, err.Error())
		// Don't return early — collect more findings.
	}

	// TLS validation.
	if c.TLSCert != "" || c.TLSKey != "" {
		if c.TLSCert == "" {
			r.Errors = append(r.Errors, "tls_cert is set but tls_key is missing")
		}
		if c.TLSKey == "" {
			r.Errors = append(r.Errors, "tls_key is set but tls_cert is missing")
		}
		if c.TLSCert != "" {
			if _, err := os.Stat(c.TLSCert); err != nil {
				r.Warnings = append(r.Warnings, fmt.Sprintf("tls_cert file not found on this host: %s (may exist on target)", c.TLSCert))
			}
		}
		if c.TLSKey != "" {
			if _, err := os.Stat(c.TLSKey); err != nil {
				r.Warnings = append(r.Warnings, fmt.Sprintf("tls_key file not found on this host: %s (may exist on target)", c.TLSKey))
			}
		}
	}

	// PSK validation.
	if c.PSK != "" && len(c.PSK) < 32 {
		r.Warnings = append(r.Warnings, fmt.Sprintf("psk is only %d characters — recommend 64+ hex characters", len(c.PSK)))
	}

	// TrustedHosts validation.
	for _, h := range c.TrustedHosts {
		if net.ParseIP(h) == nil {
			r.Errors = append(r.Errors, fmt.Sprintf("trusted_hosts: %q is not a valid IP address", h))
		}
	}
	if len(c.TrustedHosts) == 0 {
		r.Warnings = append(r.Warnings, "trusted_hosts is empty — the arbiter's token endpoints and /api/v1/ping accept requests from any source address")
	}

	// API token validation.
	tokenNames := make(map[string]bool)
	for _, t := range c.APITokens {
		if t.Name == "" {
			r.Errors = append(r.Errors, "api_tokens: token with empty name")
		}
		if t.Token == "" {
			r.Errors = append(r.Errors, fmt.Sprintf("api_tokens: token %q has empty token value", t.Name))
		}
		if t.Role != "readonly" && t.Role != "admin" && t.Role != "probe" && t.Role != "probe-admin" {
			r.Errors = append(r.Errors, fmt.Sprintf("api_tokens: token %q has invalid role %q (must be readonly, admin, probe, or probe-admin)", t.Name, t.Role))
		}
		if t.Expires != "" {
			exp, err := time.Parse(time.RFC3339, t.Expires)
			if err != nil {
				r.Errors = append(r.Errors, fmt.Sprintf("api_tokens: token %q has invalid expires format (must be RFC3339)", t.Name))
			} else if time.Now().After(exp) {
				r.Warnings = append(r.Warnings, fmt.Sprintf("api_tokens: token %q has expired (%s)", t.Name, t.Expires))
			} else if time.Until(exp) < 7*24*time.Hour {
				r.Warnings = append(r.Warnings, fmt.Sprintf("api_tokens: token %q expires within 7 days (%s)", t.Name, t.Expires))
			}
		}
		if tokenNames[t.Name] {
			r.Errors = append(r.Errors, fmt.Sprintf("api_tokens: duplicate token name %q", t.Name))
		}
		tokenNames[t.Name] = true
	}

	// Log level validation.
	switch c.EffectiveLogLevel() {
	case "auto", "debug", "info", "warning":
	default:
		r.Errors = append(r.Errors, fmt.Sprintf("log_level: invalid value %q (must be auto, debug, info, or warning)", c.LogLevel))
	}

	// Warnings (non-fatal). A missing PSK is a hard Error from validate()
	// above, so it isn't re-listed here.
	if len(c.APITokens) == 0 {
		r.Warnings = append(r.Warnings, "no api_tokens configured — API is unauthenticated")
	}
	if !c.TLSEnabled() && len(c.APITokens) > 0 {
		r.Warnings = append(r.Warnings, "api_tokens configured but TLS disabled — tokens transmitted in cleartext")
	}
	if c.DataDir == "" {
		r.Warnings = append(r.Warnings, "data_dir empty — using default /var/lib/dnshived")
	}

	if c.ScopeDefaults != nil && len(c.ScopeDefaults.NodeIPSuffixes) > 1 {
		seen := make(map[string]string, len(c.ScopeDefaults.NodeIPSuffixes))
		names := make([]string, 0, len(c.ScopeDefaults.NodeIPSuffixes))
		for name := range c.ScopeDefaults.NodeIPSuffixes {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			suffix := c.ScopeDefaults.NodeIPSuffixes[name]
			if suffix == "" {
				continue
			}
			if other, dup := seen[suffix]; dup {
				r.Errors = append(r.Errors, fmt.Sprintf(
					"scope_defaults.node_ip_suffixes: %q and %q both use suffix %q — every scope that falls back to this default would get an identical node_ip on both, a real duplicate-address condition",
					other, name, suffix))
			}
			seen[suffix] = name
		}
	}

	if c.ScopeDefaults != nil && c.ScopeDefaults.VIPSuffix != "" {
		if n, err := strconv.Atoi(c.ScopeDefaults.VIPSuffix); err != nil || n < 0 || n > 255 {
			r.Errors = append(r.Errors, fmt.Sprintf(
				"scope_defaults.vip_suffix %q is not a valid IPv4 octet (0-255)",
				c.ScopeDefaults.VIPSuffix))
		}
	}

	if err := validateCoreAddress("core_dns_address", c.CoreDNSAddress); err != "" {
		r.Errors = append(r.Errors, err)
	}
	if err := validateCoreAddress("core_dhcp_address", c.CoreDHCPAddress); err != "" {
		r.Errors = append(r.Errors, err)
	}
	if c.CoreDNSAddress != "" && c.CoreDNSAddress == c.CoreDHCPAddress {
		r.Errors = append(r.Errors, fmt.Sprintf(
			"core_dns_address and core_dhcp_address are both %q — the two core instances must bind distinct addresses",
			c.CoreDNSAddress))
	}

	if c.DNSRelayCacheSize < 0 {
		r.Errors = append(r.Errors, fmt.Sprintf("dnsrelay_cache_size %d must not be negative", c.DNSRelayCacheSize))
	}
	if c.DNSRelayCacheMaxBytes < 0 {
		r.Errors = append(r.Errors, fmt.Sprintf("dnsrelay_cache_max_bytes %d must not be negative", c.DNSRelayCacheMaxBytes))
	}

	if c.BackupEnabled && c.BackupPassword == "" {
		r.Errors = append(r.Errors, "backup_enabled is true but backup_password is empty — automated backups need a password to encrypt with")
	}

	scopeNames := make([]string, 0, len(c.Scopes))
	for name := range c.Scopes {
		scopeNames = append(scopeNames, name)
	}
	sort.Strings(scopeNames)
	for _, name := range scopeNames {
		sc := c.Scopes[name]

		if sc.VIP != "" && sc.Gateway != "" {
			vipAddr, _, _ := strings.Cut(sc.VIP, "/")
			for _, gw := range splitGatewayList(sc.Gateway) {
				if vipAddr == gw {
					r.Warnings = append(r.Warnings, fmt.Sprintf(
						"scope %q: vip and gateway are the same address (%s) — this scope's own VIP is normally not also the router",
						name, gw))
				}
			}
		}

		if sc.NodeIP != "" {
			nodeAddr, _, err := net.ParseCIDR(sc.NodeIP)
			if err != nil {
				nodeAddr = net.ParseIP(sc.NodeIP)
			}
			if nodeAddr != nil {
				if start, end, ok := parseIPRange(sc.DHCPRange); ok {
					n := ipv4ToUint32(nodeAddr.To4())
					if nodeAddr.To4() != nil && n >= start && n <= end {
						r.Warnings = append(r.Warnings, fmt.Sprintf(
							"scope %q: node_ip %s falls inside this scope's own dhcp_range (%s-%s) — DHCP could hand this exact address to a client",
							name, sc.NodeIP, sc.DHCPRange[0], sc.DHCPRange[1]))
					}
				}
			}
		}

		addrErrs, addrWarns := validateScopeAddressing(name, sc)
		r.Errors = append(r.Errors, addrErrs...)
		r.Warnings = append(r.Warnings, addrWarns...)

		if len(sc.DNSRecords) == 0 && len(c.GlobalDNSRecords) == 0 {
			continue
		}
		overridden := sc.ClientDNSServer != ""
		if !overridden {
			effectiveOpts := sc.DHCPOptions
			if len(effectiveOpts) == 0 {
				effectiveOpts = c.DefaultDHCPOptions
			}
			overridden = dhcpOptionOverridesClientDNS(effectiveOpts)
		}
		if overridden {
			r.Warnings = append(r.Warnings, fmt.Sprintf(
				"scope %q: defines local DNS name(s) but its DNS server for clients (option 6) is set away from this scope's own dnsmasq — those names will be unreachable to clients on this scope. \"upstream\" only controls where THIS dnsmasq forwards queries it can't answer itself, not what clients are told to use.",
				name))
		}
	}

	for i := 0; i < len(scopeNames); i++ {
		a := c.Scopes[scopeNames[i]]
		aStart, aEnd, aOK := parseIPRange(a.DHCPRange)
		if !aOK {
			continue
		}
		for j := i + 1; j < len(scopeNames); j++ {
			b := c.Scopes[scopeNames[j]]
			bStart, bEnd, bOK := parseIPRange(b.DHCPRange)
			if !bOK {
				continue
			}
			if ipRangesOverlap(aStart, aEnd, bStart, bEnd) {
				r.Warnings = append(r.Warnings, fmt.Sprintf(
					"scope %q and scope %q: dhcp_range overlaps (%s-%s vs %s-%s) — legitimate if these are genuinely isolated segments, worth a second look if not",
					scopeNames[i], scopeNames[j], a.DHCPRange[0], a.DHCPRange[1], b.DHCPRange[0], b.DHCPRange[1]))
			}
		}
	}

	for i := 0; i < len(scopeNames); i++ {
		a := c.Scopes[scopeNames[i]]
		_, aNet, aErr := net.ParseCIDR(a.VIP)
		if aErr != nil {
			continue
		}
		for j := i + 1; j < len(scopeNames); j++ {
			b := c.Scopes[scopeNames[j]]
			_, bNet, bErr := net.ParseCIDR(b.VIP)
			if bErr != nil {
				continue
			}
			if subnetsOverlap(aNet, bNet) {
				r.Errors = append(r.Errors, fmt.Sprintf(
					"scope %q and scope %q: vip subnets overlap (%s vs %s) — every address in the smaller range collides with the same address in the larger one; no legitimate topology shares a subnet across two scopes",
					scopeNames[i], scopeNames[j], a.VIP, b.VIP))
			}
		}
	}

	return r
}

// subnetsOverlap reports whether two IPv4 networks share any address.
func subnetsOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

// minSaneVIPPrefix is a practical floor for a scope's VIP/node_ip CIDR
// prefix length.
const minSaneVIPPrefix = 8

func splitGatewayList(gateway string) []string {
	if gateway == "" {
		return nil
	}
	parts := strings.Split(gateway, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// isNetworkOrBroadcastAddress reports whether ip is exactly ipNet's own
// network address or broadcast address.
func isNetworkOrBroadcastAddress(ip net.IP, ipNet *net.IPNet) bool {
	ip4 := ip.To4()
	base := ipNet.IP.To4()
	mask := net.IP(ipNet.Mask).To4()
	if ip4 == nil || base == nil || mask == nil {
		return false
	}
	if ip4.Equal(base) {
		return true
	}
	bcast := make(net.IP, 4)
	for i := range bcast {
		bcast[i] = base[i] | ^mask[i]
	}
	return ip4.Equal(bcast)
}

// validateScopeAddressing runs real syntax + coherence checks against one
// scope's own address fields.
func validateScopeAddressing(name string, sc ScopeConfig) (errs, warnings []string) {
	var vipNet *net.IPNet

	if sc.VIP != "" {
		ip, ipNet, err := net.ParseCIDR(sc.VIP)
		if err != nil {
			errs = append(errs, fmt.Sprintf("scope %q: vip %q is not a valid CIDR address (expected e.g. 192.168.100.1/24): %v", name, sc.VIP, err))
		} else {
			if ones, _ := ipNet.Mask.Size(); ones < minSaneVIPPrefix {
				errs = append(errs, fmt.Sprintf("scope %q: vip %q has an implausibly wide prefix (/%d) — almost certainly a typo (e.g. /2 instead of /24)", name, sc.VIP, ones))
			}
			if isNetworkOrBroadcastAddress(ip, ipNet) {
				errs = append(errs, fmt.Sprintf("scope %q: vip %q is the subnet's own network/broadcast address, never a usable host address", name, sc.VIP))
			}
			vipNet = &net.IPNet{IP: ip.Mask(ipNet.Mask), Mask: ipNet.Mask}
		}
	}

	for _, gw := range splitGatewayList(sc.Gateway) {
		gwIP := net.ParseIP(gw)
		if gwIP == nil {
			errs = append(errs, fmt.Sprintf("scope %q: gateway %q is not a valid IP address", name, gw))
		} else if vipNet != nil && !vipNet.Contains(gwIP) {
			errs = append(errs, fmt.Sprintf("scope %q: gateway %s is outside vip's own subnet (%s)", name, gw, vipNet.String()))
		} else if vipNet != nil && isNetworkOrBroadcastAddress(gwIP, vipNet) {
			errs = append(errs, fmt.Sprintf("scope %q: gateway %s is the subnet's own network/broadcast address, never a usable host address", name, gw))
		}
	}

	if sc.NodeIP != "" {
		if nodeIP, nodeIPNet, err := net.ParseCIDR(sc.NodeIP); err != nil {
			errs = append(errs, fmt.Sprintf("scope %q: node_ip %q is not a valid CIDR address (expected e.g. 192.168.100.22/24): %v", name, sc.NodeIP, err))
		} else if isNetworkOrBroadcastAddress(nodeIP, nodeIPNet) {
			errs = append(errs, fmt.Sprintf("scope %q: node_ip %q is the subnet's own network/broadcast address, never a usable host address", name, sc.NodeIP))
		}
	} else if len(sc.NodeIPOverrides) == 0 {
		warnings = append(warnings, fmt.Sprintf(
			"scope %q: node_ip is not set — a brand-new scope gets one derived automatically per node when committed through the web UI; an already-existing scope with neither node_ip nor a node_ip_overrides entry for a worker will stay stuck in VRRP FAULT forever on that worker (confirmed live: keepalived has no real IPv4 address to operate from on the VLAN interface) and never actually serve DHCP until you set one directly on this scope's own edit page (/scopes/%s, one field per worker)",
			name, name))
	}

	for i, label := range [2]string{"start", "end"} {
		addr := sc.DHCPRange[i]
		if addr == "" {
			continue
		}
		ip := net.ParseIP(addr)
		if ip == nil {
			errs = append(errs, fmt.Sprintf("scope %q: dhcp_range %s %q is not a valid IP address", name, label, addr))
			continue
		}
		if vipNet != nil && !vipNet.Contains(ip) {
			errs = append(errs, fmt.Sprintf("scope %q: dhcp_range %s %s is outside vip's own subnet (%s)", name, label, addr, vipNet.String()))
		} else if vipNet != nil && isNetworkOrBroadcastAddress(ip, vipNet) {
			errs = append(errs, fmt.Sprintf("scope %q: dhcp_range %s %s is the subnet's own network/broadcast address, never a usable host address", name, label, addr))
		}
	}

	if sc.DHCPRange[0] != "" && sc.DHCPRange[1] != "" && sc.Gateway == "" {
		errs = append(errs, fmt.Sprintf(
			"scope %q: dhcp_range is set but gateway is empty — internal/dhcpcentralrender silently excludes this scope from DHCP entirely until gateway is set (a real live incident, not a style nit: the scope looks fully constructed — interface, gate, relay all report success — but central DHCP never serves it)",
			name))
	}

	return errs, warnings
}

// parseIPRange parses a ScopeConfig.DHCPRange [start, end] pair into
// comparable uint32 IPv4 values.
func parseIPRange(r [2]string) (start, end uint32, ok bool) {
	s := net.ParseIP(r[0])
	e := net.ParseIP(r[1])
	if s == nil || e == nil {
		return 0, 0, false
	}
	s4, e4 := s.To4(), e.To4()
	if s4 == nil || e4 == nil {
		return 0, 0, false
	}
	return ipv4ToUint32(s4), ipv4ToUint32(e4), true
}

func ipv4ToUint32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func ipRangesOverlap(aStart, aEnd, bStart, bEnd uint32) bool {
	if aStart > aEnd {
		aStart, aEnd = aEnd, aStart
	}
	if bStart > bEnd {
		bStart, bEnd = bEnd, bStart
	}
	return aStart <= bEnd && bStart <= aEnd
}
