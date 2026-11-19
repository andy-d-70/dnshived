// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package configimport reads an exported configuration and merges chosen groups of it
// into a live one. Trust material (keys, tokens, certificates, trusted hosts, node
// identity) is never read from a file.
package configimport

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"dnshived/internal/config"
)

const MaxFileBytes = 64 << 20

type Group string

const (
	GroupScopes   Group = "scopes"
	GroupDomains  Group = "domains"
	GroupDNS      Group = "dns"
	GroupDHCP     Group = "dhcp"
	GroupAccess   Group = "access"
	GroupSettings Group = "settings"
	GroupPlatform Group = "platform"
)

var AllGroups = []Group{GroupScopes, GroupDomains, GroupDNS, GroupDHCP, GroupAccess, GroupSettings, GroupPlatform}

var groupLabels = map[Group]string{
	GroupScopes:   "Scopes (with reservations, records and options)",
	GroupDomains:  "Local domains",
	GroupDNS:      "Global DNS records and DNS checks",
	GroupDHCP:     "DHCP defaults (default options, scope defaults)",
	GroupAccess:   "Access list",
	GroupSettings: "Cluster settings (log level, probe interval, relay cache, core addresses, backup)",
	GroupPlatform: "Platform (interface names) and management VIP",
}

func (g Group) Label() string { return groupLabels[g] }

func ValidGroup(g Group) bool {
	_, ok := groupLabels[g]
	return ok
}

type Mode string

const (
	Merge   Mode = "merge"
	Replace Mode = "replace"
)

type Source struct {
	Cluster config.Cluster
	// IgnoredSecrets lists the kinds of trust material the file held; none of it is used.
	IgnoredSecrets []string
}

// Parse reads an export (all, cluster, scopes or data), a cluster.json or a backup's
// configuration. It does not validate the result: the commit does.
func Parse(data []byte) (*Source, error) {
	if len(data) > MaxFileBytes {
		return nil, fmt.Errorf("the file is larger than %d MiB", MaxFileBytes>>20)
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		return nil, errors.New("not a configuration file: expected a JSON object")
	}
	var c config.Cluster
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("not a configuration file: %w", err)
	}
	if c.SchemaVersion > config.CurrentSchemaVersion {
		return nil, fmt.Errorf("the file has schema version %d, this version reads up to %d: upgrade first", c.SchemaVersion, config.CurrentSchemaVersion)
	}
	s := &Source{Cluster: c}
	if c.PSK != "" {
		s.IgnoredSecrets = append(s.IgnoredSecrets, "cluster key")
	}
	if len(c.APITokens) > 0 {
		s.IgnoredSecrets = append(s.IgnoredSecrets, "API tokens")
	}
	if c.TLSKey != "" || c.TLSCert != "" {
		s.IgnoredSecrets = append(s.IgnoredSecrets, "TLS certificate and key")
	}
	if c.BackupPassword != "" {
		s.IgnoredSecrets = append(s.IgnoredSecrets, "backup password")
	}
	if len(s.Counts()) == 0 && c.ClusterID == "" {
		return nil, errors.New("the file holds no configuration data")
	}
	return s, nil
}

// Counts returns how many objects the file holds per group; a group without any is absent.
func (s *Source) Counts() map[Group]int {
	c := &s.Cluster
	out := map[Group]int{}
	if n := len(c.Scopes) + len(c.ParkedScopes); n > 0 {
		out[GroupScopes] = n
	}
	if n := len(c.LocalDomains); n > 0 {
		out[GroupDomains] = n
	}
	if n := len(c.GlobalDNSRecords) + len(c.DefaultDNSChecks); n > 0 {
		out[GroupDNS] = n
	}
	if n := len(c.DefaultDHCPOptions); n > 0 || c.ScopeDefaults != nil {
		if c.ScopeDefaults != nil {
			n++
		}
		out[GroupDHCP] = n
	}
	if c.Access != nil {
		out[GroupAccess] = 1
	}
	if settingsPresent(c) {
		out[GroupSettings] = 1
	}
	if c.Platform != nil || c.MgmtVIP != nil {
		out[GroupPlatform] = 1
	}
	return out
}

func settingsPresent(c *config.Cluster) bool {
	return c.LogLevel != "" || c.ProbeIntervalMS != 0 || c.DNSRelayCacheSize != 0 || c.DNSRelayCacheMaxBytes != 0 ||
		c.CoreDNSQueryLogging || c.SanityCheckDisabled || c.BackupEnabled || c.BackupIntervalHours != 0 ||
		c.BackupRetentionCount != 0 || c.BackupReplicateToPeers || c.CoreDNSAddress != "" || c.CoreDHCPAddress != ""
}

// ScopeNames lists the scopes the file holds, live and parked, sorted.
func (s *Source) ScopeNames() []string {
	seen := map[string]bool{}
	var names []string
	for n := range s.Cluster.Scopes {
		seen[n] = true
		names = append(names, n)
	}
	for n := range s.Cluster.ParkedScopes {
		if !seen[n] {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}

type Options struct {
	Groups map[Group]Mode
	// Scopes limits the scopes group to these names; empty means all.
	Scopes []string
}

type GroupReport struct {
	Group     Group
	Mode      Mode
	Added     []string
	Changed   []string
	Unchanged int
	Removed   []string
	Skipped   []string
	Notes     []string
}

type Report struct{ Groups []GroupReport }

func (r Report) Changes() int {
	n := 0
	for _, g := range r.Groups {
		n += len(g.Added) + len(g.Changed) + len(g.Removed)
	}
	return n
}

func sanitizeScope(sc config.ScopeConfig) config.ScopeConfig {
	sc.NodeIP = ""
	sc.NodeIPOverrides = nil
	sc.RebalanceApprovedAt = 0
	return sc
}

// Apply returns live with the chosen groups of src merged in, and a report of what changed.
// New scopes arrive parked. Existing live scopes are never touched.
func Apply(live config.Cluster, src *Source, opt Options) (config.Cluster, Report, error) {
	for g, m := range opt.Groups {
		if !ValidGroup(g) {
			return live, Report{}, fmt.Errorf("unknown group %q", g)
		}
		if m != Merge && m != Replace {
			return live, Report{}, fmt.Errorf("group %s: mode must be merge or replace", g)
		}
	}
	out := live
	var rep Report
	for _, g := range AllGroups {
		mode, on := opt.Groups[g]
		if !on {
			continue
		}
		gr := GroupReport{Group: g, Mode: mode}
		switch g {
		case GroupScopes:
			applyScopes(&out, &src.Cluster, opt.Scopes, mode, &gr)
		case GroupDomains:
			applyDomains(&out, &src.Cluster, mode, &gr)
		case GroupDNS:
			applyDNS(&out, &src.Cluster, mode, &gr)
		case GroupDHCP:
			applyDHCP(&out, &src.Cluster, mode, &gr)
		case GroupAccess:
			applyAccess(&out, &src.Cluster, mode, &gr)
		case GroupSettings:
			applySettings(&out, &src.Cluster, mode, &gr)
		case GroupPlatform:
			applyPlatform(&out, &src.Cluster, mode, &gr)
		}
		rep.Groups = append(rep.Groups, gr)
	}
	return out, rep, nil
}

func applyScopes(out *config.Cluster, src *config.Cluster, only []string, mode Mode, gr *GroupReport) {
	want := map[string]bool{}
	for _, n := range only {
		want[n] = true
	}
	incoming := map[string]config.ScopeConfig{}
	for n, sc := range src.ParkedScopes {
		incoming[n] = sc
	}
	for n, sc := range src.Scopes {
		incoming[n] = sc
	}
	names := make([]string, 0, len(incoming))
	for n := range incoming {
		names = append(names, n)
	}
	sort.Strings(names)

	parked := make(map[string]config.ScopeConfig, len(out.ParkedScopes)+len(names))
	for k, v := range out.ParkedScopes {
		parked[k] = v
	}
	inFile := map[string]bool{}
	for _, n := range names {
		if len(want) > 0 && !want[n] {
			continue
		}
		inFile[n] = true
		if !config.ValidScopeName(n) {
			gr.Skipped = append(gr.Skipped, n+": not a valid scope name")
			continue
		}
		if _, live := out.Scopes[n]; live {
			gr.Skipped = append(gr.Skipped, n+": a live scope with this name exists, kept as it is")
			continue
		}
		sc := sanitizeScope(incoming[n])
		old, had := parked[n]
		switch {
		case !had:
			gr.Added = append(gr.Added, n)
		case reflect.DeepEqual(old, sc):
			gr.Unchanged++
			continue
		default:
			gr.Changed = append(gr.Changed, n)
		}
		parked[n] = sc
	}
	if mode == Replace && len(want) == 0 {
		for _, n := range sortedKeys(parked) {
			if !inFile[n] {
				delete(parked, n)
				gr.Removed = append(gr.Removed, n)
			}
		}
	}
	if len(parked) == 0 {
		parked = nil
	}
	out.ParkedScopes = parked
	if note := missingTrunksNote(out.Platform, parked, gr); note != "" {
		gr.Notes = append(gr.Notes, note)
	}
}

// missingTrunksNote names the trunks the taken scopes sit on that this cluster's platform lacks:
// enabling those scopes is refused until the platform has them.
func missingTrunksNote(p *config.Platform, parked map[string]config.ScopeConfig, gr *GroupReport) string {
	have := map[string]bool{}
	if p != nil {
		for _, w := range p.Workers {
			have[w] = true
		}
	}
	missing := map[string]bool{}
	for _, list := range [][]string{gr.Added, gr.Changed} {
		for _, name := range list {
			if par := parked[name].Parent; par != "" && !have[par] {
				missing[par] = true
			}
		}
	}
	if len(missing) == 0 {
		return ""
	}
	names := make([]string, 0, len(missing))
	for n := range missing {
		names = append(names, n)
	}
	sort.Strings(names)
	return "these scopes sit on trunk interface(s) " + strings.Join(names, ", ") + " which this cluster's platform does not list; add them to the platform before enabling the scopes"
}

func sortedKeys(m map[string]config.ScopeConfig) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func applyDomains(out *config.Cluster, src *config.Cluster, mode Mode, gr *GroupReport) {
	domains := make([]config.LocalDomain, len(out.LocalDomains))
	copy(domains, out.LocalDomains)
	byName := make(map[string]int, len(domains)+len(src.LocalDomains))
	for i, d := range domains {
		byName[strings.ToLower(d.Name)] = i
	}
	index := func(name string) int {
		if i, ok := byName[strings.ToLower(name)]; ok {
			return i
		}
		return -1
	}
	incoming := append([]config.LocalDomain(nil), src.LocalDomains...)
	sort.SliceStable(incoming, func(i, j int) bool { return incoming[i].ForkedFrom == "" && incoming[j].ForkedFrom != "" })
	inFile := map[string]bool{}
	var changedOriginals []string
	for _, d := range incoming {
		if !config.ValidDomainName(d.Name) {
			gr.Skipped = append(gr.Skipped, d.Name+": not a valid domain name")
			continue
		}
		inFile[strings.ToLower(d.Name)] = true
		if d.ForkedFrom != "" && index(d.ForkedFrom) < 0 && !sourceHas(incoming, d.ForkedFrom) {
			gr.Skipped = append(gr.Skipped, d.Name+": its original "+d.ForkedFrom+" is not in the file")
			continue
		}
		i := index(d.Name)
		if i < 0 {
			d.Records = append([]config.LocalDomainHost(nil), d.Records...)
			byName[strings.ToLower(d.Name)] = len(domains)
			domains = append(domains, d)
			gr.Added = append(gr.Added, fmt.Sprintf("%s (%d records)", d.Name, len(d.Records)))
			if d.ForkedFrom == "" {
				changedOriginals = append(changedOriginals, d.Name)
			}
			continue
		}
		cur := domains[i]
		if mode == Replace {
			if d.ForkedFrom != "" && strings.EqualFold(cur.ForkedFrom, d.ForkedFrom) {
				gr.Unchanged++
				continue
			}
			if reflect.DeepEqual(cur, d) {
				gr.Unchanged++
				continue
			}
			d.Name = cur.Name
			domains[i] = d
			gr.Changed = append(gr.Changed, d.Name)
			changedOriginals = append(changedOriginals, d.Name)
			continue
		}
		if cur.ForkedFrom != "" {
			gr.Skipped = append(gr.Skipped, cur.Name+": linked to "+cur.ForkedFrom+", edit the original")
			continue
		}
		recs, added := unionDeep(cur.Records, d.Records)
		ttlSet := cur.TTL == 0 && d.TTL > 0
		if added == 0 && !ttlSet {
			gr.Unchanged++
			continue
		}
		cur.Records = recs
		if ttlSet {
			cur.TTL = d.TTL
		}
		domains[i] = cur
		gr.Changed = append(gr.Changed, fmt.Sprintf("%s (+%d records)", cur.Name, added))
		changedOriginals = append(changedOriginals, cur.Name)
	}
	if mode == Replace {
		kept := domains[:0]
		for _, d := range domains {
			if inFile[strings.ToLower(d.Name)] {
				kept = append(kept, d)
			} else {
				gr.Removed = append(gr.Removed, d.Name)
			}
		}
		domains = kept
	}
	for _, name := range changedOriginals {
		domains = config.PropagateForkedDomains(domains, name)
	}
	out.LocalDomains = domains
}

func sourceHas(domains []config.LocalDomain, name string) bool {
	for _, d := range domains {
		if strings.EqualFold(d.Name, name) {
			return true
		}
	}
	return false
}

func keyOf(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func unionDeep[T any](live, in []T) (out []T, added int) {
	out = append([]T(nil), live...)
	have := make(map[string]struct{}, len(live)+len(in))
	for _, e := range live {
		have[keyOf(e)] = struct{}{}
	}
	for _, v := range in {
		k := keyOf(v)
		if _, found := have[k]; found {
			continue
		}
		have[k] = struct{}{}
		out = append(out, v)
		added++
	}
	return out, added
}

func applyDNS(out *config.Cluster, src *config.Cluster, mode Mode, gr *GroupReport) {
	if mode == Replace {
		if !reflect.DeepEqual(out.GlobalDNSRecords, src.GlobalDNSRecords) {
			gr.Changed = append(gr.Changed, fmt.Sprintf("global DNS records (%d → %d)", len(out.GlobalDNSRecords), len(src.GlobalDNSRecords)))
			out.GlobalDNSRecords = append([]config.DNSRecord(nil), src.GlobalDNSRecords...)
		} else {
			gr.Unchanged++
		}
		if !reflect.DeepEqual(out.DefaultDNSChecks, src.DefaultDNSChecks) {
			gr.Changed = append(gr.Changed, fmt.Sprintf("DNS checks (%d → %d)", len(out.DefaultDNSChecks), len(src.DefaultDNSChecks)))
			out.DefaultDNSChecks = append([]config.DNSCheck(nil), src.DefaultDNSChecks...)
		} else {
			gr.Unchanged++
		}
		return
	}
	recs, n := unionDeep(out.GlobalDNSRecords, src.GlobalDNSRecords)
	if n > 0 {
		gr.Added = append(gr.Added, fmt.Sprintf("%d global DNS record(s)", n))
		out.GlobalDNSRecords = recs
	}
	checks, m := unionDeep(out.DefaultDNSChecks, src.DefaultDNSChecks)
	if m > 0 {
		gr.Added = append(gr.Added, fmt.Sprintf("%d DNS check(s)", m))
		out.DefaultDNSChecks = checks
	}
	if n == 0 && m == 0 {
		gr.Unchanged++
	}
}

func applyDHCP(out *config.Cluster, src *config.Cluster, mode Mode, gr *GroupReport) {
	if mode == Replace {
		if !reflect.DeepEqual(out.DefaultDHCPOptions, src.DefaultDHCPOptions) {
			gr.Changed = append(gr.Changed, fmt.Sprintf("default DHCP options (%d → %d)", len(out.DefaultDHCPOptions), len(src.DefaultDHCPOptions)))
			out.DefaultDHCPOptions = append([]string(nil), src.DefaultDHCPOptions...)
		}
		if d := scopeDefaultsFrom(src.ScopeDefaults, out.ScopeDefaults); d != nil && !reflect.DeepEqual(out.ScopeDefaults, d) {
			out.ScopeDefaults = d
			gr.Changed = append(gr.Changed, "scope defaults")
		}
		return
	}
	opts, n := unionDeep(out.DefaultDHCPOptions, src.DefaultDHCPOptions)
	if n > 0 {
		out.DefaultDHCPOptions = opts
		gr.Added = append(gr.Added, fmt.Sprintf("%d default DHCP option(s)", n))
	}
	if out.ScopeDefaults == nil && src.ScopeDefaults != nil {
		out.ScopeDefaults = scopeDefaultsFrom(src.ScopeDefaults, nil)
		gr.Added = append(gr.Added, "scope defaults")
	} else if src.ScopeDefaults != nil {
		gr.Skipped = append(gr.Skipped, "scope defaults: this cluster has its own, kept")
	}
	if n == 0 && src.ScopeDefaults == nil {
		gr.Unchanged++
	}
}

// scopeDefaultsFrom copies the file's scope defaults but keeps the node address suffixes of this
// cluster: they belong to its own nodes, not to the cluster the file came from.
func scopeDefaultsFrom(in, own *config.ScopeDefaults) *config.ScopeDefaults {
	if in == nil {
		return nil
	}
	d := *in
	d.NodeIPSuffixes = nil
	if own != nil {
		d.NodeIPSuffixes = own.NodeIPSuffixes
	}
	return &d
}

func applyAccess(out *config.Cluster, src *config.Cluster, mode Mode, gr *GroupReport) {
	if src.Access == nil {
		return
	}
	if out.Access == nil || mode == Replace {
		if reflect.DeepEqual(out.Access, src.Access) {
			gr.Unchanged++
			return
		}
		a := *src.Access
		if out.Access == nil {
			gr.Added = append(gr.Added, "access list")
		} else {
			gr.Changed = append(gr.Changed, "access list")
		}
		out.Access = &a
		return
	}
	gr.Skipped = append(gr.Skipped, "access list: this cluster has one, kept (choose replace to take the file's)")
}

func applySettings(out *config.Cluster, src *config.Cluster, mode Mode, gr *GroupReport) {
	type field struct {
		name string
		cur  any
		in   any
		set  func()
		zero bool
	}
	fs := []field{
		{"log_level", out.LogLevel, src.LogLevel, func() { out.LogLevel = src.LogLevel }, src.LogLevel == ""},
		{"probe_interval_ms", out.ProbeIntervalMS, src.ProbeIntervalMS, func() { out.ProbeIntervalMS = src.ProbeIntervalMS }, src.ProbeIntervalMS == 0},
		{"dnsrelay_cache_size", out.DNSRelayCacheSize, src.DNSRelayCacheSize, func() { out.DNSRelayCacheSize = src.DNSRelayCacheSize }, src.DNSRelayCacheSize == 0},
		{"dnsrelay_cache_max_bytes", out.DNSRelayCacheMaxBytes, src.DNSRelayCacheMaxBytes, func() { out.DNSRelayCacheMaxBytes = src.DNSRelayCacheMaxBytes }, src.DNSRelayCacheMaxBytes == 0},
		{"core_dns_query_logging", out.CoreDNSQueryLogging, src.CoreDNSQueryLogging, func() { out.CoreDNSQueryLogging = src.CoreDNSQueryLogging }, !src.CoreDNSQueryLogging},
		{"sanity_check_disabled", out.SanityCheckDisabled, src.SanityCheckDisabled, func() { out.SanityCheckDisabled = src.SanityCheckDisabled }, !src.SanityCheckDisabled},
		{"core_dns_address", out.CoreDNSAddress, src.CoreDNSAddress, func() { out.CoreDNSAddress = src.CoreDNSAddress }, src.CoreDNSAddress == ""},
		{"core_dhcp_address", out.CoreDHCPAddress, src.CoreDHCPAddress, func() { out.CoreDHCPAddress = src.CoreDHCPAddress }, src.CoreDHCPAddress == ""},
		{"backup_enabled", out.BackupEnabled, src.BackupEnabled, func() { out.BackupEnabled = src.BackupEnabled }, !src.BackupEnabled},
		{"backup_interval_hours", out.BackupIntervalHours, src.BackupIntervalHours, func() { out.BackupIntervalHours = src.BackupIntervalHours }, src.BackupIntervalHours == 0},
		{"backup_retention_count", out.BackupRetentionCount, src.BackupRetentionCount, func() { out.BackupRetentionCount = src.BackupRetentionCount }, src.BackupRetentionCount == 0},
		{"backup_replicate_to_peers", out.BackupReplicateToPeers, src.BackupReplicateToPeers, func() { out.BackupReplicateToPeers = src.BackupReplicateToPeers }, !src.BackupReplicateToPeers},
	}
	for _, f := range fs {
		if reflect.DeepEqual(f.cur, f.in) || (mode == Merge && f.zero) {
			continue
		}
		if f.name == "backup_enabled" && src.BackupEnabled && out.BackupPassword == "" {
			gr.Skipped = append(gr.Skipped, "backup_enabled: automated backups need a backup password, which a file never carries; set one, then switch backups on")
			continue
		}
		gr.Changed = append(gr.Changed, fmt.Sprintf("%s: %v → %v", f.name, f.cur, f.in))
		f.set()
	}
	if len(gr.Changed) == 0 {
		gr.Unchanged++
	}
}

func applyPlatform(out *config.Cluster, src *config.Cluster, mode Mode, gr *GroupReport) {
	if src.Platform != nil {
		switch {
		case out.Platform == nil:
			p := *src.Platform
			out.Platform = &p
			gr.Added = append(gr.Added, "platform")
		case mode == Replace && !reflect.DeepEqual(out.Platform, src.Platform):
			p := *src.Platform
			out.Platform = &p
			gr.Changed = append(gr.Changed, "platform")
		case reflect.DeepEqual(out.Platform, src.Platform):
			gr.Unchanged++
		default:
			gr.Skipped = append(gr.Skipped, "platform: this cluster has its own, kept (choose replace to take the file's)")
		}
	}
	if src.MgmtVIP != nil {
		switch {
		case out.MgmtVIP == nil:
			v := *src.MgmtVIP
			out.MgmtVIP = &v
			gr.Added = append(gr.Added, "management VIP")
		case mode == Replace && !reflect.DeepEqual(out.MgmtVIP, src.MgmtVIP):
			v := *src.MgmtVIP
			out.MgmtVIP = &v
			gr.Changed = append(gr.Changed, "management VIP")
		case reflect.DeepEqual(out.MgmtVIP, src.MgmtVIP):
			gr.Unchanged++
		default:
			gr.Skipped = append(gr.Skipped, "management VIP: this cluster has its own, kept")
		}
	}
}
