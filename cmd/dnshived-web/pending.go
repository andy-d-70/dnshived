// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"html/template"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"dnshived/internal/changeset"
	"dnshived/internal/config"
	"dnshived/internal/webauth"
)

// clusterDiffEntry is one cluster-wide field that differs between live
// config and the pending candidate.
type clusterDiffEntry struct {
	Label  string
	Detail string
}

var restartRequiringFields = map[string]bool{
	"psk":                true,
	"tls_cert / tls_key": true,
	"platform":           true,
}

// restartWarningFieldsFrom extracts which of diffs' own entries will force
// a restart on commit, in the same order diffClusterFields produced them.
func restartWarningFieldsFrom(diffs []clusterDiffEntry) []string {
	var out []string
	for _, d := range diffs {
		if restartRequiringFields[d.Label] {
			out = append(out, d.Label)
		}
	}
	return out
}

func diffClusterFields(live, candidate config.Cluster) []clusterDiffEntry {
	var out []clusterDiffEntry
	if live.PSK != candidate.PSK {
		out = append(out, clusterDiffEntry{"psk", "changed"})
	}
	if !reflect.DeepEqual(live.TrustedHosts, candidate.TrustedHosts) {
		out = append(out, clusterDiffEntry{"trusted_hosts", fmt.Sprintf("%v → %v", live.TrustedHosts, candidate.TrustedHosts)})
	}
	if live.TLSCert != candidate.TLSCert || live.TLSKey != candidate.TLSKey {
		out = append(out, clusterDiffEntry{"tls_cert / tls_key", "changed"})
	}
	if !reflect.DeepEqual(live.APITokens, candidate.APITokens) {
		out = append(out, clusterDiffEntry{"api_tokens", "changed (values hidden)"})
	}
	if live.LogLevel != candidate.LogLevel {
		out = append(out, clusterDiffEntry{"log_level", fmt.Sprintf("%q → %q", live.LogLevel, candidate.LogLevel)})
	}
	if live.HelperSocket != candidate.HelperSocket {
		out = append(out, clusterDiffEntry{"helper_socket", fmt.Sprintf("%q → %q", live.HelperSocket, candidate.HelperSocket)})
	}
	if !reflect.DeepEqual(live.Platform, candidate.Platform) {
		out = append(out, clusterDiffEntry{"platform", "changed"})
	}
	if live.ProbeIntervalMS != candidate.ProbeIntervalMS {
		out = append(out, clusterDiffEntry{"probe_interval_ms", fmt.Sprintf("%d → %d", live.ProbeIntervalMS, candidate.ProbeIntervalMS)})
	}
	if !reflect.DeepEqual(live.MgmtVIP, candidate.MgmtVIP) {
		out = append(out, clusterDiffEntry{"mgmt_vip", "changed"})
	}
	if !reflect.DeepEqual(live.DefaultDNSChecks, candidate.DefaultDNSChecks) {
		checkLine := func(c config.DNSCheck) string { return c.Name + "|" + c.Type }
		oldLines := make([]string, len(live.DefaultDNSChecks))
		for i, c := range live.DefaultDNSChecks {
			oldLines[i] = checkLine(c)
		}
		newLines := make([]string, len(candidate.DefaultDNSChecks))
		for i, c := range candidate.DefaultDNSChecks {
			newLines[i] = checkLine(c)
		}
		added, removed := diffLines(oldLines, newLines)
		for _, d := range diffLineDetails(added, removed) {
			out = append(out, clusterDiffEntry{"default_dns_checks", d})
		}
	}
	if !reflect.DeepEqual(live.GlobalDNSRecords, candidate.GlobalDNSRecords) {
		added, removed := diffDNSRecordLines(live.GlobalDNSRecords, candidate.GlobalDNSRecords)
		for _, d := range diffLineDetails(added, removed) {
			out = append(out, clusterDiffEntry{"global_dns_records", d})
		}
	}
	if !reflect.DeepEqual(live.ScopeDefaults, candidate.ScopeDefaults) {
		out = append(out, clusterDiffEntry{"scope_defaults", "changed"})
	}
	if !reflect.DeepEqual(live.Access, candidate.Access) {
		out = append(out, accessDiffEntries(live.Access, candidate.Access)...)
	}
	out = append(out, parkedDiffEntries(live.ParkedScopes, candidate.ParkedScopes)...)
	if !reflect.DeepEqual(live.DefaultDHCPOptions, candidate.DefaultDHCPOptions) {
		added, removed := diffLines(live.DefaultDHCPOptions, candidate.DefaultDHCPOptions)
		for _, d := range diffLineDetails(added, removed) {
			out = append(out, clusterDiffEntry{"default_dhcp_options", d})
		}
	}
	if live.CoreDNSAddress != candidate.CoreDNSAddress {
		out = append(out, clusterDiffEntry{"core_dns_address", fmt.Sprintf("%q → %q", live.CoreDNSAddress, candidate.CoreDNSAddress)})
	}
	if live.CoreDHCPAddress != candidate.CoreDHCPAddress {
		out = append(out, clusterDiffEntry{"core_dhcp_address", fmt.Sprintf("%q → %q", live.CoreDHCPAddress, candidate.CoreDHCPAddress)})
	}
	if live.CoreDNSQueryLogging != candidate.CoreDNSQueryLogging {
		out = append(out, clusterDiffEntry{"core_dns_query_logging", fmt.Sprintf("%v → %v", live.CoreDNSQueryLogging, candidate.CoreDNSQueryLogging)})
	}
	if live.DNSRelayCacheSize != candidate.DNSRelayCacheSize {
		out = append(out, clusterDiffEntry{"dnsrelay_cache_size", fmt.Sprintf("%d → %d", live.DNSRelayCacheSize, candidate.DNSRelayCacheSize)})
	}
	if live.DNSRelayCacheMaxBytes != candidate.DNSRelayCacheMaxBytes {
		out = append(out, clusterDiffEntry{"dnsrelay_cache_max_bytes", fmt.Sprintf("%d → %d", live.DNSRelayCacheMaxBytes, candidate.DNSRelayCacheMaxBytes)})
	}
	if live.SanityCheckDisabled != candidate.SanityCheckDisabled {
		out = append(out, clusterDiffEntry{"sanity_check_disabled", fmt.Sprintf("%v → %v", live.SanityCheckDisabled, candidate.SanityCheckDisabled)})
	}
	if !reflect.DeepEqual(live.LocalDomains, candidate.LocalDomains) {
		domainLine := func(d config.LocalDomain) string {
			forked := ""
			if d.ForkedFrom != "" {
				forked = ", forked from " + d.ForkedFrom
			}
			return fmt.Sprintf("%s (ttl=%d, %d record(s)%s)", d.Name, d.TTL, len(d.Records), forked)
		}
		oldLines := make([]string, len(live.LocalDomains))
		for i, d := range live.LocalDomains {
			oldLines[i] = domainLine(d)
		}
		newLines := make([]string, len(candidate.LocalDomains))
		for i, d := range candidate.LocalDomains {
			newLines[i] = domainLine(d)
		}
		added, removed := diffLines(oldLines, newLines)
		for _, d := range diffLineDetails(added, removed) {
			out = append(out, clusterDiffEntry{"local_domains", d})
		}
	}
	if live.BackupEnabled != candidate.BackupEnabled {
		out = append(out, clusterDiffEntry{"backup_enabled", fmt.Sprintf("%v → %v", live.BackupEnabled, candidate.BackupEnabled)})
	}
	if live.BackupIntervalHours != candidate.BackupIntervalHours {
		out = append(out, clusterDiffEntry{"backup_interval_hours", fmt.Sprintf("%d → %d", live.BackupIntervalHours, candidate.BackupIntervalHours)})
	}
	if live.BackupRetentionCount != candidate.BackupRetentionCount {
		out = append(out, clusterDiffEntry{"backup_retention_count", fmt.Sprintf("%d → %d", live.BackupRetentionCount, candidate.BackupRetentionCount)})
	}
	if live.BackupPassword != candidate.BackupPassword {
		out = append(out, clusterDiffEntry{"backup_password", "changed (value hidden)"})
	}
	if live.BackupReplicateToPeers != candidate.BackupReplicateToPeers {
		out = append(out, clusterDiffEntry{"backup_replicate_to_peers", fmt.Sprintf("%v → %v", live.BackupReplicateToPeers, candidate.BackupReplicateToPeers)})
	}
	return out
}

// scopeRightsFields are the diffClusterFields labels a scopeadmin may commit.
var scopeRightsFields = map[string]bool{
	"global_dns_records": true, "local_domains": true, "scope_defaults": true,
	"default_dhcp_options": true, "default_dns_checks": true,
}

// outsideScopeRights names the staged changes a scopeadmin may not commit;
// nil means everything staged is within its rights. Every field outside
// the scope-level ones must be identical, not only the ones the diff shows.
func outsideScopeRights(live, candidate config.Cluster) []string {
	strip := func(c config.Cluster) config.Cluster {
		c.Scopes, c.GlobalDNSRecords, c.LocalDomains, c.DefaultDHCPOptions, c.DefaultDNSChecks = nil, nil, nil, nil, nil
		c.ScopeDefaults = nil
		c.NodeID, c.Role, c.ControlAddr, c.BindAddr, c.DataDir, c.Peers = "", "", "", "", "", nil
		return c
	}
	if reflect.DeepEqual(strip(live), strip(candidate)) {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, d := range diffClusterFields(live, candidate) {
		if !scopeRightsFields[d.Label] && !seen[d.Label] {
			seen[d.Label] = true
			out = append(out, d.Label)
		}
	}
	if len(out) == 0 {
		out = []string{"a cluster-wide setting"}
	}
	return out
}

// refuseOutsideRights answers 403 when user may not commit or discard
// everything staged, naming what needs an admin.
func refuseOutsideRights(w http.ResponseWriter, cfg *WebConfig, user webauth.User, candidate config.Cluster, verb string) bool {
	if user.HasPermission(webauth.PermEditConfig) {
		return false
	}
	live, _, err := firstReachableConfig(nodesIncludingSelf(cfg))
	if err != nil {
		http.Error(w, "could not read the live config to check your rights: "+err.Error(), http.StatusBadGateway)
		return true
	}
	if fields := outsideScopeRights(live, candidate); fields != nil {
		http.Error(w, "forbidden: the pending changes include "+strings.Join(fields, ", ")+
			", which only an admin may "+verb+". Ask an admin, or discard your own scope changes one by one.", http.StatusForbidden)
		return true
	}
	return false
}

// scopeDiffEntry is one scope's own diff.
type scopeDiffEntry struct {
	Name    string
	Kind    string
	Changes []string
	// RenderedPreview previews the candidate scope's own real contribution to
	// the shared central DHCP/DNS config (via renderScopePreview).
	RenderedPreview string
	// ScopeDisabled marks a candidate scope that is disabled: its lines are
	// rendered but no relay forwards client requests to them.
	ScopeDisabled bool
}

// diffLines computes a simple added/removed line-level diff between two
// string slices, treated as unordered sets.
func diffLines(old, new []string) (added, removed []string) {
	oldSet := make(map[string]bool, len(old))
	for _, l := range old {
		oldSet[l] = true
	}
	newSet := make(map[string]bool, len(new))
	for _, l := range new {
		newSet[l] = true
	}
	for _, l := range new {
		if !oldSet[l] {
			added = append(added, l)
		}
	}
	for _, l := range old {
		if !newSet[l] {
			removed = append(removed, l)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// diffDNSRecordLines is diffLines specialized for []config.DNSRecord.
func diffDNSRecordLines(old, new []config.DNSRecord) (added, removed []string) {
	oldLines := make([]string, len(old))
	for i, r := range old {
		oldLines[i] = formatDNSRecordLine(r)
	}
	newLines := make([]string, len(new))
	for i, r := range new {
		newLines[i] = formatDNSRecordLine(r)
	}
	return diffLines(oldLines, newLines)
}

// diffLineDetails renders an added/removed line pair from diffLines/
// diffDNSRecordLines as bare "added: X"/"removed: X" detail strings, no
// field name prefix.
func diffLineDetails(added, removed []string) []string {
	var out []string
	for _, l := range removed {
		out = append(out, "removed: "+l)
	}
	for _, l := range added {
		out = append(out, "added: "+l)
	}
	return out
}

// formatFieldLineDiff is diffLineDetails with the field name folded into
// each line.
func formatFieldLineDiff(field string, added, removed []string) []string {
	var out []string
	for _, d := range diffLineDetails(added, removed) {
		out = append(out, field+": "+d)
	}
	return out
}

// diffNodeIPOverrides reports each worker whose own NodeIPOverrides entry
// actually changed, sorted by worker name for a stable order.
func diffNodeIPOverrides(old, new map[string]string) []string {
	names := make(map[string]bool, len(old)+len(new))
	for w := range old {
		names[w] = true
	}
	for w := range new {
		names[w] = true
	}
	sorted := make([]string, 0, len(names))
	for w := range names {
		sorted = append(sorted, w)
	}
	sort.Strings(sorted)

	var diffs []string
	for _, w := range sorted {
		o, n := old[w], new[w]
		if o != n {
			diffs = append(diffs, fmt.Sprintf("node_ip_overrides.%s: %q → %q", w, o, n))
		}
	}
	return diffs
}

// diffScopeFields lists every ScopeConfig field that differs between old
// and new as a human-readable line.
func diffScopeFields(old, new config.ScopeConfig) []string {
	var diffs []string
	str := func(field, oldVal, newVal string) {
		if oldVal != newVal {
			diffs = append(diffs, fmt.Sprintf("%s: %q → %q", field, oldVal, newVal))
		}
	}
	num := func(field string, oldVal, newVal int) {
		if oldVal != newVal {
			diffs = append(diffs, fmt.Sprintf("%s: %d → %d", field, oldVal, newVal))
		}
	}
	str("preferred core", old.PreferredWorker, new.PreferredWorker)
	str("parent", old.Parent, new.Parent)
	num("vlan_id", old.VLANID, new.VLANID)
	str("vip", old.VIP, new.VIP)
	str("node_ip", old.NodeIP, new.NodeIP)
	if !reflect.DeepEqual(old.NodeIPOverrides, new.NodeIPOverrides) {
		diffs = append(diffs, diffNodeIPOverrides(old.NodeIPOverrides, new.NodeIPOverrides)...)
	}
	if old.DHCPRange != new.DHCPRange {
		diffs = append(diffs, fmt.Sprintf("dhcp_range: %v → %v", old.DHCPRange, new.DHCPRange))
	}
	str("gateway", old.Gateway, new.Gateway)
	num("vrrp_id", old.VRRPID, new.VRRPID)
	num("advert_int_ms", old.AdvertIntMS, new.AdvertIntMS)
	num("vrrp_version", old.VRRPVersion, new.VRRPVersion)
	if !reflect.DeepEqual(old.DNSRecords, new.DNSRecords) {
		added, removed := diffDNSRecordLines(old.DNSRecords, new.DNSRecords)
		diffs = append(diffs, formatFieldLineDiff("dns_records", added, removed)...)
	}
	if !reflect.DeepEqual(old.DHCPOptions, new.DHCPOptions) {
		added, removed := diffLines(old.DHCPOptions, new.DHCPOptions)
		diffs = append(diffs, formatFieldLineDiff("dhcp_options", added, removed)...)
	}
	str("color", old.Color, new.Color)
	str("client_dns_server", old.ClientDNSServer, new.ClientDNSServer)
	str("dhcp_lease_time", old.DHCPLeaseTime, new.DHCPLeaseTime)
	if old.DHCPNoPing != new.DHCPNoPing {
		diffs = append(diffs, fmt.Sprintf("dhcp_no_ping: %v → %v", old.DHCPNoPing, new.DHCPNoPing))
	}
	if old.DHCPIoTDefaults != new.DHCPIoTDefaults {
		diffs = append(diffs, fmt.Sprintf("dhcp_iot_defaults: %v → %v", old.DHCPIoTDefaults, new.DHCPIoTDefaults))
	}
	optBool := func(field string, o, n *bool) {
		if (o == nil) != (n == nil) || o != nil && *o != *n {
			text := func(b *bool) string {
				if b == nil {
					return "default"
				}
				return strconv.FormatBool(*b)
			}
			diffs = append(diffs, fmt.Sprintf("%s: %s → %s", field, text(o), text(n)))
		}
	}
	optBool("dhcp_broadcast", old.DHCPBroadcast, new.DHCPBroadcast)
	optBool("dhcp_authoritative", old.DHCPAuthoritative, new.DHCPAuthoritative)
	optBool("vrrp_unicast", old.VRRPUnicast, new.VRRPUnicast)
	diffs = append(diffs, diffReservations(old.Reservations, new.Reservations)...)
	if old.ProbeDisabled != new.ProbeDisabled {
		diffs = append(diffs, fmt.Sprintf("probe_disabled: %v → %v", old.ProbeDisabled, new.ProbeDisabled))
	}
	if old.DNSMasqDisabled != new.DNSMasqDisabled {
		diffs = append(diffs, fmt.Sprintf("dnsmasq_disabled: %v → %v", old.DNSMasqDisabled, new.DNSMasqDisabled))
	}
	if old.RebalanceApprovedAt != new.RebalanceApprovedAt {
		oldText, newText := "never", "never"
		if old.RebalanceApprovedAt > 0 {
			oldText = time.Unix(old.RebalanceApprovedAt, 0).Format("2006-01-02 15:04:05")
		}
		if new.RebalanceApprovedAt > 0 {
			newText = time.Unix(new.RebalanceApprovedAt, 0).Format("2006-01-02 15:04:05")
		}
		diffs = append(diffs, fmt.Sprintf("rebalance approved: %s → %s", oldText, newText))
	}
	if !reflect.DeepEqual(old.ContentLinks, new.ContentLinks) {
		diffs = append(diffs, "template links of the scope changed")
	}
	if !reflect.DeepEqual(old.Extra, new.Extra) {
		diffs = append(diffs, "other settings of the scope changed")
	}
	return diffs
}

func reservationText(r config.Reservation) string {
	parts := []string{r.IP}
	if r.Hostname != "" {
		parts = append(parts, "name "+r.Hostname)
	}
	if len(r.Names) > 0 {
		parts = append(parts, "extra names "+strings.Join(r.Names, ", "))
	}
	if r.ClientID != "" {
		parts = append(parts, "client id "+r.ClientID)
	}
	return strings.Join(parts, ", ")
}

// diffReservations lists the reservations added, removed or changed, matched by MAC.
func diffReservations(old, new []config.Reservation) []string {
	index := func(rs []config.Reservation) map[string]config.Reservation {
		m := make(map[string]config.Reservation, len(rs))
		for _, r := range rs {
			m[strings.ToLower(r.MAC)] = r
		}
		return m
	}
	o, n := index(old), index(new)
	macs := make(map[string]bool, len(o)+len(n))
	for m := range o {
		macs[m] = true
	}
	for m := range n {
		macs[m] = true
	}
	sorted := make([]string, 0, len(macs))
	for m := range macs {
		sorted = append(sorted, m)
	}
	sort.Strings(sorted)
	var diffs []string
	for _, m := range sorted {
		or, inOld := o[m]
		nr, inNew := n[m]
		switch {
		case inOld && !inNew:
			diffs = append(diffs, fmt.Sprintf("reservation removed: %s (%s)", m, reservationText(or)))
		case !inOld && inNew:
			diffs = append(diffs, fmt.Sprintf("reservation added: %s (%s)", m, reservationText(nr)))
		case !reflect.DeepEqual(or, nr):
			diffs = append(diffs, fmt.Sprintf("reservation changed: %s (%s → %s)", m, reservationText(or), reservationText(nr)))
		}
	}
	return diffs
}

// diffScopes is the scope-level half of the pending-changes diff —
// added/removed/changed, sorted by name for a stable, scannable order.
func diffScopes(live, candidate map[string]config.ScopeConfig, candGlobalDNSRecords []config.DNSRecord, candDefaultDHCPOptions []string) []scopeDiffEntry {
	names := make(map[string]bool, len(live)+len(candidate))
	for n := range live {
		names[n] = true
	}
	for n := range candidate {
		names[n] = true
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)

	preview := func(name string, sc config.ScopeConfig) string {
		return renderScopePreview(name, sc, candDefaultDHCPOptions)
	}

	var entries []scopeDiffEntry
	for _, n := range sorted {
		liveSC, inLive := live[n]
		candSC, inCand := candidate[n]
		switch {
		case inLive && !inCand:
			entries = append(entries, scopeDiffEntry{Name: n, Kind: "removed"})
		case !inLive && inCand:
			entries = append(entries, scopeDiffEntry{Name: n, Kind: "added", RenderedPreview: preview(n, candSC), ScopeDisabled: candSC.DNSMasqDisabled})
		default:
			if changes := diffScopeFields(liveSC, candSC); len(changes) > 0 {
				entries = append(entries, scopeDiffEntry{Name: n, Kind: "changed", Changes: changes, RenderedPreview: preview(n, candSC), ScopeDisabled: candSC.DNSMasqDisabled})
			}
		}
	}
	return entries
}

// checkPendingCoherence adds Overview's own coherence findings for a
// stale/forgotten pending candidate.
func checkPendingCoherence(cfg *WebConfig) []string {
	live, _, err := firstReachableConfig(nodesIncludingSelf(cfg))
	if err != nil {
		return nil
	}
	candidate, exists, _, err := firstReachableCandidate(nodesIncludingSelf(cfg))
	if err != nil || !exists {
		return nil
	}
	var warnings []string
	for _, d := range diffScopes(live.Scopes, candidate.Scopes, candidate.GlobalDNSRecords, candidate.DefaultDHCPOptions) {
		switch d.Kind {
		case "added":
			warnings = append(warnings, fmt.Sprintf("PENDING: scope %q exists only in the uncommitted candidate, not live — see /pending to commit or discard", d.Name))
		case "removed":
			warnings = append(warnings, fmt.Sprintf("PENDING: scope %q is still live but staged for removal in the uncommitted candidate — see /pending to commit or discard", d.Name))
		case "changed":
			warnings = append(warnings, fmt.Sprintf("PENDING: scope %q has uncommitted changes staged — see /pending to commit or discard", d.Name))
		}
	}
	if len(diffClusterFields(live, candidate)) > 0 {
		warnings = append(warnings, "PENDING: cluster-wide settings have uncommitted changes staged — see /pending to commit or discard")
	}
	return warnings
}

// pendingPageData feeds pendingTmpl.
type pendingPageData struct {
	Error        string
	HasCandidate bool
	// HasChanges is the real gate for showing Commit/Discard and the diff
	// tables — NOT HasCandidate alone.
	HasChanges           bool
	SourceNode           string
	ClusterDiffs         []clusterDiffEntry
	RestartWarningFields []string
	ScopeDiffs           []scopeDiffEntry
	Authors              pendingAuthors
	// NodeOp is the one staged node action (onboard-as-probe/replace/
	// offboard), if any.
	NodeOp *pendingNodeOp
}

// Count is the number of staged items: the node action, each cluster-wide
// setting line and each changed scope.
func (d pendingPageData) Count() int {
	n := len(d.ClusterDiffs) + len(d.ScopeDiffs)
	if d.NodeOp != nil {
		n++
	}
	return n
}

var pendingTmpl = template.Must(template.New("pending").Parse(`<!doctype html>
<title>dnshived-web — pending changes</title>
` + styleHTML + logModalScriptHTML + `
<script>
// Narration for the staged node action's console popup
// (submitFormAsConsole); the steps run at Commit time.
function submitNodeOpCommit(form, title, steps){
  return submitFormAsConsole(form, title, steps);
}
</script>
` + navHTML + `
<div class="pagehead"><h1>Pending changes{{if .Count}} <span class="count-badge">{{.Count}}</span>{{end}}</h1></div>

{{if .Error}}<p class="crit">{{.Error}}</p>{{else}}
<p class="dim" title="Every save on the config, scope, DNS and DHCP editors stages a change here first (a candidate config); nothing reaches the running cluster until you commit. Onboard, replace and offboard actions on Cluster settings stage here as a separate Node action: a one-shot action with side effects on a whole other node, not a field diff, so it has its own Commit and Discard.">Every change you save is staged here first; nothing reaches the running cluster until you commit.</p>

{{if .NodeOp}}
<h2>Node action</h2>
<section class="card pend-card">
<p style="margin:0"><span class="chip warn">staged</span> {{.NodeOp.Describe}} <span class="dim">· by {{.NodeOp.StagedBy}} at {{.NodeOp.StagedAt.Format "15:04:05"}}</span></p>
</section>
{{if .NodeOp.LeavesZeroCoreNodes}}
<p class="crit">⚠ This is the LAST remaining core node. Committing this will PERMANENTLY WIPE the entire cluster — every credential, every scope, gone, with nothing left to recover from. Download a recent backup from <a href="/backup">Config management</a> before you commit this.</p>
<form method="post" action="/pending/nodeop/commit" style="display:inline" onsubmit="return document.getElementById('confirm_wipe').checked && confirm('This is the LAST core node — committing WIPES THE ENTIRE CLUSTER PERMANENTLY. Are you certain?') && submitNodeOpCommit(this, {{.NodeOp.DescribeJSON}}, {{.NodeOp.StepsJSON}})">
<label style="display:block;margin:.5rem 0"><input type="checkbox" id="confirm_wipe" name="confirm_wipe" required> I have downloaded a recent backup and understand this will permanently wipe the entire cluster.</label>
{{if eq .NodeOp.Kind "offboard"}}<label style="display:block;margin:.5rem 0"><input type="checkbox" name="confirm_force"> This node is unreachable — force-remove it without asking it to decommission itself. It will NOT be wiped; if it ever reconnects to a network this cluster can see, it may still present real credentials for a cluster it's no longer part of.</label>{{end}}
<button type="submit" class="btn-danger">Commit this node action</button>
</form>
{{else}}
<form method="post" action="/pending/nodeop/commit" style="display:inline" onsubmit="return confirm('Commit this node action now? This is real and disruptive — it will actually run.') && submitNodeOpCommit(this, {{.NodeOp.DescribeJSON}}, {{.NodeOp.StepsJSON}})">
{{if and (eq .NodeOp.Kind "replace") (ne .NodeOp.Role "probe")}}<label style="display:block;margin:.5rem 0" title="Before onboarding, the cluster listens on its trunks while the new node broadcasts on each of its interfaces. If a trunk hears nothing, the commit is refused unless this is checked; the node then keeps the cluster's interface name for that trunk."><input type="checkbox" name="confirm_undetected"> Onboard anyway, even if the interface check cannot detect every trunk.</label>{{end}}
{{if eq .NodeOp.Kind "offboard"}}<label style="display:block;margin:.5rem 0"><input type="checkbox" name="confirm_force"> This node is unreachable — force-remove it without asking it to decommission itself. It will NOT be wiped; if it ever reconnects to a network this cluster can see, it may still present real credentials for a cluster it's no longer part of.</label>{{end}}
<button type="submit" class="btn-success">Commit this node action</button>
</form>
{{end}}
<form method="post" action="/pending/nodeop/discard" style="display:inline" onsubmit="return confirm('Discard the staged node action? Nothing has happened yet — this just cancels it.')">
<button type="submit" class="btn-danger">Discard this node action</button>
</form>
<dialog id="log-modal">
<h3 id="log-modal-title" style="margin-top:0"></h3>
<div class="table-wrap"><pre id="log-modal-body" style="margin:0"></pre></div>
<form method="dialog"><button>Close</button></form>
</dialog>
{{end}}

{{if not .HasChanges}}
{{if not .NodeOp}}<p class="ok">No pending changes.</p>{{end}}
{{if .HasCandidate}}<p class="dim">(a staged save exists but matches the running config exactly — nothing to commit; it'll be reused as the starting point the next time you edit something)</p>{{end}}
{{else}}
<div class="banner warn actionbar">
<strong>Nothing is applied until you commit.</strong><span class="banner-detail">Snapshot from {{.SourceNode}}</span><span class="grow"></span>
{{if .Authors.Show}}
{{if .Authors.MineCount}}<form method="post" action="/pending/discard" onsubmit="return confirm('Discard your own {{.Authors.MineCount}} pending change(s)? Changes made by others stay.')" style="display:inline"><input type="hidden" name="scope" value="mine"><button type="submit" class="btn-danger">Discard my changes</button></form>{{end}}
<form method="get" action="/pending/confirm" style="display:inline"><input type="hidden" name="action" value="discard"><button type="submit" class="btn-danger" title="Also throws away the changes other admins staged. A warning comes first.">Discard everyone's…</button></form>
{{if .Authors.MineCount}}<form method="post" action="/pending/commit" onsubmit="return confirm('Commit your own {{.Authors.MineCount}} pending change(s) to every configured node? Changes made by others stay staged.')" style="display:inline"><input type="hidden" name="scope" value="mine"><button type="submit" class="btn-success">Commit my {{.Authors.MineCount}} change(s)</button></form>{{end}}
<form method="get" action="/pending/confirm" style="display:inline"><input type="hidden" name="action" value="commit"><button type="submit" class="btn-danger" title="Also makes the changes other admins staged go live. A warning comes first.">Commit everyone's…</button></form>
{{else}}
<form method="post" action="/pending/discard" onsubmit="return confirm('This will discard EVERY pending change on every node. Continue?')" style="display:inline">
<button type="submit" class="btn-danger">Discard all</button>
</form>
<form method="post" action="/pending/commit" onsubmit="return confirm('This will push every pending change to every configured node and restart the daemon where needed. Continue?')" style="display:inline">
<button type="submit" class="btn-success">Commit all {{.Count}} change(s)</button>
</form>
{{end}}
</div>
{{if .Authors.Show}}
<h2>Who changed what</h2>
<section class="card pend-card">
{{range .Authors.Groups}}<p style="margin:.2rem 0"><b>{{if .Mine}}You{{else}}{{.Name}}{{end}}</b> — {{.Count}} change(s){{if not .Mine}} <span class="chip warn">not committed with "Commit my changes"</span>{{end}}</p>
<ul class="card-list">{{range .Lines}}<li>{{.}}</li>{{end}}{{if .More}}<li class="dim">and {{.More}} more</li>{{end}}</ul>
{{end}}
</section>
{{end}}

{{if .RestartWarningFields}}
<p class="warn">⚙ This change includes {{range $i, $f := .RestartWarningFields}}{{if $i}}, {{end}}<code>{{$f}}</code>{{end}} — committing it will restart the daemon on every node where that field changed. Each node is restarted one at a time, waiting for it to fully recover before moving to the next — expect a brief interruption on that node specifically, not the whole cluster at once.</p>
{{end}}

{{if .ClusterDiffs}}
<h2>Cluster-wide settings</h2>
<section class="card pend-card"><ul class="card-list">
{{range .ClusterDiffs}}<li><b>{{.Label}}</b>: {{.Detail}}</li>{{end}}
</ul></section>
<p class="dim">Edit on <a href="/config">cluster settings</a> or <a href="/config/dhcp">DHCP</a> or <a href="/config/dns">DNS</a>.</p>
{{end}}

{{if .ScopeDiffs}}
<h2>Scopes</h2>
{{range .ScopeDiffs}}
<section class="card pend-card">
<div class="pend-head"><b><a href="/scopes/{{.Name}}">{{.Name}}</a></b><span class="grow"></span><form method="post" action="/pending/discard/scopes/{{.Name}}" onsubmit="return confirm('Discard the pending change for {{.Name}} only? Every other pending change stays.')" style="display:inline"><button type="submit" class="btn-danger btn-sm">Discard</button></form></div>
<div class="{{if eq .Kind "removed"}}crit{{else if eq .Kind "added"}}ok{{else}}warn{{end}} pend-body">
  {{if eq .Kind "added"}}new scope
  {{else if eq .Kind "removed"}}removed
  {{else}}<ul>{{range .Changes}}<li>{{.}}</li>{{end}}</ul>
  {{end}}
  {{if .ScopeDisabled}}<div class="warn" title="a disabled scope keeps its VLAN interface and node addresses but releases its VIP and VRRP, and no node relays DHCP or DNS for it">this scope will be DISABLED: DHCP and DNS stop on every node, probing off</div>{{end}}
  {{if .RenderedPreview}}<details><summary>{{if .ScopeDisabled}}rendered but not relayed while disabled (no client request reaches these lines){{else}}what will actually be rendered (this scope's own contribution to the shared central DHCP/DNS config){{end}}</summary><pre style="margin:.3rem 0;padding:.5rem;background:var(--panel);border:1px solid var(--border);overflow-x:auto">{{.RenderedPreview}}</pre></details>{{end}}
</div>
</section>
{{end}}
{{end}}
{{end}}
{{end}}
`))

func handlePending(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		live, _, err := firstReachableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			renderTemplate(w, pendingTmpl, pendingPageData{Error: "could not read live config from any node: " + err.Error()}, "pending")
			return
		}
		cr, node, err := firstReachableCandidateResponse(nodesIncludingSelf(cfg))
		if err != nil {
			renderTemplate(w, pendingTmpl, pendingPageData{Error: "could not read candidate from any node: " + err.Error()}, "pending")
			return
		}
		candidate, exists := cr.Candidate, cr.Exists
		data := pendingPageData{HasCandidate: exists, SourceNode: node.Name, NodeOp: currentNodeOp()}
		if exists {
			if v, verr := newPendingView(live, cr); verr == nil {
				user, _ := userFromContext(r)
				data.Authors = v.summary(user.Name)
			}
			data.ClusterDiffs = diffClusterFields(live, candidate)
			data.RestartWarningFields = restartWarningFieldsFrom(data.ClusterDiffs)
			data.ScopeDiffs = diffScopes(live.Scopes, candidate.Scopes, candidate.GlobalDNSRecords, candidate.DefaultDHCPOptions)
			data.HasChanges = len(data.ClusterDiffs) > 0 || len(data.ScopeDiffs) > 0
		}
		renderTemplate(w, pendingTmpl, data, "pending")
	}
}

// commitCluster pushes c to every node as the new live configuration.
func commitCluster(w http.ResponseWriter, r *http.Request, cfgPath string, ref *configRef, c config.Cluster, base int64, user webauth.User, afterOK func()) {
	cfg := ref.Load()
	payload := clusterPushPayloadFrom(c)
	payload.Scopes = c.Scopes
	payload.ConfigBaseRevision = &base

	backLink, backText := returnTarget(r)
	pushConfigAndRenderResult(w, cfg, payload, user, backLink, withOverviewLink(backLink, backText), func() {
		afterOK()
		if newHost := vipHostOf(payload.MgmtVIP); newHost != cfg.VIPHost {
			propagateVIPHost(cfgPath, ref, newHost)
		}
	})
}

// handlePendingCommit (POST /pending/commit) applies the candidate to the
// live cluster: only the committing admin's own changes with scope=mine,
// otherwise everything, which needs the typed confirmation when other admins
// have changes staged.
func handlePendingCommit(cfgPath string, ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		nodes := nodesIncludingSelf(cfg)
		cr, _, err := firstReachableCandidateResponse(nodes)
		if err != nil {
			http.Error(w, "could not read candidate: "+err.Error(), http.StatusBadGateway)
			return
		}
		if !cr.Exists {
			http.Redirect(w, r, "/pending", http.StatusSeeOther)
			return
		}
		candidate := cr.Candidate
		user, _ := userFromContext(r)

		live, _, err := firstReachableConfig(nodes)
		if err != nil {
			http.Error(w, "could not read live config: "+err.Error(), http.StatusBadGateway)
			return
		}
		view, err := newPendingView(live, cr)
		if err != nil {
			http.Error(w, "compare pending changes: "+err.Error(), http.StatusInternalServerError)
			return
		}
		authors := view.summary(user.Name)

		if r.FormValue("scope") == "mine" {
			commitMine(w, r, cfg, cfgPath, ref, view, user)
			return
		}
		if authors.OtherCount > 0 && r.FormValue("confirm") != confirmCommitAll {
			http.Redirect(w, r, "/pending/confirm?action=commit", http.StatusSeeOther)
			return
		}
		if refuseOutsideRights(w, cfg, user, candidate, "commit") {
			return
		}
		commitCluster(w, r, cfgPath, ref, candidate, candidate.ConfigRevision, user, func() {
			discardCandidateEverywhere(cfg)
			if authors.Supported {
				auditPending(cfg, user.Name, "pending.commit", "committed all pending changes: "+authors.describe())
			}
		})
	}
}

func commitMine(w http.ResponseWriter, r *http.Request, cfg *WebConfig, cfgPath string, ref *configRef, view *pendingView, user webauth.User) {
	if !view.supported {
		http.Error(w, "this cluster's daemons do not record who changed what; commit all changes instead", http.StatusConflict)
		return
	}
	mine, n, err := view.onlyMine(user.Name)
	if err != nil {
		http.Error(w, "build your changes: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if n == 0 {
		http.Error(w, "none of the pending changes are yours", http.StatusConflict)
		return
	}
	if res := mine.ValidateExtended(); !res.OK() {
		http.Error(w, "your changes cannot be committed without changes made by others, commit all changes or discard the difference: "+strings.Join(res.Errors, "; "), http.StatusConflict)
		return
	}
	if refuseOutsideRights(w, cfg, user, mine, "commit") {
		return
	}
	authors := view.summary(user.Name)
	commitCluster(w, r, cfgPath, ref, mine, view.cand.ConfigRevision, user, func() {
		keepRemainder(cfg)
		auditPending(cfg, user.Name, "pending.commit", fmt.Sprintf("committed own %d pending change(s); %d change(s) of others stay staged", n, authors.OtherCount))
	})
}

// handlePendingDiscard (POST /pending/discard) reverts the admin's own
// pending changes with scope=mine, otherwise every pending change on every
// node, which needs the typed confirmation when other admins have changes
// staged.
func handlePendingDiscard(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		user, _ := userFromContext(r)
		nodes := nodesIncludingSelf(cfg)
		cr, _, cerr := firstReachableCandidateResponse(nodes)
		if cerr != nil {
			http.Error(w, "could not read candidate: "+cerr.Error(), http.StatusBadGateway)
			return
		}
		if !cr.Exists {
			http.Redirect(w, r, "/pending", http.StatusSeeOther)
			return
		}
		if !user.HasPermission(webauth.PermEditConfig) && refuseOutsideRights(w, cfg, user, cr.Candidate, "discard") {
			return
		}
		live, _, err := firstReachableConfig(nodes)
		if err != nil {
			http.Error(w, "could not read live config: "+err.Error(), http.StatusBadGateway)
			return
		}
		view, err := newPendingView(live, cr)
		if err != nil {
			http.Error(w, "compare pending changes: "+err.Error(), http.StatusInternalServerError)
			return
		}
		authors := view.summary(user.Name)

		if r.FormValue("scope") == "mine" {
			discardMine(w, r, cfg, view, user)
			return
		}
		if authors.OtherCount > 0 && r.FormValue("confirm") != confirmDiscardAll {
			http.Redirect(w, r, "/pending/confirm?action=discard", http.StatusSeeOther)
			return
		}
		var errs []string
		for _, n := range nodes {
			if err := discardCandidate(n); err != nil {
				errs = append(errs, n.Name+": "+err.Error())
				continue
			}
			pushAudit(n, user.Name, "candidate.discard", "discarded all pending changes")
		}
		if len(errs) > 0 {
			http.Error(w, "discard failed on: "+strings.Join(errs, "; "), http.StatusBadGateway)
			return
		}
		http.Redirect(w, r, "/pending", http.StatusSeeOther)
	}
}

func discardMine(w http.ResponseWriter, r *http.Request, cfg *WebConfig, view *pendingView, user webauth.User) {
	if !view.supported {
		http.Error(w, "this cluster's daemons do not record who changed what; discard all changes instead", http.StatusConflict)
		return
	}
	rest, n, err := view.withoutMine(user.Name)
	if err != nil {
		http.Error(w, "build the remaining changes: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if n == 0 {
		http.Error(w, "none of the pending changes are yours", http.StatusConflict)
		return
	}
	restTree, _ := changeset.Tree(rest)
	if len(changeset.Changes(view.liveTree, restTree)) == 0 {
		discardCandidateEverywhere(cfg)
	} else if err := restageCandidate(cfg, rest); err != nil {
		http.Error(w, "re-stage the remaining changes: "+err.Error(), http.StatusBadGateway)
		return
	}
	auditPending(cfg, user.Name, "candidate.discard", fmt.Sprintf("discarded own %d pending change(s)", n))
	http.Redirect(w, r, "/pending", http.StatusSeeOther)
}

// handlePendingNodeOpCommit (POST /pending/nodeop/commit) executes the one
// staged node action (onboard-as-probe/replace/offboard).
func handlePendingNodeOpCommit(cfgPath string, ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		op := currentNodeOp()
		if op == nil {
			http.Redirect(w, r, "/pending", http.StatusSeeOther)
			return
		}
		user, _ := userFromContext(r)
		var msg string
		var err error
		switch {
		case op.Kind == nodeOpReplace && op.Role == probeRoleName:
			msg, err = executeReplaceProbe(cfgPath, ref, user.Name, *op)
		case op.Kind == nodeOpReplace:
			msg, err = executeReplaceNode(cfgPath, ref, user.Name, *op, r.FormValue("confirm_undetected") == "on")
		case op.Kind == nodeOpOffboard:
			msg, err = executeOffboardNode(ref, cfgPath, user.Name, *op, r.FormValue("confirm_wipe") == "on", r.FormValue("confirm_force") == "on")
		default:
			err = fmt.Errorf("unknown staged node action %q", op.Kind)
		}
		clearNodeOp()

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if err != nil {
			fmt.Fprintf(w, "FAILED: %s\n\n%s\n", op.Describe(), err.Error())
			return
		}
		fmt.Fprintf(w, "%s\n\n%s", op.Describe(), msg)
	}
}

// handlePendingNodeOpDiscard (POST /pending/nodeop/discard) drops the
// staged node action without ever contacting anything.
func handlePendingNodeOpDiscard() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clearNodeOp()
		http.Redirect(w, r, "/pending", http.StatusSeeOther)
	}
}

// handlePendingDiscardScope (POST /pending/discard/scopes/{scope}) reverts
// just one scope's pending edit.
func handlePendingDiscardScope(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		scope := r.PathValue("scope")
		user, _ := userFromContext(r)
		var errs []string
		for _, n := range nodesIncludingSelf(cfg) {
			if err := discardCandidateScope(n, scope); err != nil {
				errs = append(errs, n.Name+": "+err.Error())
				continue
			}
			pushAudit(n, user.Name, "candidate.discard", "discarded pending change for scope "+scope)
		}
		if len(errs) > 0 {
			http.Error(w, "revert failed on: "+strings.Join(errs, "; "), http.StatusBadGateway)
			return
		}
		http.Redirect(w, r, "/pending", http.StatusSeeOther)
	}
}

func parkedDiffEntries(live, candidate map[string]config.ScopeConfig) []clusterDiffEntry {
	var out []clusterDiffEntry
	for _, name := range sortedScopeKeys(candidate) {
		old, had := live[name]
		switch {
		case !had:
			out = append(out, clusterDiffEntry{"parked_scopes", "+ " + name + " (parked)"})
		case !reflect.DeepEqual(old, candidate[name]):
			out = append(out, clusterDiffEntry{"parked_scopes", "~ " + name + " (changed)"})
		}
	}
	for _, name := range sortedScopeKeys(live) {
		if _, kept := candidate[name]; !kept {
			out = append(out, clusterDiffEntry{"parked_scopes", "- " + name + " (no longer parked)"})
		}
	}
	return out
}

func sortedScopeKeys(m map[string]config.ScopeConfig) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
