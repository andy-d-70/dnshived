// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"dnshived/internal/config"
)

// isCoreRole reports whether role is one of the 3 real core roles.
func isCoreRole(role string) bool {
	switch role {
	case config.RoleCore1, config.RoleCore2, config.RoleCore3:
		return true
	default:
		return false
	}
}

// statusRow is one node's status as rendered on the page.
type statusRow struct {
	Node       NodeConfig
	Status     nodeStatus
	System     systemInfo
	HasSystem  bool
	FetchError string
	// ViaFallback: this node's mgmt path is down but its status was fetched
	// over its scope-VLAN fallback address (tunnel).
	ViaFallback  bool
	Icon         string
	Class        string
	Info         string
	SysStr       string
	Nickname     string
	RoleClass    string
	FetchedAt    time.Time
	HoldsMgmtVIP bool
}

type nodeSnapshot struct {
	Status    nodeStatus
	System    systemInfo
	HasSystem bool
}

func fetchNodeSnapshot(n NodeConfig) (nodeSnapshot, error) {
	var snap nodeSnapshot
	s, err := fetchStatus(n)
	if err != nil {
		return snap, err
	}
	snap.Status = s
	if sys, sysErr := fetchSystem(n); sysErr == nil {
		snap.System = sys
		snap.HasSystem = true
	}
	return snap, nil
}

func fetchNodeSnapshotCached(n NodeConfig) (nodeSnapshot, error) {
	snap, err := fetchNodeSnapshot(n)
	if err == nil {
		reachability.observePeerReport(snap.Status.PeersVisible, snap.Status.PeersUnreachable, snap.Status.FallbackPeers)
	}
	return snap, err
}

// fetchAllStatus is Overview/Scopes/Probes' shared "give me every
// configured node's current status" call.
func fetchAllStatus(cfg *WebConfig, nodes []NodeConfig) []statusRow {
	if rows, ok := fetchAllStatusViaSnapshot(cfg, nodes); ok {
		return rows
	}
	return fetchAllStatusLegacy(nodes)
}

func fetchAllStatusViaSnapshot(cfg *WebConfig, nodes []NodeConfig) ([]statusRow, bool) {
	byAddr, _, ok := resolveClusterSnapshot(cfg, nodes)
	if !ok {
		return nil, false
	}

	fetchedAt := time.Now()
	rows := make([]statusRow, len(nodes))
	for i, n := range nodes {
		sn := byAddr[n.Addr]
		row := statusRow{Node: n, FetchedAt: fetchedAt}
		if sn.Error != "" {
			row.FetchError = sn.Error
			if countsAsDeadMsg(sn.Error) {
				reachability.markDead(n.Addr)
			}
			rows[i] = row
			continue
		}
		var st nodeStatus
		if err := json.Unmarshal(sn.Status, &st); err != nil {
			row.FetchError = err.Error()
			rows[i] = row
			continue
		}
		row.Status = st
		if sn.Via == "fallback" {
			// Fetched over the fallback address: says nothing about the
			// mgmt path, which stays believed-down.
			row.ViaFallback = true
		} else {
			reachability.markAlive(n.Addr)
		}
		reachability.observePeerReport(st.PeersVisible, st.PeersUnreachable, st.FallbackPeers)
		if len(sn.System) > 0 {
			var si systemInfo
			if json.Unmarshal(sn.System, &si) == nil {
				row.System = si
				row.HasSystem = true
			}
		}
		rows[i] = row
	}
	computeRowDisplay(rows)
	return rows, true
}

// fetchAllStatusLegacy polls every configured node concurrently.
func fetchAllStatusLegacy(nodes []NodeConfig) []statusRow {
	results := fetchAllNodes(nodes, fetchNodeSnapshotCached)
	rows := make([]statusRow, len(results))
	for i, res := range results {
		row := statusRow{
			Node:      res.Node,
			Status:    res.Value.Status,
			System:    res.Value.System,
			HasSystem: res.Value.HasSystem,
			FetchedAt: res.FetchedAt,
		}
		if res.Err != nil {
			row.FetchError = res.Err.Error()
		} else {
			row.ViaFallback = reachability.viaFallback(res.Node.Addr)
		}
		rows[i] = row
	}
	computeRowDisplay(rows)
	return rows
}

// computeRowDisplay fills in each row's precomputed display fields.
func computeRowDisplay(rows []statusRow) {
	disabled := disabledScopeSet(rows)
	for i := range rows {
		row := &rows[i]
		row.Nickname = row.Node.displayName()
		if row.FetchError != "" {
			row.Icon = "✖" // ✖
			row.Class = "crit"
			continue
		}
		if row.Status.State == "STABLE" {
			row.Icon = "✔" // ✔
			row.Class = "ok"
		} else {
			row.Icon = "⚠" // ⚠
			row.Class = "warn"
		}
		row.RoleClass = roleClass(row.Status.Role)
		active, off := 0, 0
		for _, sc := range row.Status.Serving {
			if disabled[sc] {
				off++
			} else {
				active++
			}
		}
		row.Info = fmt.Sprintf("%d scope(s)", active)
		if off > 0 {
			row.Info += fmt.Sprintf(", %d disabled", off)
		}
		if row.ViaFallback {
			row.Info += " — via fallback path (mgmt down)"
			if row.Class == "ok" {
				row.Class = "warn"
			}
		}
		if isCoreRole(row.Status.Role) {
			known := len(row.Status.PeersVisible) + len(row.Status.PeersUnreachable)
			if known < 2 {
				row.Info += fmt.Sprintf(" — ⚠ knows only %d/2 other core peer(s)", known)
			}
			row.HoldsMgmtVIP = row.Status.HoldsMgmtVIP
		}
		if row.HasSystem {
			row.SysStr = fmt.Sprintf("load %.2f  mem %d%%", row.System.LoadAvg1, row.System.MemPct)
			if row.System.OS != "" {
				row.SysStr += "  " + row.System.OS
			}
		}
	}
}

// scopesMismatch compares scopes_hash across every real core role.
func scopesMismatch(rows []statusRow) bool {
	hashes := make(map[string]bool)
	for _, row := range rows {
		if row.FetchError == "" && row.Status.ScopesHash != "" && isCoreRole(row.Status.Role) {
			hashes[row.Status.ScopesHash] = true
		}
	}
	return len(hashes) > 1
}

func configHashMismatch(rows []statusRow) bool {
	hashes := make(map[string]bool)
	for _, row := range rows {
		if row.FetchError == "" && row.Status.ConfigHash != "" {
			hashes[row.Status.ConfigHash] = true
		}
	}
	return len(hashes) > 1
}

// settlingTimeout bounds how long bannerText will call the cluster GETTING
// THERE before treating it as actually stuck.
const settlingTimeout = 90 * time.Second

// settlingSince tracks when the cluster first entered "STABLE, but not
// every configured scope is serving yet".
var (
	settlingMu    sync.Mutex
	settlingSince time.Time
)

// bannerText picks the top banner's text and CSS class — ported from
// dnshived-top's identical function (ANSI colors replaced with CSS
// classes).
func bannerText(stable, reachable, total, configuredCount, servingCount int, settlingElapsed time.Duration) (text, class string) {
	settlingScopes := configuredCount > 0 && servingCount < configuredCount

	switch {
	case stable == total && settlingScopes && settlingElapsed > settlingTimeout:
		return fmt.Sprintf("NOT CONVERGING — stable but scopes still not serving after %ds", int(settlingElapsed.Seconds())), "crit"
	case stable == total && settlingScopes:
		return "GETTING THERE — cluster stable, scopes still starting", "warn"
	case stable == total:
		return "PRODUCTION ACTIVE", "ok"
	case reachable < total:
		return "NODE DOWN", "crit"
	default:
		return "DEGRADED", "warn"
	}
}

// roleByNodeID builds a NodeID -> Role lookup from the current row
// snapshot.
func roleByNodeID(rows []statusRow) map[string]string {
	m := make(map[string]string, len(rows))
	for _, row := range rows {
		if row.FetchError == "" {
			m[row.Status.NodeID] = row.Status.Role
		}
	}
	return m
}

// fetchArbiterTokens finds a reachable core node's own token map and
// fetches it.
func fetchArbiterTokens(cfg *WebConfig, rows []statusRow) map[string]tokenInfo {
	if tokens, ok := fetchArbiterTokensViaSnapshot(cfg); ok {
		return tokens
	}
	return fetchArbiterTokensLegacy(rows)
}

// fetchArbiterTokensViaSnapshot decodes the already-shipped GET
// /api/v1/cluster/snapshot's own "tokens" field.
func fetchArbiterTokensViaSnapshot(cfg *WebConfig) (map[string]tokenInfo, bool) {
	_, snap, ok := resolveClusterSnapshot(cfg, nil)
	if !ok || len(snap.Tokens) == 0 {
		return nil, false
	}
	var tokens map[string]tokenInfo
	if err := json.Unmarshal(snap.Tokens, &tokens); err != nil {
		return nil, false
	}
	return tokens, true
}

// fetchArbiterTokensLegacy is fetchArbiterTokens's original per-row dial,
// used whenever the snapshot fast path isn't available.
func fetchArbiterTokensLegacy(rows []statusRow) map[string]tokenInfo {
	var arbiterRow, fallbackRow *statusRow
	for i := range rows {
		row := &rows[i]
		if row.FetchError != "" {
			continue
		}
		if row.Status.Role == config.RoleCore3 {
			arbiterRow = row
			continue
		}
		if fallbackRow == nil {
			fallbackRow = row
		}
	}
	for _, row := range []*statusRow{arbiterRow, fallbackRow} {
		if row == nil {
			continue
		}
		if t, err := fetchTokenStatus(row.Node); err == nil {
			return t
		}
	}
	return map[string]tokenInfo{}
}

// clusterPathRow is one rendered row of the "Cluster paths" table.
type clusterPathRow struct {
	From      string // observing node's own display nickname
	To        string // target role (core-2, core-3, ...)
	Trunk     string // physical parent interface (ens19, ...)
	Reachable bool
	Class     string // "ok" or "crit", matching every other status cell
	Text      string // "reachable" / "unreachable"
	LastError string
	Score     int
	// BarColor is template.CSS, not a plain string.
	BarColor template.CSS
	BarWidth int
	// VLAN rows (scope beacons): the trunk they run on and their VLAN, so the
	// Cluster paths dialog can list them under that trunk.
	IsVLAN bool
	Parent string
	VLANID int
}

// clusterPathGroup is one trunk row of the Cluster paths dialog with the
// VLAN paths running over it (collapsed by default, expanded by click).
type clusterPathGroup struct {
	ID          string
	Row         clusterPathRow
	VLANs       []clusterPathRow
	VLANsDown   int
	VLANSummary string
}

// PathGroups is what the Cluster paths dialog renders: PathRows grouped by
// trunk (value receiver, callable from the template).
func (d overviewData) PathGroups() []clusterPathGroup { return clusterPathGroups(d.PathRows) }

func clusterPathGroups(flat []clusterPathRow) []clusterPathGroup {
	key := func(from, to, trunk string) string { return from + "|" + to + "|" + trunk }
	var groups []clusterPathGroup
	index := map[string]int{}
	for _, r := range flat {
		if r.IsVLAN {
			continue
		}
		index[key(r.From, r.To, r.Trunk)] = len(groups)
		groups = append(groups, clusterPathGroup{Row: r})
	}
	for _, r := range flat {
		if !r.IsVLAN {
			continue
		}
		if i, ok := index[key(r.From, r.To, r.Parent)]; ok && r.Parent != "" {
			groups[i].VLANs = append(groups[i].VLANs, r)
			if !r.Reachable {
				groups[i].VLANsDown++
			}
			continue
		}
		groups = append(groups, clusterPathGroup{Row: r})
	}
	for i := range groups {
		groups[i].ID = fmt.Sprintf("pg%d", i)
		if n := len(groups[i].VLANs); n > 0 {
			noun := "VLANs"
			if n == 1 {
				noun = "VLAN"
			}
			if groups[i].VLANsDown > 0 {
				groups[i].VLANSummary = fmt.Sprintf("%d/%d %s unreachable", groups[i].VLANsDown, n, noun)
			} else {
				groups[i].VLANSummary = fmt.Sprintf("%d %s", n, noun)
			}
		}
	}
	return groups
}

// trustBarColor maps a 0-100 trust score to a smooth green->red HSL color.
func trustBarColor(score int) template.CSS {
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	hue := score * 120 / 100
	return template.CSS(fmt.Sprintf("hsl(%d,70%%,42%%)", hue))
}

// clusterPathRows builds the "Cluster paths" table from every reachable
// row's own self-reported Status.Paths.
func clusterPathRows(rows []statusRow) []clusterPathRow {
	var out []clusterPathRow
	for _, row := range rows {
		if row.FetchError != "" {
			continue
		}
		from := row.Nickname
		if from == "" {
			from = row.Status.Role
		}
		for _, p := range row.Status.Paths {
			r := clusterPathRow{
				From:      from,
				To:        p.Role,
				Trunk:     p.Parent,
				Reachable: p.Reachable,
				LastError: p.LastError,
			}
			if p.Reachable {
				r.Class, r.Text = "ok", "reachable"
			} else {
				r.Class, r.Text = "crit", "unreachable"
			}
			r.Score = p.Score
			r.BarWidth = p.Score
			r.BarColor = trustBarColor(p.Score)
			out = append(out, r)
		}
		for _, sp := range row.Status.ScopePaths {
			r := clusterPathRow{
				From:      from,
				To:        sp.PeerRole,
				Trunk:     "scope:" + sp.Scope,
				Reachable: sp.Reachable,
				IsVLAN:    true,
				Parent:    sp.Parent,
				VLANID:    sp.VLANID,
			}
			if sp.Parent != "" {
				r.Trunk = fmt.Sprintf("VLAN %d · %s", sp.VLANID, sp.Scope)
			}
			if sp.Reachable {
				r.Class, r.Text = "ok", "reachable"
				r.Score, r.BarWidth = 100, 100
			} else {
				r.Class, r.Text = "crit", "unreachable"
				r.LastError = fmt.Sprintf("%d consecutive missed beacon(s)", sp.ConsecutiveMisses)
			}
			r.BarColor = trustBarColor(r.Score)
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		if out[i].To != out[j].To {
			return out[i].To < out[j].To
		}
		return out[i].Trunk < out[j].Trunk
	})
	return out
}

// pathsSummary condenses clusterPathRows into one glanceable line for the
// main Cluster table, matching every other row there.
func pathsSummary(rows []clusterPathRow) (text, class string) {
	if len(rows) == 0 {
		return "no data yet", "dim"
	}
	minScore := 101
	down := 0
	for _, r := range rows {
		if !r.Reachable {
			down++
		}
		if r.Score < minScore {
			minScore = r.Score
		}
	}
	switch {
	case down > 0:
		class = "crit"
	case minScore < 80:
		class = "warn"
	default:
		class = "ok"
	}
	text = fmt.Sprintf("%d path(s), min trust %d%%", len(rows), minScore)
	if down > 0 {
		text += fmt.Sprintf(" — %d down", down)
	}
	return text, class
}

// arbiterQuorumStatus summarizes "who is arbiter now" for Overview.
func arbiterQuorumStatus(rows []statusRow) (text, class string) {
	var present []string
	minKnown, minVotesSeen := -1, -1
	for _, row := range rows {
		if row.FetchError != "" {
			continue
		}
		if !isCoreRole(row.Status.Role) {
			continue
		}
		present = append(present, row.Status.Role)
		known := len(row.Status.PeersVisible) + len(row.Status.PeersUnreachable)
		votesSeen := 1 + len(row.Status.PeersVisible) // self + each reachable peer
		if minKnown < 0 || known < minKnown {
			minKnown = known
		}
		if minVotesSeen < 0 || votesSeen < minVotesSeen {
			minVotesSeen = votesSeen
		}
	}
	n := len(present)
	switch {
	case n >= 3 && minKnown >= 2:
		class = "ok"
	case minVotesSeen >= 0 && minVotesSeen < 2:
		class = "crit"
	default:
		class = "warn"
	}
	text = fmt.Sprintf("%d/3 (%s)", n, strings.Join(present, ", "))
	if minKnown >= 0 && minKnown < 2 {
		text += fmt.Sprintf(" — a reachable node knows only %d/2 other core peer(s), see its own row below", minKnown)
	}
	return text, class
}

// checkCoherence cross-validates what each node claims against arbiter
// tokens and peer state.
func versionMismatchWarning(rows []statusRow) string {
	byVersion := make(map[string][]string) // version -> roles running it
	for _, row := range rows {
		if row.FetchError == "" {
			byVersion[row.Status.Version] = append(byVersion[row.Status.Version], row.Status.Role)
		}
	}
	if len(byVersion) <= 1 {
		return ""
	}
	versions := make([]string, 0, len(byVersion))
	for v := range byVersion {
		versions = append(versions, v)
	}
	sort.Strings(versions)
	var parts []string
	for _, v := range versions {
		roles := byVersion[v]
		sort.Strings(roles)
		parts = append(parts, fmt.Sprintf("%s: %s", v, strings.Join(roles, ",")))
	}
	return fmt.Sprintf("VERSION MISMATCH: %s", strings.Join(parts, "; "))
}

// coherenceWarningTitle returns a one-line explanation of what a
// checkCoherence finding actually means and why it matters, keyed by its
// own leading ALL-CAPS tag.
func coherenceWarningTitle(w string) string {
	switch {
	case strings.HasPrefix(w, "DUAL-ACTIVE:"):
		return "Two workers both believe they're serving this scope's DHCP at the same time — a real, active safety violation (the one thing this whole project's gate/witness design exists to prevent). Should never happen; investigate immediately, don't assume it will self-heal."
	case strings.HasPrefix(w, "NO TOKEN:"):
		return "A worker is serving DHCP for this scope but the arbiter has no record of it holding a valid witness token — it may be relying on a stale or cached grant. Often a brief timing artifact right after a restart; persisting past one renewal cycle is worth a closer look."
	case strings.HasPrefix(w, "TOKEN MISMATCH:"):
		return "The arbiter's own record of who holds this scope's witness token disagrees with who's actually serving its DHCP — authority and reality have diverged. Not itself proof of dual-active (the gate is what actually enforces exclusivity), but worth understanding why they disagree."
	case strings.HasPrefix(w, "UNSERVED:"):
		return "A valid arbiter witness token exists for this scope, but no worker currently claims to be serving it — DHCP for this scope is likely down right now, not just a display glitch."
	case strings.HasPrefix(w, "VERSION MISMATCH:"):
		return "Not every node in the cluster is running the same dnshived version — expected briefly during a staged rollout, worth resolving once one is in progress."
	case strings.HasPrefix(w, "EPOCH DIVERGENCE:"):
		return "The two workers disagree on the cluster's own generation counter while both report STABLE — usually a transient right after a restart or config push; persisting suggests the two nodes are working from genuinely different config."
	case strings.HasPrefix(w, "CLOCK SKEW:"):
		return "This node's clock disagrees with another's by more than this check's tolerance — witness-token expiry and VRRP timing both assume reasonably synced clocks across the cluster. Check NTP/chrony on the flagged node."
	case strings.HasPrefix(w, "MEMBERSHIP:"):
		return "This node's own peer list (cluster.json peers) disagrees with the cluster's current core nodes. A stale entry usually means a decommission never reached this node; a missing one means it was never told about a node that joined. Either way the nodes are no longer working from the same membership: quorum sizing, peer probing and trusted_hosts can all differ between them. Fix the node's peer list rather than waiting, it does not heal on its own."
	case strings.HasPrefix(w, "TRUNK PATH:"):
		return "This node sends topology beacons on this trunk but has heard none from any other core node on it, so the cluster cannot use this trunk as a path between nodes. Most common cause on Debian 13: reverse-path filtering (net.ipv4.conf.<trunk>.rp_filter, default 2) drops beacons on a trunk with no IPv4 address; dnshived sets it to 0 when it brings the trunk up, but a non-zero net.ipv4.conf.all.rp_filter still overrides that (the daemon log names it). Otherwise check cabling, switch/bridge VLAN config, and that the peers actually sit on this trunk."
	case strings.HasPrefix(w, "PARTITION:"):
		return "\"This page\" is the node whose web UI you are looking at (named in the message). Both nodes named here answer to it, yet at least one of them reports the other unreachable on its mgmt path, and no working fallback path is confirmed between them — an asymmetric partition between two nodes, not a problem with the page's own node. A node that still reaches its peer over the fallback path is not listed (that is a mgmt-only loss, shown on the State and Interfaces rows). Can affect that pair's own quorum/failover timing until it clears."
	default:
		return ""
	}
}

func checkCoherence(rows []statusRow, tokens map[string]tokenInfo, observerName ...string) []string {
	var warnings []string

	// Build serving map: scope -> list of roles claiming to serve it.
	servingMap := make(map[string][]string)
	for _, row := range rows {
		if row.FetchError != "" || !isCoreRole(row.Status.Role) {
			continue
		}
		for _, sc := range row.Status.Serving {
			servingMap[sc] = append(servingMap[sc], row.Status.Role)
		}
	}

	// Check 1: dual-active — more than one core node serving the same scope.
	for sc, workers := range servingMap {
		if len(workers) > 1 {
			warnings = append(warnings, fmt.Sprintf("DUAL-ACTIVE: scope %s served by %s", sc, strings.Join(workers, " AND ")))
		}
	}

	// Check 2: serving without token — worker serves but arbiter has no matching token.
	for sc, workers := range servingMap {
		tok, hasTok := tokens[sc]
		if !hasTok {
			warnings = append(warnings, fmt.Sprintf("NO TOKEN: scope %s served by %s but no arbiter token exists", sc, workers[0]))
			continue
		}
		for _, row := range rows {
			if row.FetchError != "" || row.Status.Role != workers[0] {
				continue
			}
			if tok.Owner != row.Status.NodeID {
				warnings = append(warnings, fmt.Sprintf("TOKEN MISMATCH: scope %s served by %s but token owned by %s", sc, row.Status.NodeID, tok.Owner))
			}
		}
	}

	// Check 3: token exists but nobody serves — orphan token.
	for sc, tok := range tokens {
		if _, served := servingMap[sc]; !served && !tok.Expired {
			warnings = append(warnings, fmt.Sprintf("UNSERVED: scope %s has active token (%s) but no core node is serving it", sc, tok.Owner))
		}
	}

	if w := versionMismatchWarning(rows); w != "" {
		warnings = append(warnings, w)
	}

	// Check 5: epoch divergence — every core node should agree on epoch when
	// stable.
	epochsByValue := make(map[uint64][]string)
	allStable := true
	for _, row := range rows {
		if row.FetchError == "" && isCoreRole(row.Status.Role) {
			epochsByValue[row.Status.Epoch] = append(epochsByValue[row.Status.Epoch], row.Status.Role)
			if row.Status.State != "STABLE" {
				allStable = false
			}
		}
	}
	if allStable && len(epochsByValue) > 1 {
		var parts []string
		for epoch, roles := range epochsByValue {
			parts = append(parts, fmt.Sprintf("%s=%d", strings.Join(roles, "+"), epoch))
		}
		sort.Strings(parts)
		warnings = append(warnings, fmt.Sprintf("EPOCH DIVERGENCE: %s", strings.Join(parts, " vs ")))
	}

	for _, row := range rows {
		if row.FetchError != "" || row.Status.ServerTime == "" {
			continue
		}
		serverT, err := time.Parse(time.RFC3339, row.Status.ServerTime)
		if err != nil {
			continue
		}
		now := row.FetchedAt
		if now.IsZero() {
			now = time.Now()
		}
		skew := now.Sub(serverT)
		if skew < 0 {
			skew = -skew
		}
		if skew > 5*time.Second {
			warnings = append(warnings, fmt.Sprintf("CLOCK SKEW: %s is %.1fs off from this host", row.Status.NodeID, skew.Seconds()))
		}
	}

	observer := ""
	if len(observerName) > 0 {
		observer = observerName[0]
	}
	servedBy := "both answer this page"
	if observer != "" {
		servedBy = "both answer this page, served by " + observer
	}
	seenPair := map[string]bool{}
	cannotSee := func(from, to statusRow) bool {
		for _, peer := range from.Status.PeersUnreachable {
			if peer == to.Node.Addr {
				return from.Status.FallbackPeers[peer] == ""
			}
		}
		return false
	}
	for _, row := range rows {
		if row.FetchError != "" || len(row.Status.PeersUnreachable) == 0 {
			continue
		}
		for _, other := range rows {
			if other.FetchError != "" || other.Node.Addr == row.Node.Addr || !cannotSee(row, other) {
				continue
			}
			ids := []string{row.Status.NodeID, other.Status.NodeID}
			sort.Strings(ids)
			key := ids[0] + "|" + ids[1]
			if seenPair[key] {
				continue
			}
			seenPair[key] = true
			if cannotSee(other, row) {
				warnings = append(warnings, fmt.Sprintf("PARTITION: %s and %s cannot see each other (mgmt path down, no working fallback path confirmed; %s)", ids[0], ids[1], servedBy))
			} else {
				warnings = append(warnings, fmt.Sprintf("PARTITION: %s cannot see %s, but %s can see it (%s)", row.Status.NodeID, other.Status.NodeID, other.Status.NodeID, servedBy))
			}
		}
	}

	warnings = append(warnings, membershipWarnings(rows)...)
	warnings = append(warnings, trunkPathWarnings(rows)...)

	return warnings
}

const trunksAssumedTitle = "Assumed means this node is configured with the trunk and beacons on it, but has heard no beacon from any other core on it, so nothing confirms it is wired to the same network as the other cores. Check cabling and switch/bridge VLAN config; on a trunk with no IPv4 address a non-zero net.ipv4.conf.all.rp_filter also drops the beacons."

// trunkVerificationStatus summarizes, over every STABLE reachable core, how
// many of its beaconed trunks have heard another core's beacon.
func trunkVerificationStatus(rows []statusRow) (text, class, title string) {
	reachableCores := 0
	for _, row := range rows {
		if row.FetchError == "" && isCoreRole(row.Status.Role) {
			reachableCores++
		}
	}
	if reachableCores < 2 {
		return "not checkable (needs two reachable cores)", "dim", ""
	}
	total, verified := 0, 0
	var assumed []string
	for _, row := range rows {
		if row.FetchError != "" || !isCoreRole(row.Status.Role) || row.Status.State != "STABLE" {
			continue
		}
		heard := map[string]bool{}
		for _, sg := range row.Status.Topology {
			if sg.MyKind == "trunk" {
				heard[sg.MyIface] = true
			}
		}
		for _, trunk := range row.Status.TopologyTrunks {
			total++
			if heard[trunk] {
				verified++
			} else {
				assumed = append(assumed, row.Status.Role+" "+trunk)
			}
		}
	}
	if total == 0 {
		return "no trunk configured", "dim", ""
	}
	if verified == total {
		return fmt.Sprintf("verified %d/%d", verified, total), "ok", ""
	}
	sort.Strings(assumed)
	return fmt.Sprintf("verified %d/%d — assumed: %s", verified, total, strings.Join(assumed, ", ")), "warn", trunksAssumedTitle
}

// trunkPathWarnings flags a trunk a STABLE core node beacons on but has
// not heard any peer's beacon on, while at least one other core node is
// reachable.
func trunkPathWarnings(rows []statusRow) []string {
	reachableCores := 0
	for _, row := range rows {
		if row.FetchError == "" && isCoreRole(row.Status.Role) {
			reachableCores++
		}
	}
	if reachableCores < 2 {
		return nil
	}
	var warnings []string
	for _, row := range rows {
		if row.FetchError != "" || !isCoreRole(row.Status.Role) || row.Status.State != "STABLE" {
			continue
		}
		heard := map[string]bool{}
		for _, s := range row.Status.Topology {
			if s.MyKind == "trunk" {
				heard[s.MyIface] = true
			}
		}
		for _, trunk := range row.Status.TopologyTrunks {
			if !heard[trunk] {
				warnings = append(warnings, fmt.Sprintf("TRUNK PATH: %s hears no beacon from any peer on %s", row.Status.Role, trunk))
			}
		}
	}
	return warnings
}

func membershipWarnings(rows []statusRow) []string {
	members := map[string]string{}
	for _, row := range rows {
		if isCoreRole(row.Node.Name) {
			members[row.Node.Addr] = row.Node.Name
		}
	}
	var warnings []string
	for _, row := range rows {
		if row.FetchError != "" || !isCoreRole(row.Status.Role) {
			continue
		}
		configured := map[string]bool{}
		for _, p := range append(append([]string(nil), row.Status.PeersVisible...), row.Status.PeersUnreachable...) {
			configured[p] = true
		}
		var extra, missing []string
		for p := range configured {
			if _, ok := members[p]; !ok && p != row.Node.Addr {
				extra = append(extra, p)
			}
		}
		for addr, name := range members {
			if addr != row.Node.Addr && !configured[addr] {
				missing = append(missing, name+" ("+addr+")")
			}
		}
		sort.Strings(extra)
		sort.Strings(missing)
		if len(extra) > 0 {
			warnings = append(warnings, fmt.Sprintf("MEMBERSHIP: %s still lists %s as a peer, not a current cluster member", row.Status.Role, strings.Join(extra, ", ")))
		}
		if len(missing) > 0 {
			warnings = append(warnings, fmt.Sprintf("MEMBERSHIP: %s does not list %s as a peer", row.Status.Role, strings.Join(missing, ", ")))
		}
	}
	return warnings
}

func planeHealthWhatInfo(what string) (soft bool, title string) {
	switch what {
	case "gate_vrrp_coherence":
		return true, "This node's own DHCP gate is open while VRRP elected a different node as MASTER. Confirmed safe by design, not a dual-active risk: dual-active is prevented by the arbiter's own witness-token quorum and the nftables gate itself, never by VRRP state — VRRP only decides who holds the VIP. preferred_worker is only ever consulted when a scope is first contested (nobody currently holds a valid token, or the holder just went unhealthy); it never reclaims a scope from an already-serving, healthy incumbent. This can persist indefinitely on a perfectly healthy cluster — restart the node currently serving (or wait for it to naturally lose its token) if you want the preferred worker to actually take over."
	case "relay_socket_stale":
		return false, "The DHCP/DNS relay's own client socket was left bound to a since-replaced interface (e.g. after a scope rename or an interface rebuild) — genuinely stale, but this project's own self-heal already reloads the affected relay automatically; this line should clear on its own within one tick."
	case "interface":
		return false, "A scope's own VLAN interface doesn't match what this node believes it constructed — being actively reconstructed."
	case "dnsmasq":
		return false, "A scope's own dnsmasq unit isn't in the expected state — being actively restarted/reconstructed."
	case "keepalived":
		return false, "The consolidated keepalived unit isn't in the expected state — being actively restarted."
	case "node_ip":
		return false, "This scope's node_ip doesn't match what's actually configured on the interface — being actively corrected."
	case "gate":
		return false, "This node's own DHCP gate state doesn't match what it last believed it set — a real, report-only drift signal worth investigating if it doesn't clear."
	case "trunk_link_down":
		return false, "This node's own physical trunk interface has lost carrier (cable unplugged, switch port down, ...) — every scope on that trunk has been force-closed immediately as a safety precaution. Clears automatically the moment the physical link comes back; if it doesn't, check the cable/switch port directly."
	case "peer_mgmt_down":
		return false, "Another core node's own mgmt/control-plane path is unreachable, but it's confirmed still alive via its own scope-VLAN address (dual-path reachability) — its management interface itself is likely down (cable, switch port, VM NIC), not the node as a whole. That node's own witness/quorum participation may already be degraded as a result; DHCP for its own scopes may already have failed over to a survivor. Clears automatically once its mgmt path is reachable again."
	default:
		return false, ""
	}
}

func planeWarningBody(pw string) string {
	rest := pw
	if strings.HasPrefix(rest, "scope ") {
		if idx := strings.Index(rest, ": "); idx >= 0 {
			rest = rest[idx+2:]
		}
	}
	return rest
}

func isInterfaceWarning(pw string) bool {
	body := planeWarningBody(pw)
	return strings.HasPrefix(body, "trunk_link_down ") || strings.HasPrefix(body, "peer_mgmt_down ")
}

func unreachableNodeNames(rows []statusRow, mgmtOnlyAddrs map[string]bool) []string {
	var names []string
	for _, row := range rows {
		if row.FetchError == "" || mgmtOnlyAddrs[row.Node.Addr] {
			continue
		}
		name := row.Node.Name
		if name == "" {
			name = row.Node.Addr
		}
		names = append(names, name)
	}
	return names
}

func mgmtOnlyDownAddrs(rows []statusRow) map[string]bool {
	out := map[string]bool{}
	for _, row := range rows {
		if row.FetchError != "" {
			continue
		}
		for _, pw := range row.Status.PlaneWarnings {
			body := planeWarningBody(pw)
			const prefix = "peer_mgmt_down "
			if !strings.HasPrefix(body, prefix) {
				continue
			}
			detail := body[len(prefix):]
			open := strings.IndexByte(detail, '(')
			closeIdx := strings.IndexByte(detail, ')')
			if open < 0 || closeIdx <= open {
				continue
			}
			out[detail[open+1:closeIdx]] = true
		}
	}
	return out
}

func configSaneStatus(rows []statusRow) (text, class, title string) {
	var warnings []string
	seenTitles := map[string]bool{}
	var titles []string
	allSoft := true
	for _, row := range rows {
		if row.FetchError != "" {
			continue
		}
		for _, pw := range row.Status.PlaneWarnings {
			if isInterfaceWarning(pw) {
				continue
			}
			warnings = append(warnings, fmt.Sprintf("%s: %s", row.Status.Role, pw))
			// what is the first word of the body.
			rest := planeWarningBody(pw)
			what := rest
			if sp := strings.IndexByte(rest, ' '); sp > 0 {
				what = rest[:sp]
			}
			soft, t := planeHealthWhatInfo(what)
			if !soft {
				allSoft = false
			}
			if t != "" && !seenTitles[t] {
				seenTitles[t] = true
				titles = append(titles, t)
			}
		}
	}
	if len(warnings) == 0 {
		return "yes", "ok", ""
	}
	class = "crit"
	if allSoft {
		class = "warn"
	}
	return fmt.Sprintf("%d issue(s) — %s", len(warnings), strings.Join(warnings, "; ")), class, strings.Join(titles, " ")
}

func interfaceHealthStatus(rows []statusRow) (text, class string) {
	// peer_mgmt_down findings are IDENTICAL in content across every observer
	// that reports the same down peer.
	var trunkIssues []string
	peerObservers := map[string][]string{} // body -> observing roles, first-seen order
	var peerOrder []string
	for _, row := range rows {
		if row.FetchError != "" {
			continue
		}
		for _, pw := range row.Status.PlaneWarnings {
			if !isInterfaceWarning(pw) {
				continue
			}
			body := planeWarningBody(pw)
			if strings.HasPrefix(body, "peer_mgmt_down ") {
				if _, seen := peerObservers[body]; !seen {
					peerOrder = append(peerOrder, body)
				}
				peerObservers[body] = append(peerObservers[body], row.Status.Role)
				continue
			}
			trunkIssues = append(trunkIssues, fmt.Sprintf("%s: %s", row.Status.Role, pw))
		}
	}
	issues := trunkIssues
	for _, body := range peerOrder {
		issues = append(issues, fmt.Sprintf("%s (confirmed by %s)", body, strings.Join(peerObservers[body], ", ")))
	}
	if len(issues) == 0 {
		return "healthy", "ok"
	}
	return fmt.Sprintf("%d issue(s) — %s", len(issues), strings.Join(issues, "; ")), "crit"
}

var statusTmpl = template.Must(template.New("status").Funcs(template.FuncMap{
	"coherenceTitle": coherenceWarningTitle,
}).Parse(`<!doctype html>
<title>dnshived-web — overview</title>
` + styleHTML + `
<h1>dnshived cluster overview</h1>
` + navHTML + `

{{if .Mismatch}}
<p><strong class="crit">WARNING: scopes_hash differs between nodes — config is not
identical across the cluster. Re-check the config editor and re-save
until every node reports the same hash.</strong></p>
{{end}}

{{if .ConfigMismatch}}
<p><strong class="crit">WARNING: config_hash differs between nodes — a non-scope
setting (PSK, DNS defaults, core_dns_query_logging, ...) is not identical
across the cluster, most likely from a config push that only partially
landed (e.g. one node was unreachable at the time). Re-save the affected
setting once every node is reachable.</strong></p>
{{end}}

{{if .ResetMessage}}
<p class="{{.ResetMessageClass}}"><strong>{{.ResetMessage}}</strong></p>
{{end}}

<p class="{{.BannerClass}}"><strong>{{.BannerText}}</strong></p>

<h2>Cluster</h2>
<table border="1" cellpadding="4">
<tr><td>State <span class="info-ico" title="the cluster's own quorum/failover state machine: STABLE means every serving decision has settled and held for the required settling window; DEGRADED/GETTING THERE/NOT CONVERGING mean scopes are still starting, rebalancing, or stuck — not necessarily an outage, but worth watching">ⓘ</span></td><td class="{{.ClusterClass}}">{{.ClusterState}}</td></tr>
<tr><td>Configuration sane <span class="info-ico" title="every node's own real, live-observed state (interfaces, sockets, ...) checked against what's actually configured/intended — separate from State above, which is FSM/quorum health only">ⓘ</span></td><td class="{{.ConfigSaneClass}}"{{if .ConfigSaneTitle}} title="{{.ConfigSaneTitle}}"{{end}}>{{.ConfigSaneText}}</td></tr>
<tr><td>Interfaces <span class="info-ico" title="physical trunk carrier state (link up/down) per node — a link-down trunk force-closes DHCP for every scope on it">ⓘ</span></td><td class="{{.InterfaceHealthClass}}">{{.InterfaceHealthText}}</td></tr>
<tr><td>Trunks <span class="info-ico" title="every configured trunk on every stable core: verified once that node has heard a topology beacon from another core on it, assumed while nothing has been heard (the configured interface name is then unconfirmed)">ⓘ</span></td><td class="{{.TrunksClass}}"{{if .TrunksTitle}} title="{{.TrunksTitle}}"{{end}}>{{.TrunksText}}</td></tr>
{{if .StableSince}}<tr><td>Stable since</td><td class="dim">{{.StableSince}} ({{.StableFor}} ago)</td></tr>{{end}}
<tr><td>Node IDs</td><td class="dim">{{.NodeIDsLine}}</td></tr>
<tr><td>Witness <span class="info-ico" title="the time-limited token that authorizes a node to keep a scope's DHCP gate open — renewed continuously while healthy; a node that stops renewing (crash, network loss) has its gate close automatically once its current token expires, which is what actually prevents two nodes serving the same scope at once">ⓘ</span></td><td>{{.Witness}}</td></tr>
<tr><td>Arbiter quorum <span class="info-ico" title="every core node also runs its own arbiter instance since 0.9.8 — a witness grant needs 2 of these 3 to agree, so this is 'who is arbiter now', not a single node">ⓘ</span></td><td class="{{.ArbiterQuorumClass}}">{{.ArbiterQuorumText}}</td></tr>
<tr><td>Serving <span class="info-ico" title="how many of the cluster's configured scopes currently have exactly one node authoritatively serving DHCP for them — by design, never two at once; a scope can be temporarily unserved during startup/failover/rebalancing without that being an outage. Disabled scopes are not counted as serving and are listed separately">ⓘ</span></td><td class="{{.ServingClass}}">{{.ServingText}}</td></tr>
<tr><td>Unreachable nodes</td><td>{{.Unreachable}}{{if .UnreachableNames}} ({{.UnreachableNames}}){{end}}</td></tr>
<tr><td>Daemons <span class="info-ico" title="systemd unit health (dnshived itself, dnsmasq, keepalived, relays, ...) on every node — a daemon issue here is independent of State above: a unit can be unhealthy while the cluster's own quorum/serving logic stays fine, and vice versa">ⓘ</span></td><td class="{{.DaemonSummaryClass}}">{{.DaemonSummary}}</td></tr>
<tr><td>Probes <span class="info-ico" title="real DHCP/DNS validation performed from an external probe host, on each scope's own client-facing VLAN — the closest thing to 'does this actually work for a real client', not just 'does the cluster believe it's serving'">ⓘ</span></td><td class="{{.ProbeSummaryClass}}">{{.ProbeSummary}}</td></tr>
<tr><td>Cluster paths <span class="info-ico" title="each worker trunk's own alternate path to every other core role — continuously monitored, not actively used until a peer's primary (mgmt) path goes down">ⓘ</span></td><td class="{{.PathsSummaryClass}}">{{.PathsSummaryText}}{{if .PathRows}} <a href="#" onclick="document.getElementById('paths-modal').showModal();return false;">details</a>{{end}}</td></tr>
</table>

<h2>Cluster nodes</h2>
<div class="table-wrap">
<table border="1" cellpadding="4" cellspacing="0" class="fixed-table">
<colgroup>
<col style="width:9%"><col style="width:7%"><col style="width:11%">
<col style="width:13%"><col style="width:9%"><col style="width:13%">
<col style="width:13%"><col style="width:25%">
</colgroup>
<tr><th>Name</th><th>Role</th><th>Host</th><th>Addr</th><th>State</th><th>Info</th><th>Version</th><th>System</th></tr>
{{range .Rows}}
<tr>
  <td class="{{.RoleClass}}">{{.Nickname}}{{if .HoldsMgmtVIP}} <span class="vip-badge" title="currently answering as the management-VIP's VRRP MASTER">VIP</span>{{end}}</td>
  {{if .FetchError}}
  <td colspan="7" class="crit">UNREACHABLE: {{.FetchError}}</td>
  {{else}}
  <td class="{{.RoleClass}}">{{.Status.Role}}</td>
  <td class="dim">{{.Status.Hostname}}</td>
  <td style="white-space:nowrap">{{.Node.Addr}}</td>
  <td class="{{.Class}}">{{.Icon}} {{.Status.State}}</td>
  <td>{{.Info}}</td>
  <td>{{.Status.Version}}</td>
  <td class="dim">{{.SysStr}}</td>
  {{end}}
</tr>
{{end}}
{{range .MissingRoles}}
<tr>
  <td class="dim">{{.}}</td>
  <td colspan="7" class="warn">not configured — offboarded or never onboarded. <a href="/config#discovered">Discovered on the network</a> can onboard or replace it.</td>
</tr>
{{end}}
{{if .ProbeHostRows}}
<tr><td colspan="8" style="border-top:3px solid var(--muted);border-bottom:none;padding:0"></td></tr>
{{range .ProbeHostRows}}
<tr>
  <td class="node-probe">{{.Name}}</td>
  <td class="node-probe">probe</td>
  <td class="dim">{{.Hostname}}</td>
  <td style="white-space:nowrap">{{.Addr}}</td>
  <td class="{{.Class}}">{{.Icon}} {{.State}}</td>
  <td>{{.Info}}</td>
  <td>{{.Version}}</td>
  <td class="dim">{{.SysStr}}</td>
</tr>
{{end}}
{{end}}
</table>
</div>

{{if .PathRows}}
<dialog id="paths-modal">
<div class="modal-head">
<h2 title="each worker trunk's own alternate path to every other core role — continuously monitored, not actively used until a peer's primary (mgmt) path goes down">Cluster paths</h2>
<form method="dialog"><button>Close</button></form>
</div>
<div class="table-wrap">
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>From</th><th>To</th><th>Trunk</th><th>Status</th><th>Trust</th><th></th></tr>
{{range .PathGroups}}{{$g := .}}{{with .Row}}
<tr>
  <td>{{.From}}</td>
  <td>{{.To}}</td>
  <td class="dim">{{.Trunk}}{{if $g.VLANs}} <a href="#" class="dim" onclick="document.querySelectorAll('tr[data-pg={{$g.ID}}]').forEach(function(r){r.hidden=!r.hidden});var a=this.querySelector('span');a.textContent=a.textContent==='▸'?'▾':'▸';return false;" title="show/hide the VLAN paths that run over this trunk"><span>▸</span> <span{{if $g.VLANsDown}} class="crit"{{end}}>{{$g.VLANSummary}}</span></a>{{end}}</td>
  <td class="{{.Class}}" {{if .LastError}}title="{{.LastError}}"{{end}}>{{.Text}}</td>
  <td><div class="trust-bar"><div class="trust-bar-fill" style="width:{{.BarWidth}}%;background:{{.BarColor}}"></div></div><span class="dim">{{.Score}}%</span></td>
  <td>{{if not .IsVLAN}}<form method="post" action="/paths/reset" style="display:inline" onsubmit="return confirm('Reset trust-index history for {{.To}} over {{.Trunk}}, on every reachable node? Do this only if the underlying cable/link was actually fixed.')">
    <input type="hidden" name="role" value="{{.To}}">
    <input type="hidden" name="parent" value="{{.Trunk}}">
    <button type="submit" title="clears the persisted trust-index history for this (role, trunk) pair on every reachable node — use after fixing a genuinely faulty cable/link, not to silence a real, still-present problem">Reset</button>
  </form>{{end}}</td>
</tr>{{end}}{{range .VLANs}}
<tr data-pg="{{$g.ID}}" hidden>
  <td></td>
  <td></td>
  <td class="dim">&nbsp;&nbsp;↳ {{.Trunk}}</td>
  <td class="{{.Class}}" {{if .LastError}}title="{{.LastError}}"{{end}}>{{.Text}}</td>
  <td><div class="trust-bar"><div class="trust-bar-fill" style="width:{{.BarWidth}}%;background:{{.BarColor}}"></div></div><span class="dim">{{.Score}}%</span></td>
  <td></td>
</tr>{{end}}
{{end}}
</table>
</div>
{{if .TopoGraphSVG}}
<h3 title="each edge is drawn from a live internal/topobeacon correlation — real per-interface UDP beacons exchanged every 5s between already-onboarded core nodes, not the HTTP-ping-based reachability the table above shows. Solid = worker trunk, dashed = mgmt.">Physical topology (live)</h3>
{{.TopoGraphSVG}}
{{end}}
{{if .TopoSightingRows}}
<h3 title="the raw internal/topobeacon evidence behind the graph above and the mgmt row(s) in the table above — one row per (reporting node, its own interface, peer role, peer's own interface) currently heard fresh.">Topology detail (debug)</h3>
<div class="table-wrap">
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>From</th><th>My iface</th><th>Kind</th><th>Peer</th><th>Peer iface</th><th>Count</th><th>Last heard</th></tr>
{{range .TopoSightingRows}}
<tr>
  <td>{{.From}}</td>
  <td class="dim">{{.MyIface}}</td>
  <td class="dim">{{.MyKind}}</td>
  <td>{{.PeerRole}}</td>
  <td class="dim">{{.PeerIface}}</td>
  <td>{{.Count}}</td>
  <td class="dim">{{.Age}}</td>
</tr>
{{end}}
</table>
</div>
{{end}}
</dialog>
{{end}}

<h2>Tokens</h2>
<p>{{.ActiveTokens}} active, {{.ExpiredTokens}} expired</p>

{{if .DaemonIssues}}
<h2>Daemon issues</h2>
<ul>
{{range .DaemonIssues}}<li class="crit">{{.}}</li>{{end}}
</ul>
{{end}}

{{if .ProbeIssues}}
<h2>Probe issues</h2>
<ul>
{{range .ProbeIssues}}<li>{{if .Rogue}}<span class="rogue-badge">⚠ ROGUE DHCP SERVER</span> {{end}}<a href="/probes/{{.Scope}}/{{.Worker}}">{{.Scope}}</a> (from {{.Worker}}):
{{if .DNSText}} <span class="{{.DNSClass}}">{{.DNSText}}</span>{{end}}
{{if .DHCPText}} <span class="{{.DHCPClass}}">{{.DHCPText}}</span>{{end}}
{{if .Detail}} <span class="{{if .Rogue}}crit{{else}}dim{{end}}">{{.Detail}}</span>{{end}}</li>{{end}}
</ul>
{{end}}

{{if .Coherence}}
<h2>Coherence</h2>
<ul>
{{range .Coherence}}<li class="crit" title="{{coherenceTitle .}}">{{.}}</li>{{end}}
</ul>
{{end}}
`))

type overviewData struct {
	Rows           []statusRow
	Mismatch       bool
	ConfigMismatch bool
	BannerText     string
	BannerClass    string
	ClusterState   string
	ClusterClass   string
	// NodeIDsLine shows each reachable core node's role + real control address
	// (role=ip:port).
	NodeIDsLine          string
	Witness              string
	ArbiterQuorumText    string
	ArbiterQuorumClass   string
	ConfigSaneText       string
	ConfigSaneClass      string
	ConfigSaneTitle      string
	InterfaceHealthText  string
	InterfaceHealthClass string
	TrunksText           string
	TrunksClass          string
	TrunksTitle          string
	ServingText          string
	ServingClass         string
	Unreachable          int
	// UnreachableNames names the nodes counted in Unreachable, e.g. "core-2"
	// or "core-1, core-2".
	UnreachableNames   string
	ActiveTokens       int
	ExpiredTokens      int
	DaemonSummary      string
	DaemonSummaryClass string
	DaemonIssues       []string
	ProbeSummary       string
	ProbeSummaryClass  string
	ProbeIssues        []probeIssue
	Coherence          []string
	StableSince        string // empty when not currently, fully cluster-stable
	StableFor          string

	ProbeHostRows []probeHostOverviewRow

	PathRows          []clusterPathRow
	PathsSummaryText  string
	PathsSummaryClass string

	TopoGraphSVG     template.HTML
	TopoSightingRows []topoSightingRow

	ResetMessage      string
	ResetMessageClass string

	MissingRoles []string
}

// probeHostOverviewRow is one external probe host's Workers-table row.
type probeHostOverviewRow struct {
	Name string
	// Hostname is the probe host's OS hostname, empty on a DOWN row.
	Hostname string
	Addr     string
	Icon     string
	Class    string
	State    string
	Info     string
	Version  string
	SysStr   string // same "load %.2f  mem %d%%" format as the real workers' own rows
}

// probeHostRowName is a one-line pure wrapper around n.displayName().
func probeHostRowName(n NodeConfig) string {
	return n.displayName()
}

// clusterStableSince returns the most recent per-node state_since among
// every row.
func clusterStableSince(rows []statusRow, skip ...map[string]bool) (time.Time, bool) {
	var latest time.Time
	for _, row := range rows {
		if row.FetchError != "" {
			skipped := false
			for _, m := range skip {
				if m[row.Node.Addr] {
					skipped = true
					break
				}
			}
			if skipped {
				continue
			}
			return time.Time{}, false
		}
		t, err := time.Parse(time.RFC3339, row.Status.StateSince)
		if err != nil {
			return time.Time{}, false
		}
		if t.After(latest) {
			latest = t
		}
	}
	if latest.IsZero() {
		return time.Time{}, false
	}
	return latest, true
}

// formatDuration renders elapsed time precise to the second (HH:MM:SS, or
// "Nd HH:MM:SS" past 24h) — ported identically from dnshived-top.
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	total := int64(d.Seconds())
	days := total / 86400
	hours := (total % 86400) / 3600
	mins := (total % 3600) / 60
	secs := total % 60
	if days > 0 {
		return fmt.Sprintf("%dd %02d:%02d:%02d", days, hours, mins, secs)
	}
	return fmt.Sprintf("%02d:%02d:%02d", hours, mins, secs)
}

// pathDegradedTexts returns the Overview banner and State texts for a
// cluster that is otherwise healthy but has nodes whose mgmt path is down.
func pathDegradedTexts(mgmtOnly, viaFallback int) (banner, state string) {
	if mgmtOnly > 0 {
		return fmt.Sprintf("PRODUCTION ACTIVE — %d node(s) reachable via fallback path only (mgmt path down)", mgmtOnly+viaFallback),
			fmt.Sprintf("STABLE — %d node(s) mgmt path down, alive via fallback", mgmtOnly+viaFallback)
	}
	return fmt.Sprintf("PRODUCTION ACTIVE — %d node(s) served over the fallback path (mgmt path down)", viaFallback),
		fmt.Sprintf("STABLE — %d node(s) mgmt path down, data via fallback path", viaFallback)
}

// servingText renders the Overview's "Serving" line; configured excludes
// disabled scopes, which are listed separately.
func servingText(serving, configured, disabled, mgmtOnlyDown int) string {
	text := fmt.Sprintf("%d of %d scope(s)", serving, configured)
	if mgmtOnlyDown > 0 {
		text = fmt.Sprintf("%d of %d scope(s) visible — %d node(s) reachable via fallback only, their scopes not counted", serving, configured, mgmtOnlyDown)
	}
	if disabled > 0 {
		text += fmt.Sprintf(", %d disabled", disabled)
	}
	return text
}

func handleStatus(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		rows := fetchAllStatus(cfg, nodesIncludingSelf(cfg))
		tokens := fetchArbiterTokens(cfg, rows)

		stable, reachable, total := 0, 0, len(rows)
		unreachable := 0
		mgmtOnlyAddrs := mgmtOnlyDownAddrs(rows)
		mgmtOnlyCount := 0
		// Nodes whose mgmt path is down but whose REAL status was tunnelled
		// over the fallback address — fully visible, path degraded.
		viaFallbackCount := 0
		configuredScopes := make(map[string]bool)
		servingScopes := make(map[string]bool)
		disabledScopes := disabledScopeSet(rows)
		totalServing := 0
		var idParts []string
		for _, row := range rows {
			if row.FetchError != "" {
				if mgmtOnlyAddrs[row.Node.Addr] {
					mgmtOnlyCount++
				} else {
					unreachable++
				}
				continue
			}
			reachable++
			if row.ViaFallback {
				viaFallbackCount++
			}
			if row.Status.State == "STABLE" {
				stable++
			}
			idParts = append(idParts, row.Status.Role+"="+row.Node.Addr)
			if isCoreRole(row.Status.Role) {
				for _, sc := range row.Status.ConfiguredScopes {
					if !disabledScopes[sc] {
						configuredScopes[sc] = true
					}
				}
				for _, sc := range row.Status.Serving {
					if !disabledScopes[sc] {
						servingScopes[sc] = true
						totalServing++
					}
				}
			}
		}

		settlingNow := stable == total && len(configuredScopes) > 0 && len(servingScopes) < len(configuredScopes)
		settlingMu.Lock()
		if settlingNow {
			if settlingSince.IsZero() {
				settlingSince = time.Now()
			}
		} else {
			settlingSince = time.Time{}
		}
		var settlingElapsed time.Duration
		if !settlingSince.IsZero() {
			settlingElapsed = time.Since(settlingSince)
		}
		settlingMu.Unlock()

		bannerT, bannerC := bannerText(stable, reachable, total, len(configuredScopes), len(servingScopes), settlingElapsed)
		allOthersStableOrMgmtOnly := (mgmtOnlyCount > 0 || viaFallbackCount > 0) && stable+mgmtOnlyCount == total
		if allOthersStableOrMgmtOnly {
			bannerT, _ = pathDegradedTexts(mgmtOnlyCount, viaFallbackCount)
			bannerC = "warn"
		}

		overallState, overallClass := "STABLE", "ok"
		switch {
		case total == 0:
			overallState, overallClass = "NO NODES REACHABLE", "crit"
		case allOthersStableOrMgmtOnly:
			_, overallState = pathDegradedTexts(mgmtOnlyCount, viaFallbackCount)
			overallClass = "warn"
		case stable != total:
			overallState, overallClass = "DEGRADED", "warn"
		}

		servingClass := "ok"
		if len(configuredScopes) > 0 && totalServing < len(configuredScopes) && mgmtOnlyCount == 0 {
			servingClass = "warn"
		}

		activeTokens, expiredTokens := 0, 0
		for _, t := range tokens {
			if t.Expired {
				expiredTokens++
			} else {
				activeTokens++
			}
		}
		witness := "healthy"
		if expiredTokens > 0 {
			witness = fmt.Sprintf("%d expired", expiredTokens)
		}
		arbiterQuorumText, arbiterQuorumClass := arbiterQuorumStatus(rows)
		configSaneText, configSaneClass, configSaneTitle := configSaneStatus(rows)
		interfaceHealthText, interfaceHealthClass := interfaceHealthStatus(rows)
		trunksText, trunksClass, trunksTitle := trunkVerificationStatus(rows)

		daemonIssues := checkDaemonHealth(cfg, nodesIncludingSelf(cfg))
		daemonSummary, daemonSummaryClass := "all healthy", "ok"
		if len(daemonIssues) > 0 {
			daemonSummary = fmt.Sprintf("%d issue(s) — see below", len(daemonIssues))
			daemonSummaryClass = "crit"
		}

		scopeNames := configuredScopeNames(rows)
		ownerUptime := ownerDaemonUptime(cfg)
		rawProbeIssues, probeMismatches, probePending, probeCov := checkProbeHostIssuesWithCoverage(scopeNames, cfg.ProbeHosts, tokens, ownerUptime, servingScopes, disabledScopes)
		probeIssues := append(rawProbeIssues, debounceProbeMismatches(probeMismatches)...)
		sort.Slice(probeIssues, func(i, j int) bool {
			return probeIssues[i].Scope+probeIssues[i].Worker < probeIssues[j].Scope+probeIssues[j].Worker
		})
		probeSummary, probeSummaryClass := probeSummaryWithCoverage(probeIssues, probePending, probeCov)

		var stableSinceText, stableForText string
		if strings.HasPrefix(overallState, "STABLE") {
			if since, ok := clusterStableSince(rows, mgmtOnlyAddrs); ok {
				stableSinceText = since.Local().Format("15:04:05")
				stableForText = formatDuration(time.Since(since))
			}
		}

		var probeHostRows []probeHostOverviewRow
		for _, res := range fetchAllNodes(cfg.ProbeHosts, fetchNodeSnapshot) {
			row := probeHostOverviewRow{Name: probeHostRowName(res.Node), Addr: res.Node.Addr}
			if res.Err != nil {
				row.Icon, row.Class, row.State, row.Info = "✖", "crit", "DOWN", res.Err.Error()
			} else {
				row.Icon, row.State = "✔", "RUNNING"
				row.Hostname = res.Value.Status.Hostname
				pending := probePending
				swept := sweptScopeCount(len(configuredScopes), pending)
				row.Class, row.Info = probeHostRowStatus(swept, len(configuredScopes), pending, settlingNow)
				row.Version = res.Value.Status.Version
				if res.Value.HasSystem {
					row.SysStr = fmt.Sprintf("load %.2f  mem %d%%", res.Value.System.LoadAvg1, res.Value.System.MemPct)
					if res.Value.System.OS != "" {
						row.SysStr += "  " + res.Value.System.OS
					}
				}
			}
			probeHostRows = append(probeHostRows, row)
		}

		pathRows := clusterPathRows(rows)
		pathsSummaryText, pathsSummaryClass := pathsSummary(pathRows)
		missingRoles := missingCoreRolesExcludingSelf(cfg)
		topoGraphSVG := topoBeaconGraphSVG(rows, missingRoles)
		topoSightRows := topoSightingRows(rows, time.Now())

		data := overviewData{
			Rows:                 rows,
			Mismatch:             scopesMismatch(rows),
			ConfigMismatch:       configHashMismatch(rows),
			BannerText:           bannerT,
			BannerClass:          bannerC,
			ClusterState:         overallState,
			ClusterClass:         overallClass,
			NodeIDsLine:          strings.Join(idParts, "  "),
			Witness:              witness,
			ArbiterQuorumText:    arbiterQuorumText,
			ArbiterQuorumClass:   arbiterQuorumClass,
			ConfigSaneText:       configSaneText,
			ConfigSaneClass:      configSaneClass,
			ConfigSaneTitle:      configSaneTitle,
			InterfaceHealthText:  interfaceHealthText,
			InterfaceHealthClass: interfaceHealthClass,
			TrunksText:           trunksText,
			TrunksClass:          trunksClass,
			TrunksTitle:          trunksTitle,
			ServingText:          servingText(totalServing, len(configuredScopes), len(disabledScopes), mgmtOnlyCount),
			ServingClass:         servingClass,
			Unreachable:          unreachable,
			UnreachableNames:     strings.Join(unreachableNodeNames(rows, mgmtOnlyAddrs), ", "),
			ActiveTokens:         activeTokens,
			ExpiredTokens:        expiredTokens,
			DaemonSummary:        daemonSummary,
			DaemonSummaryClass:   daemonSummaryClass,
			DaemonIssues:         daemonIssues,
			ProbeSummary:         probeSummary,
			ProbeSummaryClass:    probeSummaryClass,
			ProbeIssues:          probeIssues,
			Coherence:            append(checkCoherence(rows, tokens, selfObserverName(cfg)), checkPendingCoherence(cfg)...),
			StableSince:          stableSinceText,
			StableFor:            stableForText,
			ProbeHostRows:        probeHostRows,
			MissingRoles:         missingRoles,
			PathRows:             pathRows,
			PathsSummaryText:     pathsSummaryText,
			PathsSummaryClass:    pathsSummaryClass,
			TopoGraphSVG:         topoGraphSVG,
			TopoSightingRows:     topoSightRows,
		}
		data.ResetMessage, data.ResetMessageClass = resetResultBanner(r.URL.Query())
		renderTemplate(w, statusTmpl, data, "overview")
	}
}

func selfObserverName(cfg *WebConfig) string {
	if self, ok := selfNodeConfig(cfg); ok {
		return self.Name
	}
	return ""
}
