// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"dnshived/internal/agent"
	"dnshived/internal/arbiter"
	"dnshived/internal/cluster"
	"dnshived/internal/config"
	"dnshived/internal/leasesync"
	"dnshived/internal/tlspin"
)

// findTokenByRole returns the first api_token with the given role.
func findTokenByRole(cfg *config.Cluster, role string) (string, error) {
	for _, t := range cfg.APITokens {
		if t.Role == role {
			return t.Token, nil
		}
	}
	return "", fmt.Errorf("no %s-role api_token configured on this cluster", role)
}

func liveCoreNodes(cfg *config.Cluster, snapshot []cluster.PeerState) []probeConfigNode {
	tls := cfg.TLSCert != "" && cfg.TLSKey != ""
	nodes := []probeConfigNode{{Name: cfg.Role, Addr: cfg.ControlAddr, TLS: tls}}
	for _, p := range snapshot {
		if !p.Reachable || p.Identity == nil {
			continue
		}
		nodes = append(nodes, probeConfigNode{Name: p.Identity.Role, Addr: p.Addr, TLS: tls})
	}
	return nodes
}

// addProbeRequest is POST /api/v1/nodes/probe's body.
type addProbeRequest struct {
	Addr        string `json:"addr"`
	TrunkParent string `json:"trunk_parent"`
	OTP         string `json:"otp"`
}

// addProbeHandler adopts a NEW probe host into this already-live cluster.
func addProbeHandler(observer *cluster.Observer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req addProbeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if req.Addr == "" || req.OTP == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "addr and otp are both required"})
			return
		}

		cfg := currentConfig.Load()
		if cfg.Platform == nil || len(cfg.Platform.Workers) == 0 {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cluster has no configured worker trunks (platform.workers) yet — nothing for a probe host to cover"})
			return
		}
		probeToken, err := findTokenByRole(cfg, "probe")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		probeAdminToken, _ := findTokenByRole(cfg, "probe-admin") // optional — see doc comment above
		readonlyToken, _ := findTokenByRole(cfg, "readonly")

		pc := generatedProbeConfig{
			ListenAddr:        probeListenAddr,
			TrunkParent:       cfg.Platform.Workers[0],
			TrunkParents:      cfg.Platform.Workers,
			ClusterToken:      probeToken,
			ClusterNodes:      liveCoreNodes(cfg, observer.Snapshot()),
			LocalOctet:        deriveProbeLocalOctet(req.Addr),
			ProbeHelperSocket: defaultProbeHelperSocket,
			KnownVLANsPath:    defaultKnownVLANsPath,
		}
		if probeAdminToken != "" {
			pc.APITokens = append(pc.APITokens, config.APIToken{Name: "probe-admin", Token: probeAdminToken, Role: "admin"})
		}
		if readonlyToken != "" {
			pc.APITokens = append(pc.APITokens, config.APIToken{Name: "monitoring", Token: readonlyToken, Role: "readonly"})
		}

		raw, err := json.MarshalIndent(pc, "", "  ")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal probe config: " + err.Error()})
			return
		}

		if err := pushProbeAdopt(req.Addr, req.OTP, raw); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "push to probe: " + err.Error()})
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "name": "probe", "addr": req.Addr, "probe_admin_token": probeAdminToken})
	}
}

// findSurvivingPeer looks through the observer's current snapshot for a
// reachable peer whose claimed role is neither selfRole nor deadRole.
func findSurvivingPeer(snapshot []cluster.PeerState, selfRole, deadRole string) (addr, role string, err error) {
	for _, p := range snapshot {
		if !p.Reachable || p.Identity == nil {
			continue
		}
		if p.Identity.Role == selfRole || p.Identity.Role == deadRole {
			continue
		}
		return p.Addr, p.Identity.Role, nil
	}
	return "", "", fmt.Errorf("no reachable peer found with a role other than %q and %q — can't determine the third node's address", selfRole, deadRole)
}

func configuredThirdAddr(selfAddr string, peers []string, oldDeadAddr, newAddr string) string {
	skip := map[string]bool{hostOnly(selfAddr): true, hostOnly(newAddr): true}
	if oldDeadAddr != "" {
		skip[hostOnly(oldDeadAddr)] = true
	}
	var others []string
	for _, p := range peers {
		if !skip[hostOnly(p)] {
			others = append(others, p)
		}
	}
	if len(others) == 1 {
		return others[0]
	}
	return ""
}

// resolveOldDeadAddr picks the address the role being replaced last
// actually occupied.
func resolveOldDeadAddr(reqOldAddr, thirdAddr string, peers []string) string {
	if reqOldAddr != "" {
		return reqOldAddr
	}
	if thirdAddr == "" {
		return ""
	}
	var oldDeadAddr string
	for _, p := range peers {
		if p != thirdAddr {
			oldDeadAddr = p
		}
	}
	return oldDeadAddr
}

// lastIPv4Octet returns addr's host part's final dotted-quad segment (e.g.
// "22" from "192.168.0.22:9443"), or "" if addr isn't a recognizable IPv4
// host:port.
func lastIPv4Octet(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return ""
	}
	return parts[3]
}

// deriveProbeLocalOctet returns addr's own last IPv4 octet as an int, for
// generatedProbeConfig.LocalOctet.
func deriveProbeLocalOctet(addr string) int {
	octet := lastIPv4Octet(addr)
	if octet == "" {
		return 0
	}
	n, err := strconv.Atoi(octet)
	if err != nil {
		return 0
	}
	return n
}

// remapScopeNodeIPs deep-copies scopes with every entry's NodeIP
// recalculated for newAddr's own last IPv4 octet, keeping the same VLAN
// subnet/prefix untouched.
func remapScopeNodeIPs(scopes map[string]config.ScopeConfig, newAddr string) map[string]config.ScopeConfig {
	newOctet := lastIPv4Octet(newAddr)
	out := make(map[string]config.ScopeConfig, len(scopes))
	for name, sc := range scopes {
		if newOctet != "" && sc.NodeIP != "" {
			if slash := strings.Index(sc.NodeIP, "/"); slash > 0 {
				ipParts := strings.Split(sc.NodeIP[:slash], ".")
				if len(ipParts) == 4 {
					ipParts[3] = newOctet
					sc.NodeIP = strings.Join(ipParts, ".") + sc.NodeIP[slash:]
				}
			}
		}
		out[name] = sc
	}
	return out
}

// resetNodeIPOverridesForRole drops role's own node_ip_overrides entry
// from every scope, copy-on-write.
func resetNodeIPOverridesForRole(scopes map[string]config.ScopeConfig, role string) map[string]config.ScopeConfig {
	out := make(map[string]config.ScopeConfig, len(scopes))
	for name, sc := range scopes {
		if _, ok := sc.NodeIPOverrides[role]; ok {
			newOverrides := make(map[string]string, len(sc.NodeIPOverrides)-1)
			for k, v := range sc.NodeIPOverrides {
				if k != role {
					newOverrides[k] = v
				}
			}
			if len(newOverrides) == 0 {
				newOverrides = nil
			}
			sc.NodeIPOverrides = newOverrides
		}
		out[name] = sc
	}
	return out
}

// resetRoleAddressing returns a copy of cfg with every trace of role's own
// scope-addressing defaults reset.
func resetRoleAddressing(cfg config.Cluster, role, newAddr string) config.Cluster {
	out := cfg
	out.Scopes = resetNodeIPOverridesForRole(cfg.Scopes, role)
	newSuffix := lastIPv4Octet(newAddr)
	sd := config.ScopeDefaults{}
	if cfg.ScopeDefaults != nil {
		sd = *cfg.ScopeDefaults
	}
	_, hadEntry := sd.NodeIPSuffixes[role]
	if newSuffix != "" {
		if sd.NodeIPSuffixes == nil {
			sd.NodeIPSuffixes = make(map[string]string, 1)
		} else {
			newSuffixes := make(map[string]string, len(sd.NodeIPSuffixes)+1)
			for k, v := range sd.NodeIPSuffixes {
				newSuffixes[k] = v
			}
			sd.NodeIPSuffixes = newSuffixes
		}
		sd.NodeIPSuffixes[role] = newSuffix
		out.ScopeDefaults = &sd
	} else if hadEntry {
		newSuffixes := make(map[string]string, len(sd.NodeIPSuffixes)-1)
		for k, v := range sd.NodeIPSuffixes {
			if k != role {
				newSuffixes[k] = v
			}
		}
		if len(newSuffixes) == 0 {
			newSuffixes = nil
		}
		sd.NodeIPSuffixes = newSuffixes
		out.ScopeDefaults = &sd
	}
	return withRoleInterfaces(out, role, nil)
}

// roleInterfaces is a role's own interface names, from the pre-onboarding
// broadcast match.
type roleInterfaces struct {
	Workers map[string]string `json:"workers,omitempty"`
	Mgmt    string            `json:"mgmt,omitempty"`
}

// withRoleInterfaces replaces role's Platform overrides with ri (nil
// clears them); only names that differ from the canonical ones are kept.
func withRoleInterfaces(cfg config.Cluster, role string, ri *roleInterfaces) config.Cluster {
	if cfg.Platform == nil {
		return cfg
	}
	p := *cfg.Platform
	workers := make(map[string]map[string]string)
	for r, m := range p.WorkerOverrides {
		if r != role {
			workers[r] = m
		}
	}
	mgmt := make(map[string]string)
	for r, name := range p.MgmtOverrides {
		if r != role {
			mgmt[r] = name
		}
	}
	if ri != nil {
		own := make(map[string]string)
		for canonical, local := range ri.Workers {
			if local != "" && local != canonical {
				own[canonical] = local
			}
		}
		if len(own) > 0 {
			workers[role] = own
		}
		if ri.Mgmt != "" && ri.Mgmt != p.Mgmt {
			mgmt[role] = ri.Mgmt
		}
	}
	if len(workers) == 0 {
		workers = nil
	}
	if len(mgmt) == 0 {
		mgmt = nil
	}
	p.WorkerOverrides, p.MgmtOverrides = workers, mgmt
	cfg.Platform = &p
	return cfg
}

// matchCandidateInterfaces runs the pre-onboarding broadcast match against
// the candidate at addr and returns its interface names per canonical
// trunk plus its mgmt interface; warnings name trunks nothing was heard on.
func matchCandidateInterfaces(ctx context.Context, cfg *config.Cluster, addr string) (*roleInterfaces, []string, error) {
	if cfg.Platform == nil {
		return nil, nil, nil
	}
	var trunks []string
	canonicalOf := make(map[string]string)
	for _, canonical := range cfg.Platform.Workers {
		local := cfg.Platform.ResolveParent(cfg.Role, canonical)
		trunks = append(trunks, local)
		canonicalOf[local] = canonical
	}
	mapping, status, err := correlateCandidateInterfaces(ctx, trunks, addr)
	if err != nil {
		return nil, nil, err
	}
	ri := &roleInterfaces{Workers: make(map[string]string), Mgmt: status.MgmtInterface}
	var warnings []string
	for _, local := range sortedTrunkNames(mapping) {
		canonical := canonicalOf[local]
		if mapping[local] == "" {
			warnings = append(warnings, fmt.Sprintf("trunk %s: no candidate interface heard, keeping the name %s", canonical, canonical))
			continue
		}
		ri.Workers[canonical] = mapping[local]
	}
	return ri, warnings, nil
}

// resetRoleAddressingInConfig is resetRoleAddressing's load/validate/
// save/reload counterpart, mirroring updateTrustedHostsInConfig's own
// exact shape.
func resetRoleAddressingInConfig(cfgPath, role, newAddr string, ri *roleInterfaces) (config.Cluster, error) {
	current, err := config.Load(cfgPath)
	if err != nil {
		return config.Cluster{}, fmt.Errorf("load current config: %w", err)
	}
	updated := resetRoleAddressing(*current, role, newAddr)
	if ri != nil {
		updated = withRoleInterfaces(updated, role, ri)
	}
	if result := updated.ValidateExtended(); !result.OK() {
		return config.Cluster{}, fmt.Errorf("updated config failed validation: %v", result.Errors)
	}
	if err := config.Save(cfgPath, &updated); err != nil {
		return config.Cluster{}, fmt.Errorf("save: %w", err)
	}
	currentConfig.Store(&updated)
	return updated, nil
}

// resetRoleAddressingRequest is POST /api/v1/nodes/reset-role-addressing's
// body.
type resetRoleAddressingRequest struct {
	Role       string          `json:"role"`
	NewAddr    string          `json:"new_addr,omitempty"`
	Interfaces *roleInterfaces `json:"interfaces,omitempty"`
}

// resetRoleAddressingHandler is the receiving end pushed to every OTHER
// core node whenever a role's own address changes or the role itself goes
// away.
func resetRoleAddressingHandler(cfgPath string, observer *cluster.Observer, ag *agent.Agent) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req resetRoleAddressingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !isCoreRole(req.Role) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "role (worker-a/worker-b/arbiter) is required"})
			return
		}
		if err := applyRoleAddressingReset(cfgPath, req.Role, req.NewAddr, req.Interfaces, observer, ag); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func applyRoleAddressingReset(cfgPath, role, newAddr string, ri *roleInterfaces, observer *cluster.Observer, ag *agent.Agent) error {
	fresh, err := resetRoleAddressingInConfig(cfgPath, role, newAddr, ri)
	if err != nil {
		return err
	}
	observer.SetFallbackAddrs(computeFallbackTargets(&fresh, observer))
	clearStalePathReliability(observer, &fresh, role)
	applyAgentAddressing(ag, &fresh)
	return nil
}

func applyAgentAddressing(ag *agent.Agent, c *config.Cluster) {
	if ag == nil {
		return
	}
	if c.ScopeDefaults != nil {
		ag.SetNodeIPSuffixes(c.ScopeDefaults.NodeIPSuffixes)
	} else {
		ag.SetNodeIPSuffixes(nil)
	}
	ag.HotReloadScopes(c.Scopes)
}

// applyLivePeerSwap updates the running observer after the peer list on
// disk changed: oldAddr (if any, and different) leaves, newAddr joins.
func applyLivePeerSwap(observer *cluster.Observer, oldAddr, newAddr string) {
	if oldAddr != "" && oldAddr != newAddr {
		observer.RemovePeer(oldAddr)
	}
	observer.AddPeer(newAddr)
	log.Printf("[API:NODES] peer list applied live (added %s%s), no restart", newAddr, map[bool]string{true: ", removed " + oldAddr, false: ""}[oldAddr != "" && oldAddr != newAddr])
}

func clearStalePathReliability(observer *cluster.Observer, cfg *config.Cluster, role string) {
	if cfg.Platform == nil {
		return
	}
	for _, parent := range cfg.Platform.Workers {
		observer.ResetPathReliability(role, parent)
	}
}

// pushResetRoleAddressing calls resetRoleAddressingHandler on a remote
// core node — mirrors pushUpdateTrustedHosts's own exact shape.
func pushResetRoleAddressing(cfg *config.Cluster, addr, adminToken, role, newAddr string, ri *roleInterfaces) error {
	body, err := json.Marshal(resetRoleAddressingRequest{Role: role, NewAddr: newAddr, Interfaces: ri})
	if err != nil {
		return err
	}
	client, scheme := peerAdminClient(cfg)
	req, err := http.NewRequest(http.MethodPost, scheme+"://"+addr+"/api/v1/nodes/reset-role-addressing", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s", resp.Status)
	}
	return nil
}

// computeTrustedHosts returns the full 3-address TrustedHosts set for a
// replacement in progress.
func computeTrustedHosts(selfAddr, thirdAddr, newAddr string) []string {
	var hosts []string
	for _, addr := range []string{selfAddr, thirdAddr, newAddr} {
		if addr == "" {
			continue
		}
		hosts = append(hosts, hostOnly(addr))
	}
	sort.Strings(hosts)
	return hosts
}

// pushUpdateTrustedHosts calls POST /api/v1/nodes/update-trusted-hosts on
// a remote core node.
func peerAdminClient(cfg *config.Cluster) (client *http.Client, scheme string) {
	scheme = "http"
	client = &http.Client{Timeout: pushConfigTimeout}
	if cfg.TLSEnabled() {
		scheme = "https"
		client.Transport = &http.Transport{TLSClientConfig: tlspin.Config()}
	}
	return client, scheme
}

func pushUpdateTrustedHosts(cfg *config.Cluster, addr, adminToken string, hosts []string) error {
	body, err := json.Marshal(updateTrustedHostsRequest{Hosts: hosts})
	if err != nil {
		return err
	}
	client, scheme := peerAdminClient(cfg)
	req, err := http.NewRequest(http.MethodPost, scheme+"://"+addr+"/api/v1/nodes/update-trusted-hosts", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s", resp.Status)
	}
	return nil
}

// updateTrustedHostsRequest is POST /api/v1/nodes/update-trusted-hosts's
// body.
type updateTrustedHostsRequest struct {
	Hosts []string `json:"hosts"`
}

// updateTrustedHostsHandler also live-updates this daemon's own,
// already-running Observer (observer.SetTrustedHosts), not just the
// on-disk config.
func updateTrustedHostsHandler(cfgPath string, observer *cluster.Observer, arbiterMgr *arbiter.Manager, leaseSyncHandler *leasesync.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req updateTrustedHostsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Hosts) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "hosts (non-empty) is required"})
			return
		}
		if err := updateTrustedHostsInConfig(cfgPath, req.Hosts); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		applyLiveTrustedHosts(cfgPath, req.Hosts, observer, arbiterMgr, leaseSyncHandler)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func applyLiveTrustedHosts(cfgPath string, hosts []string, observer *cluster.Observer, arbiterMgr *arbiter.Manager, leaseSyncHandler *leasesync.Handler) {
	hostsToApply := hosts
	if freshCfg, err := config.Load(cfgPath); err == nil {
		base := append(append([]string(nil), hosts...), "127.0.0.1")
		hostsToApply = fallbackAddrsTrustedHosts(base, computeFallbackTargets(freshCfg, observer))
	}
	observer.SetTrustedHosts(hostsToApply)
	if arbiterMgr != nil {
		arbiterMgr.SetTrustedHosts(hostsToApply)
	}
	if leaseSyncHandler != nil {
		leaseSyncHandler.SetTrustedHosts(hostsToApply)
	}
}

func updateTrustedHostsInConfig(cfgPath string, hosts []string) error {
	current, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load current config: %w", err)
	}
	current.TrustedHosts = hosts
	if result := current.ValidateExtended(); !result.OK() {
		return fmt.Errorf("updated config failed validation: %v", result.Errors)
	}
	if err := config.Save(cfgPath, current); err != nil {
		return fmt.Errorf("save: %w", err)
	}
	currentConfig.Store(current)
	return nil
}

// removePeerInConfig drops addr from cfgPath's own Peers list, saves, and
// refreshes currentConfig.
func removePeerInConfig(cfgPath, addr string) (updated bool, err error) {
	current, err := config.Load(cfgPath)
	if err != nil {
		return false, fmt.Errorf("load current config: %w", err)
	}
	var kept []string
	found := false
	for _, p := range current.Peers {
		if p == addr {
			found = true
			continue
		}
		kept = append(kept, p)
	}
	if !found {
		return false, nil
	}
	current.Peers = kept
	if result := current.ValidateExtended(); !result.OK() {
		return false, fmt.Errorf("updated config failed validation: %v", result.Errors)
	}
	if err := config.Save(cfgPath, current); err != nil {
		return false, fmt.Errorf("save: %w", err)
	}
	currentConfig.Store(current)
	return true, nil
}

// removePeerRequest is POST /api/v1/nodes/remove-peer's body.
type removePeerRequest struct {
	Addr string `json:"addr"`
	Role string `json:"role,omitempty"`
}

// removePeerHandler drops Addr from Peers and its host from TrustedHosts,
// on disk and live, and resets Role's addressing when given.
func removePeerHandler(cfgPath string, observer *cluster.Observer, ag *agent.Agent, arbiterMgr *arbiter.Manager, leaseSyncHandler *leasesync.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req removePeerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Addr == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "addr is required"})
			return
		}
		if req.Role != "" && !isCoreRole(req.Role) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "role must be a core role"})
			return
		}
		updated, err := removePeerInConfig(cfgPath, req.Addr)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		observer.RemovePeer(req.Addr)

		if hosts, changed, err := removeTrustedHostInConfig(cfgPath, hostOnly(req.Addr)); err != nil {
			log.Printf("[API:NODES] remove %s from trusted_hosts: %v", hostOnly(req.Addr), err)
		} else if changed {
			applyLiveTrustedHosts(cfgPath, hosts, observer, arbiterMgr, leaseSyncHandler)
		}
		if req.Role != "" {
			if err := applyRoleAddressingReset(cfgPath, req.Role, "", nil, observer, ag); err != nil {
				log.Printf("[API:NODES] reset %s's addressing: %v", req.Role, err)
			}
		}

		if updated {
			go forwardRemovePeer(currentConfig.Load(), req)
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true, "updated": updated})
	}
}

func forwardRemovePeer(cfg *config.Cluster, req removePeerRequest) {
	adminToken, err := findTokenByRole(cfg, "admin")
	if err != nil {
		log.Printf("[API:NODES] forward removal of %s: %v", req.Addr, err)
		return
	}
	for _, peer := range cfg.Peers {
		if peer == req.Addr {
			continue
		}
		if err := pushRemovePeer(cfg, peer, adminToken, req.Addr, req.Role); err != nil {
			log.Printf("[API:NODES] forward removal of %s to %s: %v", req.Addr, peer, err)
			continue
		}
		log.Printf("[API:NODES] forwarded removal of %s to %s", req.Addr, peer)
	}
}

// removeTrustedHostInConfig drops host from TrustedHosts and saves.
func removeTrustedHostInConfig(cfgPath, host string) (hosts []string, changed bool, err error) {
	current, err := config.Load(cfgPath)
	if err != nil {
		return nil, false, fmt.Errorf("load current config: %w", err)
	}
	for _, h := range current.TrustedHosts {
		if h == host {
			changed = true
			continue
		}
		hosts = append(hosts, h)
	}
	if !changed || len(hosts) == 0 {
		return current.TrustedHosts, false, nil
	}
	if err := updateTrustedHostsInConfig(cfgPath, hosts); err != nil {
		return nil, false, err
	}
	return hosts, true, nil
}

// pushRemovePeer calls POST /api/v1/nodes/remove-peer on a remote core
// node so it persists the removal and stops probing staleAddr live.
func pushRemovePeer(cfg *config.Cluster, addr, adminToken, staleAddr, role string) error {
	body, err := json.Marshal(removePeerRequest{Addr: staleAddr, Role: role})
	if err != nil {
		return err
	}
	client, scheme := peerAdminClient(cfg)
	req, err := http.NewRequest(http.MethodPost, scheme+"://"+addr+"/api/v1/nodes/remove-peer", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s", resp.Status)
	}
	return nil
}

// offboardNodeRequest is POST /api/v1/nodes/offboard's body.
type offboardNodeRequest struct {
	Role string `json:"role"`
}

func offboardNodeHandler(cfgPath string, observer *cluster.Observer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req offboardNodeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !isCoreRole(req.Role) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "role (worker-a/worker-b/arbiter) is required"})
			return
		}

		cfg := currentConfig.Load()
		if req.Role == cfg.Role {
			writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "role": req.Role, "note": "this node is decommissioning itself now"})
			go func() {
				time.Sleep(300 * time.Millisecond)
				selfDecommission(cfgPath, "requested via POST /api/v1/nodes/offboard (self)")
			}()
			return
		}

		var targetAddr string
		for _, p := range observer.Snapshot() {
			if p.Reachable && p.Identity != nil && p.Identity.Role == req.Role {
				targetAddr = p.Addr
				break
			}
		}
		if targetAddr == "" {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no reachable peer currently claims role " + req.Role})
			return
		}
		adminToken, err := findTokenByRole(cfg, "admin")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if err := pushSelfDecommission(cfg, targetAddr, adminToken); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "offboard " + req.Role + " at " + targetAddr + ": " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "role": req.Role, "addr": targetAddr})
	}
}

// pushSelfDecommission calls POST /api/v1/self-decommission on a remote
// core node.
func pushSelfDecommission(cfg *config.Cluster, addr, adminToken string) error {
	client, scheme := peerAdminClient(cfg)
	req, err := http.NewRequest(http.MethodPost, scheme+"://"+addr+"/api/v1/self-decommission", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s", resp.Status)
	}
	return nil
}

// readFileBestEffort reads path, returning nil (not an error) when it
// doesn't exist.
func readFileBestEffort(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return data
}

// replaceNodeRequest is POST /api/v1/nodes/replace's body.
type replaceNodeRequest struct {
	Role    string `json:"role"`
	Addr    string `json:"addr"`
	OTP     string `json:"otp"`
	OldAddr string `json:"old_addr,omitempty"`
	// AllowUndetectedTrunks onboards even when the interface check heard
	// no candidate interface on a trunk.
	AllowUndetectedTrunks bool `json:"allow_undetected_trunks,omitempty"`
}

// isCoreRole reports whether role is one of the three fixed,
// cluster.json-bearing roles.
func isCoreRole(role string) bool {
	return role == config.RoleCore1 || role == config.RoleCore2 || role == config.RoleCore3
}

// thirdCoreRole returns whichever of the three fixed core roles is neither
// a nor b.
func thirdCoreRole(a, b string) string {
	for _, r := range [3]string{config.RoleCore1, config.RoleCore2, config.RoleCore3} {
		if r != a && r != b {
			return r
		}
	}
	return ""
}

func correctedWebConfigJSON(raw []byte, survivorRole, survivorAddr, thirdRole, thirdAddr, fallbackToken string, tlsEnabled bool) []byte {
	if len(raw) == 0 || survivorRole == "" || thirdRole == "" {
		return raw
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return raw
	}
	var existing []webConfigNode
	_ = json.Unmarshal(doc["nodes"], &existing)
	token := ""
	for _, n := range existing {
		if n.AdminToken != "" {
			token = n.AdminToken
			break
		}
	}
	if token == "" {
		token = fallbackToken
	}
	corrected := []webConfigNode{
		{Name: survivorRole, Addr: survivorAddr, TLS: tlsEnabled, AdminToken: token},
	}
	if thirdAddr != "" {
		corrected = append(corrected, webConfigNode{Name: thirdRole, Addr: thirdAddr, TLS: tlsEnabled, AdminToken: token})
	}
	nodesJSON, err := json.Marshal(corrected)
	if err != nil {
		return raw
	}
	doc["nodes"] = nodesJSON
	if tokenJSON, err := json.Marshal(token); err == nil {
		doc["self_admin_token"] = tokenJSON
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return raw
	}
	return out
}

func resolveReplacementControlAddr(reachAddr, conventionAddr string) string {
	host, _, err := net.SplitHostPort(reachAddr)
	if err != nil {
		addrErr, ok := err.(*net.AddrError)
		if !ok || addrErr.Err != "missing port in address" {
			return reachAddr
		}
		host = reachAddr
	}
	_, port, err := net.SplitHostPort(conventionAddr)
	if err != nil {
		return reachAddr
	}
	return net.JoinHostPort(host, port)
}

func replaceNodeHandler(cfgPath string, observer *cluster.Observer, ag *agent.Agent, arbiterMgr *arbiter.Manager, leaseSyncHandler *leasesync.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req replaceNodeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if req.Addr == "" || req.OTP == "" || !isCoreRole(req.Role) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "role (worker-a/worker-b/arbiter), addr, and otp are all required"})
			return
		}

		cfg := currentConfig.Load()
		if req.Role == cfg.Role {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "that's this node's own role — call this on a DIFFERENT surviving node"})
			return
		}

		newControlAddr := resolveReplacementControlAddr(req.Addr, cfg.ControlAddr)

		thirdAddr, _, err := findSurvivingPeer(observer.Snapshot(), cfg.Role, req.Role)
		if err != nil {
			thirdAddr = ""
		}

		oldDeadAddr := resolveOldDeadAddr(req.OldAddr, thirdAddr, cfg.Peers)
		if thirdAddr == "" {
			if configured := configuredThirdAddr(cfg.ControlAddr, cfg.Peers, oldDeadAddr, newControlAddr); configured != "" {
				log.Printf("[API:NODES] third member %s is configured but not reachable right now — keeping it as a peer and in trusted_hosts", configured)
				thirdAddr = configured
				if oldDeadAddr == "" {
					oldDeadAddr = resolveOldDeadAddr(req.OldAddr, thirdAddr, cfg.Peers)
				}
			}
		}
		addrChanged := oldDeadAddr != "" && oldDeadAddr != newControlAddr

		ri, ifaceWarnings, matchErr := matchCandidateInterfaces(r.Context(), cfg, req.Addr)
		if matchErr != nil {
			log.Printf("[API:NODES] interface match with %s failed: %v — keeping the cluster's interface names for %s", req.Addr, matchErr, req.Role)
			ifaceWarnings = append(ifaceWarnings, "interface match failed: "+matchErr.Error())
		}
		for _, warning := range ifaceWarnings {
			log.Printf("[API:NODES] %s: %s", req.Role, warning)
		}
		if len(ifaceWarnings) > 0 && !req.AllowUndetectedTrunks {
			log.Printf("[API:NODES] replace %s with %s refused: interface check incomplete, nothing changed", req.Role, req.Addr)
			writeJSON(w, http.StatusConflict, map[string]interface{}{
				"error":              "interface check incomplete — nothing was changed; fix cabling/bridges or confirm onboarding anyway",
				"interface_warnings": ifaceWarnings,
			})
			return
		}
		if ri != nil {
			log.Printf("[API:NODES] %s interfaces from the broadcast match: trunks %v, mgmt %q", req.Role, ri.Workers, ri.Mgmt)
		}

		resetCfg, resetErr := resetRoleAddressingInConfig(cfgPath, req.Role, newControlAddr, ri)
		if resetErr != nil {
			log.Printf("[API:NODES] reset %s's own scope-addressing defaults: %v", req.Role, resetErr)
			resetCfg = *cfg
		} else {
			observer.SetFallbackAddrs(computeFallbackTargets(&resetCfg, observer))
			clearStalePathReliability(observer, &resetCfg, req.Role)
			applyAgentAddressing(ag, &resetCfg)
		}

		replacement := resetCfg
		replacement.Role = req.Role
		replacement.ControlAddr = newControlAddr
		replacement.Scopes = remapScopeNodeIPs(resetCfg.Scopes, req.Addr)
		nodeSuffix, err := randomHex(6)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "generate node id: " + err.Error()})
			return
		}
		replacement.NodeID = req.Role + "-" + nodeSuffix
		if thirdAddr != "" {
			replacement.Peers = []string{cfg.ControlAddr, thirdAddr}
		} else {
			replacement.Peers = []string{cfg.ControlAddr}
		}
		newTrustedHosts := computeTrustedHosts(cfg.ControlAddr, thirdAddr, req.Addr)
		replacement.TrustedHosts = newTrustedHosts

		raw, err := json.MarshalIndent(&replacement, "", "  ")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal replacement config: " + err.Error()})
			return
		}

		adminToken, tokErr := findTokenByRole(cfg, "admin")

		payload := adoptPayload{
			ClusterJSON:    raw,
			WebUsersJSON:   readFileBestEffort(webUIUsersFile),
			WebConfigJSON:  correctedWebConfigJSON(readFileBestEffort("/etc/dnshived/web.json"), cfg.Role, cfg.ControlAddr, thirdCoreRole(cfg.Role, req.Role), thirdAddr, adminToken, cfg.TLSEnabled()),
			TLSCertPEM:     readFileBestEffort(webUITLSCertFile),
			TLSKeyPEM:      readFileBestEffort(webUITLSKeyFile),
			CoreTLSCertPEM: readFileBestEffort(cfg.TLSCert),
			CoreTLSKeyPEM:  readFileBestEffort(cfg.TLSKey),
		}
		if err := pushAdoptConfig(req.Addr, req.OTP, payload); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "push to replacement: " + err.Error()})
			return
		}

		selfTrustedErr := updateTrustedHostsInConfig(cfgPath, newTrustedHosts)
		if selfTrustedErr == nil {
			hostsToApply := newTrustedHosts
			if freshCfg, err := config.Load(cfgPath); err == nil {
				base := append(append([]string(nil), newTrustedHosts...), "127.0.0.1")
				hostsToApply = fallbackAddrsTrustedHosts(base, computeFallbackTargets(freshCfg, observer))
			}
			observer.SetTrustedHosts(hostsToApply)
			if arbiterMgr != nil {
				arbiterMgr.SetTrustedHosts(hostsToApply)
			}
			if leaseSyncHandler != nil {
				leaseSyncHandler.SetTrustedHosts(hostsToApply)
			}
		}
		var thirdTrustedErr error
		if thirdAddr == "" {
		} else if tokErr == nil {
			thirdTrustedErr = pushUpdateTrustedHosts(cfg, thirdAddr, adminToken, newTrustedHosts)
		} else {
			thirdTrustedErr = tokErr
		}

		selfUpdated, selfErr := updatePeerInConfig(cfgPath, oldDeadAddr, newControlAddr)
		var thirdErr error
		if thirdAddr == "" {
		} else if tokErr == nil {
			thirdErr = pushUpdatePeer(cfg, thirdAddr, adminToken, oldDeadAddr, newControlAddr)
		} else {
			thirdErr = tokErr
		}

		var thirdAddressingErr error
		if thirdAddr == "" {
			// Same sole-survivor reasoning as thirdErr/thirdTrustedErr
			// above — nothing to push yet.
		} else if tokErr == nil {
			thirdAddressingErr = pushResetRoleAddressing(cfg, thirdAddr, adminToken, req.Role, newControlAddr, ri)
		} else {
			thirdAddressingErr = tokErr
		}

		// Best-effort: tell the OLD (just-replaced) address to decommission
		// itself, if it's still reachable.
		var oldNodeDecommissionErr error
		if addrChanged && oldDeadAddr != "" && tokErr == nil {
			if err := pushSelfDecommission(cfg, oldDeadAddr, adminToken); err != nil {
				log.Printf("[API:NODES] best-effort decommission of old address %s: %v", oldDeadAddr, err)
				oldNodeDecommissionErr = err
			}
		}

		resp := map[string]interface{}{"ok": true, "peers_updated": true, "trusted_hosts_updated": true}
		if selfErr != nil {
			resp["self_peer_update_error"] = selfErr.Error()
		} else if selfUpdated {
			applyLivePeerSwap(observer, oldDeadAddr, newControlAddr)
		}
		if selfTrustedErr != nil {
			resp["self_trusted_hosts_update_error"] = selfTrustedErr.Error()
		}
		if thirdErr != nil {
			resp["third_node_peer_update_error"] = thirdErr.Error()
		}
		if thirdTrustedErr != nil {
			resp["third_node_trusted_hosts_update_error"] = thirdTrustedErr.Error()
		}
		if thirdAddressingErr != nil {
			resp["third_node_addressing_reset_error"] = thirdAddressingErr.Error()
		}
		if oldNodeDecommissionErr != nil {
			resp["old_node_decommission_error"] = oldNodeDecommissionErr.Error()
		}
		if len(ifaceWarnings) > 0 {
			resp["interface_warnings"] = ifaceWarnings
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// updatePeerInConfig reconciles cfgPath's own Peers list against (oldAddr,
// newAddr), saves, and refreshes currentConfig.
func updatePeerInConfig(cfgPath, oldAddr, newAddr string) (updated bool, err error) {
	current, err := config.Load(cfgPath)
	if err != nil {
		return false, fmt.Errorf("load current config: %w", err)
	}

	if newAddr == current.ControlAddr {
		return false, nil
	}
	var peers []string
	hasNew := false
	for _, p := range current.Peers {
		switch {
		case p == newAddr:
			if hasNew {
				continue
			}
			hasNew = true
		case oldAddr != "" && p == oldAddr:
			if hasNew {
				continue
			}
			p = newAddr
			hasNew = true
		}
		peers = append(peers, p)
	}
	if !hasNew {
		peers = append(peers, newAddr)
	}
	if slices.Equal(peers, current.Peers) {
		return false, nil
	}
	current.Peers = peers

	result := current.ValidateExtended()
	if !result.OK() {
		return false, fmt.Errorf("updated config failed validation: %v", result.Errors)
	}
	if err := config.Save(cfgPath, current); err != nil {
		return false, fmt.Errorf("save: %w", err)
	}
	currentConfig.Store(current)
	return true, nil
}

// updatePeerRequest is POST /api/v1/nodes/update-peer's body.
type updatePeerRequest struct {
	OldAddr string `json:"old_addr"`
	NewAddr string `json:"new_addr"`
}

func updatePeerHandler(cfgPath string, observer *cluster.Observer, ag *agent.Agent) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req updatePeerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NewAddr == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "new_addr is required"})
			return
		}
		updated, err := updatePeerInConfig(cfgPath, req.OldAddr, req.NewAddr)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if updated {
			applyLivePeerSwap(observer, req.OldAddr, req.NewAddr)
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true, "updated": updated})
	}
}

// pushUpdatePeer calls POST /api/v1/nodes/update-peer on a remote core
// node.
func pushUpdatePeer(cfg *config.Cluster, addr, adminToken, oldAddr, newAddr string) error {
	body, err := json.Marshal(updatePeerRequest{OldAddr: oldAddr, NewAddr: newAddr})
	if err != nil {
		return err
	}
	client, scheme := peerAdminClient(cfg)
	req, err := http.NewRequest(http.MethodPost, scheme+"://"+addr+"/api/v1/nodes/update-peer", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s", resp.Status)
	}
	return nil
}
