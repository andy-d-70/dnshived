// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"dnshived/internal/config"
	"dnshived/internal/tlspin"
)

// probeAdoptClient has a longer timeout than httpClient's default 5s.
var probeAdoptClient = &http.Client{
	Timeout:   15 * time.Second,
	Transport: &http.Transport{TLSClientConfig: tlspin.Config()},
}

// replaceClient covers a replace that first runs the interface match
// (about 4s of broadcast bursts per candidate interface).
var replaceClient = &http.Client{
	Timeout:   90 * time.Second,
	Transport: &http.Transport{TLSClientConfig: tlspin.Config()},
}

// siblingClient calls another dnshived-web instance's own :8443 (see
// siblingWebURL).
var siblingClient = &http.Client{
	Timeout:   15 * time.Second,
	Transport: &http.Transport{TLSClientConfig: tlspin.Config()},
}

// canonicalCoreRoles is the fixed display order for this project's three
// core roles.
var canonicalCoreRoles = []string{config.RoleCore1, config.RoleCore2, config.RoleCore3}

// sortNodesByCanonicalRole returns a NEW slice (never mutates nodes)
// ordered by canonicalCoreRoles.
func sortNodesByCanonicalRole(nodes []NodeConfig) []NodeConfig {
	rank := func(name string) int {
		for i, r := range canonicalCoreRoles {
			if r == name {
				return i
			}
		}
		return len(canonicalCoreRoles)
	}
	out := append([]NodeConfig{}, nodes...)
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i].Name) < rank(out[j].Name) })
	return out
}

// missingCoreRoles reports which of canonicalCoreRoles have no entry at
// all in nodes.
func missingCoreRoles(nodes []NodeConfig) []string {
	present := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		present[n.Name] = true
	}
	var missing []string
	for _, r := range canonicalCoreRoles {
		if !present[r] {
			missing = append(missing, r)
		}
	}
	return missing
}

func onboardAndReplaceTargets(nodes []NodeConfig, probeHosts []NodeConfig) (onboard, replace []string) {
	missing := missingCoreRoles(nodes)
	missingSet := make(map[string]bool, len(missing))
	for _, r := range missing {
		missingSet[r] = true
	}
	onboard = append(onboard, missing...)
	for _, r := range canonicalCoreRoles {
		if !missingSet[r] {
			replace = append(replace, r)
		}
	}
	if len(probeHosts) == 0 {
		onboard = append(onboard, probeRoleName)
	} else {
		replace = append(replace, probeRoleName)
	}
	return onboard, replace
}

// isLocalAddr reports whether hostport's host part matches one of this
// machine's own network interface addresses.
func isLocalAddr(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	target := net.ParseIP(host)
	if target == nil {
		return false
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if ok && ipNet.IP.Equal(target) {
				return true
			}
		}
	}
	return false
}

// selfNodeConfig answers "which core role is THIS dnshived-web instance
// running on, and at what real address".
func selfNodeConfig(cfg *WebConfig) (NodeConfig, bool) {
	port := "9443"
	for _, n := range cfg.Nodes {
		if _, p, err := net.SplitHostPort(n.Addr); err == nil && p != "" {
			port = p
			break
		}
	}
	token := nodesSharedToken(cfg)
	local := NodeConfig{Addr: "127.0.0.1:" + port, TLS: true, AdminToken: token}
	c, err := fetchConfigDirect(local)
	if err != nil || c.Role == "" || c.ControlAddr == "" {
		return NodeConfig{}, false
	}
	return NodeConfig{Name: c.Role, Addr: c.ControlAddr, TLS: true, AdminToken: token, DisplayName: cfg.SelfDisplayName}, true
}

// nodesIncludingSelf is cfg.Nodes plus this instance's own entry
// (selfNodeConfig), in canonical role order.
func nodesIncludingSelf(cfg *WebConfig) []NodeConfig {
	self, ok := selfNodeConfig(cfg)
	if !ok {
		return sortNodesByCanonicalRole(cfg.Nodes)
	}
	out := make([]NodeConfig, 0, len(cfg.Nodes)+1)
	for _, n := range cfg.Nodes {
		if n.Name == self.Name {
			continue
		}
		out = append(out, n)
	}
	out = append(out, self)
	return sortNodesByCanonicalRole(out)
}

// missingCoreRolesExcludingSelf is missingCoreRoles minus this instance's
// own role (selfNodeConfig).
func missingCoreRolesExcludingSelf(cfg *WebConfig) []string {
	self, ok := selfNodeConfig(cfg)
	missing := missingCoreRoles(cfg.Nodes)
	if !ok {
		return missing
	}
	out := make([]string, 0, len(missing))
	for _, r := range missing {
		if r != self.Name {
			out = append(out, r)
		}
	}
	return out
}

// siblingWebURL builds the base URL for a SIBLING dnshived-web instance.
func siblingWebURL(n NodeConfig, cfg *WebConfig) string {
	host, _, err := net.SplitHostPort(n.Addr)
	if err != nil {
		host = n.Addr
	}
	scheme := "http"
	listenAddr := cfg.ListenAddr
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		scheme = "https"
	}
	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		port = listenAddr
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}

// siblingNodes returns every core node OTHER than this one — the fan-
// out target list for add/removeProbeFormHandler.
func siblingNodes(cfg *WebConfig) []NodeConfig {
	var out []NodeConfig
	for _, n := range cfg.Nodes {
		if !isLocalAddr(n.Addr) {
			out = append(out, n)
		}
	}
	return out
}

// saveWebConfig writes cfg to path.
func saveWebConfig(path string, cfg *WebConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal web config: %w", err)
	}
	return os.WriteFile(path, data, 0o640)
}

// nodesSharedToken authenticates the fan-out calls one dnshived-web
// instance makes to its two siblings when a probe is added/removed.
func nodesSharedToken(cfg *WebConfig) string {
	if cfg.SelfAdminToken != "" {
		return cfg.SelfAdminToken
	}
	for _, n := range cfg.Nodes {
		if n.AdminToken != "" {
			return n.AdminToken
		}
	}
	if cfg.CoordinatorNode != nil && cfg.CoordinatorNode.AdminToken != "" {
		return cfg.CoordinatorNode.AdminToken
	}
	return ""
}

func checkSharedToken(cfg *WebConfig, r *http.Request) bool {
	want := nodesSharedToken(cfg)
	if want == "" {
		return false
	}
	got := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(got) <= len(prefix) || got[:len(prefix)] != prefix {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got[len(prefix):]), []byte(want)) == 1
}

// probeHostDisplayNames is a small template-side lookup helper.
func probeHostDisplayNames(hosts []NodeConfig) map[string]string {
	m := make(map[string]string, len(hosts))
	for _, h := range hosts {
		m[h.Addr] = h.DisplayName
	}
	return m
}

// probeHostDisplayNamesList is the ordered-slice counterpart of
// probeHostDisplayNames.
func probeHostDisplayNamesList(hosts []NodeConfig) []string {
	names := make([]string, len(hosts))
	for i, h := range hosts {
		names[i] = h.displayName()
	}
	return names
}

// renderNodesError is the shared error path for every node-management
// action handler below (add/remove/replace/rename).
func renderNodesError(w http.ResponseWriter, cfg *WebConfig, msg, back string) {
	http.Error(w, msg+" — back to "+back, http.StatusBadRequest)
}

// addProbeFormHandler is the operator-facing action (POST /nodes/probe/
// add).
func addProbeFormHandler(cfgPath string, ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		user, _ := userFromContext(r)
		addr := r.FormValue("addr")
		otp := r.FormValue("otp")
		if addr == "" || otp == "" {
			renderNodesError(w, cfg, "address and join code are both required", "/probes")
			return
		}
		op := pendingNodeOp{Kind: nodeOpReplace, Role: probeRoleName, Addr: addr, JoinCode: otp, StagedBy: user.Name, Onboarding: len(cfg.ProbeHosts) == 0}
		if err := stageNodeOp(op); err != nil {
			renderNodesError(w, cfg, err.Error(), "/probes")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<!doctype html><title>dnshived-web — probe onboarding staged</title>\n"+styleHTML+navHTML+"\n")
		fmt.Fprintf(w, "<h1 class=\"ok\">Staged — nothing applied yet</h1><p>%s is now a pending change. Review and commit (or discard) from <a href=\"/pending\">Pending changes</a>.</p>",
			template.HTMLEscapeString(op.Describe()))
	}
}

func executeReplaceProbe(cfgPath string, ref *configRef, userName string, op pendingNodeOp) (string, error) {
	cfg := ref.Load()
	pushVia := (*NodeConfig)(nil)
	if len(cfg.Nodes) > 0 {
		pushVia = &cfg.Nodes[0]
	} else if self, ok := selfNodeConfig(cfg); ok {
		pushVia = &self
	} else {
		return "", fmt.Errorf("no core node reachable to push the adoption through (no configured peers, and this node's own self-probe failed)")
	}

	var removeErrs []string
	if len(cfg.ProbeHosts) > 0 {
		removed := append([]NodeConfig{}, cfg.ProbeHosts...)
		newCfg := *cfg
		newCfg.ProbeHosts = nil
		if err := saveWebConfig(cfgPath, &newCfg); err != nil {
			return "", fmt.Errorf("removing the current probe host failed: %w", err)
		}
		ref.Store(&newCfg)
		cfg = &newCfg
		for _, old := range removed {
			if note := pushProbeSelfDecommission(old); note != "" {
				removeErrs = append(removeErrs, note)
			}
			for _, n := range siblingNodes(cfg) {
				if err := applyProbeChangeRemote(n, cfg, "/internal/nodes/probe/remove", NodeConfig{Addr: old.Addr}, nodesSharedToken(cfg)); err != nil {
					removeErrs = append(removeErrs, n.Name+": "+err.Error())
				}
			}
		}
	}

	body, _ := json.Marshal(map[string]string{"addr": op.Addr, "otp": op.JoinCode})
	req, err := http.NewRequest(http.MethodPost, pushVia.baseURL()+"/api/v1/nodes/probe", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if pushVia.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+pushVia.AdminToken)
	}
	resp, err := probeAdoptClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("adopt probe: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("adopt probe: %s: %s", resp.Status, string(respBody))
	}

	// The new probe's own local API no longer accepts the real cluster admin
	// token (cfg.Nodes[0].AdminToken).
	var adoptResp struct {
		ProbeAdminToken string `json:"probe_admin_token"`
	}
	json.Unmarshal(respBody, &adoptResp)

	entry := NodeConfig{Name: "probe", Addr: resolveProbeAddr(op.Addr), AdminToken: adoptResp.ProbeAdminToken}
	newCfg := *cfg
	newCfg.ProbeHosts = append(append([]NodeConfig{}, cfg.ProbeHosts...), entry)
	if err := saveWebConfig(cfgPath, &newCfg); err != nil {
		return "", fmt.Errorf("probe adopted, but saving local web.json failed: %w", err)
	}
	// Publishes live for every subsequent request on THIS instance — no
	// restart needed (see configref.go).
	ref.Store(&newCfg)

	fanoutErrs := append([]string{}, removeErrs...)
	for _, n := range siblingNodes(cfg) {
		if err := applyProbeChangeRemote(n, cfg, "/internal/nodes/probe/add", entry, nodesSharedToken(cfg)); err != nil {
			fanoutErrs = append(fanoutErrs, n.Name+": "+err.Error())
		}
	}

	for _, n := range cfg.Nodes {
		pushAudit(n, userName, "probe.add", "adopted probe "+op.Addr)
	}

	msg := fmt.Sprintf("Adopted %s and saved locally.\n", op.Addr)
	if len(fanoutErrs) > 0 {
		msg += fmt.Sprintf("\nWarning: the other core node(s) may not show this probe yet — retry there directly: %v\n", fanoutErrs)
	}
	return msg, nil
}

// removeProbeFormHandler (POST /nodes/probe/remove) is the reverse of
// addProbeFormHandler.
func removeProbeFormHandler(cfgPath string, ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		user, _ := userFromContext(r)
		addr := r.FormValue("addr")
		if addr == "" {
			renderNodesError(w, cfg, "address is required", "/probes")
			return
		}

		var kept []NodeConfig
		var removed *NodeConfig
		found := false
		for i, h := range cfg.ProbeHosts {
			if h.Addr == addr {
				found = true
				removed = &cfg.ProbeHosts[i]
				continue
			}
			kept = append(kept, h)
		}
		if !found {
			renderNodesError(w, cfg, "no probe host recorded at "+addr, "/probes")
			return
		}

		probeWipeNote := pushProbeSelfDecommission(*removed)

		newCfg := *cfg
		newCfg.ProbeHosts = kept
		if err := saveWebConfig(cfgPath, &newCfg); err != nil {
			renderNodesError(w, cfg, "saving local web.json failed: "+err.Error(), "/probes")
			return
		}
		ref.Store(&newCfg)

		var fanoutErrs []string
		for _, n := range siblingNodes(cfg) {
			if err := applyProbeChangeRemote(n, cfg, "/internal/nodes/probe/remove", NodeConfig{Addr: addr}, nodesSharedToken(cfg)); err != nil {
				fanoutErrs = append(fanoutErrs, n.Name+": "+err.Error())
			}
		}

		for _, n := range cfg.Nodes {
			pushAudit(n, user.Name, "probe.remove", "removed probe "+addr)
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<!doctype html><title>dnshived-web — probe removed</title><h1>Probe removed</h1><p>Removed %s locally.</p>", template.HTMLEscapeString(addr))
		if probeWipeNote != "" {
			fmt.Fprintf(w, "<p><strong>Note:</strong> %s</p>", template.HTMLEscapeString(probeWipeNote))
		}
		if len(fanoutErrs) > 0 {
			fmt.Fprintf(w, "<p><strong>Warning:</strong> the other core node(s) may not have removed it yet — retry there directly: %s</p>", template.HTMLEscapeString(fmt.Sprint(fanoutErrs)))
		}
		fmt.Fprint(w, `<p><a href="/probes">back to probes</a></p>`)
	}
}

// pushProbeSelfDecommission asks the probe host at n to wipe itself and
// re-enter bootstrap mode (POST /api/v1/self-decommission on
// cmd/dnshived-probe).
func pushProbeSelfDecommission(n NodeConfig) string {
	req, err := http.NewRequest(http.MethodPost, n.baseURL()+"/api/v1/self-decommission", nil)
	if err != nil {
		return "could not build the self-wipe request for " + n.Addr + " (" + err.Error() + ")"
	}
	if n.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+n.AdminToken)
	}
	resp, err := refreshProbeClient.Do(req)
	if err != nil {
		return "the probe host at " + n.Addr + " did not confirm self-wipe (" + err.Error() + ") — it may still be running; disable dnshived-probe on it or power it off"
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return "the probe host at " + n.Addr + " rejected the self-wipe (status " + resp.Status + ": " + string(body) + ") — disable dnshived-probe on it or power it off"
	}
	return ""
}

// applyProbeChangeRemote calls path (either /internal/nodes/probe/add or
// /internal/nodes/probe/remove) on a sibling dnshived-web instance.
func applyProbeChangeRemote(n NodeConfig, cfg *WebConfig, path string, entry NodeConfig, token string) error {
	body, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, siblingWebURL(n, cfg)+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := siblingClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s: %s", resp.Status, string(respBody))
	}
	return nil
}

// applyProbeAddHandler/applyProbeRemoveHandler are the fan-out receiver
// side.
func applyProbeAddHandler(cfgPath string, ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		if !checkSharedToken(cfg, r) {
			writeJSONWeb(w, http.StatusUnauthorized, map[string]string{"error": "invalid or missing token"})
			return
		}
		var entry NodeConfig
		if err := json.NewDecoder(r.Body).Decode(&entry); err != nil || entry.Addr == "" {
			writeJSONWeb(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		for _, h := range cfg.ProbeHosts {
			if h.Addr == entry.Addr {
				writeJSONWeb(w, http.StatusOK, map[string]bool{"ok": true}) // already present — idempotent, not an error
				return
			}
		}
		newCfg := *cfg
		newCfg.ProbeHosts = append(append([]NodeConfig{}, cfg.ProbeHosts...), entry)
		if err := saveWebConfig(cfgPath, &newCfg); err != nil {
			writeJSONWeb(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		ref.Store(&newCfg)
		writeJSONWeb(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func applyProbeRemoveHandler(cfgPath string, ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		if !checkSharedToken(cfg, r) {
			writeJSONWeb(w, http.StatusUnauthorized, map[string]string{"error": "invalid or missing token"})
			return
		}
		var entry NodeConfig
		if err := json.NewDecoder(r.Body).Decode(&entry); err != nil || entry.Addr == "" {
			writeJSONWeb(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		var kept []NodeConfig
		changed := false
		for _, h := range cfg.ProbeHosts {
			if h.Addr == entry.Addr {
				changed = true
				continue
			}
			kept = append(kept, h)
		}
		if !changed {
			writeJSONWeb(w, http.StatusOK, map[string]bool{"ok": true}) // already absent — idempotent
			return
		}
		newCfg := *cfg
		newCfg.ProbeHosts = kept
		if err := saveWebConfig(cfgPath, &newCfg); err != nil {
			writeJSONWeb(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		ref.Store(&newCfg)
		writeJSONWeb(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// replaceNodeFormHandler (POST /nodes/replace) proxies to cmd/dnshived's
// own POST /api/v1/nodes/replace.
func replaceNodeFormHandler(cfgPath string, ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		user, _ := userFromContext(r)
		role := r.FormValue("role")
		addr := r.FormValue("addr")
		otp := r.FormValue("otp")
		if role == "" || addr == "" || otp == "" {
			renderNodesError(w, cfg, "role, address, and join code are all required", "/config")
			return
		}
		op := pendingNodeOp{Kind: nodeOpReplace, Role: role, Addr: addr, JoinCode: otp, StagedBy: user.Name, Onboarding: roleIsMissing(cfg, role)}
		if err := stageNodeOp(op); err != nil {
			renderNodesError(w, cfg, err.Error(), "/config")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<!doctype html><title>dnshived-web — replace staged</title>\n"+styleHTML+navHTML+"\n")
		fmt.Fprintf(w, "<h1 class=\"ok\">Staged — nothing applied yet</h1><p>%s is now a pending change. Review and commit (or discard) from <a href=\"/pending\">Pending changes</a>.</p>",
			template.HTMLEscapeString(op.Describe()))
	}
}

// roleIsMissing reports whether role has no current entry at all.
func roleIsMissing(cfg *WebConfig, role string) bool {
	if role == probeRoleName {
		return len(cfg.ProbeHosts) == 0
	}
	if self, ok := selfNodeConfig(cfg); ok && self.Name == role {
		return false
	}
	for _, n := range cfg.Nodes {
		if n.Name == role {
			return false
		}
	}
	return true
}

func resolveReplacementControlAddr(reachAddr, conventionAddr string) string {
	host, ok := hostAllowingMissingPort(reachAddr)
	if !ok {
		return reachAddr
	}
	_, port, err := net.SplitHostPort(conventionAddr)
	if err != nil {
		return reachAddr
	}
	return net.JoinHostPort(host, port)
}

// probeBootstrapPort mirrors cmd/dnshived's own probeListenAddr constant's
// port.
const probeBootstrapPort = "9444"

// resolveProbeAddr is resolveReplacementControlAddr's probe-specific
// sibling.
func resolveProbeAddr(reachAddr string) string {
	host, ok := hostAllowingMissingPort(reachAddr)
	if !ok {
		return reachAddr
	}
	return net.JoinHostPort(host, probeBootstrapPort)
}

// hostAllowingMissingPort returns addr's host, treating a bare host (no
// port at all) as valid so the caller can still apply its convention port.
func hostAllowingMissingPort(addr string) (string, bool) {
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return host, true
	}
	if addrErr, ok := err.(*net.AddrError); ok && addrErr.Err == "missing port in address" {
		return addr, true
	}
	return "", false
}

func executeReplaceNode(cfgPath string, ref *configRef, userName string, op pendingNodeOp, allowUndetected bool) (string, error) {
	cfg := ref.Load()
	role, addr, otp := op.Role, op.Addr, op.JoinCode

	// oldAddr: this role's own last-known address, straight from our own
	// cfg.Nodes.
	var oldAddr string
	var survivor *NodeConfig
	for i := range cfg.Nodes {
		if cfg.Nodes[i].Name == role {
			oldAddr = cfg.Nodes[i].Addr
			continue
		}
		if survivor == nil {
			survivor = &cfg.Nodes[i]
		}
	}
	if survivor == nil {
		if self, ok := selfNodeConfig(cfg); ok && self.Name != role {
			survivor = &self
		}
	}
	if survivor == nil {
		return "", fmt.Errorf("no surviving core node found to handle the replacement")
	}

	body, _ := json.Marshal(map[string]interface{}{"role": role, "addr": addr, "otp": otp, "old_addr": oldAddr, "allow_undetected_trunks": allowUndetected})
	req, err := http.NewRequest(http.MethodPost, survivor.baseURL()+"/api/v1/nodes/replace", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if survivor.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+survivor.AdminToken)
	}
	resp, err := replaceClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("replace node: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusConflict {
		var refused struct {
			Warnings []string `json:"interface_warnings"`
		}
		json.Unmarshal(respBody, &refused)
		return "", fmt.Errorf("nothing was changed: the interface check did not detect every trunk on %s:\n  %s\nCheck the candidate's cabling/bridges and run Inspect again. To onboard anyway, go back to /pending, check \"Onboard anyway\", and commit again", addr, strings.Join(refused.Warnings, "\n  "))
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("replace node: %s: %s", resp.Status, string(respBody))
	}

	entry := NodeConfig{Name: role, Addr: resolveReplacementControlAddr(addr, survivor.Addr), TLS: true, AdminToken: nodesSharedToken(cfg)}
	nodes := append([]NodeConfig{}, cfg.Nodes...)
	updated := false
	for i := range nodes {
		if nodes[i].Name == role {
			nodes[i] = entry
			updated = true
			break
		}
	}
	if !updated {
		nodes = append(nodes, entry)
	}
	newCfg := *cfg
	newCfg.Nodes = nodes
	if err := saveWebConfig(cfgPath, &newCfg); err != nil {
		return fmt.Sprintf("%s adopted as %s via %s, but saving local web.json failed: %s\n", addr, role, survivor.Name, err), nil
	}
	ref.Store(&newCfg)

	var fanoutErrs []string
	for _, n := range siblingNodes(cfg) {
		if err := applyProbeChangeRemote(n, cfg, "/internal/nodes/replace", entry, nodesSharedToken(cfg)); err != nil {
			fanoutErrs = append(fanoutErrs, n.Name+": "+err.Error())
		}
	}

	for _, n := range cfg.Nodes {
		if n.Name == role {
			continue // superseded by entry itself
		}
		if err := applyProbeChangeRemote(entry, cfg, "/internal/nodes/replace", n, nodesSharedToken(cfg)); err != nil {
			fanoutErrs = append(fanoutErrs, addr+" (learning about "+n.Name+"): "+err.Error())
		}
	}

	pushAudit(*survivor, userName, "node.replace", fmt.Sprintf("replaced %s with %s (via %s)", role, addr, survivor.Name))

	full := nodesIncludingSelf(&newCfg)
	patchNodes := make([]probeClusterNodePatch, 0, len(full))
	for _, n := range full {
		patchNodes = append(patchNodes, probeClusterNodePatch{Name: n.Name, Addr: n.Addr, TLS: n.TLS})
	}
	var probeErrs []string
	for _, p := range newCfg.ProbeHosts {
		if err := pushProbeHostClusterNodes(p, patchNodes); err != nil {
			probeErrs = append(probeErrs, p.Name+": "+err.Error())
		}
	}

	msg := fmt.Sprintf("%s adopted as %s via %s.\n", addr, role, survivor.Name)
	if len(fanoutErrs) > 0 {
		msg += fmt.Sprintf("\nWarning: the other core node(s) may not show this yet — retry there directly: %v\n", fanoutErrs)
	}
	if len(probeErrs) > 0 {
		msg += fmt.Sprintf("\nWarning: could not refresh cluster_nodes on some probe host(s) — they may still be polling stale addresses until manually refreshed: %v\n", probeErrs)
	}
	return msg, nil
}

func wouldBreakQuorumFloor(role string, nodes []NodeConfig) bool {
	if !isCoreRole(role) {
		return false
	}
	remaining := 0
	for _, n := range nodes {
		if isCoreRole(n.Name) && n.Name != role {
			remaining++
		}
	}
	return remaining < 2
}

func wouldLeaveZeroCoreNodes(role string, nodes []NodeConfig) bool {
	if !isCoreRole(role) {
		return false
	}
	for _, n := range nodes {
		if isCoreRole(n.Name) && n.Name != role {
			return false
		}
	}
	return true
}

func offboardNodeFormHandler(ref *configRef, cfgPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		user, _ := userFromContext(r)
		role := r.FormValue("role")
		if role == "" {
			renderNodesError(w, cfg, "role is required", "/config")
			return
		}
		found := false
		for _, n := range cfg.Nodes {
			if n.Name == role {
				found = true
				break
			}
		}
		if !found {
			// Not in cfg.Nodes — check whether the target is THIS instance's own
			// role before giving up.
			if self, ok := selfNodeConfig(cfg); ok && self.Name == role {
				found = true
			}
		}
		if !found {
			renderNodesError(w, cfg, "no known node for role "+role, "/config")
			return
		}
		breaksFloor := wouldBreakQuorumFloor(role, nodesIncludingSelf(cfg))
		leavesZero := wouldLeaveZeroCoreNodes(role, nodesIncludingSelf(cfg))
		if err := stageNodeOp(pendingNodeOp{Kind: nodeOpOffboard, Role: role, BreaksQuorumFloor: breaksFloor, LeavesZeroCoreNodes: leavesZero, StagedBy: user.Name}); err != nil {
			renderNodesError(w, cfg, err.Error(), "/config")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<!doctype html><title>dnshived-web — offboard staged</title>\n"+styleHTML+navHTML+"\n")
		fmt.Fprintf(w, "<h1 class=\"ok\">Staged — nothing applied yet</h1><p>Offboarding %s is now a pending change. Review and commit (or discard) from <a href=\"/pending\">Pending changes</a>.</p>",
			template.HTMLEscapeString(role))
		if leavesZero {
			fmt.Fprint(w, "<p class=\"crit\">⚠ This is the LAST remaining core node. Committing this will PERMANENTLY WIPE the entire cluster — every credential, every scope, gone, with nothing left to recover from. Download a recent backup from <a href=\"/backup\">Config management</a> before you commit this.</p>")
		} else if breaksFloor {
			fmt.Fprint(w, "<p class=\"warn\">⚠ This would drop the cluster to fewer than 2 remaining core nodes — zero quorum, zero failover until a replacement is onboarded. Review carefully before committing.</p>")
		}
	}
}

func executeOffboardNode(ref *configRef, cfgPath string, userName string, op pendingNodeOp, confirmedWipe, force bool) (string, error) {
	cfg := ref.Load()
	role := op.Role

	var target *NodeConfig
	for i := range cfg.Nodes {
		if cfg.Nodes[i].Name == role {
			target = &cfg.Nodes[i]
			break
		}
	}
	if target == nil {
		if self, ok := selfNodeConfig(cfg); ok && self.Name == role {
			target = &self
		}
	}
	if target == nil {
		return "", fmt.Errorf("no known node for role %s", role)
	}
	breaksFloorAtCommit := wouldBreakQuorumFloor(role, nodesIncludingSelf(cfg))
	if leavesZeroAtCommit := wouldLeaveZeroCoreNodes(role, nodesIncludingSelf(cfg)); leavesZeroAtCommit && !confirmedWipe {
		return "", fmt.Errorf("this would offboard the LAST remaining core node and permanently wipe the entire cluster — go back to /pending, check \"I have a recent backup\", and commit again to proceed")
	}
	targetAddr := target.Addr

	if !force {
		body, _ := json.Marshal(map[string]string{"role": role})
		req, err := http.NewRequest(http.MethodPost, target.baseURL()+"/api/v1/nodes/offboard", bytes.NewReader(body))
		if err != nil {
			return "", fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if target.AdminToken != "" {
			req.Header.Set("Authorization", "Bearer "+target.AdminToken)
		}
		resp, err := probeAdoptClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("offboard node: %w", err)
		}
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("offboard node: %s: %s", resp.Status, string(respBody))
		}
	}

	var kept []NodeConfig
	for _, n := range cfg.Nodes {
		if n.Name == role {
			continue
		}
		kept = append(kept, n)
	}
	newCfg := *cfg
	newCfg.Nodes = kept
	if err := saveWebConfig(cfgPath, &newCfg); err != nil {
		return fmt.Sprintf("Offboarded %s (%s), but saving local web.json failed: %s\n", role, targetAddr, err), nil
	}
	ref.Store(&newCfg)

	var fanoutErrs []string
	for _, n := range siblingNodes(cfg) {
		if err := applyProbeChangeRemote(n, cfg, "/internal/nodes/remove", NodeConfig{Name: role}, nodesSharedToken(cfg)); err != nil {
			fanoutErrs = append(fanoutErrs, n.Name+": "+err.Error())
		}
	}

	auditSummary := fmt.Sprintf("offboarded %s (%s) — it is now decommissioning itself back to bootstrap mode", role, targetAddr)
	if force {
		auditSummary = fmt.Sprintf("FORCE-offboarded %s (%s) — it was unreachable and was NOT told to decommission itself; removed from every surviving node's own membership only", role, targetAddr)
	}
	pushAudit(*target, userName, "node.offboard", auditSummary)

	full := nodesIncludingSelf(&newCfg)
	patchNodes := make([]probeClusterNodePatch, 0, len(full))
	for _, n := range full {
		patchNodes = append(patchNodes, probeClusterNodePatch{Name: n.Name, Addr: n.Addr, TLS: n.TLS})
	}
	var probeErrs []string
	for _, p := range newCfg.ProbeHosts {
		if err := pushProbeHostClusterNodes(p, patchNodes); err != nil {
			probeErrs = append(probeErrs, p.Name+": "+err.Error())
		}
	}

	var msg string
	if force {
		msg = fmt.Sprintf("Force-removed %s (%s) from every surviving node's own membership. It was NOT reachable and was NOT told to wipe its own state or decommission itself — if it ever reconnects to any network this cluster can see, it may still present real, valid credentials for a cluster it's no longer part of. Wipe or reimage it before that can happen.\n", role, targetAddr)
	} else {
		msg = fmt.Sprintf("Offboarded %s (%s) — it is decommissioning itself now: closing gates, tearing down interfaces, deleting every credential file, and re-entering bootstrap mode. It should reappear under \"Discovered on the network\" within a few seconds.\n", role, targetAddr)
	}
	if breaksFloorAtCommit {
		msg += "\n⚠ WARNING: the cluster now has fewer than 2 remaining core nodes — zero quorum, zero witness-token majority, zero failover until a replacement is onboarded.\n"
	}
	if len(fanoutErrs) > 0 {
		msg += fmt.Sprintf("\nWarning: the other core node(s) may still show it — retry there directly: %v\n", fanoutErrs)
	}
	if len(probeErrs) > 0 {
		msg += fmt.Sprintf("\nWarning: could not refresh cluster_nodes on some probe host(s) — they may still be polling stale addresses until manually refreshed: %v\n", probeErrs)
	}
	return msg, nil
}

// renameNodeFormHandler (POST /nodes/rename) sets a node's cosmetic
// DisplayName.
func renameNodeFormHandler(cfgPath string, ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		user, _ := userFromContext(r)
		addr := r.FormValue("addr")
		displayName := r.FormValue("display_name")
		if addr == "" {
			renderNodesError(w, cfg, "address is required", "/config")
			return
		}

		back := "/config"
		if isProbeHostAddr(cfg, addr) {
			back = "/probes"
		}

		newCfg := *cfg
		found := applyRename(&newCfg, addr, displayName)
		if !found {
			// Not in cfg.Nodes/cfg.ProbeHosts at all — check whether the target IS
			// this instance itself before giving up.
			if !isLocalAddr(addr) {
				renderNodesError(w, cfg, "no node recorded at "+addr, back)
				return
			}
			newCfg.SelfDisplayName = displayName
		}
		if err := saveWebConfig(cfgPath, &newCfg); err != nil {
			renderNodesError(w, cfg, "saving local web.json failed: "+err.Error(), back)
			return
		}
		ref.Store(&newCfg)

		var fanoutErrs []string
		for _, n := range siblingNodes(cfg) {
			if err := applyProbeChangeRemote(n, cfg, "/internal/nodes/rename", NodeConfig{Addr: addr, DisplayName: displayName}, nodesSharedToken(cfg)); err != nil {
				fanoutErrs = append(fanoutErrs, n.Name+": "+err.Error())
			}
		}

		for _, n := range cfg.Nodes {
			pushAudit(n, user.Name, "node.rename", fmt.Sprintf("set display name for %s to %q", addr, displayName))
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<!doctype html><title>dnshived-web — node renamed</title><h1>Display name saved</h1>")
		if len(fanoutErrs) > 0 {
			fmt.Fprintf(w, "<p><strong>Warning:</strong> the other core node(s) may not show this rename yet — retry there directly: %s</p>", template.HTMLEscapeString(fmt.Sprint(fanoutErrs)))
		}
		fmt.Fprintf(w, `<p><a href="%s">back</a></p>`, back)
	}
}

// isProbeHostAddr reports whether addr belongs to a configured probe host
// rather than a core cluster node.
func isProbeHostAddr(cfg *WebConfig, addr string) bool {
	for _, p := range cfg.ProbeHosts {
		if p.Addr == addr {
			return true
		}
	}
	return false
}

// applyRename sets cfg.Nodes/cfg.ProbeHosts to freshly-built slices with
// DisplayName set on whichever entry matches addr.
func applyRename(cfg *WebConfig, addr, displayName string) bool {
	for i, n := range cfg.Nodes {
		if n.Addr == addr {
			nodes := append([]NodeConfig{}, cfg.Nodes...)
			nodes[i].DisplayName = displayName
			cfg.Nodes = nodes
			return true
		}
	}
	for i, h := range cfg.ProbeHosts {
		if h.Addr == addr {
			hosts := append([]NodeConfig{}, cfg.ProbeHosts...)
			hosts[i].DisplayName = displayName
			cfg.ProbeHosts = hosts
			return true
		}
	}
	return false
}

// applyRenameHandler (POST /internal/nodes/rename) is the sibling fan-out
// receiver.
func applyVIPHost(cfgPath string, ref *configRef, host string) error {
	cfg := ref.Load()
	if cfg.VIPHost == host {
		return nil
	}
	newCfg := *cfg
	newCfg.VIPHost = host
	if err := saveWebConfig(cfgPath, &newCfg); err != nil {
		return err
	}
	ref.Store(&newCfg)
	log.Printf("[WEB:VIP] vip_host now %q (was %q)", host, cfg.VIPHost)
	return nil
}

type vipHostUpdate struct {
	VIPHost string `json:"vip_host"`
}

// applyVIPHostHandler is POST /internal/web/vip-host — a sibling's web
// UI telling this one that a committed config moved the mgmt VIP.
func applyVIPHostHandler(cfgPath string, ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !checkSharedToken(ref.Load(), r) {
			writeJSONWeb(w, http.StatusUnauthorized, map[string]string{"error": "invalid or missing token"})
			return
		}
		var req vipHostUpdate
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.VIPHost != "" && net.ParseIP(req.VIPHost) == nil) {
			writeJSONWeb(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if err := applyVIPHost(cfgPath, ref, req.VIPHost); err != nil {
			writeJSONWeb(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSONWeb(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// propagateVIPHost applies host locally and on every sibling web UI.
func propagateVIPHost(cfgPath string, ref *configRef, host string) {
	if err := applyVIPHost(cfgPath, ref, host); err != nil {
		log.Printf("[WEB:VIP] update own vip_host: %v", err)
	}
	cfg := ref.Load()
	body, _ := json.Marshal(vipHostUpdate{VIPHost: host})
	for _, n := range siblingNodes(cfg) {
		req, err := http.NewRequest(http.MethodPost, siblingWebURL(n, cfg)+"/internal/web/vip-host", bytes.NewReader(body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		if tok := nodesSharedToken(cfg); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := siblingClient.Do(req)
		if err != nil {
			log.Printf("[WEB:VIP] update vip_host on %s: %v", n.Name, err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			log.Printf("[WEB:VIP] update vip_host on %s: %s", n.Name, resp.Status)
		}
		resp.Body.Close()
	}
}

func applyRenameHandler(cfgPath string, ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		if !checkSharedToken(cfg, r) {
			writeJSONWeb(w, http.StatusUnauthorized, map[string]string{"error": "invalid or missing token"})
			return
		}
		var entry NodeConfig
		if err := json.NewDecoder(r.Body).Decode(&entry); err != nil || entry.Addr == "" {
			writeJSONWeb(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		newCfg := *cfg
		if !applyRename(&newCfg, entry.Addr, entry.DisplayName) {
			writeJSONWeb(w, http.StatusOK, map[string]bool{"ok": true}) // no matching node here — idempotent, not an error
			return
		}
		if err := saveWebConfig(cfgPath, &newCfg); err != nil {
			writeJSONWeb(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		ref.Store(&newCfg)
		writeJSONWeb(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// applyNodeRemoveHandler (POST /internal/nodes/remove) is the sibling
// fan-out receiver for offboardNodeFormHandler.
func applyNodeRemoveHandler(cfgPath string, ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		if !checkSharedToken(cfg, r) {
			writeJSONWeb(w, http.StatusUnauthorized, map[string]string{"error": "invalid or missing token"})
			return
		}
		var entry NodeConfig
		if err := json.NewDecoder(r.Body).Decode(&entry); err != nil || entry.Name == "" {
			writeJSONWeb(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		var kept []NodeConfig
		changed := false
		for _, n := range cfg.Nodes {
			if n.Name == entry.Name {
				changed = true
				continue
			}
			kept = append(kept, n)
		}
		if !changed {
			writeJSONWeb(w, http.StatusOK, map[string]bool{"ok": true}) // already absent — idempotent
			return
		}
		newCfg := *cfg
		newCfg.Nodes = kept
		if err := saveWebConfig(cfgPath, &newCfg); err != nil {
			writeJSONWeb(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		ref.Store(&newCfg)
		writeJSONWeb(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// applyNodeReplaceHandler (POST /internal/nodes/replace) is the sibling
// fan-out receiver for replaceNodeFormHandler.
func applyNodeReplaceHandler(cfgPath string, ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		if !checkSharedToken(cfg, r) {
			writeJSONWeb(w, http.StatusUnauthorized, map[string]string{"error": "invalid or missing token"})
			return
		}
		var entry NodeConfig
		if err := json.NewDecoder(r.Body).Decode(&entry); err != nil || entry.Name == "" || entry.Addr == "" {
			writeJSONWeb(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		nodes := append([]NodeConfig{}, cfg.Nodes...)
		updated := false
		for i := range nodes {
			if nodes[i].Name == entry.Name {
				nodes[i] = entry
				updated = true
				break
			}
		}
		if !updated {
			nodes = append(nodes, entry)
		}
		newCfg := *cfg
		newCfg.Nodes = nodes
		if err := saveWebConfig(cfgPath, &newCfg); err != nil {
			writeJSONWeb(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		ref.Store(&newCfg)
		writeJSONWeb(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func writeJSONWeb(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
