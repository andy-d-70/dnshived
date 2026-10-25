// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"dnshived/internal/loglevel"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"dnshived/internal/agent"
	"dnshived/internal/config"
	"dnshived/internal/daemonstatus"
	"dnshived/internal/helper"
)

// decommissioning is set true as the very first action selfDecommission
// takes, before anything else.
var decommissioning atomic.Bool

// decommissionUnits are the per-role systemd units a self-decommission
// stops directly, in order.
var decommissionUnits = []string{
	"dnshived-relay.service",
	"dnshived-dnsrelay.service",
	"dnshived-keepalived.service",
	"dnshived-keepalived-mgmt.service",
	"dnshived-web.service",
	"dnshived-web-helper.service",
}

// stopUnitFunc issues `systemctl disable --now` (disable, not just stop)
// through the helper.
var stopUnitFunc = func(unit string) error {
	return helper.NewClient(helperSocketFor(currentConfig.Load())).ManageUnit("disable-now", unit)
}

// listDnsmasqInstances returns every dnshived-dnsmasq@*.service instance
// systemd currently knows about on this host.
func listDnsmasqInstances() []string {
	seen := make(map[string]bool)
	add := func(args ...string) {
		out, err := exec.Command("systemctl", args...).Output()
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) == 0 {
				continue
			}
			name := f[0]
			if strings.HasPrefix(name, "dnshived-dnsmasq@") && strings.HasSuffix(name, ".service") && name != "dnshived-dnsmasq@.service" {
				seen[name] = true
			}
		}
	}
	add("list-units", "--all", "--no-legend", "--plain", "dnshived-dnsmasq@*.service")
	add("list-unit-files", "--no-legend", "--plain", "dnshived-dnsmasq@*.service")
	units := make([]string, 0, len(seen))
	for u := range seen {
		units = append(units, u)
	}
	return units
}

// finishDecommissionFunc has the helper schedule the restart into
// bootstrap mode (a transient unit starting dnshived.service a few
// seconds later) and then stop itself.
var finishDecommissionFunc = func() error {
	return helper.NewClient(helperSocketFor(currentConfig.Load())).FinishDecommission()
}

// resetHelperStateFunc drops the helper's add-scopes allowlist and its
// state directory.
var resetHelperStateFunc = func() error {
	return helper.NewClient(helperSocketFor(currentConfig.Load())).ResetScopeState()
}

// deletePath removes path (file or directory, recursively) outright — no
// archive, no rename-aside.
func deletePath(path string) {
	if path == "" {
		return
	}
	if _, err := os.Stat(path); err != nil {
		return // never existed — nothing to remove, not an error
	}
	if err := os.RemoveAll(path); err != nil {
		loglevel.Warnf("[DECOMMISSION] remove %s: %v", path, err)
		return
	}
	loglevel.Infof("[DECOMMISSION] removed %s", path)
}

// decommStep is one verified decommission action's own outcome.
type decommStep struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

func verifiedStopUnit(unit string) decommStep {
	err := stopUnitFunc(unit)
	st := daemonstatus.Query(unit, "")
	if st.ActiveState == "active" || st.ActiveState == "activating" {
		detail := fmt.Sprintf("still %s after stop", st.ActiveState)
		if err != nil {
			detail = fmt.Sprintf("stop command failed (%v) and unit is still %s", err, st.ActiveState)
		}
		return decommStep{Name: unit, OK: false, Detail: detail}
	}
	return decommStep{Name: unit, OK: true, Detail: fmt.Sprintf("confirmed %s", st.ActiveState)}
}

func verifiedDeletePath(path string) decommStep {
	if path == "" {
		return decommStep{Name: "(unset path)", OK: true, Detail: "nothing to delete"}
	}
	deletePath(path)
	if _, err := os.Stat(path); err == nil {
		return decommStep{Name: path, OK: false, Detail: "still present after deletion"}
	} else if !os.IsNotExist(err) {
		return decommStep{Name: path, OK: false, Detail: fmt.Sprintf("could not verify removal: %v", err)}
	}
	return decommStep{Name: path, OK: true, Detail: "confirmed gone"}
}

// verifiedSweepDir empties dir but keeps it: the package owns the
// directory and the unprivileged daemon cannot remove it from /var/lib.
func verifiedSweepDir(dir string) decommStep {
	if dir == "" {
		return decommStep{Name: "(unset path)", OK: true, Detail: "nothing to delete"}
	}
	sweepDir(dir)
	entries, err := os.ReadDir(dir)
	switch {
	case os.IsNotExist(err):
		return decommStep{Name: dir, OK: true, Detail: "confirmed gone"}
	case err != nil:
		return decommStep{Name: dir, OK: false, Detail: fmt.Sprintf("could not verify: %v", err)}
	case len(entries) > 0:
		return decommStep{Name: dir, OK: false, Detail: fmt.Sprintf("%d entr(y/ies) left after emptying", len(entries))}
	}
	return decommStep{Name: dir, OK: true, Detail: "confirmed empty"}
}

// decommissionReportRequest is POST /api/v1/decommission-report's body.
type decommissionReportRequest struct {
	Role   string       `json:"role"`
	Addr   string       `json:"addr"`
	Reason string       `json:"reason"`
	Steps  []decommStep `json:"steps"`
}

// pushDecommissionReport fans the completed step report out to every
// surviving peer.
func pushDecommissionReport(cfg *config.Cluster, reason string, steps []decommStep) {
	if cfg == nil {
		return
	}
	adminToken, err := findTokenByRole(cfg, "admin")
	if err != nil {
		loglevel.Warnf("[DECOMMISSION] find admin token for report push: %v", err)
		return
	}
	body, err := json.Marshal(decommissionReportRequest{
		Role:   cfg.Role,
		Addr:   cfg.ControlAddr,
		Reason: reason,
		Steps:  steps,
	})
	if err != nil {
		loglevel.Warnf("[DECOMMISSION] marshal report: %v", err)
		return
	}
	client, scheme := peerAdminClient(cfg)
	selfAddr := hostOnly(cfg.ControlAddr)
	pushed := false
	for _, peer := range cfg.Peers {
		if hostOnly(peer) == selfAddr {
			continue
		}
		req, err := http.NewRequest(http.MethodPost, scheme+"://"+peer+"/api/v1/decommission-report", bytes.NewReader(body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp, err := client.Do(req)
		if err != nil {
			loglevel.Warnf("[DECOMMISSION] push report to %s: %v", peer, err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			loglevel.Warnf("[DECOMMISSION] push report to %s: %s", peer, resp.Status)
			continue
		}
		loglevel.Infof("[DECOMMISSION] report pushed to %s", peer)
		pushed = true
	}
	if !pushed {
		loglevel.Warnf("[DECOMMISSION] report could not be pushed to any surviving peer — see this node's own log above for the full record")
	}
}

// decommissionReportHandler receives a peer's pushed report (see
// pushDecommissionReport above) and simply logs it clearly.
func decommissionReportHandler(w http.ResponseWriter, r *http.Request) {
	var req decommissionReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid report body"})
		return
	}
	loglevel.Infof("[DECOMMISSION:PEER_REPORT] received from %s (%s) — reason=%q, %d step(s):", req.Role, req.Addr, req.Reason, len(req.Steps))
	for _, s := range req.Steps {
		loglevel.Stepf(s.OK, "[DECOMMISSION:PEER_REPORT]   %s: ok=%v %s", s.Name, s.OK, s.Detail)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// sweepDir deletes every entry directly inside dir (files and
// subdirectories alike, via deletePath), but leaves dir itself in place.
func sweepDir(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return // doesn't exist or unreadable — nothing to sweep
	}
	for _, entry := range entries {
		deletePath(filepath.Join(dir, entry.Name()))
	}
}

// notifyPeersOfSelfRemoval pushes an updated TrustedHosts set (this node's
// own address removed) AND a Peers-removal (pushRemovePeer) to every
// surviving Peer.
func notifyPeersOfSelfRemoval(cfg *config.Cluster) {
	adminToken, err := findTokenByRole(cfg, "admin")
	if err != nil {
		loglevel.Warnf("[DECOMMISSION] find admin token for trusted_hosts update: %v", err)
		return
	}
	selfAddr := hostOnly(cfg.ControlAddr)
	var newHosts []string
	for _, h := range cfg.TrustedHosts {
		if h != selfAddr {
			newHosts = append(newHosts, h)
		}
	}
	for _, peer := range cfg.Peers {
		if hostOnly(peer) == selfAddr {
			continue
		}
		if err := pushUpdateTrustedHosts(cfg, peer, adminToken, newHosts); err != nil {
			loglevel.Warnf("[DECOMMISSION] remove self from trusted_hosts on %s: %v", peer, err)
			continue
		}
		loglevel.Infof("[DECOMMISSION] removed self (%s) from trusted_hosts on %s", selfAddr, peer)

		if err := pushRemovePeer(cfg, peer, adminToken, cfg.ControlAddr, cfg.Role); err != nil {
			loglevel.Warnf("[DECOMMISSION] remove self (%s) from peers on %s: %v", cfg.ControlAddr, peer, err)
			continue
		}
		loglevel.Infof("[DECOMMISSION] removed self (%s) from peers on %s", cfg.ControlAddr, peer)

		if err := pushResetRoleAddressing(cfg, peer, adminToken, cfg.Role, "", nil); err != nil {
			loglevel.Warnf("[DECOMMISSION] reset %s's own scope-addressing defaults on %s: %v", cfg.Role, peer, err)
		} else {
			loglevel.Infof("[DECOMMISSION] reset %s's own scope-addressing defaults on %s", cfg.Role, peer)
		}
	}
}

func selfDecommission(cfgPath, reason string) {
	decommissioning.Store(true)
	loglevel.Infof("[DECOMMISSION] starting: %s", reason)

	// steps accumulates a verified outcome for every destructive action below.
	var steps []decommStep

	cfg := currentConfig.Load()
	var dataDirPath string
	if cfg != nil {
		dataDirPath = dataDir(cfg)
		emergencyCloseAllGates(cfg)
		notifyPeersOfSelfRemoval(cfg)

		helperClient := helper.NewClient(helperSocketFor(cfg))
		if hostIfaces, err := agent.HostOwnedTrunkInterfaces(cfg.Platform, cfg.Role); err != nil {
			loglevel.Warnf("[DECOMMISSION] enumerate host interfaces: %v — falling back to config-driven sweep only", err)
			for scope, sc := range cfg.Scopes {
				sc.Parent = cfg.Platform.ResolveParent(cfg.Role, sc.Parent)
				agent.DeleteInterface(helperClient, scope, sc)
			}
		} else {
			names := make([]string, 0, len(hostIfaces))
			for name := range hostIfaces {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				spec := hostIfaces[name]
				step := agent.DeleteOrphanInterface(helperClient, name, spec.Parent, spec.VLANID)
				loglevel.Stepf(step.OK, "[DECOMMISSION] interface %s: ok=%v %s", name, step.OK, step.Detail)
				steps = append(steps, decommStep{Name: "interface " + name, OK: step.OK, Detail: step.Detail})
			}
		}
		for scope := range cfg.Scopes {
			unit := "dnshived-dnsmasq@" + scope + ".service"
			s := verifiedStopUnit(unit)
			steps = append(steps, s)
			if !s.OK {
				loglevel.Warnf("[DECOMMISSION] stop %s: %s", unit, s.Detail)
			}
		}

		before := len(cfg.Peers) + 1
		after := len(cfg.Peers)
		steps = append(steps, decommStep{
			Name: "arbiter quorum", OK: true,
			Detail: fmt.Sprintf("this node's own aux-arbiter instance is leaving — cluster quorum drops from %d-of-%d to %d-of-%d arbiter voices until a replacement joins", before, before, after, after),
		})
	} else {
		loglevel.Infof("[DECOMMISSION] no current config loaded — skipping gate close/interface teardown/per-scope dnsmasq stop")
	}

	for _, unit := range listDnsmasqInstances() {
		s := verifiedStopUnit(unit)
		steps = append(steps, s)
		if !s.OK {
			loglevel.Warnf("[DECOMMISSION] stop %s: %s", unit, s.Detail)
		}
	}

	for _, unit := range decommissionUnits {
		s := verifiedStopUnit(unit)
		steps = append(steps, s)
		if !s.OK {
			loglevel.Warnf("[DECOMMISSION] stop %s: %s", unit, s.Detail)
		}
	}

	steps = append(steps, verifiedSweepDir(dataDirPath))
	for _, p := range []string{webUIUsersFile, "/etc/dnshived/web.json", webUITLSCertFile, webUITLSKeyFile} {
		steps = append(steps, verifiedDeletePath(p))
	}
	if err := resetHelperStateFunc(); err != nil {
		steps = append(steps, decommStep{Name: "helper scope allowlist", OK: false, Detail: err.Error()})
	} else {
		steps = append(steps, decommStep{Name: "helper scope allowlist", OK: true, Detail: "reset, state directory removed"})
	}
	if cfg != nil {
		steps = append(steps, verifiedDeletePath(cfg.TLSCert))
		steps = append(steps, verifiedDeletePath(cfg.TLSKey))
	}

	sweepDir(filepath.Dir(cfgPath))

	cfgStep := verifiedDeletePath(cfgPath)
	steps = append(steps, cfgStep)
	if !cfgStep.OK {
		loglevel.Infof("[DECOMMISSION] %s still present after deletion — aborting before touching dnshived-helper", cfgPath)
		pushDecommissionReport(cfg, reason, steps)
		return
	}

	loglevel.Infof("[DECOMMISSION] step report (%d step(s)):", len(steps))
	for _, s := range steps {
		loglevel.Stepf(s.OK, "[DECOMMISSION]   %s: ok=%v %s", s.Name, s.OK, s.Detail)
	}
	pushDecommissionReport(cfg, reason, steps)

	if err := finishDecommissionFunc(); err != nil {
		loglevel.Warnf("[DECOMMISSION] helper finish-decommission (restart watchdog + helper stop): %v — node may not come back up on its own", err)
	}

	loglevel.Infof("[DECOMMISSION] re-executing into bootstrap mode")
	reExecFunc()
}

// selfDecommissionHandler is POST /api/v1/self-decommission —
// admin-gated, runs ON the target node itself.
func selfDecommissionHandler(cfgPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		go func() {
			time.Sleep(300 * time.Millisecond)
			selfDecommission(cfgPath, "requested via POST /api/v1/self-decommission")
		}()
	}
}
