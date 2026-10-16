// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dnshived/internal/agent"
	"dnshived/internal/arbiter"
	"dnshived/internal/auditlog"
	"dnshived/internal/auth"
	"dnshived/internal/backup"
	"dnshived/internal/cluster"
	"dnshived/internal/config"
	"dnshived/internal/coordplane"
	"dnshived/internal/daemonstatus"
	"dnshived/internal/desired"
	"dnshived/internal/dhcpcentralrender"
	"dnshived/internal/dhcplease"
	"dnshived/internal/dhcprelay"
	"dnshived/internal/discovery"
	"dnshived/internal/dnscentralrender"
	"dnshived/internal/dnsmasqlog"
	"dnshived/internal/eventlog"
	"dnshived/internal/fencing"
	"dnshived/internal/fsm"
	"dnshived/internal/helper"
	"dnshived/internal/identity"
	"dnshived/internal/ifname"
	"dnshived/internal/lease"
	"dnshived/internal/leasesync"
	"dnshived/internal/nftgate"
	"dnshived/internal/state"
	"dnshived/internal/sysinfo"
	"dnshived/internal/tlspin"
	"dnshived/internal/topobeacon"
)

var version = "0.9.7-dev"

var currentConfig atomic.Pointer[config.Cluster]

// writeJSON centralizes the Content-Type header + status + encode sequence
// duplicated across every JSON route below.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("[http:error] failed to encode response: %v", err)
	}
}

// isDnsmasqUnit and scopeFromDnsmasqUnit parse a per-scope dnsmasq unit
// name for POST /api/v1/daemons/{unit}/restart.
func isDnsmasqUnit(unit string) bool {
	return strings.HasPrefix(unit, "dnshived-dnsmasq@") && strings.HasSuffix(unit, ".service")
}

func scopeFromDnsmasqUnit(unit string) string {
	return strings.TrimSuffix(strings.TrimPrefix(unit, "dnshived-dnsmasq@"), ".service")
}

// planeWarningStore holds the most recent agent.CheckPlaneHealth()
// findings for /api/v1/status to report.
type planeWarningStore struct {
	mu    sync.Mutex
	found []agent.PlaneHealth
}

func (s *planeWarningStore) set(found []agent.PlaneHealth) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.found = found
}

// strings renders the current findings as short human-readable lines.
func (s *planeWarningStore) strings() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.found) == 0 {
		return nil
	}
	out := make([]string, 0, len(s.found))
	for _, f := range s.found {
		out = append(out, formatPlaneHealthMsg(f))
	}
	return out
}

func formatPlaneHealthMsg(f agent.PlaneHealth) string {
	msg := f.What + " " + f.Detail
	if f.Scope != "" {
		msg = "scope " + f.Scope + ": " + msg
	}
	return msg
}

// planeHealthKey identifies WHICH piece of infrastructure a finding is
// about (not its detail text, which may vary tick to tick, e.g.
// ActiveState wording).
func planeHealthKey(f agent.PlaneHealth) string {
	return f.Scope + "|" + f.What
}

// driftActionText describes what happens next for a finding, for the
// AGENT:DRIFT log/event line.
func driftActionText(f agent.PlaneHealth) string {
	if f.What == "lease_db_gap" {
		return "self-healed from peer"
	}
	if f.Healable {
		return "reconstructing"
	}
	if f.What == "relay_socket_stale" {
		return "reloading dhcp+dns relay"
	}
	if f.What == "lease_db_conflict" {
		return "report only, never auto-resolved"
	}
	if f.What == "trunk_link_down" {
		return "every scope on this trunk force-closed until carrier returns"
	}
	return "report only, not auto-healed"
}

var planeWarnings = &planeWarningStore{}

// backupPayloadFor builds what a backup's own plaintext actually marshals.
func backupPayloadFor(cfg *config.Cluster, ag *agent.Agent, observer *cluster.Observer) backup.Payload {
	payload := backup.Payload{Cluster: *cfg}
	merged := ag.MergedDHCPLeaseSnapshot()
	if len(merged) > 0 {
		entries := make([]backup.LeaseEntry, 0, len(merged))
		for _, l := range merged {
			entries = append(entries, backup.LeaseEntry{MAC: l.MAC, IP: l.IP, ExpiresAt: l.ExpiresAt, Hostname: l.Hostname})
		}
		payload.DHCPLeases = &backup.LeaseData{Leases: entries}
	}
	local := ag.TrunkReliabilitySnapshot()
	path := observer.PathReliabilitySnapshot()
	if len(local) > 0 || len(path) > 0 {
		payload.Reliability = &backup.ReliabilityData{Local: local, Path: path}
	}
	return payload
}

func main() {
	cfgPath := flag.String("config", "/etc/dnshived/cluster.json", "cluster config path")
	showVersion := flag.Bool("version", false, "print version and exit")
	checkConfig := flag.Bool("check-config", false, "validate config and exit")
	emergencyCloseGates := flag.Bool("emergency-close-gates", false,
		"close every configured scope's DHCP gate and exit — for ExecStopPost, not for manual use")
	bootstrapAddr := flag.String("bootstrap-addr", ":80",
		"plain-HTTP listen address for bootstrap mode — only used when no config file "+
			"exists yet. Port 80 (not 9443, the real API's own port once configured) is "+
			"deliberate: firewall/NAT policies far more commonly leave plain HTTP open "+
			"than an arbitrary high port, and this only ever serves the unauthenticated, "+
			"first-boot setup wizard — never the real cluster API, which still binds "+
			"whatever port this node's own control_addr names once committed. Also the "+
			"port advertised over LAN discovery, and the one the automated adopt-push "+
			"mechanism connects to — see runBootstrapMode's own doc comment")
	bootstrapTLSAddr := flag.String("bootstrap-tls-addr", ":443",
		"self-signed-HTTPS listen address for bootstrap mode, served alongside "+
			"--bootstrap-addr on the identical routes — a fresh node has no way to know "+
			"yet whether it'll be reached by an operator's browser or an already-running "+
			"cluster's own automated discovery/adopt push, so both ports are always "+
			"served together")
	bootstrapDataDir := flag.String("bootstrap-data-dir", defaultBootstrapDataDir,
		"data_dir bootstrap mode checks for prior configuration — only used when no config file exists yet; production deploys should never need this, it exists for running multiple bootstrap-mode instances on one host during testing")
	bootstrapOTPPath := flag.String("bootstrap-otp-path", defaultBootstrapOTPPath,
		"where bootstrap mode persists its join code — only used when no config file exists yet; same testing-only rationale as --bootstrap-data-dir")
	flag.Parse()

	if *showVersion {
		fmt.Println("dnshived", version)
		os.Exit(0)
	}

	config.LocalName = ifname.Resolve
	setBeaconLinkUp(defaultHelperSocket)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		if *checkConfig {
			fmt.Printf("✖ Config invalid: %v\n", err)
			os.Exit(1)
		}
		if *emergencyCloseGates {
			os.Exit(0)
		}
		if errors.Is(err, os.ErrNotExist) {
			runBootstrapMode(*cfgPath, *bootstrapAddr, *bootstrapTLSAddr, *bootstrapDataDir, *bootstrapOTPPath)
		}
		log.Fatalf("config: %v", err)
	}
	currentConfig.Store(cfg)
	setBeaconLinkUp(helperSocketFor(cfg))

	if *checkConfig {
		result := cfg.ValidateExtended()
		if len(result.Errors) > 0 {
			fmt.Printf("✖ Config validation failed (%d error(s)):\n", len(result.Errors))
			for _, e := range result.Errors {
				fmt.Printf("  ✖ %s\n", e)
			}
		}
		if len(result.Warnings) > 0 {
			fmt.Printf("⚠ Warnings (%d):\n", len(result.Warnings))
			for _, w := range result.Warnings {
				fmt.Printf("  ⚠ %s\n", w)
			}
		}
		if result.OK() {
			fmt.Printf("✔ Config valid: %s (schema v%d, role=%s, cluster=%s)\n",
				*cfgPath, cfg.SchemaVersion, cfg.Role, cfg.ClusterID)
			if len(result.Warnings) > 0 {
				os.Exit(0) // valid but with warnings
			}
			os.Exit(0)
		}
		os.Exit(1)
	}

	if *emergencyCloseGates {
		os.Exit(emergencyCloseAllGates(cfg))
	}

	incarnation, err := state.NextIncarnation(cfg.DataDir)
	if err != nil {
		log.Fatalf("incarnation: %v", err)
	}

	self := identity.Identity{
		ClusterID:   cfg.ClusterID,
		NodeID:      cfg.NodeID,
		Role:        cfg.Role,
		Epoch:       1,
		Incarnation: incarnation,
		Generation:  1,
		Version:     version,
		Token:       fencing.Token{Epoch: 1, Generation: 1},
	}

	log.Printf("dnshived %s starting — node=%s role=%s cluster=%s incarnation=%d",
		version, self.NodeID, self.Role, self.ClusterID, self.Incarnation)

	if cfg.TLSEnabled() {
		tlspin.SetFile(cfg.TLSCert)
	}
	observer := cluster.NewObserver(self, cfg.ControlAddr, cfg.Peers, cfg.PSK)
	observer.SetTLS(cfg.TLSEnabled())
	observer.SetReliabilityDir(cfg.DataDir)
	fallbackAddrs := computeFallbackTargets(cfg, observer)
	trustedHostsBase := append(append([]string(nil), cfg.TrustedHosts...), "127.0.0.1")
	trustedHostsWithFallback := fallbackAddrsTrustedHosts(trustedHostsBase, fallbackAddrs)
	observer.SetTrustedHosts(trustedHostsWithFallback)
	observer.SetFallbackAddrs(fallbackAddrs)
	probeInterval := cfg.ProbeInterval()
	observer.Start(probeInterval)
	log.Printf("[CLUSTER:INIT] visibility: handshaking %d peers every %s", len(cfg.Peers), probeInterval)

	machine := fsm.New(self.Epoch)

	if cfg.LegacyDryRun {
		log.Printf("[CONFIG:WARN] dry_run no longer exists — removing it from %s. This node SERVES real DHCP/DNS.", *cfgPath)
		if err := config.Save(*cfgPath, cfg); err != nil {
			log.Printf("[CONFIG:ERROR] remove dry_run from %s: %v", *cfgPath, err)
		}
	}

	var scopeDefs []desired.ScopeDefinition
	if cfg.HasScopes() {
		scopeDefs = desired.ScopesFromConfig(cfg.Scopes)
		log.Printf("[CONFIG:INIT] %d scopes configured: %v", len(scopeDefs), cfg.ScopeNames())
	} else {
		log.Printf("[CONFIG:INIT] no scopes configured — nothing to serve yet")
	}

	engine := desired.New(self.Generation, scopeDefs, 60*time.Second, 0)
	engine.SetTrunkGraceRange(10*time.Second, 55*time.Second)
	leaseMgr := lease.NewManager(cfg.Role, lease.DefaultTTL)

	watermark, err := fencing.NewWatermark(dataDir(cfg))
	if err != nil {
		log.Fatalf("fencing: %v", err)
	}
	log.Printf("[FENCING:INIT] watermark loaded: %s", watermark.Current())

	ag := agent.New(cfg.Role, self.NodeID, self.Incarnation, cfg.PSK, dataDir(cfg), cfg.Scopes, observer)
	ag.SetTLS(cfg.TLSEnabled())
	ag.SetGlobalDNSRecords(cfg.GlobalDNSRecords)
	ag.SetLocalDomains(cfg.LocalDomains)
	ag.SetDefaultDHCPOptions(cfg.DefaultDHCPOptions)
	if cfg.ScopeDefaults != nil {
		ag.SetCentralDNSUpstream(cfg.ScopeDefaults.Upstream)
		ag.SetNodeIPSuffixes(cfg.ScopeDefaults.NodeIPSuffixes)
	}
	ag.SetCoreDNSAddress(cfg.CoreDNSAddress)
	ag.SetCoreDHCPAddress(cfg.CoreDHCPAddress)
	ag.SetCoreDNSQueryLogging(cfg.CoreDNSQueryLogging)
	ag.SetDNSRelayCacheSize(cfg.DNSRelayCacheSize)
	ag.SetDNSRelayCacheMaxBytes(cfg.DNSRelayCacheMaxBytes)
	ag.SetSanityCheckDisabled(cfg.SanityCheckDisabled)
	ag.SetSelfAddr(cfg.ControlAddr)
	ag.SetMgmtIface(mgmtIfaceFromConfig(cfg))
	ag.SetPlatform(cfg.Platform)

	ag.StartTopoBeacon(context.Background(), cfg.Role, topobeacon.DefaultInterval)

	ag.StartScopeBeacons(context.Background(), cfg.Role, func(scope, peerRole string) {
		log.Printf("[AGENT:SCOPEBEACON] %s unreachable on scope %s — triggering a local sanity check", peerRole, scope)
		ag.TriggerOrphanCheck("SCOPEBEACON_CHECK")
	})

	ag.SetHelper(helper.NewClient(helperSocketFor(cfg)))
	log.Printf("[AGENT:INIT] privileged operations via %s", helperSocketFor(cfg))

	if isCoreRole(cfg.Role) {
		ag.SetLeasePersistDir(dataDir(cfg))
	}

	leaseCheckDirty := make(chan struct{}, 1)
	signalLeaseCheck := func() {
		select {
		case leaseCheckDirty <- struct{}{}:
		default:
		}
	}
	if isCoreRole(cfg.Role) {
		onLocalLeaseEvent := func(ev leasesync.LocalEvent) {
			ag.HandleLocalLeaseEvent(ev.Action, ev.MAC, ev.IP, ev.Hostname, ev.ExpiresAt)
			signalLeaseCheck()
		}
		if _, err := leasesync.ListenLocal(leasesync.SocketPath, onLocalLeaseEvent); err != nil {
			log.Printf("[AGENT:ERROR] dhcp lease-sync local listener: %v", err)
		} else {
			log.Printf("[AGENT:INIT] dhcp lease-sync local listener on %s", leasesync.SocketPath)
		}
	}

	// Event ring buffer — captures all state transitions regardless of log
	// level.
	events := eventlog.New(1000, self.NodeID)

	removed, decommissionSaveErr := ag.DecommissionRemovedScopes()
	for _, name := range removed {
		events.Add("WARNING", "AGENT:DECOMMISSION", "scope "+name+" removed from config — infrastructure torn down")
	}
	if decommissionSaveErr != nil {
		events.Add("WARNING", "AGENT:DECOMMISSION", "failed to persist known-scopes.json: "+decommissionSaveErr.Error()+
			" — already-removed scopes will be re-attempted on next restart until this is fixed")
	}

	ag.ConstructPlane() // Build the permanent network plane for every configured scope.

	if err := ag.RenderMgmtVIPConfig(cfg.MgmtVIP, cfg.Platform); err != nil {
		log.Printf("[AGENT:ERROR] render management VIP config: %v", err)
	}

	log.Printf("[AGENT:INIT] real service control enabled")

	auditLogger := auditlog.New(filepath.Join(dataDir(cfg), "audit.log"))

	// Auth middleware — wraps all API handlers when api_tokens is configured.
	authMw := auth.New(cfg.APITokens)
	if authMw.Enabled() {
		log.Printf("[AUTH:INIT] API authentication enabled (%d token(s))", len(cfg.APITokens))
	}

	identity := newMonotonicIdentity(self.Epoch, self.Generation, observer.UpdateSelf)
	machine.OnEpochChange = func(epoch uint64) {
		if !identity.applyEpoch(epoch) {
			return // stale, out-of-order callback — see monotonicIdentity's doc comment
		}
		log.Printf("[FSM:EPOCH] epoch advanced to %d", epoch)
		events.Add("INFO", "FSM:EPOCH", fmt.Sprintf("epoch advanced to %d", epoch))
	}
	engine.OnGenerationChange = func(gen uint64) {
		if !identity.applyGeneration(gen) {
			return
		}
		log.Printf("[DESIRED:GEN] generation advanced to %d", gen)
		events.Add("INFO", "DESIRED:GEN", fmt.Sprintf("generation advanced to %d", gen))
	}

	// Unified reconcile loop.
	rl := &reconcileLoop{
		observer:    observer,
		machine:     machine,
		engine:      engine,
		leaseMgr:    leaseMgr,
		watermark:   watermark,
		ag:          ag,
		events:      events,
		role:        cfg.Role,
		incarnation: self.Incarnation,
	}
	go func() {
		ticker := time.NewTicker(lease.DefaultRenewInterval)
		defer ticker.Stop()
		// eventDebounce guards only the event-triggered path against a rapidly
		// flapping peer causing back-to-back reconciles.
		const eventDebounce = 750 * time.Millisecond
		var lastEventFired time.Time
		for {
			select {
			case <-ticker.C:
				rl.once("timer")
			case <-observer.Changed():
				if time.Since(lastEventFired) < eventDebounce {
					continue
				}
				lastEventFired = time.Now()
				rl.once("peer reachability change")
			}
		}
	}()

	// Network-plane-intact watchdog.
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		prevDrift := make(map[string]agent.PlaneHealth)
		for range ticker.C {
			if decommissioning.Load() {
				continue
			}
			found := ag.CheckPlaneHealth()
			planeWarnings.set(found)

			ag.RefreshMgmtVIPStateCache()

			for _, role := range []string{config.RoleCore1, config.RoleCore2, config.RoleCore3} {
				if role == cfg.Role {
					continue
				}
				observer.ObserveMgmtBeacon(role, ag.TopoHeardMgmtFrom(role))
			}

			curDrift := make(map[string]agent.PlaneHealth, len(found))
			for _, f := range found {
				key := planeHealthKey(f)
				curDrift[key] = f
				if _, already := prevDrift[key]; !already {
					msg := formatPlaneHealthMsg(f)
					log.Printf("[AGENT:DRIFT] %s — %s", msg, driftActionText(f))
					events.Add("WARNING", "AGENT:DRIFT", msg)
				}
			}
			for key, f := range prevDrift {
				if _, stillDrifted := curDrift[key]; !stillDrifted {
					msg := formatPlaneHealthMsg(f) + " — resolved"
					log.Printf("[AGENT:HEALED] %s", msg)
					events.Add("INFO", "AGENT:HEALED", msg)
				}
			}
			prevDrift = curDrift
		}
	}()

	if isCoreRole(cfg.Role) {
		go func() {
			const debounceInterval = 8 * time.Second
			const fallbackInterval = 60 * time.Second
			debounceTimer := time.NewTimer(fallbackInterval)
			if !debounceTimer.Stop() {
				<-debounceTimer.C
			}
			fallbackTicker := time.NewTicker(fallbackInterval)
			defer fallbackTicker.Stop()
			prevLeaseDrift := make(map[string]agent.PlaneHealth)
			runCheck := func() {
				if decommissioning.Load() {
					return
				}
				found := ag.CheckLeaseSanity()
				curDrift := make(map[string]agent.PlaneHealth, len(found))
				for _, f := range found {
					key := planeHealthKey(f)
					curDrift[key] = f
					if _, already := prevLeaseDrift[key]; !already {
						msg := formatPlaneHealthMsg(f)
						log.Printf("[AGENT:DRIFT] %s — %s", msg, driftActionText(f))
						events.Add("WARNING", "AGENT:DRIFT", msg)
					}
				}
				for key, f := range prevLeaseDrift {
					if _, stillDrifted := curDrift[key]; !stillDrifted {
						msg := formatPlaneHealthMsg(f) + " — resolved"
						log.Printf("[AGENT:HEALED] %s", msg)
						events.Add("INFO", "AGENT:HEALED", msg)
					}
				}
				prevLeaseDrift = curDrift
			}
			for {
				select {
				case <-leaseCheckDirty:
					if !debounceTimer.Stop() {
						select {
						case <-debounceTimer.C:
						default:
						}
					}
					debounceTimer.Reset(debounceInterval)
				case <-debounceTimer.C:
					runCheck()
				case <-fallbackTicker.C:
					runCheck()
				}
			}
		}()

		go func() {
			time.Sleep(5 * time.Second)
			ag.CatchUpLeases()
		}()
	}

	discoveryListener := discovery.NewListener()
	go func() {
		if err := discoveryListener.Run(context.Background()); err != nil {
			log.Printf("[DISCOVERY] listener: %v", err)
		}
	}()

	go func() {
		tailer := dnsmasqlog.New()
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			for scope := range ag.Ready() {
				path := filepath.Join(dataDir(currentConfig.Load()), "dnsmasq-"+scope+".log")
				for _, f := range tailer.CheckScope(path, scope) {
					events.Add(f.Level, "DNSMASQ", scope+": "+f.Line)
				}
			}
			if err := ag.RotateCoreDHCPLogIfNeeded(); err != nil {
				log.Printf("[AGENT:LOGROTATE] %v", err)
			}
			if err := ag.RotateCoreDNSLogIfNeeded(); err != nil {
				log.Printf("[AGENT:LOGROTATE] %v", err)
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		var lastRun time.Time
		var lastRunLoaded bool
		for range ticker.C {
			cfg := currentConfig.Load()
			if cfg == nil || !cfg.BackupEnabled {
				continue
			}

			retain := cfg.BackupRetentionCount
			if retain <= 0 {
				retain = 14
			}
			if err := backup.Prune(dataDir(cfg), retain); err != nil {
				log.Printf("[AGENT:BACKUP] prune: %v", err)
			}

			if cfg.BackupPassword == "" {
				continue
			}
			if !isBackupCoordinator(cfg.Role, cfg.MgmtVIP, ag.CachedMgmtVIPState()) {
				continue
			}
			if !lastRunLoaded {
				lastRun = readBackupLastRun(dataDir(cfg))
				lastRunLoaded = true
			}
			if !backupDue(lastRun, resolveBackupInterval(cfg.BackupIntervalHours), time.Now()) {
				continue
			}
			plaintext, err := json.MarshalIndent(backupPayloadFor(cfg, ag, observer), "", "  ")
			if err != nil {
				log.Printf("[AGENT:BACKUP] marshal config: %v", err)
				continue
			}
			info, err := backup.Create(dataDir(cfg), cfg.BackupPassword, plaintext, "", true)
			if err != nil {
				log.Printf("[AGENT:BACKUP] create: %v", err)
				events.Add("WARNING", "AGENT:BACKUP", "automated backup failed: "+err.Error())
				continue
			}
			lastRun = time.Now()
			if err := writeBackupLastRun(dataDir(cfg), lastRun); err != nil {
				log.Printf("[AGENT:BACKUP] persist last-run: %v", err)
			}
			if err := backup.Prune(dataDir(cfg), retain); err != nil {
				log.Printf("[AGENT:BACKUP] prune: %v", err)
			}
			log.Printf("[AGENT:BACKUP] wrote %s", info.Name)
			events.Add("INFO", "AGENT:BACKUP", "automated backup written: "+info.Name)
			if cfg.BackupReplicateToPeers {
				replicateBackupToPeers(cfg, dataDir(cfg), info.Name)
			}
		}
	}()

	// ---- HTTP server ----
	mux := http.NewServeMux()

	// Arbiter witness protocol endpoints.
	var arbiterMgr *arbiter.Manager
	if isCoreRole(cfg.Role) && cfg.PSK != "" {
		arbiterMgr = arbiter.New([]byte(cfg.PSK), func() bool {
			return observer.EffectiveQuorum().HasQuorum
		}, dataDir(cfg))
		arbiterMgr.SetTrustedHosts(trustedHostsWithFallback)
		arbiterMgr.AddRoutes(mux)
	}

	var leaseSyncHandler *leasesync.Handler
	if isCoreRole(cfg.Role) {
		leaseSyncHandler = leasesync.NewHandler()
		leaseSyncHandler.Store = ag.PeerDHCPLeaseStore()
		leaseSyncHandler.MergedSnapshotFunc = ag.MergedDHCPLeaseSnapshot
		leaseSyncHandler.OnChange = func() {
			ag.OnPeerLeaseSync()
			signalLeaseCheck()
		}
		leaseSyncHandler.SetTrustedHosts(trustedHostsWithFallback)
		leaseSyncHandler.AddRoutes(mux)

		mux.HandleFunc("POST /api/v1/leasesync/restore", authMw.RequireAdmin(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Leases []leasesync.SyncedLease `json:"leases"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
				return
			}
			applied := ag.SeedPeerLeasesFromRestore(req.Leases)
			events.Add("INFO", "AGENT:LEASESYNC", fmt.Sprintf("restored %d lease(s) from backup", applied))
			writeJSON(w, http.StatusOK, map[string]any{"applied": applied})
		}))
	}

	// Scope-beacon targets, worker-trunk fallback paths and trusted_hosts.
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if decommissioning.Load() {
				continue
			}
			ag.RefreshScopeBeaconTargets()
			ag.RefreshScopeBeaconListeners()
			ag.RefreshTopoBeacon()

			fresh := currentConfig.Load()
			fallbackAddrs := computeFallbackTargets(fresh, observer)
			observer.SetFallbackAddrs(fallbackAddrs)
			base := append(append([]string(nil), fresh.TrustedHosts...), "127.0.0.1")
			hostsToApply := fallbackAddrsTrustedHosts(base, fallbackAddrs)
			observer.SetTrustedHosts(hostsToApply)
			if arbiterMgr != nil {
				arbiterMgr.SetTrustedHosts(hostsToApply)
			}
			if leaseSyncHandler != nil {
				leaseSyncHandler.SetTrustedHosts(hostsToApply)
			}
		}
	}()

	if isCoreRole(cfg.Role) {
		mux.HandleFunc("POST /api/v1/reliability/restore", authMw.RequireAdmin(func(w http.ResponseWriter, r *http.Request) {
			var req backup.ReliabilityData
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
				return
			}
			ag.RestoreTrunkReliability(req.Local)
			observer.RestorePathReliability(req.Path)
			events.Add("INFO", "AGENT:RELIABILITY", fmt.Sprintf("restored reliability history from backup (%d local, %d path)", len(req.Local), len(req.Path)))
			writeJSON(w, http.StatusOK, map[string]any{"local": len(req.Local), "path": len(req.Path)})
		}))

		mux.HandleFunc("POST /api/v1/reliability/reset", authMw.RequireAdmin(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Role   string `json:"role"`
				Parent string `json:"parent"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
				return
			}
			if req.Role == "" || req.Parent == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "role and parent are required"})
				return
			}
			observer.ResetPathReliability(req.Role, req.Parent)
			resetLocal := req.Role == cfg.Role
			if resetLocal {
				ag.ResetTrunkReliability(req.Parent)
			}
			events.Add("INFO", "AGENT:RELIABILITY", fmt.Sprintf("reset reliability history for %s/%s (local=%v)", req.Role, req.Parent, resetLocal))
			writeJSON(w, http.StatusOK, map[string]any{"reset_local": resetLocal, "reset_path": true})
		}))
	}

	if cfg.PSK != "" {
		coord := coordplane.NewServer(cfg.Role, self.NodeID, cfg.ControlAddr, []byte(cfg.PSK), cfg.Peers, cfg.TLSEnabled(),
			func(document json.RawMessage) (status int, body interface{}, checksum string, dhcpAffecting bool) {
				var upd configUpdate
				if err := json.Unmarshal(document, &upd); err != nil {
					return http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()}, "", false
				}
				before, beforeErr := config.Load(*cfgPath)
				status, body = applyConfigUpdate(*cfgPath, upd, ag, engine, authMw)
				if status == http.StatusOK {
					if fresh, err := config.Load(*cfgPath); err == nil {
						checksum = fresh.ConfigDocumentHash()
						if beforeErr == nil {
							dhcpAffecting = dhcpConfigChanged(before, fresh)
						}
					}
				}
				return status, body, checksum, dhcpAffecting
			})
		coord.SetPeersFunc(func() []string { return currentConfig.Load().Peers })
		coord.AddRoutes(mux)
		mux.HandleFunc("POST /api/v1/coord/config", authMw.RequireAdmin(coord.ConfigHandler()))
	}

	buildStatus := func() map[string]interface{} {
		snap := machine.Snapshot()
		visible, unreachable := observer.PeerVisibility()

		fresh := currentConfig.Load()
		scopesHash := fresh.ScopesHash()
		configHash := fresh.ConfigDocumentHash()
		configuredScopes := fresh.ScopeNames()
		iotScopes := fresh.IoTScopeNames()
		disabledScopes := fresh.DisabledScopeNames()

		hostname, _ := os.Hostname()

		return map[string]interface{}{
			"node_id":           self.NodeID,
			"hostname":          hostname,
			"role":              self.Role,
			"cluster_id":        self.ClusterID,
			"epoch":             snap.Epoch,
			"generation":        engine.Generation(),
			"incarnation":       self.Incarnation,
			"state":             snap.State,
			"healthy":           snap.State == fsm.StateStable,
			"state_since":       ag.StableSince().UTC().Format(time.RFC3339),
			"watermark":         watermark.Current(),
			"serving":           ag.Serving(),
			"ready":             ag.Ready(),
			"version":           version,
			"server_time":       time.Now().UTC().Format(time.RFC3339),
			"peers_visible":     visible,
			"peers_unreachable": unreachable,
			"fallback_peers":    observer.FallbackRoutes(),
			"paths":             observer.FallbackStatuses(),
			"topology":          ag.TopoSightings(),
			"topology_trunks":   ag.TopoBeaconTrunks(),
			"scope_paths":       ag.ScopeBeaconSnapshot(),
			"scopes_hash":       scopesHash,
			"config_hash":       configHash,
			"configured_scopes": configuredScopes,
			"iot_scopes":        iotScopes,
			"disabled_scopes":   disabledScopes,
			"plane_warnings":    planeWarnings.strings(),
			"mgmt_vip_state":    ag.CachedMgmtVIPState(),
			"holds_mgmt_vip":    ag.CachedMgmtVIPState() == "MASTER",
		}
	}
	mux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, buildStatus())
	})
	mux.HandleFunc("/api/v1/cluster/status", clusterStatusHandler(buildStatus, observer))
	mux.HandleFunc("/api/v1/cluster/snapshot", clusterSnapshotHandler(observer))

	// /api/v1/health — simple health check for load balancers and monitoring.
	// Returns 200 when STABLE, 503 otherwise. Minimal body for fast polling.
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		snap := machine.Snapshot()
		topoWarn := observer.TopologyCheck()
		if snap.State == fsm.StateStable && topoWarn == "" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		} else if snap.State == fsm.StateStable && topoWarn != "" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"degraded","topology_warning":"` + topoWarn + `"}`))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"status":"unhealthy","state":"` + string(snap.State) + `"}`))
		}
	})

	mux.HandleFunc("/api/v1/cluster", observer.HandleClusterAPI)
	mux.HandleFunc("/api/v1/ping", observer.HandlePing)
	mux.HandleFunc("/api/v1/quorum", observer.HandleQuorumAPI)

	mux.HandleFunc("/api/v1/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"version":        version,
			"schema_version": config.CurrentSchemaVersion,
		})
	})

	mux.HandleFunc("/api/v1/fsm", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, machine.Snapshot())
	})

	mux.HandleFunc("/api/v1/desired", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, engine.Snapshot())
	})

	mux.HandleFunc("/api/v1/leases", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"held":     leaseMgr.Held(),
			"observed": observer.ObservedLeases(engine.Generation(), watermark),
		})
	})

	mux.HandleFunc("/api/v1/fencing", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"watermark": watermark.Current(),
			"peers":     observer.ObservedTokens(),
		})
	})

	mux.HandleFunc("/api/v1/agent", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"serving": ag.Serving(),
		})
	})

	// Authority predicate evaluation — exposes the five-part safety check
	// for a specific scope. Used by dnshived-top's "Why?" drilldown.
	mux.HandleFunc("/api/v1/authority/", func(w http.ResponseWriter, r *http.Request) {
		scope := strings.TrimPrefix(r.URL.Path, "/api/v1/authority/")
		if scope == "" {
			// List all scopes' authority.
			lastIn := ag.LastReconcileInputs()
			results := make(map[string]agent.AuthorityCheck)
			for _, s := range lastIn.OwnedScopes {
				results[s] = ag.ExplainAuthority(s, lastIn)
			}
			// Also check scopes we're currently serving but may not own.
			for _, s := range ag.Serving() {
				if _, ok := results[s]; !ok {
					results[s] = ag.ExplainAuthority(s, lastIn)
				}
			}
			writeJSON(w, http.StatusOK, results)
			return
		}
		lastIn := ag.LastReconcileInputs()
		writeJSON(w, http.StatusOK, ag.ExplainAuthority(scope, lastIn))
	})

	mux.HandleFunc("/api/v1/readiness/", func(w http.ResponseWriter, r *http.Request) {
		scope := strings.TrimPrefix(r.URL.Path, "/api/v1/readiness/")
		if scope == "" {
			results := make(map[string]agent.ReadinessCheck)
			for s := range ag.Ready() {
				results[s] = ag.Readiness(s)
			}
			writeJSON(w, http.StatusOK, results)
			return
		}
		writeJSON(w, http.StatusOK, ag.Readiness(scope))
	})

	// Event ring buffer — returns recent events, optionally filtered by
	// ?since=<unix_timestamp>, ?since_id=<event_id>, or ?n=<count>.
	mux.HandleFunc("/api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		sinceStr := r.URL.Query().Get("since")
		sinceIDStr := r.URL.Query().Get("since_id")
		nStr := r.URL.Query().Get("n")

		if sinceIDStr != "" {
			id, err := strconv.ParseInt(sinceIDStr, 10, 64)
			if err == nil {
				writeJSON(w, http.StatusOK, events.SinceID(id))
				return
			}
		}

		if sinceStr != "" {
			ts, err := strconv.ParseInt(sinceStr, 10, 64)
			if err == nil {
				writeJSON(w, http.StatusOK, events.Since(time.Unix(ts, 0)))
				return
			}
		}

		n := 100
		if nStr != "" {
			if parsed, err := strconv.Atoi(nStr); err == nil && parsed > 0 {
				n = parsed
			}
		}
		writeJSON(w, http.StatusOK, events.Last(n))
	})

	mux.HandleFunc("GET /api/v1/dnsmasq-log/{scope}", func(w http.ResponseWriter, r *http.Request) {
		scope := r.PathValue("scope")
		n := 20
		if nStr := r.URL.Query().Get("n"); nStr != "" {
			if parsed, err := strconv.Atoi(nStr); err == nil && parsed > 0 {
				n = parsed
			}
		}
		if scope == "core-dns" && !currentConfig.Load().CoreDNSQueryLogging {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"lines": []string{},
				"note": "DNS query logging is not enabled for the shared central instance — turn it on under Cluster Settings → Core DNS/DHCP addresses (core_dns_query_logging) to see real query content here. " +
					"dnsmasq's own startup lines (version, upstream nameserver, etc.) already exist in this node's systemd journal regardless — see `journalctl -u dnshived-dnsmasq@core-dns` directly on this node, not shown here yet.",
			})
			return
		}
		logFileName := "dnsmasq-" + scope + ".log"
		switch scope {
		case "core-dhcp":
			logFileName = dhcpcentralrender.CoreDHCPLogFileName
		case "core-dns":
			logFileName = dnscentralrender.CoreDNSLogFileName
		}
		path := filepath.Join(dataDir(currentConfig.Load()), logFileName)
		lines, err := dnsmasqlog.TailLines(path, n)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"lines": lines})
	})

	mux.HandleFunc("GET /api/v1/daemon-log/{unit}", func(w http.ResponseWriter, r *http.Request) {
		unit := r.PathValue("unit")
		if !agent.AllowedJournalUnits[unit] {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unit not allowed: " + unit})
			return
		}
		n := 100
		if nStr := r.URL.Query().Get("n"); nStr != "" {
			if parsed, err := strconv.Atoi(nStr); err == nil && parsed > 0 {
				n = parsed
			}
		}
		lines, err := ag.GetJournalTail(unit, n)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"lines": lines})
	})

	mux.HandleFunc("GET /api/v1/leases/{scope}", func(w http.ResponseWriter, r *http.Request) {
		scope := r.PathValue("scope")
		cfg := currentConfig.Load()
		sc, ok := cfg.Scopes[scope]
		if !ok || sc.DHCPRange[0] == "" || sc.DHCPRange[1] == "" {
			writeJSON(w, http.StatusOK, map[string]interface{}{"leases": []dhcplease.Lease{}})
			return
		}
		path := filepath.Join(dataDir(cfg), dhcpcentralrender.CoreDHCPLeaseFileName)
		all, err := dhcplease.ParseFile(path)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		leases := make([]dhcplease.Lease, 0, len(all))
		for _, l := range all {
			if dhcplease.InRange(l.IP, sc.DHCPRange[0], sc.DHCPRange[1]) {
				leases = append(leases, l)
			}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"leases": leases})
	})

	mux.HandleFunc("POST /api/v1/leases/{scope}/release", authMw.RequireAdmin(func(w http.ResponseWriter, r *http.Request) {
		mac := r.FormValue("mac")
		ip := r.FormValue("ip")
		if mac == "" || ip == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mac and ip are both required"})
			return
		}
		if err := ag.ReleaseLease(r.PathValue("scope"), mac, ip); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"released": true})
	}))

	// System stats — load average, memory, uptime from /proc.
	mux.HandleFunc("/api/v1/system", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, sysinfo.Collect())
	})

	mux.HandleFunc("/api/v1/daemons", func(w http.ResponseWriter, r *http.Request) {
		liveCfg := currentConfig.Load()

		type unitQuery struct {
			unit, versionBin string
			ownVersion       string // non-empty only for dnshived.service itself
		}
		var units []unitQuery
		units = append(units, unitQuery{"dnshived.service", "", version})
		units = append(units, unitQuery{"dnshived-helper.service", "/usr/local/bin/dnshived-helper", ""})
		units = append(units, unitQuery{"dnshived-web.service", "/usr/local/bin/dnshived-web", ""})
		units = append(units, unitQuery{"dnshived-keepalived.service", "", ""})
		if liveCfg.MgmtVIP != nil {
			units = append(units, unitQuery{"dnshived-keepalived-mgmt.service", "", ""})
		}

		units = append(units, unitQuery{"dnshived-dnsmasq@core-dns.service", "", ""})
		units = append(units, unitQuery{"dnshived-dnsmasq@core-dhcp.service", "", ""})

		units = append(units, unitQuery{"dnshived-relay.service", "/usr/local/bin/dnshived-relay", ""})

		units = append(units, unitQuery{"dnshived-dnsrelay.service", "/usr/local/bin/dnshived-dnsrelay", ""})

		allUnitNames := make([]string, 0, len(units))
		for _, u := range units {
			allUnitNames = append(allUnitNames, u.unit)
		}
		queried := daemonstatus.QueryMany(allUnitNames)

		keepalivedVersion := daemonstatus.Version("/usr/sbin/keepalived")
		// dnsmasqVersion is resolved once here (rather than once per caller below)
		// whenever ANYTHING on this node could be running dnsmasq.
		var dnsmasqVersion string
		dnsmasqVersion = daemonstatus.Version("/usr/sbin/dnsmasq")

		relayCfg, _ := dhcprelay.LoadConfig(agent.RelayConfigPath)
		enabledScopes, relayLabels := relayStatusEntries(liveCfg, relayCfg)
		relayEligibleCount := len(relayLabels)

		statuses := make([]daemonstatus.Status, len(units))
		for i, u := range units {
			s := queried[u.unit]
			switch {
			case u.ownVersion != "":
				s.Version = u.ownVersion
			case u.unit == "dnshived-keepalived.service" || u.unit == "dnshived-keepalived-mgmt.service":
				s.Version = keepalivedVersion
			case u.unit == "dnshived-dnsmasq@core-dns.service" || u.unit == "dnshived-dnsmasq@core-dhcp.service":
				s.Version = dnsmasqVersion
			case u.versionBin != "":
				s.Version = daemonstatus.Version(u.versionBin)
			}
			if u.unit == "dnshived-relay.service" {
				s.TotalCount = relayEligibleCount
			}
			if u.unit == "dnshived-dnsrelay.service" {
				s.TotalCount = enabledScopes
			}
			statuses[i] = s
		}

		agg := daemonstatus.Status{
			Unit:        "dhcp-relay",
			LoadState:   queried["dnshived-relay.service"].LoadState,
			ActiveState: queried["dnshived-relay.service"].ActiveState,
			Version:     queried["dnshived-relay.service"].Version,
			TotalCount:  relayEligibleCount,
			ActiveCount: relayEligibleCount,
		}
		statuses = append(statuses, agg)

		for _, label := range relayLabels {
			statuses = append(statuses, daemonstatus.Status{
				Unit:        "dhcp-relay: " + label,
				LoadState:   "loaded",
				ActiveState: "active",
			})
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"node_id": self.NodeID,
			"daemons": statuses,
		})
	})

	mux.HandleFunc("/api/v1/dnsrelay-stats", dnsRelayStatsHandler())

	mux.HandleFunc("GET /api/v1/config", authMw.RequireAdmin(func(w http.ResponseWriter, r *http.Request) {
		current, err := config.Load(*cfgPath)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "load current config: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, current)
	}))

	mux.HandleFunc("GET /api/v1/probe-config", authMw.RequireProbeOrReadonly(func(w http.ResponseWriter, r *http.Request) {
		current, err := config.Load(*cfgPath)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "load current config: " + err.Error()})
			return
		}
		scopes := make(map[string]interface{}, len(current.Scopes))
		for name, sc := range current.Scopes {
			scopes[name] = map[string]interface{}{
				"parent":           sc.Parent,
				"vlan_id":          sc.VLANID,
				"vip":              sc.VIP,
				"node_ip":          sc.NodeIP,
				"gateway":          sc.Gateway,
				"dhcp_range":       sc.DHCPRange,
				"preferred_worker": sc.PreferredWorker,
				"dns_records":      sc.DNSRecords,
				"probe_disabled":   sc.ProbeDisabled,
			}
		}
		clusterHasUpstream := current.ScopeDefaults != nil && len(current.ScopeDefaults.Upstream) > 0
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"node_id":              self.NodeID,
			"role":                 self.Role,
			"scopes":               scopes,
			"incarnation":          self.Incarnation,
			"default_dns_checks":   current.EffectiveDefaultDNSChecks(),
			"cluster_has_upstream": clusterHasUpstream,
		})
	}))

	// POST /api/v1/config — the web UI's write path.
	mux.HandleFunc("POST /api/v1/config", authMw.RequireAdmin(func(w http.ResponseWriter, r *http.Request) {
		var upd configUpdate
		if err := json.NewDecoder(r.Body).Decode(&upd); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
			return
		}

		status, body := applyConfigUpdate(*cfgPath, upd, ag, engine, authMw)
		writeJSON(w, status, body)
	}))

	mux.HandleFunc("GET /api/v1/candidate", authMw.RequireAdmin(func(w http.ResponseWriter, r *http.Request) {
		cand, exists, err := loadCandidateConfig(dataDir(currentConfig.Load()))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "load candidate: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"exists": exists, "candidate": cand})
	}))
	mux.HandleFunc("POST /api/v1/candidate", authMw.RequireAdmin(func(w http.ResponseWriter, r *http.Request) {
		var upd configUpdate
		if err := json.NewDecoder(r.Body).Decode(&upd); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
			return
		}
		status, body := applyCandidateUpdate(dataDir(currentConfig.Load()), *cfgPath, upd)
		writeJSON(w, status, body)
	}))
	mux.HandleFunc("DELETE /api/v1/candidate", authMw.RequireAdmin(func(w http.ResponseWriter, r *http.Request) {
		if err := discardCandidateConfig(dataDir(currentConfig.Load())); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "discard candidate: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "discarded"})
	}))
	mux.HandleFunc("DELETE /api/v1/candidate/scopes/{scope}", authMw.RequireAdmin(func(w http.ResponseWriter, r *http.Request) {
		scope := r.PathValue("scope")
		if err := discardCandidateScope(dataDir(currentConfig.Load()), *cfgPath, scope); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "revert scope: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "reverted"})
	}))

	mux.HandleFunc("POST /api/v1/nodes/probe", authMw.RequireAdmin(addProbeHandler(observer)))

	mux.HandleFunc("POST /api/v1/nodes/replace", authMw.RequireAdmin(replaceNodeHandler(*cfgPath, observer, ag, arbiterMgr, leaseSyncHandler)))
	mux.HandleFunc("POST /api/v1/nodes/update-peer", authMw.RequireAdmin(updatePeerHandler(*cfgPath, observer, ag)))
	mux.HandleFunc("POST /api/v1/nodes/update-trusted-hosts", authMw.RequireAdmin(updateTrustedHostsHandler(*cfgPath, observer, arbiterMgr, leaseSyncHandler)))
	mux.HandleFunc("POST /api/v1/nodes/reset-role-addressing", authMw.RequireAdmin(resetRoleAddressingHandler(*cfgPath, observer, ag)))
	mux.HandleFunc("POST /api/v1/nodes/remove-peer", authMw.RequireAdmin(removePeerHandler(*cfgPath, observer, ag, arbiterMgr, leaseSyncHandler)))
	mux.HandleFunc("POST /api/v1/nodes/inspect", authMw.RequireAdmin(inspectNodeHandler()))

	mux.HandleFunc("GET /api/v1/discovered-nodes", authMw.RequireAdmin(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, discoveryListener.Snapshot())
	}))
	mux.HandleFunc("POST /api/v1/nodes/offboard", authMw.RequireAdmin(offboardNodeHandler(*cfgPath, observer)))
	mux.HandleFunc("POST /api/v1/self-decommission", authMw.RequireAdmin(selfDecommissionHandler(*cfgPath)))
	mux.HandleFunc("POST /api/v1/decommission-report", authMw.RequireAdmin(decommissionReportHandler))

	mux.HandleFunc("POST /api/v1/audit", authMw.RequireAdmin(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Actor   string `json:"actor"`
			Action  string `json:"action"`
			Summary string `json:"summary"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
			return
		}
		if err := auditLogger.Append(req.Actor, self.NodeID, req.Action, req.Summary); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "append: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))

	// GET /api/v1/audit — export.
	mux.HandleFunc("GET /api/v1/audit", func(w http.ResponseWriter, r *http.Request) {
		data, err := auditLogger.ReadAll()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "read audit log: " + err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Write(data)
	})

	mux.HandleFunc("GET /api/v1/backups", authMw.RequireAdmin(func(w http.ResponseWriter, r *http.Request) {
		infos, err := backup.List(dataDir(currentConfig.Load()))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "list backups: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, infos)
	}))

	// POST /api/v1/backups — create a backup right now, on demand, separate
	// from the automated ticker above.
	mux.HandleFunc("POST /api/v1/backups", authMw.RequireAdmin(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
			Comment  string `json:"comment"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
			return
		}
		if req.Password == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password is required"})
			return
		}
		cfg := currentConfig.Load()
		plaintext, err := json.MarshalIndent(backupPayloadFor(cfg, ag, observer), "", "  ")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal config: " + err.Error()})
			return
		}
		info, err := backup.Create(dataDir(cfg), req.Password, plaintext, req.Comment, false)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "create backup: " + err.Error()})
			return
		}
		events.Add("INFO", "AGENT:BACKUP", "manual backup written: "+info.Name)
		if cfg.BackupReplicateToPeers {
			replicateBackupToPeers(cfg, dataDir(cfg), info.Name)
		}
		writeJSON(w, http.StatusOK, info)
	}))

	// GET /api/v1/backups/{name} — download one backup's raw encrypted
	// bytes.
	mux.HandleFunc("GET /api/v1/backups/{name}", authMw.RequireAdmin(func(w http.ResponseWriter, r *http.Request) {
		data, err := backup.Read(dataDir(currentConfig.Load()), r.PathValue("name"))
		if err != nil {
			status := http.StatusInternalServerError
			if err == backup.ErrInvalidName {
				status = http.StatusBadRequest
			} else if os.IsNotExist(err) {
				status = http.StatusNotFound
			}
			writeJSON(w, status, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+r.PathValue("name")+`"`)
		w.Write(data)
	}))

	mux.HandleFunc("PUT /api/v1/backups/{name}", authMw.RequireAdmin(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read body: " + err.Error()})
			return
		}
		comment := ""
		if enc := r.Header.Get("X-Backup-Comment"); enc != "" {
			if decoded, err := base64.StdEncoding.DecodeString(enc); err == nil {
				comment = string(decoded)
			}
		}
		automated := r.Header.Get("X-Backup-Automated") == "true"
		info, err := backup.Import(dataDir(currentConfig.Load()), r.PathValue("name"), data, comment, automated)
		if err != nil {
			status := http.StatusInternalServerError
			if err == backup.ErrInvalidName {
				status = http.StatusBadRequest
			}
			writeJSON(w, status, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, info)
	}))

	// DELETE /api/v1/backups/{name} — admin-gated.
	mux.HandleFunc("DELETE /api/v1/backups/{name}", authMw.RequireAdmin(func(w http.ResponseWriter, r *http.Request) {
		if err := backup.Delete(dataDir(currentConfig.Load()), r.PathValue("name")); err != nil {
			status := http.StatusInternalServerError
			if err == backup.ErrInvalidName {
				status = http.StatusBadRequest
			} else if os.IsNotExist(errors.Unwrap(err)) {
				status = http.StatusNotFound
			}
			writeJSON(w, status, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))

	restartUnitHandler := func(w http.ResponseWriter, r *http.Request) {
		unit := r.PathValue("unit")

		if unit == "dnshived.service" {
			writeJSON(w, http.StatusAccepted, map[string]bool{"ok": true})
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			go func() {
				time.Sleep(300 * time.Millisecond)
				if _, err := ag.RestartSelf(); err != nil {
					log.Printf("[API:RESTART] dnshived.service: %v", err)
				}
			}()
			return
		}

		var throttled bool
		var err error
		switch {
		case unit == "dnshived-keepalived.service":
			throttled, err = ag.RestartConsolidatedKeepalived()
		case unit == "dnshived-keepalived-mgmt.service":
			throttled, err = ag.RestartMgmtKeepalived()
		case unit == "dnshived-helper.service":
			throttled, err = ag.RestartHelper()
		case unit == "dnshived-web.service":
			throttled, err = ag.RestartWeb()
		case unit == "dnshived-relay.service":
			throttled, err = ag.RestartRelay()
		case unit == "dnshived-dnsrelay.service":
			throttled, err = ag.RestartDNSRelay()
		case isDnsmasqUnit(unit):
			scope := scopeFromDnsmasqUnit(unit)
			if _, ok := currentConfig.Load().Scopes[scope]; !ok {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown scope: " + scope})
				return
			}
			throttled, err = ag.RestartScopeDnsmasq(scope)
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unit not restartable via this endpoint: " + unit})
			return
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true, "throttled": throttled})
	}
	mux.HandleFunc("POST /api/v1/daemons/{unit}/restart", authMw.RequireAdmin(restartUnitHandler))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body><h1>dnshived " + version + "</h1></body></html>"))
	})

	// Wrap all routes with auth middleware (no-op when api_tokens is empty).
	handler := authMw.Wrap(mux)

	addr := cfg.ListenAddr()
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if cfg.TLSEnabled() {
		log.Printf("[http] listening on %s (TLS)", addr)
		if err := srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey); err != nil {
			log.Fatalf("https: %v", err)
		}
	} else {
		log.Printf("[http] listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("http: %v", err)
		}
	}
}

// reconcileLoop bundles one reconcile pass's dependencies and cross-tick
// state.
type reconcileLoop struct {
	observer    *cluster.Observer
	machine     *fsm.Machine
	engine      *desired.Engine
	leaseMgr    *lease.Manager
	watermark   *fencing.Watermark
	ag          *agent.Agent
	events      *eventlog.Ring
	role        string
	incarnation uint64

	lastState fsm.State
	lastWM    fencing.Token
}

// once runs exactly one reconcile pass.
func (rl *reconcileLoop) once(reason string) {
	if decommissioning.Load() {
		return
	}
	verdict := rl.observer.EffectiveQuorum()
	reachablePeers := verdict.VotesSeen
	if verdict.SelfVotes {
		reachablePeers--
	}
	st := rl.machine.Evaluate(fsm.Inputs{
		Verdict:        verdict,
		ReachablePeers: reachablePeers,
		ObservedOnce:   rl.observer.ObservedOnce(),
	})
	if st != rl.lastState {
		log.Printf("[FSM:TRANSITION] state → %s (trigger: %s)", st, reason)
		rl.events.Add("INFO", "FSM:TRANSITION", fmt.Sprintf("state → %s (trigger: %s)", st, reason))
		rl.lastState = st
	}

	if st == fsm.StateStable {
		rl.machine.FloorToken(rl.watermark.Current())
	}

	core1Alive, core2Alive, core3Alive := rl.observer.CoreRoleLiveness()
	rl.engine.Reconcile(st, desired.WorkerLiveness{
		Core1Alive:  core1Alive,
		Core2Alive:  core2Alive,
		Core3Alive:  core3Alive,
		TrunkHealth: rl.collectTrunkHealth(),
		TrunkScore:  rl.collectTrunkScore(),
		Observed:    rl.collectObservedServing(),
	}, rl.watermark.Current().Generation)

	owned, gen := rl.engine.OwnedScopes(rl.role)
	rl.leaseMgr.Reconcile(owned, gen, rl.incarnation)
	rl.observer.UpdateLeases(rl.leaseMgr.HeldMap())

	curGenNow := rl.engine.Generation()
	curEpochNow := rl.machine.Epoch()
	tok := fencing.Token{Epoch: curEpochNow, Generation: curGenNow}
	rl.observer.UpdateFencing(tok, verdict.HasQuorum)

	if wmTok, moved := rl.observer.AdvanceWatermark(rl.watermark, verdict); moved {
		if wmTok.Compare(rl.lastWM) != 0 {
			log.Printf("[FENCING:ADVANCE] watermark advanced to %s (trigger: %s)", wmTok, reason)
			rl.events.Add("INFO", "FENCING:ADVANCE", fmt.Sprintf("watermark advanced to %s (trigger: %s)", wmTok, reason))
			rl.lastWM = wmTok
		}
	}

	prevServing := rl.ag.Serving()
	rl.ag.Reconcile(agent.ReconcileInputs{
		State:       st,
		OwnedScopes: owned,
		HeldLeases:  rl.leaseMgr.HeldMap(),
		SelfToken:   tok,
		Watermark:   rl.watermark.Current(),
		Now:         time.Now().Unix(),
	})
	newServing := rl.ag.Serving()
	if !stringSlicesEqual(prevServing, newServing) {
		log.Printf("[BENCH:DECISION] serving set changed %v -> %v (trigger: %s)", prevServing, newServing, reason)
	}
	rl.observer.UpdateServing(newServing)
	rl.observer.UpdateTrunkHealth(rl.ag.TrunkHealth())
	rl.observer.UpdateTrunkScore(rl.ag.LocalTrunkScores())
}

func (rl *reconcileLoop) collectObservedServing() desired.CurrentServing {
	byRole := rl.observer.PeerServing()
	byRole[rl.role] = rl.ag.Serving()
	return desired.ObservedServing(byRole)
}

func (rl *reconcileLoop) collectTrunkHealth() map[string]map[string]bool {
	out := make(map[string]map[string]bool, 3)
	out[rl.role] = rl.ag.TrunkHealth()
	for _, role := range cluster.OtherCoreRoles(rl.role) {
		if h := rl.observer.PeerTrunkHealth(role); h != nil {
			out[role] = h
		}
	}
	return out
}

func (rl *reconcileLoop) collectTrunkScore() map[string]map[string]int {
	out := make(map[string]map[string]int, 3)
	out[rl.role] = rl.ag.LocalTrunkScores()
	for _, role := range cluster.OtherCoreRoles(rl.role) {
		local := rl.observer.PeerTrunkScore(role)
		if local == nil {
			continue
		}
		effective := make(map[string]int, len(local))
		for parent, localScore := range local {
			pathScore, known := rl.observer.PathScore(role, parent)
			effective[parent] = effectiveTrunkScore(localScore, pathScore, known)
		}
		out[role] = effective
	}
	return out
}

func effectiveTrunkScore(localScore, pathScore int, pathKnown bool) int {
	if pathKnown && pathScore < localScore {
		return pathScore
	}
	return localScore
}

// stringSlicesEqual compares two already-sorted slices (Agent.Serving()
// always returns one).
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func dataDir(cfg *config.Cluster) string {
	if cfg.DataDir != "" {
		return cfg.DataDir
	}
	return state.DefaultDir
}

// mgmtIfaceFromConfig is the mgmt interface name to pass to
// Agent.SetMgmtIface.
// relayStatusEntries counts the enabled scopes and labels the relay's
// client interfaces that still belong to one; relay.json is not rewritten
// when no scope is eligible, so its own list can be stale.
func relayStatusEntries(cfg *config.Cluster, relayCfg *dhcprelay.Config) (enabledScopes int, labels []string) {
	ifaceToScope := make(map[string]string, len(cfg.Scopes))
	for name, sc := range cfg.Scopes {
		if sc.DNSMasqDisabled {
			continue
		}
		enabledScopes++
		local := cfg.Platform.ResolveParent(cfg.Role, sc.Parent)
		ifaceToScope[nftgate.InterfaceName(local, sc.VLANID)] = name
	}
	if relayCfg == nil {
		return enabledScopes, nil
	}
	for _, ci := range relayCfg.ClientInterfaces {
		if scope, ok := ifaceToScope[ci.Name]; ok {
			labels = append(labels, scope+" ("+ci.Name+")")
		}
	}
	return enabledScopes, labels
}

func mgmtIfaceFromConfig(cfg *config.Cluster) string {
	return cfg.Platform.ResolveMgmt(cfg.Role)
}

// bareHost strips an optional "/prefix" CIDR suffix from addr, returning
// "" if what's left isn't a real address at all.
func bareHost(addr string) string {
	if idx := strings.IndexByte(addr, '/'); idx >= 0 {
		addr = addr[:idx]
	}
	if net.ParseIP(addr) == nil {
		return ""
	}
	return addr
}

func subnetBaseOf(addr string) string {
	host := bareHost(addr)
	if host == "" {
		return ""
	}
	idx := strings.LastIndexByte(host, '.')
	if idx < 0 {
		return "" // not a dotted-quad IPv4 address
	}
	return host[:idx+1]
}

func computeFallbackTargets(cfg *config.Cluster, observer *cluster.Observer) map[string]map[string]string {
	_, port, err := net.SplitHostPort(cfg.ControlAddr)
	if err != nil || port == "" {
		return nil
	}

	names := cfg.ScopeNames()
	sort.Strings(names)

	roles := []string{config.RoleCore1, config.RoleCore2, config.RoleCore3}
	out := make(map[string]map[string]string)
	for _, role := range roles {
		if role == cfg.Role {
			continue
		}
		seenParent := make(map[string]bool)
		for _, name := range names {
			sc, ok := cfg.Scopes[name]
			if !ok || sc.Parent == "" || seenParent[sc.Parent] {
				continue
			}
			var addr string
			base := subnetBaseOf(sc.VIP)
			if host := bareHost(sc.NodeIPOverrides[role]); host != "" {
				addr = net.JoinHostPort(host, port)
			} else if observer != nil && base != "" {
				if host := observer.DeriveRoleAddr(role, base); host != "" {
					addr = net.JoinHostPort(host, port)
				}
			}
			if addr == "" && cfg.ScopeDefaults != nil {
				suffix := cfg.ScopeDefaults.NodeIPSuffixes[role]
				if suffix != "" && base != "" {
					addr = net.JoinHostPort(base+suffix, port)
				}
			}
			if addr == "" {
				continue
			}
			seenParent[sc.Parent] = true
			if out[role] == nil {
				out[role] = make(map[string]string)
			}
			out[role][sc.Parent] = addr
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// fallbackAddrsTrustedHosts extends existing with each fallbackTargets
// value's own bare host (port stripped, duplicates skipped).
func fallbackAddrsTrustedHosts(existing []string, fallbackTargets map[string]map[string]string) []string {
	out := append([]string(nil), existing...)
	seen := make(map[string]bool, len(existing))
	for _, h := range existing {
		seen[h] = true
	}
	roles := make([]string, 0, len(fallbackTargets))
	for role := range fallbackTargets {
		roles = append(roles, role)
	}
	sort.Strings(roles) // deterministic order, not that it matters for a set
	for _, role := range roles {
		parents := make([]string, 0, len(fallbackTargets[role]))
		for parent := range fallbackTargets[role] {
			parents = append(parents, parent)
		}
		sort.Strings(parents)
		for _, parent := range parents {
			host, _, err := net.SplitHostPort(fallbackTargets[role][parent])
			if err != nil || host == "" || seen[host] {
				continue
			}
			seen[host] = true
			out = append(out, host)
		}
	}
	return out
}

const backupLastRunFileName = "backup-last-run"

func backupLastRunPath(dataDirPath string) string {
	return filepath.Join(dataDirPath, backupLastRunFileName)
}

// readBackupLastRun reads the persisted lastRun timestamp.
func readBackupLastRun(dataDirPath string) time.Time {
	raw, err := os.ReadFile(backupLastRunPath(dataDirPath))
	if err != nil {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(raw)))
	if err != nil {
		return time.Time{}
	}
	return t
}

// writeBackupLastRun persists t as the ticker's own lastRun.
func writeBackupLastRun(dataDirPath string, t time.Time) error {
	return os.WriteFile(backupLastRunPath(dataDirPath), []byte(t.Format(time.RFC3339)), 0o640)
}

func resolveBackupInterval(hours int) time.Duration {
	if hours <= 0 {
		return 24 * time.Hour
	}
	return time.Duration(hours) * time.Hour
}

// isBackupCoordinator reports whether THIS node is the current sole origin
// for automated backups.
func isBackupCoordinator(role string, mgmtVIP *config.MgmtVIPConfig, cachedVIPState string) bool {
	if mgmtVIP == nil {
		return role == config.RoleCore3
	}
	return cachedVIPState == "MASTER"
}

func backupDue(lastRun time.Time, interval time.Duration, now time.Time) bool {
	if lastRun.IsZero() {
		return true
	}
	return now.Truncate(interval).After(lastRun.Truncate(interval))
}

// replicateBackupToPeers reads name's raw (still-encrypted) bytes back off
// local disk and PUTs them to every configured peer's own PUT
// /api/v1/backups/{name}.
func replicateBackupToPeers(cfg *config.Cluster, dataDirPath, name string) {
	if len(cfg.Peers) == 0 {
		return
	}
	data, err := backup.Read(dataDirPath, name)
	if err != nil {
		log.Printf("[AGENT:BACKUP] replicate %s: read local copy: %v", name, err)
		return
	}
	comment := backup.ReadComment(dataDirPath, name)
	automated := backup.IsAutomated(dataDirPath, name)
	token := adminAPIToken(cfg)
	if token == "" {
		log.Printf("[AGENT:BACKUP] backup_replicate_to_peers is on but no admin-role api_token is configured — cannot authenticate to peers")
		return
	}
	scheme := "http"
	client := &http.Client{Timeout: 10 * time.Second}
	if cfg.TLSEnabled() {
		scheme = "https"
		client.Transport = &http.Transport{TLSClientConfig: tlspin.Config()}
	}
	replicated := 0
	for _, peer := range cfg.Peers {
		url := fmt.Sprintf("%s://%s/api/v1/backups/%s", scheme, peer, name)
		req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(data))
		if err != nil {
			log.Printf("[AGENT:BACKUP] replicate %s to %s: %v", name, peer, err)
			continue
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/octet-stream")
		if comment != "" {
			req.Header.Set("X-Backup-Comment", base64.StdEncoding.EncodeToString([]byte(comment)))
		}
		if automated {
			req.Header.Set("X-Backup-Automated", "true")
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[AGENT:BACKUP] replicate %s to %s: %v", name, peer, err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			log.Printf("[AGENT:BACKUP] replicate %s to %s: status %d", name, peer, resp.StatusCode)
			continue
		}
		replicated++
	}
	if replicated > 0 {
		log.Printf("[AGENT:BACKUP] replicated %s to %d/%d peer(s)", name, replicated, len(cfg.Peers))
	}
}

// adminAPIToken returns the first admin-role api_token configured, or "".
func adminAPIToken(cfg *config.Cluster) string {
	for _, t := range cfg.APITokens {
		if t.Role == "admin" {
			return t.Token
		}
	}
	return ""
}

// configUpdate is the POST /api/v1/config request body.
type configUpdate struct {
	PSK                   string                        `json:"psk"`
	TrustedHosts          []string                      `json:"trusted_hosts"`
	TLSCert               string                        `json:"tls_cert"`
	TLSKey                string                        `json:"tls_key"`
	APITokens             []config.APIToken             `json:"api_tokens"`
	LogLevel              string                        `json:"log_level"`
	HelperSocket          string                        `json:"helper_socket"`
	Platform              *config.Platform              `json:"platform"`
	Scopes                map[string]config.ScopeConfig `json:"scopes"`
	ProbeIntervalMS       int                           `json:"probe_interval_ms"`
	MgmtVIP               *config.MgmtVIPConfig         `json:"mgmt_vip"`
	DefaultDNSChecks      []config.DNSCheck             `json:"default_dns_checks"`
	GlobalDNSRecords      []config.DNSRecord            `json:"global_dns_records"`
	LocalDomains          []config.LocalDomain          `json:"local_domains"`
	ScopeDefaults         *config.ScopeDefaults         `json:"scope_defaults"`
	DefaultDHCPOptions    []string                      `json:"default_dhcp_options"`
	CoreDNSAddress        string                        `json:"core_dns_address"`
	CoreDHCPAddress       string                        `json:"core_dhcp_address"`
	CoreDNSQueryLogging   bool                          `json:"core_dns_query_logging"`
	DNSRelayCacheSize     int                           `json:"dnsrelay_cache_size"`
	DNSRelayCacheMaxBytes int                           `json:"dnsrelay_cache_max_bytes"`
	SanityCheckDisabled   bool                          `json:"sanity_check_disabled"`

	BackupEnabled          bool   `json:"backup_enabled"`
	BackupIntervalHours    int    `json:"backup_interval_hours"`
	BackupRetentionCount   int    `json:"backup_retention_count"`
	BackupPassword         string `json:"backup_password"`
	BackupReplicateToPeers bool   `json:"backup_replicate_to_peers"`
}

// applyTo overwrites every editable field on c with u's values.
func (u configUpdate) applyTo(c *config.Cluster) {
	c.PSK = u.PSK
	c.TrustedHosts = u.TrustedHosts
	c.TLSCert = u.TLSCert
	c.TLSKey = u.TLSKey
	c.APITokens = u.APITokens
	c.LogLevel = u.LogLevel
	c.HelperSocket = u.HelperSocket
	c.Platform = u.Platform
	c.Scopes = u.Scopes
	c.ProbeIntervalMS = u.ProbeIntervalMS
	c.MgmtVIP = u.MgmtVIP
	c.DefaultDNSChecks = u.DefaultDNSChecks
	c.GlobalDNSRecords = u.GlobalDNSRecords
	c.LocalDomains = u.LocalDomains
	c.ScopeDefaults = u.ScopeDefaults
	c.DefaultDHCPOptions = u.DefaultDHCPOptions
	c.CoreDNSAddress = u.CoreDNSAddress
	c.CoreDHCPAddress = u.CoreDHCPAddress
	c.CoreDNSQueryLogging = u.CoreDNSQueryLogging
	c.DNSRelayCacheSize = u.DNSRelayCacheSize
	c.DNSRelayCacheMaxBytes = u.DNSRelayCacheMaxBytes
	c.SanityCheckDisabled = u.SanityCheckDisabled
	c.BackupEnabled = u.BackupEnabled
	c.BackupIntervalHours = u.BackupIntervalHours
	c.BackupRetentionCount = u.BackupRetentionCount
	c.BackupPassword = u.BackupPassword
	c.BackupReplicateToPeers = u.BackupReplicateToPeers
}

func applyConfigUpdate(cfgPath string, upd configUpdate, ag *agent.Agent, engine *desired.Engine, authMw *auth.Middleware) (status int, body interface{}) {
	current, err := config.Load(cfgPath)
	if err != nil {
		return http.StatusInternalServerError, map[string]string{"error": "load current config: " + err.Error()}
	}
	clusterChanged := clusterIdentityFieldsChanged(current, upd)

	upd.applyTo(current)

	result := current.ValidateExtended()
	if !result.OK() {
		return http.StatusBadRequest, result
	}

	if err := config.Save(cfgPath, current); err != nil {
		return http.StatusInternalServerError, map[string]string{"error": "save: " + err.Error()}
	}
	currentConfig.Store(current)

	if !clusterChanged && ag != nil {
		ag.HotReloadScopes(current.Scopes)
		ag.RefreshTopoBeacon()
		if engine != nil {
			engine.SetScopes(desired.ScopesFromConfig(current.Scopes))
		}

		ag.SetHelper(helper.NewClient(helperSocketFor(current)))
		setBeaconLinkUp(helperSocketFor(current))
		ag.SetProbeInterval(current.ProbeInterval())
		ag.RenderMgmtVIPConfig(current.MgmtVIP, current.Platform)
		ag.SetGlobalDNSRecords(current.GlobalDNSRecords)
		ag.SetLocalDomains(current.LocalDomains)
		ag.SetDefaultDHCPOptions(current.DefaultDHCPOptions)
		if current.ScopeDefaults != nil {
			ag.SetCentralDNSUpstream(current.ScopeDefaults.Upstream)
		} else {
			ag.SetCentralDNSUpstream(nil)
		}
		ag.SetCoreDNSAddress(current.CoreDNSAddress)
		ag.SetCoreDHCPAddress(current.CoreDHCPAddress)
		ag.SetCoreDNSQueryLogging(current.CoreDNSQueryLogging)
		ag.SetDNSRelayCacheSize(current.DNSRelayCacheSize)
		ag.SetDNSRelayCacheMaxBytes(current.DNSRelayCacheMaxBytes)
		ag.SetSanityCheckDisabled(current.SanityCheckDisabled)
		if authMw != nil {
			authMw.SetTokens(current.APITokens)
		}
	}

	return http.StatusOK, map[string]interface{}{"ok": true, "warnings": result.Warnings, "restart_needed": clusterChanged}
}

func clusterIdentityFieldsChanged(c *config.Cluster, upd configUpdate) bool {
	return c.PSK != upd.PSK ||
		c.TLSCert != upd.TLSCert ||
		c.TLSKey != upd.TLSKey ||
		!reflect.DeepEqual(c.Platform, upd.Platform)
}

// emergencyCloseAllGates closes every configured scope's DHCP gate and
// returns an exit code; it never blocks.
func emergencyCloseAllGates(cfg *config.Cluster) int {
	helperClient := helper.NewClient(helperSocketFor(cfg))

	var wg sync.WaitGroup
	for name, sc := range cfg.Scopes {
		wg.Add(1)
		go func(name string, sc config.ScopeConfig) {
			defer wg.Done()
			sc.Parent = cfg.Platform.ResolveParent(cfg.Role, sc.Parent)
			err := agent.SetDHCPGateState(helperClient, name, sc, "closed")
			if err != nil {
				log.Printf("[EMERGENCY] helper failed for scope %s, falling back to direct: %v", name, err)
				err = nftgate.Close(nftgate.InterfaceName(sc.Parent, sc.VLANID))
			}
			if err != nil {
				log.Printf("[EMERGENCY] scope %s: close gate failed: %v", name, err)
			} else {
				log.Printf("[EMERGENCY] scope %s: gate closed", name)
			}
		}(name, sc)
	}
	wg.Wait()
	return 0
}

// helperSocketFor is the config's helper_socket, or the default path when
// a hand-written config leaves it out: dnshived always needs the helper.
func helperSocketFor(c *config.Cluster) string {
	if c != nil && c.HelperSocket != "" {
		return c.HelperSocket
	}
	return defaultHelperSocket
}

func setBeaconLinkUp(socket string) {
	hc := helper.NewClient(socket)
	topobeacon.LinkUp = hc.LinkUp
	discovery.LinkUp = hc.LinkUp
}
