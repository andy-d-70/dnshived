// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package agent decides, per scope, whether THIS node should be serving
// it, and enacts the decision via the scope lifecycle stack.
package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"dnshived/internal/loglevel"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	"dnshived/internal/arbiter"
	"dnshived/internal/cluster"
	"dnshived/internal/config"
	"dnshived/internal/daemonstatus"
	"dnshived/internal/dhcpcentralrender"
	"dnshived/internal/dhcplease"
	"dnshived/internal/dnscentralrender"
	"dnshived/internal/dnsrelayrender"
	"dnshived/internal/fencing"
	"dnshived/internal/fsm"
	"dnshived/internal/helper"
	"dnshived/internal/lease"
	"dnshived/internal/leasesync"
	"dnshived/internal/nftgate"
	"dnshived/internal/psksign"
	"dnshived/internal/relayrender"
	"dnshived/internal/reliability"
	"dnshived/internal/timehealth"
	"dnshived/internal/tlspin"
	"dnshived/internal/topobeacon"
	"dnshived/internal/vrrpstate"
)

// tokenSafetyMargin is subtracted from token/lease expiry times to absorb
// clock drift between nodes.
const tokenSafetyMargin = 2 * time.Second

// settlingDuration is how long after entering STABLE the agent withholds
// starting new scopes.
const settlingDuration = 15 * time.Second

// keepalivedPIDFile is the consolidated keepalived unit's PID file, used
// in direct (non-privsep) mode.
const keepalivedPIDFile = "/run/dnshived/keepalived.pid"

// mgmtKeepalivedPIDFile is the SEPARATE management-VIP keepalived
// instance's own PID file (mgmtvip.go/packaging/systemd/dnshived-
// keepalived-mgmt.service).
const mgmtKeepalivedPIDFile = "/run/dnshived/keepalived-mgmt.pid"

// --- Authority model: pure types, pure predicate ---

// WitnessState is the cached witness token state for a scope, maintained
// by the renewal goroutine.
type WitnessState struct {
	Held      bool  `json:"held"`       // token is held (acquired or renewed)
	ExpiresAt int64 `json:"expires_at"` // unix timestamp of token expiry
}

// AuthorityInputs contains everything the predicate needs to decide
// whether a scope may be served.
type AuthorityInputs struct {
	State            fsm.State
	OwnsScope        bool
	LeaseValid       bool
	LeaseExpiresAt   int64
	SelfToken        fencing.Token
	Watermark        fencing.Token
	Witness          WitnessState
	WitnessRequired  bool
	CurrentlyServing bool // true if scope is already running — witness check applies
	Now              int64
}

// scopeServeAllowed is the SINGLE safety predicate.
func scopeServeAllowed(in AuthorityInputs) (bool, string) {
	if in.State != fsm.StateStable {
		return false, "not STABLE: " + string(in.State)
	}
	if !in.OwnsScope {
		return false, "not owned in authoritative map"
	}
	if !in.LeaseValid {
		return false, "no valid lease held"
	}
	if withinSafetyMargin(in.LeaseExpiresAt, in.Now) {
		return false, "lease expiring within safety margin"
	}
	if in.SelfToken.Less(in.Watermark) {
		return false, "fenced: token " + in.SelfToken.String() +
			" < watermark " + in.Watermark.String()
	}
	// Witness token is checked only when already serving (stop path).
	if in.CurrentlyServing && in.WitnessRequired && !in.Witness.Held {
		return false, "witness token not held"
	}
	if in.CurrentlyServing && in.WitnessRequired && withinSafetyMargin(in.Witness.ExpiresAt, in.Now) {
		return false, "witness token expiring within safety margin"
	}
	return true, "all conditions met (STABLE, owned, leased, unfenced, witnessed)"
}

// withinSafetyMargin returns true if expiresAt is within the safety margin
// of now.
func withinSafetyMargin(expiresAt, now int64) bool {
	return now >= expiresAt-int64(tokenSafetyMargin.Seconds())
}

// --- External inputs (from the reconcile loop in main.go) ---

// ReconcileInputs is everything gathered each tick by the reconcile loop.
type ReconcileInputs struct {
	State       fsm.State
	OwnedScopes []string
	HeldLeases  map[string]lease.Lease
	SelfToken   fencing.Token
	Watermark   fencing.Token
	Now         int64

	// DesiredOwners is this node's desired-state owner role per scope and
	// ServedBy the role observed serving each scope (peers + self); both
	// only feed the unserved-scope warning.
	DesiredOwners map[string]string
	ServedBy      map[string]string
}

// ServeState is the agent's current decision for a single scope.
type ServeState struct {
	Scope      string     `json:"scope"`
	Serving    bool       `json:"serving"`
	Ready      bool       `json:"ready"`
	ReadySince *time.Time `json:"ready_since,omitempty"`
	Reason     string     `json:"reason"`
}

// Decision is the full per-tick output.
type Decision struct {
	Scopes map[string]ServeState `json:"scopes"`
}

// gateKind is the action decided for a scope's DHCP gate this tick.
type gateKind int

const (
	gateClose gateKind = iota
	gateOpen
	gateKeepOpen
)

// gateDecision is computed under lock (phase 1) and executed without it
// (phase 2).
type gateDecision struct {
	scope      string
	wasServing bool
	desired    DesiredAuthority
	priority   int // VRRP priority for this scope this tick (vrrpPriority)
}

// gateResult is a decision plus its execution outcome, for the phase-3
// commit under lock.
type gateResult struct {
	scope      string
	kind       gateKind
	reason     string
	wasServing bool
	opened     bool // meaningful only for gateOpen
}

// AntiFlap tracks whether a scope has been stable long enough to take over
// from a peer that's already serving it.
type AntiFlap struct {
	StableSince time.Time
	Delay       time.Duration
}

// Remaining returns how long until eligibility.
func (af *AntiFlap) Remaining() time.Duration {
	r := af.Delay - time.Since(af.StableSince)
	if r < 0 {
		return 0
	}
	return r
}

// StableFor returns how long the scope has been stable.
func (af *AntiFlap) StableFor() time.Duration {
	return time.Since(af.StableSince)
}

// DesiredAuthority is the outcome of the AntiFlap policy stage: whether a
// scope's gate should be open right now, and why.
type DesiredAuthority struct {
	Serve  bool
	Reason string
}

// antiFlapTimerAction tells the caller how to update a.antiFlap[scope]
// after EvaluateAntiFlap returns.
type antiFlapTimerAction int

const (
	timerNoChange antiFlapTimerAction = iota
	timerStart
	timerReset
)

// EvaluateAntiFlap decides whether a scope's gate should be open right
// now.
func EvaluateAntiFlap(now time.Time, allowed bool, reason string, wasServing bool,
	timer *AntiFlap, peerServing, isPreferred, rebalanceApproved bool,
	rebalanceDelay, quickReclaimDelay, quietWindow time.Duration,
) (DesiredAuthority, antiFlapTimerAction, time.Duration) {

	if !allowed {
		action := timerNoChange
		delay := rebalanceDelay
		if wasServing {
			action = timerReset
			if timer == nil || now.Sub(timer.StableSince) >= quietWindow {
				delay = quickReclaimDelay
			}
		}
		return DesiredAuthority{Serve: false, Reason: reason}, action, delay
	}
	if wasServing {
		return DesiredAuthority{Serve: true, Reason: reason}, timerNoChange, 0
	}
	switch {
	case timer == nil && peerServing && isPreferred && !rebalanceApproved:
		return DesiredAuthority{Serve: false, Reason: "preferred worker holding — peer already serving, rebalance not approved"}, timerNoChange, 0
	case timer == nil && peerServing && !isPreferred:
		return DesiredAuthority{Serve: false, Reason: "waiting for anti-flap eligibility"}, timerStart, rebalanceDelay
	case timer == nil:
		return DesiredAuthority{Serve: true, Reason: reason}, timerNoChange, 0
	case now.Sub(timer.StableSince) >= timer.Delay:
		return DesiredAuthority{Serve: true, Reason: reason}, timerNoChange, 0
	default:
		return DesiredAuthority{Serve: false, Reason: "waiting for anti-flap eligibility"}, timerNoChange, 0
	}
}

// VRRP priority tiers.
const (
	vrrpPriorityServing   = 100 // this node should hold the VIP right now
	vrrpPriorityStandby   = 50  // not eligible at all — no penalty implied
	vrrpPriorityPenalized = 1   // predicate says yes, anti-flap policy says wait
)

// vrrpPriority maps a scope's serve decision to the VRRP priority this
// node should advertise for it.
func vrrpPriority(serve, allowed bool) int {
	switch {
	case serve:
		return vrrpPriorityServing
	case allowed:
		return vrrpPriorityPenalized
	default:
		return vrrpPriorityStandby
	}
}

// --- Agent ---

// Agent makes and enacts serve/stop decisions per scope.
type Agent struct {
	mu          sync.Mutex
	constructMu sync.Mutex
	// mgmtRestartPending: the last mgmt-VIP config change wasn't applied
	// (reload failed), so the next render applies it again even if the file is
	// unchanged.
	mgmtRestartPending bool
	topoTrunks         []string
	topoRunner         *topobeacon.Runner
	topoCtx            context.Context
	role               string
	nodeID             string
	incarnation        uint64
	// scheme is "https" when the cluster is configured with tls_cert/tls_key
	// (see SetTLS).
	scheme string
	// witnessClient is the shared, connection-pool-bounded HTTP client used by
	// acquireWitness/renewWitness.
	witnessClient *http.Client
	psk           string
	dataDir       string
	selfAddr      string
	serving       map[string]bool
	ready         map[string]time.Time // scope → when its network plane was constructed
	// scopes supports hot-reload (HotReloadScopes changes the scope set
	// without a daemon restart).
	scopes   atomic.Pointer[map[string]config.ScopeConfig]
	observer *cluster.Observer

	// globalDNSRecords are rendered into EVERY scope's own dnsmasq instance in
	// addition to that scope's own DNSRecords.
	globalDNSRecords []config.DNSRecord

	// localDomains are the named local DNS zones rendered into the same
	// central-DNS aggregate globalDNSRecords already feeds.
	localDomains []config.LocalDomain

	// defaultDHCPOptions is the cluster-wide fallback for a scope's own
	// DHCPOptions.
	defaultDHCPOptions []string

	// centralDNSUpstream is dnsmasq.central's own upstream forwarders.
	centralDNSUpstream []string

	nodeIPSuffixes map[string]string

	// coreDNSAddress/coreDHCPAddress are the two core instances' own loopback
	// bind addresses.
	coreDNSAddress  string
	coreDHCPAddress string

	// coreDNSQueryLogging mirrors config.Cluster.CoreDNSQueryLogging.
	coreDNSQueryLogging bool

	// dnsRelayCacheSize/dnsRelayCacheMaxBytes mirror config.Cluster.
	dnsRelayCacheSize     int
	dnsRelayCacheMaxBytes int

	// keepalivedReady is whether the consolidated keepalived instance has been
	// successfully started at least once.
	keepalivedReady bool

	// relayReady is whether the node-wide dnshived-relay instance has been
	// successfully started at least once.
	relayReady bool

	coreDNSReady  bool
	coreDHCPReady bool

	// dnsRelayReady is whether the node-wide dnshived-dnsrelay instance has
	// been successfully started at least once.
	dnsRelayReady bool

	// vrrpPriority is the last successfully-applied (rendered + reloaded) VRRP
	// priority per scope.
	vrrpPriority map[string]int

	lastAppliedGate map[string]string

	lastIfaceIndex map[string]int

	// sanityCheckDisabled gates checkConfigSanity entirely.
	sanityCheckDisabled bool

	// vrrpConfigSig is the last successfully-applied vrrpConfigSignature
	// (VIP/VRRPID/AdvertIntMS/VRRPVersion across every scope).
	vrrpConfigSig string

	coreDNSConfigHash  string
	coreDHCPConfigHash string
	relayConfigHash    string
	dnsRelayConfigHash string

	// dnsRelayCacheHash is dnsRelayConfigHash's own narrower sibling, covering
	// ONLY the CacheSize/CacheMaxBytes subset of the rendered dnsrelay.json
	// content.
	dnsRelayCacheHash string

	// coreDHCPHostsHash is coreDHCPConfigHash's own sibling for the separate,
	// SIGHUP-reload-capable hosts file (dhcpcentralrender.HostsFileName).
	coreDHCPHostsHash string

	coreDNSDynamicHostsHash string
	coreDNSDynamicHostsMu   sync.Mutex

	// coreDHCPHostsMu serializes applyCoreDHCPHostsFile end to end (read
	// stores, merge, render, write, reload).
	coreDHCPHostsMu sync.Mutex

	localDHCPLeases *leasesync.Store
	peerDHCPLeases  *leasesync.Store

	leaseGapCounts map[string]map[string]int

	// trunkLinkDown caches each configured physical trunk's own last-checked
	// carrier state (true = link down).
	trunkLinkDown map[string]bool

	trunkReliability *reliability.Store

	// mgmtIface is Platform.Mgmt (the management interface name).
	mgmtIface string

	// platform is config.Cluster.Platform.
	platform *config.Platform

	// topoStore holds the live, in-memory interface-correlation beacon data
	// (internal/topobeacon) once StartTopoBeacon has been called.
	topoStore *topobeacon.Store

	// scopeMonitor holds the live KindScope beacon state once
	// StartScopeBeacons has been called.
	scopeMonitor        *topobeacon.ScopeMonitor
	scopeBeaconRunner   *topobeacon.ScopeBeaconRunner
	scopeBeaconCtx      context.Context
	scopeListenerRunner *topobeacon.ScopeListenerRunner

	// Rebalance policy — how long a returning worker must stay eligible
	// before it's allowed to take a scope's gate back from a peer that's
	// already serving it.
	rebalanceDelay time.Duration
	antiFlap       map[string]*AntiFlap
	unserved       map[string]*unservedState
	unservedKnown  map[string]bool

	quickReclaimDelay   time.Duration
	antiFlapQuietWindow time.Duration

	// Convergence settling — wall-clock (see settlingDuration).
	stableSince time.Time
	lastState   fsm.State

	// startedAt is when this Agent (and therefore this daemon process) came
	// into existence — set once here, never mutated.
	startedAt time.Time

	// Witness token state — maintained by the renewal goroutine, consumed by
	// the predicate.
	tokenMu  sync.RWMutex
	tokenRaw map[string]map[string]json.RawMessage // scope → arbiter addr → raw JSON
	witness  map[string]WitnessState               // scope → aggregated state (for predicate)

	// Renewal loop.
	renewTicker *time.Ticker
	quitRenew   chan struct{}

	// Last reconcile inputs — for the authority API.
	lastInputs ReconcileInputs

	// Privilege separation — when set, privileged ops go through the helper
	// socket instead of direct execution.
	helperClient *helper.Client

	// units is the per-tick unit-state snapshot (see unitCache).
	units     *daemonstatus.Cache
	unitsOnce sync.Once

	// mgmtVIPStateMu guards mgmtVIPStateCached.
	mgmtVIPStateMu     sync.Mutex
	mgmtVIPStateCached string
}

// New creates an agent.
func reliabilityLocalPath(dataDir string) string {
	if dataDir == "" {
		return ""
	}
	return filepath.Join(dataDir, "reliability-local.json")
}

func New(role, nodeID string, incarnation uint64, psk string, dataDir string, scopes map[string]config.ScopeConfig, observer *cluster.Observer) *Agent {
	if scopes == nil {
		scopes = make(map[string]config.ScopeConfig)
	}
	a := &Agent{
		startedAt:           time.Now(),
		role:                role,
		nodeID:              nodeID,
		incarnation:         incarnation,
		psk:                 psk,
		dataDir:             dataDir,
		serving:             make(map[string]bool),
		ready:               make(map[string]time.Time),
		observer:            observer,
		tokenRaw:            make(map[string]map[string]json.RawMessage),
		witness:             make(map[string]WitnessState),
		quitRenew:           make(chan struct{}),
		rebalanceDelay:      60 * time.Second,
		quickReclaimDelay:   5 * time.Second,
		antiFlapQuietWindow: 5 * time.Minute,
		antiFlap:            make(map[string]*AntiFlap),
		unserved:            make(map[string]*unservedState),
		unservedKnown:       make(map[string]bool),
		vrrpPriority:        make(map[string]int),
		lastAppliedGate:     make(map[string]string),
		witnessClient:       newWitnessClient(false),
		localDHCPLeases:     leasesync.NewStore(),
		peerDHCPLeases:      leasesync.NewStore(),
		leaseGapCounts:      make(map[string]map[string]int),
		trunkLinkDown:       make(map[string]bool),
		trunkReliability:    reliability.NewStore(reliabilityLocalPath(dataDir)),
	}
	a.publishScopes(scopes)
	return a
}

func (a *Agent) scopeConfig(name string) (config.ScopeConfig, bool) {
	m := a.scopes.Load()
	if m == nil {
		return config.ScopeConfig{}, false
	}
	sc, ok := (*m)[name]
	return sc, ok
}

// allScopes is the lock-free replacement for ranging/len-ing a.scopes
// directly.
func (a *Agent) allScopes() map[string]config.ScopeConfig {
	m := a.scopes.Load()
	if m == nil {
		return map[string]config.ScopeConfig{}
	}
	return *m
}

// scopeCount is a small convenience wrapper for the common len(a.scopes)
// case, matching the readability of the direct field access it replaces.
func (a *Agent) scopeCount() int {
	return len(a.allScopes())
}

// newWitnessClient builds the bounded, reusable HTTP client used for every
// acquireWitness/renewWitness call.
func newWitnessClient(useTLS bool) *http.Client {
	c := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:      10,
			MaxConnsPerHost:   2,
			IdleConnTimeout:   30 * time.Second,
			DisableKeepAlives: false,
			DialContext:       (&net.Dialer{Timeout: 1 * time.Second}).DialContext,
		},
	}
	if useTLS {
		c.Transport.(*http.Transport).TLSClientConfig = tlspin.Config()
	}
	return c
}

// SetHelper configures the agent to use the privileged helper for network
// and service operations.
func (a *Agent) SetHelper(c *helper.Client) {
	a.helperClient = c
}

// SetProbeInterval forwards to the observer's own live ticker-reset.
func (a *Agent) SetProbeInterval(d time.Duration) {
	if a.observer != nil {
		a.observer.SetProbeInterval(d)
	}
}

// SetTLS tells the agent whether the cluster's HTTP API (this node's own
// listener, and by implication every peer's) is HTTPS.
func (a *Agent) SetTLS(useTLS bool) {
	if useTLS {
		a.scheme = "https"
	} else {
		a.scheme = "http"
	}
	a.witnessClient = newWitnessClient(useTLS)
}

func (a *Agent) SetGlobalDNSRecords(recs []config.DNSRecord) {
	a.globalDNSRecords = recs
}

func (a *Agent) SetLocalDomains(domains []config.LocalDomain) {
	a.localDomains = domains
}

func (a *Agent) SetDefaultDHCPOptions(opts []string) {
	a.defaultDHCPOptions = opts
}

// SetCentralDNSUpstream configures dnsmasq.central's own upstream
// forwarders (config.Cluster.ScopeDefaults.Upstream).
func (a *Agent) SetCentralDNSUpstream(upstream []string) {
	a.centralDNSUpstream = upstream
}

func (a *Agent) SetNodeIPSuffixes(suffixes map[string]string) {
	a.nodeIPSuffixes = suffixes
}

func (a *Agent) SetCoreDNSAddress(address string) {
	a.coreDNSAddress = address
}

func (a *Agent) SetCoreDHCPAddress(address string) {
	a.coreDHCPAddress = address
}

// SetSelfAddr configures this node's own control address
// (config.Cluster.ControlAddr) — same Set*-after-New() pattern as the
// other setters above.
func (a *Agent) SetSelfAddr(addr string) {
	a.selfAddr = addr
}

// SetMgmtIface configures the management interface name
// (config.Cluster.Platform.Mgmt).
func (a *Agent) SetMgmtIface(iface string) {
	a.mgmtIface = iface
}

func (a *Agent) SetPlatform(platform *config.Platform) {
	a.platform = platform
}

func (a *Agent) localParent(canonical string) string {
	return a.platform.ResolveParent(a.role, canonical)
}

// resolveScopeParents returns a copy of scopes with every entry's own
// Parent resolved to this node's real local interface name via
// localParent.
func (a *Agent) resolveScopeParents(scopes map[string]config.ScopeConfig) map[string]config.ScopeConfig {
	resolved := make(map[string]config.ScopeConfig, len(scopes))
	for name, sc := range scopes {
		sc.Parent = a.localParent(sc.Parent)
		resolved[name] = sc
	}
	return resolved
}

// topoBeaconIfaceSpecs derives the interface list internal/topobeacon
// should beacon on/listen on.
func (a *Agent) topoBeaconIfaceSpecs() []topobeacon.IfaceSpec {
	trunks := make(map[string]bool)
	for _, sc := range a.allScopes() {
		if sc.Parent != "" {
			trunks[a.localParent(sc.Parent)] = true
		}
	}
	if a.platform != nil {
		for _, w := range a.platform.Workers {
			trunks[a.localParent(w)] = true
		}
	}
	names := make([]string, 0, len(trunks))
	for t := range trunks {
		names = append(names, t)
	}
	sort.Strings(names)

	specs := make([]topobeacon.IfaceSpec, 0, len(names)+1)
	for _, n := range names {
		specs = append(specs, topobeacon.IfaceSpec{Name: n, Kind: topobeacon.KindTrunk})
	}
	if a.mgmtIface != "" {
		specs = append(specs, topobeacon.IfaceSpec{Name: a.mgmtIface, Kind: topobeacon.KindMgmt})
	}
	return specs
}

func (a *Agent) StartTopoBeacon(ctx context.Context, role string, interval time.Duration) *topobeacon.Store {
	store := topobeacon.NewStore(interval, role)
	a.topoStore = store
	a.mu.Lock()
	a.topoRunner = topobeacon.NewRunner(role, store, interval)
	a.topoCtx = ctx
	a.mu.Unlock()
	if !a.RefreshTopoBeacon() {
		loglevel.Infof("[AGENT:SKIP] topology beacon has no interface yet (no scopes, no mgmt interface) — picked up as soon as one is configured")
	}
	return store
}

func (a *Agent) RefreshTopoBeacon() bool {
	a.mu.Lock()
	runner, ctx := a.topoRunner, a.topoCtx
	a.mu.Unlock()
	if runner == nil {
		return false
	}
	specs := a.topoBeaconIfaceSpecs()
	added, removed := runner.Update(ctx, specs)
	if len(added) > 0 || len(removed) > 0 {
		loglevel.Infof("[AGENT:TOPOBEACON] beacon interfaces now %v (started %v, stopped %v)", specNames(specs), specNames(added), specNames(removed))
	}
	var trunks []string
	for _, sp := range specs {
		if sp.Kind == topobeacon.KindTrunk {
			trunks = append(trunks, sp.Name)
		}
	}
	a.mu.Lock()
	a.topoTrunks = trunks
	a.mu.Unlock()
	return len(specs) > 0
}

func specNames(specs []topobeacon.IfaceSpec) []string {
	names := make([]string, len(specs))
	for i, sp := range specs {
		names[i] = sp.Name + ":" + sp.Kind
	}
	return names
}

func (a *Agent) TopoBeaconTrunks() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.topoTrunks...)
}

func (a *Agent) TopoSightings() []topobeacon.Sighting {
	if a.topoStore == nil {
		return nil
	}
	return a.topoStore.Snapshot()
}

// TopoHeardMgmtFrom reports whether this node has recently heard role's
// own mgmt-interface beacon.
func (a *Agent) TopoHeardMgmtFrom(role string) bool {
	if a.topoStore == nil {
		return false
	}
	return a.topoStore.HeardFrom(role, topobeacon.KindMgmt)
}

// coreRoles is every core role this project's fixed 3-node topology can
// ever have.
var coreRoles = []string{config.RoleCore1, config.RoleCore2, config.RoleCore3}

// scopeBeaconLocalAddrs returns the bare (no /prefix) local address this
// node holds on every scope KNOWN-CONSTRUCTED (a.ready, via
// readyScopeSet).
func (a *Agent) scopeBeaconLocalAddrs() map[string]string {
	out := make(map[string]string)
	allScopes := a.allScopes()
	for name := range a.readyScopeSet(nil) {
		sc, ok := allScopes[name]
		if !ok {
			continue
		}
		host, _, _ := strings.Cut(sc.NodeIP, "/")
		if host == "" {
			continue
		}
		out[name] = host
	}
	return out
}

// scopeBeaconLocalAddrsList returns the same addresses as
// scopeBeaconLocalAddrs, deduplicated and as a plain slice.
func (a *Agent) scopeBeaconLocalAddrsList() []string {
	byScope := a.scopeBeaconLocalAddrs()
	seen := make(map[string]bool, len(byScope))
	out := make([]string, 0, len(byScope))
	for _, addr := range byScope {
		if seen[addr] {
			continue
		}
		seen[addr] = true
		out = append(out, addr)
	}
	return out
}

// resolveScopePeerAddr resolves peer role's own bare address on scope sc.
func (a *Agent) resolveScopePeerAddr(sc config.ScopeConfig, role string) string {
	if override := sc.NodeIPOverrides[role]; override != "" {
		if host, _, _ := strings.Cut(override, "/"); host != "" {
			return host
		}
	}
	vipHost, _, _ := strings.Cut(sc.VIP, "/")
	idx := strings.LastIndexByte(vipHost, '.')
	if idx < 0 {
		return ""
	}
	subnetBase := vipHost[:idx+1]
	if a.observer != nil {
		if addr := a.observer.DeriveRoleAddr(role, subnetBase); addr != "" {
			return addr
		}
	}
	suffix := a.nodeIPSuffixes[role]
	if suffix == "" {
		return ""
	}
	return subnetBase + suffix
}

// scopeBeaconTargets derives every (scope, peer) liveness check this node
// should run.
func (a *Agent) scopeBeaconTargets() []topobeacon.ScopeTarget {
	var out []topobeacon.ScopeTarget
	ready := a.readyScopeSet(nil)
	names := make([]string, 0, len(ready))
	for name := range ready {
		names = append(names, name)
	}
	sort.Strings(names)
	allScopes := a.allScopes()
	for _, name := range names {
		sc, ok := allScopes[name]
		if !ok {
			continue
		}
		local, _, _ := strings.Cut(sc.NodeIP, "/")
		if local == "" {
			continue
		}
		for _, role := range coreRoles {
			if role == a.role {
				continue
			}
			peer := a.resolveScopePeerAddr(sc, role)
			if peer == "" {
				continue
			}
			out = append(out, topobeacon.ScopeTarget{Scope: name, LocalAddr: local, PeerRole: role, PeerAddr: peer})
		}
	}
	return out
}

// StartScopeBeacons starts the routed, per-scope liveness beacon.
func (a *Agent) StartScopeBeacons(ctx context.Context, role string, onUnreachable func(scope, peerRole string)) *topobeacon.ScopeMonitor {
	monitor := topobeacon.NewScopeMonitor(onUnreachable)
	a.scopeMonitor = monitor
	psk := []byte(a.psk)
	a.scopeListenerRunner = topobeacon.NewScopeListenerRunner(role, psk)
	a.scopeListenerRunner.Update(ctx, a.scopeBeaconLocalAddrsList())
	a.scopeBeaconCtx = ctx
	a.scopeBeaconRunner = topobeacon.NewScopeBeaconRunner(role, psk, monitor)
	targets := a.scopeBeaconTargets()
	if len(targets) == 0 {
		loglevel.Infof("[AGENT:SKIP] scope beacon not started — no (scope, peer) pairing could be resolved yet")
		return monitor
	}
	loglevel.Infof("[AGENT:SCOPEBEACON] starting on %d (scope, peer) pairing(s)", len(targets))
	a.scopeBeaconRunner.Update(ctx, targets)
	return monitor
}

// RefreshScopeBeaconTargets recomputes the (scope, peer) pairing set and
// applies only the difference against whatever's currently running.
func (a *Agent) RefreshScopeBeaconTargets() {
	if a.scopeBeaconRunner == nil {
		return
	}
	a.scopeBeaconRunner.Update(a.scopeBeaconCtx, a.scopeBeaconTargets())
}

// RefreshScopeBeaconListeners recomputes this node's own set of per-scope
// local addresses and applies only the difference against whatever's
// currently listening.
func (a *Agent) RefreshScopeBeaconListeners() {
	if a.scopeListenerRunner == nil {
		return
	}
	a.scopeListenerRunner.Update(a.scopeBeaconCtx, a.scopeBeaconLocalAddrsList())
}

func (a *Agent) ScopeBeaconSnapshot() []topobeacon.ScopeStatus {
	if a.scopeMonitor == nil {
		return nil
	}
	snap := a.scopeMonitor.Snapshot()
	scopes := a.allScopes()
	for i := range snap {
		if sc, ok := scopes[snap[i].Scope]; ok {
			snap[i].Parent, snap[i].VLANID = sc.Parent, sc.VLANID
		}
	}
	return snap
}

func (a *Agent) SetCoreDNSQueryLogging(enabled bool) {
	a.coreDNSQueryLogging = enabled
}

func (a *Agent) SetDNSRelayCacheSize(size int) {
	a.dnsRelayCacheSize = size
}

func (a *Agent) SetDNSRelayCacheMaxBytes(maxBytes int) {
	a.dnsRelayCacheMaxBytes = maxBytes
}

// SetSanityCheckDisabled gates checkConfigSanity.
func (a *Agent) SetSanityCheckDisabled(disabled bool) {
	a.sanityCheckDisabled = disabled
}

func (a *Agent) witnessScheme() string {
	if a.scheme == "" {
		return "http"
	}
	return a.scheme
}

// witnessHTTPClient returns the shared, pool-bounded client
// acquireWitness/renewWitness both call on every invocation.
func (a *Agent) witnessHTTPClient() *http.Client {
	if a.witnessClient == nil {
		a.witnessClient = newWitnessClient(false)
	}
	return a.witnessClient
}

func (a *Agent) ConstructPlane() {
	a.constructMu.Lock()
	defer a.constructMu.Unlock()

	if !timehealth.IsHealthy(5 * time.Second) {
		loglevel.Warnf("[AGENT:WARN] time unhealthy, proceeding with plane construction")
	}

	allScopes := a.allScopes()
	names := make([]string, 0, len(allScopes))
	for name := range allScopes {
		names = append(names, name)
	}
	sort.Strings(names)

	built := 0
	for _, name := range names {
		if a.constructScope(name, allScopes[name]) {
			a.mu.Lock()
			a.ready[name] = time.Now()
			a.mu.Unlock()
			built++
		}
	}

	if a.constructKeepalivedPlane(nil) {
		a.mu.Lock()
		a.keepalivedReady = true
		a.mu.Unlock()
	}

	if a.constructRelayPlane() {
		a.mu.Lock()
		a.relayReady = true
		a.mu.Unlock()
	}

	if a.constructDNSRelayPlane() {
		a.mu.Lock()
		a.dnsRelayReady = true
		a.mu.Unlock()
	}

	if a.constructCoreDNSPlane() {
		a.mu.Lock()
		a.coreDNSReady = true
		a.mu.Unlock()
	}

	if a.constructCoreDHCPPlane() {
		a.mu.Lock()
		a.coreDHCPReady = true
		a.mu.Unlock()
	}

	loglevel.Infof("[AGENT:PLANE] network plane constructed: %d/%d scope(s)%s",
		built, len(allScopes), retryNote(built < len(allScopes) || !a.keepalivedReady || !a.relayReady || !a.dnsRelayReady || !a.coreDNSReady || !a.coreDHCPReady))
}

func retryNote(pending bool) string {
	if pending {
		return " — will retry on subsequent reconcile ticks"
	}
	return ""
}

// servesScopes reports whether this node is a candidate to serve DHCP/DNS
// scopes at all.
func (a *Agent) servesScopes() bool {
	return true
}

func (a *Agent) constructScope(name string, sc config.ScopeConfig) bool {
	sc.Parent = a.localParent(sc.Parent)
	iface := nftgate.InterfaceName(sc.Parent, sc.VLANID)

	if !a.shouldSkipInterfaceRebuild(name, iface) {
		if err := a.createInterface(name, sc); err != nil {
			loglevel.Warnf("[AGENT:ERROR] scope %s: create interface %s: %v", name, iface, err)
			return false
		}
	}

	if err := a.stopDnsmasqUnit(name); err != nil {
		loglevel.Warnf("[AGENT:WARN] scope %s: stop leftover per-scope dnsmasq: %v (continuing)", name, err)
	}

	if sc.DNSMasqDisabled {
		loglevel.Infof("[AGENT:PLANE] scope %s constructed on %s (disabled by operator — excluded from DHCP relay and DNS relay, VLAN/VIP still active)", name, iface)
	} else {
		loglevel.Infof("[AGENT:PLANE] scope %s constructed on %s (DNS via dnshived-dnsrelay, DHCP via relay once eligible, gate closed)", name, iface)
	}
	return true
}

// constructKeepalivedPlane renders the consolidated keepalived config and
// ensures the single node-wide instance is running.
func (a *Agent) constructKeepalivedPlane(extraReady map[string]bool) bool {

	if err := a.renderKeepalivedConfigAll(nil, extraReady); err != nil {
		loglevel.Warnf("[AGENT:ERROR] render consolidated keepalived config: %v", err)
		return false
	}
	if err := a.ensureKeepalivedRunning(); err != nil {
		loglevel.Warnf("[AGENT:ERROR] start consolidated keepalived: %v", err)
		return false
	}
	loglevel.Debugf("[AGENT:PLANE] consolidated keepalived running (%d scope instance(s))", a.scopeCount())
	return true
}

// RelayConfigPath matches dnshived-relay's own --config default
// (cmd/dnshived-relay/main.go).
const RelayConfigPath = "/etc/dnshived/relay.json"

// constructRelayPlane renders relay.json and ensures the single node-wide
// dnshived-relay instance is running.
func (a *Agent) constructRelayPlane() bool {

	allScopes := a.allScopes()
	relayScopes := relayEligibleScopes(allScopes, a.batchedDnsmasqActiveChecker())

	if len(relayScopes) == 0 {
		loglevel.Infof("[AGENT:SKIP] dnshived-relay not started — no scope is relay-eligible yet (0/%d, still on per-scope dnsmasq or missing node_ip)", len(allScopes))
		return true
	}

	restarted, throttled, err := a.applyRelayConfig(relayScopes)
	if err != nil {
		loglevel.Warnf("[AGENT:ERROR] apply relay config: %v", err)
		return false
	}
	if throttled {
		loglevel.Infof("[AGENT:RATE_LIMIT] dnshived-relay restart suppressed — will retry next tick")
		return false
	}
	if restarted {
		loglevel.Infof("[AGENT:RELAY_APPLIED] dnshived-relay (config not yet applied to the running process — reloaded live via SIGHUP if already running, no other VLAN disturbed; a genuine first start/crash-recovery still restarts, see reloadRelayUnit/restartRelayUnit's own doc comments)")
	}
	loglevel.Debugf("[AGENT:PLANE] dnshived-relay running (%d/%d scope(s) relay-eligible)", len(relayScopes), len(allScopes))
	return true
}

// applyRelayConfig renders relay.json (relayrender.RenderRelayConfig) from
// relayScopes and restarts dnshived-relay only when the rendered content
// changed or the unit isn't running.
func (a *Agent) applyRelayConfig(relayScopes map[string]config.ScopeConfig) (restarted, throttled bool, err error) {
	cfg, err := relayrender.RenderRelayConfig(config.Cluster{Scopes: a.resolveScopeParents(relayScopes)}, relayrender.DefaultServerAddr)
	if err != nil {
		return false, false, fmt.Errorf("render relay config: %w", err)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return false, false, fmt.Errorf("marshal relay config: %w", err)
	}
	hash := contentHash(string(data))

	a.mu.Lock()
	changed := a.relayConfigHash != hash
	a.mu.Unlock()

	alreadyActive := a.unitActive("dnshived-relay.service")
	if !changed && alreadyActive {
		return false, false, nil
	}

	if err := relayrender.WriteRelayConfig(RelayConfigPath, config.Cluster{Scopes: a.resolveScopeParents(relayScopes)}, relayrender.DefaultServerAddr); err != nil {
		return false, false, fmt.Errorf("write relay config: %w", err)
	}

	if alreadyActive {
		throttled, err = a.reloadRelayUnit()
		if err != nil {
			return true, false, fmt.Errorf("reload dnshived-relay: %w", err)
		}
	} else {
		throttled, err = a.restartRelayUnit()
		if err != nil {
			return true, false, fmt.Errorf("restart dnshived-relay: %w", err)
		}
	}
	if throttled {
		return true, true, nil
	}

	a.mu.Lock()
	a.relayConfigHash = hash
	a.mu.Unlock()
	return true, false, nil
}

func (a *Agent) refreshRelayConfig() {
	allScopes := a.allScopes()
	relayScopes := relayEligibleScopes(allScopes, a.batchedDnsmasqActiveChecker())
	if len(relayScopes) == 0 {
		if a.unitActive("dnshived-relay.service") {
			if err := a.stopRelayUnit(); err != nil {
				loglevel.Warnf("[AGENT:ERROR] stop dnshived-relay (zero eligible scopes): %v", err)
				return
			}
			loglevel.Infof("[AGENT:RELAY_APPLIED] dnshived-relay stopped — zero scope is relay-eligible")
		}
		return
	}
	restarted, throttled, err := a.applyRelayConfig(relayScopes)
	if err != nil {
		loglevel.Warnf("[AGENT:ERROR] refresh relay config: %v", err)
		return
	}
	if throttled || !restarted {
		return
	}
	loglevel.Infof("[AGENT:RELAY_APPLIED] dnshived-relay (scope change picked up — reloaded live via SIGHUP, no other VLAN disturbed; see reloadRelayUnit's own doc comment)")
}

// DNSRelayConfigPath matches dnshived-dnsrelay's own --config default
// (cmd/dnshived-dnsrelay/main.go).
const DNSRelayConfigPath = "/etc/dnshived/dnsrelay.json"

// DNSRelayStatsPath matches dnshived-dnsrelay's own dnsRelayStatsPath
// const (cmd/dnshived-dnsrelay/main.go).
const DNSRelayStatsPath = "/var/lib/dnshived-dnsrelay/stats.json"

// constructDNSRelayPlane renders dnsrelay.json and ensures the single
// node-wide dnshived-dnsrelay instance is running.
func (a *Agent) constructDNSRelayPlane() bool {

	allScopes := a.allScopes()
	if len(allScopes) == 0 {
		loglevel.Infof("[AGENT:SKIP] dnshived-dnsrelay not started — no scope configured yet")
		return true
	}

	restarted, throttled, err := a.applyDNSRelayConfig(allScopes)
	if err != nil {
		loglevel.Warnf("[AGENT:ERROR] apply dnsrelay config: %v", err)
		return false
	}
	if throttled {
		loglevel.Infof("[AGENT:RATE_LIMIT] dnshived-dnsrelay restart suppressed — will retry next tick")
		return false
	}
	if restarted {
		loglevel.Infof("[AGENT:DNSRELAY_APPLIED] dnshived-dnsrelay (reloaded live via SIGHUP if already running, no other VLAN disturbed; a genuine first start/crash-recovery still restarts)")
	}
	loglevel.Debugf("[AGENT:PLANE] dnshived-dnsrelay running (%d scope(s) configured)", len(allScopes))
	return true
}

func (a *Agent) applyDNSRelayConfig(scopes map[string]config.ScopeConfig) (restarted, throttled bool, err error) {
	cluster := config.Cluster{
		Scopes:                a.resolveScopeParents(scopes),
		CoreDNSAddress:        a.coreDNSAddress,
		DNSRelayCacheSize:     a.dnsRelayCacheSize,
		DNSRelayCacheMaxBytes: a.dnsRelayCacheMaxBytes,
	}
	rendered, err := dnsrelayrender.RenderRelayConfig(cluster)
	if err != nil {
		return false, false, fmt.Errorf("render dnsrelay config: %w", err)
	}
	data, err := json.Marshal(rendered)
	if err != nil {
		return false, false, fmt.Errorf("marshal dnsrelay config: %w", err)
	}
	hash := contentHash(string(data))
	cacheData, err := json.Marshal(struct {
		CacheSize     int `json:"cache_size"`
		CacheMaxBytes int `json:"cache_max_bytes"`
	}{rendered.CacheSize, rendered.CacheMaxBytes})
	if err != nil {
		return false, false, fmt.Errorf("marshal dnsrelay cache config: %w", err)
	}
	cacheHash := contentHash(string(cacheData))

	a.mu.Lock()
	changed := a.dnsRelayConfigHash != hash
	cacheChanged := a.dnsRelayCacheHash != cacheHash
	a.mu.Unlock()

	alreadyActive := a.unitActive("dnshived-dnsrelay.service")
	if !changed && alreadyActive {
		return false, false, nil
	}

	if err := dnsrelayrender.WriteRelayConfig(DNSRelayConfigPath, cluster); err != nil {
		return false, false, fmt.Errorf("write dnsrelay config: %w", err)
	}

	if alreadyActive && !cacheChanged {
		throttled, err = a.reloadDNSRelayUnit()
		if err != nil {
			return true, false, fmt.Errorf("reload dnshived-dnsrelay: %w", err)
		}
	} else {
		throttled, err = a.restartDNSRelayUnit()
		if err != nil {
			return true, false, fmt.Errorf("restart dnshived-dnsrelay: %w", err)
		}
	}
	if throttled {
		return true, true, nil
	}

	a.mu.Lock()
	a.dnsRelayConfigHash = hash
	a.dnsRelayCacheHash = cacheHash
	a.mu.Unlock()
	return true, false, nil
}

// refreshDNSRelayConfig is constructDNSRelayPlane's steady-state
// counterpart, called every Reconcile tick once dnsRelayReady.
func (a *Agent) refreshDNSRelayConfig() {
	allScopes := a.allScopes()
	// Eligible count computed the same way dnsrelayrender.RenderRelayConfig
	// filters (DNSMasqDisabled excluded).
	eligible := 0
	for _, sc := range allScopes {
		if !sc.DNSMasqDisabled {
			eligible++
		}
	}
	if eligible == 0 {
		if a.unitActive("dnshived-dnsrelay.service") {
			if err := a.stopDNSRelayUnit(); err != nil {
				loglevel.Warnf("[AGENT:ERROR] stop dnshived-dnsrelay (zero eligible scopes): %v", err)
				return
			}
			loglevel.Infof("[AGENT:DNSRELAY_APPLIED] dnshived-dnsrelay stopped — zero scope is relay-eligible")
		}
		return
	}
	restarted, throttled, err := a.applyDNSRelayConfig(allScopes)
	if err != nil {
		loglevel.Warnf("[AGENT:ERROR] refresh dnsrelay config: %v", err)
		return
	}
	if throttled || !restarted {
		return
	}
	loglevel.Infof("[AGENT:DNSRELAY_APPLIED] dnshived-dnsrelay (scope change picked up — reloaded live via SIGHUP, no other VLAN disturbed)")
}

func (a *Agent) refreshCoreDNSConfig() {
	restarted, throttled, err := a.applyCoreDNSConfig()
	if err != nil {
		loglevel.Warnf("[AGENT:ERROR] refresh dnsmasq.central config: %v", err)
		return
	}
	if throttled || !restarted {
		return
	}
	loglevel.Infof("[AGENT:DNSMASQ_RESTART] dnshived-dnsmasq@core-dns (scope change picked up)")
}

func (a *Agent) refreshCoreDHCPConfig() {
	restarted, throttled, err := a.applyCoreDHCPConfig()
	if err != nil {
		loglevel.Warnf("[AGENT:ERROR] refresh central DHCP config: %v", err)
	} else if !throttled && restarted {
		loglevel.Infof("[AGENT:DNSMASQ_RESTART] dnshived-dnsmasq@core-dhcp (scope change picked up)")
	}
	a.pruneAndApplyDHCPHosts()
}

func (a *Agent) pruneAndApplyDHCPHosts() {
	now := time.Now()
	prunedLocal := a.localDHCPLeases.PruneExpired(now)
	prunedPeer := a.peerDHCPLeases.PruneExpired(now)
	if prunedLocal > 0 || prunedPeer > 0 {
		loglevel.Infof("[AGENT:LEASESYNC] pruned %d local + %d peer expired shadow lease(s)", prunedLocal, prunedPeer)
	}
	if _, _, err := a.applyCoreDHCPHostsFile(); err != nil {
		loglevel.Warnf("[AGENT:ERROR] apply central DHCP hosts file: %v", err)
	}
	if _, _, err := a.applyCoreDNSDynamicHostsFile(); err != nil {
		loglevel.Warnf("[AGENT:ERROR] apply central DNS dynamic hosts file: %v", err)
	}
	if err := a.localDHCPLeases.FlushIfDirty(); err != nil {
		loglevel.Warnf("[AGENT:ERROR] persist local lease store: %v", err)
	}
	if err := a.peerDHCPLeases.FlushIfDirty(); err != nil {
		loglevel.Warnf("[AGENT:ERROR] persist peer lease store: %v", err)
	}
}

// unitCacheMaxAge covers one reconcile tick's burst of checks (all within
// ~100 ms) while every tick and every plane-health run still sees fresh
// state.
const unitCacheMaxAge = 2 * time.Second

func (a *Agent) unitCache() *daemonstatus.Cache {
	a.unitsOnce.Do(func() {
		a.units = daemonstatus.NewCache(unitCacheMaxAge,
			"dnshived-dnsmasq@*.service",
			"dnshived-relay.service",
			"dnshived-dnsrelay.service",
			"dnshived-keepalived.service")
	})
	return a.units
}

func (a *Agent) unitActive(unit string) bool {
	return a.unitCache().Get(unit).ActiveState == "active"
}

func (a *Agent) unitsChanged() {
	a.unitCache().Invalidate()
}

func (a *Agent) batchedDnsmasqActiveChecker() func(scope string) bool {
	statuses := a.unitCache().Prefixed("dnshived-dnsmasq@")
	return func(scope string) bool {
		st := statuses["dnshived-dnsmasq@"+scope+".service"]
		return st.ActiveState == "active" || st.ActiveState == "activating"
	}
}

func relayEligibleScopes(allScopes map[string]config.ScopeConfig, isDnsmasqActive func(scope string) bool) map[string]config.ScopeConfig {
	out := make(map[string]config.ScopeConfig)
	for name, sc := range allScopes {
		if sc.NodeIP == "" {
			continue
		}
		if sc.DNSMasqDisabled {
			continue
		}
		if isDnsmasqActive(name) {
			continue
		}
		out[name] = sc
	}
	return out
}

func coreDNSConfigPath(dataDir string) string { return filepath.Join(dataDir, "dnsmasq-core-dns.conf") }
func coreDHCPConfigPath(dataDir string) string {
	return filepath.Join(dataDir, "dnsmasq-core-dhcp.conf")
}

func coreDHCPHostsPath(dataDir string) string {
	return filepath.Join(dataDir, dhcpcentralrender.HostsFileName)
}

func coreDNSDynamicHostsPath(dataDir string) string {
	return filepath.Join(dataDir, dnscentralrender.DynamicHostsFileName)
}

// ReleaseLease sends a real DHCPRELEASE for mac/ip directly to this
// worker's own central DHCP instance.
func (a *Agent) ReleaseLease(scope, mac, ip string) error {
	if _, ok := a.allScopes()[scope]; !ok {
		return fmt.Errorf("scope %q not configured on this node", scope)
	}
	return dhcplease.SendRelease(dhcpcentralrender.DefaultAddress, mac, ip)
}

// chownToDnshivedGroup sets path's group ownership to the "dnshived"
// system group (created by debian/dnshived.postinst on every real
// install).
func chownToDnshivedGroup(path string) error {
	g, err := user.LookupGroup("dnshived")
	if err != nil {
		return fmt.Errorf("lookup dnshived group: %w", err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return fmt.Errorf("parse dnshived group gid %q: %w", g.Gid, err)
	}
	return os.Chown(path, -1, gid)
}

func mergeReservations(real []config.Reservation, local, peer []leasesync.SyncedLease) []config.Reservation {
	seen := make(map[string]bool, len(real))
	out := make([]config.Reservation, 0, len(real)+len(local)+len(peer))
	for _, r := range real {
		out = append(out, r)
		seen[strings.ToLower(r.MAC)] = true
	}
	addSynced := func(entries []leasesync.SyncedLease) {
		for _, l := range entries {
			key := strings.ToLower(l.MAC)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, config.Reservation{MAC: l.MAC, IP: l.IP})
		}
	}
	addSynced(local)
	addSynced(peer)
	return out
}

// dynamicDNSHosts computes the DHCP-name-to-DNS sync entries to publish
// via central DNS's own reload-capable addn-hosts file.
func dynamicDNSHosts(scopes map[string]config.ScopeConfig, global []config.DNSRecord, local, peer []leasesync.SyncedLease) []dnscentralrender.DynamicHostEntry {
	staticNames := make(map[string]bool)
	reservedMAC := make(map[string]bool)
	for _, sc := range scopes {
		for _, r := range sc.DNSRecords {
			staticNames[strings.ToLower(r.Name)] = true
		}
		for _, res := range sc.Reservations {
			reservedMAC[strings.ToLower(res.MAC)] = true
			if res.Hostname != "" {
				staticNames[strings.ToLower(res.Hostname)] = true
			}
		}
	}
	for _, r := range global {
		staticNames[strings.ToLower(r.Name)] = true
	}

	seenMAC := make(map[string]bool)
	var out []dnscentralrender.DynamicHostEntry
	add := func(entries []leasesync.SyncedLease) {
		for _, l := range entries {
			key := strings.ToLower(l.MAC)
			if seenMAC[key] {
				continue
			}
			seenMAC[key] = true
			if l.Hostname == "" || reservedMAC[key] {
				continue
			}
			if staticNames[strings.ToLower(l.Hostname)] {
				continue
			}
			out = append(out, dnscentralrender.DynamicHostEntry{Hostname: l.Hostname, IP: l.IP})
		}
	}
	add(local)
	add(peer)
	return out
}

func (a *Agent) applyCoreDNSDynamicHostsFile() (reloaded, throttled bool, err error) {
	a.coreDNSDynamicHostsMu.Lock()
	defer a.coreDNSDynamicHostsMu.Unlock()

	entries := dynamicDNSHosts(a.allScopes(), a.globalDNSRecords, a.localDHCPLeases.Snapshot(), a.peerDHCPLeases.Snapshot())
	text, err := dnscentralrender.RenderDynamicHosts(entries)
	if err != nil {
		return false, false, fmt.Errorf("render central DNS dynamic hosts file: %w", err)
	}
	hash := contentHash(text)

	a.mu.Lock()
	changed := a.coreDNSDynamicHostsHash != hash
	a.mu.Unlock()
	if !changed {
		return false, false, nil
	}

	if err := atomicWriteFile(coreDNSDynamicHostsPath(a.dataDir), []byte(text), 0640); err != nil {
		return false, false, fmt.Errorf("write central DNS dynamic hosts file: %w", err)
	}
	if err := chownToDnshivedGroup(coreDNSDynamicHostsPath(a.dataDir)); err != nil {
		return false, false, fmt.Errorf("chown central DNS dynamic hosts file: %w", err)
	}
	throttled, err = a.reloadCoreDNSUnit()
	if err != nil {
		return true, false, fmt.Errorf("reload central DNS: %w", err)
	}
	if throttled {
		return true, true, nil
	}

	a.mu.Lock()
	a.coreDNSDynamicHostsHash = hash
	a.mu.Unlock()
	return true, false, nil
}

func (a *Agent) HandleLocalLeaseEvent(action, mac, ip, hostname string, expiresAt int64) {
	if a.macHasRealReservation(mac) {
		return
	}
	var wireAction string
	switch action {
	case "add", "old":
		a.localDHCPLeases.Upsert(leasesync.SyncedLease{MAC: mac, IP: ip, ExpiresAt: expiresAt, Hostname: hostname})
		wireAction = "upsert"
	case "del":
		a.localDHCPLeases.Remove(mac)
		wireAction = "remove"
	default:
		loglevel.Warnf("[AGENT:LEASESYNC] ignoring unknown dhcp-script action %q for mac=%s", action, mac)
		return
	}
	if _, _, err := a.applyCoreDHCPHostsFile(); err != nil {
		loglevel.Warnf("[AGENT:ERROR] apply central DHCP hosts file: %v", err)
	}
	if _, _, err := a.applyCoreDNSDynamicHostsFile(); err != nil {
		loglevel.Warnf("[AGENT:ERROR] apply central DNS dynamic hosts file: %v", err)
	}
	a.pushLeaseToPeer(mac, ip, hostname, expiresAt, wireAction)
}

// macHasRealReservation reports whether mac already has an operator-
// authored config.Reservation somewhere in the current config.
func (a *Agent) macHasRealReservation(mac string) bool {
	mac = strings.ToLower(mac)
	for _, sc := range a.allScopes() {
		for _, r := range sc.Reservations {
			if strings.ToLower(r.MAC) == mac {
				return true
			}
		}
	}
	return false
}

func (a *Agent) pushLeaseToPeer(mac, ip, hostname string, expiresAt int64, wireAction string) {
	if a.observer == nil {
		return
	}
	for _, addr := range a.observer.AllPeerAddrs() {
		l := leasesync.SyncedLease{MAC: mac, IP: ip, ExpiresAt: expiresAt, Hostname: hostname}
		if err := leasesync.Push(a.witnessHTTPClient(), a.witnessScheme(), addr, l, wireAction); err != nil {
			loglevel.Warnf("[AGENT:LEASESYNC] push %s to %s failed: %v", wireAction, addr, err)
		}
	}
}

// OnPeerLeaseSync is wired as internal/leasesync.Handler.OnChange by
// cmd/dnshived's own main.go.
func (a *Agent) OnPeerLeaseSync() {
	if _, _, err := a.applyCoreDHCPHostsFile(); err != nil {
		loglevel.Warnf("[AGENT:ERROR] apply central DHCP hosts file (peer sync): %v", err)
	}
	if _, _, err := a.applyCoreDNSDynamicHostsFile(); err != nil {
		loglevel.Warnf("[AGENT:ERROR] apply central DNS dynamic hosts file (peer sync): %v", err)
	}
}

// PeerDHCPLeaseStore exposes peerDHCPLeases so cmd/dnshived's own main.go
// can hand it directly to internal/leasesync.Handler.
func (a *Agent) PeerDHCPLeaseStore() *leasesync.Store {
	return a.peerDHCPLeases
}

// LocalDHCPLeaseStore exposes localDHCPLeases.
func (a *Agent) LocalDHCPLeaseStore() *leasesync.Store {
	return a.localDHCPLeases
}

// SetLeasePersistDir wires both DHCP-lease-shadow stores' own on-disk
// persistence to dataDir, then loads whatever either already has on disk.
func (a *Agent) SetLeasePersistDir(dataDir string) {
	a.localDHCPLeases.SetPersistPath(filepath.Join(dataDir, "leasesync-local.json"))
	a.peerDHCPLeases.SetPersistPath(filepath.Join(dataDir, "leasesync-peer.json"))
	nLocal, err := a.localDHCPLeases.LoadFromDisk()
	if err != nil {
		loglevel.Infof("[AGENT:LEASESYNC] load local lease store: %v", err)
	}
	nPeer, err := a.peerDHCPLeases.LoadFromDisk()
	if err != nil {
		loglevel.Infof("[AGENT:LEASESYNC] load peer lease store: %v", err)
	}
	if nLocal > 0 || nPeer > 0 {
		loglevel.Infof("[AGENT:LEASESYNC] loaded %d local + %d peer lease(s) from disk", nLocal, nPeer)
	}
}

// MergedDHCPLeaseSnapshot returns this node's own full picture of every
// dynamic lease it knows about.
func (a *Agent) MergedDHCPLeaseSnapshot() []leasesync.SyncedLease {
	merged := make(map[string]leasesync.SyncedLease)
	for _, l := range a.peerDHCPLeases.Snapshot() {
		merged[l.MAC] = l
	}
	for _, l := range a.localDHCPLeases.Snapshot() {
		merged[l.MAC] = l
	}
	out := make([]leasesync.SyncedLease, 0, len(merged))
	for _, l := range merged {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out
}

// leaseGapThreshold/leaseCrossCheckGrace tune CheckLeaseSanity's own
// tolerance.
const (
	leaseGapThreshold    = 3
	leaseCrossCheckGrace = 2 * time.Minute
)

func (a *Agent) CheckLeaseSanity() []PlaneHealth {
	if a.observer == nil {
		return nil
	}
	peers := a.observer.AllPeerAddrs()
	if len(peers) == 0 {
		return nil
	}
	local := a.MergedDHCPLeaseSnapshot()
	localFP := leasesync.Fingerprint(local)
	now := time.Now()

	var found []PlaneHealth
	healedAny := false
	for _, addr := range peers {
		remoteFP, err := leasesync.FetchFingerprint(a.witnessHTTPClient(), a.witnessScheme(), addr)
		if err != nil {
			continue
		}
		if remoteFP == localFP {
			a.clearLeaseGapCounts(addr)
			continue
		}
		remote, err := leasesync.FetchSnapshot(a.witnessHTTPClient(), a.witnessScheme(), addr)
		if err != nil {
			continue
		}
		conflicts, gaps := leasesync.Diff(local, remote, now, leaseCrossCheckGrace)
		for _, c := range conflicts {
			found = append(found, PlaneHealth{
				What:     "lease_db_conflict",
				Healable: false,
				Detail:   fmt.Sprintf("mac=%s: this node has %s, peer %s has %s", c.MAC, c.LocalIP, addr, c.RemoteIP),
			})
		}
		toHeal := a.trackLeaseGaps(addr, gaps)
		for _, g := range toHeal {
			a.peerDHCPLeases.Upsert(g)
			healedAny = true
			found = append(found, PlaneHealth{
				What:     "lease_db_gap",
				Healable: true,
				Detail:   fmt.Sprintf("mac=%s missing from this node for %d consecutive check(s), learned from peer %s", g.MAC, leaseGapThreshold, addr),
			})
		}
	}
	if healedAny {
		if _, _, err := a.applyCoreDHCPHostsFile(); err != nil {
			loglevel.Warnf("[AGENT:ERROR] apply central DHCP hosts file (lease sanity self-heal): %v", err)
		}
		if _, _, err := a.applyCoreDNSDynamicHostsFile(); err != nil {
			loglevel.Warnf("[AGENT:ERROR] apply central DNS dynamic hosts file (lease sanity self-heal): %v", err)
		}
	}
	return found
}

func (a *Agent) trackLeaseGaps(addr string, gaps []leasesync.SyncedLease) []leasesync.SyncedLease {
	a.mu.Lock()
	defer a.mu.Unlock()
	counts := a.leaseGapCounts[addr]
	if counts == nil {
		counts = make(map[string]int)
	}
	seen := make(map[string]bool, len(gaps))
	var toHeal []leasesync.SyncedLease
	for _, g := range gaps {
		seen[g.MAC] = true
		counts[g.MAC]++
		if counts[g.MAC] == leaseGapThreshold {
			toHeal = append(toHeal, g)
		}
	}
	for mac := range counts {
		if !seen[mac] {
			delete(counts, mac)
		}
	}
	a.leaseGapCounts[addr] = counts
	return toHeal
}

// clearLeaseGapCounts drops every tracked gap counter for addr.
func (a *Agent) clearLeaseGapCounts(addr string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.leaseGapCounts, addr)
}

// CatchUpLeases is called once at startup, after SetLeasePersistDir's own
// disk load completes.
func (a *Agent) CatchUpLeases() {
	if a.observer == nil {
		return
	}
	peers := a.observer.AllPeerAddrs()
	if len(peers) == 0 {
		return
	}
	merged := make(map[string]leasesync.SyncedLease)
	reached := 0
	for _, addr := range peers {
		snap, err := leasesync.FetchSnapshot(a.witnessHTTPClient(), a.witnessScheme(), addr)
		if err != nil {
			loglevel.Warnf("[AGENT:LEASESYNC] catch-up fetch from %s failed: %v", addr, err)
			continue
		}
		reached++
		for _, l := range snap {
			if existing, ok := merged[l.MAC]; ok && existing.IP != l.IP {
				loglevel.Infof("[AGENT:LEASESYNC] catch-up: peers disagree on mac=%s (%s vs %s) — keeping first seen", l.MAC, existing.IP, l.IP)
				continue
			}
			merged[l.MAC] = l
		}
	}
	if reached == 0 {
		loglevel.Infof("[AGENT:LEASESYNC] catch-up: no peer reachable yet, starting with whatever was persisted locally")
		return
	}
	now := time.Now().Unix()
	applied := 0
	for _, l := range merged {
		if l.ExpiresAt <= now {
			continue
		}
		a.peerDHCPLeases.Upsert(l)
		applied++
	}
	loglevel.Infof("[AGENT:LEASESYNC] catch-up: seeded %d lease(s) from %d/%d reachable peer(s)", applied, reached, len(peers))
	if applied > 0 {
		if _, _, err := a.applyCoreDHCPHostsFile(); err != nil {
			loglevel.Warnf("[AGENT:ERROR] apply central DHCP hosts file (catch-up): %v", err)
		}
		if _, _, err := a.applyCoreDNSDynamicHostsFile(); err != nil {
			loglevel.Warnf("[AGENT:ERROR] apply central DNS dynamic hosts file (catch-up): %v", err)
		}
	}
}

func (a *Agent) SeedPeerLeasesFromRestore(entries []leasesync.SyncedLease) int {
	now := time.Now().Unix()
	applied := 0
	for _, l := range entries {
		if l.ExpiresAt <= now {
			continue
		}
		if a.macHasRealReservation(l.MAC) {
			continue
		}
		a.peerDHCPLeases.Upsert(l)
		applied++
	}
	if applied > 0 {
		if _, _, err := a.applyCoreDHCPHostsFile(); err != nil {
			loglevel.Warnf("[AGENT:ERROR] apply central DHCP hosts file (restore): %v", err)
		}
		if _, _, err := a.applyCoreDNSDynamicHostsFile(); err != nil {
			loglevel.Warnf("[AGENT:ERROR] apply central DNS dynamic hosts file (restore): %v", err)
		}
	}
	return applied
}

func (a *Agent) applyCoreDHCPHostsFile() (reloaded, throttled bool, err error) {
	a.coreDHCPHostsMu.Lock()
	defer a.coreDHCPHostsMu.Unlock()

	real := dhcpcentralrender.Reservations(config.Cluster{Scopes: a.allScopes()})
	merged := mergeReservations(real, a.localDHCPLeases.Snapshot(), a.peerDHCPLeases.Snapshot())
	text, err := dhcpcentralrender.RenderHostsFile(merged)
	if err != nil {
		return false, false, fmt.Errorf("render central DHCP hosts file: %w", err)
	}
	hash := contentHash(text)

	a.mu.Lock()
	changed := a.coreDHCPHostsHash != hash
	a.mu.Unlock()
	if !changed {
		return false, false, nil
	}

	if err := atomicWriteFile(coreDHCPHostsPath(a.dataDir), []byte(text), 0640); err != nil {
		return false, false, fmt.Errorf("write central DHCP hosts file: %w", err)
	}
	if err := chownToDnshivedGroup(coreDHCPHostsPath(a.dataDir)); err != nil {
		return false, false, fmt.Errorf("chown central DHCP hosts file: %w", err)
	}
	throttled, err = a.reloadCoreDHCPUnit()
	if err != nil {
		return true, false, fmt.Errorf("reload central DHCP: %w", err)
	}
	if throttled {
		return true, true, nil
	}

	a.mu.Lock()
	a.coreDHCPHostsHash = hash
	a.mu.Unlock()
	return true, false, nil
}

// coreDHCPLogRotateThreshold is the size (bytes) at which
// RotateCoreDHCPLogIfNeeded/RotateCoreDNSLogIfNeeded truncate their own
// real dnsmasq log.
const coreDHCPLogRotateThreshold = 20 * 1024 * 1024

// RotateCoreDHCPLogIfNeeded truncates central DHCP's own real transaction
// log once it crosses coreDHCPLogRotateThreshold.
func (a *Agent) RotateCoreDHCPLogIfNeeded() error {
	return rotateLogIfNeeded(filepath.Join(a.dataDir, dhcpcentralrender.CoreDHCPLogFileName), coreDHCPLogRotateThreshold)
}

// RotateCoreDNSLogIfNeeded is RotateCoreDHCPLogIfNeeded's sibling for
// central DNS's optional query log (Cluster.CoreDNSQueryLogging).
func (a *Agent) RotateCoreDNSLogIfNeeded() error {
	return rotateLogIfNeeded(filepath.Join(a.dataDir, dnscentralrender.CoreDNSLogFileName), coreDHCPLogRotateThreshold)
}

// rotateLogIfNeeded is the shared truncate mechanic both
// RotateCoreDHCPLogIfNeeded/RotateCoreDNSLogIfNeeded call.
func rotateLogIfNeeded(path string, threshold int64) error {
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Size() < threshold {
		return nil
	}
	return os.Truncate(path, 0)
}

func (a *Agent) constructCoreDNSPlane() bool {
	restarted, throttled, err := a.applyCoreDNSConfig()
	if err != nil {
		loglevel.Warnf("[AGENT:ERROR] apply dnsmasq.central config: %v", err)
		return false
	}
	if throttled {
		loglevel.Infof("[AGENT:RATE_LIMIT] dnshived-dnsmasq@core-dns restart suppressed — will retry next tick")
		return false
	}
	if restarted {
		loglevel.Infof("[AGENT:DNSMASQ_RESTART] dnshived-dnsmasq@core-dns (config not yet applied to the running process)")
	}
	loglevel.Debugf("[AGENT:PLANE] dnshived-dnsmasq@core-dns running")
	return true
}

func (a *Agent) applyCoreDNSConfig() (restarted, throttled bool, err error) {
	text, err := dnscentralrender.Render(config.Cluster{
		Scopes:              a.allScopes(),
		GlobalDNSRecords:    a.globalDNSRecords,
		LocalDomains:        a.localDomains,
		ScopeDefaults:       &config.ScopeDefaults{Upstream: a.centralDNSUpstream},
		CoreDNSQueryLogging: a.coreDNSQueryLogging,
	}, a.coreDNSAddress, a.dataDir)
	if err != nil {
		return false, false, fmt.Errorf("render dnsmasq.central config: %w", err)
	}
	hash := contentHash(text)

	a.mu.Lock()
	changed := a.coreDNSConfigHash != hash
	a.mu.Unlock()
	if !changed {
		if a.unitActive("dnshived-dnsmasq@core-dns.service") {
			return false, false, nil
		}
	}

	if err := atomicWriteFile(coreDNSConfigPath(a.dataDir), []byte(text), 0640); err != nil {
		return false, false, fmt.Errorf("write dnsmasq.central config: %w", err)
	}
	throttled, err = a.restartCoreDNSUnit()
	if err != nil {
		return true, false, fmt.Errorf("restart dnsmasq.central: %w", err)
	}
	if throttled {
		return true, true, nil
	}

	a.mu.Lock()
	a.coreDNSConfigHash = hash
	a.mu.Unlock()
	return true, false, nil
}

func (a *Agent) constructCoreDHCPPlane() bool {
	restarted, throttled, err := a.applyCoreDHCPConfig()
	if err != nil {
		loglevel.Warnf("[AGENT:ERROR] apply central DHCP config: %v", err)
		return false
	}
	if throttled {
		loglevel.Infof("[AGENT:RATE_LIMIT] dnshived-dnsmasq@core-dhcp restart suppressed — will retry next tick")
		return false
	}
	if restarted {
		loglevel.Infof("[AGENT:DNSMASQ_RESTART] dnshived-dnsmasq@core-dhcp (config not yet applied to the running process)")
	}
	if _, _, err := a.applyCoreDHCPHostsFile(); err != nil {
		loglevel.Warnf("[AGENT:ERROR] apply central DHCP hosts file: %v", err)
	}
	loglevel.Debugf("[AGENT:PLANE] dnshived-dnsmasq@core-dhcp running")
	return true
}

// applyCoreDHCPConfig is applyCoreDNSConfig's DHCP counterpart.
func (a *Agent) applyCoreDHCPConfig() (restarted, throttled bool, err error) {
	text, err := dhcpcentralrender.Render(config.Cluster{
		Scopes:             a.allScopes(),
		DefaultDHCPOptions: a.defaultDHCPOptions,
		ScopeDefaults:      &config.ScopeDefaults{NodeIPSuffixes: a.nodeIPSuffixes},
	}, a.dataDir)
	if err != nil {
		return false, false, fmt.Errorf("render central DHCP config: %w", err)
	}
	hash := contentHash(text)

	a.mu.Lock()
	changed := a.coreDHCPConfigHash != hash
	a.mu.Unlock()
	if !changed {
		if a.unitActive("dnshived-dnsmasq@core-dhcp.service") {
			return false, false, nil
		}
	}

	if err := atomicWriteFile(coreDHCPConfigPath(a.dataDir), []byte(text), 0640); err != nil {
		return false, false, fmt.Errorf("write central DHCP config: %w", err)
	}
	throttled, err = a.restartCoreDHCPUnit()
	if err != nil {
		return true, false, fmt.Errorf("restart central DHCP: %w", err)
	}
	if throttled {
		return true, true, nil
	}

	a.mu.Lock()
	a.coreDHCPConfigHash = hash
	a.mu.Unlock()
	return true, false, nil
}

// contentHash is the shared hash primitive behind
// applyCoreDNSConfig/applyCoreDHCPConfig/applyRelayConfig's own
// commit-on-success comparisons.
func contentHash(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// PlaneHealth describes one detected drift in the permanent network plane.
type PlaneHealth struct {
	Scope    string
	What     string
	Detail   string
	Healable bool
}

func (a *Agent) lastGate(scope string) (state string, known bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	state, known = a.lastAppliedGate[scope]
	return state, known
}

// shouldSkipInterfaceRebuild reports whether constructScope should skip
// calling createInterface entirely for this call.
func (a *Agent) shouldSkipInterfaceRebuild(scope, iface string) bool {
	state, known := a.lastGate(scope)
	if !known || state != "open" {
		return false
	}
	_, err := net.InterfaceByName(iface)
	return err == nil
}

func addrsMatch(addrs []net.Addr, cidr string) bool {
	want, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return true // malformed config isn't this check's problem to flag
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.Equal(want) {
			return true
		}
	}
	return false
}

// CheckPlaneHealth verifies every already-constructed scope's VLAN
// interface and dnsmasq unit, plus the consolidated keepalived unit, are
// still actually present.
type sanityIfaceObservation struct {
	scope   string
	ifIndex int
}

func (a *Agent) checkConfigSanity(observed map[string]sanityIfaceObservation) []PlaneHealth {
	if a.sanityCheckDisabled || len(observed) == 0 {
		return nil
	}

	a.mu.Lock()
	planned := make(map[string]int, len(observed))
	for iface := range observed {
		if idx, ok := a.lastIfaceIndex[iface]; ok {
			planned[iface] = idx
		}
	}
	a.mu.Unlock()

	running := make(map[string]int, len(observed))
	for iface, o := range observed {
		running[iface] = o.ifIndex
	}

	if sanityFingerprint(planned) == sanityFingerprint(running) {
		return nil
	}

	ifaces := make([]string, 0, len(observed))
	for iface := range observed {
		ifaces = append(ifaces, iface)
	}
	sort.Strings(ifaces)

	loglevel.Infof("[AGENT:SANITY] fingerprint mismatch — checking %d ready interface(s) individually: %v", len(ifaces), ifaces)

	var found []PlaneHealth
	var toUpdate []string
	var firstSeen []string
	var unresolved []string
	for _, iface := range ifaces {
		live := running[iface]
		if live == 0 {
			unresolved = append(unresolved, iface)
			continue
		}
		want, hadPlanned := planned[iface]
		if !hadPlanned {
			firstSeen = append(firstSeen, fmt.Sprintf("%s(ifindex=%d)", iface, live))
			toUpdate = append(toUpdate, iface)
			continue
		}
		if want != live {
			loglevel.Warnf("[AGENT:SANITY] DRIFT: %s (scope %s) ifindex changed %d -> %d — interface was torn down and recreated under the same name, a bound socket may now point at a dead device",
				iface, observed[iface].scope, want, live)
			found = append(found, PlaneHealth{Scope: observed[iface].scope, What: "relay_socket_stale",
				Detail:   fmt.Sprintf("%s's ifindex changed (%d -> %d) since last verified — the interface was torn down and recreated under the same name, reloading dhcp+dns relay to clear any stale socket", iface, want, live),
				Healable: false})
			toUpdate = append(toUpdate, iface)
		}
	}
	if len(firstSeen) > 0 {
		loglevel.Infof("[AGENT:SANITY] first observation, caching as baseline (no prior value to compare against): %v", firstSeen)
	}
	if len(unresolved) > 0 {
		loglevel.Infof("[AGENT:SANITY] %d interface(s) did not resolve this tick (ifindex 0), skipped: %v", len(unresolved), unresolved)
	}

	if len(found) > 0 {
		relayErr := func() error { _, err := a.reloadRelayUnit(); return err }()
		dnsRelayErr := func() error { _, err := a.reloadDNSRelayUnit(); return err }()
		if relayErr != nil {
			loglevel.Infof("[AGENT:SANITY] reload dnshived-relay to clear stale socket(s): %v", relayErr)
		}
		if dnsRelayErr != nil {
			loglevel.Infof("[AGENT:SANITY] reload dnshived-dnsrelay to clear stale socket(s): %v", dnsRelayErr)
		}
		if relayErr == nil && dnsRelayErr == nil {
			loglevel.Infof("[AGENT:SANITY] reloaded dnshived-relay and dnshived-dnsrelay to clear %d stale socket(s): %v", len(found), toUpdate)
		}
	} else {
		loglevel.Infof("[AGENT:SANITY] no genuine drift found — mismatch fully explained by first-ever observation and/or a transient unresolved interface")
	}

	if len(toUpdate) > 0 {
		a.mu.Lock()
		if a.lastIfaceIndex == nil {
			a.lastIfaceIndex = make(map[string]int)
		}
		for _, iface := range toUpdate {
			a.lastIfaceIndex[iface] = running[iface]
		}
		a.mu.Unlock()
	}

	return found
}

func sanityFingerprint(m map[string]int) string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		fmt.Fprintf(&b, "%s=%d\n", name, m[name])
	}
	return contentHash(b.String())
}

func (a *Agent) CheckPlaneHealth() []PlaneHealth {

	a.mu.Lock()
	type readyScope struct {
		name string
		sc   config.ScopeConfig
	}
	var toCheck []readyScope
	allScopes := a.allScopes()
	names := make([]string, 0, len(allScopes))
	for name := range allScopes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, ok := a.ready[name]; ok {
			toCheck = append(toCheck, readyScope{name: name, sc: allScopes[name]})
		}
	}
	checkKeepalived := a.keepalivedReady
	a.mu.Unlock()

	// One SIGDATA dump for the whole tick, not one per scope.
	var vDump []byte
	if len(toCheck) > 0 {
		if d, err := a.vrrpDump(); err == nil {
			vDump = d
		}
	}

	var gateClosed map[string]bool
	var gateErr error
	if len(toCheck) > 0 {
		gateClosed, gateErr = a.gateDump()
	}

	type checkResult struct {
		findings []PlaneHealth
		scope    string
		ifIndex  int
	}
	dnsmasqStatus := a.unitCache().Prefixed("dnshived-dnsmasq@")
	results := make([]checkResult, len(toCheck))
	indices := make([]int, len(toCheck))
	for i := range toCheck {
		indices[i] = i
	}
	runConcurrent(indices, maxConcurrentGateOps, func(i int) {
		rs := toCheck[i]
		var findings []PlaneHealth
		iface := nftgate.InterfaceName(a.localParent(rs.sc.Parent), rs.sc.VLANID)
		ifi, err := net.InterfaceByName(iface)
		if err != nil {
			results[i] = checkResult{scope: rs.name, findings: []PlaneHealth{{Scope: rs.name, What: "interface",
				Detail: fmt.Sprintf("%s no longer exists", iface), Healable: true}}}
			return
		}

		if rs.sc.NodeIP != "" {
			addrs, aerr := ifi.Addrs()
			if aerr == nil && !addrsMatch(addrs, rs.sc.NodeIP) {
				findings = append(findings, PlaneHealth{Scope: rs.name, What: "node_ip",
					Detail: fmt.Sprintf("%s does not carry configured node_ip %s", iface, rs.sc.NodeIP), Healable: true})
			}
		}

		unit := "dnshived-dnsmasq@" + rs.name + ".service"
		st := dnsmasqStatus[unit]
		if st.ActiveState == "active" || st.ActiveState == "activating" {
			findings = append(findings, PlaneHealth{Scope: rs.name, What: "dnsmasq",
				Detail: fmt.Sprintf("%s is %s (expected inactive — DHCP/DNS now served by the shared relay/central instances, not per-scope)", unit, st.ActiveState), Healable: true})
		}

		if gateErr == nil {
			real := "open"
			if gateClosed[iface] {
				real = "closed"
			}
			if want, known := a.lastGate(rs.name); known && real != want {
				findings = append(findings, PlaneHealth{Scope: rs.name, What: "gate",
					Detail: fmt.Sprintf("nftables gate is %s, this node last set it %s", real, want), Healable: false})
			}
			if real == "open" && vDump != nil {
				if vst, verr := vrrpstate.ParseInstanceState(vDump, "DNSHIVED_"+rs.name); verr == nil && vst != "MASTER" {
					findings = append(findings, PlaneHealth{Scope: rs.name, What: "gate_vrrp_coherence",
						Detail: fmt.Sprintf("DHCP gate is open but VRRP state is %s, not MASTER", vst), Healable: false})
				}
			}
		}

		results[i] = checkResult{scope: rs.name, findings: findings, ifIndex: ifi.Index}
	})

	ifaceObserved := make(map[string]sanityIfaceObservation, len(results))
	for i, r := range results {
		iface := nftgate.InterfaceName(a.localParent(toCheck[i].sc.Parent), toCheck[i].sc.VLANID)
		ifaceObserved[iface] = sanityIfaceObservation{scope: r.scope, ifIndex: r.ifIndex}
	}
	found := a.checkConfigSanity(ifaceObserved)
	var driftedScopes []string
	for _, r := range results {
		healable := false
		for _, f := range r.findings {
			found = append(found, f)
			if f.Healable {
				healable = true
			}
		}
		if healable {
			driftedScopes = append(driftedScopes, r.scope)
		}
	}

	driftedKeepalived := false
	if checkKeepalived {
		if st := a.unitCache().Get("dnshived-keepalived.service"); st.ActiveState != "active" {
			found = append(found, PlaneHealth{What: "keepalived",
				Detail: fmt.Sprintf("dnshived-keepalived.service is %s (expected active)", st.ActiveState), Healable: true})
			driftedKeepalived = true
		}
	}

	if len(driftedScopes) > 0 || driftedKeepalived {
		a.mu.Lock()
		for _, name := range driftedScopes {
			delete(a.ready, name)
		}
		if driftedKeepalived {
			a.keepalivedReady = false
		}
		a.mu.Unlock()
	}

	found = append(found, a.checkTrunkLinkState()...)
	found = append(found, a.checkPeerMgmtHealth()...)
	found = append(found, a.checkOrphans(gateClosed)...)

	return found
}

func (a *Agent) checkTrunkLinkState() []PlaneHealth {
	trunks := make(map[string]bool)
	for _, sc := range a.allScopes() {
		if sc.Parent != "" {
			trunks[sc.Parent] = true
		}
	}
	if a.mgmtIface != "" {
		trunks[a.mgmtIface] = true
	}
	names := make([]string, 0, len(trunks))
	for t := range trunks {
		names = append(names, t)
	}
	sort.Strings(names)

	var found []PlaneHealth
	// readings feeds a.trunkReliability's own Observe calls, made AFTER
	// releasing a.mu below.
	type trunkReading struct {
		trunk string
		up    bool
	}
	var readings []trunkReading

	a.mu.Lock()
	if a.trunkLinkDown == nil {
		a.trunkLinkDown = make(map[string]bool)
	}
	for _, trunk := range names {
		up, ok := readCarrier(a.localParent(trunk))
		if !ok {
			continue
		}
		readings = append(readings, trunkReading{trunk: trunk, up: up})
		isDown := !up
		a.trunkLinkDown[trunk] = isDown
		if isDown {
			detail := fmt.Sprintf("carrier lost on %s — every scope on this trunk force-closed", trunk)
			if trunk == a.mgmtIface {
				detail = fmt.Sprintf("carrier lost on %s (management interface) — no scope is affected, but this node's own primary reachability path is degraded", trunk)
			}
			found = append(found, PlaneHealth{
				Scope:    trunk,
				What:     "trunk_link_down",
				Healable: false,
				Detail:   detail,
			})
		}
	}
	a.mu.Unlock()

	for _, r := range readings {
		a.trunkReliability.Observe(r.trunk, r.up)
	}
	return found
}

// isTrunkLinkDown is checked from Reconcile's own per-scope loop.
func (a *Agent) isTrunkLinkDown(trunk string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.trunkLinkDown[trunk]
}

func (a *Agent) TrunkHealth() map[string]bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]bool, len(a.trunkLinkDown))
	for trunk, down := range a.trunkLinkDown {
		if trunk == a.mgmtIface {
			continue
		}
		out[trunk] = !down
	}
	return out
}

func (a *Agent) LocalTrunkScores() map[string]int {
	a.mu.Lock()
	mgmt := a.mgmtIface
	a.mu.Unlock()

	out := make(map[string]int)
	for trunk, e := range a.trunkReliability.Snapshot() {
		if trunk == mgmt {
			continue
		}
		out[trunk] = e.Score
	}
	return out
}

// TrunkReliabilitySnapshot returns this node's own COMPLETE, unfiltered
// LOCAL trunk-reliability history.
func (a *Agent) TrunkReliabilitySnapshot() map[string]reliability.Entry {
	return a.trunkReliability.Snapshot()
}

// ResetTrunkReliability clears this node's own persisted LOCAL trust-index
// history for trunk back to "never observed".
func (a *Agent) ResetTrunkReliability(trunk string) {
	a.trunkReliability.Reset(trunk)
}

func (a *Agent) RestoreTrunkReliability(entries map[string]reliability.Entry) {
	a.trunkReliability.RestoreAll(entries)
}

// readCarrier reads /sys/class/net/<iface>/carrier — "1" means link up,
// "0" means link down (cable pulled, switch port administratively
// disabled).
func readCarrier(iface string) (up bool, ok bool) {
	data, err := os.ReadFile(filepath.Join("/sys/class/net", iface, "carrier"))
	if err != nil {
		return false, false
	}
	return strings.TrimSpace(string(data)) == "1", true
}

func (a *Agent) checkPeerMgmtHealth() []PlaneHealth {
	if a.observer == nil {
		return nil
	}

	var found []PlaneHealth
	statuses := a.observer.FallbackStatuses()
	for _, role := range cluster.OtherCoreRoles(a.role) {
		reachablePrimary, primaryAddr := primaryStatus(a.observer, role)
		if reachablePrimary {
			continue // fine via primary — nothing to report
		}
		if primaryAddr == "" {
			continue
		}
		fbAddr := firstReachableFallbackAddr(statuses, role)
		if fbAddr == "" {
			continue
		}
		found = append(found, PlaneHealth{
			Scope:    role,
			What:     "peer_mgmt_down",
			Healable: false,
			Detail: fmt.Sprintf(
				"%s (%s) is unreachable via its mgmt/control address, but confirmed alive via its own scope-VLAN address (%s)",
				role, primaryAddr, fbAddr,
			),
		})
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Scope < found[j].Scope })
	return found
}

// primaryStatus reports whether role is currently reachable via the
// PRIMARY path alone (never fallback), plus the best-known primary address
// for it.
func primaryStatus(o *cluster.Observer, role string) (reachable bool, addr string) {
	for _, peer := range o.Snapshot() {
		if peer.Identity == nil || peer.Identity.Role != role {
			continue
		}
		addr = peer.Addr
		if peer.Reachable {
			reachable = true
		}
	}
	return reachable, addr
}

// witnessFor returns the cached WitnessState for a scope.
func (a *Agent) witnessFor(scope string) WitnessState {
	a.tokenMu.RLock()
	defer a.tokenMu.RUnlock()
	return a.witness[scope]
}

// buildAuthority normalizes ReconcileInputs into per-scope
// AuthorityInputs.
func (a *Agent) buildAuthority(scope string, in ReconcileInputs, currentlyServing bool) AuthorityInputs {
	owns := false
	for _, s := range in.OwnedScopes {
		if s == scope {
			owns = true
			break
		}
	}

	leaseValid := false
	var leaseExpires int64
	if l, ok := in.HeldLeases[scope]; ok {
		leaseValid = true
		leaseExpires = l.ExpiresAt
	}

	return AuthorityInputs{
		State:            in.State,
		OwnsScope:        owns,
		LeaseValid:       leaseValid,
		LeaseExpiresAt:   leaseExpires,
		SelfToken:        in.SelfToken,
		Watermark:        in.Watermark,
		Witness:          a.witnessFor(scope),
		WitnessRequired:  a.psk != "",
		CurrentlyServing: currentlyServing,
		Now:              in.Now,
	}
}

// maxConcurrentGateOps bounds how many scopes' gate/witness I/O
// (ApplyDesiredAuthority's openGate/closeGate, renewalLoop's renewWitness)
// run at once.
const maxConcurrentGateOps = 16

// runConcurrent calls fn(item) for every item in items, at most
// maxConcurrency at a time, and waits for all of them to finish before
// returning.
func runConcurrent[T any](items []T, maxConcurrency int, fn func(T)) {
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	for _, item := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(item T) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(item)
		}(item)
	}
	wg.Wait()
}

func splitCloseOpenDecisions(decisions []gateDecision) (closes, opens []gateDecision) {
	for _, d := range decisions {
		if d.desired.Serve {
			opens = append(opens, d)
		} else {
			closes = append(closes, d)
		}
	}
	return closes, opens
}

// Reconcile evaluates the predicate for every configured scope and drives
// the DHCP gate accordingly.
func (a *Agent) Reconcile(in ReconcileInputs) Decision {
	decisionStart := time.Now()

	a.mu.Lock()

	a.lastInputs = in

	// Track settling window — wall-clock (see settlingDuration).
	nowForSettling := time.Unix(in.Now, 0)
	if in.State != a.lastState {
		a.stableSince = nowForSettling
		a.lastState = in.State
	}
	settling := in.State == fsm.StateStable && nowForSettling.Sub(a.stableSince) < settlingDuration

	currentScopes := a.allScopes()
	scopes := make([]string, 0, len(currentScopes))
	for s := range currentScopes {
		scopes = append(scopes, s)
	}
	sort.Strings(scopes)

	// Any scope not yet in a.ready failed construction at startup (or has
	// never been attempted) — retry it here rather than leaving it
	// permanently unbuilt.
	var needsConstruction []string
	for _, scope := range scopes {
		if _, ok := a.ready[scope]; !ok {
			needsConstruction = append(needsConstruction, scope)
		}
	}
	needsKeepalived := !a.keepalivedReady
	needsRelay := !a.relayReady
	needsDNSRelay := !a.dnsRelayReady
	needsCoreDNS := !a.coreDNSReady
	needsCoreDHCP := !a.coreDHCPReady

	var decisions []gateDecision
	for _, scope := range scopes {
		if _, ok := a.ready[scope]; !ok {
			continue
		}
		wasServing := a.serving[scope]
		auth := a.buildAuthority(scope, in, wasServing)
		allowed, reason := scopeServeAllowed(auth)

		forceSettlingClose := settling && allowed && !wasServing
		effAllowed := allowed && !forceSettlingClose

		if effAllowed {
			if parent := currentScopes[scope].Parent; a.trunkLinkDown[parent] {
				effAllowed = false
				reason = "trunk link down: " + parent
			}
		}

		var timerSnap *AntiFlap
		if af, ok := a.antiFlap[scope]; ok {
			cp := *af
			timerSnap = &cp
		}

		now := time.Unix(in.Now, 0)
		desired, timerAction, timerDelay := EvaluateAntiFlap(now, effAllowed, reason, wasServing,
			timerSnap, a.peerCurrentlyServing(scope), a.isPreferredScope(scope), a.rebalanceApproved(scope),
			a.rebalanceDelay, a.quickReclaimDelay, a.antiFlapQuietWindow)

		if forceSettlingClose {
			elapsed := now.Sub(a.stableSince).Round(time.Second)
			remaining := (settlingDuration - now.Sub(a.stableSince)).Round(time.Second)
			loglevel.Debugf("[AGENT:SETTLING] suppressing gate-open for scope %s (stable for %s, eligible in %s)",
				scope, elapsed, remaining)
			desired.Reason = fmt.Sprintf("settling (stable for %s, eligible in %s)", elapsed, remaining)
		}

		switch timerAction {
		case timerStart:
			a.antiFlap[scope] = &AntiFlap{StableSince: now, Delay: timerDelay}
			loglevel.Infof("[AGENT:ANTIFLAP] scope %s — peer serving, anti-flap timer started (%s)",
				scope, timerDelay)
		case timerReset:
			a.antiFlap[scope] = &AntiFlap{StableSince: now, Delay: timerDelay}
			if timerDelay < a.rebalanceDelay {
				loglevel.Infof("[AGENT:ANTIFLAP] scope %s — fenced but quiet beforehand, quick-reclaim wait (%s, not the full %s)",
					scope, timerDelay, a.rebalanceDelay)
			}
		}

		priority := vrrpPriority(desired.Serve, effAllowed)

		if allowed && !wasServing && !forceSettlingClose && timerSnap != nil {
			if desired.Serve {
				loglevel.Infof("[AGENT:REBALANCE] scope %s stable for %s, taking over",
					scope, timerSnap.StableFor().Round(time.Second))
			} else {
				loglevel.Debugf("[AGENT:READY_WAIT] scope %s stable for %s, eligible in %s",
					scope, timerSnap.StableFor().Round(time.Second), timerSnap.Remaining().Round(time.Second))
			}
		}

		decisions = append(decisions, gateDecision{scope, wasServing, desired, priority})
	}

	lastPriorities := make(map[string]int, len(a.vrrpPriority))
	for scope, p := range a.vrrpPriority {
		lastPriorities[scope] = p
	}

	a.mu.Unlock()

	// Retry construction for anything not yet built, before evaluating any
	// gate action this tick.
	a.constructMu.Lock()
	freshScopes := a.allScopes()
	constructedScopes := make(map[string]bool, len(needsConstruction))
	for _, scope := range needsConstruction {
		sc, stillConfigured := freshScopes[scope]
		if !stillConfigured {
			loglevel.Infof("[AGENT:HOT_RELOAD] %s: skipping stale construction retry — "+
				"removed while this tick waited for constructMu", scope)
			continue
		}
		if a.constructScope(scope, sc) {
			constructedScopes[scope] = true
		}
	}
	keepalivedConstructed := false
	if needsKeepalived {
		keepalivedConstructed = a.constructKeepalivedPlane(constructedScopes)
	}
	relayConstructed := false
	if needsRelay {
		relayConstructed = a.constructRelayPlane()
	} else {
		a.refreshRelayConfig()
	}
	dnsRelayConstructed := false
	if needsDNSRelay {
		dnsRelayConstructed = a.constructDNSRelayPlane()
	} else {
		a.refreshDNSRelayConfig()
	}
	coreDNSConstructed := false
	if needsCoreDNS {
		coreDNSConstructed = a.constructCoreDNSPlane()
	} else {
		a.refreshCoreDNSConfig()
	}
	coreDHCPConstructed := false
	if needsCoreDHCP {
		coreDHCPConstructed = a.constructCoreDHCPPlane()
	} else {
		a.refreshCoreDHCPConfig()
	}
	a.constructMu.Unlock()

	// Phase 2: execute WITHOUT the lock.
	closeDecisions, openDecisions := splitCloseOpenDecisions(decisions)

	results := make([]gateResult, 0, len(decisions))
	var resultsMu sync.Mutex
	collect := func(d gateDecision) {
		r := a.ApplyDesiredAuthority(d.scope, d.wasServing, d.desired)
		resultsMu.Lock()
		results = append(results, r)
		resultsMu.Unlock()
	}
	runConcurrent(closeDecisions, maxConcurrentGateOps, collect)
	runConcurrent(openDecisions, maxConcurrentGateOps, collect)

	var committedPriorities map[string]int
	if !(needsKeepalived && keepalivedConstructed) {
		if full, ok := a.reconcileVRRPPriorities(decisions, lastPriorities, constructedScopes, decisionStart); ok {
			committedPriorities = full
		}
	}

	// Phase 3: re-acquire lock and commit bookkeeping.
	a.mu.Lock()

	if committedPriorities != nil {
		a.vrrpPriority = committedPriorities
	}

	for scope := range constructedScopes {
		a.ready[scope] = time.Now()
	}
	if keepalivedConstructed {
		a.keepalivedReady = true
	}
	if relayConstructed {
		a.relayReady = true
	}
	if dnsRelayConstructed {
		a.dnsRelayReady = true
	}
	if coreDNSConstructed {
		a.coreDNSReady = true
	}
	if coreDHCPConstructed {
		a.coreDHCPReady = true
	}

	for _, r := range results {
		switch r.kind {
		case gateClose:
			if r.wasServing {
				loglevel.Infof("[AGENT:STOP] scope %s (%s)", r.scope, r.reason)
			}
			delete(a.serving, r.scope)
		case gateOpen:
			if r.opened {
				if !r.wasServing {
					loglevel.Infof("[AGENT:START] scope %s (%s)", r.scope, r.reason)
				}
				a.serving[r.scope] = true
				delete(a.antiFlap, r.scope) // successfully serving — clear
			}
			// !r.opened: witness denied/unreachable (openGate already logged it).
		case gateKeepOpen:
			// no bookkeeping change — already serving=true
		}
	}

	// Build result.
	resultByScope := make(map[string]gateResult, len(results))
	for _, r := range results {
		resultByScope[r.scope] = r
	}
	result := Decision{Scopes: make(map[string]ServeState)}
	for _, scope := range scopes {
		var reason string
		if r, ok := resultByScope[scope]; ok {
			reason = r.reason
		} else {
			auth := a.buildAuthority(scope, in, a.serving[scope])
			_, reason = scopeServeAllowed(auth)
		}
		ss := ServeState{
			Scope:   scope,
			Serving: a.serving[scope],
			Reason:  reason,
		}
		if readySince, isReady := a.ready[scope]; isReady {
			ss.Ready = true
			ss.ReadySince = &readySince
		}
		result.Scopes[scope] = ss
		if !currentScopes[scope].DNSMasqDisabled {
			a.trackUnserved(scope, ss.Serving, reason, in, time.Unix(in.Now, 0))
		}
	}
	for scope := range a.unserved {
		if _, ok := currentScopes[scope]; !ok {
			delete(a.unserved, scope)
		}
	}
	for scope := range a.unservedKnown {
		if _, ok := currentScopes[scope]; !ok {
			delete(a.unservedKnown, scope)
		}
	}

	// Manage the renewal loop.
	if a.psk != "" {
		if len(a.serving) > 0 && a.renewTicker == nil {
			a.renewTicker = time.NewTicker(5 * time.Second)
			a.quitRenew = make(chan struct{})
			go a.renewalLoop(a.renewTicker, a.quitRenew)
		}
		if len(a.serving) == 0 && a.renewTicker != nil {
			a.renewTicker.Stop()
			close(a.quitRenew)
			a.renewTicker = nil
		}
	}

	a.mu.Unlock()

	return result
}

const (
	unservedWarnAfter = 30 * time.Second
	unservedRepeat    = 5 * time.Minute
	unservedGapLog    = 5 * time.Second
)

type unservedState struct {
	since   time.Time
	lastLog time.Time
	// atStart: the gap was already there when this node first looked at
	// the scope, so its start is unknown.
	atStart bool
}

// trackUnserved warns when no node serves scope: after unservedWarnAfter,
// again every unservedRepeat, and once when a node serves it again; a
// shorter gap of at least unservedGapLog is logged when it ends.
func (a *Agent) trackUnserved(scope string, servingHere bool, reason string, in ReconcileInputs, now time.Time) {
	servedBy := in.ServedBy[scope]
	if servingHere {
		servedBy = a.role
	}
	known := a.unservedKnown[scope]
	a.unservedKnown[scope] = true
	st := a.unserved[scope]
	if servedBy != "" {
		switch {
		case st == nil:
		case !st.lastLog.IsZero():
			loglevel.Infof("[AGENT:UNSERVED] scope %s served again by %s after %s", scope, servedBy, now.Sub(st.since).Round(time.Second))
		case !st.atStart && now.Sub(st.since) >= unservedGapLog:
			loglevel.Infof("[AGENT:UNSERVED] scope %s was served by no node for %s, now served by %s", scope, now.Sub(st.since).Round(time.Second), servedBy)
		}
		delete(a.unserved, scope)
		return
	}
	if st == nil {
		a.unserved[scope] = &unservedState{since: now, atStart: !known}
		return
	}
	if now.Sub(st.since) < unservedWarnAfter || (!st.lastLog.IsZero() && now.Sub(st.lastLog) < unservedRepeat) {
		return
	}
	owner := in.DesiredOwners[scope]
	if owner == "" {
		owner = "none"
	}
	loglevel.Warnf("[AGENT:UNSERVED] WARNING scope %s served by no node for %s — this node (%s, %s): %s; desired owner here: %s (generation %d)",
		scope, now.Sub(st.since).Round(time.Second), a.role, in.State, reason, owner, in.SelfToken.Generation)
	st.lastLog = now
}

// --- DHCP gate actions ---

// closeGate closes the DHCP gate for a scope immediately and
// unconditionally.
func (a *Agent) closeGate(scope, reason string) {
	sc, hasCfg := a.scopeConfig(scope)
	if !hasCfg {
		return
	}
	if err := a.setDHCPGateState(scope, sc, "closed"); err != nil {
		loglevel.Warnf("[AGENT:ERROR] scope %s: close gate: %v", scope, err)
	} else {
		a.recordAppliedGate(scope, "closed")
	}
	a.clearWitness(scope)
}

func (a *Agent) recordAppliedGate(scope, state string) {
	a.mu.Lock()
	a.lastAppliedGate[scope] = state
	a.mu.Unlock()
}

// openGate attempts to acquire the witness token for a scope and, only if
// successful, opens its DHCP gate.
func (a *Agent) openGate(scope, reason string) bool {
	sc, hasCfg := a.scopeConfig(scope)
	if !hasCfg {
		return false
	}

	if a.psk != "" {
		if !a.acquireWitness(scope) {
			loglevel.Warnf("[AGENT:TOKEN_DENY] cannot open gate for scope %s — arbiter token not acquired", scope)
			return false
		}
	}

	if err := a.setDHCPGateState(scope, sc, "open"); err != nil {
		loglevel.Warnf("[AGENT:ERROR] scope %s: open gate: %v", scope, err)
		a.clearWitness(scope) // don't hold a token for a gate we failed to open
		return false
	}
	a.recordAppliedGate(scope, "open")

	iface := nftgate.InterfaceName(a.localParent(sc.Parent), sc.VLANID)
	loglevel.Infof("[AGENT:GATE_OPEN] scope %s (%s) on %s", scope, reason, iface)
	return true
}

// ApplyDesiredAuthority is the sole place that turns a pure
// Evaluate+AntiFlap decision into an actual gate/dnsmasq/witness action.
func (a *Agent) ApplyDesiredAuthority(scope string, wasServing bool, desired DesiredAuthority) gateResult {
	if !desired.Serve {
		a.closeGate(scope, desired.Reason)
		return gateResult{scope, gateClose, desired.Reason, wasServing, false}
	}
	if wasServing {
		return gateResult{scope, gateKeepOpen, desired.Reason, wasServing, true}
	}
	opened := a.openGate(scope, desired.Reason)
	return gateResult{scope, gateOpen, desired.Reason, wasServing, opened}
}

// reconcileVRRPPriorities is the sole place VRRP priority is written and
// keepalived reloaded.
func (a *Agent) reconcileVRRPPriorities(decisions []gateDecision, last map[string]int, constructedScopes map[string]bool, decisionStart time.Time) (map[string]int, bool) {
	ready := a.readyScopeSet(constructedScopes)
	allCurrentScopes := a.allScopes()
	currentScopes := make(map[string]config.ScopeConfig, len(allCurrentScopes))
	for scope, sc := range allCurrentScopes {
		if ready[scope] {
			currentScopes[scope] = sc
		}
	}
	full := make(map[string]int, len(currentScopes))
	for _, d := range decisions {
		if _, ok := currentScopes[d.scope]; !ok {
			continue
		}
		full[d.scope] = d.priority
	}
	for scope, sc := range currentScopes {
		if _, ok := full[scope]; ok {
			continue
		}
		if p, ok := last[scope]; ok {
			full[scope] = p
			continue
		}
		full[scope] = staticDefaultPriority(sc, a.role)
	}

	sig := vrrpConfigSignature(currentScopes)
	a.mu.Lock()
	sigChanged := a.vrrpConfigSig != sig
	a.mu.Unlock()

	changed := len(constructedScopes) > 0 || sigChanged
	if !changed {
		for scope, p := range full {
			if last[scope] != p {
				changed = true
				break
			}
		}
	}
	if !changed {
		return last, true
	}

	if err := a.renderKeepalivedConfigAll(full, constructedScopes); err != nil {
		loglevel.Warnf("[AGENT:ERROR] render keepalived config: %v", err)
		return last, false
	}
	throttled, err := a.reloadKeepalived()
	if err != nil {
		loglevel.Warnf("[AGENT:ERROR] reload keepalived (config rendered, live process not yet updated): %v", err)
		return last, false
	}
	if throttled {
		loglevel.Infof("[AGENT:VRRP_PRIORITY] reload throttled by helper — config rendered, live process not yet updated, will retry")
		return last, false
	}
	loglevel.Infof("[AGENT:VRRP_PRIORITY] keepalived reloaded %s after decision",
		time.Since(decisionStart).Round(time.Millisecond))
	a.mu.Lock()
	a.vrrpConfigSig = sig
	a.mu.Unlock()
	return full, true
}

// vrrpConfigSignature computes a deterministic signature of every scope's
// VRRP-relevant fields (VIP, VRRPID, AdvertIntMS, VRRPVersion).
func vrrpConfigSignature(scopes map[string]config.ScopeConfig) string {
	names := make([]string, 0, len(scopes))
	for name := range scopes {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		sc := scopes[name]
		fmt.Fprintf(&b, "%s|%s|%d|%d|%d\n", name, sc.VIP, sc.VRRPID, sc.AdvertIntMS, sc.VRRPVersion)
	}
	h := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(h[:])
}

// isPreferredScope returns true if this worker is the preferred owner for
// the scope.
func (a *Agent) isPreferredScope(scope string) bool {
	sc, ok := a.scopeConfig(scope)
	if !ok {
		return false
	}
	return sc.PreferredWorker == a.role
}

// peerCurrentlyServing checks if any reachable peer is serving the given
// scope, from cached identity data collected by the observer's own
// handshake probe cycle.
func (a *Agent) peerCurrentlyServing(scope string) bool {
	if a.observer == nil {
		return false
	}
	for _, peer := range a.observer.Snapshot() {
		if !peer.Reachable || peer.Identity == nil {
			continue
		}
		for _, s := range peer.Identity.Serving {
			if s == scope {
				return true
			}
		}
	}
	return false
}

func (a *Agent) rebalanceApproved(scope string) bool {
	sc, ok := a.scopeConfig(scope)
	if !ok || sc.RebalanceApprovedAt <= 0 {
		return false
	}
	return !time.Unix(sc.RebalanceApprovedAt, 0).Before(a.startedAt)
}

// --- Witness token management ---

func (a *Agent) requiredArbiterQuorum() (needed int, standalone bool, viaFailure bool) {
	if a.observer == nil {
		return 2, false, false
	}
	total := a.observer.EffectiveQuorum().TotalVoters
	if total <= 1 {
		rawTotal := a.observer.Quorum().TotalVoters
		return 1, true, rawTotal > 1
	}
	return total/2 + 1, false, false
}

// arbiterCandidate is one arbiter instance this node may poll for a
// witness grant/renewal.
type arbiterCandidate struct {
	addr     string // primary/mgmt address, tried first
	fallback string // alternate path to the SAME instance; "" if none known
}

func (a *Agent) arbiterAddrs() []arbiterCandidate {
	var out []arbiterCandidate
	seen := make(map[string]bool)
	add := func(c arbiterCandidate) {
		if c.addr == "" || seen[c.addr] {
			return
		}
		seen[c.addr] = true
		out = append(out, c)
	}
	if a.selfAddr != "" {
		add(arbiterCandidate{addr: a.selfAddr, fallback: selfLoopbackAddr(a.selfAddr)})
	}
	if a.observer != nil {
		statuses := a.observer.FallbackStatuses()
		for _, role := range cluster.OtherCoreRoles(a.role) {
			_, addr := primaryStatus(a.observer, role)
			fb := firstReachableFallbackAddr(statuses, role)
			if addr == "" {
				addr = fb
				fb = ""
			}
			if addr == "" {
				continue
			}
			add(arbiterCandidate{addr: addr, fallback: fb})
		}
	}
	return out
}

// firstReachableFallbackAddr picks ONE confirmed-reachable fallback
// address for role from statuses.
func firstReachableFallbackAddr(statuses []cluster.FallbackStatus, role string) string {
	var candidates []cluster.FallbackStatus
	for _, fs := range statuses {
		if fs.Role == role && fs.Reachable && fs.Addr != "" {
			candidates = append(candidates, fs)
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Parent < candidates[j].Parent })
	if len(candidates) == 0 {
		return ""
	}
	return candidates[0].Addr
}

// selfLoopbackAddr derives this node's own loopback address from its real
// control address — same port, 127.0.0.1 instead of the real host.
func selfLoopbackAddr(selfAddr string) string {
	_, port, err := net.SplitHostPort(selfAddr)
	if err != nil || port == "" {
		return ""
	}
	return net.JoinHostPort("127.0.0.1", port)
}

// clearWitness removes every cached witness state for a scope — every
// per-instance raw token as well as the aggregated predicate state.
func (a *Agent) clearWitness(scope string) {
	a.tokenMu.Lock()
	delete(a.tokenRaw, scope)
	delete(a.witness, scope)
	a.tokenMu.Unlock()
}

func (a *Agent) acquireWitness(scope string) bool {
	candidates := a.arbiterAddrs()
	if len(candidates) == 0 {
		loglevel.Warnf("[AGENT:TOKEN_DENY] no arbiter instance reachable for scope %s", scope)
		a.clearWitness(scope)
		return false
	}

	type instanceResult struct {
		addr      string
		ok        bool
		raw       json.RawMessage
		expiresAt int64
	}
	results := make([]instanceResult, len(candidates))
	indices := make([]int, len(candidates))
	for i := range candidates {
		indices[i] = i
	}
	runConcurrent(indices, maxConcurrentGateOps, func(i int) {
		c := candidates[i]
		raw, expiresAt, ok := a.acquireFromInstance(scope, c)
		results[i] = instanceResult{addr: c.addr, ok: ok, raw: raw, expiresAt: expiresAt}
	})

	a.tokenMu.Lock()
	if a.tokenRaw[scope] == nil {
		a.tokenRaw[scope] = make(map[string]json.RawMessage)
	}
	agreed := 0
	var minExpiry int64
	for _, r := range results {
		if r.ok {
			a.tokenRaw[scope][r.addr] = r.raw
			agreed++
			if minExpiry == 0 || r.expiresAt < minExpiry {
				minExpiry = r.expiresAt
			}
		} else {
			delete(a.tokenRaw[scope], r.addr)
		}
	}
	required, standalone, viaFailure := a.requiredArbiterQuorum()
	quorumOK := agreed >= required
	if quorumOK {
		a.witness[scope] = WitnessState{Held: true, ExpiresAt: minExpiry}
	} else {
		delete(a.witness, scope)
	}
	if len(a.tokenRaw[scope]) == 0 {
		delete(a.tokenRaw, scope)
	}
	a.tokenMu.Unlock()

	if !quorumOK {
		loglevel.Warnf("[AGENT:TOKEN_DENY] quorum not reached for scope %s (%d/%d arbiter instance(s) agreed, need %d)",
			scope, agreed, len(candidates), required)
		return false
	}
	if standalone {
		if viaFailure {
			loglevel.Warnf("[AGENT:STANDALONE] witness confirmed for scope %s — a configured peer has been unreachable past the fail-grace period, serving without peer quorum until it reconnects and stabilizes", scope)
		} else {
			loglevel.Warnf("[AGENT:STANDALONE] witness confirmed for scope %s — this is the only configured core node (no peers left after offboard), serving without peer quorum until a replacement is onboarded", scope)
		}
		return true
	}
	loglevel.InfoOnChange("token:"+scope, fmt.Sprintf("%d/%d", agreed, len(candidates)), "[AGENT:TOKEN_ACQ] witness confirmed for scope %s (%d/%d arbiter instance(s) agreed)", scope, agreed, len(candidates))
	return true
}

func (a *Agent) postWitnessRequest(addr, path, scope string, body []byte) (raw json.RawMessage, expiresAt int64, accepted, dialFailed bool) {
	url := a.witnessScheme() + "://" + addr + path
	resp, err := a.witnessHTTPClient().Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, 0, false, true
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, false, false
	}
	var result struct {
		Accepted bool            `json:"accepted"`
		Token    json.RawMessage `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || !result.Accepted {
		return nil, 0, false, false
	}
	expiresAt, err = a.checkGrant(scope, result.Token)
	if err != nil {
		loglevel.Warnf("[AGENT:TOKEN_DENY] grant from %s for scope %s rejected: %v", addr, scope, err)
		return nil, 0, false, false
	}
	return result.Token, expiresAt, true, false
}

const maxGrantAhead = time.Minute

func (a *Agent) checkGrant(scope string, raw json.RawMessage) (int64, error) {
	var tok arbiter.Token
	if err := json.Unmarshal(raw, &tok); err != nil {
		return 0, fmt.Errorf("unreadable token: %w", err)
	}
	if !tok.Verify([]byte(a.psk)) {
		return 0, errors.New("bad signature")
	}
	if tok.Scope != scope || tok.Owner != a.nodeID || tok.Incarnation != a.incarnation {
		return 0, fmt.Errorf("token is for scope %s, owner %s, incarnation %d", tok.Scope, tok.Owner, tok.Incarnation)
	}
	now := time.Now()
	if !tok.ExpiresAt.After(now) {
		return 0, errors.New("token already expired")
	}
	if tok.ExpiresAt.After(now.Add(maxGrantAhead)) {
		return 0, fmt.Errorf("expiry %s is more than %s ahead", tok.ExpiresAt.Format(time.RFC3339), maxGrantAhead)
	}
	return tok.ExpiresAt.Unix(), nil
}

// acquireFromInstance requests or renews a witness token for scope from
// exactly one arbiter instance (c).
func (a *Agent) acquireFromInstance(scope string, c arbiterCandidate) (json.RawMessage, int64, bool) {
	a.tokenMu.RLock()
	existing, hasExisting := a.tokenRaw[scope][c.addr]
	a.tokenMu.RUnlock()

	if hasExisting {
		if raw, expiresAt, ok := a.renewFromInstance(scope, c, existing); ok {
			return raw, expiresAt, true
		}
	}

	now := time.Now().Unix()
	nonce := randomHex(16)
	data := fmt.Sprintf("%s:%s:%d:%d:%s", scope, a.nodeID, a.incarnation, now, nonce)
	hmacHex := psksign.Sign([]byte(a.psk), data)

	reqBody := map[string]interface{}{
		"scope":       scope,
		"node_id":     a.nodeID,
		"incarnation": a.incarnation,
		"timestamp":   now,
		"nonce":       nonce,
		"hmac":        hmacHex,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, 0, false
	}

	raw, expiresAt, accepted, dialFailed := a.postWitnessRequest(c.addr, "/api/v1/token/request", scope, body)
	if dialFailed && c.fallback != "" {
		loglevel.Warnf("[AGENT:TOKEN_DENY] request to %s failed for scope %s, trying fallback %s", c.addr, scope, c.fallback)
		raw, expiresAt, accepted, dialFailed = a.postWitnessRequest(c.fallback, "/api/v1/token/request", scope, body)
	}
	if dialFailed {
		loglevel.Warnf("[AGENT:TOKEN_DENY] request to %s failed for scope %s: no reachable path", c.addr, scope)
	}
	if !accepted {
		return nil, 0, false
	}
	return raw, expiresAt, true
}

// renewFromInstance renews an already-held raw token against exactly one
// arbiter instance (c).
func (a *Agent) renewFromInstance(scope string, c arbiterCandidate, tokenJSON json.RawMessage) (json.RawMessage, int64, bool) {
	now := time.Now().Unix()
	nonce := randomHex(16)
	reqBody := map[string]interface{}{
		"token":     tokenJSON,
		"nonce":     nonce,
		"timestamp": now,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, 0, false
	}

	raw, expiresAt, accepted, dialFailed := a.postWitnessRequest(c.addr, "/api/v1/token/renew", scope, body)
	if dialFailed && c.fallback != "" {
		raw, expiresAt, accepted, _ = a.postWitnessRequest(c.fallback, "/api/v1/token/renew", scope, body)
	}
	if !accepted {
		return nil, 0, false
	}
	return raw, expiresAt, true
}

// --- token renewal loop ---

// renewalLoop takes ticker/quit as PARAMETERS, not read live off
// a.renewTicker/a.quitRenew.
func (a *Agent) renewalLoop(ticker *time.Ticker, quit chan struct{}) {
	for {
		select {
		case <-ticker.C:
			a.mu.Lock()
			scopes := make([]string, 0, len(a.serving))
			for s := range a.serving {
				scopes = append(scopes, s)
			}
			a.mu.Unlock()

			runConcurrent(scopes, maxConcurrentGateOps, func(scope string) {
				if !a.acquireWitness(scope) {
					loglevel.Warnf("[AGENT:TOKEN_EXPIRE] renewal failed for scope %s", scope)
				}
			})
		case <-quit:
			return
		}
	}
}

// --- Privileged operations (dispatch to helper or direct) ---

func (a *Agent) createInterface(scope string, sc config.ScopeConfig) error {
	if a.helperClient != nil {
		if err := a.helperClient.AddScopes([]string{scope}); err != nil {
			return fmt.Errorf("sync helper allowlist for scope %s: %w", scope, err)
		}
		return a.helperClient.CreateInterface(scope, sc.Parent, sc.VLANID, sc.NodeIP)
	}
	return errNoHelper
}

func (a *Agent) deleteInterface(scope string, sc config.ScopeConfig) {
	sc.Parent = a.localParent(sc.Parent)
	DeleteInterface(a.helperClient, scope, sc)
}

// DeleteInterface is the package-level form of (*Agent).deleteInterface,
// so a node decommission can tear down VLAN interfaces without a full
// *Agent.
func DeleteInterface(helperClient *helper.Client, scope string, sc config.ScopeConfig) {
	if helperClient == nil {
		loglevel.Warnf("[AGENT:ERROR] delete interface for scope %s: %v", scope, errNoHelper)
		return
	}
	helperClient.DeleteInterface(scope, sc.Parent, sc.VLANID)
}

func (a *Agent) stopDnsmasqUnit(scope string) error {
	defer a.unitsChanged()
	if a.helperClient != nil {
		return a.helperClient.StopDnsmasq(scope)
	}
	return errNoHelper
}

// restartDnsmasqUnit applies a config change refreshScopeConfig already
// wrote to disk to the actually-running dnsmasq process.
func (a *Agent) restartDnsmasqUnit(scope string) (throttled bool, err error) {
	defer a.unitsChanged()
	if a.helperClient != nil {
		return a.helperClient.RestartDnsmasq(scope)
	}
	return false, errNoHelper
}

// restartRelayUnit restarts the single consolidated dnshived-relay unit.
func (a *Agent) restartRelayUnit() (throttled bool, err error) {
	defer a.unitsChanged()
	if a.helperClient != nil {
		return a.helperClient.RestartRelay()
	}
	return false, errNoHelper
}

// reloadRelayUnit SIGHUPs the single consolidated dnshived-relay unit.
func (a *Agent) reloadRelayUnit() (throttled bool, err error) {
	defer a.unitsChanged()
	if a.helperClient != nil {
		return a.helperClient.ReloadRelay()
	}
	return false, errNoHelper
}

// stopRelayUnit/stopDNSRelayUnit stop the single consolidated relay
// process outright.
func (a *Agent) stopRelayUnit() error {
	defer a.unitsChanged()
	if a.helperClient != nil {
		return a.helperClient.StopRelay()
	}
	return errNoHelper
}

func (a *Agent) stopDNSRelayUnit() error {
	defer a.unitsChanged()
	if a.helperClient != nil {
		return a.helperClient.StopDNSRelay()
	}
	return errNoHelper
}

func (a *Agent) restartDNSRelayUnit() (throttled bool, err error) {
	defer a.unitsChanged()
	if a.helperClient != nil {
		return a.helperClient.RestartDNSRelay()
	}
	return false, errNoHelper
}

func (a *Agent) reloadDNSRelayUnit() (throttled bool, err error) {
	defer a.unitsChanged()
	if a.helperClient != nil {
		return a.helperClient.ReloadDNSRelay()
	}
	return false, errNoHelper
}

// restartCoreDNSUnit/restartCoreDHCPUnit restart the two consolidated,
// reserved-instance-name dnsmasq units.
func (a *Agent) restartCoreDNSUnit() (throttled bool, err error) {
	defer a.unitsChanged()
	if a.helperClient != nil {
		return a.helperClient.RestartCoreDNS()
	}
	return false, errNoHelper
}

func (a *Agent) restartCoreDHCPUnit() (throttled bool, err error) {
	defer a.unitsChanged()
	if a.helperClient != nil {
		return a.helperClient.RestartCoreDHCP()
	}
	return false, errNoHelper
}

// AllowedJournalUnits mirrors dnshived-helper's own identical fixed
// allowlist exactly (cmd/dnshived-helper/main.go).
var AllowedJournalUnits = map[string]bool{
	"dnshived.service":                 true,
	"dnshived-web.service":             true,
	"dnshived-helper.service":          true,
	"dnshived-relay.service":           true,
	"dnshived-dnsrelay.service":        true,
	"dnshived-keepalived.service":      true,
	"dnshived-keepalived-mgmt.service": true,
}

// GetJournalTail returns the last `lines` lines of unit's own systemd
// journal.
func (a *Agent) GetJournalTail(unit string, lines int) ([]string, error) {
	if !AllowedJournalUnits[unit] {
		return nil, fmt.Errorf("unit not allowed: %s", unit)
	}
	if a.helperClient != nil {
		return a.helperClient.GetJournalTail(unit, lines)
	}
	return nil, errNoHelper
}

// reloadCoreDHCPUnit SIGHUPs core-dhcp after its separate, reload-capable
// hosts file (internal/dhcpcentralrender.HostsFileName) has been
// re-rendered.
func (a *Agent) reloadCoreDHCPUnit() (throttled bool, err error) {
	defer a.unitsChanged()
	if a.helperClient != nil {
		return a.helperClient.ReloadCoreDHCP()
	}
	return false, errNoHelper
}

// reloadCoreDNSUnit SIGHUPs core-dns after its separate, reload-capable
// dynamic-hosts file (dnscentralrender.DynamicHostsFileName) has been
// re-rendered.
func (a *Agent) reloadCoreDNSUnit() (throttled bool, err error) {
	defer a.unitsChanged()
	if a.helperClient != nil {
		return a.helperClient.ReloadCoreDNS()
	}
	return false, errNoHelper
}

// ensureKeepalivedRunning idempotently starts the single consolidated
// keepalived unit covering every scope.
func (a *Agent) ensureKeepalivedRunning() error {
	defer a.unitsChanged()
	if a.helperClient != nil {
		return a.helperClient.EnsureKeepalived()
	}
	return errNoHelper
}

// reloadKeepalived reloads the consolidated keepalived unit after its
// config has been re-rendered.
func (a *Agent) reloadKeepalived() (throttled bool, err error) {
	defer a.unitsChanged()
	if a.helperClient != nil {
		return a.helperClient.ReloadKeepalived()
	}
	return false, errNoHelper
}

func (a *Agent) setDHCPGateState(scope string, sc config.ScopeConfig, state string) error {
	sc.Parent = a.localParent(sc.Parent)
	return SetDHCPGateState(a.helperClient, scope, sc, state)
}

// restartSelfFunc performs the actual dnshived.service restart.
var restartSelfFunc = func(helperClient *helper.Client) (bool, error) {
	if helperClient != nil {
		return helperClient.RestartDaemon()
	}
	return false, errNoHelper
}

func (a *Agent) RestartSelf() (throttled bool, err error) {
	return restartSelfFunc(a.helperClient)
}

// RestartMgmtKeepalived restarts the management-VIP keepalived unit on an
// operator's explicit request.
func (a *Agent) RestartMgmtKeepalived() (throttled bool, err error) {
	if a.helperClient != nil {
		return a.helperClient.RestartMgmtKeepalived()
	}
	return false, errNoHelper
}

func (a *Agent) RestartHelper() (throttled bool, err error) {
	if a.helperClient != nil {
		return a.helperClient.RestartHelper()
	}
	return false, errNoHelper
}

// RestartWeb restarts dnshived-web.service on an operator's explicit
// request.
func (a *Agent) RestartWeb() (throttled bool, err error) {
	if a.helperClient != nil {
		return a.helperClient.RestartWeb()
	}
	return false, errNoHelper
}

// RestartScopeDnsmasq restarts one scope's dnsmasq unit on an operator's
// explicit request.
func (a *Agent) RestartScopeDnsmasq(scope string) (throttled bool, err error) {
	return a.restartDnsmasqUnit(scope)
}

// RestartConsolidatedKeepalived reloads the single consolidated keepalived
// unit on an operator's explicit request.
func (a *Agent) RestartConsolidatedKeepalived() (throttled bool, err error) {
	return a.reloadKeepalived()
}

func (a *Agent) RestartRelay() (throttled bool, err error) {
	return a.restartRelayUnit()
}

// RestartDNSRelay mirrors RestartRelay exactly, for the single
// consolidated dnshived-dnsrelay unit instead of dnshived-relay.
func (a *Agent) RestartDNSRelay() (throttled bool, err error) {
	return a.restartDNSRelayUnit()
}

// SetDHCPGateState is the package-level DHCP gate dispatch through the
// helper.
func SetDHCPGateState(helperClient *helper.Client, scope string, sc config.ScopeConfig, state string) error {
	if helperClient == nil {
		return errNoHelper
	}
	return helperClient.SetDHCPGate(scope, sc.Parent, sc.VLANID, state)
}

func (a *Agent) getDHCPGateStateFor(scope string, sc config.ScopeConfig) (string, error) {
	sc.Parent = a.localParent(sc.Parent)
	if a.helperClient != nil {
		return a.helperClient.GetDHCPGate(scope, sc.Parent, sc.VLANID)
	}
	return "", errNoHelper
}

func (a *Agent) getVRRPStateFor(scope string) (string, error) {
	if a.helperClient != nil {
		return a.helperClient.GetVRRPState(scope)
	}
	return "", errNoHelper
}

// MgmtVRRPState reads back the management VIP's own current VRRP state
// (MASTER/BACKUP/FAULT/etc.).
func (a *Agent) MgmtVRRPState() (string, error) {
	if a.helperClient != nil {
		return a.helperClient.GetMgmtVRRPState()
	}
	return "", errNoHelper
}

// RefreshMgmtVIPStateCache calls MgmtVRRPState (a real signal/helper round
// trip) and stores the result for CachedMgmtVIPState to read cheaply.
func (a *Agent) RefreshMgmtVIPStateCache() {
	state, err := a.MgmtVRRPState()
	if err != nil {
		state = ""
	}
	a.mgmtVIPStateMu.Lock()
	a.mgmtVIPStateCached = state
	a.mgmtVIPStateMu.Unlock()
}

// CachedMgmtVIPState is the cheap, request-path-safe read of the last
// value RefreshMgmtVIPStateCache stored.
func (a *Agent) CachedMgmtVIPState() string {
	a.mgmtVIPStateMu.Lock()
	defer a.mgmtVIPStateMu.Unlock()
	return a.mgmtVIPStateCached
}

// vrrpDump returns one fresh, node-wide SIGDATA dump.
func (a *Agent) vrrpDump() ([]byte, error) {
	if a.helperClient != nil {
		return a.helperClient.GetVRRPDump()
	}
	return nil, errNoHelper
}

// gateDump returns one fresh, node-wide DHCP-gate listing (iface -> true
// if closed).
func (a *Agent) gateDump() (map[string]bool, error) {
	if a.helperClient != nil {
		return a.helperClient.GetDHCPGateDump()
	}
	return nil, errNoHelper
}

func (a *Agent) helperReachable() bool {
	if a.helperClient == nil {
		return false
	}
	return a.helperClient.Reachable()
}

// --- config rendering ---

// keepalivedAllTmpl renders every configured scope's vrrp_instance into a
// single consolidated file.
var keepalivedAllTmpl = template.Must(template.New("keepalived-all").Parse(`# dnshived managed — consolidated, all scopes
# DO NOT EDIT — this file is rendered by dnshived and will be overwritten.
{{- range . }}
vrrp_instance DNSHIVED_{{.Scope}} {
    state BACKUP
    interface {{.Interface}}
    virtual_router_id {{.VRRPID}}
    priority {{.Priority}}
{{- if .VRRPVersion}}
    version {{.VRRPVersion}}
{{- end}}
    advert_int {{.AdvertInt}}
    virtual_ipaddress {
        {{.VIP}}
    }
}
{{ end -}}
`))

type keepalivedInstanceData struct {
	Scope, Interface string
	VRRPID, Priority int
	VRRPVersion      int // 0 omits the "version" line (keepalived's own v2 default)
	AdvertInt        string
	VIP              string
}

func renderAdvertInt(ms int) string {
	if ms <= 0 {
		ms = 1000 // default: 1s, matching the pre-Phase-4 hardcoded value
	}
	if ms%1000 == 0 {
		return strconv.Itoa(ms / 1000)
	}
	return strconv.FormatFloat(float64(ms)/1000, 'f', 2, 64)
}

// staticDefaultPriority is the fallback: preferred worker gets the serving
// tier, everyone else gets standby.
func staticDefaultPriority(sc config.ScopeConfig, role string) int {
	if sc.PreferredWorker == role {
		return vrrpPriorityServing
	}
	return vrrpPriorityStandby
}

// renderKeepalivedConfigAll renders every KNOWN-CONSTRUCTED configured
// scope's vrrp_instance into one consolidated keepalived.conf.
func (a *Agent) renderKeepalivedConfigAll(priorities map[string]int, extraReady map[string]bool) error {
	currentScopes := a.allScopes()
	ready := a.readyScopeSet(extraReady)
	names := make([]string, 0, len(currentScopes))
	for name := range currentScopes {
		if !ready[name] {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names) // deterministic render order

	instances := make([]keepalivedInstanceData, 0, len(names))
	for _, name := range names {
		sc := currentScopes[name]
		iface := nftgate.InterfaceName(a.localParent(sc.Parent), sc.VLANID)
		priority, ok := priorities[name]
		if !ok {
			priority = staticDefaultPriority(sc, a.role)
		}
		instances = append(instances, keepalivedInstanceData{
			Scope: name, Interface: iface, VRRPID: sc.VRRPID, Priority: priority,
			VRRPVersion: sc.VRRPVersion, AdvertInt: renderAdvertInt(sc.AdvertIntMS), VIP: sc.VIP,
		})
	}

	return atomicRender(filepath.Join(a.dataDir, "keepalived.conf"), keepalivedAllTmpl, instances)
}

func atomicRender(path string, tmpl *template.Template, data interface{}) error {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return err
	}
	return atomicWriteFile(path, buf.Bytes(), 0o644)
}

// atomicWriteFile writes data to path via a temp file + fsync + rename,
// cleaning up the temp file on every failure path.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// --- helpers ---

var errNoHelper = errors.New("dnshived-helper is required but no helper_socket is configured")

// randomHex returns n random bytes hex-encoded (2n characters).
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("[AGENT] crypto/rand failed, refusing to issue a predictable nonce: %v", err)
	}
	return hex.EncodeToString(b)
}

// Serving returns the scopes this node currently considers itself serving.
func (a *Agent) Serving() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.serving))
	for s := range a.serving {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Ready returns scopes whose network plane has been constructed
// (interface, dnsmasq, keepalived instance, gate — all present,
// regardless of current authority).
func (a *Agent) Ready() map[string]time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]time.Time, len(a.ready))
	for s, t := range a.ready {
		out[s] = t
	}
	return out
}

// readyScopeSet snapshots a.ready (under lock, matching every other
// shared-map read in this file) and unions in extra.
func (a *Agent) readyScopeSet(extra map[string]bool) map[string]bool {
	a.mu.Lock()
	out := make(map[string]bool, len(a.ready)+len(extra))
	for s := range a.ready {
		out[s] = true
	}
	a.mu.Unlock()
	for s := range extra {
		out[s] = true
	}
	return out
}

// StableSince returns when this node's FSM state last changed.
func (a *Agent) StableSince() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.stableSince
}

// ReadinessCheck is the per-scope verification that the permanent network
// plane exists and is correctly configured.
type ReadinessCheck struct {
	InterfaceExists bool `json:"interface_exists"`
	NodeIPAssigned  bool `json:"node_ip_assigned"`
	VRRPOperational bool `json:"vrrp_operational"`
	DHCPGateClosed  bool `json:"dhcp_gate_closed"`
	ConfigValidated bool `json:"config_validated"`
	HelperReachable bool `json:"helper_reachable"`
}

// AllReady reports whether every check that gates readiness passed.
func (r ReadinessCheck) AllReady() bool {
	return r.InterfaceExists && r.NodeIPAssigned && r.VRRPOperational &&
		r.ConfigValidated && r.HelperReachable
}

// Readiness returns the ReadinessCheck for a scope.
func (a *Agent) Readiness(scope string) ReadinessCheck {
	sc, ok := a.scopeConfig(scope)
	if !ok {
		return ReadinessCheck{}
	}
	iface := nftgate.InterfaceName(a.localParent(sc.Parent), sc.VLANID)

	var rc ReadinessCheck
	if _, err := os.Stat("/sys/class/net/" + iface); err == nil {
		rc.InterfaceExists = true
	}

	if out, err := exec.Command("ip", "addr", "show", "dev", iface).CombinedOutput(); err == nil {
		rc.NodeIPAssigned = sc.NodeIP != "" && strings.Contains(string(out), strings.Split(sc.NodeIP, "/")[0])
	}

	if state, err := a.getVRRPStateFor(scope); err == nil {
		rc.VRRPOperational = state == "MASTER" || state == "BACKUP"
	}

	if state, err := a.getDHCPGateStateFor(scope, sc); err == nil {
		rc.DHCPGateClosed = state == "closed"
	}

	if _, err := os.Stat(filepath.Join(a.dataDir, "dnsmasq-"+scope+".conf")); err == nil {
		rc.ConfigValidated = true
	}

	rc.HelperReachable = a.helperReachable()

	return rc
}

// AuthorityCheck is the result of evaluating the predicate for one scope.
type AuthorityCheck struct {
	Scope         string        `json:"scope"`
	Allowed       bool          `json:"allowed"`
	Serving       bool          `json:"serving"`
	Decision      string        `json:"decision"`
	Reason        string        `json:"reason"`
	PrimaryReason string        `json:"primary_reason,omitempty"` // first failing check name
	EvaluatedAt   string        `json:"evaluated_at"`
	Checks        []CheckResult `json:"checks"`
}

// CheckResult is one condition's pass/fail with detail.
type CheckResult struct {
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail"`
}

// ExplainAuthority runs the predicate for a single scope and returns the
// full check breakdown.
func (a *Agent) ExplainAuthority(scope string, in ReconcileInputs) AuthorityCheck {
	a.mu.Lock()
	serving := a.serving[scope]
	a.mu.Unlock()

	auth := a.buildAuthority(scope, in, serving)
	allowed, reason := scopeServeAllowed(auth)

	ac := AuthorityCheck{
		Scope:       scope,
		Allowed:     allowed,
		Serving:     serving,
		Reason:      reason,
		EvaluatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	if allowed {
		ac.Decision = "SERVE"
	} else if serving {
		ac.Decision = "STOP"
	} else {
		ac.Decision = "WAIT"
	}

	// Build ordered checks — same order as the predicate evaluates.
	checks := []CheckResult{
		{Name: "stable", Pass: auth.State == fsm.StateStable,
			Detail: "state is " + string(auth.State)},
		{Name: "owned", Pass: auth.OwnsScope,
			Detail: boolDetail(auth.OwnsScope, "authoritative map assigns to this node", "not assigned to this node")},
		{Name: "leased", Pass: auth.LeaseValid && !withinSafetyMargin(auth.LeaseExpiresAt, auth.Now),
			Detail: leaseDetail(auth)},
		{Name: "unfenced", Pass: !auth.SelfToken.Less(auth.Watermark),
			Detail: fmt.Sprintf("token %s vs watermark %s", auth.SelfToken, auth.Watermark)},
	}

	// Witness check — depends on context.
	if !auth.WitnessRequired {
		checks = append(checks, CheckResult{Name: "witnessed", Pass: true, Detail: "not required (no PSK)"})
	} else if !auth.CurrentlyServing {
		checks = append(checks, CheckResult{Name: "witnessed", Pass: true, Detail: "acquired during gate-open (not serving yet)"})
	} else {
		held := auth.Witness.Held && !withinSafetyMargin(auth.Witness.ExpiresAt, auth.Now)
		detail := "not held"
		if auth.Witness.Held {
			remaining := auth.Witness.ExpiresAt - auth.Now
			if remaining > 0 {
				detail = fmt.Sprintf("held, expires in %ds", remaining)
			} else {
				detail = fmt.Sprintf("expired %ds ago", -remaining)
			}
		}
		checks = append(checks, CheckResult{Name: "witnessed", Pass: held, Detail: detail})
	}

	ac.Checks = checks

	// PrimaryReason — first failing check.
	for _, c := range checks {
		if !c.Pass {
			ac.PrimaryReason = c.Name
			break
		}
	}

	return ac
}

func boolDetail(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}

func leaseDetail(auth AuthorityInputs) string {
	if !auth.LeaseValid {
		return "no valid lease held"
	}
	remaining := auth.LeaseExpiresAt - auth.Now
	if withinSafetyMargin(auth.LeaseExpiresAt, auth.Now) {
		return fmt.Sprintf("expiring within safety margin (%ds remaining)", remaining)
	}
	return fmt.Sprintf("valid, expires in %ds", remaining)
}

// LastReconcileInputs returns the inputs from the most recent reconcile
// tick.
func (a *Agent) LastReconcileInputs() ReconcileInputs {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastInputs
}
