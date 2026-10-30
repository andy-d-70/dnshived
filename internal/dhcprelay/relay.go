// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcprelay

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"dnshived/internal/unixsock"
)

// udpConn is the subset of *net.UDPConn the relay's read/write paths need.
type udpConn interface {
	ReadFromUDP(b []byte) (int, *net.UDPAddr, error)
	WriteToUDP(b []byte, addr *net.UDPAddr) (int, error)
	Close() error
}

type clientInterface struct {
	name       string
	scope      string
	gate       *scopeGate
	giaddr     net.IP
	serverAddr *net.UDPAddr
	conn       udpConn
	reply      udpConn

	serverIdentifier atomic.Pointer[net.IP]

	// ifIndex is the kernel ifindex this interface's sockets were bound
	// against, captured via net.InterfaceByName at bind time.
	ifIndex int

	rateLimit atomic.Int32
	rateBurst atomic.Int32
	limiter   *tokenBucket
	clients   *clientLimiter
	pending   atomic.Int64
	stats     vlanStats

	removing atomic.Bool
	wg       sync.WaitGroup
}

type metrics struct {
	requestsSeen        atomic.Int64
	requestsForwarded   atomic.Int64
	requestsDropped     atomic.Int64
	requestsRateLimited atomic.Int64
	requestsClientLimit atomic.Int64
	requestsPendingFull atomic.Int64
	repliesSeen         atomic.Int64
	repliesForwarded    atomic.Int64
	repliesDropped      atomic.Int64
	gateClosedRequests  atomic.Int64
	gateClosedReplies   atomic.Int64
}

// Metrics is a point-in-time snapshot of Relay's counters, safe to log or
// serve over an API.
type Metrics struct {
	RequestsSeen        int64
	RequestsForwarded   int64
	RequestsDropped     int64
	RequestsRateLimited int64
	RequestsClientLimit int64
	RequestsPendingFull int64
	RepliesSeen         int64
	RepliesForwarded    int64
	RepliesDropped      int64
	Pending             int64
	GateClosedRequests  int64
	GateClosedReplies   int64
}

type Relay struct {
	cfg Config

	serverConn atomic.Pointer[serverSocket] // write-only: forwards a client request upstream. Never read from.
	serverAddr *net.UDPAddr

	// cifMu guards clientIfaces itself (the slice, add/remove).
	cifMu        sync.Mutex
	clientIfaces []*clientInterface

	// reconfigureMu serializes Reconfigure calls against each other.
	reconfigureMu sync.Mutex

	pending *pendingTable
	metrics metrics

	pendingPerVLAN  atomic.Int32
	clientRateLimit atomic.Int32
	clientRateBurst atomic.Int32
	clientTracked   atomic.Int64

	closing atomic.Bool
	wg      sync.WaitGroup
	stop    chan struct{}

	throttleMu   sync.Mutex
	throttleSeen map[throttleKey]time.Time

	gates      *gateTable
	gateSocket string
	gateServer *unixsock.Server
	runDir     string
	version    string
	startedAt  time.Time
}

type serverSocket struct{ udpConn }

type throttleKey struct {
	kind  string
	iface string
}

func (r *Relay) setServerConn(c udpConn) udpConn {
	old := r.serverConn.Swap(&serverSocket{c})
	if old == nil {
		return nil
	}
	return old.udpConn
}

const logThrottleWindow = 30 * time.Second

func currentIfIndex(name string) int {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0
	}
	return iface.Index
}

// resolveServerAddr resolves a client interface's own effective forward-to
// address -- its own ServerAddr if set, else fallback (Config.ServerAddr).
func resolveServerAddr(perInterface, fallback string) (*net.UDPAddr, error) {
	addr := perInterface
	if addr == "" {
		addr = fallback
	}
	resolved, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve server_addr %q: %w", addr, err)
	}
	return resolved, nil
}

// resolveServerIdentifier picks ci's effective client-visible server
// identifier: its own ServerIdentifier (the scope's VIP) if set, else
// giaddr itself.
func resolveServerIdentifier(configured string, giaddr net.IP) net.IP {
	if configured == "" {
		return giaddr
	}
	return net.ParseIP(configured).To4()
}

// effectiveServerIdentifier returns ci's current, resolved server
// identifier.
func (ci *clientInterface) effectiveServerIdentifier() net.IP {
	if p := ci.serverIdentifier.Load(); p != nil {
		return *p
	}
	return ci.giaddr
}

// New builds a Relay from cfg but opens no sockets -- see Start.
func New(cfg Config) (*Relay, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	serverAddr, err := net.ResolveUDPAddr("udp4", cfg.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve server_addr %q: %w", cfg.ServerAddr, err)
	}

	r := &Relay{
		cfg:          cfg,
		serverAddr:   serverAddr,
		pending:      newPendingTable(),
		stop:         make(chan struct{}),
		throttleSeen: make(map[throttleKey]time.Time),
		gates:        newGateTable(),
		startedAt:    time.Now(),
	}
	r.gates.applyConfig(cfg.NodeID, cfg.CoreCount)

	r.applyOptionalLimits(cfg)

	for _, ci := range cfg.ClientInterfaces {
		newCif, err := newClientInterface(ci, cfg, &r.clientTracked, r.gates)
		if err != nil {
			return nil, err
		}
		r.clientIfaces = append(r.clientIfaces, newCif)
	}

	return r, nil
}

func (r *Relay) applyOptionalLimits(cfg Config) {
	r.pendingPerVLAN.Store(int32(resolveOptionalLimit(cfg.PendingPerVLAN, defaultPendingPerVLAN)))
	rate := resolveOptionalLimit(cfg.ClientRateLimit, defaultClientRateLimit)
	burst := resolveOptionalLimit(cfg.ClientRateBurst, defaultClientRateBurst)
	if rate > 0 && burst == 0 {
		burst = rate * 2
	}
	r.clientRateLimit.Store(int32(rate))
	r.clientRateBurst.Store(int32(burst))
}

// newClientInterface resolves ci against cfg's cluster-wide defaults; no
// sockets are opened.
func newClientInterface(ci ClientInterfaceConfig, cfg Config, tracked *atomic.Int64, gates *gateTable) (*clientInterface, error) {
	giaddr := net.ParseIP(ci.GIAddr).To4()
	serverAddr, err := resolveServerAddr(ci.ServerAddr, cfg.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("client interface %q: %w", ci.Name, err)
	}
	rate := resolveRateLimit(ci.RateLimit, cfg.RateLimit)
	burst := resolveRateBurst(ci.RateBurst, cfg.RateBurst, rate)
	cif := &clientInterface{name: ci.Name, scope: ci.Scope, giaddr: giaddr, serverAddr: serverAddr, limiter: newTokenBucket(burst), clients: newClientLimiter(tracked)}
	if ci.Scope != "" {
		cif.gate = gates.scope(ci.Scope)
	}
	cif.rateLimit.Store(int32(rate))
	cif.rateBurst.Store(int32(burst))
	sid := resolveServerIdentifier(ci.ServerIdentifier, giaddr)
	cif.serverIdentifier.Store(&sid)
	return cif, nil
}

func (r *Relay) Start() error {
	r.gates.checkClock(time.Now())
	serverConn, err := bindServerFacingUDPPort(r.cfg.ServerInterface, dhcpServerPort)
	if err != nil {
		return fmt.Errorf("bind server-facing socket: %w", err)
	}
	r.setServerConn(serverConn)

	for _, cif := range r.clientIfaces {
		conn, err := bindClientUDPPort(cif.name, dhcpServerPort)
		if err != nil {
			r.closeAll()
			return fmt.Errorf("bind client-facing socket on %s: %w", cif.name, err)
		}
		cif.conn = conn

		reply, err := bindReplyUDPPort(cif.name, cif.giaddr, dhcpServerPort)
		if err != nil {
			r.closeAll()
			return fmt.Errorf("bind reply socket for %s (giaddr %s): %w", cif.name, cif.giaddr, err)
		}
		cif.reply = reply
		cif.ifIndex = currentIfIndex(cif.name)
	}

	for _, cif := range r.clientIfaces {
		cif := cif
		cif.wg.Add(2)
		r.wg.Add(2)
		go func() {
			defer r.wg.Done()
			defer cif.wg.Done()
			r.handleClientRequests(cif)
		}()
		go func() {
			defer r.wg.Done()
			defer cif.wg.Done()
			r.handleServerReplies(cif)
		}()
	}

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.pending.runSweeper(r.stop)
	}()

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.runGateChecks()
	}()

	if r.gateSocket != "" {
		if err := r.startGateServer(); err != nil {
			r.closeAll()
			return fmt.Errorf("gate socket: %w", err)
		}
	}

	return nil
}

// runGateChecks re-checks the clock and every gate's deadline until the relay stops.
func (r *Relay) runGateChecks() {
	ticker := time.NewTicker(gateCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.stop:
			return
		case now := <-ticker.C:
			r.gates.checkClock(now)
		}
	}
}

// diffClientInterfaces is Reconfigure's own pure decision.
func diffClientInterfaces(old []*clientInterface, newIfaces []ClientInterfaceConfig, newDefaultServerAddr string) (toRemove []*clientInterface, toAdd []ClientInterfaceConfig, unchanged int) {
	oldByName := make(map[string]*clientInterface, len(old))
	for _, cif := range old {
		oldByName[cif.name] = cif
	}
	newByName := make(map[string]ClientInterfaceConfig, len(newIfaces))
	for _, ci := range newIfaces {
		newByName[ci.Name] = ci
	}

	for name, cif := range oldByName {
		newCi, stillPresent := newByName[name]
		if !stillPresent {
			toRemove = append(toRemove, cif)
			continue
		}
		giaddrChanged := !net.ParseIP(newCi.GIAddr).To4().Equal(cif.giaddr)
		newServerAddr, resolveErr := resolveServerAddr(newCi.ServerAddr, newDefaultServerAddr)
		serverAddrChanged := resolveErr != nil || cif.serverAddr == nil || cif.serverAddr.String() != newServerAddr.String()
		if giaddrChanged || serverAddrChanged || newCi.Scope != cif.scope {
			toRemove = append(toRemove, cif)
			toAdd = append(toAdd, newCi)
			continue
		}
		unchanged++
	}
	for name, ci := range newByName {
		if _, existed := oldByName[name]; !existed {
			toAdd = append(toAdd, ci)
		}
	}
	return toRemove, toAdd, unchanged
}

// Reconfigure diffs newCfg's ClientInterfaces against the currently
// running set and applies ONLY the difference.
func (r *Relay) Reconfigure(newCfg Config) error {
	if err := newCfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	r.reconfigureMu.Lock()
	defer r.reconfigureMu.Unlock()

	if r.closing.Load() {
		return fmt.Errorf("relay is shutting down")
	}

	if newCfg.ServerAddr != r.cfg.ServerAddr || newCfg.ServerInterface != r.cfg.ServerInterface {
		newServerAddr, err := net.ResolveUDPAddr("udp4", newCfg.ServerAddr)
		if err != nil {
			return fmt.Errorf("resolve server_addr %q: %w", newCfg.ServerAddr, err)
		}
		newServerConn, err := bindServerFacingUDPPort(newCfg.ServerInterface, dhcpServerPort)
		if err != nil {
			return fmt.Errorf("bind new server-facing socket: %w", err)
		}
		oldServerConn := r.setServerConn(newServerConn)
		r.serverAddr = newServerAddr
		if oldServerConn != nil {
			oldServerConn.Close()
		}
		log.Printf("[RELAY] reconfigure: server address changed to %s", newCfg.ServerAddr)
	}

	r.cifMu.Lock()
	old := make([]*clientInterface, len(r.clientIfaces))
	copy(old, r.clientIfaces)
	r.cifMu.Unlock()

	toRemove, toAdd, unchanged := diffClientInterfaces(old, newCfg.ClientInterfaces, newCfg.ServerAddr)

	// Remove first, add second — mirrors this project's own authority
	// pipeline's close-before-open discipline.
	for _, cif := range toRemove {
		r.removeClientInterface(cif)
	}
	addedOK := 0
	for _, ci := range toAdd {
		if err := r.addClientInterface(ci, newCfg); err != nil {
			log.Printf("[RELAY] reconfigure: add client interface %s: %v (continuing with the rest)", ci.Name, err)
			continue
		}
		addedOK++
	}

	removedSet := make(map[*clientInterface]bool, len(toRemove))
	for _, cif := range toRemove {
		removedSet[cif] = true
	}
	newByName := make(map[string]ClientInterfaceConfig, len(newCfg.ClientInterfaces))
	for _, ci := range newCfg.ClientInterfaces {
		newByName[ci.Name] = ci
	}
	rebound := 0
	for _, cif := range old {
		if removedSet[cif] {
			continue
		}
		newCi, ok := newByName[cif.name]
		if !ok {
			continue
		}

		if live := currentIfIndex(cif.name); live != 0 && cif.ifIndex != 0 && live != cif.ifIndex {
			log.Printf("[RELAY] reconfigure: %s ifindex changed (%d -> %d) — interface was replaced since this socket was bound, rebinding",
				cif.name, cif.ifIndex, live)
			r.removeClientInterface(cif)
			if err := r.addClientInterface(newCi, newCfg); err != nil {
				log.Printf("[RELAY] reconfigure: rebind %s: %v", newCi.Name, err)
			} else {
				rebound++
			}
			continue
		}

		rate := resolveRateLimit(newCi.RateLimit, newCfg.RateLimit)
		burst := resolveRateBurst(newCi.RateBurst, newCfg.RateBurst, rate)
		if int32(rate) != cif.rateLimit.Load() || int32(burst) != cif.rateBurst.Load() {
			cif.rateLimit.Store(int32(rate))
			cif.rateBurst.Store(int32(burst))
			log.Printf("[RELAY] reconfigure: %s rate limit changed to %d/s burst %d", cif.name, rate, burst)
		}

		newSid := resolveServerIdentifier(newCi.ServerIdentifier, cif.giaddr)
		if !newSid.Equal(cif.effectiveServerIdentifier()) {
			cif.serverIdentifier.Store(&newSid)
			log.Printf("[RELAY] reconfigure: %s server identifier changed to %s", cif.name, newSid)
		}
	}

	r.applyOptionalLimits(newCfg)
	r.cfg = newCfg
	r.gates.applyConfig(newCfg.NodeID, newCfg.CoreCount)
	keep := make(map[string]bool, len(newCfg.ClientInterfaces))
	for _, ci := range newCfg.ClientInterfaces {
		if ci.Scope != "" {
			keep[ci.Scope] = true
		}
	}
	r.gates.retain(keep, time.Now())
	if rebound > 0 {
		log.Printf("[RELAY] reconfigure: %d interface(s) rebound due to stale ifindex", rebound)
	}
	log.Printf("[RELAY] reconfigure: %d removed, %d added, %d unchanged (now %d client interface(s) configured)",
		len(toRemove), addedOK, unchanged, len(newCfg.ClientInterfaces))
	return nil
}

func (r *Relay) removeClientInterface(cif *clientInterface) {
	cif.removing.Store(true)
	if cif.conn != nil {
		cif.conn.Close()
	}
	if cif.reply != nil {
		cif.reply.Close()
	}
	cif.wg.Wait()

	r.cifMu.Lock()
	for i, c := range r.clientIfaces {
		if c == cif {
			r.clientIfaces = append(r.clientIfaces[:i], r.clientIfaces[i+1:]...)
			break
		}
	}
	r.cifMu.Unlock()
	log.Printf("[RELAY] reconfigure: removed client interface %s", cif.name)
}

// addClientInterface binds a fresh socket pair for one new client
// interface and launches its own two read-loop goroutines.
func (r *Relay) addClientInterface(ci ClientInterfaceConfig, cfg Config) error {
	cif, err := newClientInterface(ci, cfg, &r.clientTracked, r.gates)
	if err != nil {
		return err
	}
	conn, err := bindClientUDPPort(ci.Name, dhcpServerPort)
	if err != nil {
		return fmt.Errorf("bind client-facing socket on %s: %w", ci.Name, err)
	}
	reply, err := bindReplyUDPPort(ci.Name, cif.giaddr, dhcpServerPort)
	if err != nil {
		conn.Close()
		return fmt.Errorf("bind reply socket for %s (giaddr %s): %w", ci.Name, cif.giaddr, err)
	}
	cif.conn, cif.reply, cif.ifIndex = conn, reply, currentIfIndex(ci.Name)

	r.cifMu.Lock()
	r.clientIfaces = append(r.clientIfaces, cif)
	r.cifMu.Unlock()

	cif.wg.Add(2)
	r.wg.Add(2)
	go func() {
		defer r.wg.Done()
		defer cif.wg.Done()
		r.handleClientRequests(cif)
	}()
	go func() {
		defer r.wg.Done()
		defer cif.wg.Done()
		r.handleServerReplies(cif)
	}()

	log.Printf("[RELAY] reconfigure: added client interface %s (giaddr %s, server %s)", ci.Name, cif.giaddr, cif.serverAddr)
	return nil
}

// Stop closes every socket (unblocking every read loop) and waits for them
// all to exit.
func (r *Relay) Stop() {
	if !r.closing.CompareAndSwap(false, true) {
		return
	}
	r.reconfigureMu.Lock()
	defer r.reconfigureMu.Unlock()
	close(r.stop)
	if r.gateServer != nil {
		r.gateServer.Close()
	}
	r.closeAll()
	r.wg.Wait()
}

func (r *Relay) closeAll() {
	if sc := r.serverConn.Load(); sc != nil {
		sc.Close()
	}
	r.cifMu.Lock()
	defer r.cifMu.Unlock()
	for _, cif := range r.clientIfaces {
		if cif.conn != nil {
			cif.conn.Close()
		}
		if cif.reply != nil {
			cif.reply.Close()
		}
	}
}

// Snapshot returns a point-in-time copy of the relay's counters.
func (r *Relay) Snapshot() Metrics {
	return Metrics{
		RequestsSeen:        r.metrics.requestsSeen.Load(),
		RequestsForwarded:   r.metrics.requestsForwarded.Load(),
		RequestsDropped:     r.metrics.requestsDropped.Load(),
		RequestsRateLimited: r.metrics.requestsRateLimited.Load(),
		RequestsClientLimit: r.metrics.requestsClientLimit.Load(),
		RequestsPendingFull: r.metrics.requestsPendingFull.Load(),
		RepliesSeen:         r.metrics.repliesSeen.Load(),
		RepliesForwarded:    r.metrics.repliesForwarded.Load(),
		RepliesDropped:      r.metrics.repliesDropped.Load(),
		Pending:             r.pending.globalCnt.Load(),
		GateClosedRequests:  r.metrics.gateClosedRequests.Load(),
		GateClosedReplies:   r.metrics.gateClosedReplies.Load(),
	}
}

// isValidServerSource accepts either ci's OWN configured server address,
// or ci's own giaddr.
func (r *Relay) isValidServerSource(from *net.UDPAddr, ci *clientInterface) bool {
	return (ci.serverAddr != nil && from.IP.Equal(ci.serverAddr.IP)) || from.IP.Equal(ci.giaddr)
}

// logThrottled logs at most once per logThrottleWindow per distinct key,
// matching internal/agent's own established rate-limited-logging
// convention.
func (r *Relay) logThrottled(key throttleKey, format string, args ...any) {
	if r.shouldLog(time.Now(), key) {
		log.Printf("[RELAY] "+format, args...)
	}
}

// shouldLog is logThrottled's check alone, for hot paths that must not
// build the log arguments while the key is throttled.
func (r *Relay) shouldLog(now time.Time, key throttleKey) bool {
	r.throttleMu.Lock()
	defer r.throttleMu.Unlock()
	if last, seen := r.throttleSeen[key]; seen && now.Sub(last) < logThrottleWindow {
		return false
	}
	r.throttleSeen[key] = now
	return true
}
