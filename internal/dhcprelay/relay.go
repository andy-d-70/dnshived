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
)

// udpConn is the subset of *net.UDPConn the relay's read/write paths need.
type udpConn interface {
	ReadFromUDP(b []byte) (int, *net.UDPAddr, error)
	WriteToUDP(b []byte, addr *net.UDPAddr) (int, error)
	Close() error
}

type clientInterface struct {
	name       string
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

	removing atomic.Bool
	wg       sync.WaitGroup
}

type metrics struct {
	requestsSeen        atomic.Int64
	requestsForwarded   atomic.Int64
	requestsDropped     atomic.Int64
	requestsRateLimited atomic.Int64
	repliesSeen         atomic.Int64
	repliesForwarded    atomic.Int64
	repliesDropped      atomic.Int64
}

// Metrics is a point-in-time snapshot of Relay's counters, safe to log or
// serve over an API.
type Metrics struct {
	RequestsSeen        int64
	RequestsForwarded   int64
	RequestsDropped     int64
	RequestsRateLimited int64
	RepliesSeen         int64
	RepliesForwarded    int64
	RepliesDropped      int64
	Pending             int64
}

type Relay struct {
	cfg Config

	serverConn udpConn // write-only: forwards a client request upstream. Never read from.
	serverAddr *net.UDPAddr

	// cifMu guards clientIfaces itself (the slice, add/remove).
	cifMu        sync.Mutex
	clientIfaces []*clientInterface

	// reconfigureMu serializes Reconfigure calls against each other.
	reconfigureMu sync.Mutex

	pending *pendingTable
	metrics metrics

	closing atomic.Bool
	wg      sync.WaitGroup
	stop    chan struct{}

	throttleMu   sync.Mutex
	throttleSeen map[string]time.Time
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
		throttleSeen: make(map[string]time.Time),
	}

	for _, ci := range cfg.ClientInterfaces {
		giaddr := net.ParseIP(ci.GIAddr).To4()
		cifServerAddr, err := resolveServerAddr(ci.ServerAddr, cfg.ServerAddr)
		if err != nil {
			return nil, fmt.Errorf("client interface %q: %w", ci.Name, err)
		}
		rate := resolveRateLimit(ci.RateLimit, cfg.RateLimit)
		burst := resolveRateBurst(ci.RateBurst, cfg.RateBurst, rate)
		newCif := &clientInterface{name: ci.Name, giaddr: giaddr, serverAddr: cifServerAddr, limiter: newTokenBucket(burst)}
		newCif.rateLimit.Store(int32(rate))
		newCif.rateBurst.Store(int32(burst))
		sid := resolveServerIdentifier(ci.ServerIdentifier, giaddr)
		newCif.serverIdentifier.Store(&sid)
		r.clientIfaces = append(r.clientIfaces, newCif)
	}

	return r, nil
}

func (r *Relay) Start() error {
	serverConn, err := bindServerFacingUDPPort(r.cfg.ServerInterface, dhcpServerPort)
	if err != nil {
		return fmt.Errorf("bind server-facing socket: %w", err)
	}
	r.serverConn = serverConn

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

	return nil
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
		if giaddrChanged || serverAddrChanged {
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
		oldServerConn := r.serverConn
		r.serverConn = newServerConn
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
		if err := r.addClientInterface(ci, newCfg.ServerAddr); err != nil {
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
			if err := r.addClientInterface(newCi, newCfg.ServerAddr); err != nil {
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

	r.cfg = newCfg
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
func (r *Relay) addClientInterface(ci ClientInterfaceConfig, defaultServerAddr string) error {
	giaddr := net.ParseIP(ci.GIAddr).To4()
	serverAddr, err := resolveServerAddr(ci.ServerAddr, defaultServerAddr)
	if err != nil {
		return fmt.Errorf("client interface %q: %w", ci.Name, err)
	}
	conn, err := bindClientUDPPort(ci.Name, dhcpServerPort)
	if err != nil {
		return fmt.Errorf("bind client-facing socket on %s: %w", ci.Name, err)
	}
	reply, err := bindReplyUDPPort(ci.Name, giaddr, dhcpServerPort)
	if err != nil {
		conn.Close()
		return fmt.Errorf("bind reply socket for %s (giaddr %s): %w", ci.Name, giaddr, err)
	}

	rate := resolveRateLimit(ci.RateLimit, r.cfg.RateLimit)
	burst := resolveRateBurst(ci.RateBurst, r.cfg.RateBurst, rate)
	cif := &clientInterface{name: ci.Name, giaddr: giaddr, serverAddr: serverAddr, conn: conn, reply: reply, limiter: newTokenBucket(burst), ifIndex: currentIfIndex(ci.Name)}
	cif.rateLimit.Store(int32(rate))
	cif.rateBurst.Store(int32(burst))
	sid := resolveServerIdentifier(ci.ServerIdentifier, giaddr)
	cif.serverIdentifier.Store(&sid)

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

	log.Printf("[RELAY] reconfigure: added client interface %s (giaddr %s, server %s)", ci.Name, giaddr, serverAddr)
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
	r.closeAll()
	r.wg.Wait()
}

func (r *Relay) closeAll() {
	if r.serverConn != nil {
		r.serverConn.Close()
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
		RepliesSeen:         r.metrics.repliesSeen.Load(),
		RepliesForwarded:    r.metrics.repliesForwarded.Load(),
		RepliesDropped:      r.metrics.repliesDropped.Load(),
		Pending:             r.pending.globalCnt.Load(),
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
func (r *Relay) logThrottled(key, format string, args ...any) {
	r.throttleMu.Lock()
	last, seen := r.throttleSeen[key]
	now := time.Now()
	if seen && now.Sub(last) < logThrottleWindow {
		r.throttleMu.Unlock()
		return
	}
	r.throttleSeen[key] = now
	r.throttleMu.Unlock()
	log.Printf("[RELAY] "+format, args...)
}
