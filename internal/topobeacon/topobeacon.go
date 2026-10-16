// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package topobeacon implements a continuous, always-on interface-
// identity beacon between already-onboarded core nodes.
package topobeacon

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"sync"
	"syscall"
	"time"
)

// Port is this package's own dedicated UDP port.
const Port = 9446

// Magic guards against a stray/malformed packet on this port ever being
// mistaken for a real beacon.
const Magic = "DNSHIVED-TOPO-BEACON-V1"

const DefaultInterval = 5 * time.Second

// staleAfterFactor: a Sighting not refreshed within
// staleAfterFactor*interval is pruned as stale on the next Snapshot.
const staleAfterFactor = 4

// KindTrunk/KindMgmt are the two interface roles this package beacons on.
const (
	KindTrunk = "trunk"
	KindMgmt  = "mgmt"
)

// Beacon is the small UDP payload broadcast on the wire.
type Beacon struct {
	Magic string `json:"magic"`
	Role  string `json:"role"`
	Iface string `json:"iface"`
	Kind  string `json:"kind"` // KindTrunk or KindMgmt
}

// IfaceSpec names one of THIS node's own interfaces to beacon on and
// listen on.
type IfaceSpec struct {
	Name string // raw OS interface name
	Kind string // KindTrunk or KindMgmt
}

type Sighting struct {
	MyIface   string    `json:"my_iface"`
	MyKind    string    `json:"my_kind"`
	PeerRole  string    `json:"peer_role"`
	PeerIface string    `json:"peer_iface"`
	PeerKind  string    `json:"peer_kind"`
	LastSeen  time.Time `json:"last_seen"`
	// Count is the total number of beacons heard on this exact pairing since
	// this process started.
	Count int64 `json:"count"`
}

func sightingKey(myIface, peerRole, peerIface string) string {
	return myIface + "|" + peerRole + "|" + peerIface
}

// Store holds live, in-memory sightings.
type Store struct {
	mu       sync.Mutex
	interval time.Duration
	entries  map[string]Sighting
	selfRole string
}

// NewStore creates a Store.
func NewStore(interval time.Duration, selfRole string) *Store {
	if interval <= 0 {
		interval = DefaultInterval
	}
	return &Store{interval: interval, entries: make(map[string]Sighting), selfRole: selfRole}
}

func (s *Store) record(myIface, myKind string, b Beacon) {
	if s.selfRole != "" && b.Role == s.selfRole {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sightingKey(myIface, b.Role, b.Iface)
	e := s.entries[key]
	e.MyIface = myIface
	e.MyKind = myKind
	e.PeerRole = b.Role
	e.PeerIface = b.Iface
	e.PeerKind = b.Kind
	e.LastSeen = time.Now()
	e.Count++
	s.entries[key] = e
}

// Snapshot returns every currently-fresh sighting, sorted
// deterministically (MyIface, then PeerRole, then PeerIface).
func (s *Store) Snapshot() []Sighting {
	cutoff := time.Now().Add(-staleAfterFactor * s.interval)
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Sighting, 0, len(s.entries))
	for key, e := range s.entries {
		if e.LastSeen.Before(cutoff) {
			delete(s.entries, key)
			continue
		}
		out = append(out, e)
	}
	sortSightings(out)
	return out
}

func sortSightings(s []Sighting) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && sightingLess(s[j], s[j-1]); j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func sightingLess(a, b Sighting) bool {
	if a.MyIface != b.MyIface {
		return a.MyIface < b.MyIface
	}
	if a.PeerRole != b.PeerRole {
		return a.PeerRole < b.PeerRole
	}
	return a.PeerIface < b.PeerIface
}

// Forget drops every sighting recorded on myIface.
func (s *Store) Forget(myIface string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, e := range s.entries {
		if e.MyIface == myIface {
			delete(s.entries, key)
		}
	}
}

// Runner keeps one sender+listener pair per interface and, on Update,
// starts/stops only the difference.
type Runner struct {
	mu       sync.Mutex
	role     string
	store    *Store
	interval time.Duration
	running  map[string]runningIface // key: name + "|" + kind
	// start is overridden in tests; it must run until ctx is done.
	start func(ctx context.Context, role string, spec IfaceSpec, store *Store, interval time.Duration)
}

type runningIface struct {
	spec   IfaceSpec
	cancel context.CancelFunc
}

// NewRunner creates a Runner that records into store.
func NewRunner(role string, store *Store, interval time.Duration) *Runner {
	if interval <= 0 {
		interval = DefaultInterval
	}
	return &Runner{role: role, store: store, interval: interval, running: make(map[string]runningIface), start: startIface}
}

// startIface runs the sender and listener for spec until ctx is done.
func startIface(ctx context.Context, role string, spec IfaceSpec, store *Store, interval time.Duration) {
	go untilDone(ctx, func() { SendOnInterface(ctx, role, spec, interval) })
	untilDone(ctx, func() { listenOnInterface(ctx, spec, store) })
}

const ifaceRetryDelay = 30 * time.Second

func untilDone(ctx context.Context, f func()) {
	for {
		f()
		select {
		case <-ctx.Done():
			return
		case <-time.After(ifaceRetryDelay):
		}
	}
}

// Update makes the running set equal specs and returns what it started and
// stopped.
func (r *Runner) Update(ctx context.Context, specs []IfaceSpec) (added, removed []IfaceSpec) {
	r.mu.Lock()
	defer r.mu.Unlock()
	wanted := make(map[string]IfaceSpec, len(specs))
	for _, sp := range specs {
		wanted[sp.Name+"|"+sp.Kind] = sp
	}
	for key, ri := range r.running {
		if _, ok := wanted[key]; ok {
			continue
		}
		ri.cancel()
		delete(r.running, key)
		r.store.Forget(ri.spec.Name)
		removed = append(removed, ri.spec)
	}
	for key, sp := range wanted {
		if _, ok := r.running[key]; ok {
			continue
		}
		ictx, cancel := context.WithCancel(ctx)
		r.running[key] = runningIface{spec: sp, cancel: cancel}
		go r.start(ictx, r.role, sp, r.store, r.interval)
		added = append(added, sp)
	}
	return added, removed
}

// HeardFrom reports whether store currently holds a fresh sighting of role
// on any interface of the given kind.
func (s *Store) HeardFrom(role, kind string) bool {
	for _, sig := range s.Snapshot() {
		if sig.PeerRole == role && sig.PeerKind == kind {
			return true
		}
	}
	return false
}

// bindToDeviceUDP4 mirrors internal/discovery's own identical helper
// (unexported there too).
func bindToDeviceUDP4(iface string) net.ListenConfig {
	return net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			cerr := c.Control(func(fd uintptr) {
				if serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1); serr != nil {
					return
				}
				serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
			})
			if cerr != nil {
				return cerr
			}
			return serr
		},
	}
}

func SendOnInterface(ctx context.Context, role string, spec IfaceSpec, interval time.Duration) {
	linkUp(spec.Name)

	payload, err := json.Marshal(Beacon{Magic: Magic, Role: role, Iface: spec.Name, Kind: spec.Kind})
	if err != nil {
		log.Printf("[TOPOBEACON:ERROR] marshal beacon for %s: %v", spec.Name, err)
		return
	}

	lc := bindToDeviceUDP4(spec.Name)
	pc, err := lc.ListenPacket(ctx, "udp4", ":0")
	if err != nil {
		log.Printf("[TOPOBEACON:ERROR] bind send socket on %s: %v", spec.Name, err)
		return
	}
	defer pc.Close()

	dst := &net.UDPAddr{IP: net.IPv4bcast, Port: Port}
	failing := false
	send := func() {
		_, err := pc.WriteTo(payload, dst)
		switch {
		case err != nil && !failing:
			log.Printf("[TOPOBEACON:ERROR] send beacon on %s: %v", spec.Name, err)
		case err == nil && failing:
			log.Printf("[TOPOBEACON:RECOVERED] beacon send on %s works again", spec.Name)
		}
		failing = err != nil
	}
	send()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			send()
		}
	}
}

// listenOnInterface binds to spec.Name via SO_BINDTODEVICE and records
// every valid Beacon heard into store, forever, until ctx is done.
func listenOnInterface(ctx context.Context, spec IfaceSpec, store *Store) {
	lc := bindToDeviceUDP4(spec.Name)
	pc, err := lc.ListenPacket(ctx, "udp4", ":"+itoa(Port))
	if err != nil {
		log.Printf("[TOPOBEACON:ERROR] bind listen socket on %s: %v", spec.Name, err)
		return
	}
	defer pc.Close()
	go func() {
		<-ctx.Done()
		pc.Close()
	}()

	buf := make([]byte, 1024)
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		var b Beacon
		if err := json.Unmarshal(buf[:n], &b); err != nil {
			continue
		}
		if b.Magic != Magic || b.Iface == "" || b.Role == "" {
			continue
		}
		store.record(spec.Name, spec.Kind, b)
	}
}

// itoa avoids importing strconv for exactly one int-to-string conversion
// in this small package.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// LinkUp brings an interface up before beaconing on it; dnshived points it
// at dnshived-helper. Nil skips it.
var LinkUp func(iface string) error

func linkUp(iface string) {
	if LinkUp == nil {
		return
	}
	if err := LinkUp(iface); err != nil {
		log.Printf("[TOPOBEACON:WARN] bring %s up before beaconing: %v", iface, err)
	}
}
