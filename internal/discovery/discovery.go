// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package discovery implements dnshived's own LAN autodiscovery for
// unclaimed/unconfigured nodes waiting to be onboarded.
package discovery

import (
	"context"
	"dnshived/internal/loglevel"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Magic identifies a genuine dnshived discovery packet — distinguishes
// it from any other stray broadcast traffic that might land on this port.
const (
	Magic        = "DNSHIVED-UNCLAIMED"
	ProtoVersion = 1

	// Port is dnshived's own dedicated discovery broadcast port.
	Port = 9445

	// interval is how often a fresh, unclaimed node re-announces itself.
	interval = 5 * time.Second
	ttl      = 30 * time.Second
)

// Announcement is the wire payload.
type Announcement struct {
	Magic        string `json:"magic"`
	ProtoVersion int    `json:"proto_version"`
	Hostname     string `json:"hostname"`
	Version      string `json:"version"`
	// BootstrapPort is the real port this candidate's own bootstrap API is
	// listening on.
	BootstrapPort int `json:"bootstrap_port"`
}

func Broadcast(ctx context.Context, hostname, version string, bootstrapPort int) {
	payload, err := json.Marshal(Announcement{
		Magic: Magic, ProtoVersion: ProtoVersion,
		Hostname: hostname, Version: version, BootstrapPort: bootstrapPort,
	})
	if err != nil {
		loglevel.Infof("[DISCOVERY] marshal announcement: %v", err)
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	broadcastOnce(payload)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			broadcastOnce(payload)
		}
	}
}

func broadcastOnce(payload []byte) {
	for _, dst := range broadcastAddrs() {
		conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: dst, Port: Port})
		if err != nil {
			continue
		}
		conn.Write(payload)
		conn.Close()
	}
}

// broadcastAddrs computes the IPv4 directed-broadcast address of every up,
// non-loopback interface currently carrying a real IPv4 address.
func broadcastAddrs() []net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []net.IP
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagBroadcast == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil || len(ipNet.Mask) != 4 {
				continue
			}
			bcast := make(net.IP, 4)
			for i := range bcast {
				bcast[i] = ip4[i] | ^ipNet.Mask[i]
			}
			out = append(out, bcast)
		}
	}
	return out
}

// PortFromAddr extracts the numeric port from a "host:port" or ":port"
// listen-address string (the shape every --bootstrap-addr flag in this
// project already takes).
func PortFromAddr(addr string, fallback int) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fallback
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 {
		return fallback
	}
	return port
}

// UnconfiguredInterfaces lists every non-loopback interface that currently
// carries NO IPv4 address.
func UnconfiguredInterfaces() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		hasIPv4 := false
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if ok && ipNet.IP.To4() != nil {
				hasIPv4 = true
				break
			}
		}
		if !hasIPv4 {
			out = append(out, iface.Name)
		}
	}
	sort.Strings(out)
	return out, nil
}

const (
	InterfaceProbeMagic = "DNSHIVED-IFPROBE"
	InterfaceProbePort  = 9448
	// interfaceProbeInterval is how often a burst re-sends while active.
	interfaceProbeInterval = 500 * time.Millisecond
)

// InterfaceProbe is the burst-mode wire payload.
type InterfaceProbe struct {
	Magic          string `json:"magic"`
	ProtoVersion   int    `json:"proto_version"`
	Hostname       string `json:"hostname"`
	LocalInterface string `json:"local_interface"`
}

// bindToDeviceUDP4 returns a net.ListenConfig whose sockets (both
// listening and dialing) are bound to iface via SO_BINDTODEVICE.
func bindToDeviceUDP4(iface string) net.ListenConfig {
	return net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
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

func BroadcastOnInterface(ctx context.Context, iface, hostname string) error {
	return broadcastOnInterfaceAt(ctx, iface, hostname, InterfaceProbePort)
}

func broadcastOnInterfaceAt(ctx context.Context, iface, hostname string, port int) error {
	linkUp(iface)

	payload, err := json.Marshal(InterfaceProbe{
		Magic: InterfaceProbeMagic, ProtoVersion: ProtoVersion,
		Hostname: hostname, LocalInterface: iface,
	})
	if err != nil {
		return fmt.Errorf("marshal interface probe: %w", err)
	}

	lc := bindToDeviceUDP4(iface)
	pc, err := lc.ListenPacket(ctx, "udp4", ":0")
	if err != nil {
		return fmt.Errorf("bind to %s: %w", iface, err)
	}
	defer pc.Close()

	dst := &net.UDPAddr{IP: net.IPv4bcast, Port: port}
	ticker := time.NewTicker(interfaceProbeInterval)
	defer ticker.Stop()
	logged := false
	send := func() {
		if _, err := pc.WriteTo(payload, dst); err != nil && !logged {
			logged = true
			loglevel.Warnf("[DISCOVERY:WARN] interface probe send on %s: %v", iface, err)
		}
	}
	send()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			send()
		}
	}
}

// ListenOnInterface binds to localIface via SO_BINDTODEVICE and waits up
// to timeout for one valid InterfaceProbe.
func ListenOnInterface(ctx context.Context, localIface string, timeout time.Duration) (probe InterfaceProbe, ok bool) {
	return listenOnInterfaceAt(ctx, localIface, timeout, InterfaceProbePort)
}

func listenOnInterfaceAt(ctx context.Context, localIface string, timeout time.Duration, port int) (probe InterfaceProbe, ok bool) {
	lc := bindToDeviceUDP4(localIface)
	pc, err := lc.ListenPacket(ctx, "udp4", fmt.Sprintf(":%d", port))
	if err != nil {
		loglevel.Warnf("[DISCOVERY:ERROR] listen for interface probes on %s: %v", localIface, err)
		return InterfaceProbe{}, false
	}
	defer pc.Close()

	deadline := time.Now().Add(timeout)
	pc.SetReadDeadline(deadline)
	buf := make([]byte, 1024)
	for {
		if time.Now().After(deadline) {
			return InterfaceProbe{}, false
		}
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return InterfaceProbe{}, false
		}
		var p InterfaceProbe
		if err := json.Unmarshal(buf[:n], &p); err != nil {
			continue
		}
		if p.Magic != InterfaceProbeMagic || p.ProtoVersion != ProtoVersion {
			continue
		}
		return p, true
	}
}

// Candidate is one currently-live, discovered-but-unclaimed node, as
// reported by GET /api/v1/discovered-nodes.
type Candidate struct {
	Addr          string    `json:"addr"`
	Hostname      string    `json:"hostname"`
	Version       string    `json:"version"`
	BootstrapPort int       `json:"bootstrap_port"`
	LastSeen      time.Time `json:"last_seen"`
}

// Listener maintains an in-memory, TTL-pruned view of every currently
// reachable, unclaimed dnshived node this host has heard an Announcement
// from recently.
type Listener struct {
	mu   sync.Mutex
	seen map[string]Candidate // keyed by source IP
}

// NewListener returns a Listener with an empty view — call Run to
// actually start listening.
func NewListener() *Listener {
	return &Listener{seen: make(map[string]Candidate)}
}

// Run listens for Announcements on Port until ctx is cancelled.
func (l *Listener) Run(ctx context.Context) error {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: Port})
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	buf := make([]byte, 1024)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		var ann Announcement
		if err := json.Unmarshal(buf[:n], &ann); err != nil {
			continue
		}
		if ann.Magic != Magic || ann.ProtoVersion != ProtoVersion {
			continue
		}
		l.mu.Lock()
		l.seen[src.IP.String()] = Candidate{
			Addr:          src.IP.String(),
			Hostname:      ann.Hostname,
			Version:       ann.Version,
			BootstrapPort: ann.BootstrapPort,
			LastSeen:      time.Now(),
		}
		l.mu.Unlock()
	}
}

// Snapshot returns every candidate heard from within the last ttl, pruning
// anything older from the live map.
func (l *Listener) Snapshot() []Candidate {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := time.Now().Add(-ttl)
	out := make([]Candidate, 0, len(l.seen))
	for addr, c := range l.seen {
		if c.LastSeen.Before(cutoff) {
			delete(l.seen, addr)
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	return out
}

// LinkUp brings an interface up before beaconing on it; dnshived points it
// at dnshived-helper. Nil skips it.
var LinkUp func(iface string) error

func linkUp(iface string) {
	if LinkUp == nil {
		return
	}
	if err := LinkUp(iface); err != nil {
		loglevel.Warnf("[DISCOVERY:WARN] bring %s up before beaconing: %v", iface, err)
	}
}

// carrierWait bounds how long EnsureUp waits for a freshly enabled link
// to report carrier (physical NICs negotiate for a few seconds).
var carrierWait = 5 * time.Second

var sysClassNet = "/sys/class/net/"

// EnsureUp brings iface up before listening on it — on a node in bootstrap
// mode or without scopes the trunk NICs are still down and would hear
// nothing — and waits briefly for carrier.
func EnsureUp(iface string) {
	if _, err := os.Stat(sysClassNet + iface); err != nil {
		return
	}
	linkUp(iface)
	deadline := time.Now().Add(carrierWait)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(sysClassNet + iface + "/carrier"); err == nil && strings.TrimSpace(string(b)) == "1" {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	loglevel.Warnf("[DISCOVERY:WARN] %s has no carrier after %s — the interface check may not hear anything on it", iface, carrierWait)
}
