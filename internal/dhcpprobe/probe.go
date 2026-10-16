// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package dhcpprobe sends a single DHCPDISCOVER on an interface and
// reports EVERY DHCPOFFER that arrives within a listen window.
package dhcpprobe

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// probeLocks serializes DHCP probes PER PHYSICAL PARENT INTERFACE, not
// across the whole process.
var (
	probeLocksMu sync.Mutex
	probeLocks   = map[string]*sync.Mutex{}
)

// resourceFor returns the lock key for iface.
func resourceFor(iface string) string {
	if i := strings.LastIndexByte(iface, '.'); i > 0 {
		return iface[:i]
	}
	return iface
}

// lockFor returns the shared *sync.Mutex for resource, creating it on
// first use.
func lockFor(resource string) *sync.Mutex {
	probeLocksMu.Lock()
	defer probeLocksMu.Unlock()
	m, ok := probeLocks[resource]
	if !ok {
		m = &sync.Mutex{}
		probeLocks[resource] = m
	}
	return m
}

const (
	bootRequest = 1
	bootReply   = 2
	htypeEther  = 1
	hlenEther   = 6

	optPad          = 0
	optSubnetMask   = 1
	optRouter       = 3
	optDNS          = 6
	optLeaseTime    = 51
	optMessageType  = 53
	optServerID     = 54
	optParamReqList = 55
	optEnd          = 255

	dhcpDiscover = 1
	dhcpOffer    = 2
)

var magicCookie = []byte{0x63, 0x82, 0x53, 0x63}

// Offer is one parsed DHCPOFFER.
type Offer struct {
	ServerID net.IP
	YourIP   net.IP
	GIAddr   net.IP // relay that handled it; 0.0.0.0 if unrelayed
	Router   net.IP
	DNS      []net.IP
	Lease    uint32
	At       time.Duration
}

// Verdict classifies a Result the same way the CLI tool's exit codes do.
type Verdict string

const (
	VerdictOK         Verdict = "ok"          // exactly one server (possibly via multiple relays)
	VerdictNoAnswer   Verdict = "no_answer"   // nothing served this segment
	VerdictDualActive Verdict = "dual_active" // more than one distinct server answered
)

// Result is the outcome of one Probe call.
type Result struct {
	Offers  []Offer
	Servers []string // distinct server-ids, sorted
	Verdict Verdict
}

// Options tunes a Probe call.
type Options struct {
	MAC       net.HardwareAddr // client MAC; nil = random, locally-administered
	Broadcast bool             // set the BOOTP broadcast flag (replies to 255.255.255.255)

	// StopOnFirstOffer returns as soon as ONE offer is parsed, instead of
	// always listening out the full wait window.
	StopOnFirstOffer bool
}

func DefaultOptions() Options {
	return Options{Broadcast: true}
}

// ProbeWithOptions sends one DHCPDISCOVER on iface and collects every
// DHCPOFFER that arrives within wait, using the given MAC/broadcast-flag
// choice.
func ProbeWithOptions(iface string, wait time.Duration, opts Options) (Result, error) {
	mu := lockFor(resourceFor(iface))
	mu.Lock()
	defer mu.Unlock()

	chaddr := opts.MAC
	if chaddr == nil {
		var err error
		chaddr, err = randomMAC()
		if err != nil {
			return Result{}, err
		}
	}
	if len(chaddr) != 6 {
		return Result{}, fmt.Errorf("MAC must be 6 bytes, got %d", len(chaddr))
	}
	xid := rand.Uint32()

	pc, err := listen68(iface)
	if err != nil {
		return Result{}, fmt.Errorf("bind :68 on %s: %w", iface, err)
	}
	defer pc.Close()

	discover := buildDiscover(xid, chaddr, opts.Broadcast)
	start := time.Now()

	dst := &net.UDPAddr{IP: net.IPv4bcast, Port: 67}
	if _, err := pc.WriteTo(discover, dst); err != nil {
		return Result{}, fmt.Errorf("send DISCOVER: %w", err)
	}

	offers := collect(pc, xid, chaddr, wait, start, opts.StopOnFirstOffer)
	servers := distinctServers(offers)

	verdict := VerdictOK
	switch {
	case len(offers) == 0:
		verdict = VerdictNoAnswer
	case len(servers) > 1:
		verdict = VerdictDualActive
	}

	return Result{Offers: offers, Servers: servers, Verdict: verdict}, nil
}

// listen68 opens a UDP socket on :68 with SO_BROADCAST and SO_REUSEADDR,
// bound to the given device so the probe is unambiguous on a multi-homed
// host.
func listen68(iface string) (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var serr error
			cerr := c.Control(func(fd uintptr) {
				if serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET,
					syscall.SO_BROADCAST, 1); serr != nil {
					return
				}
				if serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET,
					syscall.SO_REUSEADDR, 1); serr != nil {
					return
				}
				serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET,
					syscall.SO_BINDTODEVICE, iface)
			})
			if cerr != nil {
				return cerr
			}
			return serr
		},
	}
	return lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:68")
}

func randomMAC() ([]byte, error) {
	// Locally administered, unicast: 02:xx:xx:xx:xx:xx
	b := make([]byte, 6)
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	b[0] = 0x02
	return b, nil
}

// buildDiscover assembles a BOOTP/DHCP DISCOVER with the broadcast flag
// set, so replies come back to 255.255.255.255:68 and we can see every one
// of them.
func buildDiscover(xid uint32, chaddr []byte, bcast bool) []byte {
	p := make([]byte, 240, 300)
	p[0] = bootRequest
	p[1] = htypeEther
	p[2] = hlenEther
	p[3] = 0 // hops
	binary.BigEndian.PutUint32(p[4:8], xid)
	binary.BigEndian.PutUint16(p[8:10], 0) // secs
	if bcast {
		binary.BigEndian.PutUint16(p[10:12], 0x8000) // flags: BROADCAST
	}
	// ciaddr/yiaddr/siaddr/giaddr stay zero (12..28)
	copy(p[28:34], chaddr)
	// sname (44 bytes at 44), file (128 at 108) stay zero
	copy(p[236:240], magicCookie)

	p = append(p, optMessageType, 1, dhcpDiscover)
	p = append(p, optParamReqList, 4, optSubnetMask, optRouter, optDNS, optLeaseTime)
	p = append(p, optEnd)

	// BOOTP minimum payload is 300 bytes; pad it out.
	for len(p) < 300 {
		p = append(p, optPad)
	}
	return p
}

func collect(pc net.PacketConn, xid uint32, chaddr []byte, wait time.Duration, start time.Time, stopOnFirstOffer bool) []Offer {
	var out []Offer
	deadline := time.Now().Add(wait)
	pc.SetReadDeadline(deadline)

	buf := make([]byte, 1500)
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			break // deadline or closed
		}
		o, ok := parseOffer(buf[:n], xid, chaddr)
		if !ok {
			continue
		}
		o.At = time.Since(start)
		out = append(out, o)
		if stopOnFirstOffer {
			break
		}
		pc.SetReadDeadline(deadline)
	}
	return out
}

func parseOffer(p []byte, xid uint32, chaddr []byte) (Offer, bool) {
	var o Offer
	if len(p) < 240 {
		return o, false
	}
	if p[0] != bootReply {
		return o, false
	}
	if binary.BigEndian.Uint32(p[4:8]) != xid {
		return o, false
	}
	if string(p[28:34]) != string(chaddr) {
		return o, false
	}
	if string(p[236:240]) != string(magicCookie) {
		return o, false
	}

	o.YourIP = net.IP(append([]byte(nil), p[16:20]...))
	o.GIAddr = net.IP(append([]byte(nil), p[24:28]...))

	isOffer := false
	for i := 240; i < len(p); {
		code := p[i]
		if code == optEnd {
			break
		}
		if code == optPad {
			i++
			continue
		}
		if i+1 >= len(p) {
			break
		}
		l := int(p[i+1])
		if i+2+l > len(p) {
			break
		}
		v := p[i+2 : i+2+l]
		switch code {
		case optMessageType:
			if l == 1 && v[0] == dhcpOffer {
				isOffer = true
			}
		case optServerID:
			if l == 4 {
				o.ServerID = net.IP(append([]byte(nil), v...))
			}
		case optRouter:
			if l >= 4 {
				o.Router = net.IP(append([]byte(nil), v[:4]...))
			}
		case optDNS:
			for j := 0; j+4 <= l; j += 4 {
				o.DNS = append(o.DNS, net.IP(append([]byte(nil), v[j:j+4]...)))
			}
		case optLeaseTime:
			if l == 4 {
				o.Lease = binary.BigEndian.Uint32(v)
			}
		}
		i += 2 + l
	}
	return o, isOffer
}

func distinctServers(offers []Offer) []string {
	seen := make(map[string]bool)
	for _, o := range offers {
		if o.ServerID != nil {
			seen[o.ServerID.String()] = true
		}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
