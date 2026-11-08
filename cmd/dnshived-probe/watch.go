// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"crypto/sha256"
	"fmt"
	"net"
	"regexp"
	"sync"
	"time"

	"dnshived/internal/dhcpprobe"
)

const (
	maxManualProbes   = 64
	maxExpectedServer = 16
	watchPrefix       = "watch:"
	watchWait         = 4 * time.Second
)

var manualProbeNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// ManualProbe is an operator-defined DHCP watch on one interface, tagged or
// untagged: it sends a DISCOVER (never a REQUEST) and reports every server
// that answers. Any server not listed in ExpectedServers is a rogue.
type ManualProbe struct {
	Name            string   `json:"name"`
	Interface       string   `json:"interface"`
	VLANID          int      `json:"vlan_id,omitempty"`
	ExpectedServers []string `json:"expected_servers,omitempty"`
}

func (m ManualProbe) key() string { return watchPrefix + m.Name }

func (m ManualProbe) iface() string { return realIfaceName(m.Interface, m.VLANID) }

// validateManualProbes checks a full replacement list against the interfaces
// this host may serve.
func validateManualProbes(cfg *ProbeConfig, list []ManualProbe) error {
	if len(list) > maxManualProbes {
		return fmt.Errorf("at most %d manual probes", maxManualProbes)
	}
	allowed := make(map[string]bool)
	for _, p := range cfg.servingParents() {
		allowed[p] = true
	}
	names := make(map[string]bool, len(list))
	places := make(map[string]string, len(list))
	for _, m := range list {
		if !manualProbeNameRE.MatchString(m.Name) {
			return fmt.Errorf("manual probe name %q: lowercase letters, digits, - and _, 1 to 32 characters", m.Name)
		}
		if names[m.Name] {
			return fmt.Errorf("manual probe name %q is used twice", m.Name)
		}
		names[m.Name] = true
		if !allowed[m.Interface] {
			return fmt.Errorf("manual probe %q: interface %q is not one this probe host serves", m.Name, m.Interface)
		}
		if m.VLANID != 0 && (m.VLANID < 2 || m.VLANID > 4094) {
			return fmt.Errorf("manual probe %q: vlan_id %d out of range (2-4094, or 0 for untagged)", m.Name, m.VLANID)
		}
		if m.VLANID != 0 && m.Interface == cfg.MgmtInterface {
			return fmt.Errorf("manual probe %q: the management interface is never tagged", m.Name)
		}
		where := fmt.Sprintf("%s|%d", m.Interface, m.VLANID)
		if other, dup := places[where]; dup {
			return fmt.Errorf("manual probes %q and %q watch the same interface and VLAN", other, m.Name)
		}
		places[where] = m.Name
		if len(m.ExpectedServers) > maxExpectedServer {
			return fmt.Errorf("manual probe %q: at most %d expected servers", m.Name, maxExpectedServer)
		}
		for _, s := range m.ExpectedServers {
			if ip := net.ParseIP(s); ip == nil || ip.To4() == nil {
				return fmt.Errorf("manual probe %q: expected server %q is not an IPv4 address", m.Name, s)
			}
		}
	}
	return nil
}

// WatchResult is the latest outcome of one manual probe.
type WatchResult struct {
	Name      string `json:"name"`
	Interface string `json:"interface"`
	VLANID    int    `json:"vlan_id,omitempty"`
	Pending   bool   `json:"pending,omitempty"`
	// ExpectedServers echoes the configured list so a client can edit it.
	ExpectedServers []string          `json:"expected_servers,omitempty"`
	Verdict         string            `json:"verdict,omitempty"` // clear, ok, rogue, error
	Servers         []string          `json:"servers,omitempty"`
	Unexpected      []string          `json:"unexpected,omitempty"`
	Offers          []DHCPOfferDetail `json:"offers,omitempty"`
	OfferMS         int64             `json:"offer_ms,omitempty"`
	Error           string            `json:"error,omitempty"`
	ProbedAt        time.Time         `json:"probed_at,omitzero"`
}

type watchStore struct {
	mu      sync.Mutex
	results map[string]WatchResult
}

// watchResults is the one store every runner and the API share.
var watchResults = newWatchStore()

func newWatchStore() *watchStore { return &watchStore{results: make(map[string]WatchResult)} }

func (s *watchStore) set(r WatchResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results[r.Name] = r
}

func (s *watchStore) prune(keep map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name := range s.results {
		if !keep[name] {
			delete(s.results, name)
		}
	}
}

// list returns one entry per configured manual probe, in configured order; a
// probe that has not run yet is flagged pending.
func (s *watchStore) list(configured []ManualProbe) []WatchResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]WatchResult, 0, len(configured))
	for _, m := range configured {
		if r, ok := s.results[m.Name]; ok {
			r.ExpectedServers = m.ExpectedServers
			out = append(out, r)
			continue
		}
		out = append(out, WatchResult{Name: m.Name, Interface: m.Interface, VLANID: m.VLANID, Pending: true, ExpectedServers: m.ExpectedServers})
	}
	return out
}

func unexpectedServers(servers, expected []string) []string {
	want := make(map[string]bool, len(expected))
	for _, e := range expected {
		want[e] = true
	}
	var out []string
	for _, s := range servers {
		if !want[s] {
			out = append(out, s)
		}
	}
	return out
}

// stableMAC derives a locally administered unicast MAC from a label, so the
// same probe always presents the same client and a DHCP server re-offers one
// address instead of holding a new one for every probe.
func stableMAC(label string) net.HardwareAddr {
	sum := sha256.Sum256([]byte(label))
	mac := net.HardwareAddr(sum[:6])
	mac[0] = (mac[0] | 0x02) &^ 0x01
	return mac
}

func watchOptions(m ManualProbe, stopAtFirst bool) dhcpprobe.Options {
	o := dhcpprobe.DefaultOptions()
	o.MAC = stableMAC(fmt.Sprintf("manual|%s|%s|%d", m.Name, m.Interface, m.VLANID))
	if stopAtFirst {
		o.StopOnFirstOffer = true
		o.FirstOfferGrace = dhcpOfferGrace
	}
	return o
}

// runWatchProbe sends one DISCOVER and classifies every answer. An answer
// from an unlisted server is probed once more over the whole window so
// every server that answers is listed.
func runWatchProbe(m ManualProbe) WatchResult {
	r := WatchResult{Name: m.Name, Interface: m.Interface, VLANID: m.VLANID}
	iface := m.iface()
	if _, err := ifaceExistsFn(iface); err != nil {
		r.Verdict, r.Error = "error", "interface "+iface+" does not exist on this probe host (yet)"
		r.ProbedAt = time.Now()
		return r
	}
	dr, err := dhcpProbeFn(iface, watchWait, watchOptions(m, true))
	if err == nil && len(unexpectedServers(dr.Servers, m.ExpectedServers)) > 0 {
		if full, ferr := dhcpProbeFn(iface, watchWait, watchOptions(m, false)); ferr == nil && len(full.Offers) >= len(dr.Offers) {
			dr = full
		}
	}
	r.ProbedAt = time.Now()
	if err != nil {
		r.Verdict, r.Error = "error", err.Error()
		return r
	}
	r.Servers = dr.Servers
	r.Offers = dhcpOffersToDetails(dr.Offers)
	if len(dr.Offers) > 0 {
		r.OfferMS = dr.Offers[0].At.Milliseconds()
	}
	r.Unexpected = unexpectedServers(dr.Servers, m.ExpectedServers)
	switch {
	case len(dr.Offers) == 0:
		r.Verdict = "clear"
	case len(r.Unexpected) > 0:
		r.Verdict = "rogue"
	default:
		r.Verdict = "ok"
	}
	return r
}
