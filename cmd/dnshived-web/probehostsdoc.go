// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"sync"
	"time"

	"dnshived/internal/repldoc"
)

// Limits on an incoming probe-host list; far above real use.
const (
	maxReplProbeHosts = 500
	maxReplHostField  = 8192
)

// probeHostsWire is the probe-host document as sent between instances.
type probeHostsWire struct {
	repldoc.Meta
	ProbeHosts []NodeConfig `json:"probe_hosts"`
}

// probeHostsDoc replicates the probe-host list kept in web.json. The list
// is still changed (and sent to the siblings at once) by the probe
// handlers; this document makes an instance that missed such a change catch
// up. A change is noticed by comparing the content hash with the stamp.
type probeHostsDoc struct {
	ref     *configRef
	cfgPath string
	self    func() string

	// writeMu serialises this document's own writers (adopt, drift, first revision).
	writeMu sync.Mutex
}

func newProbeHostsDoc(ref *configRef, cfgPath string, self func() string) *probeHostsDoc {
	return &probeHostsDoc{ref: ref, cfgPath: cfgPath, self: self}
}

// probeHostsHash is the content hash of a list, independent of its order.
func probeHostsHash(hosts []NodeConfig) string {
	sorted := append([]NodeConfig(nil), hosts...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Addr < sorted[j].Addr })
	data, err := json.Marshal(sorted)
	if err != nil {
		return ""
	}
	return repldoc.BodyHash(data)
}

func (d *probeHostsDoc) Meta() repldoc.Meta {
	cfg := d.ref.Load()
	return repldoc.Meta{
		Version:   cfg.ProbeHostsVersion,
		UpdatedAt: cfg.ProbeHostsUpdatedAt,
		Origin:    cfg.ProbeHostsOrigin,
		Hash:      probeHostsHash(cfg.ProbeHosts),
	}
}

func (d *probeHostsDoc) Marshal() ([]byte, error) {
	cfg := d.ref.Load()
	hosts := cfg.ProbeHosts
	if hosts == nil {
		hosts = []NodeConfig{}
	}
	return json.Marshal(probeHostsWire{Meta: d.Meta(), ProbeHosts: hosts})
}

// validateProbeHosts refuses a list no real instance would send.
func validateProbeHosts(hosts []NodeConfig) error {
	if len(hosts) > maxReplProbeHosts {
		return fmt.Errorf("probe-host list has %d entries, more than the limit of %d", len(hosts), maxReplProbeHosts)
	}
	seen := make(map[string]bool, len(hosts))
	for i, h := range hosts {
		if h.Addr == "" || len(h.Addr) > 255 {
			return fmt.Errorf("probe-host list: entry %d has an empty or oversized address", i)
		}
		if seen[h.Addr] {
			return fmt.Errorf("probe-host list: address %q appears twice", h.Addr)
		}
		seen[h.Addr] = true
		for _, f := range []string{h.Name, h.DisplayName, h.AdminToken, h.TLSPort, h.TLSFingerprint} {
			if len(f) > maxReplHostField {
				return fmt.Errorf("probe-host list: entry %q has an oversized field", h.Addr)
			}
		}
		if h.TLSPort != "" {
			if n, err := strconv.Atoi(h.TLSPort); err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("probe-host list: entry %q has an invalid TLS port", h.Addr)
			}
		}
	}
	return nil
}

// publish writes next to web.json and makes it the live value, unless a
// handler changed the live value meanwhile (then it returns an error and the
// next comparison tries again).
func (d *probeHostsDoc) publish(old, next *WebConfig) error {
	if err := saveWebConfig(d.cfgPath, next); err != nil {
		return fmt.Errorf("save web.json: %w", err)
	}
	if !d.ref.CompareAndSwap(old, next) {
		return errors.New("web.json changed while the probe-host list was being updated; retrying on the next comparison")
	}
	return nil
}

func stampNow() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// Adopt installs the list in raw when it is newer than this instance's. A
// never-replicated local list is merged by address, so no local probe host
// is lost, and the merged result gets a new revision so it spreads.
func (d *probeHostsDoc) Adopt(raw []byte, from string) (adopted, spread bool, err error) {
	var wire struct {
		repldoc.Meta
		ProbeHosts *[]NodeConfig `json:"probe_hosts"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return false, false, invalidDocError{"parse probe-host document: " + err.Error()}
	}
	if wire.ProbeHosts == nil {
		return false, false, invalidDocError{"probe-host document has no probe_hosts list"}
	}
	if err := repldoc.ValidMeta(wire.Meta); err != nil {
		return false, false, invalidDocError{err.Error()}
	}
	in := probeHostsWire{Meta: wire.Meta, ProbeHosts: *wire.ProbeHosts}
	if err := validateProbeHosts(in.ProbeHosts); err != nil {
		return false, false, invalidDocError{err.Error()}
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	cfg := d.ref.Load()
	localStamp := repldoc.Meta{Version: cfg.ProbeHostsVersion, UpdatedAt: cfg.ProbeHostsUpdatedAt, Origin: cfg.ProbeHostsOrigin}
	if !repldoc.Newer(in.Meta, localStamp) {
		return false, false, nil
	}
	hosts := append([]NodeConfig(nil), in.ProbeHosts...)
	next := *cfg
	next.ProbeHostsVersion, next.ProbeHostsUpdatedAt, next.ProbeHostsOrigin = in.Version, in.UpdatedAt, in.Origin
	var kept []string
	if cfg.ProbeHostsVersion == 0 {
		have := make(map[string]bool, len(hosts))
		for _, h := range hosts {
			have[h.Addr] = true
		}
		for _, h := range cfg.ProbeHosts {
			if !have[h.Addr] {
				hosts = append(hosts, h)
				kept = append(kept, h.Addr)
			}
		}
		if len(kept) > 0 {
			next.ProbeHostsVersion++
			next.ProbeHostsUpdatedAt = stampNow()
			next.ProbeHostsOrigin = d.self()
		}
	}
	next.ProbeHosts = hosts
	next.ProbeHostsHash = probeHostsHash(hosts)
	if err := d.publish(cfg, &next); err != nil {
		return false, false, err
	}
	log.Printf("[REPL] probe-host list %d → %d from %s (%d host(s))", cfg.ProbeHostsVersion, next.ProbeHostsVersion, from, len(hosts))
	if len(kept) > 0 {
		log.Printf("[REPL] kept this instance's own probe hosts %v while joining the replicated list", kept)
		auditAll(d.ref.Load(), "system", "probehosts.merge", fmt.Sprintf("merged probe hosts %v from %s into the replicated probe-host list", kept, d.self()))
	}
	return true, len(kept) > 0, nil
}

// StartFirst begins revision 1 of a never-replicated list.
func (d *probeHostsDoc) StartFirst(self string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	cfg := d.ref.Load()
	if cfg.ProbeHostsVersion != 0 {
		return nil
	}
	next := *cfg
	next.ProbeHostsVersion, next.ProbeHostsUpdatedAt, next.ProbeHostsOrigin = 1, stampNow(), self
	next.ProbeHostsHash = probeHostsHash(cfg.ProbeHosts)
	return d.publish(cfg, &next)
}

// Drift stamps a new revision when the list was changed by a probe handler
// since the last stamp. A never-replicated list is not stamped here.
func (d *probeHostsDoc) Drift(self string) (bool, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	cfg := d.ref.Load()
	if cfg.ProbeHostsVersion == 0 {
		return false, nil
	}
	cur := probeHostsHash(cfg.ProbeHosts)
	if cur == cfg.ProbeHostsHash {
		return false, nil
	}
	next := *cfg
	next.ProbeHostsVersion++
	next.ProbeHostsUpdatedAt, next.ProbeHostsOrigin, next.ProbeHostsHash = stampNow(), self, cur
	if err := d.publish(cfg, &next); err != nil {
		return false, err
	}
	return true, nil
}

// newProbeHostsSyncer builds the syncer for the probe-host document.
func newProbeHostsSyncer(ref *configRef, doc *probeHostsDoc, self func() string) *repldoc.Syncer {
	return &repldoc.Syncer{
		Name:       "REPL:probe-hosts",
		Path:       "/internal/docs/probe-hosts",
		Doc:        doc,
		Self:       self,
		Peers:      func() []repldoc.Peer { return replPeers(ref) },
		Do:         replDo(ref),
		DecodeMeta: decodeMeta,
		OnConflict: replConflict(ref, "probe-hosts"),
		Logf:       log.Printf,
	}
}

// runProbeHostsSync starts the periodic comparison.
func runProbeHostsSync(ctx context.Context, s *repldoc.Syncer) {
	s.Run(ctx, 7*time.Second, authSyncInterval)
}

func (d *probeHostsDoc) handlers(push func()) replHandlers {
	return replHandlers{ref: d.ref, doc: d, push: push}
}
