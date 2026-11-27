// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"fmt"
	"strconv"
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

// probeHostsDoc replicates the probe-host list kept in web.json, keyed by address.
type probeHostsDoc = listDoc

var probeHostsSpec = listSpec{
	tag:     "probe-hosts",
	path:    "/internal/docs/probe-hosts",
	wireKey: "probe_hosts",
	part:    "probe_hosts",
	noun:    "probe host",
	key:     func(n NodeConfig) string { return n.Addr },
	get:     func(c *WebConfig) []NodeConfig { return c.ProbeHosts },
	set:     func(c *WebConfig, l []NodeConfig) { c.ProbeHosts = l },
	stamp: func(c *WebConfig) (*int64, *string, *string, *string) {
		return &c.ProbeHostsVersion, &c.ProbeHostsUpdatedAt, &c.ProbeHostsOrigin, &c.ProbeHostsHash
	},
	check: validateProbeHosts,
}

func newProbeHostsDoc(ref *configRef, cfgPath string, self func() string) *listDoc {
	return &listDoc{spec: probeHostsSpec, ref: ref, cfgPath: cfgPath, self: self}
}

func newProbeHostsSyncer(ref *configRef, doc *listDoc, self func() string) *repldoc.Syncer {
	return newListSyncer(ref, doc, self)
}

func runProbeHostsSync(ctx context.Context, s *repldoc.Syncer) { runListSync(ctx, s, 7*time.Second) }

// probeHostsHash is the content hash of a list, independent of its order.
func probeHostsHash(hosts []NodeConfig) string { return listHash(probeHostsSpec, hosts) }

// saveProbeHostsChange saves a change of the probe-host list (see saveWebChange).
func saveProbeHostsChange(cfgPath string, ref *configRef, old, next *WebConfig) error {
	return saveWebChange(cfgPath, ref, old, next)
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
