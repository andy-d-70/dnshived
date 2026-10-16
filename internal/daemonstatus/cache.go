// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package daemonstatus

import (
	"strings"
	"sync"
	"time"
)

// Cache serves unit states from one `systemctl show` over a fixed set of
// unit names and globs, refreshed at most once per maxAge.
type Cache struct {
	patterns []string
	maxAge   time.Duration
	query    func([]string) map[string]Status

	mu   sync.Mutex
	at   time.Time
	data map[string]Status
}

func NewCache(maxAge time.Duration, patterns ...string) *Cache {
	return &Cache{patterns: patterns, maxAge: maxAge, query: QueryMany}
}

func (c *Cache) snapshot() map[string]Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.data == nil || time.Since(c.at) >= c.maxAge {
		c.data = c.query(c.patterns)
		c.at = time.Now()
	}
	return c.data
}

// Get returns unit's state from the current snapshot.
func (c *Cache) Get(unit string) Status {
	if st, ok := c.snapshot()[unit]; ok {
		return st
	}
	return Status{Unit: unit}
}

// Prefixed returns every unit in the snapshot whose name starts with
// prefix (e.g. "dnshived-dnsmasq@").
func (c *Cache) Prefixed(prefix string) map[string]Status {
	out := make(map[string]Status)
	for unit, st := range c.snapshot() {
		if strings.HasPrefix(unit, prefix) {
			out[unit] = st
		}
	}
	return out
}

// Invalidate forces the next read to query systemd again; called after
// starting, stopping or reloading a unit.
func (c *Cache) Invalidate() {
	c.mu.Lock()
	c.data = nil
	c.mu.Unlock()
}

// NewCacheForTest returns a long-lived Cache backed by query instead of
// systemctl, for other packages' tests.
func NewCacheForTest(query func([]string) map[string]Status) *Cache {
	c := NewCache(time.Hour)
	c.query = query
	return c
}
