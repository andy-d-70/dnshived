// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package leasesync implements dynamic DHCP lease sync between the two
// workers' shared central-DHCP dnsmasq instances
// (internal/dhcpcentralrender).
package leasesync

import (
	"sort"
	"sync"
	"time"
)

const SocketPath = "/run/dnshived/dhcp-lease.sock"

// SyncedLease is one dynamically-granted DHCP lease being shadowed as a
// temporary reservation.
type SyncedLease struct {
	MAC       string `json:"mac"`
	IP        string `json:"ip"`
	ExpiresAt int64  `json:"expires_at,omitempty"` // unix seconds, from DNSMASQ_LEASE_EXPIRES
	// Hostname is the client's own DHCP-supplied name (dnsmasq's --dhcp-script
	// hook receives it as its own argument when the client sent one via option
	// 12/61).
	Hostname string `json:"hostname,omitempty"`
}

// Store is a small, mutex-protected, MAC-keyed table of currently-valid
// synced leases.
type Store struct {
	mu    sync.RWMutex
	byMAC map[string]SyncedLease
	path  string
	dirty bool
}

// NewStore returns an empty Store, ready to use.
func NewStore() *Store {
	return &Store{byMAC: make(map[string]SyncedLease)}
}

// SetPersistPath installs where LoadFromDisk/FlushIfDirty read/write.
func (s *Store) SetPersistPath(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.path = path
}

// Upsert records or replaces the entry for l.MAC.
func (s *Store) Upsert(l SyncedLease) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byMAC[l.MAC] = l
	s.dirty = true
}

// Remove deletes mac's entry, if any.
func (s *Store) Remove(mac string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byMAC[mac]; !ok {
		return
	}
	delete(s.byMAC, mac)
	s.dirty = true
}

// PruneExpired removes every entry whose ExpiresAt is at or before now,
// returning how many were removed.
func (s *Store) PruneExpired(now time.Time) int {
	cutoff := now.Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for mac, l := range s.byMAC {
		if l.ExpiresAt <= cutoff {
			delete(s.byMAC, mac)
			n++
		}
	}
	if n > 0 {
		s.dirty = true
	}
	return n
}

// Snapshot returns every current entry, sorted by MAC for a deterministic,
// diffable render.
func (s *Store) Snapshot() []SyncedLease {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SyncedLease, 0, len(s.byMAC))
	for _, l := range s.byMAC {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out
}

// Len reports the current entry count — used by /api/v1/daemons-style
// visibility and tests, without needing a full Snapshot.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byMAC)
}

func (s *Store) LoadFromDisk() (int, error) {
	s.mu.Lock()
	path := s.path
	s.mu.Unlock()
	if path == "" {
		return 0, nil
	}
	leases, err := loadLeasesFile(path)
	if err != nil {
		return 0, err
	}
	cutoff := time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, l := range leases {
		if l.ExpiresAt <= cutoff {
			continue
		}
		s.byMAC[l.MAC] = l
		n++
	}
	return n, nil
}

// FlushIfDirty writes the current contents to disk if anything changed
// since the last flush (or load) — a no-op, cheaply, otherwise.
func (s *Store) FlushIfDirty() error {
	s.mu.Lock()
	if !s.dirty || s.path == "" {
		s.mu.Unlock()
		return nil
	}
	path := s.path
	out := make([]SyncedLease, 0, len(s.byMAC))
	for _, l := range s.byMAC {
		out = append(out, l)
	}
	s.dirty = false
	s.mu.Unlock()

	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return saveLeasesFile(path, out)
}
