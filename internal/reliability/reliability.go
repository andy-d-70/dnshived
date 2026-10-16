// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package reliability

import (
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"
)

const (
	DecayFactor  = 0.7
	RecoveryStep = 3
)

// Entry is one persisted trust-index record.
type Entry struct {
	Score      int       `json:"score"`
	UpdatedAt  time.Time `json:"updated_at"`
	WasHealthy bool      `json:"was_healthy"`
}

// Next computes the entry that should replace prev given this tick's fresh
// healthyNow observation.
func Next(prev Entry, everObserved, healthyNow bool) Entry {
	base := prev.Score
	if !everObserved {
		base = 100 // never observed before -- start from full trust
	}
	now := time.Now()
	if healthyNow {
		score := base + RecoveryStep
		if score > 100 {
			score = 100
		}
		return Entry{Score: score, UpdatedAt: now, WasHealthy: true}
	}
	if !everObserved || prev.WasHealthy {
		score := int(float64(base) * DecayFactor)
		if score < 0 {
			score = 0
		}
		return Entry{Score: score, UpdatedAt: now, WasHealthy: false}
	}
	return Entry{Score: base, UpdatedAt: now, WasHealthy: false}
}

type Store struct {
	mu   sync.Mutex
	path string
	data map[string]Entry
}

func NewStore(path string) *Store {
	s := &Store{path: path, data: make(map[string]Entry)}
	if path == "" {
		return s
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	var loaded map[string]Entry
	if err := json.Unmarshal(data, &loaded); err != nil {
		log.Printf("[RELIABILITY:WARN] %s corrupt, ignoring: %v", path, err)
		return s
	}
	s.data = loaded
	return s
}

func (s *Store) Observe(key string, healthyNow bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, everObserved := s.data[key]
	next := Next(prev, everObserved, healthyNow)
	s.data[key] = next

	if s.path != "" {
		if err := save(s.path, s.cloneLocked()); err != nil {
			log.Printf("[RELIABILITY:WARN] persist %s: %v", s.path, err)
		}
	}
	return next.Score
}

// Get returns key's current entry, or (Entry{}, false) if never observed.
func (s *Store) Get(key string) (Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[key]
	return e, ok
}

// Snapshot returns a defensive copy of every currently-tracked entry.
func (s *Store) Snapshot() map[string]Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cloneLocked()
}

// cloneLocked returns a defensive copy of s.data.
func (s *Store) cloneLocked() map[string]Entry {
	cp := make(map[string]Entry, len(s.data))
	for k, v := range s.data {
		cp[k] = v
	}
	return cp
}

// Reset clears key back to "never observed".
func (s *Store) Reset(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)

	if s.path != "" {
		if err := save(s.path, s.cloneLocked()); err != nil {
			log.Printf("[RELIABILITY:WARN] persist %s: %v", s.path, err)
		}
	}
}

// RestoreAll replaces the store's ENTIRE contents with entries.
func (s *Store) RestoreAll(entries map[string]Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make(map[string]Entry, len(entries))
	for k, v := range entries {
		cp[k] = v
	}
	s.data = cp

	if s.path != "" {
		if err := save(s.path, s.cloneLocked()); err != nil {
			log.Printf("[RELIABILITY:WARN] persist %s: %v", s.path, err)
		}
	}
}

// save atomically overwrites path with data.
func save(path string, data map[string]Entry) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, b, 0o640)
}

// atomicWriteFile writes data to path via a temp file + fsync + rename, so
// a crash mid-write can never leave a truncated/corrupt file in path's
// place.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
