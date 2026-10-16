// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package eventlog provides a thread-safe ring buffer for cluster events.
package eventlog

import (
	"sync"
	"time"
)

// Event is a single log entry with structured metadata.
type Event struct {
	ID        int64     `json:"id"` // monotonically increasing, never resets
	Timestamp time.Time `json:"ts"`
	Level     string    `json:"level"`  // DEBUG, INFO, WARNING, ERROR, CRITICAL
	Prefix    string    `json:"prefix"` // e.g. "AGENT:START", "FSM:TRANSITION"
	Message   string    `json:"message"`
	NodeID    string    `json:"node_id"`
}

// Ring is a fixed-size circular buffer of events.
type Ring struct {
	mu     sync.RWMutex
	events []Event
	size   int
	head   int // next write position
	count  int // number of events written (may exceed size)
	nodeID string
}

// New creates a ring buffer with the given capacity.
func New(size int, nodeID string) *Ring {
	return &Ring{
		events: make([]Event, size),
		size:   size,
		nodeID: nodeID,
	}
}

// Add inserts an event into the ring buffer.
func (r *Ring) Add(level, prefix, message string) {
	r.mu.Lock()
	r.count++
	r.events[r.head] = Event{
		ID:        int64(r.count),
		Timestamp: time.Now().UTC(),
		Level:     level,
		Prefix:    prefix,
		Message:   message,
		NodeID:    r.nodeID,
	}
	r.head = (r.head + 1) % r.size
	r.mu.Unlock()
}

// Since returns all events with timestamps after the given time.
func (r *Ring) Since(after time.Time) []Event {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []Event
	n := r.size
	if r.count < r.size {
		n = r.count
	}

	// Walk the buffer in order from oldest to newest.
	start := r.head - n
	if start < 0 {
		start += r.size
	}
	for i := 0; i < n; i++ {
		idx := (start + i) % r.size
		e := r.events[idx]
		if e.Timestamp.After(after) {
			result = append(result, e)
		}
	}
	return result
}

// Last returns the most recent n events (newest last).
func (r *Ring) Last(n int) []Event {
	r.mu.RLock()
	defer r.mu.RUnlock()

	total := r.size
	if r.count < r.size {
		total = r.count
	}
	if n > total {
		n = total
	}

	result := make([]Event, n)
	start := r.head - n
	if start < 0 {
		start += r.size
	}
	for i := 0; i < n; i++ {
		result[i] = r.events[(start+i)%r.size]
	}
	return result
}

// Count returns the total number of events ever written.
func (r *Ring) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.count
}

// SinceID returns all events with IDs greater than afterID.
func (r *Ring) SinceID(afterID int64) []Event {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []Event
	n := r.size
	if r.count < r.size {
		n = r.count
	}

	start := r.head - n
	if start < 0 {
		start += r.size
	}
	for i := 0; i < n; i++ {
		idx := (start + i) % r.size
		e := r.events[idx]
		if e.ID > afterID {
			result = append(result, e)
		}
	}
	return result
}
