// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package timehealth provides health checks for system clock
// synchronisation.
package timehealth

import (
	"log"
	"sync"
	"syscall"
	"time"
)

// Status holds the time health state.
type Status struct {
	Synchronized bool
	Offset       time.Duration
	Available    bool // false if the kernel clock state could not be read
}

var (
	mu         sync.RWMutex
	lastCheck  time.Time
	cached     Status
	warnedOnce bool
)

// Check returns the current time health status, using a 30-second cache.
func Check() Status {
	mu.RLock()
	if time.Since(lastCheck) < 30*time.Second {
		defer mu.RUnlock()
		return cached
	}
	mu.RUnlock()
	mu.Lock()
	defer mu.Unlock()
	// Double-check under write lock.
	if time.Since(lastCheck) < 30*time.Second {
		return cached
	}
	cached = doCheck()
	lastCheck = time.Now()
	return cached
}

// maxErrorSyncedUsec mirrors systemd-timedated (what `timedatectl`
// reports as "System clock synchronized"): synchronized while the
// kernel's maximum error is below 16 s.
const maxErrorSyncedUsec = 16000000

const (
	staNano = 0x2000
)

var adjtimex = func(t *syscall.Timex) error {
	_, err := syscall.Adjtimex(t)
	return err
}

// doCheck reads the kernel clock state (adjtimex with no modes set:
// read-only, unprivileged), which every NTP client (chrony,
// systemd-timesyncd, ntpd) keeps up to date.
func doCheck() Status {
	var tx syscall.Timex
	if err := adjtimex(&tx); err != nil {
		if !warnedOnce {
			log.Printf("[timehealth] adjtimex failed (%v) — time health check unavailable, assuming healthy", err)
			warnedOnce = true
		}
		return Status{Available: false, Synchronized: true}
	}
	return statusFromTimex(tx)
}

func statusFromTimex(tx syscall.Timex) Status {
	offset := time.Duration(tx.Offset) * time.Microsecond
	if tx.Status&staNano != 0 {
		offset = time.Duration(tx.Offset)
	}
	return Status{
		Available:    true,
		Synchronized: tx.Maxerror < maxErrorSyncedUsec,
		Offset:       offset,
	}
}

func IsHealthy(threshold time.Duration) bool {
	st := Check()
	if !st.Available {
		return true // can't check → don't block
	}
	return isHealthy(st, threshold)
}

func IsHealthyStrict(threshold time.Duration) bool {
	st := Check()
	if !st.Available {
		return false
	}
	return isHealthy(st, threshold)
}

func isHealthy(st Status, threshold time.Duration) bool {
	if !st.Synchronized {
		return false
	}
	if st.Offset > threshold || st.Offset < -threshold {
		return false
	}
	return true
}
