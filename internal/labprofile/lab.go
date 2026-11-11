// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

//go:build labprofile

// Package labprofile is a development tool for lab hosts: root sends SIGWINCH
// and the process writes a CPU, heap and goroutine profile. It exists only in
// builds made with the labprofile tag (make lab-deb, make lab-rpm), does
// nothing unless a root-owned enable file exists, and must never ship.
package labprofile

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	Enabled = true
	// Marker is searched for by tools/release-guard.sh; it must appear in no
	// release binary.
	Marker     = "DNSHIVED-LAB-PROFILE-BUILD"
	EnableFile = "/etc/dnshived/lab-profile.enable"

	defaultSeconds = 30
	minSeconds     = 5
	maxSeconds     = 120
	keepFiles      = 12
)

var busy atomic.Bool

func VersionSuffix() string { return " [LAB PROFILE BUILD]" }

// Start installs the SIGWINCH handler. The enable file is checked at every
// trigger, so profiling can be switched on later without a restart. dir returns
// the state directory the profiles are written under.
func Start(dir func() string) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	if secs, err := gate(EnableFile, true); err != nil {
		log.Printf("[LAB] PROFILE BUILD (%s): profiling is off until %s exists (%v); this build must never ship", Marker, EnableFile, err)
	} else {
		log.Printf("[LAB] PROFILE BUILD (%s): kill -WINCH writes a %d s CPU profile; this build must never ship", Marker, secs)
	}
	go func() {
		for range ch {
			secs, err := gate(EnableFile, true)
			if err != nil {
				log.Printf("[LAB] profile refused: %v", err)
				continue
			}
			capture(dir(), secs)
		}
	}()
}

// gate checks the enable file: a regular file (no symlink), owned by root when
// requireRoot, not writable by group or others. It returns the profile length
// in seconds from the file's first word (default 30, clamped to 5..120).
func gate(path string, requireRoot bool) (int, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, fmt.Errorf("enable file %s missing", path)
	}
	if !fi.Mode().IsRegular() {
		return 0, fmt.Errorf("enable file %s is not a regular file", path)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && requireRoot && st.Uid != 0 {
		return 0, fmt.Errorf("enable file %s is not owned by root", path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return 0, fmt.Errorf("enable file %s is writable by group or others", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, 64))
	secs := defaultSeconds
	if w := strings.Fields(string(b)); len(w) > 0 {
		if n, err := strconv.Atoi(w[0]); err == nil {
			secs = n
		}
	}
	return min(max(secs, minSeconds), maxSeconds), nil
}

// capture records one profile set under base/lab-profile and returns a channel
// that closes when it is done (closed at once when one is already running).
func capture(base string, secs int) <-chan struct{} {
	done := make(chan struct{})
	if !busy.CompareAndSwap(false, true) {
		log.Printf("[LAB] a profile is already running")
		close(done)
		return done
	}
	go func() {
		defer close(done)
		defer busy.Store(false)
		dir := filepath.Join(base, "lab-profile")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			log.Printf("[LAB] cannot create %s: %v", dir, err)
			return
		}
		ts := time.Now().UTC().Format("20060102-150405")
		cpu, err := os.OpenFile(filepath.Join(dir, "cpu-"+ts+".pprof"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			log.Printf("[LAB] cannot create the CPU profile: %v", err)
			return
		}
		if err := pprof.StartCPUProfile(cpu); err != nil {
			cpu.Close()
			log.Printf("[LAB] cannot start the CPU profile: %v", err)
			return
		}
		time.Sleep(time.Duration(secs) * time.Second)
		pprof.StopCPUProfile()
		cpu.Close()
		runtime.GC()
		writeProfile(dir, "heap-"+ts+".pprof", "heap", 0)
		writeProfile(dir, "goroutine-"+ts+".txt", "goroutine", 1)
		prune(dir, keepFiles)
		log.Printf("[LAB] profiles written to %s (%s: cpu %d s, heap, goroutine)", dir, ts, secs)
	}()
	return done
}

func writeProfile(dir, name, kind string, debug int) {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		log.Printf("[LAB] cannot create %s: %v", name, err)
		return
	}
	defer f.Close()
	if p := pprof.Lookup(kind); p != nil {
		if err := p.WriteTo(f, debug); err != nil {
			log.Printf("[LAB] cannot write %s: %v", name, err)
		}
	}
}

// prune keeps the newest keep files in dir.
func prune(dir string, keep int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type file struct {
		name string
		mod  time.Time
	}
	var files []file
	for _, e := range entries {
		if info, err := e.Info(); err == nil && info.Mode().IsRegular() {
			files = append(files, file{e.Name(), info.ModTime()})
		}
	}
	if len(files) <= keep {
		return
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mod.After(files[j].mod) })
	for _, f := range files[keep:] {
		os.Remove(filepath.Join(dir, f.name))
	}
}
