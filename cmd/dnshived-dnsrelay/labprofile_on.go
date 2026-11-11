// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

//go:build labprofile

// This file is a copy of internal/labprofile/lab.go (the relay is its own module).
// It is a development tool for lab hosts: root sends SIGWINCH
// and the process writes a CPU, heap and goroutine profile. It exists only in
// builds made with the labprofile tag (make lab-deb, make lab-rpm), does
// nothing unless a root-owned enable file exists, and must never ship.
package main

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
	labEnabled = true
	// labMarker is searched for by tools/release-guard.sh; it must appear in no
	// release binary.
	labMarker     = "DNSHIVED-LAB-PROFILE-BUILD"
	labEnableFile = "/etc/dnshived/lab-profile.enable"

	labDefaultSeconds = 30
	labMinSeconds     = 5
	labMaxSeconds     = 120
	labKeepFiles      = 12
)

var labBusy atomic.Bool

func labVersionSuffix() string { return " [LAB PROFILE BUILD]" }

// labStart installs the SIGWINCH handler. The enable file is checked at every
// trigger, so profiling can be switched on later without a restart. dir returns
// the state directory the profiles are written under.
func labStart(dir func() string) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	if secs, err := labGate(labEnableFile, true); err != nil {
		log.Printf("[LAB] PROFILE BUILD (%s): profiling is off until %s exists (%v); this build must never ship", labMarker, labEnableFile, err)
	} else {
		log.Printf("[LAB] PROFILE BUILD (%s): kill -WINCH writes a %d s CPU profile; this build must never ship", labMarker, secs)
	}
	go func() {
		for range ch {
			secs, err := labGate(labEnableFile, true)
			if err != nil {
				log.Printf("[LAB] profile refused: %v", err)
				continue
			}
			labCapture(dir(), secs)
		}
	}()
}

// labGate checks the enable file: a regular file (no symlink), owned by root when
// requireRoot, not writable by group or others. It returns the profile length
// in seconds from the file's first word (default 30, clamped to 5..120).
func labGate(path string, requireRoot bool) (int, error) {
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
	secs := labDefaultSeconds
	if w := strings.Fields(string(b)); len(w) > 0 {
		if n, err := strconv.Atoi(w[0]); err == nil {
			secs = n
		}
	}
	return min(max(secs, labMinSeconds), labMaxSeconds), nil
}

// labCapture records one profile set under base/lab-profile and returns a channel
// that closes when it is done (closed at once when one is already running).
func labCapture(base string, secs int) <-chan struct{} {
	done := make(chan struct{})
	if !labBusy.CompareAndSwap(false, true) {
		log.Printf("[LAB] a profile is already running")
		close(done)
		return done
	}
	go func() {
		defer close(done)
		defer labBusy.Store(false)
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
		labWriteProfile(dir, "heap-"+ts+".pprof", "heap", 0)
		labWriteProfile(dir, "goroutine-"+ts+".txt", "goroutine", 1)
		labPrune(dir, labKeepFiles)
		log.Printf("[LAB] profiles written to %s (%s: cpu %d s, heap, goroutine)", dir, ts, secs)
	}()
	return done
}

func labWriteProfile(dir, name, kind string, debug int) {
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

// labPrune keeps the newest keep files in dir.
func labPrune(dir string, keep int) {
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
