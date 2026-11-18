// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package access

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// MaxReportItems bounds the table of sources, so a flood of spoofed addresses
// cannot grow memory. When it is full the least counted source goes first.
const MaxReportItems = 256

const maxReportFile = 1 << 20

type ReportItem struct {
	Src   string    `json:"src"`
	Svc   string    `json:"svc"`
	Count uint64    `json:"count"`
	Last  time.Time `json:"last"`
}

type Report struct {
	Enforcing bool         `json:"enforcing"`
	Updated   time.Time    `json:"updated"`
	Dropped   uint64       `json:"dropped"`
	Items     []ReportItem `json:"items,omitempty"`
}

type repKey struct {
	svc  Service
	addr netip.Addr
}

type repVal struct {
	n    uint64
	last time.Time
}

type Reporter struct {
	mu      sync.Mutex
	max     int
	items   map[repKey]*repVal
	dropped uint64
	dirty   bool
}

func NewReporter(max int) *Reporter {
	if max <= 0 || max > MaxReportItems {
		max = MaxReportItems
	}
	return &Reporter{max: max, items: make(map[repKey]*repVal)}
}

func (r *Reporter) Add(svc Service, addr netip.Addr, now time.Time) {
	if r == nil {
		return
	}
	k := repKey{svc: svc, addr: addr.Unmap()}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dropped++
	r.dirty = true
	if v, ok := r.items[k]; ok {
		v.n++
		v.last = now
		return
	}
	if len(r.items) >= r.max {
		var worst repKey
		var wv *repVal
		for kk, vv := range r.items {
			if wv == nil || vv.n < wv.n || (vv.n == wv.n && vv.last.Before(wv.last)) {
				worst, wv = kk, vv
			}
		}
		delete(r.items, worst)
	}
	r.items[k] = &repVal{n: 1, last: now}
}

func (r *Reporter) Snapshot(enforcing bool, now time.Time) Report {
	rep := Report{Enforcing: enforcing, Updated: now}
	if r == nil {
		return rep
	}
	r.mu.Lock()
	rep.Dropped = r.dropped
	for k, v := range r.items {
		rep.Items = append(rep.Items, ReportItem{Src: k.addr.String(), Svc: k.svc.String(), Count: v.n, Last: v.last})
	}
	r.mu.Unlock()
	sort.Slice(rep.Items, func(i, j int) bool {
		if rep.Items[i].Count != rep.Items[j].Count {
			return rep.Items[i].Count > rep.Items[j].Count
		}
		return rep.Items[i].Src < rep.Items[j].Src
	})
	return rep
}

func (r *Reporter) takeDirty() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := r.dirty
	r.dirty = false
	return d
}

func WriteReport(path string, rep Report) error {
	data, err := json.Marshal(rep)
	if err != nil {
		return fmt.Errorf("encode access report: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".access-report-*")
	if err != nil {
		return fmt.Errorf("write access report: %w", err)
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return fmt.Errorf("write access report: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		os.Remove(name)
		return fmt.Errorf("write access report: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return fmt.Errorf("write access report: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return fmt.Errorf("write access report: %w", err)
	}
	return nil
}

// ReadReport reads a report written by WriteReport. A missing file is an empty
// report; a file over 1 MiB is refused.
func ReadReport(path string) (Report, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Report{}, nil
		}
		return Report{}, fmt.Errorf("read access report: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxReportFile+1))
	if err != nil {
		return Report{}, fmt.Errorf("read access report: %w", err)
	}
	if len(data) > maxReportFile {
		return Report{}, fmt.Errorf("access report %s is larger than %d bytes", path, maxReportFile)
	}
	var rep Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return Report{}, fmt.Errorf("read access report: %w", err)
	}
	if len(rep.Items) > MaxReportItems {
		rep.Items = rep.Items[:MaxReportItems]
	}
	return rep, nil
}

// Run writes the table to path every interval while it changes, and once more
// when ctx ends. enforcing says which mode the writer runs in right now.
func (r *Reporter) Run(ctx context.Context, path string, every time.Duration, enforcing func() bool, logf func(format string, args ...any)) {
	t := time.NewTicker(every)
	defer t.Stop()
	flush := func(force bool) {
		if !r.takeDirty() && !force {
			return
		}
		if err := WriteReport(path, r.Snapshot(enforcing(), time.Now())); err != nil && logf != nil {
			logf("%v", err)
		}
	}
	flush(true)
	for {
		select {
		case <-ctx.Done():
			flush(true)
			return
		case <-t.C:
			flush(false)
		}
	}
}
