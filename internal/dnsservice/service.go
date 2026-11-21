// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsservice

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dnshived/internal/config"
	"dnshived/internal/dnsanswer"
	"dnshived/internal/dnsdata"
	"dnshived/internal/dnsstore"
	"dnshived/internal/dnsstore/vfs"
)

const (
	OriginForm      uint8 = 1
	OriginImport    uint8 = 2
	OriginAPI       uint8 = 3
	OriginRestore   uint8 = 4
	OriginMigration uint8 = 5

	refreshEvery   = 5 * time.Second
	proposeTimeout = 15 * time.Second
)

// CompileInput is what the cluster configuration contributes to the table and to the write gate.
type CompileInput struct {
	Zones      []dnsanswer.Zone
	Reserved   map[string]string
	DefaultTTL uint32
	NegTTL     uint32
	MaxNames   int
}

type Options struct {
	Dir       string
	TablePath string
	TableMode os.FileMode
	Keys      dnsstore.Keys
	FS        vfs.FS
	Input     func() CompileInput
	Leases    func() []dnsdata.LeaseName
	Log       func(format string, a ...any)
	Chown     func(path string) error

	// Store, when set, is an already open store that the caller keeps running; the service then does not close it.
	Store *dnsstore.Store
	// Propose replaces the local commit when the store is replicated: it returns once the batch is committed
	// cluster-wide. Gate checks then run against the newest records, not only the committed state.
	Propose func(ctx context.Context, b dnsstore.Batch) (uint64, error)
	// ReplStatus adds the replication state to the status answer; LeaderAddr turns a leader id into an API address.
	ReplStatus func() any
	LeaderAddr func(leader string) string
	// ImportSource lists the configuration's DNS records for the import endpoint.
	ImportSource func() []config.DNSRecord
	// OnSettings is called when the replicated settings change (and once at start); OnServing when this core's ability
	// to serve DNS changes. CheckDNSVIP vets a new DNS VIP against the cluster configuration.
	OnSettings  func(dnsdata.Settings)
	OnServing   func(ok bool)
	CheckDNSVIP func(vip string, vrrpID int) error
}

type buildState struct {
	rev        uint64
	digest     [32]byte
	names      int
	records    int
	report     dnsdata.Report
	collisions []dnsdata.Collision
	builtAt    time.Time
	fp         [32]byte
	err        string
}

type Service struct {
	o       Options
	store   *dnsstore.Store
	mu      sync.Mutex
	buildMu sync.Mutex
	state   atomic.Pointer[buildState]
	seen    map[string]bool
	stop    chan struct{}
	wg      sync.WaitGroup
	kick    chan struct{}
	owned   bool

	closeOnce sync.Once

	serving atomic.Int32
	lastSet atomic.Pointer[dnsdata.Settings]
}

func New(o Options) (*Service, error) {
	if o.TableMode == 0 {
		o.TableMode = 0o640
	}
	if o.Log == nil {
		o.Log = func(string, ...any) {}
	}
	if o.Leases == nil {
		o.Leases = func() []dnsdata.LeaseName { return nil }
	}
	st, owned := o.Store, false
	if st == nil {
		var err error
		if st, err = dnsstore.Open(o.Dir, dnsstore.Options{FS: o.FS, Keys: o.Keys, Create: true}); err != nil {
			return nil, fmt.Errorf("open DNS store: %w", err)
		}
		owned = true
	}
	s := &Service{o: o, store: st, owned: owned, seen: map[string]bool{}, stop: make(chan struct{}), kick: make(chan struct{}, 1)}
	if r := st.Recovery(); r.TruncatedBytes > 0 || r.DroppedSegment != "" || len(r.SkippedSnapshots) > 0 {
		o.Log("[DNSSTORE:RECOVERED] truncated=%d dropped=%q skipped_snapshots=%v", r.TruncatedBytes, r.DroppedSegment, r.SkippedSnapshots)
	}
	if err := s.Rebuild(true); err != nil {
		o.Log("[DNSSTORE:ERROR] first build: %v", err)
	}
	s.wg.Add(1)
	go s.refreshLoop()
	return s, nil
}

func (s *Service) Close() error {
	s.closeOnce.Do(func() { close(s.stop) })
	s.wg.Wait()
	if !s.owned {
		return nil
	}
	return s.store.Close()
}

// Authoritative reports whether the cutover has happened: the table then answers for the whole of its domains.
func (s *Service) Authoritative() bool { return dnsdata.ReadSettings(s.store.View()).Authoritative }

// Kick asks for a rebuild soon, for when the committed state changed underneath the service.
func (s *Service) Kick() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

func (s *Service) Store() *dnsstore.Store { return s.store }

func (s *Service) refreshLoop() {
	defer s.wg.Done()
	t := time.NewTicker(refreshEvery)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
		case <-s.kick:
		}
		if err := s.Rebuild(false); err != nil {
			s.o.Log("[DNSSTORE:ERROR] refresh: %v", err)
		}
	}
}

func fingerprint(rev uint64, in CompileInput, leases []dnsdata.LeaseName) [32]byte {
	h := sha256.New()
	fmt.Fprintf(h, "%d|%d|%d|%d|", rev, in.DefaultTTL, in.NegTTL, in.MaxNames)
	for _, z := range in.Zones {
		fmt.Fprintf(h, "z:%s:%v|", z.Name, z.Forward)
	}
	for _, l := range leases {
		fmt.Fprintf(h, "l:%s:%s:%s:%d|", l.Name, l.IP, l.MAC, l.LeasedAt)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// Rebuild compiles the table from the store, the configuration and the lease names, and publishes it when it changed.
func (s *Service) Rebuild(force bool) error {
	s.buildMu.Lock()
	defer s.buildMu.Unlock()
	view := s.store.View()
	in := s.o.Input()
	leases := s.o.Leases()
	sort.Slice(leases, func(i, j int) bool {
		if leases[i].Name != leases[j].Name {
			return leases[i].Name < leases[j].Name
		}
		return leases[i].MAC+leases[i].IP.String() < leases[j].MAC+leases[j].IP.String()
	})
	fp := fingerprint(view.Rev(), in, leases)
	old := s.state.Load()
	if !force && old != nil && old.fp == fp && old.err == "" {
		return nil
	}
	spec, rep := dnsdata.Compile(view, dnsdata.CompileConfig{Zones: in.Zones, DefaultTTL: in.DefaultTTL, NegTTL: in.NegTTL, Authoritative: dnsdata.ReadSettings(view).Authoritative})
	cols := dnsdata.MergeLeases(spec, leases, in.DefaultTTL)
	tb, err := spec.Build()
	if err != nil {
		s.fail(old, fp, view.Rev(), err)
		return err
	}
	st := &buildState{rev: view.Rev(), digest: tb.Digest(), names: tb.Names(), records: tb.Records(), report: rep, collisions: cols, builtAt: time.Now(), fp: fp}
	if old == nil || old.digest != st.digest || force {
		if err := writeFileAtomic(s.o.TablePath, dnsanswer.EncodeTable(spec, tb.Digest()), s.o.TableMode); err != nil {
			s.fail(old, fp, view.Rev(), err)
			return err
		}
		if s.o.Chown != nil {
			if err := s.o.Chown(s.o.TablePath); err != nil {
				s.o.Log("[DNSSTORE:ERROR] chown %s: %v", s.o.TablePath, err)
			}
		}
	}
	s.state.Store(st)
	s.noteServing(true)
	s.noteSettings(dnsdata.ReadSettings(view))
	s.logCollisions(cols)
	if len(rep.Errors) > 0 {
		s.o.Log("[DNSSTORE:ROWS] %d row(s) skipped by the compile, first: %s", len(rep.Errors), rep.Errors[0].Msg)
	}
	return nil
}

// noteServing tells the daemon when this core starts or stops being able to serve DNS: a table was built and published.
func (s *Service) noteServing(ok bool) {
	v := int32(2)
	if ok {
		v = 1
	}
	if s.serving.Swap(v) != v && s.o.OnServing != nil {
		s.o.OnServing(ok)
	}
}

// Serving reports whether the last attempt to build and publish the table worked.
func (s *Service) Serving() bool { return s.serving.Load() == 1 }

func (s *Service) noteSettings(set dnsdata.Settings) {
	old := s.lastSet.Load()
	if old != nil && *old == set {
		return
	}
	s.lastSet.Store(&set)
	if s.o.OnSettings != nil {
		s.o.OnSettings(set)
	}
}

func (s *Service) fail(old *buildState, fp [32]byte, rev uint64, err error) {
	s.noteServing(false)
	n := &buildState{rev: rev, fp: fp, builtAt: time.Now(), err: err.Error()}
	if old != nil {
		c := *old
		c.err, c.fp = err.Error(), fp
		n = &c
	}
	s.state.Store(n)
}

func (s *Service) logCollisions(cols []dnsdata.Collision) {
	now := map[string]bool{}
	for _, c := range cols {
		k := c.Name + "|" + c.MAC + "|" + c.Holder
		now[k] = true
		if !s.seen[k] {
			s.o.Log("[DNSSTORE:COLLISION] %s is held by %s; the DHCP lease of %s (%s, %s) stays without its name", c.Name, c.Holder, c.MAC, c.IP, c.Scope)
		}
	}
	s.seen = now
}

type CommitRequest struct {
	Author        string
	Origin        uint8
	ConfigBaseRev uint64
	ImportID      dnsstore.ID
	ImportSeq     uint32
	Ops           []dnsstore.Op
	DryRun        bool
}

type CommitResult struct {
	Rev          uint64
	Warnings     []dnsdata.Warning
	PublishError string
}

type GateError struct {
	Errors   []string
	Warnings []dnsdata.Warning
}

func (e *GateError) Error() string { return "the change was refused: " + strings.Join(e.Errors, "; ") }

func (s *Service) gateContext() dnsdata.GateContext {
	in := s.o.Input()
	zones := map[string]bool{}
	for _, z := range in.Zones {
		if c, err := dnsanswer.CanonicalName(z.Name); err == nil {
			zones[c] = true
		}
	}
	holders := map[string]string{}
	for _, l := range s.o.Leases() {
		if _, ok := holders[l.Name]; !ok {
			holders[l.Name] = l.MAC
		}
	}
	return dnsdata.GateContext{
		Zones: zones, Reserved: in.Reserved, MaxNames: in.MaxNames,
		LeaseHolder: func(n string) (string, bool) { h, ok := holders[n]; return h, ok },
	}
}

// Commit validates a change with the write gate and commits it; it returns once the change is durable.
func (s *Service) Commit(req CommitRequest) (CommitResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	view := s.store.View()
	if s.o.Propose != nil {
		view = s.store.HeadView()
	}
	verdict := dnsdata.Validate(view, req.Ops, s.gateContext())
	if !verdict.OK() {
		return CommitResult{}, &GateError{Errors: verdict.Errors, Warnings: verdict.Warnings}
	}
	if req.DryRun {
		return CommitResult{Rev: s.store.View().Rev(), Warnings: verdict.Warnings}, nil
	}
	batch := dnsstore.Batch{
		Origin: req.Origin, Author: req.Author, TimeMs: time.Now().UnixMilli(),
		ConfigBaseRev: req.ConfigBaseRev, ImportID: req.ImportID, ImportSeq: req.ImportSeq, Ops: req.Ops,
	}
	var rev uint64
	var err error
	if s.o.Propose != nil {
		ctx, cancel := context.WithTimeout(context.Background(), proposeTimeout)
		defer cancel()
		rev, err = s.o.Propose(ctx, batch)
	} else {
		rev, err = s.store.Commit(batch)
	}
	if err != nil {
		return CommitResult{}, err
	}
	res := CommitResult{Rev: rev, Warnings: verdict.Warnings}
	if err := s.Rebuild(false); err != nil {
		res.PublishError = err.Error()
		s.o.Log("[DNSSTORE:ERROR] publish after commit %d: %v", rev, err)
	}
	return res, nil
}

var ErrDisabled = errors.New("dnsservice: the DNS store is not enabled")
