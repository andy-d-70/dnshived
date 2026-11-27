// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"dnshived/internal/agent"
	"dnshived/internal/auth"
	"dnshived/internal/cfgjournal"
	"dnshived/internal/cluster"
	"dnshived/internal/config"
	"dnshived/internal/desired"
	"dnshived/internal/dnsrepl"
	"dnshived/internal/dnsstore"
	"dnshived/internal/dnsstore/vfs"
	"dnshived/internal/loglevel"
	"dnshived/internal/tlspin"
	"dnshived/internal/trustedhosts"
)

const (
	cfgJournalEnableFile  = "/etc/dnshived/config-journal.enable"
	cfgJournalReplPrefix  = "/internal/cfgrepl"
	cfgJournalProposePath = "/internal/cfgjournal/propose"
	cfgJournalTokenHeader = "X-Cfgjournal-Token"
	cfgJournalDoc         = "cluster"
	maxProposeBody        = 64 << 20
	proposeWait           = 15 * time.Second
	leaderWait            = 3 * time.Second
)

var (
	errNoJournalLeader = errors.New("no core leads the configuration journal right now")
	cfgJournal         atomic.Pointer[cfgJournalRuntime]
)

// cfgJournalRuntime is the configuration change journal on this core: its store, its replication and the single
// writer that orders changes while this core leads.
type cfgJournalRuntime struct {
	path    string
	store   *dnsstore.Store
	node    *dnsrepl.Node
	writer  *cfgjournal.Writer
	doc     *cfgjournal.ConfigDoc
	dataDir string

	pendingWriter *cfgjournal.Writer
	pendingDoc    *cfgjournal.Document

	templatesWriter *cfgjournal.Writer
	templatesDoc    *cfgjournal.Document
	secretIdxWriter *cfgjournal.Writer
	secretIdxDoc    *cfgjournal.Document
	token           string
	scheme          string
	client          *http.Client
	addrOf          func(role string) (string, bool)
	kick            chan struct{}
	errMu           sync.Mutex
	lastErr         string

	ag      *agent.Agent
	engine  *desired.Engine
	authMw  *auth.Middleware
	liveRev uint64
	fileRev atomic.Uint64
	// seenRev is the journal revision the last successful sync covered; a sync with nothing newer is skipped, so an
	// idle core never reads its configuration files. Guarded by cfgWriteMu.
	seenRev uint64
	// docCache is the last answer per shared document and the journal head it was read at, set only right after a
	// successful sync. Guarded by cfgWriteMu.
	docCache map[string]cachedDoc
}

// cfgJournalStatus is the journal's part of /api/v1/status; nil while the journal is off. It reads only values kept
// in memory, so a status poll never touches the configuration files.
func cfgJournalStatus() map[string]any {
	j := cfgJournal.Load()
	if j == nil {
		return nil
	}
	j.errMu.Lock()
	lastErr := j.lastErr
	j.errMu.Unlock()
	return map[string]any{
		"role":         j.node.Role().String(),
		"leader":       j.node.Leader(),
		"term":         j.node.Term(),
		"journal_rev":  j.store.View().Rev(),
		"commit_index": j.store.CommitIndex(),
		"applied_rev":  j.fileRev.Load(),
		"last_error":   lastErr,
		"docs":         []string{secretIndexDoc, templatesDoc},
	}
}

func cfgJournalEnabled() bool {
	_, err := os.Stat(cfgJournalEnableFile)
	return err == nil
}

func cfgJournalIdentity(psk string) (keys dnsstore.Keys, id dnsstore.ID, token string) {
	derive := func(label string) []byte {
		m := hmac.New(sha256.New, []byte(psk))
		m.Write([]byte(label))
		return m.Sum(nil)
	}
	keys = dnsstore.StaticKeys{Cur: 1, Epochs: map[uint32][]byte{1: derive("dnshived-cfgjournal-key-v1")}}
	copy(id[:], derive("dnshived-cfgjournal-id-v1"))
	return keys, id, hex.EncodeToString(derive("dnshived-cfgrepl-token-v1"))
}

// startConfigJournal switches the configuration change journal on when its switch file exists: every change of the
// cluster-wide configuration is ordered by the core that leads the journal, replicated to every core and applied to
// each core's cluster.json. Without the file nothing changes.
func startConfigJournal(mux *http.ServeMux, cfgPath string, ag *agent.Agent, engine *desired.Engine, authMw *auth.Middleware, observer *cluster.Observer, trusted []string) {
	if !cfgJournalEnabled() {
		return
	}
	cfg := currentConfig.Load()
	if cfg.PSK == "" || !isCoreRole(cfg.Role) {
		loglevel.Warnf("[CFGJOURNAL:ERROR] the configuration journal needs a cluster key and a core role; it stays off")
		return
	}
	keys, storeID, token := cfgJournalIdentity(cfg.PSK)
	dir := filepath.Join(dataDir(cfg), "cfgjournal")
	st, err := dnsstore.Open(dir, dnsstore.Options{Keys: keys, Create: true, StoreID: storeID})
	if err != nil {
		loglevel.Warnf("[CFGJOURNAL:ERROR] open %s: %v", dir, err)
		return
	}
	ids := dnsVoters(cfg)
	var peers []string
	self := false
	for _, id := range ids {
		if id == cfg.Role {
			self = true
		} else {
			peers = append(peers, id)
		}
	}
	if !self {
		loglevel.Warnf("[CFGJOURNAL:ERROR] this node's role %q is not one of the cluster's voters %v; the journal stays off", cfg.Role, ids)
		_ = st.Close()
		return
	}
	node, err := dnsrepl.New(dnsrepl.Config{ID: cfg.Role, Peers: peers, Membership: dnsMembership(ids)}, st, vfs.OS{}, dir)
	if err != nil {
		loglevel.Warnf("[CFGJOURNAL:ERROR] replication: %v", err)
		_ = st.Close()
		return
	}
	scheme := "http"
	client := &http.Client{Timeout: proposeWait, Transport: &http.Transport{MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext}}
	if cfg.TLSEnabled() {
		scheme = "https"
		client.Transport.(*http.Transport).TLSClientConfig = tlspin.Config()
	}
	addrOf := func(role string) (string, bool) {
		if role == cfg.Role {
			return cfg.ListenAddr(), true
		}
		ok, addr := observer.RoleReachable(role)
		return addr, ok && addr != ""
	}
	j := &cfgJournalRuntime{path: cfgPath, dataDir: dataDir(cfg), store: st, node: node, token: token, scheme: scheme, client: client, addrOf: addrOf, kick: make(chan struct{}, 1), ag: ag, engine: engine, authMw: authMw}
	drv := j.build()
	allowed := trustedhosts.New(trusted)
	allow := func(r *http.Request) bool { return allowed.Allowed(r.RemoteAddr) }
	drv.RoutesAt(mux, cfgJournalReplPrefix, token, allow)
	mux.HandleFunc("POST "+cfgJournalProposePath, j.handlePropose(allow))
	cfgJournal.Store(j)
	drv.Start()
	go j.applyLoop()
	j.poke()
	loglevel.Infof("[CFGJOURNAL:START] configuration journal open at revision %d (voters %v)", st.View().Rev(), ids)
}

// build creates the replication driver and the writer; the runtime's store, node, path and transport fields are set.
func (j *cfgJournalRuntime) build() *dnsrepl.Driver {
	j.doc = &cfgjournal.ConfigDoc{Name: cfgJournalDoc, Path: j.path}
	drv := dnsrepl.NewDriver(j.node, &dnsrepl.HTTPTransport{Client: j.client, Scheme: j.scheme, Token: j.token, Addr: j.addrOf, Prefix: cfgJournalReplPrefix}, dnsrepl.DriverConfig{
		Permit:   func() bool { return true },
		OnCommit: j.poke,
		Log:      func(f string, a ...any) { loglevel.Infof("[CFGJOURNAL] "+f, a...) },
	})
	journal := cfgjournal.New(func(b dnsstore.Batch) (uint64, error) {
		ctx, cancel := context.WithTimeout(context.Background(), proposeWait)
		defer cancel()
		return drv.Propose(ctx, b)
	})
	j.writer = cfgjournal.NewWriter(journal, j.doc, j.store.View)
	j.pendingDoc = &cfgjournal.Document{FS: vfs.OS{}, Name: cfgjournal.PendingDoc, Path: filepath.Join(j.dataDir, "pending.json"), Mode: 0o600, Empty: cfgjournal.EmptyPending}
	j.pendingWriter = cfgjournal.NewWriter(journal, j.pendingDoc, j.store.View)
	j.templatesDoc = &cfgjournal.Document{FS: vfs.OS{}, Name: templatesDoc, Path: filepath.Join(j.dataDir, "templates.json"), Mode: 0o600, Empty: emptyTemplates}
	j.templatesWriter = cfgjournal.NewWriter(journal, j.templatesDoc, j.store.View)
	j.secretIdxDoc = &cfgjournal.Document{FS: vfs.OS{}, Name: secretIndexDoc, Path: filepath.Join(j.dataDir, "secret-index.json"), Mode: 0o600, Empty: emptySecretIndex}
	j.secretIdxWriter = cfgjournal.NewWriter(journal, j.secretIdxDoc, j.store.View)
	j.writer.Validate = func(tree any) error {
		c, err := j.doc.Candidate(tree)
		if err != nil {
			return err
		}
		if res := c.ValidateExtended(); !res.OK() {
			return fmt.Errorf("the configuration would not be valid: %v", res.Errors)
		}
		return nil
	}
	return drv
}

func (j *cfgJournalRuntime) poke() {
	select {
	case j.kick <- struct{}{}:
	default:
	}
}

func (j *cfgJournalRuntime) noteErr(err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	j.errMu.Lock()
	changed := msg != j.lastErr
	j.lastErr = msg
	j.errMu.Unlock()
	if changed && msg != "" {
		loglevel.Warnf("[CFGJOURNAL:ERROR] %s", msg)
	} else if changed {
		loglevel.Infof("[CFGJOURNAL] the configuration is in step with the journal again")
	}
}

// refreshLocked loads cluster.json into the running daemon when it holds a newer journal revision than the one the
// daemon runs on, whichever path applied it. The caller holds cfgWriteMu.
func (j *cfgJournalRuntime) refreshLocked() (uint64, error) {
	_, rev, _, err := j.doc.Load()
	if err != nil {
		return rev, err
	}
	j.fileRev.Store(rev)
	if rev <= j.liveRev {
		return rev, nil
	}
	cur, err := config.Load(j.path)
	if err != nil {
		return rev, err
	}
	currentConfig.Store(cur)
	applyLiveConfig(cur, false, j.ag, j.engine, j.authMw)
	j.liveRev = rev
	return rev, nil
}

// syncLocked applies committed changes to cluster.json and to the running daemon. The caller holds cfgWriteMu.
func (j *cfgJournalRuntime) syncLocked() (uint64, error) {
	head := j.store.View().Rev()
	if head == j.seenRev && j.seenRev != 0 {
		return j.fileRev.Load(), nil
	}
	_, _, err := j.writer.Sync()
	if err == nil {
		_, _, err = j.pendingWriter.Sync()
	}
	if err == nil {
		_, _, err = j.templatesWriter.Sync()
	}
	if err == nil {
		_, _, err = j.secretIdxWriter.Sync()
	}
	j.noteErr(err)
	if err != nil {
		return 0, err
	}
	rev, err := j.refreshLocked()
	if err == nil {
		j.seenRev = head
	}
	return rev, err
}

func (j *cfgJournalRuntime) applyLoop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-j.kick:
		case <-t.C:
		}
		cfgWriteMu.Lock()
		_, _ = j.syncLocked()
		cfgWriteMu.Unlock()
	}
}

type proposeRequest struct {
	Author  string             `json:"author"`
	Origin  uint8              `json:"origin"`
	TimeMs  int64              `json:"time_ms"`
	Entries []cfgjournal.Entry `json:"entries"`
}

type proposeAnswer struct {
	Rev   uint64 `json:"rev"`
	Noop  bool   `json:"noop"`
	Code  string `json:"code,omitempty"`
	Error string `json:"error,omitempty"`
	Path  string `json:"path,omitempty"`
}

// propose orders a change: on the leading core directly, otherwise through the leader. It returns once the change is
// committed and applied on this core too. The caller holds cfgWriteMu.
func (j *cfgJournalRuntime) writerFor(entries []cfgjournal.Entry) (*cfgjournal.Writer, cfgjournal.Target, error) {
	if len(entries) == 0 {
		return nil, nil, fmt.Errorf("%w: no entries", cfgjournal.ErrEntry)
	}
	switch entries[0].Doc {
	case cfgJournalDoc:
		return j.writer, j.doc, nil
	case cfgjournal.PendingDoc:
		return j.pendingWriter, j.pendingDoc, nil
	case templatesDoc, secretIndexDoc:
		w, d, err := j.sharedDoc(entries[0].Doc)
		return w, d, err
	}
	return nil, nil, fmt.Errorf("%w: unknown document %q", cfgjournal.ErrEntry, entries[0].Doc)
}

func (j *cfgJournalRuntime) sharedDoc(name string) (*cfgjournal.Writer, *cfgjournal.Document, error) {
	switch name {
	case templatesDoc:
		return j.templatesWriter, j.templatesDoc, nil
	case secretIndexDoc:
		return j.secretIdxWriter, j.secretIdxDoc, nil
	}
	return nil, nil, fmt.Errorf("%w: unknown shared document %q", cfgjournal.ErrEntry, name)
}

func (j *cfgJournalRuntime) propose(m cfgjournal.Meta, entries []cfgjournal.Entry) (cfgjournal.Result, error) {
	w, target, err := j.writerFor(entries)
	if err != nil {
		return cfgjournal.Result{}, err
	}
	var res cfgjournal.Result
	if j.node.Role() == dnsrepl.Leader {
		res, err = w.Propose(m, entries)
	} else {
		res, err = j.forward(m, entries)
	}
	if err != nil {
		return res, err
	}
	deadline := time.Now().Add(proposeWait)
	for {
		_, serr := j.syncLocked()
		rev := uint64(0)
		if serr == nil {
			_, rev, _, serr = target.Load()
		}
		if serr != nil {
			return res, fmt.Errorf("committed at revision %d but not applied here: %w", res.Rev, serr)
		}
		if rev >= res.Rev {
			return res, nil
		}
		if time.Now().After(deadline) {
			return res, fmt.Errorf("committed at revision %d, this core holds %d so far; it follows within seconds", res.Rev, rev)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (j *cfgJournalRuntime) forward(m cfgjournal.Meta, entries []cfgjournal.Entry) (cfgjournal.Result, error) {
	var leader, addr string
	for wait := time.Now().Add(leaderWait); ; {
		var ok bool
		leader = j.node.Leader()
		if addr, ok = j.addrOf(leader); leader != "" && ok {
			break
		}
		if time.Now().After(wait) {
			return cfgjournal.Result{}, errNoJournalLeader
		}
		time.Sleep(25 * time.Millisecond)
	}
	body, err := json.Marshal(proposeRequest{Author: m.Author, Origin: m.Origin, TimeMs: m.TimeMs, Entries: entries})
	if err != nil {
		return cfgjournal.Result{}, err
	}
	req, err := http.NewRequest(http.MethodPost, j.scheme+"://"+addr+cfgJournalProposePath, bytes.NewReader(body))
	if err != nil {
		return cfgjournal.Result{}, err
	}
	req.Header.Set(cfgJournalTokenHeader, j.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := j.client.Do(req)
	if err != nil {
		return cfgjournal.Result{}, fmt.Errorf("send the change to %s: %w", leader, err)
	}
	defer resp.Body.Close()
	var ans proposeAnswer
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ans); err != nil {
		return cfgjournal.Result{}, fmt.Errorf("answer of %s (%d): %w", leader, resp.StatusCode, err)
	}
	switch {
	case resp.StatusCode == http.StatusOK:
		return cfgjournal.Result{Rev: ans.Rev, Noop: ans.Noop}, nil
	case ans.Code == "conflict":
		return cfgjournal.Result{}, &cfgjournal.ConflictError{Path: ans.Path}
	}
	return cfgjournal.Result{}, fmt.Errorf("%s refused the change: %s", leader, ans.Error)
}

func (j *cfgJournalRuntime) handlePropose(allow func(*http.Request) bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !allow(r) || subtle.ConstantTimeCompare([]byte(r.Header.Get(cfgJournalTokenHeader)), []byte(j.token)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		var req proposeRequest
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProposeBody))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, proposeAnswer{Error: "bad request: " + err.Error()})
			return
		}
		if j.node.Role() != dnsrepl.Leader {
			writeJSON(w, http.StatusConflict, proposeAnswer{Code: "not_leader", Error: "this core does not lead the configuration journal"})
			return
		}
		wr, _, werr := j.writerFor(req.Entries)
		if werr != nil {
			writeJSON(w, http.StatusBadRequest, proposeAnswer{Error: werr.Error()})
			return
		}
		cfgWriteMu.Lock()
		res, err := wr.Propose(cfgjournal.Meta{Author: req.Author, Origin: req.Origin, TimeMs: req.TimeMs}, req.Entries)
		if err == nil {
			if _, rerr := j.refreshLocked(); rerr != nil {
				loglevel.Warnf("[CFGJOURNAL:ERROR] reload after revision %d: %v", res.Rev, rerr)
			}
		}
		cfgWriteMu.Unlock()
		if err != nil {
			writeJSON(w, proposeStatus(err), proposeError(err))
			return
		}
		writeJSON(w, http.StatusOK, proposeAnswer{Rev: res.Rev, Noop: res.Noop})
	}
}

func proposeStatus(err error) int {
	switch {
	case errors.Is(err, cfgjournal.ErrConflict):
		return http.StatusConflict
	case errors.Is(err, errNoJournalLeader):
		return http.StatusServiceUnavailable
	case errors.Is(err, cfgjournal.ErrEntry):
		return http.StatusBadRequest
	}
	return http.StatusUnprocessableEntity
}

func proposeError(err error) proposeAnswer {
	var ce *cfgjournal.ConflictError
	if errors.As(err, &ce) {
		return proposeAnswer{Code: "conflict", Path: ce.Path, Error: "someone else changed " + ce.Path + " in the meantime; reload and enter the change again"}
	}
	return proposeAnswer{Error: err.Error()}
}

// saveThroughJournal stores a change of the configuration from before to after: the cluster-wide part as one change
// set in the journal (ordered by the leading core, applied everywhere), this core's own fields locally. The caller
// holds cfgWriteMu.
func (j *cfgJournalRuntime) saveThroughJournal(before, after *config.Cluster, author string) error {
	lt, err := cfgjournal.Replicated(before)
	if err != nil {
		return err
	}
	at, err := cfgjournal.Replicated(after)
	if err != nil {
		return err
	}
	entries, err := cfgjournal.FromChange(cfgJournalDoc, lt, at, 0)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		if _, err := j.propose(cfgjournal.Meta{Author: author, Origin: 1, TimeMs: time.Now().UnixMilli()}, entries); err != nil {
			return err
		}
		if err := j.pruneCommittedLocked(); err != nil {
			loglevel.Warnf("[CFGJOURNAL:ERROR] committed, but the committed items are still listed as pending: %v", err)
		}
	}
	cur, err := config.Load(j.path)
	if err != nil {
		return err
	}
	next, err := cfgjournal.WithOwnFields(cur, after)
	if err != nil {
		return err
	}
	a, _ := json.Marshal(cur)
	b, _ := json.Marshal(next)
	if bytes.Equal(a, b) {
		return nil
	}
	return config.Save(j.path, next)
}
