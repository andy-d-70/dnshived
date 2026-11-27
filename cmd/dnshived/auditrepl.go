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
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"dnshived/internal/auditlog"
	"dnshived/internal/cluster"
	"dnshived/internal/config"
	"dnshived/internal/loglevel"
	"dnshived/internal/tlspin"
	"dnshived/internal/trustedhosts"
)

// The audit log is kept on every core as an append-only set and merged by union: each core pushes a new entry to
// its peers at once and every minute pulls whatever a peer holds that it does not.

const (
	auditTokenHeader  = "X-Audit-Token"
	auditPullEvery    = time.Minute
	auditPeerTimeout  = 30 * time.Second
	auditFetchBatch   = 200
	auditShardsPerAsk = 32
	auditMaxBody      = 16 << 20
	auditSizeWarn     = 64 << 20
	auditPushQueue    = 256
)

type auditWireEntry struct {
	ID   string `json:"id"`
	Body []byte `json:"body"`
}

type auditRepl struct {
	st     *auditlog.Store
	token  string
	scheme string
	client *http.Client
	self   string
	peers  func() []string
	addrOf func(role string) (string, bool)
	allow  func(*http.Request) bool
	queue  chan auditlog.StoredEntry
}

func auditIdentity(psk string) (key []byte, token string) {
	derive := func(label string) []byte {
		m := hmac.New(sha256.New, []byte(psk))
		m.Write([]byte(label))
		return m.Sum(nil)
	}
	return derive("dnshived-auditlog-key-v1"), hex.EncodeToString(derive("dnshived-auditlog-token-v1"))
}

// startAuditStore keeps the audit log in the replicated store on a core with a cluster key; other nodes keep only
// their local file, as before.
func startAuditStore(mux *http.ServeMux, logger *auditlog.Logger, observer *cluster.Observer, trusted []string) {
	cfg := currentConfig.Load()
	if cfg.PSK == "" || !isCoreRole(cfg.Role) {
		return
	}
	key, token := auditIdentity(cfg.PSK)
	dir := filepath.Join(dataDir(cfg), "auditstore")
	st, err := auditlog.Open(dir, auditlog.Options{Key: key})
	if err != nil {
		loglevel.Warnf("[AUDIT:ERROR] open %s: %v; the audit log stays in the local file only", dir, err)
		return
	}
	for _, n := range st.Notes() {
		loglevel.Warnf("[AUDIT:DAMAGE] %s; the entries are fetched again from the other cores", n)
	}
	added, skipped, err := auditlog.ImportFiles(logger, st, dir)
	if err != nil {
		loglevel.Warnf("[AUDIT:ERROR] import of the local audit files: %v (%d imported so far); retried at the next start", err, added)
	} else if added > 0 || skipped > 0 {
		loglevel.Infof("[AUDIT:IMPORT] %d entries taken from the local audit files, %d lines too long to store (kept in the files)", added, skipped)
	}
	a := newAuditRepl(st, token, cfg, observer, trusted)
	logger.Attach(st, a.enqueue)
	a.routes(mux)
	go a.pushLoop()
	go a.pullLoop()
	loglevel.Infof("[AUDIT:START] audit log store open: %d entries, %d bytes", st.Len(), st.Bytes())
}

func newAuditRepl(st *auditlog.Store, token string, cfg *config.Cluster, observer *cluster.Observer, trusted []string) *auditRepl {
	scheme := "http"
	tr := &http.Transport{MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext}
	if cfg.TLSEnabled() {
		scheme = "https"
		tr.TLSClientConfig = tlspin.Config()
	}
	allowed := trustedhosts.New(trusted)
	self := cfg.Role
	return &auditRepl{
		st:     st,
		token:  token,
		scheme: scheme,
		client: &http.Client{Timeout: auditPeerTimeout, Transport: tr},
		self:   self,
		peers: func() []string {
			var out []string
			for _, id := range dnsVoters(currentConfig.Load()) {
				if id != self {
					out = append(out, id)
				}
			}
			return out
		},
		addrOf: func(role string) (string, bool) {
			ok, addr := observer.RoleReachable(role)
			return addr, ok && addr != ""
		},
		allow: func(r *http.Request) bool { return allowed.Allowed(r.RemoteAddr) },
		queue: make(chan auditlog.StoredEntry, auditPushQueue),
	}
}

// enqueue hands a new entry to the push loop without blocking; a full queue drops it, the next pull fetches it.
func (a *auditRepl) enqueue(e auditlog.StoredEntry) {
	select {
	case a.queue <- e:
	default:
	}
}

func (a *auditRepl) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /internal/audit/hashes", a.guard(a.handleHashes))
	mux.HandleFunc("POST /internal/audit/ids", a.guard(a.handleIDs))
	mux.HandleFunc("POST /internal/audit/fetch", a.guard(a.handleFetch))
	mux.HandleFunc("POST /internal/audit/push", a.guard(a.handlePush))
}

func (a *auditRepl) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.allow(r) || subtle.ConstantTimeCompare([]byte(r.Header.Get(auditTokenHeader)), []byte(a.token)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, auditMaxBody)
		h(w, r)
	}
}

func (a *auditRepl) handleHashes(w http.ResponseWriter, _ *http.Request) {
	hs := a.st.Hashes()
	out := make([]string, len(hs))
	for i := range hs {
		out[i] = hex.EncodeToString(hs[i][:])
	}
	writeJSON(w, http.StatusOK, map[string]any{"hashes": out})
}

func (a *auditRepl) handleIDs(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Shards []int `json:"shards"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Shards) > auditShardsPerAsk {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	out := map[string][]string{}
	for _, sh := range req.Shards {
		if sh < 0 || sh > 255 {
			http.Error(w, "bad shard", http.StatusBadRequest)
			return
		}
		ids := a.st.IDs(byte(sh))
		list := make([]string, len(ids))
		for i, id := range ids {
			list[i] = hex.EncodeToString(id[:])
		}
		out[strconv.Itoa(sh)] = list
	}
	writeJSON(w, http.StatusOK, map[string]any{"ids": out})
}

func (a *auditRepl) handleFetch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.IDs) > auditFetchBatch {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	out := make([]auditWireEntry, 0, len(req.IDs))
	for _, s := range req.IDs {
		id, err := parseAuditID(s)
		if err != nil {
			http.Error(w, "bad id", http.StatusBadRequest)
			return
		}
		body, ok, err := a.st.Get(id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if ok {
			out = append(out, auditWireEntry{ID: s, Body: body})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": out})
}

func (a *auditRepl) handlePush(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Entries []auditWireEntry `json:"entries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Entries) > auditFetchBatch {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	entries, err := fromWire(req.Entries)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	n, err := a.st.Append(entries)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"added": n})
}

func parseAuditID(s string) (auditlog.ID, error) {
	var id auditlog.ID
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(id) {
		return id, fmt.Errorf("bad audit id %q", s)
	}
	copy(id[:], b)
	return id, nil
}

func fromWire(in []auditWireEntry) ([]auditlog.StoredEntry, error) {
	out := make([]auditlog.StoredEntry, 0, len(in))
	for _, e := range in {
		id, err := parseAuditID(e.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, auditlog.StoredEntry{ID: id, Body: e.Body})
	}
	return out, nil
}

func (a *auditRepl) pushLoop() {
	for e := range a.queue {
		body, _ := json.Marshal(map[string]any{"entries": []auditWireEntry{{ID: hex.EncodeToString(e.ID[:]), Body: e.Body}}})
		for _, role := range a.peers() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = a.call(ctx, role, http.MethodPost, "/internal/audit/push", body, nil)
			cancel()
		}
	}
}

func (a *auditRepl) pullLoop() {
	t := time.NewTimer(10 * time.Second)
	defer t.Stop()
	var warned time.Time
	for range t.C {
		for _, role := range a.peers() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*auditPeerTimeout)
			n, err := a.pullFrom(ctx, role)
			cancel()
			if err != nil {
				loglevel.Debugf("[AUDIT] pull from %s: %v", role, err)
			} else if n > 0 {
				loglevel.Infof("[AUDIT:SYNC] %d entries taken from %s", n, role)
			}
		}
		if b := a.st.Bytes(); b > auditSizeWarn && time.Since(warned) > 24*time.Hour {
			warned = time.Now()
			loglevel.Warnf("[AUDIT:SIZE] the audit log holds %d MB; nothing is removed until retention with verified backups exists", b>>20)
		}
		t.Reset(auditPullEvery)
	}
}

// pullFrom fetches every entry role holds that this core does not, and returns how many were new.
func (a *auditRepl) pullFrom(ctx context.Context, role string) (int, error) {
	var remote struct {
		Hashes []string `json:"hashes"`
	}
	if err := a.call(ctx, role, http.MethodGet, "/internal/audit/hashes", nil, &remote); err != nil {
		return 0, err
	}
	if len(remote.Hashes) != 256 {
		return 0, fmt.Errorf("%s sent %d shard hashes", role, len(remote.Hashes))
	}
	local := a.st.Hashes()
	var diff []int
	for i, h := range remote.Hashes {
		if h != hex.EncodeToString(local[i][:]) {
			diff = append(diff, i)
		}
	}
	var missing []string
	for len(diff) > 0 {
		ask := diff[:min(len(diff), auditShardsPerAsk)]
		diff = diff[len(ask):]
		body, _ := json.Marshal(map[string]any{"shards": ask})
		var ans struct {
			IDs map[string][]string `json:"ids"`
		}
		if err := a.call(ctx, role, http.MethodPost, "/internal/audit/ids", body, &ans); err != nil {
			return 0, err
		}
		for _, list := range ans.IDs {
			for _, s := range list {
				id, err := parseAuditID(s)
				if err != nil {
					return 0, err
				}
				if !a.st.Has(id) {
					missing = append(missing, s)
				}
			}
		}
	}
	added := 0
	for len(missing) > 0 {
		ask := missing[:min(len(missing), auditFetchBatch)]
		missing = missing[len(ask):]
		body, _ := json.Marshal(map[string]any{"ids": ask})
		var ans struct {
			Entries []auditWireEntry `json:"entries"`
		}
		if err := a.call(ctx, role, http.MethodPost, "/internal/audit/fetch", body, &ans); err != nil {
			return added, err
		}
		entries, err := fromWire(ans.Entries)
		if err != nil {
			return added, err
		}
		n, err := a.st.Append(entries)
		added += n
		if err != nil {
			return added, err
		}
	}
	return added, nil
}

func (a *auditRepl) call(ctx context.Context, role, method, path string, body []byte, out any) error {
	addr, ok := a.addrOf(role)
	if !ok {
		return fmt.Errorf("%s not reachable", role)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.scheme+"://"+addr+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set(auditTokenHeader, a.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s: status %d", role, path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, auditMaxBody)).Decode(out); err != nil {
		return fmt.Errorf("%s %s: %w", role, path, err)
	}
	return nil
}
