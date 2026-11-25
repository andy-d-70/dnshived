// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsservice

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"dnshived/internal/dnsanswer"
	"dnshived/internal/dnsdata"
	"dnshived/internal/dnsrepl"
	"dnshived/internal/dnsstore"
)

const (
	maxRequestBody = 64 << 20
	maxPage        = 500
)

type addrJSON struct {
	IP  string `json:"ip"`
	PTR bool   `json:"ptr,omitempty"`
}

type hostJSON struct {
	Label   string     `json:"label"`
	Domains []string   `json:"domains"`
	Addrs   []addrJSON `json:"addrs,omitempty"`
	TTL     uint32     `json:"ttl,omitempty"`
	OwnTTL  bool       `json:"own_ttl,omitempty"`
}

type recordJSON struct {
	Host    string `json:"host,omitempty"`
	Sub     string `json:"sub,omitempty"`
	Owner   string `json:"owner,omitempty"`
	Type    string `json:"type"`
	TTL     uint32 `json:"ttl,omitempty"`
	OwnTTL  bool   `json:"own_ttl,omitempty"`
	Value   string `json:"value,omitempty"`
	Target  string `json:"target,omitempty"`
	Pref    uint16 `json:"pref,omitempty"`
	Prio    uint16 `json:"priority,omitempty"`
	Weight  uint16 `json:"weight,omitempty"`
	Port    uint16 `json:"port,omitempty"`
	Order   uint16 `json:"order,omitempty"`
	Flags   string `json:"flags,omitempty"`
	Service string `json:"service,omitempty"`
	Regexp  string `json:"regexp,omitempty"`
	CAAFlag uint8  `json:"caa_flag,omitempty"`
	CAATag  string `json:"caa_tag,omitempty"`
	Raw     string `json:"raw,omitempty"`
}

type opJSON struct {
	Op     string      `json:"op"`
	Kind   string      `json:"kind"`
	ID     string      `json:"id,omitempty"`
	Host   *hostJSON   `json:"host,omitempty"`
	Record *recordJSON `json:"record,omitempty"`
}

type commitJSON struct {
	Author        string   `json:"author"`
	ConfigBaseRev uint64   `json:"config_base_rev,omitempty"`
	ImportID      string   `json:"import_id,omitempty"`
	ImportSeq     uint32   `json:"import_seq,omitempty"`
	DryRun        bool     `json:"dry_run,omitempty"`
	Ops           []opJSON `json:"ops"`
}

var typeCodes = map[string]uint16{
	"A": dnsanswer.TypeA, "AAAA": dnsanswer.TypeAAAA, "CNAME": dnsanswer.TypeCNAME, "TXT": dnsanswer.TypeTXT,
	"SRV": dnsanswer.TypeSRV, "PTR": dnsanswer.TypePTR, "MX": dnsanswer.TypeMX, "NAPTR": dnsanswer.TypeNAPTR,
	"CAA": dnsanswer.TypeCAA, "NS": dnsanswer.TypeNS, "RAW": dnsdata.TypeRAW,
}

func typeName(code uint16) string {
	for n, c := range typeCodes {
		if c == code {
			return n
		}
	}
	return "TYPE" + strconv.Itoa(int(code))
}

func parseType(s string) (uint16, bool) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if c, ok := typeCodes[s]; ok {
		return c, true
	}
	if n, err := strconv.Atoi(strings.TrimPrefix(s, "TYPE")); err == nil && n > 0 && n < 65536 {
		return uint16(n), true
	}
	return 0, false
}

func parseID(s string) (dnsstore.ID, error) {
	var id dnsstore.ID
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(id) {
		return id, fmt.Errorf("id %q must be 32 hex characters", s)
	}
	copy(id[:], b)
	return id, nil
}

func newID() (dnsstore.ID, error) {
	var id dnsstore.ID
	_, err := rand.Read(id[:])
	return id, err
}

func canonName(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	return dnsanswer.CanonicalName(s)
}

func nameTypes(code uint16) bool {
	switch code {
	case dnsanswer.TypeCNAME, dnsanswer.TypePTR, dnsanswer.TypeNS:
		return true
	}
	return false
}

func hostFromJSON(j *hostJSON) (dnsdata.Host, error) {
	label, err := dnsanswer.CanonicalName(j.Label)
	if err != nil {
		return dnsdata.Host{}, err
	}
	h := dnsdata.Host{Label: label, TTL: j.TTL, OwnTTL: j.OwnTTL}
	for _, d := range j.Domains {
		c, err := dnsanswer.CanonicalName(d)
		if err != nil {
			return h, err
		}
		h.Domains = append(h.Domains, c)
	}
	for _, a := range j.Addrs {
		ip, err := netip.ParseAddr(a.IP)
		if err != nil {
			return h, fmt.Errorf("address %q: %w", a.IP, err)
		}
		h.Addrs = append(h.Addrs, dnsdata.Addr{IP: ip.Unmap(), PTR: a.PTR})
	}
	return h, nil
}

func recordFromJSON(j *recordJSON) (dnsdata.Record, error) {
	code, ok := parseType(j.Type)
	if !ok {
		return dnsdata.Record{}, fmt.Errorf("unknown record type %q", j.Type)
	}
	r := dnsdata.Record{Type: code, TTL: j.TTL, OwnTTL: j.OwnTTL, Value: j.Value, Pref: j.Pref, Prio: j.Prio, Weight: j.Weight, Port: j.Port,
		Order: j.Order, Flags: j.Flags, Service: j.Service, Regexp: j.Regexp, CAAFlag: j.CAAFlag, CAATag: j.CAATag, Raw: strings.ToLower(j.Raw)}
	var err error
	if j.Host != "" {
		if r.Host, err = parseID(j.Host); err != nil {
			return r, err
		}
	}
	if r.Sub, err = canonName(j.Sub); err != nil {
		return r, err
	}
	if r.Owner, err = canonName(j.Owner); err != nil {
		return r, err
	}
	if r.Target, err = canonName(j.Target); err != nil {
		return r, err
	}
	if nameTypes(code) || code == dnsanswer.TypeNAPTR {
		if r.Value, err = canonName(j.Value); err != nil {
			return r, err
		}
	}
	return r, nil
}

func opsFromJSON(in []opJSON) ([]dnsstore.Op, []string, error) {
	ops := make([]dnsstore.Op, 0, len(in))
	var ids []string
	for i, o := range in {
		var typ uint8
		switch o.Kind {
		case "host":
			typ = dnsdata.TypeHost
		case "record":
			typ = dnsdata.TypeRecord
		default:
			return nil, nil, fmt.Errorf("operation %d: kind %q", i, o.Kind)
		}
		var id dnsstore.ID
		var err error
		if o.ID != "" {
			id, err = parseID(o.ID)
		} else if o.Op == "put" {
			id, err = newID()
		} else {
			err = errors.New("a delete needs an id")
		}
		if err != nil {
			return nil, nil, fmt.Errorf("operation %d: %w", i, err)
		}
		ids = append(ids, hex.EncodeToString(id[:]))
		op := dnsstore.Op{Type: typ, ID: id}
		switch o.Op {
		case "put":
			op.Kind = dnsstore.OpPut
			switch {
			case typ == dnsdata.TypeHost && o.Host != nil:
				h, err := hostFromJSON(o.Host)
				if err != nil {
					return nil, nil, fmt.Errorf("operation %d: %w", i, err)
				}
				op.Body = h.Encode()
			case typ == dnsdata.TypeRecord && o.Record != nil:
				r, err := recordFromJSON(o.Record)
				if err != nil {
					return nil, nil, fmt.Errorf("operation %d: %w", i, err)
				}
				op.Body = r.Encode()
			default:
				return nil, nil, fmt.Errorf("operation %d: a put needs its %s", i, o.Kind)
			}
		case "del":
			op.Kind = dnsstore.OpDel
		default:
			return nil, nil, fmt.Errorf("operation %d: op %q", i, o.Op)
		}
		ops = append(ops, op)
	}
	return ops, ids, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func plainError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	_, _ = fmt.Fprintln(w, msg)
}

func hex32(b [32]byte) string { return hex.EncodeToString(b[:]) }

type statusJSON struct {
	Rev       uint64         `json:"rev"`
	Term      uint64         `json:"term"`
	Chain     string         `json:"chain"`
	Manifest  string         `json:"manifest"`
	Rows      int            `json:"rows"`
	Tombs     int            `json:"tombstones"`
	StoreID   string         `json:"store_id"`
	Published *publishedJSON `json:"published,omitempty"`
	Commit    uint64         `json:"commit_index"`
	Auth      bool           `json:"authoritative"`
	TTL       uint32         `json:"default_ttl"`
	Serving   bool           `json:"serving"`
	Hosts     int            `json:"hosts"`
	Records   int            `json:"records"`
	Head      uint64         `json:"head"`
	Repl      any            `json:"replication,omitempty"`
}

type collisionJSON struct {
	Name   string `json:"name"`
	MAC    string `json:"mac"`
	Scope  string `json:"scope"`
	IP     string `json:"ip"`
	Holder string `json:"holder"`
}

type publishedJSON struct {
	Rev        uint64          `json:"rev"`
	Digest     string          `json:"digest"`
	Names      int             `json:"names"`
	Records    int             `json:"records"`
	BuiltAt    string          `json:"built_at"`
	Legacy     int             `json:"legacy_rows"`
	RowErrors  []string        `json:"row_errors,omitempty"`
	RowErrN    int             `json:"row_error_count,omitempty"`
	Dangling   []string        `json:"dangling,omitempty"`
	DanglingN  int             `json:"dangling_count,omitempty"`
	Collisions []collisionJSON `json:"collisions,omitempty"`
	Error      string          `json:"error,omitempty"`
}

func (s *Service) Status() statusJSON {
	v := s.store.View()
	id := s.store.ID()
	head, _, _ := s.store.Head()
	set := dnsdata.ReadSettings(v)
	out := statusJSON{Rev: v.Rev(), Term: v.Term(), Chain: hex32(v.Chain()), Manifest: hex32(v.Manifest()), Rows: v.Len(), Tombs: v.Tombstones(), StoreID: hex.EncodeToString(id[:]), Commit: s.store.CommitIndex(), Head: head, Auth: set.Authoritative, TTL: set.DefaultTTL, Serving: s.Serving(), Hosts: v.CountOf(dnsdata.TypeHost), Records: v.CountOf(dnsdata.TypeRecord)}
	if s.o.ReplStatus != nil {
		out.Repl = s.o.ReplStatus()
	}
	if b := s.state.Load(); b != nil {
		p := &publishedJSON{Rev: b.rev, Digest: hex32(b.digest), Names: b.names, Records: b.records, BuiltAt: b.builtAt.UTC().Format("2006-01-02T15:04:05Z"), Legacy: b.report.Legacy, Error: b.err, RowErrN: len(b.report.Errors), DanglingN: len(b.report.Dangling)}
		for i, e := range b.report.Errors {
			if i == 20 {
				break
			}
			p.RowErrors = append(p.RowErrors, e.Msg)
		}
		p.Dangling = b.report.Dangling[:min(len(b.report.Dangling), 20)]
		for i, c := range b.collisions {
			if i == 50 {
				break
			}
			p.Collisions = append(p.Collisions, collisionJSON{c.Name, c.MAC, c.Scope, c.IP.String(), c.Holder})
		}
		out.Published = p
	}
	return out
}

type hostItem struct {
	ID      string     `json:"id"`
	Rev     uint64     `json:"rev"`
	Label   string     `json:"label"`
	Domains []string   `json:"domains"`
	Addrs   []addrJSON `json:"addrs,omitempty"`
	TTL     uint32     `json:"ttl,omitempty"`
	OwnTTL  bool       `json:"own_ttl,omitempty"`
}

type recordItem struct {
	ID  string `json:"id"`
	Rev uint64 `json:"rev"`
	recordJSON
}

func page(r *http.Request) (q string, limit, offset int) {
	q = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 || limit > maxPage {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return
}

func (s *Service) listHosts(q string, limit, offset int) (int, []hostItem) {
	var all []hostItem
	s.store.View().Range(dnsdata.TypeHost, func(id dnsstore.ID, rev uint64, body []byte) bool {
		h, err := dnsdata.DecodeHost(body)
		if err != nil {
			return true
		}
		it := hostItem{ID: hex.EncodeToString(id[:]), Rev: rev, Label: h.Label, Domains: h.Domains, TTL: h.TTL, OwnTTL: h.OwnTTL}
		match := q == "" || strings.Contains(h.Label, q) || strings.Contains(it.ID, q)
		for _, d := range h.Domains {
			match = match || strings.Contains(d, q)
		}
		for _, a := range h.Addrs {
			it.Addrs = append(it.Addrs, addrJSON{IP: a.IP.String(), PTR: a.PTR})
			match = match || strings.Contains(a.IP.String(), q)
		}
		if match {
			all = append(all, it)
		}
		return true
	})
	sort.Slice(all, func(i, j int) bool {
		if all[i].Label != all[j].Label {
			return all[i].Label < all[j].Label
		}
		return all[i].ID < all[j].ID
	})
	return len(all), all[min(offset, len(all)):min(offset+limit, len(all))]
}

func (s *Service) listRecords(q string, limit, offset int) (int, []recordItem) {
	var all []recordItem
	s.store.View().Range(dnsdata.TypeRecord, func(id dnsstore.ID, rev uint64, body []byte) bool {
		r, err := dnsdata.DecodeRecord(body)
		if err != nil {
			return true
		}
		j := recordJSON{Sub: r.Sub, Owner: r.Owner, Type: typeName(r.Type), TTL: r.TTL, OwnTTL: r.OwnTTL, Value: r.Value, Target: r.Target, Pref: r.Pref,
			Prio: r.Prio, Weight: r.Weight, Port: r.Port, Order: r.Order, Flags: r.Flags, Service: r.Service, Regexp: r.Regexp, CAAFlag: r.CAAFlag, CAATag: r.CAATag, Raw: r.Raw}
		if r.Host != (dnsstore.ID{}) {
			j.Host = hex.EncodeToString(r.Host[:])
		}
		hay := strings.ToLower(strings.Join([]string{j.Owner, j.Sub, j.Type, j.Value, j.Target}, " "))
		if q == "" || strings.Contains(hay, q) {
			all = append(all, recordItem{ID: hex.EncodeToString(id[:]), Rev: rev, recordJSON: j})
		}
		return true
	})
	sort.Slice(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if a.Owner+a.Sub != b.Owner+b.Sub {
			return a.Owner+a.Sub < b.Owner+b.Sub
		}
		return a.ID < b.ID
	})
	return len(all), all[min(offset, len(all)):min(offset+limit, len(all))]
}

// Routes registers the admin API; admin wraps a handler with the daemon's admin authentication.
func (s *Service) Routes(mux *http.ServeMux, admin func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("GET /api/v1/dnsstore/status", admin(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.Status())
	}))
	mux.HandleFunc("GET /api/v1/dnsstore/hosts", admin(func(w http.ResponseWriter, r *http.Request) {
		q, limit, offset := page(r)
		total, items := s.listHosts(q, limit, offset)
		writeJSON(w, http.StatusOK, map[string]any{"total": total, "items": items})
	}))
	mux.HandleFunc("GET /api/v1/dnsstore/records", admin(func(w http.ResponseWriter, r *http.Request) {
		q, limit, offset := page(r)
		total, items := s.listRecords(q, limit, offset)
		writeJSON(w, http.StatusOK, map[string]any{"total": total, "items": items})
	}))
	mux.HandleFunc("POST /api/v1/dnsstore/commit", admin(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		var req commitJSON
		if err := dec.Decode(&req); err != nil {
			plainError(w, http.StatusBadRequest, "bad request: "+err.Error())
			return
		}
		ops, ids, err := opsFromJSON(req.Ops)
		if err != nil {
			plainError(w, http.StatusBadRequest, err.Error())
			return
		}
		cr := CommitRequest{Author: req.Author, Origin: OriginAPI, ConfigBaseRev: req.ConfigBaseRev, ImportSeq: req.ImportSeq, Ops: ops, DryRun: req.DryRun}
		if req.ImportID != "" {
			if cr.ImportID, err = parseID(req.ImportID); err != nil {
				plainError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		res, err := s.Commit(cr)
		if s.writeCommitError(w, err) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"rev": res.Rev, "ids": ids, "warnings": res.Warnings, "publish_error": res.PublishError, "dry_run": req.DryRun})
	}))
	mux.HandleFunc("POST /api/v1/dnsstore/settings", admin(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Authoritative *bool   `json:"authoritative"`
			DefaultTTL    *uint32 `json:"default_ttl"`
			Author        string  `json:"author"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil || (req.Authoritative == nil && req.DefaultTTL == nil) {
			plainError(w, http.StatusBadRequest, "send {\"authoritative\": true or false} and/or {\"default_ttl\": seconds}")
			return
		}
		if req.Authoritative != nil && *req.Authoritative && len(s.o.Input().Zones) == 0 {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"errors": []string{"no local domain is configured, so there is nothing to answer for"}})
			return
		}
		var ops []dnsstore.Op
		out := map[string]any{}
		if req.Authoritative != nil {
			ops = append(ops, dnsdata.SettingOp(dnsdata.AuthoritativeKey, *req.Authoritative))
			out["authoritative"] = *req.Authoritative
		}
		if req.DefaultTTL != nil {
			ops = append(ops, dnsdata.DefaultTTLOp(*req.DefaultTTL))
			out["default_ttl"] = *req.DefaultTTL
		}
		res, err := s.Commit(CommitRequest{Author: req.Author, Origin: OriginAPI, Ops: ops})
		if s.writeCommitError(w, err) {
			return
		}
		out["rev"] = res.Rev
		writeJSON(w, http.StatusOK, out)
	}))
	mux.HandleFunc("POST /api/v1/dnsstore/import", admin(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			DryRun bool   `json:"dry_run"`
			Author string `json:"author"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			plainError(w, http.StatusBadRequest, "bad request: "+err.Error())
			return
		}
		if s.o.ImportSource == nil {
			plainError(w, http.StatusNotImplemented, "this node cannot import")
			return
		}
		ops, rep := dnsdata.ImportOps(s.o.ImportSource())
		out := map[string]any{"records": rep.Records, "skipped": rep.Skipped, "dry_run": req.DryRun}
		if req.DryRun || len(ops) == 0 {
			writeJSON(w, http.StatusOK, out)
			return
		}
		importID, err := newID()
		if err != nil {
			plainError(w, http.StatusInternalServerError, err.Error())
			return
		}
		batches := 0
		for i := 0; i < len(ops); i += importBatch {
			end := min(i+importBatch, len(ops))
			res, err := s.Commit(CommitRequest{Author: req.Author, Origin: OriginImport, ImportID: importID, ImportSeq: uint32(batches + 1), Ops: ops[i:end]})
			if s.writeCommitError(w, err) {
				return
			}
			out["rev"] = res.Rev
			batches++
		}
		out["batches"] = batches
		writeJSON(w, http.StatusOK, out)
	}))
}

const importBatch = 2000

// writeCommitError answers a failed write and reports whether it did.
func (s *Service) writeCommitError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	var ge *GateError
	var nl *dnsrepl.NotLeaderError
	switch {
	case errors.As(err, &nl):
		addr := ""
		if s.o.LeaderAddr != nil && nl.Leader != "" {
			addr = s.o.LeaderAddr(nl.Leader)
		}
		w.Header().Set("X-Dns-Leader", addr)
		writeJSON(w, http.StatusConflict, map[string]any{"error": "not_leader", "leader": nl.Leader, "leader_addr": addr})
	case errors.Is(err, dnsrepl.ErrLost), errors.Is(err, dnsrepl.ErrUnknown):
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
	case errors.As(err, &ge):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"errors": ge.Errors, "warnings": ge.Warnings})
	default:
		plainError(w, http.StatusInternalServerError, err.Error())
	}
	return true
}
