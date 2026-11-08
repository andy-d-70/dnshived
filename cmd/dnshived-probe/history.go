// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"log/syslog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	historyDefaultFileMB  = 25
	historyDefaultFiles   = 4
	historyDefaultAgeDays = 7
	historyQueueSize      = 4096
	historyScanBudget     = 64 << 20
	historyMaxLimit       = 1000
	historyDefaultLimit   = 200
)

var historyDir = "/var/lib/dnshived-probe/history"

// HistoryConfig says what the probe host records of its own results. Absent
// or "none" records nothing, so an existing configuration is unchanged.
type HistoryConfig struct {
	DHCP       string `json:"dhcp,omitempty"` // none, all, failures
	DNS        string `json:"dns,omitempty"`  // none, all, failures
	Syslog     *bool  `json:"syslog,omitempty"`
	MaxFileMB  int    `json:"max_file_mb,omitempty"`
	MaxFiles   int    `json:"max_files,omitempty"`
	MaxAgeDays int    `json:"max_age_days,omitempty"`
}

func validHistoryMode(m string) bool {
	return m == "" || m == "none" || m == "all" || m == "failures"
}

func validateHistory(h HistoryConfig) error {
	if !validHistoryMode(h.DHCP) || !validHistoryMode(h.DNS) {
		return fmt.Errorf("history modes are none, all or failures")
	}
	if h.MaxFileMB < 0 || h.MaxFileMB > 1024 {
		return fmt.Errorf("max_file_mb must be 1 to 1024 (0 = default %d)", historyDefaultFileMB)
	}
	if h.MaxFiles < 0 || h.MaxFiles > 50 {
		return fmt.Errorf("max_files must be 1 to 50 (0 = default %d)", historyDefaultFiles)
	}
	if h.MaxAgeDays < 0 || h.MaxAgeDays > 365 {
		return fmt.Errorf("max_age_days must be 1 to 365 (0 = default %d)", historyDefaultAgeDays)
	}
	return nil
}

// mode is the recording mode for a leg: DHCP also covers manual probes.
func (h HistoryConfig) mode(leg string) string {
	m := h.DHCP
	if leg == "dns" {
		m = h.DNS
	}
	if m == "" {
		return "none"
	}
	return m
}

func (h HistoryConfig) enabled() bool { return h.mode("dhcp") != "none" || h.mode("dns") != "none" }

func (h HistoryConfig) syslogOn() bool { return h.Syslog == nil || *h.Syslog }

func (h HistoryConfig) limits() (maxBytes int64, files int, age time.Duration) {
	mb, files, days := h.MaxFileMB, h.MaxFiles, h.MaxAgeDays
	if mb <= 0 {
		mb = historyDefaultFileMB
	}
	if files <= 0 {
		files = historyDefaultFiles
	}
	if days <= 0 {
		days = historyDefaultAgeDays
	}
	return int64(mb) << 20, files, time.Duration(days) * 24 * time.Hour
}

// HistoryCheck is one DNS check inside a DNS history record.
type HistoryCheck struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Against   string `json:"against"`
	Answered  bool   `json:"answered"`
	Valid     bool   `json:"valid"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	Error     string `json:"error,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// HistoryRecord is one probe result as it was produced.
type HistoryRecord struct {
	Time         time.Time      `json:"ts"`
	Scope        string         `json:"scope"`
	Leg          string         `json:"leg"` // dhcp, dns, watch
	Interface    string         `json:"interface,omitempty"`
	VLANID       int            `json:"vlan_id,omitempty"`
	Outcome      string         `json:"outcome"` // ok, failed, recovered
	Verdict      string         `json:"verdict,omitempty"`
	Reason       string         `json:"reason,omitempty"`
	Error        string         `json:"error,omitempty"`
	Servers      []string       `json:"servers,omitempty"`
	Unexpected   []string       `json:"unexpected,omitempty"`
	OfferMS      int64          `json:"offer_ms,omitempty"`
	Checks       []HistoryCheck `json:"checks,omitempty"`
	Flags        []string       `json:"flags,omitempty"`
	FailingForMS int64          `json:"failing_for_ms,omitempty"`
}

// historyRecorder queues records and writes them from one goroutine, so a slow
// disk never slows probing: a full queue drops its oldest entry and counts it.
type historyRecorder struct {
	dir     string
	cfg     atomic.Pointer[HistoryConfig]
	ch      chan HistoryRecord
	dropped atomic.Uint64
	sysFn   func(string)

	mu      sync.Mutex
	failing map[string]time.Time

	wg   sync.WaitGroup
	stop chan struct{}

	f        *os.File
	size     int64
	started  time.Time
	lastWarn time.Time
}

func newHistoryRecorder(dir string, sysFn func(string)) *historyRecorder {
	h := &historyRecorder{dir: dir, ch: make(chan HistoryRecord, historyQueueSize), sysFn: sysFn,
		failing: make(map[string]time.Time), stop: make(chan struct{})}
	h.cfg.Store(&HistoryConfig{})
	h.wg.Add(1)
	go h.run()
	return h
}

func (h *historyRecorder) SetConfig(c HistoryConfig) {
	if h != nil {
		h.cfg.Store(&c)
	}
}

func (h *historyRecorder) Config() HistoryConfig {
	if h == nil {
		return HistoryConfig{}
	}
	return *h.cfg.Load()
}

func (h *historyRecorder) Dropped() uint64 {
	if h == nil {
		return 0
	}
	return h.dropped.Load()
}

// Record decides, from the mode of the leg, whether a result is kept. A failing
// scope's first success is written as "recovered" with how long it failed.
func (h *historyRecorder) Record(rec HistoryRecord, failed bool) {
	if h == nil {
		return
	}
	mode := h.cfg.Load().mode(rec.Leg)
	if mode == "none" {
		return
	}
	key := rec.Leg + "|" + rec.Scope
	h.mu.Lock()
	first, wasFailing := h.failing[key]
	switch {
	case failed:
		if !wasFailing {
			h.failing[key] = rec.Time
		}
		rec.Outcome = "failed"
	case wasFailing:
		rec.Outcome = "recovered"
		rec.FailingForMS = rec.Time.Sub(first).Milliseconds()
		delete(h.failing, key)
	default:
		rec.Outcome = "ok"
	}
	h.mu.Unlock()
	if mode == "failures" && rec.Outcome == "ok" {
		return
	}
	select {
	case h.ch <- rec:
	default:
		select {
		case <-h.ch:
			h.dropped.Add(1)
		default:
		}
		select {
		case h.ch <- rec:
		default:
			h.dropped.Add(1)
		}
	}
}

func (h *historyRecorder) Close() {
	if h == nil {
		return
	}
	close(h.stop)
	h.wg.Wait()
}

func (h *historyRecorder) activePath() string { return filepath.Join(h.dir, "history.ndjson") }

func (h *historyRecorder) rotatedPath(n int) string {
	return filepath.Join(h.dir, "history."+strconv.Itoa(n)+".ndjson")
}

func (h *historyRecorder) run() {
	defer h.wg.Done()
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		select {
		case rec := <-h.ch:
			h.write(rec)
		case <-tick.C:
			h.sweep(time.Now())
		case <-h.stop:
			for {
				select {
				case rec := <-h.ch:
					h.write(rec)
				default:
					if h.f != nil {
						h.f.Close()
					}
					return
				}
			}
		}
	}
}

func (h *historyRecorder) warn(format string, args ...interface{}) {
	if time.Since(h.lastWarn) > time.Minute {
		h.lastWarn = time.Now()
		log.Printf("[PROBE:HISTORY] "+format, args...)
	}
}

func (h *historyRecorder) write(rec HistoryRecord) {
	cfg := h.cfg.Load()
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	if cfg.syslogOn() && h.sysFn != nil {
		h.sysFn(string(line))
	}
	maxBytes, files, _ := cfg.limits()
	if h.f != nil && h.size+int64(len(line))+1 > maxBytes {
		h.rotate(files)
	}
	if h.f == nil {
		if err := os.MkdirAll(h.dir, 0o700); err != nil {
			h.warn("create %s: %v", h.dir, err)
			return
		}
		f, err := os.OpenFile(h.activePath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			h.warn("open %s: %v", h.activePath(), err)
			return
		}
		st, _ := f.Stat()
		h.f, h.size, h.started = f, 0, rec.Time
		if st != nil {
			h.size = st.Size()
			if h.size > 0 {
				h.started = st.ModTime()
			}
		}
	}
	n, err := h.f.Write(append(line, '\n'))
	h.size += int64(n)
	if err != nil {
		h.warn("write: %v", err)
	}
}

// rotate shifts history.ndjson to history.1.ndjson and so on, dropping what
// would exceed files.
func (h *historyRecorder) rotate(files int) {
	if h.f != nil {
		h.f.Close()
		h.f = nil
	}
	os.Remove(h.rotatedPath(files - 1))
	for n := files - 2; n >= 1; n-- {
		os.Rename(h.rotatedPath(n), h.rotatedPath(n+1))
	}
	if files > 1 {
		os.Rename(h.activePath(), h.rotatedPath(1))
	} else {
		os.Remove(h.activePath())
	}
	h.size = 0
}

// sweep removes files older than the age cap and rotates an active file whose
// oldest record is older than it.
func (h *historyRecorder) sweep(now time.Time) {
	cfg := h.cfg.Load()
	_, files, age := cfg.limits()
	for n := 1; n < 100; n++ {
		st, err := os.Stat(h.rotatedPath(n))
		if err != nil {
			continue
		}
		if now.Sub(st.ModTime()) > age {
			os.Remove(h.rotatedPath(n))
		}
	}
	if h.f != nil && !h.started.IsZero() && now.Sub(h.started) > age {
		h.rotate(files)
	}
}

// historyFilesNewestFirst lists the existing files, newest first.
func historyFilesNewestFirst(dir string) []string {
	out := []string{}
	if _, err := os.Stat(filepath.Join(dir, "history.ndjson")); err == nil {
		out = append(out, filepath.Join(dir, "history.ndjson"))
	}
	var rotated []string
	ents, _ := os.ReadDir(dir)
	re := regexp.MustCompile(`^history\.(\d+)\.ndjson$`)
	for _, e := range ents {
		if re.MatchString(e.Name()) {
			rotated = append(rotated, e.Name())
		}
	}
	sort.Slice(rotated, func(i, j int) bool {
		a, _ := strconv.Atoi(re.FindStringSubmatch(rotated[i])[1])
		b, _ := strconv.Atoi(re.FindStringSubmatch(rotated[j])[1])
		return a < b
	})
	for _, r := range rotated {
		out = append(out, filepath.Join(dir, r))
	}
	return out
}

func historySizeBytes(dir string) int64 {
	var total int64
	for _, f := range historyFilesNewestFirst(dir) {
		if st, err := os.Stat(f); err == nil {
			total += st.Size()
		}
	}
	return total
}

type historyQuery struct {
	Scope        string
	Leg          string
	FailuresOnly bool
	Since, Until time.Time
	Limit        int
}

var historyScopeRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

// parseHistoryQuery validates the request's query values.
func parseHistoryQuery(v map[string][]string) (historyQuery, error) {
	get := func(k string) string {
		if x := v[k]; len(x) > 0 {
			return x[0]
		}
		return ""
	}
	q := historyQuery{Limit: historyDefaultLimit}
	if s := get("scope"); s != "" {
		if !historyScopeRE.MatchString(s) {
			return q, fmt.Errorf("scope is not a valid name")
		}
		q.Scope = s
	}
	switch l := get("leg"); l {
	case "", "dhcp", "dns", "watch":
		q.Leg = l
	default:
		return q, fmt.Errorf("leg is dhcp, dns or watch")
	}
	switch o := get("outcome"); o {
	case "", "all":
	case "failures":
		q.FailuresOnly = true
	default:
		return q, fmt.Errorf("outcome is all or failures")
	}
	for k, dst := range map[string]*time.Time{"since": &q.Since, "until": &q.Until} {
		if s := get(k); s != "" {
			t, err := time.Parse(time.RFC3339Nano, s)
			if err != nil {
				return q, fmt.Errorf("%s must be an RFC 3339 time", k)
			}
			*dst = t
		}
	}
	if s := get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			return q, fmt.Errorf("limit must be a positive number")
		}
		q.Limit = min(n, historyMaxLimit)
	}
	return q, nil
}

func (q historyQuery) match(r HistoryRecord) bool {
	if q.Scope != "" && r.Scope != q.Scope {
		return false
	}
	if q.Leg != "" && r.Leg != q.Leg {
		return false
	}
	if q.FailuresOnly && r.Outcome == "ok" {
		return false
	}
	if !q.Since.IsZero() && r.Time.Before(q.Since) {
		return false
	}
	if !q.Until.IsZero() && !r.Time.Before(q.Until) {
		return false
	}
	return true
}

// readHistory returns the newest matching records first. It reads at most
// historyScanBudget bytes; truncated says it stopped before the oldest file.
func readHistory(dir string, q historyQuery) (recs []HistoryRecord, truncated bool, err error) {
	var scanned int64
	for _, path := range historyFilesNewestFirst(dir) {
		f, oerr := os.Open(path)
		if oerr != nil {
			continue
		}
		var fileRecs []HistoryRecord
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			scanned += int64(len(sc.Bytes())) + 1
			var r HistoryRecord
			if json.Unmarshal(sc.Bytes(), &r) == nil && q.match(r) {
				fileRecs = append(fileRecs, r)
			}
		}
		f.Close()
		for i := len(fileRecs) - 1; i >= 0; i-- {
			recs = append(recs, fileRecs[i])
			if len(recs) >= q.Limit {
				return recs, false, nil
			}
		}
		if scanned >= historyScanBudget {
			return recs, true, nil
		}
	}
	return recs, false, nil
}

// historySyslogSink writes each record to the local syslog with its own tag so
// rsyslog can route it; without a syslog socket it falls back to the journal.
func historySyslogSink() func(string) {
	var once sync.Once
	var w *syslog.Writer
	return func(line string) {
		once.Do(func() {
			var err error
			w, err = syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "dnshived-probe-history")
			if err != nil {
				log.Printf("[PROBE:HISTORY] no syslog socket (%v): history lines go to the journal instead", err)
				w = nil
			}
		})
		if w != nil {
			_ = w.Info(line)
			return
		}
		log.Printf("[PROBE:HISTORY] %s", line)
	}
}

// histRec is the one recorder the runners and the API share; nil until main
// creates it, and every method is nil-safe.
var histRec *historyRecorder

func historyFailedDHCP(r ScopeProbeResult) bool {
	return r.DHCP.Error != "" || r.DHCP.Verdict != "ok" || !r.DHCP.Valid
}

func historyFailedDNS(r ScopeProbeResult) bool {
	for _, c := range r.DNSChecks {
		if c.Skipped == "" && (c.Error != "" || !c.Valid) {
			return true
		}
	}
	return r.DNS.Error != "" || (len(r.DNSChecks) == 0 && !r.DNS.Valid)
}

func recordScopeLeg(leg, name string, t scopeProbeTarget, res ScopeProbeResult, flags []string) {
	if histRec == nil || !res.Reachable || !res.Enabled {
		return
	}
	rec := HistoryRecord{Scope: name, Leg: leg, Interface: t.parent, VLANID: t.vlanID, Flags: flags}
	var failed bool
	switch leg {
	case "dhcp":
		rec.Time = res.DHCPProbedAt
		if rec.Time.IsZero() {
			rec.Time = res.ProbedAt
		}
		rec.Verdict, rec.Reason, rec.Error = res.DHCP.Verdict, res.DHCP.Reason, res.DHCP.Error
		rec.Servers, rec.OfferMS = res.DHCP.Servers, res.DHCP.OfferMS
		rec.Flags = append(rec.Flags, res.Flags...)
		failed = historyFailedDHCP(res)
	case "dns":
		rec.Time = res.DNSProbedAt
		if rec.Time.IsZero() {
			rec.Time = res.ProbedAt
		}
		rec.Reason, rec.Error = res.DNS.Reason, res.DNS.Error
		for _, c := range res.DNSChecks {
			if c.Skipped != "" {
				continue
			}
			rec.Checks = append(rec.Checks, HistoryCheck{Name: c.Name, Type: c.Type, Against: c.Against, Answered: c.Answered, Valid: c.Valid, LatencyMS: c.LatencyMS, Error: c.Error, Reason: c.Reason})
		}
		failed = historyFailedDNS(res)
	}
	if rec.Time.IsZero() {
		rec.Time = time.Now()
	}
	histRec.Record(rec, failed)
}

func recordWatch(res WatchResult) {
	if histRec == nil {
		return
	}
	rec := HistoryRecord{Time: res.ProbedAt, Scope: res.Name, Leg: "watch", Interface: res.Interface, VLANID: res.VLANID,
		Verdict: res.Verdict, Error: res.Error, Servers: res.Servers, Unexpected: res.Unexpected, OfferMS: res.OfferMS}
	if rec.Time.IsZero() {
		rec.Time = time.Now()
	}
	histRec.Record(rec, res.Verdict == "rogue" || res.Verdict == "error")
}
