// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"container/list"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ------------------------- Configuration -------------------------

type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(dur)
	return nil
}

func (d Duration) D() time.Duration { return time.Duration(d) }

type Config struct {
	ListenAddr        string   `json:"listen_addr"`
	Upstreams         []string `json:"upstreams"`
	AllowedInterfaces []string `json:"allowed_interfaces"`
	RateLimit         int      `json:"rate_limit"`
	RateBurst         int      `json:"rate_burst"`
	RateLimitScope    string   `json:"rate_limit_scope"` // "subnet" or "host"
	// InterfaceRateLimit/InterfaceRateBurst are a second, AGGREGATE ceiling
	// per interface, checked before RateLimit/RateBurst's own per-source
	// buckets.
	InterfaceRateLimit     int `json:"interface_rate_limit"`
	InterfaceRateBurst     int `json:"interface_rate_burst"`
	UpstreamSocketPoolSize int `json:"upstream_socket_pool_size"` // default 16
	CacheSize              int `json:"cache_size"`
	// CacheMaxBytes is an OPTIONAL second ceiling on top of CacheSize's own
	// entry count.
	CacheMaxBytes     int      `json:"cache_max_bytes,omitempty"`
	MaxOutstanding    int      `json:"max_outstanding"`
	MaxTCPConnections int      `json:"max_tcp_connections"`
	MaxTCPPerSource   int      `json:"max_tcp_per_source"`
	Timeout           Duration `json:"timeout"`
	TCPTimeout        Duration `json:"tcp_timeout"`
	MaxPacketSize     int      `json:"max_packet_size"`
	LogFile           string   `json:"log_file"`
	// AddrRefreshInterval controls how often each allowed interface's current
	// IPv4 address set is re-scanned.
	AddrRefreshInterval Duration `json:"addr_refresh_interval"`
	// InterfaceACLs holds an optional per-interface policy override, keyed by
	// interface name (must match an entry in AllowedInterfaces to have any
	// effect).
	InterfaceACLs map[string]ACLConfig `json:"interface_acls,omitempty"`
	// Rewrites holds the cluster-wide query/answer rewrite rules, applied to
	// every configured interface.
	Rewrites []RewriteRule `json:"rewrites,omitempty"`
}

// ACLConfig is one interface's policy override.
type ACLConfig struct {
	RateLimit *int `json:"rate_limit,omitempty"`
	RateBurst *int `json:"rate_burst,omitempty"`
	// InterfaceRateLimit/InterfaceRateBurst override the cluster-wide
	// aggregate ceiling (Config.InterfaceRateLimit/InterfaceRateBurst) for
	// this one interface.
	InterfaceRateLimit *int     `json:"interface_rate_limit,omitempty"`
	InterfaceRateBurst *int     `json:"interface_rate_burst,omitempty"`
	RateLimitScope     *string  `json:"rate_limit_scope,omitempty"`
	MaxTCPConnections  *int     `json:"max_tcp_connections,omitempty"`
	MaxTCPPerSource    *int     `json:"max_tcp_per_source,omitempty"`
	AllowedQTypes      []string `json:"allowed_qtypes,omitempty"`
	DeniedQTypes       []string `json:"denied_qtypes,omitempty"`
	AllowedDomains     []string `json:"allowed_domains,omitempty"`
	DeniedDomains      []string `json:"denied_domains,omitempty"`
	// Rewrites are this interface's OWN extra rewrite rules, checked BEFORE
	// the cluster-wide Config.Rewrites list (first match wins).
	Rewrites []RewriteRule `json:"rewrites,omitempty"`
}

type RewriteRule struct {
	Match string `json:"match"`
	// Answer synthesizes a static A record locally for Match, for EVERY qtype.
	Answer string `json:"answer,omitempty"`
	// TTL is the synthesized Answer record's TTL, seconds.
	TTL     uint32 `json:"ttl,omitempty"`
	Rewrite string `json:"rewrite,omitempty"`
}

// resolvedRewriteRule is one RewriteRule after load/reload-time validation
// and normalization.
type resolvedRewriteRule struct {
	exact    string // normalized (lowercase, no trailing dot) — used when !wildcard
	wildcard bool
	suffix   string

	answer net.IP // non-nil => Answer action; nil => Rewrite action
	ttl    uint32

	rewriteTo string
}

// matches reports whether qnameLower (already lowercased) is covered by
// this rule's Match.
func (r *resolvedRewriteRule) matches(qnameLower string) bool {
	if r.wildcard {
		return qnameLower == r.suffix || strings.HasSuffix(qnameLower, "."+r.suffix)
	}
	return qnameLower == r.exact
}

// target computes the actual upstream-facing name for a Rewrite action,
// given the specific qnameLower that matched this rule.
func (r *resolvedRewriteRule) target(qnameLower string) string {
	if !r.wildcard || qnameLower == r.suffix {
		return r.rewriteTo
	}
	prefix := qnameLower[:len(qnameLower)-len(r.suffix)-1] // strip the leading "."+suffix
	return prefix + "." + r.rewriteTo
}

// resolveRewriteRules validates and normalizes rules into their
// ready-to-enforce form.
func resolveRewriteRules(rules []RewriteRule) ([]resolvedRewriteRule, error) {
	out := make([]resolvedRewriteRule, 0, len(rules))
	for _, rule := range rules {
		if (rule.Answer == "") == (rule.Rewrite == "") {
			return nil, fmt.Errorf("rewrite rule %q: exactly one of answer/rewrite must be set", rule.Match)
		}
		matchLower := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rule.Match), "."))
		if matchLower == "" {
			return nil, fmt.Errorf("rewrite rule: empty match")
		}
		var resolved resolvedRewriteRule
		if strings.HasPrefix(matchLower, "*.") {
			resolved.wildcard = true
			resolved.suffix = matchLower[2:]
			if resolved.suffix == "" {
				return nil, fmt.Errorf("rewrite rule %q: wildcard match needs a base domain", rule.Match)
			}
		} else {
			resolved.exact = matchLower
		}
		if rule.Answer != "" {
			ip := net.ParseIP(rule.Answer).To4()
			if ip == nil {
				return nil, fmt.Errorf("rewrite rule %q: invalid answer IPv4 address %q", rule.Match, rule.Answer)
			}
			resolved.answer = ip
			resolved.ttl = rule.TTL
			if resolved.ttl == 0 {
				resolved.ttl = 60
			}
		} else {
			target := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rule.Rewrite), "."))
			if target == "" {
				return nil, fmt.Errorf("rewrite rule %q: empty rewrite target", rule.Match)
			}
			resolved.rewriteTo = target
		}
		out = append(out, resolved)
	}
	return out, nil
}

// ------------------------- Globals -------------------------

// logMu/lastLogTimes back logThrottled below.
var (
	logMu        sync.Mutex
	lastLogTimes = make(map[string]time.Time)
)

func logThrottled(category string, format string, v ...any) {
	logMu.Lock()
	defer logMu.Unlock()
	if time.Since(lastLogTimes[category]) > 5*time.Second {
		logger.Printf(format, v...)
		lastLogTimes[category] = time.Now()
	}
}

var (
	cfg Config

	// raw upstream addresses (used during init)
	upstreams []*net.UDPAddr

	// upstream pools (one per upstream address, each containing multiple
	// sockets)
	upstreamPools []*upstreamPool

	allowedIfaces atomic.Pointer[map[int]*ifaceInfo]

	// reconcileMu guards BOTH allowedIfaces (via reconfigureInterfaces) AND
	// openSockets (via reconcileAddrSockets) as one combined critical section.
	reconcileMu sync.Mutex

	// openSockets holds the one UDP+TCP socket PAIR actually bound to each
	// currently-live IPv4 address (keyed by ipToUint32) across every allowed
	// interface.
	openSockets map[uint32]*addrSocket

	// udpReaderWG tracks every currently-running udpReadLoopForSocket
	// goroutine.
	udpReaderWG sync.WaitGroup

	// jobs is the one shared UDP work queue every open address's own
	// udpReadLoopForSocket goroutine feeds, drained by the fixed-size
	// udpWorker pool started in main().
	jobs chan udpJob

	// rate limiter: fixed shards, keyed by first byte
	rateShards [256]*rateShard

	outstandingSem     chan struct{}
	outstandingQueries atomic.Int64

	logger *log.Logger

	// Metrics
	queriesTotal   atomic.Uint64
	forwardedTotal atomic.Uint64
	droppedTotal   atomic.Uint64
	aclDeniedTotal atomic.Uint64
	// rewriteAnsweredTotal counts queries answered locally by a RewriteRule's
	// Answer action (never forwarded).
	rewriteAnsweredTotal  atomic.Uint64
	rewriteForwardedTotal atomic.Uint64
	cacheHits             atomic.Uint64
	cacheMisses           atomic.Uint64
	// cacheBytesUsed is the live sum of len(entry.resp) across every shard's
	// own cache.
	cacheBytesUsed   atomic.Int64
	repliesSent      atomic.Uint64
	rateLimitedTotal atomic.Uint64
	upstreamErrors   atomic.Uint64
	tcpConnections   atomic.Int64

	// tcpConnPerIface tracks live TCP connection counts PER INTERFACE, keyed
	// by ifIndex.
	tcpConnPerIface sync.Map // map[int]*atomic.Int64

	// TCP per-source connection tracking
	tcpConnMu     sync.Mutex
	tcpConnPerSrc map[string]int

	// Context for graceful shutdown
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
)

type ifaceInfo struct {
	name string
	// subnet is derived from whichever IPv4 address buildIfaceInfo happened to
	// see first on this interface, and treated as static thereafter.
	subnet *net.IPNet
	// acl is this interface's fully-resolved policy.
	acl *resolvedACL
}

// addrSocket is one UDP+TCP socket PAIR bound to exactly one currently
// live IPv4 address.
type addrSocket struct {
	ip      net.IP
	ifIndex int
	udpConn *net.UDPConn
	tcpLn   *net.TCPListener
	// ifInfo is swapped (never mutated in place) by reconcileAddrSocketsLocked
	// whenever this address's own interface gets a fresh ACL/subnet from a
	// SIGHUP reload.
	ifInfo atomic.Pointer[ifaceInfo]
}

// resolvedACL is one interface's fully-merged, ready-to-enforce policy —
// cluster-wide defaults with any per-interface override already applied.
type resolvedACL struct {
	rateLimit          int
	rateBurst          int
	rateLimitScope     string
	interfaceRateLimit int
	interfaceRateBurst int
	maxTCPConnections  int
	maxTCPPerSource    int
	allowedQTypes      map[uint16]bool
	deniedQTypes       map[uint16]bool
	allowedDomains     []string
	deniedDomains      []string
	rewrites           []resolvedRewriteRule
}

// qtypeNames maps the ACLConfig-facing type names an operator writes in
// JSON to their real DNS TYPE values.
var qtypeNames = map[string]uint16{
	"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12,
	"MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "ANY": 255,
}

func parseQTypeNames(names []string) (map[uint16]bool, error) {
	set := make(map[uint16]bool, len(names))
	for _, n := range names {
		qtype, ok := qtypeNames[strings.ToUpper(strings.TrimSpace(n))]
		if !ok {
			return nil, fmt.Errorf("unknown query type %q", n)
		}
		set[qtype] = true
	}
	return set, nil
}

// normalizeDomains lowercases and strips any trailing dot from every
// entry, so domainListMatches never has to re-normalize per query.
func normalizeDomains(domains []string) []string {
	out := make([]string, len(domains))
	for i, d := range domains {
		out[i] = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
	}
	return out
}

// domainListMatches reports whether qnameLower (already lowercased)
// equals, or is a subdomain of, any entry in domains (already normalized
// by normalizeDomains).
func domainListMatches(domains []string, qnameLower string) bool {
	for _, d := range domains {
		if qnameLower == d || strings.HasSuffix(qnameLower, "."+d) {
			return true
		}
	}
	return false
}

// resolveACL merges the cluster-wide defaults (the top-level Config
// fields) with name's own InterfaceACLs override, if any, into a
// ready-to-enforce resolvedACL.
func resolveACL(name string) (*resolvedACL, error) {
	acl := &resolvedACL{
		rateLimit:          cfg.RateLimit,
		rateBurst:          cfg.RateBurst,
		rateLimitScope:     cfg.RateLimitScope,
		interfaceRateLimit: cfg.InterfaceRateLimit,
		interfaceRateBurst: cfg.InterfaceRateBurst,
		maxTCPConnections:  cfg.MaxTCPConnections,
		maxTCPPerSource:    cfg.MaxTCPPerSource,
	}
	globalRewrites, err := resolveRewriteRules(cfg.Rewrites)
	if err != nil {
		return nil, fmt.Errorf("cluster-wide rewrites: %w", err)
	}
	acl.rewrites = globalRewrites
	override, ok := cfg.InterfaceACLs[name]
	if !ok {
		return acl, nil
	}
	if override.RateLimit != nil {
		acl.rateLimit = *override.RateLimit
	}
	if override.RateBurst != nil {
		acl.rateBurst = *override.RateBurst
	}
	if override.InterfaceRateLimit != nil {
		acl.interfaceRateLimit = *override.InterfaceRateLimit
	}
	if override.InterfaceRateBurst != nil {
		acl.interfaceRateBurst = *override.InterfaceRateBurst
	}
	if override.RateLimitScope != nil {
		if *override.RateLimitScope != "subnet" && *override.RateLimitScope != "host" {
			return nil, fmt.Errorf("invalid rate_limit_scope override %q", *override.RateLimitScope)
		}
		acl.rateLimitScope = *override.RateLimitScope
	}
	if override.MaxTCPConnections != nil {
		acl.maxTCPConnections = *override.MaxTCPConnections
	}
	if override.MaxTCPPerSource != nil {
		acl.maxTCPPerSource = *override.MaxTCPPerSource
	}
	if len(override.AllowedQTypes) > 0 {
		set, err := parseQTypeNames(override.AllowedQTypes)
		if err != nil {
			return nil, fmt.Errorf("allowed_qtypes: %w", err)
		}
		acl.allowedQTypes = set
	}
	if len(override.DeniedQTypes) > 0 {
		set, err := parseQTypeNames(override.DeniedQTypes)
		if err != nil {
			return nil, fmt.Errorf("denied_qtypes: %w", err)
		}
		acl.deniedQTypes = set
	}
	if len(override.AllowedDomains) > 0 {
		acl.allowedDomains = normalizeDomains(override.AllowedDomains)
	}
	if len(override.DeniedDomains) > 0 {
		acl.deniedDomains = normalizeDomains(override.DeniedDomains)
	}
	if len(override.Rewrites) > 0 {
		ifaceRewrites, err := resolveRewriteRules(override.Rewrites)
		if err != nil {
			return nil, fmt.Errorf("interface %q rewrites: %w", name, err)
		}
		acl.rewrites = append(ifaceRewrites, acl.rewrites...)
	}
	return acl, nil
}

// aclDenies reports whether acl's query-type/domain policy blocks this
// specific query.
func aclDenies(acl *resolvedACL, qname string, qtype uint16) bool {
	if acl == nil {
		return false
	}
	if acl.deniedQTypes != nil && acl.deniedQTypes[qtype] {
		return true
	}
	if acl.allowedQTypes != nil && !acl.allowedQTypes[qtype] {
		return true
	}
	qnameLower := strings.ToLower(qname)
	if acl.deniedDomains != nil && domainListMatches(acl.deniedDomains, qnameLower) {
		return true
	}
	if acl.allowedDomains != nil && !domainListMatches(acl.allowedDomains, qnameLower) {
		return true
	}
	return false
}

// ------------------------- Rate Limiter -------------------------

type tokenBucket struct {
	tokens float64
	last   time.Time
}

func (tb *tokenBucket) allow(rate, burst int) bool {
	now := time.Now()
	elapsed := now.Sub(tb.last).Seconds()
	tb.last = now
	tb.tokens += elapsed * float64(rate)
	if tb.tokens > float64(burst) {
		tb.tokens = float64(burst)
	}
	if tb.tokens >= 1.0 {
		tb.tokens--
		return true
	}
	return false
}

type rateShard struct {
	mu      sync.Mutex
	buckets map[[4]byte]*tokenBucket
	order   [][4]byte // FIFO queue of keys for eviction
}

func newRateShard() *rateShard {
	return &rateShard{
		buckets: make(map[[4]byte]*tokenBucket),
	}
}

func keyForScope(ip net.IP, scope string) [4]byte {
	v4 := ip.To4()
	var key [4]byte
	copy(key[:], v4)
	if scope == "subnet" {
		key[3] = 0
	}
	return key
}

func (rs *rateShard) allow(ip net.IP, rate, burst int, scope string) bool {
	key := keyForScope(ip, scope)
	rs.mu.Lock()
	defer rs.mu.Unlock()

	bucket, ok := rs.buckets[key]
	if !ok {
		bucket = &tokenBucket{tokens: float64(burst), last: time.Now()}
		rs.buckets[key] = bucket
		rs.order = append(rs.order, key)
		const maxBucketsPerShard = 1000
		if len(rs.order) > maxBucketsPerShard {
			oldestKey := rs.order[0]
			rs.order = rs.order[1:]
			delete(rs.buckets, oldestKey)
		}
	}
	return bucket.allow(rate, burst)
}

// isAllowed applies THIS query's own interface's rate limit.
func isAllowed(ip net.IP, rateLimit, rateBurst int, rateLimitScope string) bool {
	if ip.To4() == nil {
		return false
	}
	shardIdx := ip.To4()[0]
	return rateShards[shardIdx].allow(ip, rateLimit, rateBurst, rateLimitScope)
}

type ifaceLimiter struct {
	mu     sync.Mutex
	bucket *tokenBucket
}

var ifaceLimiters sync.Map // map[int]*ifaceLimiter

func ifaceAllowed(ifIndex, rate, burst int) bool {
	if rate <= 0 {
		return true
	}
	v, _ := ifaceLimiters.LoadOrStore(ifIndex, &ifaceLimiter{bucket: &tokenBucket{tokens: float64(burst), last: time.Now()}})
	l := v.(*ifaceLimiter)
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.bucket.allow(rate, burst)
}

func tcpConnCounterFor(ifIndex int) *atomic.Int64 {
	if v, ok := tcpConnPerIface.Load(ifIndex); ok {
		return v.(*atomic.Int64)
	}
	v, _ := tcpConnPerIface.LoadOrStore(ifIndex, new(atomic.Int64))
	return v.(*atomic.Int64)
}

// ------------------------- Cache (sharded) -------------------------

const cacheShardCount = 64
const maxCacheEntrySize = 2048 // don't cache responses larger than this

type cacheKey struct {
	qnameRaw string // lowercased raw wire-format QNAME as string
	qtype    uint16
	qclass   uint16
}

type cacheEntry struct {
	key      cacheKey
	resp     []byte
	storedAt time.Time
	expires  time.Time
	listElem *list.Element
}

type cacheShard struct {
	mu    sync.Mutex
	items map[cacheKey]*cacheEntry
	order *list.List
}

var cacheShards [cacheShardCount]*cacheShard

func initCacheShards() {
	for i := range cacheShards {
		cacheShards[i] = &cacheShard{
			items: make(map[cacheKey]*cacheEntry),
			order: list.New(),
		}
	}
}

func cacheShardIndex(key cacheKey) int {
	h := fnv.New32a()
	h.Write([]byte(key.qnameRaw))
	h.Write([]byte{byte(key.qtype >> 8), byte(key.qtype), byte(key.qclass >> 8), byte(key.qclass)})
	return int(h.Sum32() % cacheShardCount)
}

func cacheGet(key cacheKey) ([]byte, bool) {
	shard := cacheShards[cacheShardIndex(key)]
	shard.mu.Lock()
	defer shard.mu.Unlock()

	entry, ok := shard.items[key]
	if !ok || time.Now().After(entry.expires) {
		if ok {
			removeCacheEntryFromShard(shard, key, entry)
		}
		return nil, false
	}

	elapsed := uint32(time.Since(entry.storedAt).Seconds())
	respCopy := make([]byte, len(entry.resp))
	copy(respCopy, entry.resp)
	decrementTTLs(respCopy, elapsed)
	return respCopy, true
}

func cacheSet(key cacheKey, resp []byte, ttl uint32) {
	if ttl == 0 {
		return
	}
	if len(resp) > maxCacheEntrySize {
		return // skip large responses
	}
	shard := cacheShards[cacheShardIndex(key)]
	shard.mu.Lock()
	defer shard.mu.Unlock()

	if entry, exists := shard.items[key]; exists {
		removeCacheEntryFromShard(shard, key, entry)
	}

	if shard.order.Len() >= cfg.CacheSize/cacheShardCount {
		oldest := shard.order.Front()
		if oldest != nil {
			oldEntry := oldest.Value.(*cacheEntry)
			removeCacheEntryFromShard(shard, oldEntry.key, oldEntry)
		}
	}

	if cfg.CacheMaxBytes > 0 {
		if len(resp) > cfg.CacheMaxBytes {
			return
		}
		for cacheBytesUsed.Load()+int64(len(resp)) > int64(cfg.CacheMaxBytes) {
			oldest := shard.order.Front()
			if oldest == nil {
				break
			}
			oldEntry := oldest.Value.(*cacheEntry)
			removeCacheEntryFromShard(shard, oldEntry.key, oldEntry)
		}
	}

	copyResp := make([]byte, len(resp))
	copy(copyResp, resp)

	now := time.Now()
	entry := &cacheEntry{
		key:      key,
		resp:     copyResp,
		storedAt: now,
		expires:  now.Add(time.Duration(ttl) * time.Second),
	}
	entry.listElem = shard.order.PushBack(entry)
	shard.items[key] = entry
	cacheBytesUsed.Add(int64(len(copyResp)))
}

func removeCacheEntryFromShard(shard *cacheShard, key cacheKey, entry *cacheEntry) {
	delete(shard.items, key)
	shard.order.Remove(entry.listElem)
	cacheBytesUsed.Add(-int64(len(entry.resp)))
}

// cacheStats returns a point-in-time entry count across every shard, plus
// the running hit/miss counters — SIGUSR1's own data source (see main's
// signal loop).
func cacheStats() (entries int, hits, misses uint64, bytesUsed int64) {
	for _, shard := range cacheShards {
		shard.mu.Lock()
		entries += len(shard.items)
		shard.mu.Unlock()
	}
	return entries, cacheHits.Load(), cacheMisses.Load(), cacheBytesUsed.Load()
}

// cacheFlushAll empties every shard immediately — SIGUSR2's own action
// (see main's signal loop).
func cacheFlushAll() int {
	var cleared int
	for _, shard := range cacheShards {
		shard.mu.Lock()
		cleared += len(shard.items)
		shard.items = make(map[cacheKey]*cacheEntry)
		shard.order.Init()
		shard.mu.Unlock()
	}
	cacheBytesUsed.Store(0)
	return cleared
}

// ------------------------- Cache stats file -------------------------

// dnsRelayStatsPath is where statsFileLoop writes cacheStatsSnapshot.
const dnsRelayStatsPath = "/var/lib/dnshived-dnsrelay/stats.json"

// cacheStatsSnapshot is dnsRelayStatsPath's own on-disk shape.
type cacheStatsSnapshot struct {
	Entries       int     `json:"entries"`
	CacheSize     int     `json:"cache_size"`
	CacheMaxBytes int     `json:"cache_max_bytes,omitempty"`
	BytesUsed     int64   `json:"bytes_used"`
	Hits          uint64  `json:"hits"`
	Misses        uint64  `json:"misses"`
	HitRatePct    float64 `json:"hit_rate_pct"`
	UpdatedAt     string  `json:"updated_at"`
}

// buildCacheStatsSnapshot is writeStatsFile's own pure half.
func buildCacheStatsSnapshot() cacheStatsSnapshot {
	entries, hits, misses, bytesUsed := cacheStats()
	total := hits + misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}
	return cacheStatsSnapshot{
		Entries:       entries,
		CacheSize:     cfg.CacheSize,
		CacheMaxBytes: cfg.CacheMaxBytes,
		BytesUsed:     bytesUsed,
		Hits:          hits,
		Misses:        misses,
		HitRatePct:    hitRate,
		UpdatedAt:     time.Now().UTC().Format(time.RFC3339),
	}
}

func writeCacheStatsSnapshot(snap cacheStatsSnapshot, path string) error {
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal cache stats: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename to %s: %w", path, err)
	}
	return nil
}

// writeStatsFile computes a fresh cacheStatsSnapshot and writes it to
// dnsRelayStatsPath.
func writeStatsFile() {
	if err := writeCacheStatsSnapshot(buildCacheStatsSnapshot(), dnsRelayStatsPath); err != nil {
		logThrottled("stats-file-write", "[STATS] %v", err)
	}
}

func statsFileLoop(ctx context.Context, interval time.Duration) {
	writeStatsFile()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			writeStatsFile()
		}
	}
}

// ------------------------- Upstream Client (single socket) -------------------------

type dnsResponse struct {
	packet []byte
	err    error
}

type upstreamClient struct {
	addr     *net.UDPAddr
	conn     *net.UDPConn
	mu       sync.Mutex
	pending  map[uint16]chan *dnsResponse
	pendMu   sync.Mutex
	healthy  atomic.Bool
	lastFail atomic.Int64
}

func newUpstreamClient(addr *net.UDPAddr) (*upstreamClient, error) {
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return nil, err
	}
	uc := &upstreamClient{
		addr:    addr,
		conn:    conn,
		pending: make(map[uint16]chan *dnsResponse),
	}
	uc.healthy.Store(true)
	go uc.readLoop()
	return uc, nil
}

func (uc *upstreamClient) readLoop() {
	buf := make([]byte, cfg.MaxPacketSize)
	for {
		n, err := uc.conn.Read(buf)
		if err != nil {
			uc.healthy.Store(false)
			uc.conn.Close() // prevent FD leak
			uc.markFailure()
			uc.pendMu.Lock()
			for id, ch := range uc.pending {
				ch <- &dnsResponse{err: err}
				close(ch)
				delete(uc.pending, id)
			}
			uc.pendMu.Unlock()
			return
		}
		resp := make([]byte, n)
		copy(resp, buf[:n])
		if len(resp) < 2 {
			continue
		}
		id := binary.BigEndian.Uint16(resp[0:2])
		uc.pendMu.Lock()
		ch, ok := uc.pending[id]
		if ok {
			delete(uc.pending, id)
			uc.pendMu.Unlock()
			ch <- &dnsResponse{packet: resp}
			close(ch)
		} else {
			uc.pendMu.Unlock()
		}
	}
}

// maxIDAllocAttempts bounds query's own collision-retry loop below.
const maxIDAllocAttempts = 16

func (uc *upstreamClient) query(modified []byte, timeout time.Duration) ([]byte, uint16, error) {
	ch := make(chan *dnsResponse, 1)
	uc.pendMu.Lock()
	id := binary.BigEndian.Uint16(modified[0:2])
	for attempt := 0; attempt < maxIDAllocAttempts; attempt++ {
		if _, exists := uc.pending[id]; !exists {
			break
		}
		id = randomUint16()
	}
	uc.pending[id] = ch
	uc.pendMu.Unlock()
	binary.BigEndian.PutUint16(modified[0:2], id)

	uc.mu.Lock()
	_, err := uc.conn.Write(modified)
	uc.mu.Unlock()
	if err != nil {
		uc.pendMu.Lock()
		delete(uc.pending, id)
		uc.pendMu.Unlock()
		uc.markFailure()
		return nil, id, err
	}

	select {
	case resp := <-ch:
		if resp.err != nil {
			uc.markFailure()
			return nil, id, resp.err
		}
		return resp.packet, id, nil
	case <-time.After(timeout):
		// Before giving up, check if response just arrived
		select {
		case resp := <-ch:
			if resp.err != nil {
				uc.markFailure()
				return nil, id, resp.err
			}
			return resp.packet, id, nil
		default:
		}
		uc.pendMu.Lock()
		delete(uc.pending, id)
		uc.pendMu.Unlock()
		uc.markFailure()
		return nil, id, fmt.Errorf("timeout")
	}
}

func (uc *upstreamClient) markFailure() {
	uc.healthy.Store(false)
	uc.lastFail.Store(time.Now().Unix())
}

func (uc *upstreamClient) isHealthy() bool {
	if uc.healthy.Load() {
		return true
	}
	return time.Now().Unix()-uc.lastFail.Load() > 30
}

// ------------------------- Upstream Pool -------------------------

type upstreamPool struct {
	addr    *net.UDPAddr
	clients []*upstreamClient
	mu      sync.RWMutex
}

func newUpstreamPool(addr *net.UDPAddr, size int, ctx context.Context) (*upstreamPool, error) {
	pool := &upstreamPool{addr: addr}
	for i := 0; i < size; i++ {
		uc, err := newUpstreamClient(addr)
		if err != nil {
			for _, c := range pool.clients {
				c.conn.Close()
			}
			return nil, err
		}
		pool.clients = append(pool.clients, uc)
	}
	go pool.reaper(ctx)
	return pool, nil
}

// reaper periodically replaces dead clients that have been unhealthy for
// >30s.
func (p *upstreamPool) reaper(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Collect dead indices under read lock
			p.mu.RLock()
			var deadIdx []int
			for i, c := range p.clients {
				if !c.isHealthy() && time.Since(time.Unix(c.lastFail.Load(), 0)) > 30*time.Second {
					deadIdx = append(deadIdx, i)
				}
			}
			p.mu.RUnlock()

			// Replace outside the lock
			for _, i := range deadIdx {
				newClient, err := newUpstreamClient(p.addr)
				if err == nil {
					p.mu.Lock()
					p.clients[i].conn.Close()
					p.clients[i] = newClient
					p.mu.Unlock()
				}
			}
		}
	}
}

func (p *upstreamPool) query(modified []byte, timeout time.Duration) ([]byte, uint16, error) {
	p.mu.RLock()
	healthyIdx := make([]int, 0, len(p.clients))
	for i, c := range p.clients {
		if c.isHealthy() {
			healthyIdx = append(healthyIdx, i)
		}
	}
	p.mu.RUnlock()

	if len(healthyIdx) == 0 {
		return nil, 0, fmt.Errorf("no healthy upstream socket")
	}

	b := make([]byte, 1)
	if _, err := rand.Read(b); err == nil {
		idx := healthyIdx[int(b[0])%len(healthyIdx)]
		return p.clients[idx].query(modified, timeout)
	}
	idx := healthyIdx[time.Now().UnixNano()%int64(len(healthyIdx))]
	return p.clients[idx].query(modified, timeout)
}

func (p *upstreamPool) isHealthy() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, c := range p.clients {
		if c.isHealthy() {
			return true
		}
	}
	return false
}

// ------------------------- DNS Parsing Helpers -------------------------

func parseQuestion(msg []byte) (qname string, qtype, qclass uint16, ok bool) {
	if len(msg) < 12 {
		return "", 0, 0, false
	}
	offset := 12
	var labels []string
	for {
		if offset >= len(msg) {
			return "", 0, 0, false
		}
		labelLen := int(msg[offset])
		if labelLen == 0 {
			offset++
			break
		}
		if labelLen&0xC0 == 0xC0 {
			return "", 0, 0, false
		}
		if labelLen > 63 {
			return "", 0, 0, false
		}
		if offset+1+labelLen > len(msg) {
			return "", 0, 0, false
		}
		labels = append(labels, string(msg[offset+1:offset+1+labelLen]))
		offset += 1 + labelLen
	}
	if offset+4 > len(msg) {
		return "", 0, 0, false
	}
	qtype = binary.BigEndian.Uint16(msg[offset : offset+2])
	qclass = binary.BigEndian.Uint16(msg[offset+2 : offset+4])
	qname = strings.Join(labels, ".")
	return qname, qtype, qclass, true
}

func parseRawQName(msg []byte) ([]byte, bool) {
	if len(msg) < 12 {
		return nil, false
	}
	offset := 12
	var raw []byte
	for {
		if offset >= len(msg) {
			return nil, false
		}
		labelLen := int(msg[offset])
		if labelLen == 0 {
			raw = append(raw, 0)
			return raw, true
		}
		if labelLen&0xC0 == 0xC0 {
			return nil, false
		}
		if labelLen > 63 {
			return nil, false
		}
		if offset+1+labelLen > len(msg) {
			return nil, false
		}
		raw = append(raw, msg[offset:offset+1+labelLen]...)
		offset += 1 + labelLen
	}
}

// skipName uses a jump counter, no map allocation
func skipName(pkt []byte, offset int) (int, bool) {
	steps := 0
	for {
		if steps > 128 {
			return 0, false
		}
		steps++
		if offset >= len(pkt) {
			return 0, false
		}
		labelLen := int(pkt[offset])
		if labelLen == 0 {
			return offset + 1, true
		}
		if labelLen&0xC0 == 0xC0 {
			if offset+1 >= len(pkt) {
				return 0, false
			}
			ptr := int(binary.BigEndian.Uint16(pkt[offset:offset+2]) & 0x3FFF)
			if ptr >= len(pkt) {
				return 0, false
			}
			offset = ptr
			continue
		}
		if labelLen > 63 {
			return 0, false
		}
		offset += 1 + labelLen
		if offset > len(pkt) {
			return 0, false
		}
	}
}

// nameWireLength returns how many bytes the name AT pkt[offset:] occupies
// IN PLACE.
func nameWireLength(pkt []byte, offset int) (int, bool) {
	start := offset
	steps := 0
	for {
		if steps > 128 {
			return 0, false
		}
		steps++
		if offset >= len(pkt) {
			return 0, false
		}
		labelLen := int(pkt[offset])
		if labelLen == 0 {
			return offset + 1 - start, true
		}
		if labelLen&0xC0 == 0xC0 {
			if offset+1 >= len(pkt) {
				return 0, false
			}
			return offset + 2 - start, true
		}
		if labelLen > 63 {
			return 0, false
		}
		offset += 1 + labelLen
		if offset > len(pkt) {
			return 0, false
		}
	}
}

// skipRRName returns the offset immediately after the owner name of the
// resource record starting at offset (offset + nameWireLength).
func skipRRName(pkt []byte, offset int) (int, bool) {
	n, ok := nameWireLength(pkt, offset)
	if !ok {
		return 0, false
	}
	return offset + n, true
}

// extractName resolves the name at offset, following compression pointers.
func extractName(pkt []byte, offset int) (string, bool) {
	var labels []string
	steps := 0
	for {
		if steps > 128 {
			return "", false
		}
		steps++
		if offset >= len(pkt) {
			return "", false
		}
		labelLen := int(pkt[offset])
		if labelLen == 0 {
			break
		}
		if labelLen&0xC0 == 0xC0 {
			if offset+1 >= len(pkt) {
				return "", false
			}
			ptr := int(binary.BigEndian.Uint16(pkt[offset:offset+2]) & 0x3FFF)
			if ptr >= len(pkt) {
				return "", false
			}
			offset = ptr
			continue
		}
		if labelLen > 63 {
			return "", false
		}
		if offset+1+labelLen > len(pkt) {
			return "", false
		}
		labels = append(labels, string(pkt[offset+1:offset+1+labelLen]))
		offset += 1 + labelLen
	}
	return strings.Join(labels, "."), true
}

func hasOPT(resp []byte) bool {
	if len(resp) < 12 {
		return false
	}
	offset := 12
	qdcount := int(binary.BigEndian.Uint16(resp[4:6]))
	for i := 0; i < qdcount; i++ {
		off, ok := skipName(resp, offset)
		if !ok {
			return false
		}
		offset = off + 4
		if offset > len(resp) {
			return false
		}
	}
	ancount := int(binary.BigEndian.Uint16(resp[6:8]))
	nscount := int(binary.BigEndian.Uint16(resp[8:10]))
	for i := 0; i < ancount; i++ {
		off, ok := skipRRName(resp, offset)
		if !ok {
			return false
		}
		offset = off
		if offset+10 > len(resp) {
			return false
		}
		rdlen := int(binary.BigEndian.Uint16(resp[offset+8 : offset+10]))
		offset += 10 + rdlen
	}
	for i := 0; i < nscount; i++ {
		off, ok := skipRRName(resp, offset)
		if !ok {
			return false
		}
		offset = off
		if offset+10 > len(resp) {
			return false
		}
		rdlen := int(binary.BigEndian.Uint16(resp[offset+8 : offset+10]))
		offset += 10 + rdlen
	}
	arcount := int(binary.BigEndian.Uint16(resp[10:12]))
	for i := 0; i < arcount; i++ {
		off, ok := skipRRName(resp, offset)
		if !ok {
			return false
		}
		offset = off
		if offset+10 > len(resp) {
			return false
		}
		typ := binary.BigEndian.Uint16(resp[offset : offset+2])
		if typ == 41 {
			return true
		}
		rdlen := int(binary.BigEndian.Uint16(resp[offset+8 : offset+10]))
		offset += 10 + rdlen
	}
	return false
}

func getMinTTL(resp []byte) uint32 {
	if len(resp) < 12 {
		return 0
	}
	qdcount := int(binary.BigEndian.Uint16(resp[4:6]))
	ancount := int(binary.BigEndian.Uint16(resp[6:8]))
	offset := 12
	for i := 0; i < qdcount; i++ {
		off, ok := skipName(resp, offset)
		if !ok {
			return 0
		}
		offset = off + 4
		if offset > len(resp) {
			return 0
		}
	}
	minTTL := uint32(0xFFFFFFFF)
	for i := 0; i < ancount; i++ {
		off, ok := skipRRName(resp, offset)
		if !ok {
			return 0
		}
		offset = off
		if offset+10 > len(resp) {
			return 0
		}
		ttl := binary.BigEndian.Uint32(resp[offset+4 : offset+8])
		if ttl < minTTL {
			minTTL = ttl
		}
		rdlen := int(binary.BigEndian.Uint16(resp[offset+8 : offset+10]))
		offset += 10 + rdlen
	}
	if minTTL == 0xFFFFFFFF {
		return 0
	}
	return minTTL
}

func shouldCache(resp []byte, qtype uint16) bool {
	if !isCacheableType(qtype) || len(resp) < 12 {
		return false
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x0200 != 0 || flags&0xF != 0 {
		return false
	}
	return binary.BigEndian.Uint16(resp[6:8]) > 0
}

func isCacheableType(qtype uint16) bool {
	switch qtype {
	case 1, 28, 5, 12:
		return true
	default:
		return false
	}
}

func makeServFail(query []byte) []byte {
	resp := make([]byte, len(query))
	copy(resp, query)
	flags := binary.BigEndian.Uint16(resp[2:4])
	flags |= 0x8000
	flags &^= 0xF
	flags |= 0x2
	binary.BigEndian.PutUint16(resp[2:4], flags)
	return resp
}

// makeRefused builds a real REFUSED (RCODE 5) response.
func makeRefused(query []byte) []byte {
	resp := make([]byte, len(query))
	copy(resp, query)
	flags := binary.BigEndian.Uint16(resp[2:4])
	flags |= 0x8000
	flags &^= 0xF
	flags |= 0x5
	binary.BigEndian.PutUint16(resp[2:4], flags)
	return resp
}

func encodeName(name string) ([]byte, error) {
	if name == "" {
		return []byte{0}, nil
	}
	var buf bytes.Buffer
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue // tolerate a stray empty label (e.g. an already-trimmed trailing dot)
		}
		if len(label) > 63 {
			return nil, fmt.Errorf("label %q exceeds 63 bytes", label)
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0)
	if buf.Len() > 255 {
		return nil, fmt.Errorf("encoded name %q exceeds 255 bytes", name)
	}
	return buf.Bytes(), nil
}

// questionEndOffset returns the byte offset immediately after msg's first
// question's qtype+qclass fields.
func questionEndOffset(msg []byte) (int, bool) {
	off, ok := skipName(msg, 12)
	if !ok {
		return 0, false
	}
	off += 4 // qtype + qclass
	if off > len(msg) {
		return 0, false
	}
	return off, true
}

// buildRewrittenQuery builds a copy of query with its question's own QNAME
// replaced by newName (qtype/qclass unchanged).
func buildRewrittenQuery(query []byte, qnameEnd int, newName string, qtype, qclass uint16) ([]byte, error) {
	encoded, err := encodeName(newName)
	if err != nil {
		return nil, err
	}
	rest := query[qnameEnd:]
	out := make([]byte, 12+len(encoded)+4+len(rest))
	copy(out[:12], query[:12])
	off := 12
	copy(out[off:], encoded)
	off += len(encoded)
	binary.BigEndian.PutUint16(out[off:off+2], qtype)
	binary.BigEndian.PutUint16(out[off+2:off+4], qclass)
	off += 4
	copy(out[off:], rest)
	return out, nil
}

// parseRR decodes one resource record starting at offset.
func parseRR(pkt []byte, offset int) (owner string, rtype, rclass uint16, ttl uint32, rdata []byte, next int, ok bool) {
	owner, ok = extractName(pkt, offset)
	if !ok {
		return
	}
	nameEnd, ok2 := skipRRName(pkt, offset)
	if !ok2 || nameEnd+10 > len(pkt) {
		ok = false
		return
	}
	rtype = binary.BigEndian.Uint16(pkt[nameEnd : nameEnd+2])
	rclass = binary.BigEndian.Uint16(pkt[nameEnd+2 : nameEnd+4])
	ttl = binary.BigEndian.Uint32(pkt[nameEnd+4 : nameEnd+8])
	rdlen := int(binary.BigEndian.Uint16(pkt[nameEnd+8 : nameEnd+10]))
	rdataStart := nameEnd + 10
	if rdataStart+rdlen > len(pkt) {
		ok = false
		return
	}
	rdata = pkt[rdataStart : rdataStart+rdlen]
	next = rdataStart + rdlen
	ok = true
	return
}

func rewriteResponseNames(resp []byte, fromLower, to string) ([]byte, error) {
	if len(resp) < 12 {
		return nil, fmt.Errorf("response too short")
	}
	qdcount := int(binary.BigEndian.Uint16(resp[4:6]))
	ancount := int(binary.BigEndian.Uint16(resp[6:8]))
	nscount := int(binary.BigEndian.Uint16(resp[8:10]))
	arcount := int(binary.BigEndian.Uint16(resp[10:12]))

	var out bytes.Buffer
	out.Write(resp[0:12])

	rewriteIfMatch := func(name string) string {
		if strings.EqualFold(name, fromLower) {
			return to
		}
		return name
	}

	offset := 12
	for i := 0; i < qdcount; i++ {
		name, ok := extractName(resp, offset)
		if !ok {
			return nil, fmt.Errorf("bad question name")
		}
		nameEnd, ok := skipName(resp, offset)
		if !ok || nameEnd+4 > len(resp) {
			return nil, fmt.Errorf("bad question")
		}
		qtype := binary.BigEndian.Uint16(resp[nameEnd : nameEnd+2])
		qclass := binary.BigEndian.Uint16(resp[nameEnd+2 : nameEnd+4])
		encoded, err := encodeName(rewriteIfMatch(name))
		if err != nil {
			return nil, err
		}
		out.Write(encoded)
		var tmp [4]byte
		binary.BigEndian.PutUint16(tmp[0:2], qtype)
		binary.BigEndian.PutUint16(tmp[2:4], qclass)
		out.Write(tmp[:])
		offset = nameEnd + 4
	}

	for _, count := range []int{ancount, nscount, arcount} {
		for i := 0; i < count; i++ {
			owner, rtype, rclass, ttl, rdata, next, ok := parseRR(resp, offset)
			if !ok {
				return nil, fmt.Errorf("bad resource record")
			}
			encoded, err := encodeName(rewriteIfMatch(owner))
			if err != nil {
				return nil, err
			}
			out.Write(encoded)
			var tmp [10]byte
			binary.BigEndian.PutUint16(tmp[0:2], rtype)
			binary.BigEndian.PutUint16(tmp[2:4], rclass)
			binary.BigEndian.PutUint32(tmp[4:8], ttl)
			binary.BigEndian.PutUint16(tmp[8:10], uint16(len(rdata)))
			out.Write(tmp[:])
			out.Write(rdata)
			offset = next
		}
	}

	return out.Bytes(), nil
}

// makeSynthesizedAnswer builds a locally-synthesized NOERROR response for
// a matched RewriteRule Answer action.
func makeSynthesizedAnswer(query []byte, qnameEnd int, ip net.IP, ttl uint32, hasRecord bool) []byte {
	question := query[12:qnameEnd]
	var out bytes.Buffer
	var hdr [12]byte
	copy(hdr[0:2], query[0:2]) // echo the client's own ID
	flags := uint16(0x8000)    // QR=1, RCODE=NOERROR
	if binary.BigEndian.Uint16(query[2:4])&0x0100 != 0 {
		flags |= 0x0080 | 0x0100 // echo RD, set RA (we're answering authoritatively for this one name)
	}
	binary.BigEndian.PutUint16(hdr[2:4], flags)
	binary.BigEndian.PutUint16(hdr[4:6], 1) // qdcount
	var ancount uint16
	if hasRecord {
		ancount = 1
	}
	binary.BigEndian.PutUint16(hdr[6:8], ancount)
	out.Write(hdr[:])
	out.Write(question)
	if hasRecord {
		out.Write([]byte{0xC0, 0x0C})
		var rr [10]byte
		binary.BigEndian.PutUint16(rr[0:2], 1) // TYPE A
		binary.BigEndian.PutUint16(rr[2:4], 1) // CLASS IN
		binary.BigEndian.PutUint32(rr[4:8], ttl)
		binary.BigEndian.PutUint16(rr[8:10], 4) // RDLENGTH
		out.Write(rr[:])
		out.Write(ip.To4())
	}
	return out.Bytes()
}

// rewriteDecision is the resolved outcome of matching an interface's ACL
// rewrite rules against one query.
type rewriteDecision struct {
	// answer is non-nil when an Answer rule matched.
	answer    net.IP
	answerTTL uint32
	// hasRecord is true only when the query's own qtype is A (1) — see
	// makeSynthesizedAnswer.
	hasRecord bool
	// rewritten is true when a Rewrite rule matched.
	rewritten   bool
	targetLower string
}

func matchRewrite(acl *resolvedACL, qnameLower string, qtype uint16) rewriteDecision {
	if acl == nil {
		return rewriteDecision{}
	}
	for i := range acl.rewrites {
		r := &acl.rewrites[i]
		if !r.matches(qnameLower) {
			continue
		}
		if r.answer != nil {
			return rewriteDecision{answer: r.answer, answerTTL: r.ttl, hasRecord: qtype == 1}
		}
		return rewriteDecision{rewritten: true, targetLower: r.target(qnameLower)}
	}
	return rewriteDecision{}
}

func validateDNSQuery(msg []byte) bool {
	if len(msg) < 12 {
		return false
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&0x8000 != 0 {
		return false
	}
	if (flags>>11)&0xF != 0 {
		return false
	}
	if binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return false
	}
	_, _, _, ok := parseQuestion(msg)
	return ok
}

func validateDNSResponse(resp []byte, expectedID uint16, qname string, qtype, qclass uint16) bool {
	if len(resp) < 12 {
		return false
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x8000 == 0 {
		return false
	}
	if (flags>>11)&0xF != 0 {
		return false
	}
	if binary.BigEndian.Uint16(resp[4:6]) != 1 {
		return false
	}
	if binary.BigEndian.Uint16(resp[0:2]) != expectedID {
		return false
	}
	rName, rType, rClass, ok := parseQuestion(resp)
	if !ok {
		return false
	}
	if !strings.EqualFold(rName, qname) || rType != qtype || rClass != qclass {
		return false
	}
	ancount := binary.BigEndian.Uint16(resp[6:8])
	if ancount > 0 {
		offset := 12
		qdcount := int(binary.BigEndian.Uint16(resp[4:6]))
		for i := 0; i < qdcount; i++ {
			off, ok := skipName(resp, offset)
			if !ok {
				return false
			}
			offset = off + 4
			if offset > len(resp) {
				return false
			}
		}
		owner, ok := extractName(resp, offset)
		if !ok || !strings.EqualFold(owner, qname) {
			return false
		}
	}
	return true
}

func decrementTTLs(resp []byte, seconds uint32) {
	if len(resp) < 12 {
		return
	}
	qdcount := int(binary.BigEndian.Uint16(resp[4:6]))
	ancount := int(binary.BigEndian.Uint16(resp[6:8]))
	nscount := int(binary.BigEndian.Uint16(resp[8:10]))
	arcount := int(binary.BigEndian.Uint16(resp[10:12]))

	offset := 12
	for i := 0; i < qdcount; i++ {
		off, ok := skipName(resp, offset)
		if !ok {
			return
		}
		offset = off + 4
		if offset > len(resp) {
			return
		}
	}

	for _, count := range []int{ancount, nscount, arcount} {
		for i := 0; i < count; i++ {
			off, ok := skipRRName(resp, offset)
			if !ok {
				return
			}
			offset = off
			if offset+10 > len(resp) {
				return
			}
			rrType := binary.BigEndian.Uint16(resp[offset : offset+2])
			const typeOPT = 41
			if rrType != typeOPT {
				ttl := binary.BigEndian.Uint32(resp[offset+4 : offset+8])
				if ttl > seconds {
					ttl -= seconds
				} else {
					ttl = 0
				}
				binary.BigEndian.PutUint32(resp[offset+4:offset+8], ttl)
			}
			rdlen := int(binary.BigEndian.Uint16(resp[offset+8 : offset+10]))
			offset += 10 + rdlen
			if offset > len(resp) {
				return
			}
		}
	}
}

// ------------------------- Network Helpers -------------------------

// reuseAddrControl sets SO_REUSEADDR on every socket this relay opens
// (both UDP and TCP, per-address).
func reuseAddrControl(network, address string, c syscall.RawConn) error {
	var innerErr error
	err := c.Control(func(fd uintptr) {
		innerErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	})
	if err != nil {
		return err
	}
	return innerErr
}

// listenPort extracts just the :port suffix of cfg.ListenAddr.
func listenPort() (int, error) {
	_, portStr, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil {
		return 0, fmt.Errorf("parse listen_addr %q: %w", cfg.ListenAddr, err)
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return 0, fmt.Errorf("parse listen_addr port %q: %w", portStr, err)
	}
	return port, nil
}

// openAddrSocket binds one UDP+TCP socket pair to ip:port.
func openAddrSocket(ip net.IP, ifIndex int, info *ifaceInfo, port int) (*addrSocket, error) {
	udpAddr := &net.UDPAddr{IP: ip, Port: port}
	lc := net.ListenConfig{Control: reuseAddrControl}
	pc, err := lc.ListenPacket(context.Background(), "udp4", udpAddr.String())
	if err != nil {
		return nil, fmt.Errorf("udp bind %s: %w", udpAddr, err)
	}
	udpConn := pc.(*net.UDPConn)

	tcpAddr := &net.TCPAddr{IP: ip, Port: port}
	tl, err := lc.Listen(context.Background(), "tcp4", tcpAddr.String())
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("tcp bind %s: %w", tcpAddr, err)
	}
	tcpLn := tl.(*net.TCPListener)

	sock := &addrSocket{ip: ip, ifIndex: ifIndex, udpConn: udpConn, tcpLn: tcpLn}
	sock.ifInfo.Store(info)
	return sock, nil
}

// closeAddrSocket closes both halves of sock.
func closeAddrSocket(sock *addrSocket) {
	sock.udpConn.Close()
	sock.tcpLn.Close()
}

// reconcileAddrSockets acquires reconcileMu and delegates to
// reconcileAddrSocketsLocked.
func reconcileAddrSockets() {
	reconcileMu.Lock()
	defer reconcileMu.Unlock()
	reconcileAddrSocketsLocked()
}

func reconcileAddrSocketsLocked() {
	type desiredAddr struct {
		ip      net.IP
		ifIndex int
		info    *ifaceInfo
	}
	desired := make(map[uint32]desiredAddr)

	ifaces := allowedIfaces.Load()
	if ifaces != nil {
		for idx, info := range *ifaces {
			iface, err := net.InterfaceByIndex(idx)
			if err != nil {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				ipNet, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				v4 := ipNet.IP.To4()
				if v4 == nil {
					continue
				}
				desired[ipToUint32(v4)] = desiredAddr{ip: v4, ifIndex: idx, info: info}
			}
		}
	}

	if openSockets == nil {
		openSockets = make(map[uint32]*addrSocket)
	}

	var removed, added []string
	for key, sock := range openSockets {
		if _, ok := desired[key]; !ok {
			closeAddrSocket(sock)
			delete(openSockets, key)
			removed = append(removed, sock.ip.String())
		}
	}

	port, err := listenPort()
	if err != nil {
		logger.Printf("[SOCKET] %v — cannot open any new address socket this tick", err)
		port = -1
	}

	for key, d := range desired {
		if existing, ok := openSockets[key]; ok {
			existing.ifInfo.Store(d.info) // pick up a fresh ACL/subnet without reopening the socket
			continue
		}
		if port < 0 {
			continue
		}
		sock, err := openAddrSocket(d.ip, d.ifIndex, d.info, port)
		if err != nil {
			logger.Printf("[SOCKET] %v", err)
			continue
		}
		openSockets[key] = sock
		udpReaderWG.Add(1)
		go udpReadLoopForSocket(sock)
		go tcpAcceptLoopForSocket(sock)
		added = append(added, d.ip.String())
	}

	if len(added) > 0 || len(removed) > 0 {
		logger.Printf("[SOCKET] reconciled: %d added %v, %d removed %v (now %d address(es) bound)",
			len(added), added, len(removed), removed, len(openSockets))
	}
}

// addrSocketReconcileLoop drives reconcileAddrSockets on a fixed interval
// until ctx is done.
func addrSocketReconcileLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reconcileAddrSockets()
		}
	}
}

// buildIfaceInfo resolves one interface name into its current ifIndex and
// a fresh *ifaceInfo (own subnet, derived from whichever IPv4 address
// happens to be first).
func buildIfaceInfo(name string) (int, *ifaceInfo, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, nil, fmt.Errorf("interface not found: %s", name)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return 0, nil, fmt.Errorf("read addresses for %s: %w", name, err)
	}
	var subnet *net.IPNet
	for _, a := range addrs {
		if ipNet, ok := a.(*net.IPNet); ok {
			if ipNet.IP.To4() != nil {
				subnet = ipNet
				break
			}
		}
	}
	if subnet == nil {
		return 0, nil, fmt.Errorf("no IPv4 address on interface %s", name)
	}
	acl, err := resolveACL(name)
	if err != nil {
		return 0, nil, fmt.Errorf("interface %q ACL: %w", name, err)
	}
	return iface.Index, &ifaceInfo{name: name, subnet: subnet, acl: acl}, nil
}

func reconfigureInterfaces(newNames []string) bool {
	reconcileMu.Lock()
	defer reconcileMu.Unlock()

	oldIfaces := allowedIfaces.Load()
	oldByName := make(map[string]bool)
	if oldIfaces != nil {
		for _, info := range *oldIfaces {
			oldByName[info.name] = true
		}
	}

	next := make(map[int]*ifaceInfo, len(newNames))
	var added, unchanged, failed []string
	seenNames := make(map[string]bool, len(newNames))

	for _, name := range newNames {
		seenNames[name] = true
		idx, info, err := buildIfaceInfo(name)
		if err != nil {
			logger.Printf("[RELOAD] %v (keeping this interface out of the allowed set)", err)
			failed = append(failed, name)
			continue
		}
		next[idx] = info
		if oldByName[name] {
			unchanged = append(unchanged, name)
		} else {
			added = append(added, name)
		}
	}

	var removed []string
	for name := range oldByName {
		if !seenNames[name] {
			removed = append(removed, name)
		}
	}

	if len(next) == 0 {
		logger.Printf("[RELOAD] refusing: new config resolved zero usable interface(s) out of %d requested — keeping current %d interface(s)",
			len(newNames), len(oldByName))
		return false
	}

	allowedIfaces.Store(&next)
	reconcileAddrSocketsLocked()

	logger.Printf("[RELOAD] applied: %d added %v, %d removed %v, %d unchanged, %d failed %v (now %d interface(s) allowed)",
		len(added), added, len(removed), removed, len(unchanged), len(failed), failed, len(next))
	return true
}

// reloadInterfaces re-reads configPath and applies ONLY its
// allowed_interfaces, interface_acls, and rewrites fields, via
// reconfigureInterfaces.
func reloadInterfaces(configPath string) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		logger.Printf("[RELOAD] read config: %v (keeping current interfaces, nothing changed)", err)
		return
	}
	var newCfg Config
	if err := json.Unmarshal(data, &newCfg); err != nil {
		logger.Printf("[RELOAD] parse config: %v (keeping current interfaces, nothing changed)", err)
		return
	}
	prevInterfaceACLs := cfg.InterfaceACLs
	prevRewrites := cfg.Rewrites
	cfg.InterfaceACLs = newCfg.InterfaceACLs
	cfg.Rewrites = newCfg.Rewrites
	if !reconfigureInterfaces(newCfg.AllowedInterfaces) {
		cfg.InterfaceACLs = prevInterfaceACLs
		cfg.Rewrites = prevRewrites
	}
}

func randomUint16() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err == nil {
		return binary.BigEndian.Uint16(b[:])
	}
	return uint16(time.Now().UnixNano() & 0xFFFF)
}

func forwardTCP(upstream *net.UDPAddr, query []byte, timeout time.Duration) ([]byte, error) {
	addr := &net.TCPAddr{IP: upstream.IP, Port: upstream.Port}
	conn, err := net.DialTimeout("tcp4", addr.String(), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if len(query) > 65535 {
		return nil, fmt.Errorf("DNS query too large")
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(query)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if respLen < 12 || respLen > cfg.MaxPacketSize {
		return nil, fmt.Errorf("invalid TCP response length %d", respLen)
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// sendUDPReply writes resp back to client on conn.
func sendUDPReply(conn *net.UDPConn, client *net.UDPAddr, resp []byte) {
	if _, err := conn.WriteToUDP(resp, client); err != nil {
		logger.Printf("UDP write error: %v", err)
		upstreamErrors.Add(1)
		return
	}
	repliesSent.Add(1)
}

func acquireOutstanding() bool {
	select {
	case outstandingSem <- struct{}{}:
		outstandingQueries.Add(1)
		return true
	default:
		return false
	}
}

func releaseOutstanding() {
	<-outstandingSem
	outstandingQueries.Add(-1)
}

// ------------------------- UDP Worker -------------------------

type udpJob struct {
	conn   *net.UDPConn
	packet []byte
	client *net.UDPAddr
	acl    *resolvedACL
}

func udpWorker(wg *sync.WaitGroup, jobs <-chan udpJob) {
	defer wg.Done()
	for job := range jobs {
		processUDPQuery(job.conn, job.packet, job.client, job.acl)
		putPacketBuffer(job.packet)
	}
}

// udpReadLoopForSocket is the read loop for exactly one addrSocket's UDP
// half.
func udpReadLoopForSocket(sock *addrSocket) {
	defer udpReaderWG.Done()
	buf := make([]byte, cfg.MaxPacketSize)
	for {
		n, remoteAddr, err := sock.udpConn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			logThrottled("udp_read_error", "UDP read error: %v", err)
			continue
		}
		info := sock.ifInfo.Load()
		if info.subnet != nil && !info.subnet.Contains(remoteAddr.IP) {
			droppedTotal.Add(1)
			continue
		}
		if !ifaceAllowed(sock.ifIndex, info.acl.interfaceRateLimit, info.acl.interfaceRateBurst) {
			droppedTotal.Add(1)
			rateLimitedTotal.Add(1)
			logThrottled("iface_rate_limit:"+info.name, "[RATELIMIT] dropped UDP query on %s: interface aggregate rate limit exceeded (%d/s burst %d)",
				info.name, info.acl.interfaceRateLimit, info.acl.interfaceRateBurst)
			continue
		}
		if !isAllowed(remoteAddr.IP, info.acl.rateLimit, info.acl.rateBurst, info.acl.rateLimitScope) {
			droppedTotal.Add(1)
			rateLimitedTotal.Add(1)
			logThrottled("rate_limit:"+info.name, "[RATELIMIT] dropped UDP query from %s on %s: rate limit exceeded (%d/s burst %d, scope=%s)",
				remoteAddr.IP, info.name, info.acl.rateLimit, info.acl.rateBurst, info.acl.rateLimitScope)
			continue
		}
		queriesTotal.Add(1)

		packet := getPacketBuffer()
		packet = packet[:n]
		copy(packet, buf[:n])

		client := &net.UDPAddr{IP: append(net.IP(nil), remoteAddr.IP...), Port: remoteAddr.Port, Zone: remoteAddr.Zone}

		job := udpJob{conn: sock.udpConn, packet: packet, client: client, acl: info.acl}
		select {
		case jobs <- job:
		default:
			droppedTotal.Add(1)
			putPacketBuffer(packet)
		}
	}
}

func processUDPQuery(conn *net.UDPConn, packet []byte, client *net.UDPAddr, acl *resolvedACL) {
	if !validateDNSQuery(packet) {
		droppedTotal.Add(1)
		return
	}
	qname, qtype, qclass, _ := parseQuestion(packet)
	rawQName, _ := parseRawQName(packet)

	if aclDenies(acl, qname, qtype) {
		aclDeniedTotal.Add(1)
		sendUDPReply(conn, client, makeRefused(packet))
		return
	}

	qnameLower := strings.ToLower(qname)
	decision := matchRewrite(acl, qnameLower, qtype)
	if decision.answer != nil {
		rewriteAnsweredTotal.Add(1)
		qnameEnd, ok := questionEndOffset(packet)
		if !ok {
			droppedTotal.Add(1)
			return
		}
		sendUDPReply(conn, client, makeSynthesizedAnswer(packet, qnameEnd, decision.answer, decision.answerTTL, decision.hasRecord))
		return
	}

	forwardQName := qname
	forwardQNameLower := qnameLower
	if decision.rewritten {
		forwardQName = decision.targetLower
		forwardQNameLower = decision.targetLower
	}
	rawForwardName := rawQName
	if decision.rewritten {
		encoded, err := encodeName(forwardQNameLower)
		if err != nil {
			droppedTotal.Add(1)
			return
		}
		rawForwardName = encoded
	}

	cacheKey := cacheKey{qnameRaw: string(bytes.ToLower(rawForwardName)), qtype: qtype, qclass: qclass}

	if isCacheableType(qtype) {
		if resp, found := cacheGet(cacheKey); found {
			cacheHits.Add(1)
			binary.BigEndian.PutUint16(resp[0:2], binary.BigEndian.Uint16(packet[0:2]))
			flags := binary.BigEndian.Uint16(resp[2:4])
			flags &^= 0x0020
			binary.BigEndian.PutUint16(resp[2:4], flags)
			if decision.rewritten {
				translated, err := rewriteResponseNames(resp, forwardQNameLower, qname)
				if err != nil {
					sendUDPReply(conn, client, makeServFail(packet))
					return
				}
				resp = translated
				rewriteForwardedTotal.Add(1)
			}
			sendUDPReply(conn, client, resp)
			return
		}
		cacheMisses.Add(1)
	}

	if !acquireOutstanding() {
		droppedTotal.Add(1)
		return
	}
	defer releaseOutstanding()

	originalID := binary.BigEndian.Uint16(packet[0:2])
	newID := randomUint16()
	var modified []byte
	if decision.rewritten {
		qnameEnd, ok := questionEndOffset(packet)
		if !ok {
			droppedTotal.Add(1)
			return
		}
		built, err := buildRewrittenQuery(packet, qnameEnd, forwardQNameLower, qtype, qclass)
		if err != nil {
			droppedTotal.Add(1)
			return
		}
		modified = built
	} else {
		modified = make([]byte, len(packet))
		copy(modified, packet)
	}
	binary.BigEndian.PutUint16(modified[0:2], newID)

	var lastErr error
	for _, pool := range upstreamPools {
		if !pool.isHealthy() {
			continue
		}
		resp, usedID, err := pool.query(modified, cfg.Timeout.D())
		if err != nil {
			upstreamErrors.Add(1)
			lastErr = err
			continue
		}
		if !validateDNSResponse(resp, usedID, forwardQName, qtype, qclass) {
			upstreamErrors.Add(1)
			lastErr = fmt.Errorf("invalid response")
			continue
		}
		flags := binary.BigEndian.Uint16(resp[2:4])
		flags &^= 0x0020
		binary.BigEndian.PutUint16(resp[2:4], flags)

		if isTruncated(resp) {
			tcpQuery := packet
			if decision.rewritten {
				tcpQuery = make([]byte, len(modified))
				copy(tcpQuery, modified)
				binary.BigEndian.PutUint16(tcpQuery[0:2], originalID)
			}
			tcpResp, err := forwardTCP(pool.addr, tcpQuery, cfg.TCPTimeout.D())
			if err == nil {
				if validateDNSResponse(tcpResp, originalID, forwardQName, qtype, qclass) {
					resp = tcpResp
					flags = binary.BigEndian.Uint16(resp[2:4])
					flags &^= 0x0020
					binary.BigEndian.PutUint16(resp[2:4], flags)
				}
			}
		}

		binary.BigEndian.PutUint16(resp[0:2], originalID)

		if shouldCache(resp, qtype) && !hasOPT(resp) {
			ttl := getMinTTL(resp)
			if ttl > 0 {
				cacheSet(cacheKey, resp, ttl)
			}
		}

		if decision.rewritten {
			translated, err := rewriteResponseNames(resp, forwardQNameLower, qname)
			if err != nil {
				sendUDPReply(conn, client, makeServFail(packet))
				return
			}
			resp = translated
			rewriteForwardedTotal.Add(1)
		}

		sendUDPReply(conn, client, resp)
		forwardedTotal.Add(1)
		return
	}

	if lastErr != nil {
		logger.Printf("[ERROR] All upstreams failed for %s: %v", qname, lastErr)
	}
	servfail := makeServFail(packet)
	sendUDPReply(conn, client, servfail)
}

func isTruncated(resp []byte) bool {
	if len(resp) < 4 {
		return false
	}
	return binary.BigEndian.Uint16(resp[2:4])&0x0200 != 0
}

// ------------------------- TCP Handling -------------------------

// tcpAcceptLoopForSocket is the accept loop for exactly one addrSocket's
// TCP half.
func tcpAcceptLoopForSocket(sock *addrSocket) {
	for {
		conn, err := sock.tcpLn.AcceptTCP()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return // reconcile removed this address, or the process is shutting down
			}
			continue
		}
		info := sock.ifInfo.Load()
		srcIP := conn.RemoteAddr().(*net.TCPAddr).IP
		if info.subnet != nil && !info.subnet.Contains(srcIP) {
			droppedTotal.Add(1)
			conn.Close()
			continue
		}
		if !ifaceAllowed(sock.ifIndex, info.acl.interfaceRateLimit, info.acl.interfaceRateBurst) {
			droppedTotal.Add(1)
			rateLimitedTotal.Add(1)
			logThrottled("iface_rate_limit_tcp:"+info.name, "[RATELIMIT] dropped TCP connection on %s: interface aggregate rate limit exceeded (%d/s burst %d)",
				info.name, info.acl.interfaceRateLimit, info.acl.interfaceRateBurst)
			conn.Close()
			continue
		}
		if !isAllowed(srcIP, info.acl.rateLimit, info.acl.rateBurst, info.acl.rateLimitScope) {
			droppedTotal.Add(1)
			rateLimitedTotal.Add(1)
			logThrottled("rate_limit_tcp:"+info.name, "[RATELIMIT] dropped TCP connection from %s on %s: rate limit exceeded (%d/s burst %d, scope=%s)",
				srcIP, info.name, info.acl.rateLimit, info.acl.rateBurst, info.acl.rateLimitScope)
			conn.Close()
			continue
		}
		ifaceCounter := tcpConnCounterFor(sock.ifIndex)
		if ifaceCounter.Load() >= int64(info.acl.maxTCPConnections) {
			droppedTotal.Add(1)
			conn.Close()
			continue
		}
		key := srcIP.String()
		tcpConnMu.Lock()
		if tcpConnPerSrc[key] >= info.acl.maxTCPPerSource {
			tcpConnMu.Unlock()
			droppedTotal.Add(1)
			conn.Close()
			continue
		}
		tcpConnPerSrc[key]++
		tcpConnMu.Unlock()
		tcpConnections.Add(1)
		ifaceCounter.Add(1)

		go func(c *net.TCPConn, srcKey string, ifIndex int, acl *resolvedACL, ifaceCounter *atomic.Int64) {
			defer func() {
				c.Close()
				tcpConnMu.Lock()
				tcpConnPerSrc[srcKey]--
				if tcpConnPerSrc[srcKey] == 0 {
					delete(tcpConnPerSrc, srcKey)
				}
				tcpConnMu.Unlock()
				tcpConnections.Add(-1)
				ifaceCounter.Add(-1)
			}()
			handleTCPConn(c, ifIndex, acl)
		}(conn, key, sock.ifIndex, info.acl, ifaceCounter)
	}
}

func handleTCPConn(conn *net.TCPConn, ifIndex int, acl *resolvedACL) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	for {
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		queryLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if queryLen < 12 || queryLen > cfg.MaxPacketSize {
			return
		}
		query := make([]byte, queryLen)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}

		queriesTotal.Add(1)

		if !validateDNSQuery(query) {
			droppedTotal.Add(1)
			continue
		}
		qname, qtype, qclass, _ := parseQuestion(query)
		rawQName, _ := parseRawQName(query)

		if aclDenies(acl, qname, qtype) {
			aclDeniedTotal.Add(1)
			writeTCPResponse(conn, makeRefused(query))
			continue
		}

		qnameLower := strings.ToLower(qname)
		decision := matchRewrite(acl, qnameLower, qtype)
		if decision.answer != nil {
			rewriteAnsweredTotal.Add(1)
			qnameEnd, ok := questionEndOffset(query)
			if !ok {
				droppedTotal.Add(1)
				continue
			}
			writeTCPResponse(conn, makeSynthesizedAnswer(query, qnameEnd, decision.answer, decision.answerTTL, decision.hasRecord))
			continue
		}

		forwardQName := qname
		forwardQNameLower := qnameLower
		queryToSend := query
		if decision.rewritten {
			forwardQName = decision.targetLower
			forwardQNameLower = decision.targetLower
			qnameEnd, ok := questionEndOffset(query)
			if !ok {
				droppedTotal.Add(1)
				continue
			}
			built, err := buildRewrittenQuery(query, qnameEnd, forwardQNameLower, qtype, qclass)
			if err != nil {
				droppedTotal.Add(1)
				continue
			}
			queryToSend = built
		}
		rawForwardName := rawQName
		if decision.rewritten {
			encoded, err := encodeName(forwardQNameLower)
			if err != nil {
				droppedTotal.Add(1)
				continue
			}
			rawForwardName = encoded
		}

		cacheKey := cacheKey{qnameRaw: string(bytes.ToLower(rawForwardName)), qtype: qtype, qclass: qclass}

		if isCacheableType(qtype) {
			if resp, found := cacheGet(cacheKey); found {
				cacheHits.Add(1)
				binary.BigEndian.PutUint16(resp[0:2], binary.BigEndian.Uint16(query[0:2]))
				flags := binary.BigEndian.Uint16(resp[2:4])
				flags &^= 0x0020
				binary.BigEndian.PutUint16(resp[2:4], flags)
				if decision.rewritten {
					translated, err := rewriteResponseNames(resp, forwardQNameLower, qname)
					if err != nil {
						writeTCPResponse(conn, makeServFail(query))
						continue
					}
					resp = translated
					rewriteForwardedTotal.Add(1)
				}
				writeTCPResponse(conn, resp)
				continue
			}
			cacheMisses.Add(1)
		}

		if !acquireOutstanding() {
			droppedTotal.Add(1)
			continue
		}

		// Held explicitly, released at every exit point below instead of deferred.
		var upstreamAddr *net.UDPAddr
		for _, pool := range upstreamPools {
			if pool.isHealthy() {
				upstreamAddr = pool.addr
				break
			}
		}
		if upstreamAddr == nil {
			droppedTotal.Add(1)
			releaseOutstanding()
			continue
		}

		resp, err := forwardTCP(upstreamAddr, queryToSend, cfg.TCPTimeout.D())
		if err != nil {
			// try other upstreams
			for _, pool := range upstreamPools {
				if pool.isHealthy() {
					resp, err = forwardTCP(pool.addr, queryToSend, cfg.TCPTimeout.D())
					if err == nil {
						break
					}
				}
			}
		}

		if resp == nil {
			servfail := makeServFail(query)
			writeTCPResponse(conn, servfail)
			releaseOutstanding()
			continue
		}

		if !validateDNSResponse(resp, binary.BigEndian.Uint16(query[0:2]), forwardQName, qtype, qclass) {
			droppedTotal.Add(1)
			servfail := makeServFail(query)
			writeTCPResponse(conn, servfail)
			releaseOutstanding()
			continue
		}

		flags := binary.BigEndian.Uint16(resp[2:4])
		flags &^= 0x0020
		binary.BigEndian.PutUint16(resp[2:4], flags)

		if shouldCache(resp, qtype) && !hasOPT(resp) {
			ttl := getMinTTL(resp)
			if ttl > 0 {
				cacheSet(cacheKey, resp, ttl)
			}
		}
		if decision.rewritten {
			translated, err := rewriteResponseNames(resp, forwardQNameLower, qname)
			if err != nil {
				writeTCPResponse(conn, makeServFail(query))
				releaseOutstanding()
				continue
			}
			resp = translated
			rewriteForwardedTotal.Add(1)
		}
		writeTCPResponse(conn, resp)
		forwardedTotal.Add(1)
		releaseOutstanding()
	}
}

func writeTCPResponse(conn *net.TCPConn, resp []byte) {
	if len(resp) > 65535 {
		return
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(resp)))
	if err := writeFull(conn, lenBuf[:]); err != nil {
		return
	}
	if err := writeFull(conn, resp); err != nil {
		return
	}
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

// ------------------------- Buffer Pool -------------------------

var packetPool = sync.Pool{}

func getPacketBuffer() []byte {
	buf := packetPool.Get()
	if buf == nil {
		return make([]byte, cfg.MaxPacketSize)
	}
	return buf.([]byte)
}

func putPacketBuffer(buf []byte) {
	packetPool.Put(buf)
}

// ------------------------- Main -------------------------

var version = "0.9.7-dev"

func main() {
	configPath := flag.String("config", "dnsrelay.json", "path to config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("dnshived-dnsrelay", version)
		os.Exit(0)
	}

	if err := loadConfig(*configPath); err != nil {
		log.Fatalf("load config: %v", err)
	}
	if err := loadUpstreams(); err != nil {
		log.Fatalf("load upstreams: %v", err)
	}

	if cfg.LogFile != "" {
		f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("open log: %v", err)
		}
		defer f.Close()
		logger = log.New(f, "", log.LstdFlags)
	} else {
		logger = log.New(os.Stdout, "", log.LstdFlags)
	}

	// init rate shards
	for i := range rateShards {
		rateShards[i] = newRateShard()
	}
	tcpConnPerSrc = make(map[string]int)
	initCacheShards()

	// register allowed interfaces
	initialIfaces := make(map[int]*ifaceInfo, len(cfg.AllowedInterfaces))
	for _, name := range cfg.AllowedInterfaces {
		idx, info, err := buildIfaceInfo(name)
		if err != nil {
			logger.Fatalf("%v", err)
		}
		initialIfaces[idx] = info
	}
	allowedIfaces.Store(&initialIfaces)

	// initialize semaphore
	outstandingSem = make(chan struct{}, cfg.MaxOutstanding)

	// create shutdown context
	shutdownCtx, shutdownCancel = context.WithCancel(context.Background())
	defer shutdownCancel()

	// create upstream pools
	for _, u := range upstreams {
		pool, err := newUpstreamPool(u, cfg.UpstreamSocketPoolSize, shutdownCtx)
		if err != nil {
			logger.Fatalf("failed to create upstream pool for %s: %v", u, err)
		}
		upstreamPools = append(upstreamPools, pool)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2)

	numWorkers := runtime.GOMAXPROCS(0) * 8
	jobs = make(chan udpJob, 1024)
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go udpWorker(&wg, jobs)
	}

	reconcileAddrSockets()
	addrRefreshInterval := cfg.AddrRefreshInterval.D()
	go addrSocketReconcileLoop(shutdownCtx, addrRefreshInterval)
	go statsFileLoop(shutdownCtx, 15*time.Second)

	logger.Printf("dnsrelay started: listen_port=%s upstreams=%v allowed_ifaces=%v cache_size=%d cache_max_bytes=%d max_outstanding=%d rate_scope=%s socket_pool=%d addr_refresh=%s cluster_rewrites=%d",
		cfg.ListenAddr, cfg.Upstreams, cfg.AllowedInterfaces, cfg.CacheSize, cfg.CacheMaxBytes, cfg.MaxOutstanding, cfg.RateLimitScope, cfg.UpstreamSocketPoolSize, addrRefreshInterval, len(cfg.Rewrites))

	for s := range sig {
		switch s {
		case syscall.SIGHUP:
			reloadInterfaces(*configPath)
			continue
		case syscall.SIGUSR1:
			entries, hits, misses, bytesUsed := cacheStats()
			total := hits + misses
			hitRate := 0.0
			if total > 0 {
				hitRate = float64(hits) / float64(total) * 100
			}
			if cfg.CacheMaxBytes > 0 {
				logger.Printf("[CACHE] entries=%d/%d bytes=%d/%d hits=%d misses=%d hit_rate=%.1f%%", entries, cfg.CacheSize, bytesUsed, cfg.CacheMaxBytes, hits, misses, hitRate)
			} else {
				logger.Printf("[CACHE] entries=%d/%d bytes=%d hits=%d misses=%d hit_rate=%.1f%%", entries, cfg.CacheSize, bytesUsed, hits, misses, hitRate)
			}
			continue
		case syscall.SIGUSR2:
			cleared := cacheFlushAll()
			logger.Printf("[CACHE] flushed %d entries", cleared)
			writeStatsFile() // don't leave the stats file showing pre-flush numbers for up to 15s
			continue
		}
		break
	}
	logger.Println("shutting down...")
	shutdownCancel()
	reconcileMu.Lock()
	for _, sock := range openSockets {
		closeAddrSocket(sock)
	}
	reconcileMu.Unlock()
	udpReaderWG.Wait()
	close(jobs)
	wg.Wait()
	logger.Printf("shutdown complete: queries=%d forwarded=%d dropped=%d rate_limited=%d acl_denied=%d rewrite_answered=%d rewrite_forwarded=%d cache_hits=%d cache_misses=%d replies=%d",
		queriesTotal.Load(), forwardedTotal.Load(), droppedTotal.Load(), rateLimitedTotal.Load(), aclDeniedTotal.Load(), rewriteAnsweredTotal.Load(), rewriteForwardedTotal.Load(), cacheHits.Load(), cacheMisses.Load(), repliesSent.Load())
}

// ------------------------- Config Loading -------------------------

func loadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "0.0.0.0:53"
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 100
	}
	if cfg.RateBurst <= 0 {
		cfg.RateBurst = cfg.RateLimit * 2
	}
	if cfg.InterfaceRateLimit <= 0 {
		cfg.InterfaceRateLimit = cfg.RateLimit * 10
	}
	if cfg.InterfaceRateBurst <= 0 {
		cfg.InterfaceRateBurst = cfg.InterfaceRateLimit * 2
	}
	if cfg.RateLimitScope == "" {
		cfg.RateLimitScope = "subnet"
	}
	if cfg.RateLimitScope != "subnet" && cfg.RateLimitScope != "host" {
		return fmt.Errorf("invalid rate_limit_scope: %q", cfg.RateLimitScope)
	}
	if cfg.UpstreamSocketPoolSize <= 0 {
		cfg.UpstreamSocketPoolSize = 16
	}
	if cfg.CacheSize <= 0 {
		cfg.CacheSize = 5000
	}
	if cfg.MaxOutstanding <= 0 {
		cfg.MaxOutstanding = 10000
	}
	if cfg.MaxTCPConnections <= 0 {
		cfg.MaxTCPConnections = 1000
	}
	if cfg.MaxTCPPerSource <= 0 {
		cfg.MaxTCPPerSource = 10
	}
	if cfg.Timeout.D() <= 0 {
		cfg.Timeout = Duration(2 * time.Second)
	}
	if cfg.TCPTimeout.D() <= 0 {
		cfg.TCPTimeout = Duration(5 * time.Second)
	}
	if cfg.MaxPacketSize <= 0 {
		cfg.MaxPacketSize = 4096
	}
	if cfg.MaxPacketSize > 65535 {
		cfg.MaxPacketSize = 65535
	}
	if cfg.AddrRefreshInterval.D() <= 0 {
		cfg.AddrRefreshInterval = Duration(2 * time.Second)
	}
	return nil
}

func loadUpstreams() error {
	for _, s := range cfg.Upstreams {
		s = strings.TrimSpace(s)
		host, port, err := net.SplitHostPort(s)
		if err != nil {
			host = s
			port = "53"
		}
		ip := net.ParseIP(host).To4()
		if ip == nil {
			return fmt.Errorf("invalid upstream IPv4 address: %q", s)
		}
		p, err := net.LookupPort("udp", port)
		if err != nil {
			return fmt.Errorf("invalid upstream port %q: %w", port, err)
		}
		if p != 53 {
			return fmt.Errorf("upstream DNS port must be 53, got %d", p)
		}
		upstreams = append(upstreams, &net.UDPAddr{IP: ip, Port: 53})
	}
	if len(upstreams) == 0 {
		return fmt.Errorf("no upstream DNS servers configured")
	}
	return nil
}

func ipToUint32(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip.To4())
}
