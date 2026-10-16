// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package nftgate

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// resetCache clears package-level cache state between tests.
func resetCache(t *testing.T) {
	t.Helper()
	resetCacheState()
	orig := listRulesFreshFn
	t.Cleanup(func() {
		listRulesFreshFn = orig
		resetCacheState()
	})
}

func resetCacheState() {
	cacheMu.Lock()
	cachedRules = nil
	cachedAt = time.Time{}
	inFlight = nil
	inFlightErr = nil
	cacheMu.Unlock()
}

func TestCheckIfaceName_AcceptsRealisticNames(t *testing.T) {
	valid := []string{"ens19.100", "eth0", "br-lan", "ens19_100", "a", "eth0.4094"}
	for _, name := range valid {
		if err := CheckIfaceName(name); err != nil {
			t.Errorf("CheckIfaceName(%q) = %v, want nil", name, err)
		}
	}
}

func TestCheckIfaceName_RejectsLiveDemonstratedInjection(t *testing.T) {
	malicious := "lo udp dport 9999 accept ; add rule inet dnshived dhcp_gate iif lo"
	if err := CheckIfaceName(malicious); err == nil {
		t.Error("expected the live-demonstrated injection payload to be rejected")
	}
}

func TestCheckIfaceName_RejectsOtherUnsafeShapes(t *testing.T) {
	invalid := []string{
		"",
		"eth0 eth1",           // embedded space
		"eth0;drop",           // embedded statement separator
		"eth0\nadd rule",      // embedded newline
		"1234567890123456789", // exceeds IFNAMSIZ-1 (15 chars)
		"eth0/24",             // not a valid interface character
	}
	for _, name := range invalid {
		if err := CheckIfaceName(name); err == nil {
			t.Errorf("CheckIfaceName(%q) = nil, want a rejection error", name)
		}
	}
}

// TestEnsureClosed_RejectsUnsafeIfaceBeforeAnyLookup confirms the check
// runs BEFORE any exec/lookup is attempted.
func TestEnsureClosed_RejectsUnsafeIfaceBeforeAnyLookup(t *testing.T) {
	resetCache(t)
	called := false
	listRulesFreshFn = func() (map[string]int, error) {
		called = true
		return map[string]int{}, nil
	}
	if err := EnsureClosed("eth0 ; drop"); err == nil {
		t.Error("expected EnsureClosed to reject an unsafe interface name")
	}
	if called {
		t.Error("EnsureClosed must reject an unsafe name before ever consulting the rule lister")
	}
}

func TestOpen_RejectsUnsafeIfaceBeforeAnyLookup(t *testing.T) {
	resetCache(t)
	called := false
	listRulesFreshFn = func() (map[string]int, error) {
		called = true
		return map[string]int{}, nil
	}
	if err := Open("eth0 ; drop"); err == nil {
		t.Error("expected Open to reject an unsafe interface name")
	}
	if called {
		t.Error("Open must reject an unsafe name before ever consulting the rule lister")
	}
}

func TestRemoveRule_RejectsUnsafeIface(t *testing.T) {
	if err := RemoveRule("eth0 ; drop"); err == nil {
		t.Error("expected RemoveRule to reject an unsafe interface name")
	}
}

func TestIsClosed_RejectsUnsafeIface(t *testing.T) {
	if _, err := IsClosed("eth0 ; drop"); err == nil {
		t.Error("expected IsClosed to reject an unsafe interface name")
	}
}

// TestListRulesCached_ReusesRecentListing pins the actual optimization: a
// second call within cacheTTL must not hit the (fake) lister again.
func TestListRulesCached_ReusesRecentListing(t *testing.T) {
	resetCache(t)
	calls := 0
	listRulesFreshFn = func() (map[string]int, error) {
		calls++
		return map[string]int{"ens19.100": 7}, nil
	}

	for i := 0; i < 5; i++ {
		rules, err := listRulesCached()
		if err != nil {
			t.Fatalf("listRulesCached: %v", err)
		}
		if rules["ens19.100"] != 7 {
			t.Errorf("call %d: rules[ens19.100] = %d, want 7", i, rules["ens19.100"])
		}
	}
	if calls != 1 {
		t.Errorf("underlying lister called %d times, want 1 — repeated calls within cacheTTL should reuse the cached listing", calls)
	}
}

func TestListRulesCached_RefreshesAfterTTL(t *testing.T) {
	resetCache(t)
	calls := 0
	listRulesFreshFn = func() (map[string]int, error) {
		calls++
		return map[string]int{"ens19.100": calls}, nil
	}

	if _, err := listRulesCached(); err != nil {
		t.Fatalf("listRulesCached: %v", err)
	}

	// Force the cache to look expired without a real sleep.
	cacheMu.Lock()
	cachedAt = time.Now().Add(-2 * cacheTTL)
	cacheMu.Unlock()

	rules, err := listRulesCached()
	if err != nil {
		t.Fatalf("listRulesCached: %v", err)
	}
	if calls != 2 {
		t.Errorf("underlying lister called %d times, want 2 — an expired cache must trigger a fresh listing", calls)
	}
	if rules["ens19.100"] != 2 {
		t.Errorf("rules[ens19.100] = %d, want 2 (the fresh listing's value)", rules["ens19.100"])
	}
}

// TestInvalidateCache_ForcesFreshListing checks the next read after a
// mutating nft call never sees a stale pre-write snapshot.
func TestInvalidateCache_ForcesFreshListing(t *testing.T) {
	resetCache(t)
	calls := 0
	listRulesFreshFn = func() (map[string]int, error) {
		calls++
		return map[string]int{"ens19.100": calls}, nil
	}

	if _, err := listRulesCached(); err != nil {
		t.Fatalf("listRulesCached: %v", err)
	}
	if _, err := listRulesCached(); err != nil {
		t.Fatalf("listRulesCached: %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d before invalidation, want 1", calls)
	}

	invalidateCache()

	if _, err := listRulesCached(); err != nil {
		t.Fatalf("listRulesCached: %v", err)
	}
	if calls != 2 {
		t.Errorf("underlying lister called %d times after invalidateCache, want 2 — a write must force the next read to be fresh", calls)
	}
}

func TestListRulesFresh_ParsesRealNftJSON(t *testing.T) {
	sample := `{"nftables": [
		{"metainfo": {"version": "1.0.6"}},
		{"table": {"family": "inet", "name": "dnshived"}},
		{"chain": {"family": "inet", "table": "dnshived", "name": "dhcp_gate"}},
		{"rule": {"family": "inet", "table": "dnshived", "chain": "dhcp_gate", "handle": 3,
			"expr": [
				{"match": {"op": "==", "left": {"meta": {"key": "iif"}}, "right": "ens19.100"}},
				{"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 67}},
				{"drop": null}
			]}},
		{"rule": {"family": "inet", "table": "dnshived", "chain": "dhcp_gate", "handle": 9,
			"expr": [
				{"match": {"op": "==", "left": {"meta": {"key": "iif"}}, "right": "ens19.101"}},
				{"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 67}},
				{"drop": null}
			]}}
	]}`

	var result listResult
	if err := json.Unmarshal([]byte(sample), &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	rules := rulesFromListResult(result)
	if len(rules) != 2 {
		t.Fatalf("len(rules) = %d, want 2", len(rules))
	}
	if rules["ens19.100"] != 3 {
		t.Errorf("rules[ens19.100] = %d, want 3", rules["ens19.100"])
	}
	if rules["ens19.101"] != 9 {
		t.Errorf("rules[ens19.101] = %d, want 9", rules["ens19.101"])
	}
}

func TestListRulesCached_ConcurrentCallsSingleFlightToOneRealFetch(t *testing.T) {
	resetCache(t)

	var fetchCount atomic.Int32
	release := make(chan struct{})
	listRulesFreshFn = func() (map[string]int, error) {
		fetchCount.Add(1)
		<-release // hold every concurrent caller here until released together
		return map[string]int{"ens19.100": 1}, nil
	}

	const callers = 20
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make([]map[string]int, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			rules, err := listRulesCached()
			if err != nil {
				t.Errorf("caller %d: unexpected error: %v", i, err)
				return
			}
			results[i] = rules
		}(i)
	}

	close(start)
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := fetchCount.Load(); got != 1 {
		t.Errorf("real fetches = %d, want exactly 1 — %d concurrent callers should single-flight to one real nft call", got, callers)
	}
	for i, r := range results {
		if r["ens19.100"] != 1 {
			t.Errorf("caller %d got %v, want the single fetch's real result", i, r)
		}
	}
}

// TestDump_ReturnsClosedIfaceSet pins nftgate.Dump's own contract.
func TestDump_ReturnsClosedIfaceSet(t *testing.T) {
	orig := listRulesFreshFn
	t.Cleanup(func() { listRulesFreshFn = orig })
	listRulesFreshFn = func() (map[string]int, error) {
		return map[string]int{"ens19.100": 3, "ens20.7": 9}, nil
	}

	closed, err := Dump()
	if err != nil {
		t.Fatalf("Dump: %v", err)
	}
	if len(closed) != 2 || !closed["ens19.100"] || !closed["ens20.7"] {
		t.Errorf("Dump() = %v, want both gated ifaces present and true", closed)
	}
	if closed["ens19.999"] {
		t.Error("Dump() reported a non-gated iface as closed")
	}
}
