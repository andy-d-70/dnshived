// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// TestReloadKeepalived_Throttled checks a reload suppressed by the 1s rate
// limit reports throttled=true, never a silent success.
func TestReloadKeepalived_Throttled(t *testing.T) {
	reloadMu.Lock()
	lastReloadAt = time.Now()
	reloadMu.Unlock()

	throttled, err := reloadKeepalived()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !throttled {
		t.Errorf("throttled = false, want true — a reload within 1s of the last one must be reported as suppressed, not silently treated as applied")
	}
}

// TestReloadKeepalived_NotThrottledAfterWindow verifies the rate limit
// itself doesn't fire once the 1s window has passed.
func TestReloadKeepalived_NotThrottledAfterWindow(t *testing.T) {
	reloadMu.Lock()
	lastReloadAt = time.Now().Add(-2 * time.Second)
	reloadMu.Unlock()

	throttled, _ := reloadKeepalived()
	if throttled {
		t.Errorf("throttled = true, want false — reload should not be rate-limited once the 1s window has passed")
	}
}

// TestRestartDnsmasq_Throttled pins the same "throttled means not applied"
// contract as reload-keepalived, but for restart-dnsmasq.
func TestRestartDnsmasq_Throttled(t *testing.T) {
	restartMu.Lock()
	lastRestartAt["office"] = time.Now()
	restartMu.Unlock()

	throttled, err := restartDnsmasq(Request{Scope: "office"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !throttled {
		t.Errorf("throttled = false, want true — a restart within 5s of the last one for the same scope must be reported as suppressed")
	}
}

// TestRestartDnsmasq_NotThrottledAfterWindow verifies the rate limit
// doesn't fire once the 5s window has passed.
func TestRestartDnsmasq_NotThrottledAfterWindow(t *testing.T) {
	restartMu.Lock()
	lastRestartAt["office"] = time.Now().Add(-6 * time.Second)
	restartMu.Unlock()

	throttled, _ := restartDnsmasq(Request{Scope: "office"})
	if throttled {
		t.Errorf("throttled = true, want false — restart should not be rate-limited once the 5s window has passed")
	}
}

func TestRestartDnsmasq_ScopesIndependentlyRateLimited(t *testing.T) {
	restartMu.Lock()
	lastRestartAt["office"] = time.Now()
	delete(lastRestartAt, "av-dante")
	restartMu.Unlock()

	throttled, _ := restartDnsmasq(Request{Scope: "av-dante"})
	if throttled {
		t.Error("throttled = true for a scope with no prior restart — must not be affected by a different scope's rate limit")
	}
}

// TestRestartDaemon_Throttled pins the same "throttled means not applied"
// contract, at the 10s tier.
func TestRestartDaemon_Throttled(t *testing.T) {
	daemonRestartMu.Lock()
	lastDaemonRestartAt = time.Now()
	daemonRestartMu.Unlock()

	throttled, err := restartDaemon()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !throttled {
		t.Errorf("throttled = false, want true — a restart within 10s of the last one must be reported as suppressed")
	}
}

// TestRestartDaemon_NotThrottledAfterWindow verifies the rate limit
// doesn't fire once the 10s window has passed.
func TestRestartDaemon_NotThrottledAfterWindow(t *testing.T) {
	daemonRestartMu.Lock()
	lastDaemonRestartAt = time.Now().Add(-11 * time.Second)
	daemonRestartMu.Unlock()

	throttled, _ := restartDaemon()
	if throttled {
		t.Errorf("throttled = true, want false — restart should not be rate-limited once the 10s window has passed")
	}
}

func TestRestartMgmtKeepalived_Throttled(t *testing.T) {
	mgmtRestartMu.Lock()
	lastMgmtRestartAt = time.Now()
	mgmtRestartMu.Unlock()

	throttled, err := restartMgmtKeepalived()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !throttled {
		t.Errorf("throttled = false, want true — a restart within 5s of the last one must be reported as suppressed")
	}
}

// TestRestartMgmtKeepalived_NotThrottledAfterWindow verifies the rate
// limit doesn't fire once the 5s window has passed.
func TestRestartMgmtKeepalived_NotThrottledAfterWindow(t *testing.T) {
	mgmtRestartMu.Lock()
	lastMgmtRestartAt = time.Now().Add(-6 * time.Second)
	mgmtRestartMu.Unlock()

	throttled, _ := restartMgmtKeepalived()
	if throttled {
		t.Errorf("throttled = true, want false — restart should not be rate-limited once the 5s window has passed")
	}
}

// TestRestartWeb_Throttled/NotThrottledAfterWindow pin the same contract
// at the same 5s tier as restart-mgmt-keepalived.
func TestRestartWeb_Throttled(t *testing.T) {
	webRestartMu.Lock()
	lastWebRestartAt = time.Now()
	webRestartMu.Unlock()

	throttled, err := restartWeb()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !throttled {
		t.Errorf("throttled = false, want true — a restart within 5s of the last one must be reported as suppressed")
	}
}

func TestRestartWeb_NotThrottledAfterWindow(t *testing.T) {
	webRestartMu.Lock()
	lastWebRestartAt = time.Now().Add(-6 * time.Second)
	webRestartMu.Unlock()

	throttled, _ := restartWeb()
	if throttled {
		t.Errorf("throttled = true, want false — restart should not be rate-limited once the 5s window has passed")
	}
}

func TestHelperSelfRestartThrottled_Throttled(t *testing.T) {
	helperRestartMu.Lock()
	lastHelperRestartAt = time.Now()
	helperRestartMu.Unlock()

	if !helperSelfRestartThrottled() {
		t.Error("expected throttled = true for a restart within 10s of the last one")
	}
}

func TestHelperSelfRestartThrottled_NotThrottledAfterWindow(t *testing.T) {
	helperRestartMu.Lock()
	lastHelperRestartAt = time.Now().Add(-11 * time.Second)
	helperRestartMu.Unlock()

	if helperSelfRestartThrottled() {
		t.Error("expected throttled = false once the 10s window has passed")
	}
}

func TestHandleConn_RestartHelper_RespondsBeforeSelfRestarting(t *testing.T) {
	helperRestartMu.Lock()
	lastHelperRestartAt = time.Time{}
	helperRestartMu.Unlock()

	server, client := net.Pipe()
	defer client.Close()
	go handleConn(server)

	if err := json.NewEncoder(client).Encode(Request{Command: "restart-helper"}); err != nil {
		t.Fatalf("encode request: %v", err)
	}

	type result struct {
		resp Response
		err  error
	}
	done := make(chan result, 1)
	go func() {
		var r result
		r.err = json.NewDecoder(client).Decode(&r.resp)
		done <- r
	}()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("decode response: %v", r.err)
		}
		if !r.resp.OK {
			t.Errorf("resp.OK = false, want true (throttled=%v)", r.resp.Throttled)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a response — restart-helper must respond BEFORE triggering its own restart, not after")
	}
}

func TestScopedCommands_ReloadCoreDHCPIsUnscoped(t *testing.T) {
	if scopedCommands["reload-core-dhcp"] {
		t.Error("reload-core-dhcp must never be in scopedCommands — it targets the reserved core-dhcp instance, not a real configured scope")
	}
}

// TestScopedCommands_ReloadCoreDNSIsUnscoped is reload-core-dhcp's own
// sibling for the DHCP-name-to-DNS sync path's own reload target —
// identical reasoning.
func TestScopedCommands_ReloadCoreDNSIsUnscoped(t *testing.T) {
	if scopedCommands["reload-core-dns"] {
		t.Error("reload-core-dns must never be in scopedCommands — it targets the reserved core-dns instance, not a real configured scope")
	}
}

// TestScopedCommands_JournalTailIsUnscoped guards the same invariant as
// reload-core-dhcp/reload-core-dns above, for journal-tail's own Unit
// field.
func TestScopedCommands_JournalTailIsUnscoped(t *testing.T) {
	if scopedCommands["journal-tail"] {
		t.Error("journal-tail must never be in scopedCommands — it targets a fixed unit name, not a configured scope")
	}
}

// TestScopedCommands_GetMgmtVRRPStateIsUnscoped mirrors vrrp-dump's own
// exclusion.
func TestScopedCommands_GetMgmtVRRPStateIsUnscoped(t *testing.T) {
	if scopedCommands["get-mgmt-vrrp-state"] {
		t.Error("get-mgmt-vrrp-state must never be in scopedCommands — it reads node-wide state, not a real configured scope")
	}
}

func TestGetJournalTail_RejectsUnlistedUnit(t *testing.T) {
	_, err := getJournalTail(Request{Command: "journal-tail", Unit: "sshd.service"})
	if err == nil {
		t.Fatal("expected an error for a unit outside allowedJournalUnits, got nil")
	}
}

// TestGetJournalTail_AllowsRealUnits confirms every unit this project
// actually ships is in the allowlist.
func TestGetJournalTail_AllowsRealUnits(t *testing.T) {
	for _, u := range []string{
		"dnshived.service", "dnshived-web.service", "dnshived-helper.service",
		"dnshived-relay.service", "dnshived-dnsrelay.service",
		"dnshived-keepalived.service", "dnshived-keepalived-mgmt.service",
	} {
		if !allowedJournalUnits[u] {
			t.Errorf("expected %s in allowedJournalUnits", u)
		}
	}
}

func TestParseScopeAllowlist_EmptyInputYieldsEmptyNonNilMap(t *testing.T) {
	got := parseScopeAllowlist("")
	if got == nil {
		t.Fatal("parseScopeAllowlist(\"\") returned nil, want a non-nil empty map — a nil map is still safe to read from, but an explicit empty map matches the documented \"valid, supported state\" intent")
	}
	if len(got) != 0 {
		t.Errorf("parseScopeAllowlist(\"\") = %v, want empty", got)
	}
}

func TestParseScopeAllowlist_TrimsWhitespaceAndSkipsBlankEntries(t *testing.T) {
	got := parseScopeAllowlist(" office , av-dante ,, rw-100")
	want := map[string]bool{"office": true, "av-dante": true, "rw-100": true}
	if len(got) != len(want) {
		t.Fatalf("parseScopeAllowlist(...) = %v, want %v", got, want)
	}
	for name := range want {
		if !got[name] {
			t.Errorf("parseScopeAllowlist(...) missing %q", name)
		}
	}
}

func resetAllowlistState(t *testing.T, seed map[string]bool) {
	t.Helper()
	allowedScopesMu.Lock()
	allowedScopes = seed
	allowedScopesMu.Unlock()
	stateDir = t.TempDir()
}

func TestAddScopes_GrowsAllowlistAndPersists(t *testing.T) {
	resetAllowlistState(t, map[string]bool{"rw-100": true})

	if err := addScopes(Request{Scopes: []string{"rw-140", "rw-141"}}); err != nil {
		t.Fatalf("addScopes: %v", err)
	}

	allowedScopesMu.RLock()
	got := allowedScopes["rw-140"] && allowedScopes["rw-141"] && allowedScopes["rw-100"]
	allowedScopesMu.RUnlock()
	if !got {
		t.Fatalf("expected rw-100 (pre-existing), rw-140, rw-141 all allowed, got %v", allowedScopes)
	}

	persisted := loadPersistedScopes(stateDir)
	if !persisted["rw-140"] || !persisted["rw-141"] {
		t.Errorf("expected the new names persisted to disk, got %v", persisted)
	}
}

func TestAddScopes_NeverShrinksAcrossARestart(t *testing.T) {
	dir := t.TempDir()
	resetAllowlistState(t, map[string]bool{"rw-100": true})
	stateDir = dir
	if err := addScopes(Request{Scopes: []string{"rw-140"}}); err != nil {
		t.Fatalf("addScopes: %v", err)
	}

	fresh := map[string]bool{"rw-100": true}
	for name := range loadPersistedScopes(dir) {
		fresh[name] = true
	}
	if !fresh["rw-140"] {
		t.Errorf("expected rw-140 to survive a simulated restart via the persisted file, got %v", fresh)
	}
}

// TestAddScopes_RejectsInvalidNames confirms the defense-in-depth format
// check.
func TestAddScopes_RejectsInvalidNames(t *testing.T) {
	resetAllowlistState(t, map[string]bool{})
	if err := addScopes(Request{Scopes: []string{"../../etc/cron.d/x"}}); err == nil {
		t.Error("expected an error for a path-traversal-shaped scope name")
	}
	allowedScopesMu.RLock()
	_, exists := allowedScopes["../../etc/cron.d/x"]
	allowedScopesMu.RUnlock()
	if exists {
		t.Error("invalid name must never be added to the allowlist")
	}
}

// TestAddScopes_AlreadyAllowedIsHarmlessNoOp confirms idempotence.
func TestAddScopes_AlreadyAllowedIsHarmlessNoOp(t *testing.T) {
	resetAllowlistState(t, map[string]bool{"rw-100": true})
	if err := addScopes(Request{Scopes: []string{"rw-100"}}); err != nil {
		t.Fatalf("addScopes on an already-allowed name should be a harmless no-op, got: %v", err)
	}
}

func TestPersistedScopes_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := map[string]bool{"rw-140": true, "rw-141": true}
	if err := savePersistedScopes(dir, want); err != nil {
		t.Fatalf("save: %v", err)
	}
	got := loadPersistedScopes(dir)
	if len(got) != len(want) || !got["rw-140"] || !got["rw-141"] {
		t.Errorf("round trip mismatch: got %v, want %v", got, want)
	}
}

func TestLoadPersistedScopes_MissingFileToleratedAsEmpty(t *testing.T) {
	got := loadPersistedScopes(filepath.Join(t.TempDir(), "does-not-exist"))
	if got != nil {
		t.Errorf("expected nil for a missing persisted-scopes file, got %v", got)
	}
}

func TestHasIPv4(t *testing.T) {
	v4 := &net.IPNet{IP: net.ParseIP("192.168.0.51"), Mask: net.CIDRMask(24, 32)}
	v6 := &net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)}
	if hasIPv4(nil) || hasIPv4([]net.Addr{v6}) {
		t.Error("no IPv4 address must report false")
	}
	if !hasIPv4([]net.Addr{v6, v4}) {
		t.Error("an IPv4 address must report true")
	}
}
