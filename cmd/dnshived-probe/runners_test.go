// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"dnshived/internal/config"
	"dnshived/internal/dhcpprobe"
	"dnshived/internal/dnsprobe"
	"dnshived/internal/eventlog"
)

func offerAt(server string, at time.Duration) dhcpprobe.Offer {
	return dhcpprobe.Offer{ServerID: net.ParseIP(server), YourIP: net.ParseIP("10.0.0.50"), At: at}
}

func TestMergeLeg_DNSAloneIsShownWhileDHCPIsPending(t *testing.T) {
	dns := ScopeProbeResult{Scope: "s1", Reachable: true, Enabled: true, DHCPPending: true, ProbedAt: time.Unix(100, 0)}
	dns.DNS.Answered, dns.DNS.Valid = true, true

	got := mergeLeg(ScopeProbeResult{}, false, legDNS, dns)

	if !got.DNS.Valid || !got.DHCPPending || got.DNSPending {
		t.Fatalf("got DNS.Valid=%v DHCPPending=%v DNSPending=%v, want the DNS result with DHCP pending", got.DNS.Valid, got.DHCPPending, got.DNSPending)
	}
	if !got.DHCPProbedAt.IsZero() || !got.DNSProbedAt.Equal(time.Unix(100, 0)) {
		t.Errorf("stamps dhcp=%v dns=%v, want zero and 100", got.DHCPProbedAt, got.DNSProbedAt)
	}
}

func TestMergeLeg_SecondLegKeepsTheFirstAndProbedAtIsTheNewer(t *testing.T) {
	dns := ScopeProbeResult{Scope: "s1", Reachable: true, Enabled: true, DHCPPending: true, ProbedAt: time.Unix(100, 0)}
	dns.DNS.Valid = true
	dhcp := ScopeProbeResult{Scope: "s1", Reachable: true, Enabled: true, DNSPending: true, ProbedAt: time.Unix(160, 0)}
	dhcp.DHCP.Verdict = "ok"

	got := mergeLeg(mergeLeg(ScopeProbeResult{}, false, legDNS, dns), true, legDHCP, dhcp)

	if !got.DNS.Valid || got.DHCP.Verdict != "ok" || got.DHCPPending || got.DNSPending {
		t.Fatalf("legs not both kept: %+v", got)
	}
	if !got.ProbedAt.Equal(time.Unix(160, 0)) {
		t.Errorf("ProbedAt = %v, want the newer leg stamp", got.ProbedAt)
	}
}

func TestMergeLeg_ScopeWithNoCoverageOrProbingOffCarriesNoLegs(t *testing.T) {
	for _, fresh := range []ScopeProbeResult{
		{Scope: "s1", ProbedAt: time.Unix(5, 0)},
		{Scope: "s1", Reachable: true, ProbedAt: time.Unix(5, 0)},
	} {
		fresh.DNSPending = true
		got := mergeLeg(ScopeProbeResult{}, false, legDHCP, fresh)
		if got.DHCPPending || got.DNSPending {
			t.Errorf("%+v: an inactive scope must not report pending legs", got)
		}
	}
}

func TestTracker_DNSLegNeverTouchesDHCPState(t *testing.T) {
	events := eventlog.New(20, "probe")
	tr := newProbeLogTracker(nil)
	fail := ScopeProbeResult{Scope: "s1", Reachable: true, Enabled: true, DNSPending: true}
	fail.DHCP.Verdict = "no_answer"
	tr.check(events, "s1", fail)

	dns := ScopeProbeResult{Scope: "s1", Reachable: true, Enabled: true, DHCPPending: true}
	dns.DNSChecks = []DNSCheckResult{{Name: "a.", Type: "A", Against: "x", Answered: true, Valid: true}}
	tr.check(events, "s1", dns)

	for _, ev := range events.Last(50) {
		if strings.Contains(ev.Prefix, "DHCP_OK") {
			t.Fatalf("a DNS leg logged %q: it must not reset the DHCP failure state", ev.Message)
		}
	}
	if tr.dhcp["s1"] == "" {
		t.Error("DHCP failure signature was cleared by a DNS-only leg")
	}
}

func TestDHCPWaitFor(t *testing.T) {
	tests := []struct {
		name string
		cfg  *ProbeConfig
		prev time.Duration
		want time.Duration
	}{
		{"first probe", &ProbeConfig{}, 0, dhcpFirstWait},
		{"fast offers never go below the ping-check floor", &ProbeConfig{}, 20 * time.Millisecond, dhcpWaitFloor},
		{"slow offers are capped", &ProbeConfig{}, 6 * time.Second, dhcpWaitCap},
		{"a 3 s offer gets room for a second ping-checked request ahead of it", &ProbeConfig{}, 3 * time.Second, 6500 * time.Millisecond},
		{"operator value wins", &ProbeConfig{DHCPWaitMS: 1200}, 3 * time.Second, 1200 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dhcpWaitFor(tt.cfg, tt.prev); got != tt.want {
				t.Errorf("dhcpWaitFor = %v, want %v", got, tt.want)
			}
		})
	}
}

func stubDHCP(t *testing.T, fn func(iface string, wait time.Duration, o dhcpprobe.Options) (dhcpprobe.Result, error)) {
	t.Helper()
	orig := dhcpProbeFn
	dhcpProbeFn = fn
	t.Cleanup(func() { dhcpProbeFn = orig })
}

func legitByNodeID() map[string]probeConfigResponse {
	return map[string]probeConfigResponse{
		"core-1": {NodeID: "core-1", Role: config.RoleCore1, Scopes: map[string]remoteScope{
			"s1": {VLANID: 100, NodeIP: "10.0.0.22/24", VIP: "10.0.0.1/24"},
		}},
	}
}

func TestRunDHCPLeg_StopsAtFirstOfferWithGrace(t *testing.T) {
	var calls int
	stubDHCP(t, func(iface string, wait time.Duration, o dhcpprobe.Options) (dhcpprobe.Result, error) {
		calls++
		if !o.StopOnFirstOffer || o.FirstOfferGrace != dhcpOfferGrace {
			t.Errorf("options %+v, want stop-on-first-offer with the %v grace", o, dhcpOfferGrace)
		}
		return dhcpprobe.Result{Verdict: dhcpprobe.VerdictOK, Servers: []string{"10.0.0.22"}, Offers: []dhcpprobe.Offer{offerAt("10.0.0.22", 40*time.Millisecond)}}, nil
	})
	tgt := scopeProbeTarget{name: "s1", parent: "ens19", iface: "ens19.100", vlanID: 100}

	tokens := map[string]tokenInfo{"s1": {Owner: "core-1"}}
	res, next := runDHCPLeg(&ProbeConfig{}, tgt, legitByNodeID(), tokens, dhcpHint{})

	if calls != 1 {
		t.Errorf("probe calls = %d, want 1", calls)
	}
	if !res.DNSPending || res.DHCPPending || res.DHCP.Verdict != "ok" || !res.DHCP.Valid {
		t.Errorf("leg result %+v, want the DHCP leg with DNS pending", res)
	}
	if next.latency != 40*time.Millisecond || next.silent || res.DHCP.OfferMS != 40 {
		t.Errorf("hint = %+v, want the offer latency remembered", next)
	}
}

func TestRunDHCPLeg_RetriesOnceUnlessTheScopeWasAlreadySilent(t *testing.T) {
	var waits []time.Duration
	stubDHCP(t, func(iface string, wait time.Duration, o dhcpprobe.Options) (dhcpprobe.Result, error) {
		waits = append(waits, wait)
		return dhcpprobe.Result{Verdict: dhcpprobe.VerdictNoAnswer}, nil
	})
	tgt := scopeProbeTarget{name: "s1", parent: "ens19", iface: "ens19.100", vlanID: 100}

	runDHCPLeg(&ProbeConfig{}, tgt, legitByNodeID(), nil, dhcpHint{silent: true})
	if len(waits) != 1 {
		t.Fatalf("a scope that was already silent got %d probes, want 1", len(waits))
	}
	waits = nil
	res, next := runDHCPLeg(&ProbeConfig{}, tgt, legitByNodeID(), nil, dhcpHint{latency: time.Second})
	if !next.silent {
		t.Error("hint must remember the silent scope, so the retry is not repeated every cycle")
	}
	if len(waits) != 2 || waits[1] != dhcpRetryWait {
		t.Fatalf("waits = %v, want a retry over %v", waits, dhcpRetryWait)
	}
	if res.DHCP.Verdict != "no_answer" {
		t.Errorf("verdict = %q, want no_answer after the retry", res.DHCP.Verdict)
	}
}

func TestRunDHCPLeg_UnexpectedServerIsProbedAgainOverTheFullWindow(t *testing.T) {
	var full bool
	stubDHCP(t, func(iface string, wait time.Duration, o dhcpprobe.Options) (dhcpprobe.Result, error) {
		if o.StopOnFirstOffer {
			return dhcpprobe.Result{Verdict: dhcpprobe.VerdictOK, Servers: []string{"10.0.0.99"}, Offers: []dhcpprobe.Offer{offerAt("10.0.0.99", 5*time.Millisecond)}}, nil
		}
		full = true
		return dhcpprobe.Result{
			Verdict: dhcpprobe.VerdictDualActive, Servers: []string{"10.0.0.22", "10.0.0.99"},
			Offers: []dhcpprobe.Offer{offerAt("10.0.0.99", 5*time.Millisecond), offerAt("10.0.0.22", 3*time.Second)},
		}, nil
	})
	tgt := scopeProbeTarget{name: "s1", parent: "ens19", iface: "ens19.100", vlanID: 100}

	res, _ := runDHCPLeg(&ProbeConfig{}, tgt, legitByNodeID(), nil, dhcpHint{})

	if !full {
		t.Fatal("an answer from a server the scope does not own must trigger the full-window probe")
	}
	if res.DHCP.Verdict != "dual_active" || len(res.DHCP.Servers) != 2 {
		t.Errorf("result %+v, want every answering server listed", res.DHCP)
	}
	if res.DHCP.Valid {
		t.Error("a rogue answer must stay invalid")
	}
}

func TestNextDue_NeverAttemptedFirstThenOldest(t *testing.T) {
	now := time.Now()
	att := map[string]time.Time{"a": now.Add(-10 * time.Second), "b": now.Add(-30 * time.Second)}
	name, due := nextDue([]string{"a", "b", "c"}, att, 20*time.Second)
	if name != "c" || !due.IsZero() {
		t.Fatalf("got %q due %v, want the never-attempted c, due at once", name, due)
	}
	att["c"] = now
	name, due = nextDue([]string{"a", "b", "c"}, att, 20*time.Second)
	if name != "b" || !due.Equal(att["b"].Add(20*time.Second)) {
		t.Fatalf("got %q due %v, want the oldest b", name, due)
	}
}

func planServer(t *testing.T, scopes map[string]remoteScope) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(probeConfigResponse{NodeID: "core-1", Role: config.RoleCore1, Scopes: scopes, Incarnation: 1})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func fakeIfaces(t *testing.T) {
	t.Helper()
	orig := ifaceExistsFn
	ifaceExistsFn = func(name string) (*net.Interface, error) { return &net.Interface{Name: name}, nil }
	t.Cleanup(func() { ifaceExistsFn = orig })
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRunners_DNSResultIsShownWhileDHCPIsStillRunning(t *testing.T) {
	fakeIfaces(t)
	release := make(chan struct{})
	stubDHCP(t, func(iface string, wait time.Duration, o dhcpprobe.Options) (dhcpprobe.Result, error) {
		<-release
		return dhcpprobe.Result{Verdict: dhcpprobe.VerdictNoAnswer}, nil
	})
	defer close(release)
	origDNS := dnsProbeFn
	dnsProbeFn = func(addr, qname, qtype string, timeout time.Duration) (dnsprobe.Result, error) {
		return dnsprobe.Result{Answered: true}, nil
	}
	defer func() { dnsProbeFn = origDNS }()

	srv := planServer(t, map[string]remoteScope{"s1": {Parent: "lo", VLANID: 100, NodeIP: "172.16.100.22/24"}})
	cfg := &ProbeConfig{TrunkParent: "lo", ClusterNodes: []ClusterNode{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	store := newResultStore()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rn := newProbeRunners(ctx, cfg, store, newProbeLogTracker(nil), eventlog.New(50, "probe"), newOwnershipDebounce())
	t.Cleanup(rn.stop)

	refreshProbePlan(cfg, rn, newIncarnationTracker())

	waitFor(t, "the DNS leg", func() bool { r, ok := store.get("s1"); return ok && !r.DNSPending })
	r, _ := store.get("s1")
	if !r.DHCPPending || !r.DHCPProbedAt.IsZero() || r.DNSProbedAt.IsZero() {
		t.Fatalf("record %+v: DNS must be visible while DHCP is pending, with its own stamp", r)
	}
}

func TestRunners_OneDHCPAndOneDNSRunnerPerInterfaceAndRetiredWithIt(t *testing.T) {
	fakeIfaces(t)
	scopes := map[string]remoteScope{
		"a": {Parent: "ens19", VLANID: 10, NodeIP: "10.0.10.22/24", ProbeDisabled: true},
		"b": {Parent: "ens20", VLANID: 11, NodeIP: "10.0.11.22/24", ProbeDisabled: true},
		"c": {Parent: "ens20", VLANID: 12, NodeIP: "10.0.12.22/24", ProbeDisabled: true},
	}
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		json.NewEncoder(w).Encode(probeConfigResponse{NodeID: "core-1", Role: config.RoleCore1, Scopes: scopes, Incarnation: 1})
	}))
	defer srv.Close()
	cfg := &ProbeConfig{TrunkParent: "ens19", TrunkParents: []string{"ens19", "ens20"}, ClusterNodes: []ClusterNode{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rn := newProbeRunners(ctx, cfg, newResultStore(), newProbeLogTracker(nil), eventlog.New(50, "probe"), newOwnershipDebounce())
	t.Cleanup(rn.stop)
	inc := newIncarnationTracker()

	refreshProbePlan(cfg, rn, inc)
	if got := rn.runnerCount(); got != 4 {
		t.Fatalf("runnerCount = %d, want 4 (2 interfaces x DHCP and DNS)", got)
	}

	mu.Lock()
	delete(scopes, "b")
	delete(scopes, "c")
	mu.Unlock()
	refreshProbePlan(cfg, rn, inc)
	if got := rn.runnerCount(); got != 2 {
		t.Fatalf("runnerCount = %d after ens20 lost its scopes, want 2", got)
	}
}

func TestRunners_ScopeOnAnInterfaceThisHostDoesNotServeHasNoCoverageAndNoRunner(t *testing.T) {
	fakeIfaces(t)
	srv := planServer(t, map[string]remoteScope{"x": {Parent: "eth9", VLANID: 5, NodeIP: "10.0.5.22/24"}})
	cfg := &ProbeConfig{TrunkParent: "ens19", TrunkParents: []string{"ens19"}, ClusterNodes: []ClusterNode{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	store := newResultStore()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rn := newProbeRunners(ctx, cfg, store, newProbeLogTracker(nil), eventlog.New(50, "probe"), newOwnershipDebounce())
	t.Cleanup(rn.stop)

	refreshProbePlan(cfg, rn, newIncarnationTracker())

	if rn.runnerCount() != 0 {
		t.Errorf("runnerCount = %d, want 0 for an interface outside trunk_parents", rn.runnerCount())
	}
	r, ok := store.get("x")
	if !ok || r.Reachable || r.DHCPPending || r.DNSPending {
		t.Errorf("record %+v ok=%v, want a no-coverage record", r, ok)
	}
}

func TestRunDHCPLeg_OwnershipMismatchOfAKnownServerIsNotProbedAgain(t *testing.T) {
	var calls int
	stubDHCP(t, func(iface string, wait time.Duration, o dhcpprobe.Options) (dhcpprobe.Result, error) {
		calls++
		return dhcpprobe.Result{Verdict: dhcpprobe.VerdictOK, Servers: []string{"10.0.0.22"}, Offers: []dhcpprobe.Offer{offerAt("10.0.0.22", time.Millisecond)}}, nil
	})
	tgt := scopeProbeTarget{name: "s1", parent: "ens19", iface: "ens19.100", vlanID: 100}

	res, _ := runDHCPLeg(&ProbeConfig{}, tgt, legitByNodeID(), nil, dhcpHint{})

	if calls != 1 {
		t.Errorf("probe calls = %d, want 1 — a known server with no token is an ownership question, not a rogue", calls)
	}
	if res.DHCP.Valid {
		t.Error("result must stay invalid (no arbiter token)")
	}
}

func TestProbeConfig_MgmtInterfaceServesButIsNeverATrunk(t *testing.T) {
	cfg := &ProbeConfig{TrunkParent: "ens19", TrunkParents: []string{"ens19", "ens20"}, MgmtInterface: "ens18"}
	if got := strings.Join(cfg.trunkParents(), ","); got != "ens19,ens20" {
		t.Errorf("trunkParents = %s, want the workers only: no VLAN is ever built on the management interface", got)
	}
	if got := strings.Join(cfg.servingParents(), ","); got != "ens19,ens20,ens18" {
		t.Errorf("servingParents = %s, want the workers then the management interface", got)
	}
	single := &ProbeConfig{TrunkParent: "ens18", MgmtInterface: "ens18"}
	if len(single.trunkParents()) != 0 || strings.Join(single.servingParents(), ",") != "ens18" {
		t.Errorf("one-NIC install: trunks %v serving %v, want no trunk and the one NIC serving", single.trunkParents(), single.servingParents())
	}
	old := &ProbeConfig{TrunkParent: "ens19"}
	if strings.Join(old.servingParents(), ",") != "ens19" {
		t.Errorf("a config without mgmt_interface must behave as before, got %v", old.servingParents())
	}
}

func TestDesiredVLANs_NeverPlansAnythingOnTheManagementInterface(t *testing.T) {
	cfg := &ProbeConfig{TrunkParent: "ens19", MgmtInterface: "ens18"}
	byNodeID := map[string]probeConfigResponse{"core-1": {Scopes: map[string]remoteScope{
		"office": {Parent: "ens19", VLANID: 100, VIP: "10.0.100.1/24"},
		"mgmt-s": {Parent: "ens18", VLANID: 0, VIP: "10.0.1.1/24"},
	}}}

	got := desiredVLANs(byNodeID, cfg.trunkParents())

	if len(got) != 1 {
		t.Fatalf("desired = %v, want only the worker VLAN: the management interface is never created, changed or removed", got)
	}
}

func TestRunners_ScopeOnTheManagementInterfaceGetsRunnersAndAStableDerivedMAC(t *testing.T) {
	fakeIfaces(t)
	var mu sync.Mutex
	var macs []net.HardwareAddr
	stubDHCP(t, func(iface string, wait time.Duration, o dhcpprobe.Options) (dhcpprobe.Result, error) {
		mu.Lock()
		macs = append(macs, o.MAC)
		mu.Unlock()
		return dhcpprobe.Result{Verdict: dhcpprobe.VerdictNoAnswer}, nil
	})
	srv := planServer(t, map[string]remoteScope{"m": {Parent: "ens18", VLANID: 0, NodeIP: "10.0.1.22/24"}})
	cfg := &ProbeConfig{TrunkParent: "ens18", MgmtInterface: "ens18", ClusterNodes: []ClusterNode{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	store := newResultStore()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rn := newProbeRunners(ctx, cfg, store, newProbeLogTracker(nil), eventlog.New(50, "probe"), newOwnershipDebounce())
	t.Cleanup(rn.stop)

	refreshProbePlan(cfg, rn, newIncarnationTracker())

	if rn.runnerCount() != 2 {
		t.Fatalf("runnerCount = %d, want one DHCP and one DNS runner for the management interface", rn.runnerCount())
	}
	waitFor(t, "the DHCP leg", func() bool { r, ok := store.get("m"); return ok && !r.DHCPPending })
	mu.Lock()
	defer mu.Unlock()
	for _, m := range macs {
		if len(m) != 6 || m[0]&0x02 == 0 || !bytes.Equal(m, stableMAC("scope|m")) {
			t.Errorf("DHCP probe on the management interface used MAC %v, want the stable derived one (not the NIC's own)", m)
		}
	}
}
