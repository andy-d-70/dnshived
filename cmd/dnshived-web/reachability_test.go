// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// freshReachability returns an isolated nodeReachability, not the shared
// package-level var.
func freshReachability() *nodeReachability {
	return &nodeReachability{dead: make(map[string]time.Time), fallback: make(map[string]string), failStreak: make(map[string]int)}
}

// markDeadForTest drives markDead to an actually-dead state
// (deadStreakThreshold consecutive calls).
func markDeadForTest(r *nodeReachability, addr string) {
	for i := 0; i < deadStreakThreshold; i++ {
		r.markDead(addr)
	}
}

func TestNodeReachability_NotDeadUntilMarked(t *testing.T) {
	r := freshReachability()
	if r.isDead("10.0.0.1:9443") {
		t.Error("isDead() = true for an address never marked at all")
	}
}

func TestNodeReachability_MarkDeadThenAlive(t *testing.T) {
	r := freshReachability()
	markDeadForTest(r, "10.0.0.1:9443")
	if !r.isDead("10.0.0.1:9443") {
		t.Error("isDead() = false after deadStreakThreshold consecutive markDead() calls")
	}
	r.markAlive("10.0.0.1:9443")
	if r.isDead("10.0.0.1:9443") {
		t.Error("isDead() = true after markAlive() cleared it")
	}
}

func TestNodeReachability_MarkDeadDebounced(t *testing.T) {
	r := freshReachability()
	r.markDead("10.0.0.1:9443")
	if r.isDead("10.0.0.1:9443") {
		t.Error("isDead() = true after a single markDead() call — must be debounced, not immediate")
	}
	r.markAlive("10.0.0.1:9443") // a success resets the streak
	r.markDead("10.0.0.1:9443")
	if r.isDead("10.0.0.1:9443") {
		t.Error("isDead() = true after only 1 failure post-reset — streak must have been reset by markAlive()")
	}
	r.markDead("10.0.0.1:9443")
	if !r.isDead("10.0.0.1:9443") {
		t.Error("isDead() = false after 2 genuinely consecutive failures — should now be confirmed dead")
	}
}

func TestNodeReachability_RecheckIntervalElapses(t *testing.T) {
	r := freshReachability()
	r.dead["10.0.0.1:9443"] = time.Now().Add(-deadRecheckInterval - time.Second)
	if r.isDead("10.0.0.1:9443") {
		t.Error("isDead() = true for a mark older than deadRecheckInterval — must allow a real re-check")
	}
}

func TestNodeReachability_RecheckIntervalNotYetElapsed(t *testing.T) {
	r := freshReachability()
	r.dead["10.0.0.1:9443"] = time.Now().Add(-time.Second)
	if !r.isDead("10.0.0.1:9443") {
		t.Error("isDead() = false for a mark well within deadRecheckInterval")
	}
}

func TestNodeReachability_ObservePeerReport_TransitiveRecovery(t *testing.T) {
	r := freshReachability()
	markDeadForTest(r, "10.0.0.24:9443")

	r.observePeerReport([]string{"10.0.0.24:9443"}, nil, nil) // a peer now reports it visible

	if r.isDead("10.0.0.24:9443") {
		t.Error("isDead() = true after a peer reported the address visible again — transitive recovery must clear it")
	}
}

func TestNodeReachability_ObservePeerReport_MarksUnreachable(t *testing.T) {
	r := freshReachability()
	r.observePeerReport(nil, []string{"10.0.0.24:9443"}, nil)
	if !r.isDead("10.0.0.24:9443") {
		t.Error("isDead() = false after a peer reported the address unreachable")
	}
}

func TestNodeReachability_ObservePeerReport_DoesNotExtendAnAlreadyStaleMark(t *testing.T) {
	r := freshReachability()
	original := time.Now().Add(-deadRecheckInterval - time.Second)
	r.dead["10.0.0.24:9443"] = original

	r.observePeerReport(nil, []string{"10.0.0.24:9443"}, nil)

	if !r.dead["10.0.0.24:9443"].Equal(original) {
		t.Errorf("dead[addr] = %v, want unchanged at %v — a repeated peer report must not refresh an existing mark's timestamp", r.dead["10.0.0.24:9443"], original)
	}
}

func TestReachabilityRoundTripper_SkipsAlreadyDeadAddress(t *testing.T) {
	saved := reachability
	reachability = freshReachability()
	t.Cleanup(func() { reachability = saved })

	deadAddr := "127.0.0.1:1"
	markDeadForTest(reachability, deadAddr)

	innerCalled := false
	rt := reachabilityRoundTripper{inner: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		innerCalled = true
		return nil, nil
	})}
	req, _ := http.NewRequest(http.MethodGet, "https://"+deadAddr+"/api/v1/candidate", nil)
	_, err := rt.RoundTrip(req)
	if innerCalled {
		t.Error("the real inner RoundTripper was invoked for an address already believed dead")
	}
	if err == nil {
		t.Error("RoundTrip() returned a nil error for a believed-dead address")
	}
}

func TestReachabilityRoundTripper_MarksDeadOnErrorAliveOnSuccess(t *testing.T) {
	saved := reachability
	reachability = freshReachability()
	t.Cleanup(func() { reachability = saved })

	okAddr := "10.0.0.1:9443"
	rtOK := reachabilityRoundTripper{inner: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})}
	req, _ := http.NewRequest(http.MethodGet, "https://"+okAddr+"/api/v1/status", nil)
	if _, err := rtOK.RoundTrip(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reachability.isDead(okAddr) {
		t.Error("a successful round trip must mark the address alive, not dead")
	}

	failAddr := "10.0.0.2:9443"
	rtFail := reachabilityRoundTripper{inner: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, errNodeBelievedOffline
	})}
	req2, _ := http.NewRequest(http.MethodGet, "https://"+failAddr+"/api/v1/status", nil)
	if _, err := rtFail.RoundTrip(req2); err == nil {
		t.Fatal("expected an error from the failing inner RoundTripper")
	}
	if reachability.isDead(failAddr) {
		t.Error("a SINGLE failed round trip must not yet mark the address dead — debounced, see deadStreakThreshold")
	}
	req3, _ := http.NewRequest(http.MethodGet, "https://"+failAddr+"/api/v1/status", nil)
	if _, err := rtFail.RoundTrip(req3); err == nil {
		t.Fatal("expected an error from the failing inner RoundTripper")
	}
	if !reachability.isDead(failAddr) {
		t.Error("2 consecutive failed round trips must mark the address dead")
	}
}

// roundTripFunc adapts a plain function to http.RoundTripper, the same
// idiom net/http's own docs recommend for a test double.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFetchAllNodes_SkipsAlreadyDeadNodeAcrossEveryCallShape(t *testing.T) {
	saved := reachability
	reachability = freshReachability()
	t.Cleanup(func() { reachability = saved })

	deadAddr := "127.0.0.1:1" // nothing listens here, a real dial would refuse/time out
	markDeadForTest(reachability, deadAddr)
	nodes := []NodeConfig{{Name: "dead-node", Addr: deadAddr}}

	dialed := false
	fetchA := func(n NodeConfig) (string, error) {
		dialed = true
		return "unused", nil
	}
	resultsA := fetchAllNodes(nodes, fetchA)
	if dialed {
		t.Error("fetchA was actually called for an address already believed dead — fetchAllNodes must short-circuit before ever invoking fetch")
	}
	if resultsA[0].Err == nil {
		t.Error("fetchAllNodes()[0].Err = nil, want a synthetic offline error")
	}

	dialedB := false
	fetchB := func(n NodeConfig) ([]int, error) {
		dialedB = true
		return nil, nil
	}
	resultsB := fetchAllNodes(nodes, fetchB)
	if dialedB {
		t.Error("fetchB (a completely different fetch shape) was actually called for the same believed-dead address — the belief must apply generically, not per fetch function")
	}
	if resultsB[0].Err == nil {
		t.Error("fetchAllNodes()[0].Err = nil for fetchB, want a synthetic offline error")
	}
}

func TestRefusedConnectionNeverMarksDead(t *testing.T) {
	saved := reachability
	reachability = freshReachability()
	t.Cleanup(func() { reachability = saved })

	refused := "127.0.0.1:1"
	client := &http.Client{Transport: clusterTransport, Timeout: 2 * time.Second}
	for i := 0; i < deadStreakThreshold+1; i++ {
		if _, err := client.Get("http://" + refused + "/"); err == nil {
			t.Fatal("expected a refused connection")
		}
	}
	if reachability.isDead(refused) {
		t.Error("a refused connection (node still starting) must not mark the address dead")
	}
}

func TestFetchAllNodesFailureCountsOnce(t *testing.T) {
	saved := reachability
	reachability = freshReachability()
	t.Cleanup(func() { reachability = saved })

	addr := "10.0.0.9:9443"
	fetchAllNodes([]NodeConfig{{Name: "x", Addr: addr}}, func(NodeConfig) (int, error) {
		reachability.markDead(addr)
		return 0, errors.New("timeout")
	})
	if reachability.isDead(addr) {
		t.Error("one failed request counted twice: fetchAllNodes must leave marking to the transport")
	}
}

func TestCountsAsDead(t *testing.T) {
	if countsAsDead(syscall.ECONNREFUSED) || countsAsDeadMsg("dial tcp 1.2.3.4:9443: connect: connection refused") {
		t.Error("refused must not count")
	}
	if !countsAsDead(errors.New("i/o timeout")) || !countsAsDeadMsg("context deadline exceeded") {
		t.Error("a timeout must count")
	}
}

func TestObservePeerReport_RecordsAndClearsFallbackRoute(t *testing.T) {
	r := &nodeReachability{dead: map[string]time.Time{}, fallback: map[string]string{}}
	r.observePeerReport(nil, []string{"192.0.2.22:9443"}, map[string]string{"192.0.2.22:9443": "10.200.18.23:9443"})
	if got := r.fallbackFor("192.0.2.22:9443"); got != "10.200.18.23:9443" {
		t.Fatalf("fallbackFor() = %q, want the reported fallback", got)
	}
	if !r.viaFallback("192.0.2.22:9443") {
		t.Error("viaFallback() = false, want true (dead over mgmt with a known route)")
	}
	// The reporter stops confirming the route: dropped.
	r.observePeerReport(nil, []string{"192.0.2.22:9443"}, nil)
	if r.fallbackFor("192.0.2.22:9443") != "" {
		t.Error("route still present after the reporter stopped confirming it")
	}
	// Recovery: reported visible again clears mark AND route.
	r.observePeerReport(nil, []string{"192.0.2.22:9443"}, map[string]string{"192.0.2.22:9443": "10.200.18.23:9443"})
	r.observePeerReport([]string{"192.0.2.22:9443"}, nil, nil)
	if r.isDead("192.0.2.22:9443") || r.fallbackFor("192.0.2.22:9443") != "" {
		t.Error("node reported visible again must clear both the dead mark and the fallback route")
	}
}

// A node with a known fallback route must stay routed over it past
// deadRecheckInterval.
func TestIsDead_StaysDeadPastRecheckWindowWhileFallbackRouteKnown(t *testing.T) {
	r := &nodeReachability{
		dead:     map[string]time.Time{"a:1": time.Now().Add(-2 * deadRecheckInterval), "b:1": time.Now().Add(-2 * deadRecheckInterval)},
		fallback: map[string]string{"a:1": "fb:1"},
	}
	if !r.isDead("a:1") {
		t.Error("node with a fallback route must stay dead/routed past the recheck window")
	}
	if r.isDead("b:1") {
		t.Error("node without a route must still be re-dialed once the recheck window elapses")
	}
}

func setRouteForTest(t *testing.T, primary, fallback string) {
	t.Helper()
	reachability.observePeerReport(nil, []string{primary}, map[string]string{primary: fallback})
	t.Cleanup(func() { reachability.markAlive(primary) })
}

func TestReachabilityRoundTripper_TunnelsToFallbackWhenMgmtDead(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	fallbackAddr := srv.Listener.Addr().String()
	const primary = "192.0.2.77:9443" // TEST-NET: never dialed — must be rerouted
	setRouteForTest(t, primary, fallbackAddr)

	client := &http.Client{Transport: reachabilityRoundTripper{inner: http.DefaultTransport}, Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + primary + "/api/v1/status")
	if err != nil {
		t.Fatalf("request to a mgmt-dead node with a fallback route failed: %v", err)
	}
	resp.Body.Close()
	if hits.Load() != 1 {
		t.Errorf("fallback server hits = %d, want 1 (request must be tunnelled there)", hits.Load())
	}
	if !reachability.isDead(primary) {
		t.Error("a successful tunnelled request must not clear the mgmt-path dead belief")
	}
}

func TestReachabilityRoundTripper_DeadWithoutRouteStillFailsFast(t *testing.T) {
	const primary = "192.0.2.78:9443"
	markDeadForTest(reachability, primary)
	t.Cleanup(func() { reachability.markAlive(primary) })
	client := &http.Client{Transport: reachabilityRoundTripper{inner: http.DefaultTransport}, Timeout: 3 * time.Second}
	start := time.Now()
	_, err := client.Get("http://" + primary + "/x")
	if err == nil || time.Since(start) > time.Second {
		t.Errorf("err=%v after %v, want an immediate errNodeBelievedOffline", err, time.Since(start))
	}
}

func TestFetchAllNodes_FetchesDeadNodeThatHasFallbackRoute(t *testing.T) {
	const primary = "192.0.2.79:9443"
	setRouteForTest(t, primary, "10.0.0.1:9443")
	var called atomic.Int32
	res := fetchAllNodes([]NodeConfig{{Name: "core-2", Addr: primary}}, func(n NodeConfig) (string, error) {
		called.Add(1)
		return "real status", nil
	})
	if called.Load() != 1 || res[0].Err != nil {
		t.Fatalf("fetch called %d times, err=%v — a dead node WITH a route must still be fetched", called.Load(), res[0].Err)
	}
	if !reachability.isDead(primary) {
		t.Error("a successful fetch over the fallback must leave the mgmt-path belief as dead")
	}
}

func TestPathDegradedTexts(t *testing.T) {
	b, s := pathDegradedTexts(0, 1)
	if !strings.Contains(b, "served over the fallback path") || !strings.Contains(s, "data via fallback path") {
		t.Errorf("tunnelled-only texts = %q / %q", b, s)
	}
	b, s = pathDegradedTexts(1, 0)
	if !strings.Contains(b, "reachable via fallback path only") || !strings.Contains(s, "alive via fallback") {
		t.Errorf("invisible-node texts = %q / %q", b, s)
	}
}
