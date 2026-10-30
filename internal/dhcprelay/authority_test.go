// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcprelay

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"dnshived/internal/arbiter"
)

const testPSK = "test-psk-not-secret"

func gateRelay(t *testing.T, runDir string) *Relay {
	t.Helper()
	silenceLog(t)
	r, err := New(Config{
		ServerAddr: "127.0.0.21:67",
		NodeID:     "core-1",
		CoreCount:  3,
		ClientInterfaces: []ClientInterfaceConfig{
			{Name: "ens19.200", GIAddr: "192.168.200.22", Scope: "office"},
			{Name: "ens20.50", GIAddr: "172.16.50.22", Scope: "dante"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.ConfigureGate("", runDir, "test"); err != nil {
		t.Fatal(err)
	}
	r.handleGate(gateRequest{Command: "set-psk", PSK: testPSK}, time.Now())
	return r
}

func signedToken(t *testing.T, scope, owner, arb string, granted, expires time.Time) json.RawMessage {
	t.Helper()
	tok := arbiter.Token{Scope: scope, Owner: owner, Incarnation: 7, GrantedAt: granted, ExpiresAt: expires,
		Nonce: arb + expires.String(), Arbiter: arb}
	tok.Signature = tok.Sign([]byte(testPSK))
	raw, err := json.Marshal(tok)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func trackState(t *testing.T, dir, scope string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, scope+".track"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

func TestGateStartsClosedAndWritesFault(t *testing.T) {
	dir := t.TempDir()
	r := gateRelay(t, dir)
	r.gates.clockOK.Store(true)
	ci := r.clientIfaces[0]
	if r.gates.allows(ci.gate, time.Now()) {
		t.Fatal("a fresh scope is open before authorize")
	}
	if got := trackState(t, dir, "office"); got != "fault" {
		t.Fatalf("track file = %q, want fault", got)
	}
}

func TestPacketPathDropsWhileClosed(t *testing.T) {
	r := gateRelay(t, t.TempDir())
	serverConn := newFakeUDPConn()
	r.setServerConn(serverConn)
	ci := r.clientIfaces[0]
	r.handleClientRequest(ci, buildTestPacket(bootpOpRequest, 1, [6]byte{1}, net.IPv4zero, net.IPv4zero, 0, true, true),
		&net.UDPAddr{IP: net.IPv4(192, 168, 200, 50), Port: dhcpClientPort})
	if _, ok := serverConn.lastWrite(); ok {
		t.Fatal("a request was forwarded while the gate was closed")
	}
	if n := r.Snapshot().GateClosedRequests; n != 1 {
		t.Fatalf("GateClosedRequests = %d, want 1", n)
	}
}

func TestAuthorizeOpensAndCountsDistinctArbiters(t *testing.T) {
	dir := t.TempDir()
	r := gateRelay(t, dir)
	now := time.Now()
	r.gates.clockOK.Store(true)
	tokens := []json.RawMessage{
		signedToken(t, "office", "core-1", "core-2", now.Add(-5*time.Second), now.Add(30*time.Second)),
		signedToken(t, "office", "core-1", "core-3", now.Add(-5*time.Second), now.Add(40*time.Second)),
	}
	reply := r.handleGate(gateRequest{Command: "authorize", Scope: "office", Incarnation: 7, Tokens: tokens}, now)
	if !reply.OK || reply.Deadline == "" {
		t.Fatalf("authorize: %+v", reply)
	}
	if !r.gates.allows(r.clientIfaces[0].gate, now) {
		t.Fatal("authorized scope is closed")
	}
	if got := trackState(t, dir, "office"); got != "eligible" {
		t.Fatalf("track file = %q, want eligible", got)
	}
}

func TestAuthorizeRejectsWithTheFailedCheck(t *testing.T) {
	r := gateRelay(t, t.TempDir())
	now := time.Now()
	wrongOwner := signedToken(t, "office", "core-9", "core-2", now.Add(-5*time.Second), now.Add(30*time.Second))
	reply := r.handleGate(gateRequest{Command: "authorize", Scope: "office", Incarnation: 7,
		Tokens: []json.RawMessage{wrongOwner}}, now)
	if reply.OK || reply.Error != "owner" {
		t.Fatalf("wrong owner: %+v, want error owner", reply)
	}

	one := signedToken(t, "office", "core-1", "core-2", now.Add(-5*time.Second), now.Add(30*time.Second))
	reply = r.handleGate(gateRequest{Command: "authorize", Scope: "office", Incarnation: 7, Tokens: []json.RawMessage{one}}, now)
	if reply.OK || reply.Error != "quorum" {
		t.Fatalf("one arbiter of three cores: %+v, want error quorum", reply)
	}

	reply = r.handleGate(gateRequest{Command: "authorize", Scope: "dante", Incarnation: 7, Tokens: []json.RawMessage{one}}, now)
	if reply.OK || r.gates.allows(r.clientIfaces[1].gate, now) {
		t.Fatal("a token for another scope opened dante")
	}
}

func TestAuthorizeRefusesWithoutNodeOrPSK(t *testing.T) {
	r := gateRelay(t, t.TempDir())
	r.gates.applyConfig("", 3)
	reply := r.handleGate(gateRequest{Command: "authorize", Scope: "office", Tokens: nil}, time.Now())
	if reply.OK || !strings.Contains(reply.Error, "node_id") {
		t.Fatalf("no node ID: %+v", reply)
	}
	r.gates.applyConfig("core-1", 3)
	r.gates.setPSK(nil)
	reply = r.handleGate(gateRequest{Command: "authorize", Scope: "office", Tokens: nil}, time.Now())
	if reply.OK || !strings.Contains(reply.Error, "PSK") {
		t.Fatalf("no PSK: %+v", reply)
	}
}

func TestDeadlineClosesBothLegsAndTheTrackFile(t *testing.T) {
	dir := t.TempDir()
	r := gateRelay(t, dir)
	now := time.Now()
	r.gates.clockOK.Store(true)
	tokens := []json.RawMessage{
		signedToken(t, "office", "core-1", "core-2", now.Add(-5*time.Second), now.Add(20*time.Second)),
		signedToken(t, "office", "core-1", "core-3", now.Add(-5*time.Second), now.Add(20*time.Second)),
	}
	if reply := r.handleGate(gateRequest{Command: "authorize", Scope: "office", Incarnation: 7, Tokens: tokens}, now); !reply.OK {
		t.Fatalf("authorize: %+v", reply)
	}
	g := r.clientIfaces[0].gate
	later := now.Add(20 * time.Second) // earliest expiry minus the 3 s margin has passed
	if r.gates.allows(g, later) {
		t.Fatal("request leg open past the deadline")
	}
	r.gates.mu.Lock()
	r.gates.evaluateLocked(later)
	r.gates.mu.Unlock()
	if g.deadline.Load() != 0 {
		t.Fatal("deadline not cleared by the sweep")
	}
	if got := trackState(t, dir, "office"); got != "fault" {
		t.Fatalf("track file after the deadline = %q, want fault", got)
	}
}

func TestRevokeAndRevokeAllClose(t *testing.T) {
	dir := t.TempDir()
	r := gateRelay(t, dir)
	now := time.Now()
	r.gates.clockOK.Store(true)
	for _, scope := range []string{"office", "dante"} {
		g := r.gates.scope(scope)
		g.deadline.Store(now.Add(time.Hour).UnixNano())
	}
	r.handleGate(gateRequest{Command: "revoke", Scope: "office"}, now)
	if r.gates.allows(r.clientIfaces[0].gate, now) || !r.gates.allows(r.clientIfaces[1].gate, now) {
		t.Fatal("revoke closed the wrong scope")
	}
	if got := trackState(t, dir, "office"); got != "fault" {
		t.Fatalf("office track after revoke = %q", got)
	}
	r.handleGate(gateRequest{Command: "revoke-all"}, now)
	if r.gates.allows(r.clientIfaces[1].gate, now) {
		t.Fatal("revoke-all left dante open")
	}
}

func TestClockUnhealthyClosesEveryScope(t *testing.T) {
	r := gateRelay(t, t.TempDir())
	now := time.Now()
	r.gates.clockOK.Store(true)
	r.gates.scope("office").deadline.Store(now.Add(time.Hour).UnixNano())
	r.gates.clockOK.Store(false)
	if r.gates.allows(r.clientIfaces[0].gate, now) {
		t.Fatal("open scope admitted with an unhealthy clock")
	}
}

func TestClockHealthyRules(t *testing.T) {
	cases := []struct {
		name  string
		state int
		tx    syscall.Timex
		want  bool
	}{
		{"synchronised", 0, syscall.Timex{Maxerror: 1000}, true},
		{"unsynced flag", 0, syscall.Timex{Status: clockUnsynced, Maxerror: 1000}, false},
		{"maxerror over 2 s", 0, syscall.Timex{Maxerror: 2_000_001}, false},
		{"TIME_ERROR state", clockStateError, syscall.Timex{Maxerror: 1000}, false},
	}
	for _, c := range cases {
		if got := clockHealthy(c.state, c.tx); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestGateCommandsAndStatus(t *testing.T) {
	r := gateRelay(t, t.TempDir())
	if reply := r.handleGate(gateRequest{Command: "reboot"}, time.Now()); reply.Error != "unknown command: reboot" {
		t.Fatalf("unknown command: %+v", reply)
	}
	if reply := r.handleGate(gateRequest{Command: "set-psk"}, time.Now()); reply.OK {
		t.Fatal("empty PSK accepted")
	}
	st := r.handleGate(gateRequest{Command: "status"}, time.Now())
	if !st.OK || st.Version != "test" || st.Clock == "" || len(st.Scopes) != 2 {
		t.Fatalf("status: %+v", st)
	}
	for _, sc := range st.Scopes {
		if sc.Gate != "closed" || sc.Deadline != nil {
			t.Fatalf("scope %s reported %+v, want closed", sc.Scope, sc)
		}
	}
}

func TestRetainClosesScopesRemovedFromConfig(t *testing.T) {
	r := gateRelay(t, t.TempDir())
	now := time.Now()
	r.gates.clockOK.Store(true)
	r.gates.scope("dante").deadline.Store(now.Add(time.Hour).UnixNano())
	r.gates.retain(map[string]bool{"office": true}, now)
	if _, ok := r.gates.scopes["dante"]; ok {
		t.Fatal("removed scope still tracked")
	}
}
