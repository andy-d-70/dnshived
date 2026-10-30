// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"sync"
	"testing"

	"dnshived/internal/config"
	"dnshived/internal/relaygate"
	"dnshived/internal/unixsock"
)

type fakeRelayGate struct {
	mu       sync.Mutex
	commands []string
	tokens   int
}

func startFakeRelayGate(t *testing.T) (string, *fakeRelayGate) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gate.sock")
	srv, err := unixsock.Listen(path, 0o660, unixsock.Limits{MaxConns: 4, Deadline: 5e9, MaxRequest: 1 << 16, DrainTimeout: 5e9})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	fake := &fakeRelayGate{}
	go srv.Serve(func(c net.Conn) {
		var req struct {
			Command string            `json:"command"`
			Tokens  []json.RawMessage `json:"tokens"`
		}
		json.NewDecoder(c).Decode(&req)
		fake.mu.Lock()
		fake.commands = append(fake.commands, req.Command)
		fake.tokens = len(req.Tokens)
		fake.mu.Unlock()
		c.Write([]byte(`{"ok":true,"deadline":"2026-10-25T12:00:00Z"}` + "\n"))
	}, func(unixsock.Peer, error) {})
	return path, fake
}

func (f *fakeRelayGate) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.commands...)
}

func newRelayGateAgent(t *testing.T, path string) *Agent {
	t.Helper()
	scopes := map[string]config.ScopeConfig{"office": {Parent: "ens19", VLANID: 2, NodeIP: "192.168.2.22/24", VIP: "192.168.2.254/24"}}
	a := New(config.RoleCore1, "core-1", 7, "cluster-psk", t.TempDir(), scopes, nil)
	a.SetRelayGate(&relaygate.Client{Path: path})
	return a
}

func TestAuthorizeRelaySendsPSKThenTokens(t *testing.T) {
	path, fake := startFakeRelayGate(t)
	a := newRelayGateAgent(t, path)
	a.tokenRaw["office"] = map[string]json.RawMessage{
		"core-2": json.RawMessage(`{"scope":"office","arbiter":"core-2"}`),
		"core-3": json.RawMessage(`{"scope":"office","arbiter":"core-3"}`),
	}
	if err := a.authorizeRelay("office"); err != nil {
		t.Fatalf("authorizeRelay: %v", err)
	}
	got := fake.seen()
	if len(got) != 2 || got[0] != "set-psk" || got[1] != "authorize" || fake.tokens != 2 {
		t.Fatalf("relay saw %v with %d token(s), want set-psk then authorize with 2", got, fake.tokens)
	}
}

func TestAuthorizeRelayNeedsAToken(t *testing.T) {
	path, fake := startFakeRelayGate(t)
	a := newRelayGateAgent(t, path)
	if err := a.authorizeRelay("office"); err == nil {
		t.Fatal("authorize without a held token succeeded")
	}
	if len(fake.seen()) != 0 {
		t.Fatalf("relay was contacted without a token: %v", fake.seen())
	}
}

func TestCloseGateRevokesOnlyWhatWasAuthorized(t *testing.T) {
	path, fake := startFakeRelayGate(t)
	a := newRelayGateAgent(t, path)
	a.tokenRaw["office"] = map[string]json.RawMessage{"core-2": json.RawMessage(`{"scope":"office","arbiter":"core-2"}`)}
	if err := a.authorizeRelay("office"); err != nil {
		t.Fatal(err)
	}
	a.closeGate("office", "test")
	a.closeGate("office", "test again")
	got := fake.seen()
	revokes := 0
	for _, c := range got {
		if c == "revoke" {
			revokes++
		}
	}
	if revokes != 1 {
		t.Fatalf("revokes = %d, want 1 (got %v)", revokes, got)
	}
}

func TestNoRelayGateMeansNoRelayCalls(t *testing.T) {
	a := New(config.RoleCore1, "core-1", 7, "cluster-psk", t.TempDir(), nil, nil)
	if err := a.authorizeRelay("office"); err != nil {
		t.Fatalf("without a relay gate: %v", err)
	}
	a.revokeRelay("office")
}

// TestAuthorizeRelayAbsentSocketIsNotARefusal covers F2's lazy check: with no relay socket authorizeRelay returns
// errRelayAbsent, which the agent does not treat as a refusal.
func TestAuthorizeRelayAbsentSocketIsNotARefusal(t *testing.T) {
	a := newRelayGateAgent(t, filepath.Join(t.TempDir(), "absent.sock"))
	a.tokenRaw["office"] = map[string]json.RawMessage{"core-2": json.RawMessage(`{"scope":"office"}`)}
	err := a.authorizeRelay("office")
	if !errors.Is(err, errRelayAbsent) {
		t.Fatalf("authorizeRelay with no socket = %v, want errRelayAbsent", err)
	}
	if relayRefused(err) {
		t.Fatal("an absent relay was treated as a refusal")
	}
	if relayRefused(errors.New("quorum")) != true {
		t.Fatal("a real relay refusal was not treated as one")
	}
}

// TestOpenGateWithoutWitnessNeverReachesTheRelay confirms the order: the witness comes first, so a scope without
// a granted token is not authorized on the relay.
func TestOpenGateWithoutWitnessNeverReachesTheRelay(t *testing.T) {
	path, fake := startFakeRelayGate(t)
	a := newRelayGateAgent(t, path)
	if a.openGate("office", "test") {
		t.Fatal("openGate succeeded without a witness")
	}
	if len(fake.seen()) != 0 {
		t.Fatalf("relay was contacted before the witness: %v", fake.seen())
	}
}
