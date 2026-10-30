// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"encoding/json"
	"errors"
	"testing"

	"dnshived/internal/config"
)

type closeFakeGate struct {
	available  bool
	revokeErrs []error
	revokes    int
}

func (f *closeFakeGate) Available() bool     { return f.available }
func (f *closeFakeGate) SetPSK(string) error { return nil }
func (f *closeFakeGate) Authorize(string, uint64, []json.RawMessage, string) (string, error) {
	return "", nil
}

func (f *closeFakeGate) Revoke(string) error {
	f.revokes++
	if len(f.revokeErrs) == 0 {
		return nil
	}
	err := f.revokeErrs[0]
	f.revokeErrs = f.revokeErrs[1:]
	return err
}

func closeTestAgent(gate relayGateway, scope string) *Agent {
	a := &Agent{
		relayGate:       gate,
		relayAuthorized: map[string]bool{scope: true},
		closePending:    map[string]bool{},
		serving:         map[string]bool{},
		lastAppliedGate: map[string]string{},
		tokenRaw:        map[string]map[string]json.RawMessage{scope: {"arbiter": json.RawMessage(`{}`)}},
		witness:         map[string]WitnessState{scope: {}},
	}
	scopes := map[string]config.ScopeConfig{scope: {}}
	a.scopes.Store(&scopes)
	return a
}

func tokenHeld(a *Agent, scope string) bool {
	_, ok := a.tokenRaw[scope]
	return ok
}

func TestCloseGate_KeepsTokenWhileRelayRefuses(t *testing.T) {
	gate := &closeFakeGate{available: true, revokeErrs: []error{errors.New("relay refused")}}
	a := closeTestAgent(gate, "office")

	if a.closeGate("office", "test") {
		t.Fatal("closeGate reported closed while the relay refused")
	}
	if !tokenHeld(a, "office") {
		t.Fatal("arbiter token released before the relay confirmed the close")
	}
	if !a.closePending["office"] {
		t.Fatal("scope not marked close-pending")
	}
	if !a.relayAuthorized["office"] {
		t.Fatal("relayAuthorized cleared although the close failed; a retry would be skipped")
	}
}

func TestCloseGate_ReleasesTokenWhenRelayCloses(t *testing.T) {
	gate := &closeFakeGate{available: true}
	a := closeTestAgent(gate, "office")

	if !a.closeGate("office", "test") {
		t.Fatal("closeGate did not report closed")
	}
	if tokenHeld(a, "office") {
		t.Fatal("token still held after the relay closed")
	}
	if a.closePending["office"] || a.relayAuthorized["office"] {
		t.Fatal("close state not cleared after a confirmed close")
	}
	if gate.revokes != 1 {
		t.Fatalf("revokes = %d, want 1", gate.revokes)
	}
}

func TestRetryClosePending_ResolvesAfterRecovery(t *testing.T) {
	refused := errors.New("relay refused")
	gate := &closeFakeGate{available: true, revokeErrs: []error{refused, refused, nil}}
	a := closeTestAgent(gate, "office")

	a.closeGate("office", "test")
	a.retryClosePending("office")
	if !tokenHeld(a, "office") || !a.closePending["office"] {
		t.Fatal("retry that still fails must keep the token and the pending mark")
	}
	a.retryClosePending("office")
	if tokenHeld(a, "office") || a.closePending["office"] {
		t.Fatal("retry after the relay recovered did not release the token")
	}
}

func TestCloseGate_NoRelayIsClosed(t *testing.T) {
	gate := &closeFakeGate{available: false}
	a := closeTestAgent(gate, "office")

	if !a.closeGate("office", "test") {
		t.Fatal("closeGate with no relay running must count as closed")
	}
	if tokenHeld(a, "office") {
		t.Fatal("token kept although no relay is running to forward")
	}
	if gate.revokes != 0 {
		t.Fatalf("revokes = %d, want 0 when the relay is not running", gate.revokes)
	}
}

func TestAbandonOpen_RevokesRelayBeforeReleasingToken(t *testing.T) {
	gate := &closeFakeGate{available: true}
	a := closeTestAgent(gate, "office")
	a.relayAuthorized["office"] = false

	a.abandonOpen("office")
	if gate.revokes != 1 {
		t.Fatalf("revokes = %d, want 1: the relay may have opened the scope", gate.revokes)
	}
	if tokenHeld(a, "office") {
		t.Fatal("token kept after the relay confirmed the close")
	}
}

func TestAbandonOpen_RefusedCloseKeepsToken(t *testing.T) {
	gate := &closeFakeGate{available: true, revokeErrs: []error{errors.New("relay refused")}}
	a := closeTestAgent(gate, "office")

	a.abandonOpen("office")
	if !tokenHeld(a, "office") || !a.closePending["office"] {
		t.Fatal("refused close must keep the token and mark the scope pending")
	}
}
