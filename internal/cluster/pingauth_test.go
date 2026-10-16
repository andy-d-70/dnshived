// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package cluster

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"dnshived/internal/identity"
)

func TestSignPingBody_DeterministicAndKeyDependent(t *testing.T) {
	body := []byte(`{"node_id":"a"}`)
	sig1 := signPingBody([]byte("psk-one"), body)
	sig2 := signPingBody([]byte("psk-one"), body)
	sig3 := signPingBody([]byte("psk-two"), body)

	if sig1 != sig2 {
		t.Errorf("same key+body produced different signatures: %s vs %s", sig1, sig2)
	}
	if sig1 == sig3 {
		t.Error("different keys produced the same signature")
	}
}

// TestHandlePing_SignsResponseWhenPSKConfigured confirms the server side
// actually sets the header, with a signature that verifies against the
// exact bytes written.
func TestHandlePing_SignsResponseWhenPSKConfigured(t *testing.T) {
	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "shared-secret")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ping", strings.NewReader(`{}`))
	o.HandlePing(rr, req)

	sig := rr.Header().Get(pingSigHeader)
	if sig == "" {
		t.Fatal("HandlePing did not set the signature header despite a configured PSK")
	}
	want := signPingBody([]byte("shared-secret"), rr.Body.Bytes())
	if sig != want {
		t.Errorf("signature header = %s, want %s (does not match the actual response bytes)", sig, want)
	}
}

// TestHandlePing_NoSignatureWhenNoPSK confirms the header is omitted
// entirely with no PSK.
func TestHandlePing_NoSignatureWhenNoPSK(t *testing.T) {
	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ping", strings.NewReader(`{}`))
	o.HandlePing(rr, req)

	if sig := rr.Header().Get(pingSigHeader); sig != "" {
		t.Errorf("signature header present (%q) despite no PSK configured", sig)
	}
}

func TestObserver_Probe_AcceptsCorrectlySignedResponse(t *testing.T) {
	const psk = "shared-secret"
	peerID := identity.Identity{ClusterID: "test-cluster", NodeID: "peer-1", Role: "core-2"}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := json.Marshal(peerID)
		w.Header().Set(pingSigHeader, signPingBody([]byte(psk), body))
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", []string{addr}, psk)
	o.probeAll()

	o.mu.RLock()
	ps := o.peers[addr]
	identityOK := ps.Identity != nil && ps.Identity.NodeID == "peer-1"
	reachable := ps.Reachable
	o.mu.RUnlock()

	if !reachable {
		t.Error("Reachable = false after a correctly-signed response, want true")
	}
	if !identityOK {
		t.Errorf("Identity not stored/correct after a correctly-signed response: %+v", ps.Identity)
	}
}

func TestObserver_Probe_RejectsSpoofedResponse(t *testing.T) {
	const realPSK = "shared-secret"
	const attackerPSK = "attacker-does-not-know-the-real-psk"
	spoofedID := identity.Identity{
		ClusterID:    "test-cluster",
		NodeID:       "peer-1",
		Role:         "core-2",
		ClaimsQuorum: true,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := json.Marshal(spoofedID)
		w.Header().Set(pingSigHeader, signPingBody([]byte(attackerPSK), body))
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", []string{addr}, realPSK)
	o.probeAll()

	o.mu.RLock()
	ps := o.peers[addr]
	identityStored := ps.Identity != nil
	failures := ps.Failures
	lastErr := ps.LastError
	o.mu.RUnlock()

	if identityStored {
		t.Error("spoofed/wrongly-signed identity was stored — the core vulnerability this fix closes")
	}
	if failures == 0 {
		t.Error("a spoofed response should count as a failed probe, Failures still 0")
	}
	if !strings.Contains(lastErr, "signature") {
		t.Errorf("LastError = %q, want it to mention signature verification (diagnosability)", lastErr)
	}
}

func TestObserver_Probe_RejectsUnsignedResponseWhenPSKConfigured(t *testing.T) {
	peerID := identity.Identity{ClusterID: "test-cluster", NodeID: "peer-1", Role: "core-2"}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := json.Marshal(peerID)
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", []string{addr}, "shared-secret")
	o.probeAll()

	o.mu.RLock()
	identityStored := o.peers[addr].Identity != nil
	o.mu.RUnlock()

	if identityStored {
		t.Error("unsigned response was accepted despite a configured PSK")
	}
}

func TestObserver_Probe_NoPSKSkipsVerification(t *testing.T) {
	peerID := identity.Identity{ClusterID: "test-cluster", NodeID: "peer-1", Role: "core-2"}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := json.Marshal(peerID)
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", []string{addr}, "")
	o.probeAll()

	o.mu.RLock()
	ps := o.peers[addr]
	identityOK := ps.Identity != nil && ps.Identity.NodeID == "peer-1"
	o.mu.RUnlock()

	if !identityOK {
		t.Errorf("no-PSK cluster rejected an unsigned response — backward compatibility broken: %+v", ps.Identity)
	}
}

// TestHandlePing_DeniesUntrustedSource confirms an unlisted caller gets
// 403, not the node's identity.
func TestHandlePing_DeniesUntrustedSource(t *testing.T) {
	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	o.SetTrustedHosts([]string{"192.168.0.22", "192.168.0.23"})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ping", strings.NewReader(`{}`))
	req.RemoteAddr = "192.168.0.43:12345"
	o.HandlePing(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for untrusted source, got %d: %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), self.NodeID) {
		t.Fatal("identity leaked to an untrusted caller despite the 403")
	}
}

// TestHandlePing_AllowsTrustedSource confirms the allowlist doesn't break
// the legitimate peer-probing path once configured.
func TestHandlePing_AllowsTrustedSource(t *testing.T) {
	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	o.SetTrustedHosts([]string{"192.168.0.22"})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ping", strings.NewReader(`{}`))
	req.RemoteAddr = "192.168.0.22:12345"
	o.HandlePing(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for trusted source, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), self.NodeID) {
		t.Fatal("expected identity in response for a trusted caller")
	}
}

// TestHandlePing_EmptyTrustedHostsFailsOpen confirms an upgraded-but-not-
// yet-reconfigured cluster keeps today's exact permissive behavior.
func TestHandlePing_EmptyTrustedHostsFailsOpen(t *testing.T) {
	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "") // SetTrustedHosts never called

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ping", strings.NewReader(`{}`))
	req.RemoteAddr = "203.0.113.99:12345"
	o.HandlePing(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected fail-open 200 with no trusted_hosts configured, got %d: %s", rr.Code, rr.Body.String())
	}
}
