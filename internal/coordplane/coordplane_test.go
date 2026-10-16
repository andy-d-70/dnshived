// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package coordplane

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"dnshived/internal/psksign"
)

func registerAll(mux *http.ServeMux, s *Server) {
	s.AddRoutes(mux)
	mux.HandleFunc("POST /api/v1/coord/config", s.ConfigHandler())
}

// fakeApply builds an ApplyFunc that always returns the given status/
// checksum, ignoring the document.
func fakeApply(status int, checksum string) ApplyFunc {
	return fakeApplyWithDHCP(status, checksum, false)
}

// fakeApplyWithDHCP is fakeApply plus a caller-chosen dhcpAffecting
// return.
func fakeApplyWithDHCP(status int, checksum string, dhcpAffecting bool) ApplyFunc {
	return func(document json.RawMessage) (int, interface{}, string, bool) {
		if status != http.StatusOK {
			return status, map[string]string{"error": "rejected"}, "", false
		}
		return status, map[string]interface{}{"ok": true}, checksum, dhcpAffecting
	}
}

// docsBody builds a POST /api/v1/coord/config request body.
func docsBody(t *testing.T, docs map[string]string) []byte {
	t.Helper()
	m := make(map[string]json.RawMessage, len(docs))
	for addr, doc := range docs {
		m[addr] = json.RawMessage(doc)
	}
	body, err := json.Marshal(map[string]interface{}{"documents": m})
	if err != nil {
		t.Fatalf("build request body: %v", err)
	}
	return body
}

func TestHandleConfig_WorkerCoordinatesSuccessfully(t *testing.T) {
	srv := NewServer("core-1", "core-1", "worker-a-addr:9443", []byte("psk"), nil, false, fakeApply(http.StatusOK, "abc"))
	mux := http.NewServeMux()
	registerAll(mux, srv)

	req := httptest.NewRequest("POST", "/api/v1/coord/config", bytes.NewReader(docsBody(t, map[string]string{"worker-a-addr:9443": "{}"})))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("a worker coordinating should succeed, got %d: %s", w.Code, w.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["frozen"] != nil {
		t.Errorf("response should carry no frozen field at all now, got %v", body)
	}
	if body["overall"] != "ok" {
		t.Errorf("overall = %v, want \"ok\"", body["overall"])
	}
}

func TestHandleConfig_UnreachableArbiterDuringWorkerCoordinationIsPartial(t *testing.T) {
	srv := NewServer("core-1", "core-1", "worker-a-addr:9443", []byte("psk"), []string{"arbiter-addr:9443"}, false, fakeApply(http.StatusOK, "abc"))
	mux := http.NewServeMux()
	registerAll(mux, srv)

	req := httptest.NewRequest("POST", "/api/v1/coord/config", bytes.NewReader(docsBody(t, map[string]string{
		"worker-a-addr:9443": "{}",
		"arbiter-addr:9443":  "{}",
	})))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (self apply succeeded, only the peer relay failed)", w.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["overall"] != "partial" {
		t.Errorf("overall = %v, want \"partial\" — the unreachable arbiter's own entry should have failed, not blocked the whole push", body["overall"])
	}
	results, _ := body["results"].(map[string]interface{})
	arbiterResult, _ := results["arbiter-addr:9443"].(map[string]interface{})
	if arbiterResult == nil || arbiterResult["ok"] != false {
		t.Errorf("results[arbiter] = %v, want ok:false (unreachable)", arbiterResult)
	}
}

func TestHandleConfig_MissingSelfDocumentIsRejected(t *testing.T) {
	srv := NewServer("core-3", "core-3", "arbiter-addr:9443", []byte("psk"), nil, false, fakeApply(http.StatusOK, "abc"))
	mux := http.NewServeMux()
	registerAll(mux, srv)

	// documents map present but missing an entry for the coordinator's
	// own selfAddr.
	req := httptest.NewRequest("POST", "/api/v1/coord/config", bytes.NewReader(docsBody(t, map[string]string{"some-other-addr:9443": "{}"})))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing self document should be a 400, got %d", w.Code)
	}
}

func TestHandleConfig_ArbiterWithNoPeersAppliesLocallyAndReportsOK(t *testing.T) {
	srv := NewServer("core-3", "core-3", "arbiter-addr:9443", []byte("psk"), nil, false, fakeApply(http.StatusOK, "checksum-1"))
	mux := http.NewServeMux()
	registerAll(mux, srv)

	req := httptest.NewRequest("POST", "/api/v1/coord/config", bytes.NewReader(docsBody(t, map[string]string{"arbiter-addr:9443": `{"log_level":"debug"}`})))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Coordinator string `json:"coordinator"`
		Overall     string `json:"overall"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Coordinator != "core-3" {
		t.Errorf("coordinator = %q, want %q", body.Coordinator, "core-3")
	}
	if body.Overall != "ok" {
		t.Errorf("overall = %q, want %q", body.Overall, "ok")
	}
}

func TestHandleConfig_SelfRejectionNeverRelaysToPeers(t *testing.T) {
	relayed := false
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relayed = true
		w.WriteHeader(http.StatusOK)
	}))
	defer peer.Close()
	peerAddr := peer.Listener.Addr().String()

	srv := NewServer("core-3", "core-3", "arbiter-addr:9443", []byte("psk"), []string{peerAddr}, false, fakeApply(http.StatusBadRequest, ""))
	mux := http.NewServeMux()
	registerAll(mux, srv)

	req := httptest.NewRequest("POST", "/api/v1/coord/config", bytes.NewReader(docsBody(t, map[string]string{
		"arbiter-addr:9443": "{}",
		peerAddr:            "{}",
	})))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var body struct {
		Overall string `json:"overall"`
	}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body.Overall != "rejected" {
		t.Errorf("overall = %q, want %q", body.Overall, "rejected")
	}
	if relayed {
		t.Error("a document this node's own apply rejected must never be relayed to a peer")
	}
}

// coordPeer stands up a real *Server on an httptest.Server so relay tests
// exercise the actual HTTP+HMAC round trip, not a mock.
func coordPeer(t *testing.T, role, nodeID string, psk []byte, apply ApplyFunc) (*httptest.Server, *Server) {
	t.Helper()
	srv := NewServer(role, nodeID, nodeID, psk, nil, false, apply)
	mux := http.NewServeMux()
	registerAll(mux, srv)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, srv
}

func TestHandleConfig_RelaysToRealPeerOverHTTP(t *testing.T) {
	psk := []byte("shared-psk")
	peerTS, _ := coordPeer(t, "core-1", "core-1", psk, fakeApply(http.StatusOK, "checksum-1"))
	peerAddr := peerTS.Listener.Addr().String()

	coord := NewServer("core-3", "core-3", "arbiter-addr:9443", psk, []string{peerAddr}, false, fakeApply(http.StatusOK, "checksum-1"))
	mux := http.NewServeMux()
	registerAll(mux, coord)

	req := httptest.NewRequest("POST", "/api/v1/coord/config", bytes.NewReader(docsBody(t, map[string]string{
		"arbiter-addr:9443": `{"log_level":"debug"}`,
		peerAddr:            `{"log_level":"debug"}`,
	})))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var body struct {
		Overall string                `json:"overall"`
		Results map[string]PeerResult `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Overall != "ok" {
		t.Fatalf("overall = %q, want %q; results=%+v", body.Overall, "ok", body.Results)
	}
	peerRes, ok := body.Results[peerAddr]
	if !ok || !peerRes.OK {
		t.Fatalf("peer result missing or not OK: %+v", body.Results)
	}
}

func TestHandleConfig_RelaysToRealPeerOverTLS(t *testing.T) {
	psk := []byte("shared-psk")

	mux := http.NewServeMux()
	peerSrv := NewServer("core-1", "core-1", "core-1", psk, nil, true, fakeApply(http.StatusOK, "checksum-1"))
	registerAll(mux, peerSrv)
	peerTS := httptest.NewTLSServer(mux)
	t.Cleanup(peerTS.Close)
	peerAddr := peerTS.Listener.Addr().String()

	coord := NewServer("core-3", "core-3", "arbiter-addr:9443", psk, []string{peerAddr}, true, fakeApply(http.StatusOK, "checksum-1"))
	coordMux := http.NewServeMux()
	registerAll(coordMux, coord)

	req := httptest.NewRequest("POST", "/api/v1/coord/config", bytes.NewReader(docsBody(t, map[string]string{
		"arbiter-addr:9443": `{"log_level":"debug"}`,
		peerAddr:            `{"log_level":"debug"}`,
	})))
	w := httptest.NewRecorder()
	coordMux.ServeHTTP(w, req)

	var body struct {
		Overall string                `json:"overall"`
		Results map[string]PeerResult `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Overall != "ok" {
		t.Fatalf("overall = %q, want %q (the pre-fix bug reports \"partial\" with an x509 error) — results=%+v", body.Overall, "ok", body.Results)
	}
	peerRes, ok := body.Results[peerAddr]
	if !ok || !peerRes.OK {
		t.Fatalf("peer result missing or not OK over TLS: %+v", body.Results)
	}
}

func TestHandleConfig_RelaysNonCompactDocumentSuccessfully(t *testing.T) {
	psk := []byte("shared-psk")
	peerTS, _ := coordPeer(t, "core-1", "core-1", psk, fakeApply(http.StatusOK, "checksum-1"))
	peerAddr := peerTS.Listener.Addr().String()

	coord := NewServer("core-3", "core-3", "arbiter-addr:9443", psk, []string{peerAddr}, false, fakeApply(http.StatusOK, "checksum-1"))
	mux := http.NewServeMux()
	registerAll(mux, coord)

	nonCompactDoc := `{"log_level": "debug", "advert_int_ms": 1000}`
	reqBody := `{"documents":{"arbiter-addr:9443":{"log_level":"debug"},"` + peerAddr + `":` + nonCompactDoc + `}}`

	req := httptest.NewRequest("POST", "/api/v1/coord/config", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var body struct {
		Overall string                `json:"overall"`
		Results map[string]PeerResult `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Overall != "ok" {
		t.Fatalf("overall = %q, want %q (the pre-fix bug reports \"partial\" with an HMAC-invalid error) — results=%+v", body.Overall, "ok", body.Results)
	}
	peerRes, ok := body.Results[peerAddr]
	if !ok || !peerRes.OK {
		t.Fatalf("peer result missing or not OK for a non-compact document: %+v", body.Results)
	}
}

func TestHandleConfig_MissingPeerDocumentReportsPartial(t *testing.T) {
	psk := []byte("shared-psk")
	relayed := false
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relayed = true
		w.WriteHeader(http.StatusOK)
	}))
	defer peer.Close()
	peerAddr := peer.Listener.Addr().String()

	coord := NewServer("core-3", "core-3", "arbiter-addr:9443", psk, []string{peerAddr}, false, fakeApply(http.StatusOK, "checksum-1"))
	mux := http.NewServeMux()
	registerAll(mux, coord)

	// Documents map covers self only — the peer's own address is
	// missing, simulating a caller that forgot to include it.
	req := httptest.NewRequest("POST", "/api/v1/coord/config", bytes.NewReader(docsBody(t, map[string]string{"arbiter-addr:9443": "{}"})))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var body struct {
		Overall string                `json:"overall"`
		Results map[string]PeerResult `json:"results"`
	}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body.Overall != "partial" {
		t.Errorf("overall = %q, want %q for a peer with no document", body.Overall, "partial")
	}
	if res, ok := body.Results[peerAddr]; !ok || res.OK || res.Error == "" {
		t.Errorf("expected a missing-document result for the peer, got %+v", res)
	}
	if relayed {
		t.Error("a peer with no document in the push must never be contacted at all")
	}
}

func TestHandleConfig_ChecksumMismatchReportsPartial(t *testing.T) {
	psk := []byte("shared-psk")
	peerTS, _ := coordPeer(t, "core-1", "core-1", psk, fakeApply(http.StatusOK, "checksum-DIFFERENT"))
	peerAddr := peerTS.Listener.Addr().String()

	coord := NewServer("core-3", "core-3", "arbiter-addr:9443", psk, []string{peerAddr}, false, fakeApply(http.StatusOK, "checksum-1"))
	mux := http.NewServeMux()
	registerAll(mux, coord)

	req := httptest.NewRequest("POST", "/api/v1/coord/config", bytes.NewReader(docsBody(t, map[string]string{
		"arbiter-addr:9443": "{}",
		peerAddr:            "{}",
	})))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var body struct {
		Overall string `json:"overall"`
	}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body.Overall != "partial" {
		t.Errorf("overall = %q, want %q on checksum mismatch", body.Overall, "partial")
	}
}

func TestHandleConfig_UnreachablePeerReportsPartial(t *testing.T) {
	psk := []byte("shared-psk")
	coord := NewServer("core-3", "core-3", "arbiter-addr:9443", psk, []string{"127.0.0.1:1"}, false, fakeApply(http.StatusOK, "checksum-1"))
	mux := http.NewServeMux()
	registerAll(mux, coord)

	req := httptest.NewRequest("POST", "/api/v1/coord/config", bytes.NewReader(docsBody(t, map[string]string{
		"arbiter-addr:9443": "{}",
		"127.0.0.1:1":       "{}",
	})))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var body struct {
		Overall string                `json:"overall"`
		Results map[string]PeerResult `json:"results"`
	}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body.Overall != "partial" {
		t.Errorf("overall = %q, want %q for an unreachable peer", body.Overall, "partial")
	}
	if res, ok := body.Results["127.0.0.1:1"]; !ok || res.OK || res.Error == "" {
		t.Errorf("expected an unreachable-peer result with a transport error, got %+v", res)
	}
}

func TestHandleRelay_RejectsWrongPSK(t *testing.T) {
	peerTS, _ := coordPeer(t, "core-1", "core-1", []byte("real-psk"), fakeApply(http.StatusOK, "cs"))
	peerAddr := peerTS.Listener.Addr().String()

	// Sign with a different PSK than the peer holds.
	sender := NewServer("core-3", "core-3", "arbiter-addr:9443", []byte("wrong-psk"), nil, false, nil)
	res := sender.relayToPeer(peerAddr, []byte(`{}`))

	if res.OK {
		t.Error("relay signed with the wrong PSK must be rejected")
	}
}

func TestHandleRelay_RejectsReplayedNonce(t *testing.T) {
	psk := []byte("shared-psk")
	peerTS, _ := coordPeer(t, "core-1", "core-1", psk, fakeApply(http.StatusOK, "cs"))

	sender := NewServer("core-3", "core-3", "arbiter-addr:9443", psk, nil, false, nil)
	addr := peerTS.Listener.Addr().String()
	document := []byte(`{}`)

	first := sender.relayToPeer(addr, document)
	if !first.OK {
		t.Fatalf("first relay should succeed, got %+v", first)
	}

	now := time.Now().Unix()
	nonce := "fixed-nonce-for-replay-test"
	sig := psksign.Sign(psk, signData("core-3", now, nonce, document))

	env := relayEnvelope{NodeID: "core-3", Timestamp: now, Nonce: nonce, HMAC: sig, Document: document}
	body, _ := json.Marshal(env)

	post := func() *http.Response {
		resp, err := http.Post("http://"+addr+"/api/v1/coord/config/relay", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		return resp
	}

	resp1 := post()
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first hand-built relay should succeed, got %d", resp1.StatusCode)
	}
	resp2 := post()
	resp2.Body.Close()
	if resp2.StatusCode == http.StatusOK {
		t.Error("a replayed nonce must be rejected, not re-applied")
	}
}

// labeledApply builds an ApplyFunc that, on success, appends label to the
// shared, mutex-protected log.
func labeledApply(mu *sync.Mutex, log *[]string, label string) ApplyFunc {
	return func(document json.RawMessage) (int, interface{}, string, bool) {
		mu.Lock()
		*log = append(*log, label)
		mu.Unlock()
		return http.StatusOK, map[string]interface{}{"ok": true}, "checksum-1", false
	}
}

func TestHandleConfig_DHCPAffectingPushRelaysSequentiallyWithSettleWait(t *testing.T) {
	psk := []byte("shared-psk")
	var mu sync.Mutex
	var log []string

	peer1TS, _ := coordPeer(t, "core-1", "core-1", psk, labeledApply(&mu, &log, "peer1"))
	peer2TS, _ := coordPeer(t, "core-2", "core-2", psk, labeledApply(&mu, &log, "peer2"))
	peer1Addr := peer1TS.Listener.Addr().String()
	peer2Addr := peer2TS.Listener.Addr().String()

	coord := NewServer("core-3", "core-3", "arbiter-addr:9443", psk, []string{peer1Addr, peer2Addr}, false,
		fakeApplyWithDHCP(http.StatusOK, "checksum-1", true))
	coord.settleWait = func(time.Duration) {
		mu.Lock()
		log = append(log, "settle")
		mu.Unlock()
	}
	mux := http.NewServeMux()
	registerAll(mux, coord)

	req := httptest.NewRequest("POST", "/api/v1/coord/config", bytes.NewReader(docsBody(t, map[string]string{
		"arbiter-addr:9443": `{"log_level":"debug"}`,
		peer1Addr:           `{"log_level":"debug"}`,
		peer2Addr:           `{"log_level":"debug"}`,
	})))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	want := []string{"peer1", "settle", "peer2"}
	if !reflect.DeepEqual(log, want) {
		t.Errorf("call order = %v, want %v (sequential relay with settle strictly between legs)", log, want)
	}
}

// TestHandleConfig_NonDHCPPushStaysConcurrent confirms an ordinary push
// (dhcpAffecting=false) never engages settleWait at all.
func TestHandleConfig_NonDHCPPushStaysConcurrent(t *testing.T) {
	psk := []byte("shared-psk")
	var mu sync.Mutex
	var log []string

	peer1TS, _ := coordPeer(t, "core-1", "core-1", psk, labeledApply(&mu, &log, "peer1"))
	peer2TS, _ := coordPeer(t, "core-2", "core-2", psk, labeledApply(&mu, &log, "peer2"))
	peer1Addr := peer1TS.Listener.Addr().String()
	peer2Addr := peer2TS.Listener.Addr().String()

	settleCalls := 0
	coord := NewServer("core-3", "core-3", "arbiter-addr:9443", psk, []string{peer1Addr, peer2Addr}, false,
		fakeApplyWithDHCP(http.StatusOK, "checksum-1", false))
	coord.settleWait = func(time.Duration) {
		mu.Lock()
		settleCalls++
		mu.Unlock()
	}
	mux := http.NewServeMux()
	registerAll(mux, coord)

	req := httptest.NewRequest("POST", "/api/v1/coord/config", bytes.NewReader(docsBody(t, map[string]string{
		"arbiter-addr:9443": `{"log_level":"debug"}`,
		peer1Addr:           `{"log_level":"debug"}`,
		peer2Addr:           `{"log_level":"debug"}`,
	})))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if settleCalls != 0 {
		t.Errorf("settleWait called %d time(s), want 0 for a non-DHCP-affecting push", settleCalls)
	}
	if len(log) != 2 {
		t.Errorf("log = %v, want both peers relayed to", log)
	}
}

// TestHandleConfig_DHCPAffectingSingleWorkerNeverWaits confirms the settle
// wait is only ever inserted BETWEEN legs.
func TestHandleConfig_DHCPAffectingSingleWorkerNeverWaits(t *testing.T) {
	psk := []byte("shared-psk")
	peerTS, _ := coordPeer(t, "core-1", "core-1", psk, fakeApply(http.StatusOK, "checksum-1"))
	peerAddr := peerTS.Listener.Addr().String()

	settleCalls := 0
	coord := NewServer("core-3", "core-3", "arbiter-addr:9443", psk, []string{peerAddr}, false,
		fakeApplyWithDHCP(http.StatusOK, "checksum-1", true))
	coord.settleWait = func(time.Duration) { settleCalls++ }
	mux := http.NewServeMux()
	registerAll(mux, coord)

	req := httptest.NewRequest("POST", "/api/v1/coord/config", bytes.NewReader(docsBody(t, map[string]string{
		"arbiter-addr:9443": `{"log_level":"debug"}`,
		peerAddr:            `{"log_level":"debug"}`,
	})))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if settleCalls != 0 {
		t.Errorf("settleWait called %d time(s), want 0 for a single peer (nothing left to protect)", settleCalls)
	}
}

func TestHandleConfig_DHCPAffectingFailedLegNeverWaitsButStillProceeds(t *testing.T) {
	psk := []byte("shared-psk")
	var mu sync.Mutex
	var log []string
	peer2TS, _ := coordPeer(t, "core-2", "core-2", psk, labeledApply(&mu, &log, "peer2"))
	peer2Addr := peer2TS.Listener.Addr().String()
	unreachableAddr := "127.0.0.1:1"

	settleCalls := 0
	coord := NewServer("core-3", "core-3", "arbiter-addr:9443", psk, []string{unreachableAddr, peer2Addr}, false,
		fakeApplyWithDHCP(http.StatusOK, "checksum-1", true))
	coord.settleWait = func(time.Duration) { settleCalls++ }
	mux := http.NewServeMux()
	registerAll(mux, coord)

	req := httptest.NewRequest("POST", "/api/v1/coord/config", bytes.NewReader(docsBody(t, map[string]string{
		"arbiter-addr:9443": `{"log_level":"debug"}`,
		unreachableAddr:     `{"log_level":"debug"}`,
		peer2Addr:           `{"log_level":"debug"}`,
	})))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if settleCalls != 0 {
		t.Errorf("settleWait called %d time(s), want 0 — the failed first leg has nothing to settle for", settleCalls)
	}
	if len(log) != 1 || log[0] != "peer2" {
		t.Errorf("log = %v, want the second (reachable) peer still relayed to despite the first failing", log)
	}
}
