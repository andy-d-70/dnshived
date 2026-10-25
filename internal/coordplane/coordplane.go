// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package coordplane

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"dnshived/internal/loglevel"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"dnshived/internal/psksign"
	"dnshived/internal/tlspin"
)

const (
	// relayTimestampWindow bounds how stale a relay envelope's own timestamp
	// may be — mirrors internal/arbiter's identical window for its
	// witness-token protocol.
	relayTimestampWindow = 5 // seconds

	// nonceMaxAge is how long a seen relay nonce is remembered before its
	// entry is dropped.
	nonceMaxAge = 60 // seconds

	// relayClientTimeout bounds a single peer relay call.
	relayClientTimeout = 10 * time.Second

	dhcpStaggerSettle = 8 * time.Second
)

// ApplyFunc applies a raw pushed config document to this node's own
// running config.
type ApplyFunc func(document json.RawMessage) (status int, body interface{}, checksum string, dhcpAffecting bool)

// PeerResult is one peer's outcome from a config relay.
type PeerResult struct {
	OK       bool        `json:"ok"`
	Status   int         `json:"status,omitempty"`
	Checksum string      `json:"checksum,omitempty"`
	Body     interface{} `json:"body,omitempty"`
	Error    string      `json:"error,omitempty"`
}

// relayEnvelope is the wire shape POST /api/v1/coord/config/relay accepts.
type relayEnvelope struct {
	NodeID    string          `json:"node_id"`
	Timestamp int64           `json:"timestamp"`
	Nonce     string          `json:"nonce"`
	HMAC      string          `json:"hmac"`
	Document  json.RawMessage `json:"document"`
}

// signData returns the canonical string a relayEnvelope's HMAC covers.
func signData(nodeID string, timestamp int64, nonce string, document []byte) string {
	digest := sha256.Sum256(document)
	return fmt.Sprintf("%s:%d:%s:%s", nodeID, timestamp, nonce, hex.EncodeToString(digest[:]))
}

// Server implements the coordination plane's config-write leg on one core
// node.
type Server struct {
	role     string
	nodeID   string
	selfAddr string
	psk      []byte
	peers    []string
	peersFn  func() []string
	scheme   string
	apply    ApplyFunc

	httpClient *http.Client

	// settleWait is dhcpStaggerSettle's own actual wait mechanism.
	settleWait func(time.Duration)

	mu    sync.Mutex
	nonce map[string]int64 // nonce → seen-at unix time, for relay replay protection
}

// NewServer constructs a Server.
func (s *Server) SetPeersFunc(f func() []string) {
	s.mu.Lock()
	s.peersFn = f
	s.mu.Unlock()
}

func (s *Server) currentPeers() []string {
	s.mu.Lock()
	f := s.peersFn
	s.mu.Unlock()
	if f != nil {
		return f()
	}
	return s.peers
}

func NewServer(role, nodeID, selfAddr string, psk []byte, peers []string, useTLS bool, apply ApplyFunc) *Server {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	s := &Server{
		role:     role,
		nodeID:   nodeID,
		selfAddr: selfAddr,
		psk:      psk,
		peers:    peers,
		scheme:   scheme,
		apply:    apply,
		nonce:    make(map[string]int64),
		httpClient: &http.Client{
			Timeout: relayClientTimeout,
		},
		settleWait: time.Sleep,
	}
	if useTLS {
		s.httpClient.Transport = &http.Transport{
			TLSClientConfig: tlspin.Config(),
		}
	}
	go s.cleanupLoop()
	return s
}

func (s *Server) cleanupLoop() {
	ticker := time.NewTicker(nonceMaxAge * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Unix() - nonceMaxAge
		s.mu.Lock()
		for n, ts := range s.nonce {
			if ts < cutoff {
				delete(s.nonce, n)
			}
		}
		s.mu.Unlock()
	}
}

// AddRoutes registers the node-to-node relay route only — it's
// internally PSK-authenticated (see handleRelay), so it needs no wrapping
// by the caller.
func (s *Server) AddRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/coord/config/relay", s.handleRelay)
}

// ConfigHandler returns the "POST /api/v1/coord/config" handler for the
// caller to register (wrapped in admin auth) itself.
func (s *Server) ConfigHandler() http.HandlerFunc {
	return s.handleConfig
}

// configRequest is the wire shape POST /api/v1/coord/config accepts.
type configRequest struct {
	Documents map[string]json.RawMessage `json:"documents"`
}

// handleConfig serves POST /api/v1/coord/config — the entry point -web
// (or any other admin-authenticated caller) posts a config update to.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	var req configRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	if s.role != "core-3" {
		loglevel.Infof("[COORDPLANE:COORDINATE] processing config push as %s (role=%s) — core-3 (the mgmt VIP's preferred holder) is presumably unreachable, standing in as coordinator", s.nodeID, s.role)
	}

	selfDoc, haveSelf := req.Documents[s.selfAddr]
	if !haveSelf {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("no document provided for this node's own address (%s) — every documents map must include an entry for the coordinator itself", s.selfAddr),
		})
		return
	}

	selfStatus, selfBody, selfChecksum, dhcpAffecting := s.apply(selfDoc)
	results := map[string]PeerResult{
		s.selfAddr: {OK: selfStatus == http.StatusOK, Status: selfStatus, Checksum: selfChecksum, Body: selfBody},
	}

	if selfStatus != http.StatusOK {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"coordinator": s.nodeID,
			"results":     results,
			"overall":     "rejected",
		})
		return
	}

	if dhcpAffecting {
		s.relayToPeersSequentially(req, results)
	} else {
		s.relayToPeersConcurrently(req, results)
	}

	overall := "ok"
	for key, res := range results {
		if !res.OK {
			overall = "partial"
			loglevel.Warnf("[COORDPLANE:PUSH_FAIL] peer %s rejected or unreachable: %s", key, res.Error)
			continue
		}
		if key != s.selfAddr && res.Checksum != selfChecksum {
			overall = "partial"
			loglevel.Warnf("[COORDPLANE:CHECKSUM_MISMATCH] peer %s checksum=%s want=%s", key, res.Checksum, selfChecksum)
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"coordinator": s.nodeID,
		"results":     results,
		"overall":     overall,
	})
}

// relayToPeersConcurrently is the default relay strategy.
func (s *Server) relayToPeersConcurrently(req configRequest, results map[string]PeerResult) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, addr := range s.currentPeers() {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			peerDoc, ok := req.Documents[addr]
			var res PeerResult
			if !ok {
				res = PeerResult{Error: "no document provided for this peer's address in the push"}
			} else {
				res = s.relayToPeer(addr, peerDoc)
			}
			mu.Lock()
			results[addr] = res
			mu.Unlock()
		}(addr)
	}
	wg.Wait()
}

func (s *Server) relayToPeersSequentially(req configRequest, results map[string]PeerResult) {
	peers := s.currentPeers()
	loglevel.Infof("[COORDPLANE:STAGGER] config push affects central DHCP — relaying to %d peer(s) sequentially with a %s settle wait between each", len(peers), dhcpStaggerSettle)
	for i, addr := range peers {
		peerDoc, ok := req.Documents[addr]
		var res PeerResult
		if !ok {
			res = PeerResult{Error: "no document provided for this peer's address in the push"}
		} else {
			res = s.relayToPeer(addr, peerDoc)
		}
		results[addr] = res
		if res.OK && i < len(peers)-1 {
			s.settleWait(dhcpStaggerSettle)
		}
	}
}

// relayToPeer signs and POSTs document (this specific peer's own
// already-derived copy) to that peer's own /api/v1/coord/config/relay
// endpoint.
func (s *Server) relayToPeer(addr string, document []byte) PeerResult {
	// Compact BEFORE signing, not after.
	var buf bytes.Buffer
	if err := json.Compact(&buf, document); err != nil {
		return PeerResult{Error: "invalid document JSON: " + err.Error()}
	}
	document = buf.Bytes()

	now := time.Now().Unix()
	nonce := randomHex(16)
	sig := psksign.Sign(s.psk, signData(s.nodeID, now, nonce, document))

	env := relayEnvelope{
		NodeID:    s.nodeID,
		Timestamp: now,
		Nonce:     nonce,
		HMAC:      sig,
		Document:  json.RawMessage(document),
	}
	body, err := json.Marshal(env)
	if err != nil {
		return PeerResult{Error: "encode relay envelope: " + err.Error()}
	}

	url := s.scheme + "://" + addr + "/api/v1/coord/config/relay"
	resp, err := s.httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return PeerResult{Error: "unreachable: " + err.Error()}
	}
	defer resp.Body.Close()

	var out struct {
		OK       bool        `json:"ok"`
		Checksum string      `json:"checksum"`
		Body     interface{} `json:"body"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return PeerResult{Status: resp.StatusCode, Error: "decode response: " + err.Error()}
	}
	return PeerResult{
		OK:       resp.StatusCode == http.StatusOK && out.OK,
		Status:   resp.StatusCode,
		Checksum: out.Checksum,
		Body:     out.Body,
	}
}

// handleRelay serves POST /api/v1/coord/config/relay — the node-to-node
// leaf endpoint.
func (s *Server) handleRelay(w http.ResponseWriter, r *http.Request) {
	var env relayEnvelope
	if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	if !psksign.Verify(s.psk, signData(env.NodeID, env.Timestamp, env.Nonce, env.Document), env.HMAC) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "HMAC invalid"})
		return
	}

	now := time.Now().Unix()
	if abs64(now-env.Timestamp) > relayTimestampWindow {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "timestamp out of window"})
		return
	}

	s.mu.Lock()
	if _, seen := s.nonce[env.Nonce]; seen {
		s.mu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nonce reused"})
		return
	}
	s.nonce[env.Nonce] = now
	s.mu.Unlock()

	status, body, checksum, _ := s.apply(env.Document)
	resp := map[string]interface{}{
		"ok":       status == http.StatusOK,
		"checksum": checksum,
		"body":     body,
	}
	writeJSON(w, status, resp)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b)
}
