// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcprelay

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"strconv"
	"time"

	"dnshived/internal/unixsock"
)

// gateRequest is one command on the gate socket.
type gateRequest struct {
	Command      string            `json:"command"`
	Scope        string            `json:"scope"`
	Incarnation  uint64            `json:"incarnation"`
	Tokens       []json.RawMessage `json:"tokens"`
	Quorum       int               `json:"quorum"`
	QuorumReason string            `json:"quorum_reason"`
	PSK          string            `json:"psk"`
}

type scopeStatus struct {
	Scope      string  `json:"scope"`
	Gate       string  `json:"gate"`
	Deadline   *string `json:"deadline"`
	LastReason string  `json:"last_reason"`
}

type gateReply struct {
	OK       bool                    `json:"ok"`
	Error    string                  `json:"error,omitempty"`
	Deadline string                  `json:"deadline,omitempty"`
	Version  string                  `json:"version,omitempty"`
	UptimeS  int64                   `json:"uptime_s,omitempty"`
	Clock    string                  `json:"clock,omitempty"`
	Scopes   []scopeStatus           `json:"scopes,omitempty"`
	Counters *Metrics                `json:"counters,omitempty"`
	VLANs    map[string]VLANSnapshot `json:"vlans,omitempty"`
}

// ConfigureGate sets the gate socket path, the track-file directory and the version status reports. Call before Start.
func (r *Relay) ConfigureGate(socketPath, runDir, version string) error {
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return fmt.Errorf("runtime directory %s: %w", runDir, err)
	}
	r.gateSocket = socketPath
	r.runDir = runDir
	r.version = version
	r.gates.setRunDir(runDir)
	return nil
}

// startGateServer opens the control socket. Only root and the dnshived user may connect (SOCKET_PROTOCOL §1).
func (r *Relay) startGateServer() error {
	allow := []uint32{0}
	if u, err := user.Lookup("dnshived"); err == nil {
		if uid, err := strconv.ParseUint(u.Uid, 10, 32); err == nil {
			allow = append(allow, uint32(uid))
		}
	} else {
		log.Printf("[RELAY:GATE] user dnshived not found: only root may use the gate socket")
	}
	srv, err := unixsock.Listen(r.gateSocket, 0o660, unixsock.Limits{
		MaxConns:     4,
		Deadline:     5 * time.Second,
		MaxRequest:   4 << 10,
		DrainTimeout: 5 * time.Second,
		AllowUIDs:    allow,
	})
	if err != nil {
		return err
	}
	r.gateServer = srv
	go srv.Serve(r.serveGate, func(peer unixsock.Peer, err error) {
		log.Printf("[RELAY:GATE] connection refused from %s: %v", peer, err)
	})
	log.Printf("[RELAY:GATE] control socket %s", r.gateSocket)
	return nil
}

func (r *Relay) serveGate(conn net.Conn) {
	var resp gateReply
	var req gateRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		resp = gateReply{Error: "invalid request: " + err.Error()}
	} else {
		resp = r.handleGate(req, time.Now())
	}
	if body, err := json.Marshal(resp); err == nil {
		conn.Write(append(body, '\n'))
	}
}

func (r *Relay) handleGate(req gateRequest, now time.Time) gateReply {
	switch req.Command {
	case "status":
		return r.gateStatus(now)
	case "authorize":
		deadline, err := r.gates.authorize(req.Scope, req.Tokens, req.Incarnation, req.Quorum, req.QuorumReason, now)
		if err != nil {
			return gateReply{Error: err.Error()}
		}
		return gateReply{OK: true, Deadline: deadline.Format(time.RFC3339Nano)}
	case "revoke":
		r.gates.revoke(req.Scope, "revoked by daemon", now)
		return gateReply{OK: true}
	case "revoke-all":
		r.gates.revokeAll("revoked by daemon (revoke-all)", now)
		return gateReply{OK: true}
	case "set-psk":
		if req.PSK == "" {
			return gateReply{Error: "psk must not be empty"}
		}
		r.gates.setPSK([]byte(req.PSK))
		return gateReply{OK: true}
	default:
		return gateReply{Error: "unknown command: " + req.Command}
	}
}

func (r *Relay) gateStatus(now time.Time) gateReply {
	clock := "unhealthy"
	if r.gates.clockOK.Load() {
		clock = "healthy"
	}
	counters := r.Snapshot()
	reply := gateReply{
		OK:       true,
		Version:  r.version,
		UptimeS:  int64(now.Sub(r.startedAt).Seconds()),
		Clock:    clock,
		Counters: &counters,
		VLANs:    r.VLANSnapshots(),
	}
	r.gates.mu.Lock()
	defer r.gates.mu.Unlock()
	for name, g := range r.gates.scopes {
		st := scopeStatus{Scope: name, Gate: "closed", LastReason: g.reason}
		if d := g.deadline.Load(); r.gates.allows(g, now) {
			st.Gate = "open"
			s := time.Unix(0, d).Format(time.RFC3339Nano)
			st.Deadline = &s
		}
		reply.Scopes = append(reply.Scopes, st)
	}
	return reply
}
