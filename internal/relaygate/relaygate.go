// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package relaygate is the daemon's client for the DHCP relay's gate socket:
// the PSK, authorize with the held witness tokens, and revoke. One request per connection.
package relaygate

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

// DefaultPath is the gate socket of the relay on a standard install.
const DefaultPath = "/run/dnshived-relay/relay-gate.sock"

const callTimeout = 5 * time.Second

// Client sends commands to one relay's gate socket.
type Client struct {
	Path string
}

// Available reports whether a relay's gate socket exists on this node. A node without a relay (or with the
// old one) has none, so no scope can be opened on that node.
func (c *Client) Available() bool {
	_, err := os.Stat(c.Path)
	return err == nil
}

type request struct {
	Command      string            `json:"command"`
	Scope        string            `json:"scope,omitempty"`
	Incarnation  uint64            `json:"incarnation"`
	Tokens       []json.RawMessage `json:"tokens,omitempty"`
	QuorumReason string            `json:"quorum_reason,omitempty"`
	PSK          string            `json:"psk,omitempty"`
}

type reply struct {
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Deadline string `json:"deadline,omitempty"`
}

func (c *Client) call(req request) (reply, error) {
	conn, err := net.DialTimeout("unix", c.Path, callTimeout)
	if err != nil {
		return reply{}, fmt.Errorf("relay gate socket: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(callTimeout))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return reply{}, fmt.Errorf("relay gate socket: send: %w", err)
	}
	var resp reply
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return reply{}, fmt.Errorf("relay gate socket: reply: %w", err)
	}
	if !resp.OK {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

// SetPSK gives the relay the cluster PSK. It is kept in the relay's memory only.
func (c *Client) SetPSK(psk string) error {
	_, err := c.call(request{Command: "set-psk", PSK: psk})
	return err
}

// Authorize opens scope on the relay until the tokens' earliest expiry minus the relay's margin. It returns the
// deadline the relay set.
func (c *Client) Authorize(scope string, incarnation uint64, tokens []json.RawMessage, reason string) (string, error) {
	resp, err := c.call(request{Command: "authorize", Scope: scope, Incarnation: incarnation, Tokens: tokens, QuorumReason: reason})
	return resp.Deadline, err
}

// Revoke closes scope at once.
func (c *Client) Revoke(scope string) error {
	_, err := c.call(request{Command: "revoke", Scope: scope})
	return err
}

// RevokeAll closes every scope.
func (c *Client) RevokeAll() error {
	_, err := c.call(request{Command: "revoke-all"})
	return err
}
