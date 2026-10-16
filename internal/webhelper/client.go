// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package webhelper

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Request matches dnshived-web-helper's expected input — one command, so
// no fields beyond Command exist to send.
type Request struct {
	Command string `json:"command"`
}

// Response matches dnshived-web-helper's output.
type Response struct {
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	Throttled bool   `json:"throttled,omitempty"`
}

// Client communicates with dnshived-web-helper over a Unix socket.
type Client struct {
	socketPath string
	timeout    time.Duration
}

// NewClient creates a webhelper client.
func NewClient(socketPath string) *Client {
	return &Client{socketPath: socketPath, timeout: 5 * time.Second}
}

func (c *Client) RestartSelf() (throttled bool, err error) {
	conn, err := net.DialTimeout("unix", c.socketPath, c.timeout)
	if err != nil {
		return false, fmt.Errorf("webhelper connect: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(c.timeout))

	if err := json.NewEncoder(conn).Encode(Request{Command: "restart-self"}); err != nil {
		return false, fmt.Errorf("webhelper send: %w", err)
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return false, fmt.Errorf("webhelper recv: %w", err)
	}
	if !resp.OK {
		return false, fmt.Errorf("webhelper: %s", resp.Error)
	}
	return resp.Throttled, nil
}
