// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package probehelper

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Request matches dnshived-probe-helper's expected input.
type Request struct {
	Command string `json:"command"`
	Content []byte `json:"content,omitempty"`
	Parent  string `json:"parent,omitempty"`
	VLANID  int    `json:"vlan_id,omitempty"`
	Addr    string `json:"addr,omitempty"`
	// Unit/Lines (journal-tail only).
	Unit  string `json:"unit,omitempty"`
	Lines int    `json:"lines,omitempty"`
}

// Response matches dnshived-probe-helper's output.
type Response struct {
	OK           bool     `json:"ok"`
	Error        string   `json:"error,omitempty"`
	Throttled    bool     `json:"throttled,omitempty"`
	JournalLines []string `json:"journal_lines,omitempty"`
}

// Client communicates with dnshived-probe-helper over a Unix socket.
type Client struct {
	socketPath string
	timeout    time.Duration
}

// NewClient creates a probehelper client.
func NewClient(socketPath string) *Client {
	return &Client{socketPath: socketPath, timeout: 5 * time.Second}
}

// RestartSelf restarts dnshived-probe.service itself, on an operator's
// explicit request.
func (c *Client) RestartSelf() (throttled bool, err error) {
	conn, err := net.DialTimeout("unix", c.socketPath, c.timeout)
	if err != nil {
		return false, fmt.Errorf("probehelper connect: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(c.timeout))

	if err := json.NewEncoder(conn).Encode(Request{Command: "restart-self"}); err != nil {
		return false, fmt.Errorf("probehelper send: %w", err)
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return false, fmt.Errorf("probehelper recv: %w", err)
	}
	if !resp.OK {
		return false, fmt.Errorf("probehelper: %s", resp.Error)
	}
	return resp.Throttled, nil
}

// GetJournalTail returns the last `lines` journal lines for one of this
// probe host's own units (dnshived-probe.service,
// dnshived-probe-helper.service).
func (c *Client) GetJournalTail(unit string, lines int) ([]string, error) {
	conn, err := net.DialTimeout("unix", c.socketPath, c.timeout)
	if err != nil {
		return nil, fmt.Errorf("probehelper connect: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(c.timeout))

	if err := json.NewEncoder(conn).Encode(Request{Command: "journal-tail", Unit: unit, Lines: lines}); err != nil {
		return nil, fmt.Errorf("probehelper send: %w", err)
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("probehelper recv: %w", err)
	}
	if !resp.OK {
		return nil, fmt.Errorf("probehelper: %s", resp.Error)
	}
	return resp.JournalLines, nil
}

// WriteConfig writes content to the probe helper's one hardcoded target,
// /etc/dnshived/probe.json.
func (c *Client) WriteConfig(content []byte) error {
	conn, err := net.DialTimeout("unix", c.socketPath, c.timeout)
	if err != nil {
		return fmt.Errorf("probehelper connect: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(c.timeout))

	if err := json.NewEncoder(conn).Encode(Request{Command: "write-config", Content: content}); err != nil {
		return fmt.Errorf("probehelper send: %w", err)
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return fmt.Errorf("probehelper recv: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("probehelper: %s", resp.Error)
	}
	return nil
}

// StopCoreDaemons stops+disables dnshived.service/dnshived-helper.service
// on this same host.
func (c *Client) StopCoreDaemons() error {
	conn, err := net.DialTimeout("unix", c.socketPath, c.timeout)
	if err != nil {
		return fmt.Errorf("probehelper connect: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(c.timeout))

	if err := json.NewEncoder(conn).Encode(Request{Command: "stop-core-daemons"}); err != nil {
		return fmt.Errorf("probehelper send: %w", err)
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return fmt.Errorf("probehelper recv: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("probehelper: %s", resp.Error)
	}
	return nil
}

// CreateInterface creates a VLAN sub-interface (parent.vlanID) and assigns
// it addr (CIDR).
func (c *Client) CreateInterface(parent string, vlanID int, addr string) error {
	return c.doInterfaceCmd(Request{Command: "create-interface", Parent: parent, VLANID: vlanID, Addr: addr})
}

// DeleteInterface tears down a VLAN sub-interface previously created by
// CreateInterface.
func (c *Client) DeleteInterface(parent string, vlanID int, addr string) error {
	return c.doInterfaceCmd(Request{Command: "delete-interface", Parent: parent, VLANID: vlanID, Addr: addr})
}

func (c *Client) doInterfaceCmd(req Request) error {
	conn, err := net.DialTimeout("unix", c.socketPath, c.timeout)
	if err != nil {
		return fmt.Errorf("probehelper connect: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(c.timeout))

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return fmt.Errorf("probehelper send: %w", err)
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return fmt.Errorf("probehelper recv: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("probehelper: %s", resp.Error)
	}
	return nil
}

func (c *Client) Decommission() error {
	conn, err := net.DialTimeout("unix", c.socketPath, 15*time.Second)
	if err != nil {
		return fmt.Errorf("probehelper connect: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	if err := json.NewEncoder(conn).Encode(Request{Command: "decommission"}); err != nil {
		return fmt.Errorf("probehelper send: %w", err)
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return fmt.Errorf("probehelper recv: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("probehelper: %s", resp.Error)
	}
	return nil
}
