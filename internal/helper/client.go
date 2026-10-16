// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package helper provides a client for the dnshived-helper Unix socket.
package helper

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Request matches the helper's expected input.
type Request struct {
	Command   string   `json:"command"`
	Scope     string   `json:"scope"`
	Parent    string   `json:"parent"`
	VLANID    int      `json:"vlan_id"`
	VIP       string   `json:"vip"`
	NodeIP    string   `json:"node_ip"`
	GateState string   `json:"gate_state"`
	Scopes    []string `json:"scopes,omitempty"` // add-scopes only
	// Unit/Lines (journal-tail only).
	Unit  string `json:"unit,omitempty"`
	Lines int    `json:"lines,omitempty"`
	// Action: manage-unit only. Iface: link-up, remove-gate-rule-unscoped.
	Action string `json:"action,omitempty"`
	Iface  string `json:"iface,omitempty"`
}

// Response matches the helper's output.
type Response struct {
	OK           bool            `json:"ok"`
	Error        string          `json:"error,omitempty"`
	GateState    string          `json:"gate_state,omitempty"`
	GateDump     map[string]bool `json:"gate_dump,omitempty"`
	VRRPState    string          `json:"vrrp_state,omitempty"`
	VRRPDump     string          `json:"vrrp_dump,omitempty"`
	Throttled    bool            `json:"throttled,omitempty"`
	JournalLines []string        `json:"journal_lines,omitempty"`
}

// Client communicates with dnshived-helper over a Unix socket.
type Client struct {
	socketPath string
	timeout    time.Duration
}

// NewClient creates a helper client.
func NewClient(socketPath string) *Client {
	return &Client{
		socketPath: socketPath,
		timeout:    5 * time.Second,
	}
}

// roundTrip sends a request and returns the full response, including
// fields (like GateState) that a plain success/error result would discard.
func (c *Client) roundTrip(req Request) (Response, error) {
	conn, err := net.DialTimeout("unix", c.socketPath, c.timeout)
	if err != nil {
		return Response{}, fmt.Errorf("helper connect: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(c.timeout))

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, fmt.Errorf("helper send: %w", err)
	}

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return Response{}, fmt.Errorf("helper recv: %w", err)
	}
	return resp, nil
}

// send sends a request and returns only the error — the common case
// where the caller doesn't need any response payload beyond
// success/failure.
func (c *Client) send(req Request) error {
	resp, err := c.roundTrip(req)
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("helper: %s", resp.Error)
	}
	return nil
}

// CreateInterface creates a VLAN sub-interface with the node IP only, and
// ensures the scope's DHCP gate exists and defaults to closed.
func (c *Client) CreateInterface(scope, parent string, vlanID int, nodeIP string) error {
	return c.send(Request{
		Command: "create-interface",
		Scope:   scope,
		Parent:  parent,
		VLANID:  vlanID,
		NodeIP:  nodeIP,
	})
}

// AddScopes grows the helper's own scope allowlist to include names.
func (c *Client) AddScopes(names []string) error {
	return c.send(Request{
		Command: "add-scopes",
		Scopes:  names,
	})
}

// DeleteInterface removes a VLAN sub-interface and its DHCP gate rule.
func (c *Client) DeleteInterface(scope, parent string, vlanID int) error {
	return c.send(Request{
		Command: "delete-interface",
		Scope:   scope,
		Parent:  parent,
		VLANID:  vlanID,
	})
}

// DeleteInterfaceUnscoped tears down a real interface that has no current
// scope backing it.
func (c *Client) DeleteInterfaceUnscoped(parent string, vlanID int) error {
	return c.send(Request{
		Command: "delete-interface-unscoped",
		Parent:  parent,
		VLANID:  vlanID,
	})
}

// StopDnsmasq stops the dnsmasq unit for a scope.
func (c *Client) StopDnsmasq(scope string) error {
	return c.send(Request{
		Command: "stop-dnsmasq",
		Scope:   scope,
	})
}

// StopDnsmasqUnscoped stops a dnsmasq instance with no current scope
// backing it — an orphan found by the host-vs-config sweep.
func (c *Client) StopDnsmasqUnscoped(scope string) error {
	return c.send(Request{
		Command: "stop-dnsmasq-unscoped",
		Scope:   scope,
	})
}

// StopRelay/StopDNSRelay stop the single consolidated dnshived-relay/
// dnshived-dnsrelay unit outright.
func (c *Client) StopRelay() error {
	return c.send(Request{Command: "stop-relay"})
}

func (c *Client) StopDNSRelay() error {
	return c.send(Request{Command: "stop-dnsrelay"})
}

// RestartDnsmasq restarts the dnsmasq unit for a scope after the daemon
// has re-rendered its config.
func (c *Client) RestartDnsmasq(scope string) (throttled bool, err error) {
	resp, err := c.roundTrip(Request{
		Command: "restart-dnsmasq",
		Scope:   scope,
	})
	if err != nil {
		return false, err
	}
	if !resp.OK {
		return false, fmt.Errorf("helper: %s", resp.Error)
	}
	return resp.Throttled, nil
}

// EnsureKeepalived idempotently starts the single consolidated keepalived
// unit covering every scope.
func (c *Client) EnsureKeepalived() error {
	return c.send(Request{
		Command: "ensure-keepalived",
	})
}

// RestartRelay restarts the single consolidated dnshived-relay unit after
// the daemon has re-rendered relay.json directly.
func (c *Client) RestartRelay() (throttled bool, err error) {
	resp, err := c.roundTrip(Request{Command: "restart-relay"})
	if err != nil {
		return false, err
	}
	if !resp.OK {
		return false, fmt.Errorf("helper: %s", resp.Error)
	}
	return resp.Throttled, nil
}

// ReloadRelay SIGHUPs the single consolidated dnshived-relay unit after
// the daemon has re-rendered relay.json directly.
func (c *Client) ReloadRelay() (throttled bool, err error) {
	resp, err := c.roundTrip(Request{Command: "reload-relay"})
	if err != nil {
		return false, err
	}
	if !resp.OK {
		return false, fmt.Errorf("helper: %s", resp.Error)
	}
	return resp.Throttled, nil
}

// RestartDNSRelay restarts the single consolidated dnshived-dnsrelay unit
// after the daemon has re-rendered dnsrelay.json directly.
func (c *Client) RestartDNSRelay() (throttled bool, err error) {
	resp, err := c.roundTrip(Request{Command: "restart-dnsrelay"})
	if err != nil {
		return false, err
	}
	if !resp.OK {
		return false, fmt.Errorf("helper: %s", resp.Error)
	}
	return resp.Throttled, nil
}

// ReloadDNSRelay SIGHUPs the single consolidated dnshived-dnsrelay unit
// after the daemon has re-rendered dnsrelay.json directly.
func (c *Client) ReloadDNSRelay() (throttled bool, err error) {
	resp, err := c.roundTrip(Request{Command: "reload-dnsrelay"})
	if err != nil {
		return false, err
	}
	if !resp.OK {
		return false, fmt.Errorf("helper: %s", resp.Error)
	}
	return resp.Throttled, nil
}

// RestartCoreDNS/RestartCoreDHCP restart the two consolidated,
// reserved-instance-name dnsmasq units after the daemon re-renders their
// config.
func (c *Client) RestartCoreDNS() (throttled bool, err error) {
	resp, err := c.roundTrip(Request{Command: "restart-core-dns"})
	if err != nil {
		return false, err
	}
	if !resp.OK {
		return false, fmt.Errorf("helper: %s", resp.Error)
	}
	return resp.Throttled, nil
}

func (c *Client) RestartCoreDHCP() (throttled bool, err error) {
	resp, err := c.roundTrip(Request{Command: "restart-core-dhcp"})
	if err != nil {
		return false, err
	}
	if !resp.OK {
		return false, fmt.Errorf("helper: %s", resp.Error)
	}
	return resp.Throttled, nil
}

func (c *Client) ReloadCoreDHCP() (throttled bool, err error) {
	resp, err := c.roundTrip(Request{Command: "reload-core-dhcp"})
	if err != nil {
		return false, err
	}
	if !resp.OK {
		return false, fmt.Errorf("helper: %s", resp.Error)
	}
	return resp.Throttled, nil
}

// ReloadCoreDNS is ReloadCoreDHCP's own sibling for central DNS's
// separate, reload-capable dynamic-hosts file
// (internal/dnscentralrender.DynamicHostsFileName).
func (c *Client) ReloadCoreDNS() (throttled bool, err error) {
	resp, err := c.roundTrip(Request{Command: "reload-core-dns"})
	if err != nil {
		return false, err
	}
	if !resp.OK {
		return false, fmt.Errorf("helper: %s", resp.Error)
	}
	return resp.Throttled, nil
}

// ReloadKeepalived reloads the consolidated keepalived unit after its
// config has been re-rendered.
func (c *Client) ReloadKeepalived() (throttled bool, err error) {
	resp, err := c.roundTrip(Request{
		Command: "reload-keepalived",
	})
	if err != nil {
		return false, err
	}
	if !resp.OK {
		return false, fmt.Errorf("helper: %s", resp.Error)
	}
	return resp.Throttled, nil
}

// SetDHCPGate opens or closes the DHCP gate for a scope.
func (c *Client) SetDHCPGate(scope, parent string, vlanID int, state string) error {
	return c.send(Request{
		Command:   "set-dhcp-gate",
		Scope:     scope,
		Parent:    parent,
		VLANID:    vlanID,
		GateState: state,
	})
}

func (c *Client) GetDHCPGate(scope, parent string, vlanID int) (string, error) {
	resp, err := c.roundTrip(Request{
		Command: "get-dhcp-gate",
		Scope:   scope,
		Parent:  parent,
		VLANID:  vlanID,
	})
	if err != nil {
		return "", err
	}
	if !resp.OK {
		return "", fmt.Errorf("helper: %s", resp.Error)
	}
	return resp.GateState, nil
}

// GetDHCPGateDump returns every gated interface's closed/open state (iface
// -> true if closed) in one round trip.
func (c *Client) GetDHCPGateDump() (map[string]bool, error) {
	resp, err := c.roundTrip(Request{Command: "dhcp-gate-dump"})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("helper: %s", resp.Error)
	}
	return resp.GateDump, nil
}

// GetVRRPState reads back a scope's current VRRP state (MASTER/BACKUP/
// FAULT/etc.) from the consolidated keepalived process.
func (c *Client) GetVRRPState(scope string) (string, error) {
	resp, err := c.roundTrip(Request{
		Command: "get-vrrp-state",
		Scope:   scope,
	})
	if err != nil {
		return "", err
	}
	if !resp.OK {
		return "", fmt.Errorf("helper: %s", resp.Error)
	}
	return resp.VRRPState, nil
}

// GetMgmtVRRPState reads back the management VIP's own current VRRP state
// (MASTER/BACKUP/FAULT/etc.) from its SEPARATE keepalived-mgmt process.
func (c *Client) GetMgmtVRRPState() (string, error) {
	resp, err := c.roundTrip(Request{Command: "get-mgmt-vrrp-state"})
	if err != nil {
		return "", err
	}
	if !resp.OK {
		return "", fmt.Errorf("helper: %s", resp.Error)
	}
	return resp.VRRPState, nil
}

// GetVRRPDump returns the consolidated keepalived process's raw SIGDATA
// dump (every vrrp_instance's state in one text blob).
func (c *Client) GetVRRPDump() ([]byte, error) {
	resp, err := c.roundTrip(Request{Command: "vrrp-dump"})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("helper: %s", resp.Error)
	}
	return []byte(resp.VRRPDump), nil
}

func (c *Client) GetJournalTail(unit string, lines int) ([]string, error) {
	resp, err := c.roundTrip(Request{Command: "journal-tail", Unit: unit, Lines: lines})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("helper: %s", resp.Error)
	}
	return resp.JournalLines, nil
}

// StopMgmtKeepalived stops and disables the management-VIP keepalived
// unit.
func (c *Client) StopMgmtKeepalived() error {
	return c.send(Request{
		Command: "stop-mgmt-keepalived",
	})
}

// RestartDaemon restarts dnshived.service itself, on an operator's
// explicit request.
func (c *Client) RestartDaemon() (throttled bool, err error) {
	resp, err := c.roundTrip(Request{
		Command: "restart-daemon",
	})
	if err != nil {
		return false, err
	}
	if !resp.OK {
		return false, fmt.Errorf("helper: %s", resp.Error)
	}
	return resp.Throttled, nil
}

// ReloadMgmtKeepalived makes the management-VIP keepalived re-read a
// changed config (starting it if it isn't running).
func (c *Client) ReloadMgmtKeepalived() error {
	return c.send(Request{
		Command: "reload-mgmt-keepalived",
	})
}

// EnsureMgmtKeepalived enables and starts the management-VIP keepalived
// unit, leaving an already-running one untouched.
func (c *Client) EnsureMgmtKeepalived() error {
	return c.send(Request{
		Command: "ensure-mgmt-keepalived",
	})
}

// RestartMgmtKeepalived restarts the management-VIP keepalived unit on an
// operator's explicit request.
func (c *Client) RestartMgmtKeepalived() (throttled bool, err error) {
	resp, err := c.roundTrip(Request{
		Command: "restart-mgmt-keepalived",
	})
	if err != nil {
		return false, err
	}
	if !resp.OK {
		return false, fmt.Errorf("helper: %s", resp.Error)
	}
	return resp.Throttled, nil
}

func (c *Client) RestartHelper() (throttled bool, err error) {
	resp, err := c.roundTrip(Request{
		Command: "restart-helper",
	})
	if err != nil {
		return false, err
	}
	if !resp.OK {
		return false, fmt.Errorf("helper: %s", resp.Error)
	}
	return resp.Throttled, nil
}

// RestartWeb restarts dnshived-web.service on an operator's explicit
// request.
func (c *Client) RestartWeb() (throttled bool, err error) {
	resp, err := c.roundTrip(Request{
		Command: "restart-web",
	})
	if err != nil {
		return false, err
	}
	if !resp.OK {
		return false, fmt.Errorf("helper: %s", resp.Error)
	}
	return resp.Throttled, nil
}

// Reachable reports whether the helper's Unix socket accepts a connection,
// without sending any command.
func (c *Client) Reachable() bool {
	conn, err := net.DialTimeout("unix", c.socketPath, c.timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// LinkUp brings an existing interface up (never down).
func (c *Client) LinkUp(iface string) error {
	return c.send(Request{Command: "link-up", Iface: iface})
}

// RemoveGateRuleUnscoped removes an orphan DHCP gate rule that no
// configured scope backs.
func (c *Client) RemoveGateRuleUnscoped(iface string) error {
	return c.send(Request{Command: "remove-gate-rule-unscoped", Iface: iface})
}

// unitTimeout covers a systemctl stop that waits for the unit's own stop
// timeout.
const unitTimeout = 30 * time.Second

// ManageUnit runs one allowlisted unit action (enable-now, enable,
// disable-now) for adopt and self-decommission.
func (c *Client) ManageUnit(action, unit string) error {
	slow := &Client{socketPath: c.socketPath, timeout: unitTimeout}
	return slow.send(Request{Command: "manage-unit", Action: action, Unit: unit})
}

// ResetScopeState drops every add-scopes name, back to the helper's
// --scopes list.
func (c *Client) ResetScopeState() error {
	return c.send(Request{Command: "reset-scope-state"})
}

// FinishDecommission schedules the restart into bootstrap mode, then the
// helper stops itself.
func (c *Client) FinishDecommission() error {
	return c.send(Request{Command: "finish-decommission"})
}
