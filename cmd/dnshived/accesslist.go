// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"

	"dnshived/internal/access"
	"dnshived/internal/activation"
	"dnshived/internal/agent"
	"dnshived/internal/cluster"
	"dnshived/internal/config"
)

var accessGate = &outageRules{}

// accessAgent is the running agent, for the latch goroutine that starts before it exists.
var accessAgent atomic.Pointer[agent.Agent]

const dhcpRelayAccessReportPath = "/run/dnshived-relay/access-report.json"

const dnsRelayAccessReportPath = "/var/lib/dnshived-dnsrelay/access-report.json"

func persistAccessLatch(cfgPath string) error {
	cfgWriteMu.Lock()
	defer cfgWriteMu.Unlock()
	c, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if c.AccessListActive {
		currentConfig.Store(c)
		return nil
	}
	c.AccessListActive = true
	if err := config.Save(cfgPath, c); err != nil {
		return err
	}
	currentConfig.Store(c)
	return nil
}

// applyAccessToAgent gives the agent the list, the always-allowed addresses and the latch; the relays pick
// them up on the agent's next reconcile.
func applyAccessToAgent(ag *agent.Agent, c *config.Cluster) {
	if ag == nil || c == nil {
		return
	}
	ag.SetAccess(c.Access, c.AccessAlways(), accessGate.Active())
}

// accessUpdate is the "access" key of a configuration push. A push without the key leaves the list as it is
// (an older web interface does not know it); null clears it; an object replaces it.
type accessUpdate struct {
	present bool
	cfg     *access.Config
}

func parseAccessUpdate(raw json.RawMessage) (accessUpdate, error) {
	if len(raw) == 0 {
		return accessUpdate{}, nil
	}
	if string(raw) == "null" {
		return accessUpdate{present: true}, nil
	}
	var c access.Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return accessUpdate{}, fmt.Errorf("access: %w", err)
	}
	if err := c.Validate(); err != nil {
		return accessUpdate{}, err
	}
	return accessUpdate{present: true, cfg: &c}, nil
}

func (u accessUpdate) applyTo(c *config.Cluster) {
	if u.present {
		c.Access = u.cfg
	}
}

type accessStateResponse struct {
	Active   bool                 `json:"active"`
	Required string               `json:"required"`
	Blocking []activation.Blocker `json:"blocking,omitempty"`
	Mode     string               `json:"mode"`
	List     *access.Config       `json:"list,omitempty"`
	Always   []string             `json:"always,omitempty"`
	DNS      access.Report        `json:"dns"`
	DHCP     access.Report        `json:"dhcp"`
}

func accessStateHandler(observer *cluster.Observer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res := evaluateActivation(observer, activation.AccessListVersion)
		cur := currentConfig.Load()
		out := accessStateResponse{Active: accessGate.Active(), Required: activation.AccessListVersion, Blocking: res.Blocking, Mode: access.ModeReport}
		if cur != nil {
			out.List = cur.Access
			out.Always = cur.AccessAlways()
			if cur.Access != nil && cur.Access.Mode != "" {
				out.Mode = cur.Access.Mode
			}
		}
		out.DNS, _ = access.ReadReport(dnsRelayAccessReportPath)
		out.DHCP, _ = access.ReadReport(dhcpRelayAccessReportPath)
		writeJSON(w, http.StatusOK, out)
	}
}
