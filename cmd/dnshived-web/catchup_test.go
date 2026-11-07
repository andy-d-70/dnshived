// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"dnshived/internal/config"
)

func rev(n int64) *int64 { return &n }

func catchUpFixture(t *testing.T, self string, st map[string]nodeStatus) (*catchUp, *[]string, *[]configPushPayload) {
	t.Helper()
	cfg := &WebConfig{Nodes: []NodeConfig{
		{Name: "core-1", Addr: "192.0.2.1:9443"},
		{Name: "core-2", Addr: "192.0.2.2:9443"},
		{Name: "core-3", Addr: "192.0.2.3:9443"},
	}}
	var pushedTo []string
	var payloads []configPushPayload
	c := newCatchUp(newConfigRef(cfg))
	c.self = func() string { return self }
	c.statuses = func(nodes []NodeConfig) map[string]nodeStatus {
		out := map[string]nodeStatus{}
		for _, n := range nodes {
			if s, ok := st[n.Name]; ok {
				out[n.Name] = s
			}
		}
		return out
	}
	c.fetchCfg = func(n NodeConfig) (config.Cluster, error) {
		switch n.Name {
		case "core-1":
			return config.Cluster{ConfigRevision: 5, ConfigRevisionAt: "2026-11-07T10:00:00Z", ConfigRevisionOrigin: "core-1", LogLevel: "debug",
				ScopeDefaults: &config.ScopeDefaults{NodeIPSuffixes: map[string]string{"core-1": "21", "core-3": "23"}},
				Scopes:        map[string]config.ScopeConfig{"office": {Parent: "eth1", VLANID: 10, VIP: "192.0.2.254/24", NodeIP: "192.0.2.21/24"}}}, nil
		default:
			return config.Cluster{ConfigRevision: 3, Scopes: map[string]config.ScopeConfig{"office": {NodeIP: "192.0.2.23/24"}}}, nil
		}
	}
	c.push = func(n NodeConfig, body []byte) (int, []byte, error) {
		var p configPushPayload
		if err := json.Unmarshal(body, &p); err != nil {
			t.Errorf("push body: %v", err)
		}
		pushedTo = append(pushedTo, n.Name)
		payloads = append(payloads, p)
		return http.StatusOK, []byte(`{"ok":true}`), nil
	}
	c.audit = func(NodeConfig, string, string, string) error { return nil }
	return c, &pushedTo, &payloads
}

func status(r *int64, hash string) nodeStatus { return nodeStatus{ConfigRevision: r, ConfigHash: hash} }

func TestPickLeader(t *testing.T) {
	tests := []struct {
		name     string
		st       map[string]nodeStatus
		wantName string
		wantRev  int64
	}{
		{"highest wins", map[string]nodeStatus{"core-1": status(rev(3), "a"), "core-2": status(rev(5), "b")}, "core-2", 5},
		{"tie goes to the lowest name", map[string]nodeStatus{"core-3": status(rev(5), "a"), "core-2": status(rev(5), "a")}, "core-2", 5},
		{"old daemons are ignored", map[string]nodeStatus{"core-1": status(nil, "a"), "core-2": status(rev(2), "a")}, "core-2", 2},
		{"nobody reports", map[string]nodeStatus{"core-1": status(nil, "a")}, "", 0},
		{"all zero", map[string]nodeStatus{"core-1": status(rev(0), "a")}, "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, r := pickLeader(tt.st)
			if n != tt.wantName || r != tt.wantRev {
				t.Errorf("got %q %d, want %q %d", n, r, tt.wantName, tt.wantRev)
			}
		})
	}
}

func TestCatchUp_NeedsTwoPassesThenPushesTheLeadersConfig(t *testing.T) {
	st := map[string]nodeStatus{"core-1": status(rev(5), "H5"), "core-2": status(rev(5), "H5"), "core-3": status(rev(3), "H3")}
	c, pushedTo, payloads := catchUpFixture(t, "core-1", st)
	c.pass()
	if len(*pushedTo) != 0 {
		t.Fatalf("pushed on the first sighting: %v", *pushedTo)
	}
	c.pass()
	if len(*pushedTo) != 1 || (*pushedTo)[0] != "core-3" {
		t.Fatalf("pushed to %v, want only core-3", *pushedTo)
	}
	p := (*payloads)[0]
	if !p.ConfigCatchUp {
		t.Error("a catch-up push must be marked so the daemon refuses it when it is not newer")
	}
	if p.ConfigRevision != 5 || p.ConfigRevisionOrigin != "core-1" || p.LogLevel != "debug" {
		t.Errorf("payload = rev %d origin %q log %q", p.ConfigRevision, p.ConfigRevisionOrigin, p.LogLevel)
	}
	if got := p.Scopes["office"].NodeIP; got != "192.0.2.23/24" {
		t.Errorf("core-3 got node_ip %q, want its own derived 192.0.2.23/24 and never the leader's .21", got)
	}
}

func TestCatchUp_KeepsTheLaggardsOwnNodeIPWhenNothingCanBeDerived(t *testing.T) {
	leader := config.Cluster{ConfigRevision: 5, Scopes: map[string]config.ScopeConfig{"office": {Parent: "eth1", VLANID: 10, NodeIP: "192.0.2.21/24"}}}
	lag := config.Cluster{Scopes: map[string]config.ScopeConfig{"office": {NodeIP: "192.0.2.99/24"}}}
	p := catchUpPayload(leader, lag, NodeConfig{Name: "core-3", Addr: "not-an-address"})
	if got := p.Scopes["office"].NodeIP; got != "192.0.2.99/24" {
		t.Errorf("node_ip = %q: the leader's address must never reach another node", got)
	}
	empty := catchUpPayload(leader, config.Cluster{}, NodeConfig{Name: "core-3", Addr: "not-an-address"})
	if got := empty.Scopes["office"].NodeIP; got != "" {
		t.Errorf("node_ip = %q, want empty when nothing is known", got)
	}
}

func TestCatchUp_DoesNothingWhen(t *testing.T) {
	tests := []struct {
		name string
		self string
		st   map[string]nodeStatus
	}{
		{"this instance is not the leader", "core-2", map[string]nodeStatus{"core-1": status(rev(5), "H5"), "core-2": status(rev(5), "H5"), "core-3": status(rev(3), "H3")}},
		{"the laggard has the same content", "core-1", map[string]nodeStatus{"core-1": status(rev(5), "H5"), "core-2": status(rev(5), "H5"), "core-3": status(rev(3), "H5")}},
		{"the laggard reports no revision (old daemon)", "core-1", map[string]nodeStatus{"core-1": status(rev(5), "H5"), "core-2": status(rev(5), "H5"), "core-3": status(nil, "H3")}},
		{"same revision, different content (hand edit)", "core-1", map[string]nodeStatus{"core-1": status(rev(5), "H5"), "core-2": status(rev(5), "H5"), "core-3": status(rev(5), "Hx")}},
		{"only a minority answers", "core-1", map[string]nodeStatus{"core-1": status(rev(5), "H5")}},
		{"nothing was ever committed", "core-1", map[string]nodeStatus{"core-1": status(rev(0), "H"), "core-2": status(rev(0), "H"), "core-3": status(rev(0), "Hx")}},
		{"the laggard is unreachable", "core-1", map[string]nodeStatus{"core-1": status(rev(5), "H5"), "core-2": status(rev(5), "H5")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, pushedTo, _ := catchUpFixture(t, tt.self, tt.st)
			c.pass()
			c.pass()
			c.pass()
			if len(*pushedTo) != 0 {
				t.Errorf("pushed to %v", *pushedTo)
			}
		})
	}
}

func TestCatchUp_ALagThatChangesBetweenPassesStartsOver(t *testing.T) {
	st := map[string]nodeStatus{"core-1": status(rev(5), "H5"), "core-2": status(rev(5), "H5"), "core-3": status(rev(3), "H3")}
	c, pushedTo, _ := catchUpFixture(t, "core-1", st)
	c.pass()
	st["core-3"] = status(rev(4), "H4")
	c.pass()
	if len(*pushedTo) != 0 {
		t.Fatalf("pushed although the laggard moved: %v", *pushedTo)
	}
	c.pass()
	if len(*pushedTo) != 1 {
		t.Errorf("pushes = %v, want one after two identical sightings", *pushedTo)
	}
}

func TestCatchUp_ARefusedPushIsRetriedNotForgotten(t *testing.T) {
	st := map[string]nodeStatus{"core-1": status(rev(5), "H5"), "core-2": status(rev(5), "H5"), "core-3": status(rev(3), "H3")}
	c, _, _ := catchUpFixture(t, "core-1", st)
	calls := 0
	c.push = func(NodeConfig, []byte) (int, []byte, error) {
		calls++
		if calls == 1 {
			return http.StatusBadRequest, []byte(`{"ok":false,"errors":["nope"]}`), nil
		}
		return http.StatusOK, []byte(`{"ok":true}`), nil
	}
	c.pass()
	c.pass()
	c.pass()
	if calls != 2 {
		t.Errorf("pushes = %d, want a retry on the next pass after a refusal", calls)
	}
}

func TestCatchUp_StopsWhenTheLeaderMovedOnMeanwhile(t *testing.T) {
	st := map[string]nodeStatus{"core-1": status(rev(5), "H5"), "core-2": status(rev(5), "H5"), "core-3": status(rev(3), "H3")}
	c, pushedTo, _ := catchUpFixture(t, "core-1", st)
	c.fetchCfg = func(NodeConfig) (config.Cluster, error) { return config.Cluster{ConfigRevision: 2}, nil }
	c.pass()
	c.pass()
	if len(*pushedTo) != 0 {
		t.Errorf("pushed a configuration that is not newer than the laggard's: %v", *pushedTo)
	}
}

func TestCatchUp_FetchFailureIsReportedNotFatal(t *testing.T) {
	st := map[string]nodeStatus{"core-1": status(rev(5), "H5"), "core-2": status(rev(5), "H5"), "core-3": status(rev(3), "H3")}
	c, pushedTo, _ := catchUpFixture(t, "core-1", st)
	c.fetchCfg = func(NodeConfig) (config.Cluster, error) { return config.Cluster{}, errors.New("down") }
	c.pass()
	c.pass()
	if len(*pushedTo) != 0 {
		t.Error("pushed without a configuration")
	}
}

func TestWithNextRevision(t *testing.T) {
	nodes := []NodeConfig{{Name: "core-1"}, {Name: "core-2"}, {Name: "core-3"}}
	old := statusFetcher
	defer func() { statusFetcher = old }()
	tests := []struct {
		name string
		st   map[string]nodeStatus
		want int64
	}{
		{"highest plus one", map[string]nodeStatus{"core-1": status(rev(4), ""), "core-2": status(rev(6), ""), "core-3": status(rev(5), "")}, 7},
		{"a down node does not matter", map[string]nodeStatus{"core-1": status(rev(2), "")}, 3},
		{"first commit after the upgrade", map[string]nodeStatus{"core-1": status(rev(0), ""), "core-2": status(rev(0), "")}, 1},
		{"nobody reports: leave it to the daemons", map[string]nodeStatus{"core-1": status(nil, "")}, 0},
		{"nobody answers", map[string]nodeStatus{}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statusFetcher = func(n NodeConfig) (nodeStatus, error) {
				if s, ok := tt.st[n.Name]; ok {
					return s, nil
				}
				return nodeStatus{}, errors.New("down")
			}
			p := withNextRevision(nodes, configPushPayload{PSK: "x"})
			if p.ConfigRevision != tt.want {
				t.Errorf("revision = %d, want %d", p.ConfigRevision, tt.want)
			}
			if tt.want > 0 && (p.ConfigRevisionAt == "" || p.PSK != "x") {
				t.Errorf("stamp or payload damaged: %+v", p)
			}
			if tt.want == 0 && (p.ConfigRevisionAt != "" || strings.Contains(p.ConfigRevisionOrigin, "x")) {
				t.Errorf("a stamp was set without a revision: %+v", p)
			}
		})
	}
}
