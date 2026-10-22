// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"encoding/json"
	"net"
	"path/filepath"
	"sync"
	"testing"

	"dnshived/internal/config"
	"dnshived/internal/helper"
)

type recordingHelper struct {
	mu       sync.Mutex
	commands []string
	fail     bool
}

func startRecordingHelper(t *testing.T) (*recordingHelper, string) {
	t.Helper()
	rh := &recordingHelper{}
	sock := filepath.Join(t.TempDir(), "helper.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req helper.Request
			if json.NewDecoder(conn).Decode(&req) == nil {
				rh.mu.Lock()
				rh.commands = append(rh.commands, req.Command)
				failed := rh.fail && req.Command == "reload-mgmt-keepalived"
				rh.mu.Unlock()
				if failed {
					json.NewEncoder(conn).Encode(helper.Response{OK: false, Error: "simulated failure"})
				} else {
					json.NewEncoder(conn).Encode(helper.Response{OK: true})
				}
			}
			conn.Close()
		}
	}()
	return rh, sock
}

func (rh *recordingHelper) take() []string {
	rh.mu.Lock()
	defer rh.mu.Unlock()
	out := rh.commands
	rh.commands = nil
	return out
}

func TestRenderMgmtVIPConfig_ReloadsOnlyWhenConfigChanges(t *testing.T) {
	rh, sock := startRecordingHelper(t)
	a := &Agent{dataDir: t.TempDir(), role: config.RoleCore1}
	a.SetHelper(helper.NewClient(sock))
	platform := &config.Platform{Mgmt: "eth0"}
	vip := &config.MgmtVIPConfig{VIP: "192.0.2.230/24", VRRPID: 60}

	steps := []struct {
		name string
		vip  *config.MgmtVIPConfig
		want string
	}{
		{"first render", vip, "reload-mgmt-keepalived"},
		{"unchanged save", vip, "ensure-mgmt-keepalived"},
		{"unchanged save again", vip, "ensure-mgmt-keepalived"},
		{"vip changed", &config.MgmtVIPConfig{VIP: "192.0.2.231/24", VRRPID: 60}, "reload-mgmt-keepalived"},
	}
	for _, s := range steps {
		if err := a.RenderMgmtVIPConfig(s.vip, platform); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		got := rh.take()
		if len(got) != 1 || got[0] != s.want {
			t.Errorf("%s: helper commands = %v, want [%s]", s.name, got, s.want)
		}
	}
}

func TestRenderMgmtVIPConfig_FailedReloadRetriedOnNextSave(t *testing.T) {
	rh, sock := startRecordingHelper(t)
	a := &Agent{dataDir: t.TempDir(), role: config.RoleCore1}
	a.SetHelper(helper.NewClient(sock))
	platform := &config.Platform{Mgmt: "eth0"}
	vip := &config.MgmtVIPConfig{VIP: "192.0.2.230/24", VRRPID: 60}

	rh.mu.Lock()
	rh.fail = true
	rh.mu.Unlock()
	if err := a.RenderMgmtVIPConfig(vip, platform); err != nil {
		t.Fatal(err)
	}
	rh.take()
	rh.mu.Lock()
	rh.fail = false
	rh.mu.Unlock()

	if err := a.RenderMgmtVIPConfig(vip, platform); err != nil {
		t.Fatal(err)
	}
	if got := rh.take(); len(got) != 1 || got[0] != "reload-mgmt-keepalived" {
		t.Errorf("after a failed reload, unchanged save sent %v, want a retried reload", got)
	}
	if err := a.RenderMgmtVIPConfig(vip, platform); err != nil {
		t.Fatal(err)
	}
	if got := rh.take(); len(got) != 1 || got[0] != "ensure-mgmt-keepalived" {
		t.Errorf("once the reload landed, unchanged save sent %v, want ensure", got)
	}
}
