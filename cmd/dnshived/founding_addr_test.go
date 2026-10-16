// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"dnshived/internal/config"
)

func TestNormalizeNodeAddr(t *testing.T) {
	cases := []struct{ addr, role, want string }{
		{"192.168.0.52", config.RoleCore2, "192.168.0.52:9443"},
		{" 192.168.0.52 ", config.RoleCore2, "192.168.0.52:9443"},
		{"192.168.0.52:9443", config.RoleCore2, "192.168.0.52:9443"},
		{"192.168.0.52:8000", config.RoleCore2, "192.168.0.52:8000"},
		{"192.168.0.54", "probe", "192.168.0.54:9444"},
		{"192.168.0.54:9444", "probe", "192.168.0.54:9444"},
		{"fd00::52", config.RoleCore2, "[fd00::52]:9443"},
		{"[fd00::52]:9443", config.RoleCore2, "[fd00::52]:9443"},
		{"", config.RoleCore2, ""},
	}
	for _, c := range cases {
		if got := normalizeNodeAddr(c.addr, c.role, "9443"); got != c.want {
			t.Errorf("normalizeNodeAddr(%q, %s) = %q, want %q", c.addr, c.role, got, c.want)
		}
	}
}

func TestBootstrapAddNodeHandler_StoresAddressWithPort(t *testing.T) {
	state := &builderState{}
	state.setSelfAddr("192.168.0.51:9443")
	state.setRole(config.RoleCore1)
	handler := bootstrapAddNodeHandler("host", "9443", state)
	for _, f := range []url.Values{
		{"addr": {"192.168.0.52"}, "role": {config.RoleCore2}, "otp": {"CODE"}},
		{"addr": {"192.168.0.54"}, "role": {"probe"}, "otp": {"CODE"}, "trunk_parent": {"ens19"}},
	} {
		req := httptest.NewRequest(http.MethodPost, "/setup/nodes", strings.NewReader(f.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("add %v: status %d: %s", f, rec.Code, rec.Body.String())
		}
	}
	got := map[string]string{}
	for _, n := range state.getNodes() {
		got[n.Role] = n.Addr
	}
	if got[config.RoleCore2] != "192.168.0.52:9443" || got["probe"] != "192.168.0.54:9444" {
		t.Errorf("stored addresses %v, want core-2 with :9443 and probe with :9444", got)
	}
}

func TestBootstrapSetupTmpl_ShowsDetectedInterfaces(t *testing.T) {
	state := &builderState{}
	state.setRole(config.RoleCore1)
	state.setSelfAddr("192.168.0.51:9443")
	state.setPlatform("ens18", []string{"ens19", "ens20"})
	if err := state.addNodeDetected("192.168.0.26:9443", config.RoleCore3, "CODE", "", map[string]string{"ens19": "eth1"},
		[]trunkDetection{{Canonical: "ens19", Local: "eth1"}, {Canonical: "ens20"}}, "eth0"); err != nil {
		t.Fatal(err)
	}
	for _, step := range []string{"5", "6"} {
		rec := httptest.NewRecorder()
		bootstrapSetupHandler("host", "9443", state)(rec, httptest.NewRequest(http.MethodGet, "/?step="+step, nil))
		body := rec.Body.String()
		if !strings.Contains(body, "ens19 → eth1") || !strings.Contains(body, "NOT DETECTED") || !strings.Contains(body, "mgmt: eth0") {
			t.Errorf("step %s does not show the detected interfaces:\n%s", step, body)
		}
	}
}
