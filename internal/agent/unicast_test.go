// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"bytes"
	"strings"
	"testing"

	"dnshived/internal/config"
)

func unicastScope() config.ScopeConfig {
	return config.ScopeConfig{
		VIP:    "192.168.100.1/24",
		NodeIP: "192.168.100.21/24",
		NodeIPOverrides: map[string]string{
			config.RoleCore1: "192.168.100.21/24",
			config.RoleCore2: "192.168.100.22/24",
			config.RoleCore3: "192.168.100.23/24",
		},
	}
}

func unicastAgent(on *bool) *Agent {
	a := New(config.RoleCore1, "core-1", 1, "psk", "", nil, nil)
	a.SetVRRPUnicast(on)
	return a
}

func boolPtr(v bool) *bool { return &v }

func TestUnicastPeers_DefaultIsMulticast(t *testing.T) {
	if _, _, ok := unicastAgent(nil).unicastPeers(unicastScope()); ok {
		t.Fatal("no cluster or scope setting: unicast must stay off")
	}
}

func TestUnicastPeers_CompleteFromLiveOverrides(t *testing.T) {
	src, peers, ok := unicastAgent(boolPtr(true)).unicastPeers(unicastScope())
	if !ok {
		t.Fatal("complete overrides, unicast on: refused")
	}
	if src != "192.168.100.21" {
		t.Fatalf("src = %q, want 192.168.100.21", src)
	}
	if strings.Join(peers, ",") != "192.168.100.22,192.168.100.23" {
		t.Fatalf("peers = %v, want the other two cores", peers)
	}
}

func TestUnicastPeers_MissingPeerStaysMulticast(t *testing.T) {
	sc := unicastScope()
	delete(sc.NodeIPOverrides, config.RoleCore3)
	if _, _, ok := unicastAgent(boolPtr(true)).unicastPeers(sc); ok {
		t.Fatal("core-3 unresolved: unicast must stay off")
	}
}

func TestUnicastPeers_DuplicateStaysMulticast(t *testing.T) {
	sc := unicastScope()
	sc.NodeIPOverrides[config.RoleCore3] = "192.168.100.22/24"
	if _, _, ok := unicastAgent(boolPtr(true)).unicastPeers(sc); ok {
		t.Fatal("core-3 equals core-2: unicast must stay off")
	}
}

func TestUnicastPeers_SelfCollisionStaysMulticast(t *testing.T) {
	sc := unicastScope()
	sc.NodeIPOverrides[config.RoleCore2] = "192.168.100.21/24"
	if _, _, ok := unicastAgent(boolPtr(true)).unicastPeers(sc); ok {
		t.Fatal("core-2 equals this node: unicast must stay off")
	}
}

func TestUnicastPeers_NoVLANAddressStaysMulticast(t *testing.T) {
	sc := unicastScope()
	sc.NodeIP = ""
	sc.NodeIPOverrides[config.RoleCore1] = ""
	if _, _, ok := unicastAgent(boolPtr(true)).unicastPeers(sc); ok {
		t.Fatal("no VLAN address on this node: unicast must stay off")
	}
}

func TestUnicastPeers_NonAddressOverrideStaysMulticast(t *testing.T) {
	sc := unicastScope()
	sc.NodeIPOverrides[config.RoleCore2] = "192.168.100.82\n    state MASTER"
	if _, _, ok := unicastAgent(boolPtr(true)).unicastPeers(sc); ok {
		t.Fatal("override with a newline is not an address: unicast must stay off")
	}
}

func TestUnicastPeers_ScopeSettingWinsOverCluster(t *testing.T) {
	a := unicastAgent(boolPtr(true))
	sc := unicastScope()
	sc.VRRPUnicast = boolPtr(false)
	if _, _, ok := a.unicastPeers(sc); ok {
		t.Fatal("scope false overrides cluster true: unicast must be off")
	}
	if _, _, ok := a.unicastPeers(unicastScope()); !ok {
		t.Fatal("scope unset inherits cluster true: unicast must be on")
	}
}

func TestKeepalivedTemplate_UnicastBlock(t *testing.T) {
	var on, off bytes.Buffer
	if err := keepalivedAllTmpl.Execute(&on, []keepalivedInstanceData{{
		Scope: "office", Interface: "ens19.100", VRRPID: 2, Priority: 100, AdvertInt: "1", VIP: "192.168.100.1/24",
		UnicastSrc: "192.168.100.21", UnicastPeers: []string{"192.168.100.22", "192.168.100.23"},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := keepalivedAllTmpl.Execute(&off, []keepalivedInstanceData{{
		Scope: "office", Interface: "ens19.100", VRRPID: 2, Priority: 100, AdvertInt: "1", VIP: "192.168.100.1/24",
	}}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"unicast_src_ip 192.168.100.21", "unicast_peer {", "192.168.100.22", "192.168.100.23"} {
		if !strings.Contains(on.String(), want) {
			t.Fatalf("unicast config lacks %q:\n%s", want, on.String())
		}
	}
	if strings.Contains(off.String(), "unicast") {
		t.Fatalf("multicast config carries a unicast block:\n%s", off.String())
	}
}
