// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcprelay

import (
	"testing"
	"time"

	"dnshived/internal/access"
)

func accessTestRelay(t *testing.T, list *access.Config) (*Relay, *clientInterface) {
	t.Helper()
	cfg := Config{
		ServerAddr: "127.0.0.1:67",
		ClientInterfaces: []ClientInterfaceConfig{
			{Name: "lan0", GIAddr: "10.1.0.22", Scope: "a", Network: "10.1.0.0/24"},
			{Name: "pub0", GIAddr: "203.0.113.22", Scope: "b", Network: "203.0.113.0/24"},
		},
		Access:       list,
		AccessAlways: []string{"203.0.113.22"},
	}
	r, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r, r.clientIfaces[1]
}

func discoverFrom(mac [6]byte) []byte {
	p := make([]byte, 300)
	copy(p[bootpCHAddrOffset:], mac[:])
	return p
}

func TestAccessAllows(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	known := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	stranger := [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}

	t.Run("no list serves everyone", func(t *testing.T) {
		r, pub := accessTestRelay(t, nil)
		if !r.accessAllows(pub, discoverFrom(stranger), now) {
			t.Fatal("without a list every request must pass")
		}
		if r.AccessEnforcing() {
			t.Fatal("no list must not enforce")
		}
	})
	t.Run("enforce drops a network the list does not allow", func(t *testing.T) {
		r, pub := accessTestRelay(t, &access.Config{Mode: access.ModeEnforce})
		if r.accessAllows(pub, discoverFrom(stranger), now) {
			t.Fatal("a public network that is not listed must be dropped")
		}
		if r.metrics.accessDropped.Load() != 1 {
			t.Errorf("accessDropped = %d, want 1", r.metrics.accessDropped.Load())
		}
		if rep := r.AccessReporter().Snapshot(true, now); len(rep.Items) != 1 || rep.Items[0].Svc != "dhcp" || rep.Items[0].Src != "203.0.113.0" {
			t.Errorf("report = %+v, want the network 203.0.113.0 for dhcp", rep.Items)
		}
		lan := r.clientIfaces[0]
		if !r.accessAllows(lan, discoverFrom(stranger), now) {
			t.Error("a private network is allowed by default")
		}
	})
	t.Run("a listed network is served", func(t *testing.T) {
		r, pub := accessTestRelay(t, &access.Config{Mode: access.ModeEnforce, Entries: []access.Entry{{Net: "203.0.113.0/24"}}})
		if !r.accessAllows(pub, discoverFrom(stranger), now) {
			t.Fatal("a listed network must be served")
		}
	})
	t.Run("deny DHCP for a network that is allowed for DNS", func(t *testing.T) {
		r, pub := accessTestRelay(t, &access.Config{Mode: access.ModeEnforce, Entries: []access.Entry{{Net: "203.0.113.0/24", DHCP: access.Deny}}})
		if r.accessAllows(pub, discoverFrom(stranger), now) {
			t.Fatal("DHCP denied for the network must drop the request")
		}
	})
	t.Run("a whitelisted MAC is served from a dropped network", func(t *testing.T) {
		r, pub := accessTestRelay(t, &access.Config{Mode: access.ModeEnforce, Hosts: []access.Host{{MAC: "00:11:22:33:44:55", DHCP: true}}})
		if !r.accessAllows(pub, discoverFrom(known), now) {
			t.Fatal("a whitelisted MAC must be served")
		}
		if r.accessAllows(pub, discoverFrom(stranger), now) {
			t.Fatal("another MAC on the same network must still be dropped")
		}
	})
	t.Run("report mode counts and lets the request through", func(t *testing.T) {
		r, pub := accessTestRelay(t, &access.Config{Mode: access.ModeReport})
		if !r.accessAllows(pub, discoverFrom(stranger), now) {
			t.Fatal("report mode must not drop")
		}
		if r.metrics.accessWouldDrop.Load() != 1 || r.metrics.accessDropped.Load() != 0 {
			t.Errorf("counters would=%d dropped=%d", r.metrics.accessWouldDrop.Load(), r.metrics.accessDropped.Load())
		}
		if rep := r.AccessReporter().Snapshot(false, now); len(rep.Items) != 1 {
			t.Errorf("report mode must still list the network: %+v", rep.Items)
		}
	})
	t.Run("an interface without a network is not judged", func(t *testing.T) {
		cfg := Config{ServerAddr: "127.0.0.1:67", ClientInterfaces: []ClientInterfaceConfig{{Name: "old0", GIAddr: "203.0.113.22", Scope: "x"}}, Access: &access.Config{Mode: access.ModeEnforce}}
		r, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if !r.accessAllows(r.clientIfaces[0], discoverFrom(stranger), now) {
			t.Fatal("a config from an older renderer has no network; that interface must keep working")
		}
	})
	t.Run("a blocked MAC is dropped in report mode, on an allowed network", func(t *testing.T) {
		r, _ := accessTestRelay(t, &access.Config{Mode: access.ModeReport, Blocked: []access.Block{{MAC: "de:ad:be:ef:00:01", DHCP: true}}})
		lan := r.clientIfaces[0]
		if r.accessAllows(lan, discoverFrom(stranger), now) {
			t.Fatal("a blocked MAC must be dropped")
		}
		if !r.accessAllows(lan, discoverFrom(known), now) {
			t.Fatal("another client on the same network must pass")
		}
		if r.metrics.accessDropped.Load() != 1 {
			t.Errorf("accessDropped = %d, want 1", r.metrics.accessDropped.Load())
		}
	})
	t.Run("a whitelisted MAC that is also blocked stays blocked", func(t *testing.T) {
		r, pub := accessTestRelay(t, &access.Config{Mode: access.ModeEnforce, Hosts: []access.Host{{MAC: "de:ad:be:ef:00:01", DHCP: true}}, Blocked: []access.Block{{MAC: "de:ad:be:ef:00:01", DHCP: true}}})
		if r.accessAllows(pub, discoverFrom(stranger), now) {
			t.Fatal("the block beats the whitelist")
		}
	})
	t.Run("reconfigure swaps the list", func(t *testing.T) {
		r, pub := accessTestRelay(t, &access.Config{Mode: access.ModeReport})
		r.applyAccess(Config{ClientInterfaces: []ClientInterfaceConfig{{Name: "pub0", Network: "203.0.113.0/24"}}, Access: &access.Config{Mode: access.ModeEnforce}})
		if r.accessAllows(pub, discoverFrom(stranger), now) {
			t.Fatal("the new list enforces")
		}
		r.applyAccess(Config{})
		if !r.accessAllows(pub, discoverFrom(stranger), now) {
			t.Fatal("removing the list serves everyone again")
		}
	})
}

func TestConfigValidate_Access(t *testing.T) {
	base := Config{ServerAddr: "127.0.0.1:67", ClientInterfaces: []ClientInterfaceConfig{{Name: "a", GIAddr: "10.0.0.1", Scope: "s"}}}
	bad := base
	bad.Access = &access.Config{Mode: "loud"}
	if err := bad.Validate(); err == nil {
		t.Error("an invalid access list must be refused")
	}
	bad = base
	bad.AccessAlways = []string{"nope"}
	if err := bad.Validate(); err == nil {
		t.Error("an invalid always address must be refused")
	}
	bad = base
	bad.ClientInterfaces = []ClientInterfaceConfig{{Name: "a", GIAddr: "10.0.0.1", Scope: "s", Network: "10.0.0.1"}}
	if err := bad.Validate(); err == nil {
		t.Error("a network that is not CIDR must be refused")
	}
	if err := base.Validate(); err != nil {
		t.Errorf("a config without the new fields must stay valid: %v", err)
	}
}
