// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"dnshived/internal/dhcpprobe"
	"dnshived/internal/eventlog"
)

func watchCfg() *ProbeConfig {
	return &ProbeConfig{TrunkParent: "ens19", TrunkParents: []string{"ens19", "ens20"}, MgmtInterface: "ens18"}
}

func TestValidateManualProbes(t *testing.T) {
	cfg := watchCfg()
	tests := []struct {
		name    string
		list    []ManualProbe
		wantErr string
	}{
		{"empty list clears", nil, ""},
		{"untagged on the management interface", []ManualProbe{{Name: "mgmt-net", Interface: "ens18"}}, ""},
		{"tagged on a worker with expected servers", []ManualProbe{{Name: "iot", Interface: "ens19", VLANID: 300, ExpectedServers: []string{"10.0.0.1"}}}, ""},
		{"tagged on the management interface", []ManualProbe{{Name: "bad", Interface: "ens18", VLANID: 300}}, "never tagged"},
		{"interface the host does not serve", []ManualProbe{{Name: "x", Interface: "eth9"}}, "not one this probe host serves"},
		{"vlan out of range", []ManualProbe{{Name: "x", Interface: "ens19", VLANID: 4095}}, "out of range"},
		{"vlan 1 is not usable", []ManualProbe{{Name: "x", Interface: "ens19", VLANID: 1}}, "out of range"},
		{"bad name", []ManualProbe{{Name: "Has Space", Interface: "ens19"}}, "manual probe name"},
		{"duplicate name", []ManualProbe{{Name: "a", Interface: "ens19"}, {Name: "a", Interface: "ens20"}}, "used twice"},
		{"same place twice", []ManualProbe{{Name: "a", Interface: "ens19"}, {Name: "b", Interface: "ens19"}}, "same interface and VLAN"},
		{"not an IPv4 address", []ManualProbe{{Name: "a", Interface: "ens19", ExpectedServers: []string{"fe80::1"}}}, "not an IPv4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateManualProbes(cfg, tt.list)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("err = %v, want none", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestRunWatchProbe_Verdicts(t *testing.T) {
	fakeIfaces(t)
	m := ManualProbe{Name: "seg", Interface: "ens19", ExpectedServers: []string{"10.0.0.1"}}
	tests := []struct {
		name    string
		offers  []string
		verdict string
		unexp   int
	}{
		{"nothing answers", nil, "clear", 0},
		{"only the expected server", []string{"10.0.0.1"}, "ok", 0},
		{"an unlisted server", []string{"10.0.0.99"}, "rogue", 1},
		{"expected and unlisted together", []string{"10.0.0.1", "10.0.0.99"}, "rogue", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubDHCP(t, func(iface string, wait time.Duration, o dhcpprobe.Options) (dhcpprobe.Result, error) {
				if len(o.MAC) != 6 || o.MAC[0]&0x02 == 0 || o.MAC[0]&0x01 != 0 {
					t.Errorf("MAC %v, want a locally administered unicast one for a watch", o.MAC)
				}
				if !bytes.Equal(o.MAC, stableMAC("manual|seg|ens19|0")) {
					t.Errorf("MAC %v is not the stable one for this probe", o.MAC)
				}
				var res dhcpprobe.Result
				for _, s := range tt.offers {
					res.Offers = append(res.Offers, offerAt(s, 30*time.Millisecond))
					res.Servers = append(res.Servers, s)
				}
				return res, nil
			})
			got := runWatchProbe(m)
			if got.Verdict != tt.verdict || len(got.Unexpected) != tt.unexp {
				t.Errorf("verdict=%s unexpected=%v, want %s with %d unexpected", got.Verdict, got.Unexpected, tt.verdict, tt.unexp)
			}
		})
	}
}

func TestRunWatchProbe_AnUnlistedServerIsProbedAgainOverTheWholeWindow(t *testing.T) {
	fakeIfaces(t)
	var full bool
	stubDHCP(t, func(iface string, wait time.Duration, o dhcpprobe.Options) (dhcpprobe.Result, error) {
		if o.StopOnFirstOffer {
			return dhcpprobe.Result{Servers: []string{"10.0.0.99"}, Offers: []dhcpprobe.Offer{offerAt("10.0.0.99", time.Millisecond)}}, nil
		}
		full = true
		return dhcpprobe.Result{Servers: []string{"10.0.0.1", "10.0.0.99"}, Offers: []dhcpprobe.Offer{offerAt("10.0.0.99", time.Millisecond), offerAt("10.0.0.1", 2*time.Second)}}, nil
	})
	got := runWatchProbe(ManualProbe{Name: "seg", Interface: "ens19", ExpectedServers: []string{"10.0.0.1"}})
	if !full || len(got.Servers) != 2 || got.Verdict != "rogue" {
		t.Fatalf("full=%v result=%+v, want both servers listed and a rogue verdict", full, got)
	}
}

func TestRunWatchProbe_MissingInterfaceIsAnErrorNotClear(t *testing.T) {
	got := runWatchProbe(ManualProbe{Name: "seg", Interface: "nonexistent-iface-for-test", VLANID: 300})
	if got.Verdict != "error" || !strings.Contains(got.Error, "does not exist") {
		t.Fatalf("result %+v, want an error: silence on a missing interface must never read as a clear segment", got)
	}
}

func TestWatchStore_ListKeepsConfiguredOrderAndFlagsPending(t *testing.T) {
	s := newWatchStore()
	s.set(WatchResult{Name: "b", Interface: "ens19", Verdict: "ok"})
	got := s.list([]ManualProbe{{Name: "a", Interface: "ens20"}, {Name: "b", Interface: "ens19"}})
	if len(got) != 2 || got[0].Name != "a" || !got[0].Pending || got[1].Pending || got[1].Verdict != "ok" {
		t.Fatalf("list = %+v, want a pending then b with its result", got)
	}
}

func TestDesiredWithWatch(t *testing.T) {
	cfg := watchCfg()
	cfg.ManualProbes = []ManualProbe{
		{Name: "untagged", Interface: "ens19"},
		{Name: "tagged", Interface: "ens19", VLANID: 300},
		{Name: "scoped", Interface: "ens20", VLANID: 100},
		{Name: "mgmt", Interface: "ens18"},
	}
	byNodeID := map[string]probeConfigResponse{"core-1": {Scopes: map[string]remoteScope{
		"office": {Parent: "ens20", VLANID: 100, VIP: "10.0.100.1/24"},
	}}}

	got := desiredWithWatch(cfg, byNodeID)

	if v, ok := got["ens19.300"]; !ok || !v.Watch {
		t.Errorf("ens19.300 = %+v ok=%v, want a watch VLAN", v, ok)
	}
	if v := got["ens20.100"]; v.Watch || v.VIP == "" {
		t.Errorf("ens20.100 = %+v, want the scope's own entry to win", v)
	}
	if len(got) != 2 {
		t.Errorf("desired = %v, want exactly the tagged watch and the scope VLAN", got)
	}
	if vlanAddr(knownVLAN{Parent: "ens19", VLANID: 300, Watch: true}, 54) != "" {
		t.Error("a watch VLAN must carry no address")
	}
}

func TestCheckWatch_LogsOnlyTransitionsAndSurvivesAPlanRefresh(t *testing.T) {
	events := eventlog.New(20, "probe")
	tr := newProbeLogTracker(nil)
	rogue := WatchResult{Name: "seg", Interface: "ens18", Verdict: "rogue", Unexpected: []string{"10.0.0.99"}}

	tr.checkWatch(events, rogue)
	tr.prune(map[string]bool{})
	tr.checkWatch(events, rogue)
	tr.checkWatch(events, WatchResult{Name: "seg", Interface: "ens18", Verdict: "clear"})

	got := events.Last(10)
	if len(got) != 2 || got[0].Prefix != "PROBE:WATCH_FAIL" || got[1].Prefix != "PROBE:WATCH_OK" {
		t.Fatalf("events = %+v, want one fail then one recovery", got)
	}
	if !strings.Contains(got[0].Message, "ROGUE DHCP on ens18 (untagged)") {
		t.Errorf("message %q does not name the interface", got[0].Message)
	}
}

func TestRunners_ManualProbeRunsInTheInterfacesDHCPRunner(t *testing.T) {
	fakeIfaces(t)
	watchResults.prune(map[string]bool{})
	stubDHCP(t, func(iface string, wait time.Duration, o dhcpprobe.Options) (dhcpprobe.Result, error) {
		return dhcpprobe.Result{Servers: []string{"10.0.0.99"}, Offers: []dhcpprobe.Offer{offerAt("10.0.0.99", time.Millisecond)}}, nil
	})
	srv := planServer(t, nil)
	cfg := &ProbeConfig{TrunkParent: "ens19", ClusterNodes: []ClusterNode{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	cfg.SetManualProbes([]ManualProbe{{Name: "seg", Interface: "ens19"}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rn := newProbeRunners(ctx, cfg, newResultStore(), newProbeLogTracker(nil), eventlog.New(50, "probe"), newOwnershipDebounce())
	t.Cleanup(rn.stop)

	refreshProbePlan(cfg, rn, newIncarnationTracker())

	waitFor(t, "the manual probe", func() bool { return !watchResults.list(cfg.manualProbeList())[0].Pending })
	got := watchResults.list(cfg.manualProbeList())[0]
	if got.Verdict != "rogue" || got.Unexpected[0] != "10.0.0.99" {
		t.Fatalf("result %+v, want a rogue finding", got)
	}
}
