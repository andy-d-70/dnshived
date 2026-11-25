// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsverify

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"testing"
	"time"

	"dnshived/internal/config"
	"dnshived/internal/dnsanswer"
	"dnshived/internal/dnsdata"
	"dnshived/internal/dnsstore"
	"dnshived/internal/dnsstore/vfs/faultfs"
)

func newStore(t testing.TB) *dnsstore.Store {
	t.Helper()
	keys := dnsstore.StaticKeys{Cur: 1, Epochs: map[uint32][]byte{1: []byte("0123456789abcdef0123456789abcdef")}}
	s, err := dnsstore.Open("/s", dnsstore.Options{FS: faultfs.New(1), Keys: keys, Create: true, SnapshotBytes: 1 << 40})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func commit(t testing.TB, s *dnsstore.Store, ops ...dnsstore.Op) {
	t.Helper()
	for len(ops) > 0 {
		n := min(len(ops), 100000)
		if _, err := s.Commit(dnsstore.Batch{Origin: 5, Ops: ops[:n]}); err != nil {
			t.Fatal(err)
		}
		ops = ops[n:]
	}
}

func fixture() *config.Cluster {
	recs := []config.LocalDomainHost{
		{Host: "nas", Type: "A", Value: "10.1.0.5"},
		{Host: "nas", Type: "AAAA", Value: "fd00:1::5"},
		{Host: "cam", Type: "A", Value: "10.1.0.6", TTL: 120},
		{Host: "www", Type: "CNAME", Value: "nas.home.lan"},
		{Host: "_sip._udp", Type: "SRV", Target: "nas.home.lan", Port: 5060, Priority: 1, Weight: 2},
		{Host: "@", Type: "TXT", Value: "v=spf1 -all"},
		{Host: "never", Type: "A", Value: "10.1.0.9"},
	}
	return &config.Cluster{
		ConfigRevision: 42,
		Scopes: map[string]config.ScopeConfig{
			"office": {
				DNSRecords:   []config.DNSRecord{{Name: "printer-web.office.lan", Type: "A", Value: "10.2.0.10", TTL: 600}},
				Reservations: []config.Reservation{{IP: "10.2.0.20", Hostname: "scanner", Names: []string{"scan2.office.lan"}}},
			},
			"av": {DNSRecords: []config.DNSRecord{{Name: "mixer.av.lan", Type: "A", Value: "10.3.0.4"}}},
		},
		GlobalDNSRecords: []config.DNSRecord{{Name: "ntp.home.lan", Type: "A", Value: "10.1.0.1"}},
		LocalDomains: []config.LocalDomain{
			{Name: "home.lan", TTL: 300, Records: recs},
			{Name: "lab.lan", ForkedFrom: "home.lan", Records: recs},
			{Name: "office.lan"},
			{Name: "av.lan"},
		},
	}
}

func leases() []dnsdata.LeaseName {
	return []dnsdata.LeaseName{
		{Name: "phone.home.lan", IP: netip.MustParseAddr("10.1.0.50"), MAC: "02:00:00:00:00:01", LeasedAt: 1},
		{Name: "nas.home.lan", IP: netip.MustParseAddr("10.1.0.51"), MAC: "02:00:00:00:00:02", LeasedAt: 2},
	}
}

type rig struct {
	t     testing.TB
	store *dnsstore.Store
	cfg   *config.Cluster
	in    Input
}

// newRig puts what the configuration implies into a fresh store, reports every core in step and publishes the
// verified table, so every available check starts green.
func newRig(t testing.TB, c *config.Cluster) *rig {
	t.Helper()
	r := &rig{t: t, store: newStore(t), cfg: c}
	ops, _ := dnsdata.MigrateOps(c)
	commit(t, r.store, ops...)
	r.in = inputFor(c, r.store.View())
	r.in.Leases = leases()
	r.publish()
	r.coresInStep("core-1", "core-2", "core-3")
	return r
}

func inputFor(c *config.Cluster, v *dnsstore.View) Input {
	in := Input{Config: c, View: v, NegTTL: 60, Now: time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)}
	zones := map[string]bool{}
	var domains []string
	for _, d := range c.LocalDomains {
		if n, err := dnsanswer.CanonicalName(d.Name); err == nil {
			in.Zones = append(in.Zones, dnsanswer.Zone{Name: n})
			zones[n] = true
			domains = append(domains, n)
		}
	}
	reserved := map[string]string{}
	for scope, sc := range c.Scopes {
		for _, rs := range sc.Reservations {
			for _, n := range rs.DNSNames() {
				if n, err := dnsanswer.CanonicalName(n); err == nil {
					reserved[n] = scope
					if !strings.Contains(n, ".") {
						for _, d := range domains {
							reserved[n+"."+d] = scope
						}
					}
				}
			}
		}
	}
	in.Gate = dnsdata.GateContext{Zones: zones, Reserved: reserved}
	return in
}

func (r *rig) refresh() {
	r.in.View = r.store.View()
	r.in.Config = r.cfg
}

func (r *rig) publish() {
	r.t.Helper()
	r.refresh()
	r.in.Published = nil
	_, _, digest := checkAnswersAndPublished(r.in)
	var d [32]byte
	if n, err := hex.Decode(d[:], []byte(digest)); err != nil || n != 32 {
		r.t.Fatalf("no table digest: %q %v", digest, err)
	}
	r.in.Published = &d
}

func (r *rig) coresInStep(names ...string) {
	v := r.store.View()
	r.in.Cores = nil
	for _, n := range names {
		r.in.Cores = append(r.in.Cores, Core{Name: n, Commit: v.Rev(), Manifest: v.Manifest()})
	}
}

func (r *rig) run() Result {
	r.t.Helper()
	r.refresh()
	return Run(r.in)
}

func check(t testing.TB, res Result, name string) Check {
	t.Helper()
	for _, c := range res.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no check %q in %+v", name, res.Checks)
	return Check{}
}

var builtChecks = []string{CheckRows, CheckAnswers, CheckGate, CheckReplication, CheckPublished}

func expectState(t *testing.T, res Result, red ...string) {
	t.Helper()
	isRed := map[string]bool{}
	for _, n := range red {
		isRed[n] = true
	}
	for _, n := range builtChecks {
		c := check(t, res, n)
		if c.OK == isRed[n] {
			t.Errorf("check %s: ok %v, want %v (reason %q, examples %q)", n, c.OK, !isRed[n], c.Reason, c.Examples)
		}
		if !c.OK && c.Reason == "" {
			t.Errorf("check %s is red without a reason", n)
		}
	}
}

func TestRun_StoreEqualToTheConfigurationPassesEveryBuiltCheck(t *testing.T) {
	r := newRig(t, fixture())
	res := r.run()
	expectState(t, res)
	if res.ConfigRevision != 42 || res.StoreRevision != r.store.View().Rev() || res.At != "2026-11-25T12:00:00Z" || res.TableDigest == "" {
		t.Fatalf("result header: %+v", res)
	}
	a := check(t, res, CheckAnswers)
	if a.Counts["reservation names"] != 2 || a.Counts["lease names"] != 1 || a.Counts["records the configuration means"] == 0 {
		t.Fatalf("answer counts: %v", a.Counts)
	}
	if info := check(t, res, CheckGate).Info; len(info) != 1 || !strings.Contains(info[0], "home.lan") {
		t.Fatalf("the domain whose default TTL no longer applies is listed: %q", info)
	}
}

func TestRun_ChecksOfLaterPhasesStayRedSoTheResultIsNotGreen(t *testing.T) {
	res := newRig(t, fixture()).run()
	if res.Green {
		t.Fatal("the result cannot be green while checks of later phases are missing")
	}
	for _, n := range []string{CheckLive, CheckForwarder, CheckQueryLog} {
		if c := check(t, res, n); c.OK || c.Available || !strings.HasPrefix(c.Reason, "not available yet") {
			t.Errorf("%s: %+v", n, c)
		}
	}
}

func TestRun_EachDifferenceTurnsTheRightCheckRed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(r *rig)
		red    []string
		want   string
	}{
		{"a row is missing from the store", func(r *rig) {
			ops, _ := dnsdata.MigrateOps(r.cfg)
			commit(r.t, r.store, dnsstore.Op{Kind: dnsstore.OpDel, Type: ops[0].Type, ID: ops[0].ID})
			r.publish()
			r.coresInStep("core-1")
		}, []string{CheckRows, CheckAnswers}, "missing from the store"},
		{"the store holds a row the configuration does not have", func(r *rig) {
			extra := dnsdata.Record{Owner: "ghost.home.lan", Type: dnsanswer.TypeTXT, Value: "x"}
			commit(r.t, r.store, dnsstore.Op{Kind: dnsstore.OpPut, Type: dnsdata.TypeRecord, ID: dnsstore.ID{1}, Body: extra.Encode()})
			r.publish()
			r.coresInStep("core-1")
		}, []string{CheckRows, CheckAnswers}, "extra in the store"},
		{"a row has another TTL", func(r *rig) {
			ops, _ := dnsdata.MigrateOps(r.cfg)
			for _, op := range ops {
				if op.Type != dnsdata.TypeHost {
					continue
				}
				h, _ := dnsdata.DecodeHost(op.Body)
				h.TTL = 7
				commit(r.t, r.store, dnsstore.Op{Kind: dnsstore.OpPut, Type: op.Type, ID: op.ID, Body: h.Encode()})
				break
			}
			r.publish()
			r.coresInStep("core-1")
		}, []string{CheckRows, CheckAnswers}, "different:"},
		{"the configuration changed after the sync", func(r *rig) {
			c := fixture()
			c.GlobalDNSRecords = append(c.GlobalDNSRecords, config.DNSRecord{Name: "new.home.lan", Type: "A", Value: "10.1.0.77"})
			r.cfg = c
		}, []string{CheckRows, CheckAnswers}, "new.home.lan"},
		{"a core is behind", func(r *rig) {
			r.in.Cores[1].Commit--
		}, []string{CheckReplication}, "core-2: at revision"},
		{"a core holds other data", func(r *rig) {
			r.in.Cores[2].Manifest[0] ^= 1
		}, []string{CheckReplication}, "core-3: different data"},
		{"a core does not answer", func(r *rig) {
			r.in.Cores[0].Err = "connection refused"
		}, []string{CheckReplication}, "core-1: no answer"},
		{"no core reported", func(r *rig) {
			r.in.Cores = nil
		}, []string{CheckReplication}, ""},
		{"the published table is another one", func(r *rig) {
			r.in.Published[0] ^= 1
		}, []string{CheckPublished}, ""},
		{"nothing is published", func(r *rig) {
			r.in.Published = nil
		}, []string{CheckPublished}, ""},
		{"the default TTL changed but the table was not rebuilt", func(r *rig) {
			commit(r.t, r.store, dnsdata.DefaultTTLOp(900))
			r.coresInStep("core-1")
		}, []string{CheckPublished}, ""},
		{"the default TTL changed and the table was rebuilt", func(r *rig) {
			commit(r.t, r.store, dnsdata.DefaultTTLOp(900))
			r.publish()
			r.coresInStep("core-1")
		}, nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig(t, fixture())
			tt.mutate(r)
			res := r.run()
			expectState(t, res, tt.red...)
			if tt.want != "" {
				var all []string
				for _, c := range res.Checks {
					all = append(all, c.Examples...)
				}
				if !strings.Contains(strings.Join(all, "\n"), tt.want) {
					t.Errorf("no example mentions %q: %q", tt.want, all)
				}
			}
		})
	}
}

func TestRun_ConfigurationTheGateRefusesBlocksTheCutover(t *testing.T) {
	tests := []struct {
		name string
		add  config.DNSRecord
		want string
	}{
		{"a CNAME next to other data", config.DNSRecord{Name: "nas.home.lan", Type: "CNAME", Value: "www.home.lan"}, "CNAME"},
		{"an address record named like a reservation", config.DNSRecord{Name: "scan2.office.lan", Type: "A", Value: "10.2.0.99"}, "reservation"},
		{"a record the store cannot hold", config.DNSRecord{Name: "odd.home.lan", Type: "HINFO", Value: "x"}, "cannot be stored"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := fixture()
			c.GlobalDNSRecords = append(c.GlobalDNSRecords, tt.add)
			r := newRig(t, c)
			g := check(t, r.run(), CheckGate)
			if g.OK || g.Counts["refused"] == 0 || !strings.Contains(strings.Join(g.Examples, "\n"), tt.want) {
				t.Fatalf("gate: %+v", g)
			}
		})
	}
}

func TestRun_LegacyRawRecordsFromTheConfigurationPassTheGate(t *testing.T) {
	c := fixture()
	c.GlobalDNSRecords = append(c.GlobalDNSRecords, config.DNSRecord{Name: "raw.home.lan", Type: "RAW", RRType: 99, RRDataHex: "0161"})
	if g := check(t, newRig(t, c).run(), CheckGate); !g.OK {
		t.Fatalf("gate: %+v", g)
	}
}

func TestLeaseCheck_ReportsALeaseNameTheTableDoesNotAnswer(t *testing.T) {
	ls := leases()
	got := []dnsanswer.RR{{Owner: "phone.home.lan", Type: dnsanswer.TypeA, TTL: 0, RData: netip.MustParseAddr("10.1.0.99").AsSlice()}}
	var ex examples
	checked, lost := leaseCheck(leaseSet(ls), map[string]bool{"nas.home.lan": true}, got, 0, &ex)
	if checked != 1 || lost != 1 || len(ex.all) != 1 || !strings.Contains(ex.all[0], "phone.home.lan") {
		t.Fatalf("checked %d lost %d: %q", checked, lost, ex.all)
	}
	got[0].RData = netip.MustParseAddr("10.1.0.50").AsSlice()
	got[0].TTL = 5
	if _, lost := leaseCheck(leaseSet(ls), map[string]bool{"nas.home.lan": true}, got, 0, &ex); lost != 1 {
		t.Fatal("a lease name with the wrong TTL counts as not answered")
	}
}

func TestRun_IsDeterministic(t *testing.T) {
	c := fixture()
	c.GlobalDNSRecords = append(c.GlobalDNSRecords,
		config.DNSRecord{Name: "nas.home.lan", Type: "CNAME", Value: "www.home.lan"},
		config.DNSRecord{Name: "odd.home.lan", Type: "HINFO", Value: "x"})
	r := newRig(t, c)
	r.in.Cores[0].Err = "down"
	first, _ := json.Marshal(r.run())
	for range 5 {
		if again, _ := json.Marshal(r.run()); string(again) != string(first) {
			t.Fatalf("two runs differ:\n%s\n%s", first, again)
		}
	}
}

func TestRun_ExamplesAreBounded(t *testing.T) {
	c := fixture()
	for i := range 50 {
		c.GlobalDNSRecords = append(c.GlobalDNSRecords, config.DNSRecord{Name: fmt.Sprintf("n%d.home.lan", i), Type: "A", Value: fmt.Sprintf("10.9.0.%d", i)})
	}
	r := newRig(t, fixture())
	r.cfg = c
	r.in.MaxExamples = 5
	rows := check(t, r.run(), CheckRows)
	if rows.Counts["missing"] != 100 || len(rows.Examples) != 5 {
		t.Fatalf("missing %d, examples %d", rows.Counts["missing"], len(rows.Examples))
	}
}

// randomCluster builds configurations without data the gate refuses, so the store equal to them must verify green.
func randomCluster(rng *rand.Rand) *config.Cluster {
	labels := []string{"a", "b", "cam", "nas", "pc", "srv"}
	ttls := []int{0, 0, 60, 120}
	c := &config.Cluster{Scopes: map[string]config.ScopeConfig{}}
	nd := 1 + rng.Intn(3)
	for i := 0; i < nd; i++ {
		d := config.LocalDomain{Name: fmt.Sprintf("d%d.lan", i), TTL: ttls[rng.Intn(len(ttls))]}
		for j := 0; j < rng.Intn(8); j++ {
			h := config.LocalDomainHost{Host: labels[rng.Intn(len(labels))], TTL: ttls[rng.Intn(len(ttls))], ProbeDisabled: rng.Intn(5) == 0}
			if rng.Intn(3) == 0 {
				h.Type, h.Value = "AAAA", fmt.Sprintf("fd00::%x", 1+rng.Intn(20))
			} else {
				h.Type, h.Value = "A", fmt.Sprintf("10.0.%d.%d", i, 1+rng.Intn(20))
			}
			d.Records = append(d.Records, h)
		}
		if rng.Intn(2) == 0 {
			d.Records = append(d.Records, config.LocalDomainHost{Host: fmt.Sprintf("txt%d", rng.Intn(1000)), Type: "TXT", Value: "v"})
		}
		if i > 0 && rng.Intn(3) == 0 {
			d.ForkedFrom = c.LocalDomains[0].Name
			d.Records = c.LocalDomains[0].Records
		}
		c.LocalDomains = append(c.LocalDomains, d)
	}
	for s := 0; s < rng.Intn(3); s++ {
		sc := config.ScopeConfig{}
		for k := 0; k < rng.Intn(4); k++ {
			sc.DNSRecords = append(sc.DNSRecords, config.DNSRecord{Name: fmt.Sprintf("s%d-%d.d0.lan", s, k), Type: "A", Value: fmt.Sprintf("10.5.%d.%d", s, 1+rng.Intn(10)), TTL: ttls[rng.Intn(len(ttls))]})
		}
		for k := 0; k < rng.Intn(3); k++ {
			sc.Reservations = append(sc.Reservations, config.Reservation{IP: fmt.Sprintf("10.6.%d.%d", s, 1+k), Hostname: fmt.Sprintf("r%d-%d", s, k)})
		}
		c.Scopes[fmt.Sprintf("scope%d", s)] = sc
	}
	return c
}

func TestRun_RandomConfigurationsVerifyAgainstTheirOwnStore(t *testing.T) {
	seed := time.Now().UnixNano()
	t.Logf("seed %d", seed)
	rng := rand.New(rand.NewSource(seed))
	for i := range 200 {
		c := randomCluster(rng)
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			r := newRig(t, c)
			r.in.Leases = nil
			r.publish()
			res := r.run()
			for _, n := range builtChecks {
				if ch := check(t, res, n); !ch.OK {
					b, _ := json.MarshalIndent(c, "", " ")
					t.Fatalf("check %s red: %s %q\n%s", n, ch.Reason, ch.Examples, b)
				}
			}
		})
	}
}
