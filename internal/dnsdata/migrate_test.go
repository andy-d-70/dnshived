// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsdata

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/netip"
	"sort"
	"strings"
	"testing"

	"dnshived/internal/config"
	"dnshived/internal/dnsanswer"
	"dnshived/internal/dnsstore"
)

func migrateCluster() *config.Cluster {
	foo := []config.LocalDomainHost{
		{Host: "www", Type: "A", Value: "10.0.0.1", TTL: 120},
		{Host: "www", Type: "AAAA", Value: "fd00::1", TTL: 120},
		{Host: "mail", Type: "A", Value: "10.0.0.2"},
		{Host: "cam", Type: "A", Value: "10.0.0.3", ProbeDisabled: true},
		{Host: "mixed", Type: "A", Value: "10.0.0.4", TTL: 60},
		{Host: "mixed", Type: "A", Value: "10.0.0.5", TTL: 90},
		{Host: "@", Type: "TXT", Value: "v=spf1 -all"},
		{Host: "", Type: "MX", Target: "mail.foo.lan.", Priority: 10},
		{Host: "_sip._tcp", Type: "SRV", Target: "www.foo.lan.", Port: 5060, Priority: 1, Weight: 5},
		{Host: "alias", Type: "CNAME", Value: "www.foo.lan."},
		{Host: "x", Type: "RAW", RRType: 99, RRDataHex: "C0A80001"},
		{Host: "dup", Type: "A", Value: "10.0.0.3"},
	}
	return &config.Cluster{
		Scopes: map[string]config.ScopeConfig{
			"office": {DNSRecords: []config.DNSRecord{
				{Name: "scoped.office.lan.", Type: "A", Value: "10.0.0.9"},
				{Name: "cert.office.lan.", Type: "CAA", Value: "letsencrypt.org", CAATag: "issue"},
			}},
			"av": {
				DNSRecords: []config.DNSRecord{{Name: "ndi.av.lan.", Type: "A", Value: "10.0.0.2", ProbeDisabled: true}},
				Reservations: []config.Reservation{
					{MAC: "02:00:00:00:00:01", IP: "10.0.0.2", Hostname: "mixer", Names: []string{"Mixer.Foo.LAN", "mixer-alt"}},
					{MAC: "02:00:00:00:00:02", IP: "10.0.0.3", Hostname: "www.foo.lan"},
					{MAC: "02:00:00:00:00:03", IP: "10.0.0.50", Hostname: "bad name"},
				},
			},
		},
		GlobalDNSRecords: []config.DNSRecord{
			{Name: "global.example.net.", Type: "A", Value: "10.1.1.1"},
			{Name: "sip.example.net.", Type: "NAPTR", Target: "_sip._udp.example.net.", NAPTROrder: 10, Priority: 20, NAPTRFlags: "s", NAPTRService: "SIP+D2U"},
			{Name: "4.0.0.10.in-addr.arpa.", Type: "PTR", Value: "mixed.foo.lan."},
			{Name: "bad name.example.net.", Type: "A", Value: "10.1.1.2"},
			{Name: "nope.example.net.", Type: "A", Value: "not-an-address"},
		},
		LocalDomains: []config.LocalDomain{
			{Name: "foo.lan", TTL: 300, Records: foo},
			{Name: "bar.lan", TTL: 300, ForkedFrom: "foo.lan", Records: foo},
			{Name: "baz.lan", Records: []config.LocalDomainHost{{Host: "www", Type: "A", Value: "10.0.0.77"}}},
		},
	}
}

type rrSet map[string]bool

func rrKey(owner string, typ uint16, rd []byte) string {
	return fmt.Sprintf("%s|%d|%s", owner, typ, hex.EncodeToString(rd))
}

func (s rrSet) keys() []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// expectedFromConfig applies dnsmasq's meaning to the configuration in the order the central instance renders it.
func expectedFromConfig(t *testing.T, c *config.Cluster) rrSet {
	t.Helper()
	out := rrSet{}
	claimed := map[netip.Addr]bool{}
	var all []config.DNSRecord
	names := make([]string, 0, len(c.Scopes))
	for n := range c.Scopes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		all = append(all, c.Scopes[n].DNSRecords...)
		for _, r := range c.Scopes[n].Reservations {
			for _, name := range r.DNSNames() {
				all = append(all, config.DNSRecord{Name: name, Type: "A", Value: r.IP})
			}
		}
	}
	all = append(all, c.GlobalDNSRecords...)
	all = append(all, config.ExpandedLocalDomainRecords(c.LocalDomains)...)
	for _, r := range all {
		rec, err := recordFromConfig(r)
		if err != nil {
			continue
		}
		rd, err := recordData(&rec)
		if err != nil {
			t.Fatal(err)
		}
		out[rrKey(rec.Owner, rec.Type, rd)] = true
		if rec.Type == dnsanswer.TypeA || rec.Type == dnsanswer.TypeAAAA {
			ip := netip.MustParseAddr(rec.Value).Unmap()
			if !claimed[ip] {
				claimed[ip] = true
				w, _ := dnsanswer.ToWire(rec.Owner)
				out[rrKey(dnsanswer.ReverseName(ip), dnsanswer.TypePTR, w)] = true
			}
		}
	}
	return out
}

func compiledSet(t *testing.T, ops []dnsstore.Op, c *config.Cluster) rrSet {
	t.Helper()
	s := newStore(t)
	if len(ops) > 0 {
		commit(t, s, ops...)
	}
	cc := CompileConfig{DefaultTTL: 300, NegTTL: 60, Authoritative: true}
	for _, d := range c.LocalDomains {
		cc.Zones = append(cc.Zones, dnsanswer.Zone{Name: d.Name})
	}
	spec, rep := Compile(s.View(), cc)
	if len(rep.Errors) != 0 || len(rep.Dangling) != 0 {
		t.Fatalf("compile report: %+v", rep)
	}
	MergeReserved(spec, ReservedNames(c), 300)
	out := rrSet{}
	for _, rr := range spec.RRs {
		out[rrKey(rr.Owner, rr.Type, rr.RData)] = true
	}
	return out
}

func TestMigrate_AnswersEqualWhatTheConfigurationMeans(t *testing.T) {
	c := migrateCluster()
	ops, rep := MigrateOps(c)
	if len(rep.Skipped) != 2 {
		t.Fatalf("skipped: %v", rep.Skipped)
	}
	want, got := expectedFromConfig(t, c), compiledSet(t, ops, c)
	for _, k := range want.keys() {
		if !got[k] {
			t.Errorf("the store would lose %s", k)
		}
	}
	for _, k := range got.keys() {
		if !want[k] {
			t.Errorf("the store would add %s", k)
		}
	}
}

func TestMigrate_GroupsLinkedDomainsIntoOneHostAndKeepsTags(t *testing.T) {
	c := migrateCluster()
	ops, rep := MigrateOps(c)
	var hosts []Host
	var recs []Record
	for _, op := range ops {
		switch op.Type {
		case TypeHost:
			h, err := DecodeHost(op.Body)
			if err != nil {
				t.Fatal(err)
			}
			hosts = append(hosts, h)
		case TypeRecord:
			r, err := DecodeRecord(op.Body)
			if err != nil {
				t.Fatal(err)
			}
			recs = append(recs, r)
		}
	}
	if rep.Hosts != len(hosts) || rep.Records != len(recs) {
		t.Fatalf("report %+v vs %d hosts %d records", rep, len(hosts), len(recs))
	}
	find := func(label string, dom string) *Host {
		for i := range hosts {
			if hosts[i].Label == label && strings.Join(hosts[i].Domains, ",") == dom {
				return &hosts[i]
			}
		}
		return nil
	}
	www := find("www", "foo.lan,bar.lan")
	if www == nil || www.TTL != 120 || len(www.Addrs) != 2 {
		t.Fatalf("the linked domains share one host: %+v", hosts)
	}
	if find("www", "baz.lan") == nil {
		t.Fatal("an unrelated domain keeps its own host")
	}
	if cam := find("cam", "foo.lan,bar.lan"); cam == nil || !cam.ProbeDisabled {
		t.Fatal("the probe flag moves to the host")
	}
	if find("mixed", "foo.lan,bar.lan") != nil {
		t.Fatal("a label with different TTLs is not grouped")
	}
	var scoped, ndi *Record
	for i := range recs {
		switch recs[i].Owner {
		case "scoped.office.lan":
			scoped = &recs[i]
		case "ndi.av.lan":
			ndi = &recs[i]
		}
	}
	if scoped == nil || scoped.Scope != "office" || ndi == nil || ndi.Scope != "av" || !ndi.ProbeDisabled {
		t.Fatalf("scope and probe flag are kept: %+v %+v", scoped, ndi)
	}
}

func TestMigrate_ReverseRecordGoesToTheFirstOwnerOfAnAddress(t *testing.T) {
	c := migrateCluster()
	ops, _ := MigrateOps(c)
	var ptrs []string
	for _, op := range ops {
		if op.Type != TypeRecord {
			continue
		}
		if r, _ := DecodeRecord(op.Body); r.Type == dnsanswer.TypePTR && r.Owner == "2.0.0.10.in-addr.arpa" {
			ptrs = append(ptrs, r.Value)
		}
	}
	if len(ptrs) != 1 || ptrs[0] != "ndi.av.lan" {
		t.Fatalf("10.0.0.2 belongs first to the scope record, the host must not add a second reverse record: %v", ptrs)
	}
}

func TestMigrate_IsDeterministicAndIdempotent(t *testing.T) {
	c := migrateCluster()
	a, _ := MigrateOps(c)
	b, _ := MigrateOps(c)
	if len(a) != len(b) {
		t.Fatal("different row counts")
	}
	for i := range a {
		if a[i].ID != b[i].ID || string(a[i].Body) != string(b[i].Body) || a[i].Type != b[i].Type {
			t.Fatalf("row %d differs between runs", i)
		}
	}
	s := newStore(t)
	commit(t, s, a...)
	commit(t, s, b...)
	if s.View().Len() != len(a) {
		t.Fatalf("a second run must not add rows: %d rows for %d ops", s.View().Len(), len(a))
	}
}

func TestMigrate_RowsPassTheWriteGate(t *testing.T) {
	c := migrateCluster()
	ops, _ := MigrateOps(c)
	zones := map[string]bool{}
	for _, d := range c.LocalDomains {
		zones[d.Name] = true
	}
	s := newStore(t)
	vd := Validate(s.View(), ops, GateContext{Zones: zones, AllowLegacy: true})
	for _, e := range vd.Errors {
		t.Errorf("gate: %s", e)
	}
}

func TestMigrate_TagsRoundTrip(t *testing.T) {
	h := Host{Label: "a", Domains: []string{"x.lan"}, Addrs: []Addr{{IP: netip.MustParseAddr("10.0.0.1"), PTR: true}}, ProbeDisabled: true, LastBy: "operator", LastAt: 1790000000}
	back, err := DecodeHost(h.Encode())
	if err != nil || back.LastBy != "operator" || back.LastAt != 1790000000 || !back.ProbeDisabled {
		t.Fatalf("host: %+v %v", back, err)
	}
	r := Record{Owner: "a.x.lan", Type: dnsanswer.TypeTXT, Value: "v", Scope: "office", ProbeDisabled: true, LastBy: "x", LastAt: 5}
	rb, err := DecodeRecord(r.Encode())
	if err != nil || rb.Scope != "office" || !rb.ProbeDisabled || rb.LastBy != "x" || rb.LastAt != 5 {
		t.Fatalf("record: %+v %v", rb, err)
	}
	if _, err := DecodeRecord(append(r.Encode(), 20, 1, 7)); err == nil {
		t.Fatal("a probe flag above 1 is refused")
	}
}

func TestMigrate_EmptyAndInvalidConfigurations(t *testing.T) {
	if ops, rep := MigrateOps(&config.Cluster{}); len(ops) != 0 || len(rep.Skipped) != 0 {
		t.Fatalf("nothing in, nothing out: %d %v", len(ops), rep.Skipped)
	}
	c := &config.Cluster{LocalDomains: []config.LocalDomain{{Name: "bad name"}, {Name: "ok.lan", Records: []config.LocalDomainHost{{Host: "h", Type: "A", Value: "10.0.0.1"}}}}}
	ops, rep := MigrateOps(c)
	if len(rep.Skipped) != 1 || rep.Hosts != 1 || len(ops) != 1 {
		t.Fatalf("one bad domain is reported, the rest migrates: %+v ops %d", rep, len(ops))
	}
}

func randomCluster(rng *rand.Rand) *config.Cluster {
	c := &config.Cluster{Scopes: map[string]config.ScopeConfig{}}
	labels := []string{"a", "b", "www", "cam", "_x._tcp", "*"}
	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "fd00::1", "fd00::2"}
	ttls := []int{0, 0, 60, 120}
	n := 1 + rng.Intn(4)
	for i := 0; i < n; i++ {
		d := config.LocalDomain{Name: fmt.Sprintf("d%d.lan", i), TTL: ttls[rng.Intn(len(ttls))]}
		for j := rng.Intn(8); j > 0; j-- {
			h := config.LocalDomainHost{Host: labels[rng.Intn(len(labels))], TTL: ttls[rng.Intn(len(ttls))], ProbeDisabled: rng.Intn(5) == 0}
			switch rng.Intn(4) {
			case 0:
				h.Type, h.Value = "TXT", fmt.Sprintf("v%d", rng.Intn(3))
			case 1:
				h.Type, h.Value = "CNAME", "a.d0.lan."
			default:
				ip := ips[rng.Intn(len(ips))]
				h.Type, h.Value = "A", ip
				if strings.Contains(ip, ":") {
					h.Type = "AAAA"
				}
			}
			d.Records = append(d.Records, h)
		}
		if i > 0 && rng.Intn(2) == 0 {
			d.ForkedFrom = "d0.lan"
			d.Records = append([]config.LocalDomainHost(nil), c.LocalDomains[0].Records...)
			d.TTL = c.LocalDomains[0].TTL
		}
		c.LocalDomains = append(c.LocalDomains, d)
	}
	for i := rng.Intn(3); i > 0; i-- {
		name := fmt.Sprintf("s%d", i)
		sc := config.ScopeConfig{}
		for j := rng.Intn(3); j > 0; j-- {
			sc.DNSRecords = append(sc.DNSRecords, config.DNSRecord{Name: fmt.Sprintf("r%d.%s.lan.", j, name), Type: "A", Value: ips[rng.Intn(3)]})
		}
		for j := rng.Intn(4); j > 0; j-- {
			r := config.Reservation{MAC: fmt.Sprintf("02:00:00:00:%02x:%02x", i, j), IP: ips[rng.Intn(3)], Hostname: []string{"a", "www", "pr1", ""}[rng.Intn(4)]}
			if rng.Intn(2) == 0 {
				r.Names = []string{"x.d0.lan", "alt"}
			}
			sc.Reservations = append(sc.Reservations, r)
		}
		c.Scopes[name] = sc
	}
	for j := rng.Intn(3); j > 0; j-- {
		c.GlobalDNSRecords = append(c.GlobalDNSRecords, config.DNSRecord{Name: fmt.Sprintf("g%d.example.net.", j), Type: "A", Value: ips[rng.Intn(3)]})
	}
	return c
}

func TestMigrate_RandomConfigurationsKeepTheirMeaning(t *testing.T) {
	rng := rand.New(rand.NewSource(20261122))
	for i := 0; i < 200; i++ {
		c := randomCluster(rng)
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			ops, _ := MigrateOps(c)
			want, got := expectedFromConfig(t, c), compiledSet(t, ops, c)
			for _, k := range want.keys() {
				if !got[k] {
					t.Fatalf("the store would lose %s", k)
				}
			}
			for _, k := range got.keys() {
				if !want[k] {
					t.Fatalf("the store would add %s", k)
				}
			}
			if again, _ := MigrateOps(c); len(again) != len(ops) {
				t.Fatal("not deterministic")
			}
		})
	}
}
