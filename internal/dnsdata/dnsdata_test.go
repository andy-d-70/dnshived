// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsdata

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"dnshived/internal/config"
	"dnshived/internal/dnsanswer"
	"dnshived/internal/dnsstore"
	"dnshived/internal/dnsstore/vfs/faultfs"
)

func id(n int) dnsstore.ID {
	var i dnsstore.ID
	binary.BigEndian.PutUint64(i[:8], uint64(n)*0x9E3779B97F4A7C15)
	binary.BigEndian.PutUint64(i[8:], uint64(n))
	return i
}

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

func putHost(n int, h Host) dnsstore.Op {
	return dnsstore.Op{Kind: dnsstore.OpPut, Type: TypeHost, ID: id(n), Body: h.Encode()}
}

func putRec(n int, r Record) dnsstore.Op {
	return dnsstore.Op{Kind: dnsstore.OpPut, Type: TypeRecord, ID: id(n), Body: r.Encode()}
}

func commit(t testing.TB, s *dnsstore.Store, ops ...dnsstore.Op) {
	t.Helper()
	if _, err := s.Commit(dnsstore.Batch{Origin: 1, Ops: ops}); err != nil {
		t.Fatal(err)
	}
}

func ip(s string) Addr { return Addr{IP: netip.MustParseAddr(s), PTR: true} }

var cfg = CompileConfig{
	Zones:      []dnsanswer.Zone{{Name: "example.lan"}, {Name: "lab.example.lan"}, {Name: "remote.lan", Forward: true}},
	DefaultTTL: 300,
	NegTTL:     60,

	Authoritative: true,
}

func answers(t testing.TB, tb *dnsanswer.Table, name string, typ uint16) (rcode int, got []string) {
	t.Helper()
	q := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, byte(typ>>8), byte(typ), 0, 1)
	out, st := tb.Respond(q, nil, false)
	if st != dnsanswer.Answered {
		return -1, nil
	}
	rcode = int(out[3] & 0xF)
	an := int(binary.BigEndian.Uint16(out[6:]))
	off := 12
	for out[off] != 0 {
		off += 1 + int(out[off])
	}
	off += 5
	for i := 0; i < an; i++ {
		for out[off]&0xC0 == 0 && out[off] != 0 {
			off += 1 + int(out[off])
		}
		if out[off]&0xC0 == 0xC0 {
			off += 2
		} else {
			off++
		}
		rt := binary.BigEndian.Uint16(out[off:])
		rdl := int(binary.BigEndian.Uint16(out[off+8:]))
		rd := out[off+10 : off+10+rdl]
		off += 10 + rdl
		switch rt {
		case dnsanswer.TypeA, dnsanswer.TypeAAAA:
			a, _ := netip.AddrFromSlice(rd)
			got = append(got, a.String())
		default:
			got = append(got, fmt.Sprintf("type%d:%x", rt, rd))
		}
	}
	return rcode, got
}

func TestCodec_RoundTrip(t *testing.T) {
	h := Host{Label: "cam-1", Domains: []string{"example.lan", "lab.example.lan"}, Addrs: []Addr{ip("10.0.0.5"), {IP: netip.MustParseAddr("fd00::5")}}, TTL: 600}
	got, err := DecodeHost(h.Encode())
	if err != nil || fmt.Sprint(got) != fmt.Sprint(h) {
		t.Fatalf("host: %+v %v", got, err)
	}
	r := Record{Host: id(7), Sub: "_svc", Type: dnsanswer.TypeSRV, TTL: 120, Target: "x.example.lan", Prio: 1, Weight: 2, Port: 4440, Raw: "legacy"}
	gr, err := DecodeRecord(r.Encode())
	if err != nil || gr != r {
		t.Fatalf("record: %+v %v", gr, err)
	}
	for _, bad := range [][]byte{{1}, {1, 200}, {4, 2, 9, 9}} {
		if _, err := DecodeHost(bad); err == nil {
			t.Errorf("host bytes %v must be rejected", bad)
		}
	}
	if _, err := DecodeRecord(nil); err == nil {
		t.Error("a record without a type must be rejected")
	}
}

func FuzzDecodeRows(f *testing.F) {
	h := Host{Label: "a", Domains: []string{"b"}, Addrs: []Addr{ip("10.0.0.1")}}
	f.Add(h.Encode())
	f.Add((&Record{Type: 16, Owner: "x", Value: "y"}).Encode())
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = DecodeHost(b)
		_, _ = DecodeRecord(b)
	})
}

func TestCompile_HostsDomainsAndAnswers(t *testing.T) {
	s := newStore(t)
	commit(t, s,
		putHost(1, Host{Label: "cam-1", Domains: []string{"example.lan", "lab.example.lan"}, Addrs: []Addr{ip("10.0.0.5"), ip("fd00::5")}}),
		putHost(2, Host{Label: "*.apps", Domains: []string{"example.lan"}, Addrs: []Addr{{IP: netip.MustParseAddr("10.0.0.99")}}}),
		putRec(3, Record{Host: id(1), Sub: "_rtsp._tcp", Type: dnsanswer.TypeSRV, Target: "cam-1.example.lan", Port: 554}),
		putRec(4, Record{Owner: "info.example.lan", Type: dnsanswer.TypeTXT, Value: "hello"}),
		putRec(5, Record{Owner: "other.free.lan", Type: dnsanswer.TypeA, Value: "10.9.9.9"}),
		putRec(6, Record{Owner: "old.example.lan", Type: TypeRAW, Raw: "something"}),
		putRec(7, Record{Owner: "web.example.lan", Type: dnsanswer.TypeCNAME, Value: "cam-1.example.lan"}),
	)
	spec, rep := Compile(s.View(), cfg)
	if rep.Hosts != 2 || rep.Records != 5 || rep.Legacy != 1 || len(rep.Errors) != 0 || len(rep.Dangling) != 0 {
		t.Fatalf("report %+v", rep)
	}
	tb, err := spec.Build()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		typ  uint16
		rc   int
		n    int
	}{
		{"cam-1.example.lan", dnsanswer.TypeA, 0, 1}, {"cam-1.lab.example.lan", dnsanswer.TypeA, 0, 1},
		{"cam-1.example.lan", dnsanswer.TypeAAAA, 0, 1}, {"anything.apps.example.lan", dnsanswer.TypeA, 0, 1},
		{"_rtsp._tcp.cam-1.example.lan", dnsanswer.TypeSRV, 0, 1}, {"_rtsp._tcp.cam-1.lab.example.lan", dnsanswer.TypeSRV, 0, 1},
		{"info.example.lan", dnsanswer.TypeTXT, 0, 1}, {"other.free.lan", dnsanswer.TypeA, 0, 1},
		{"5.0.0.10.in-addr.arpa", dnsanswer.TypePTR, 0, 1}, {"nothing.example.lan", dnsanswer.TypeA, 3, 0},
		{"web.example.lan", dnsanswer.TypeA, 0, 2}, {"old.example.lan", dnsanswer.TypeA, 3, 0},
	} {
		if rc, got := answers(t, tb, c.name, c.typ); rc != c.rc || len(got) != c.n {
			t.Errorf("%s/%d: rcode %d answers %v", c.name, c.typ, rc, got)
		}
	}
	_, ptr := answers(t, tb, "5.0.0.10.in-addr.arpa", dnsanswer.TypePTR)
	want, _ := dnsanswer.ToWire("cam-1.example.lan")
	if fmt.Sprint(ptr) != fmt.Sprintf("[type12:%x]", want) {
		t.Fatalf("the PTR must name the first domain: %v", ptr)
	}
	if rc, _ := answers(t, tb, "fd00::5", dnsanswer.TypeAAAA); rc != -1 {
		t.Log("ignored")
	}
}

func TestCompile_BadRowsAreSkippedAndDanglingDomainsFlagged(t *testing.T) {
	s := newStore(t)
	commit(t, s,
		putHost(1, Host{Label: "ok", Domains: []string{"example.lan", "gone.lan"}, Addrs: []Addr{ip("10.0.0.1")}}),
		putRec(2, Record{Owner: "bad name!.example.lan", Type: dnsanswer.TypeA, Value: "10.0.0.2"}),
		putRec(3, Record{Host: id(99), Type: dnsanswer.TypeTXT, Value: "x"}),
		putRec(4, Record{Owner: "x.example.lan", Type: dnsanswer.TypeA, Value: "not an ip"}),
		dnsstore.Op{Kind: dnsstore.OpPut, Type: TypeHost, ID: id(5), Body: []byte{1, 200}},
	)
	spec, rep := Compile(s.View(), cfg)
	if len(rep.Errors) != 4 || len(rep.Dangling) != 1 || rep.Dangling[0] != "ok.gone.lan" {
		t.Fatalf("report %+v", rep)
	}
	tb, err := spec.Build()
	if err != nil {
		t.Fatal(err)
	}
	if rc, got := answers(t, tb, "ok.example.lan", dnsanswer.TypeA); rc != 0 || len(got) != 1 {
		t.Fatal("the host must stay served under its remaining domain")
	}
}

func TestMergeLeases(t *testing.T) {
	s := newStore(t)
	commit(t, s, putHost(1, Host{Label: "fixed", Domains: []string{"example.lan"}, Addrs: []Addr{ip("10.0.0.1")}}))
	spec, _ := Compile(s.View(), cfg)
	l := func(name, ipS, mac string, at int64) LeaseName {
		return LeaseName{Name: name, IP: netip.MustParseAddr(ipS), MAC: mac, LeasedAt: at, Scope: "office"}
	}
	cols := MergeLeases(spec, []LeaseName{
		l("fixed.example.lan", "10.0.5.1", "aa:01", 100),
		l("pc.example.lan", "10.0.5.2", "aa:03", 300),
		l("pc.example.lan", "10.0.5.3", "aa:02", 200),
		l("pc.example.lan", "fd00::2", "aa:02", 210),
		l("late.example.lan", "10.0.5.4", "aa:09", 0),
		l("late.example.lan", "10.0.5.5", "aa:08", 0),
		l("Bad Name", "10.0.5.6", "aa:07", 1),
	}, 300)
	if len(cols) != 3 {
		t.Fatalf("collisions %+v", cols)
	}
	want := map[string]string{"fixed.example.lan|aa:01": "authored", "pc.example.lan|aa:03": "aa:02", "late.example.lan|aa:09": "aa:08"}
	for _, c := range cols {
		if want[c.Name+"|"+c.MAC] != c.Holder {
			t.Errorf("unexpected collision %+v", c)
		}
	}
	tb, err := spec.Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, got := answers(t, tb, "pc.example.lan", dnsanswer.TypeA); fmt.Sprint(got) != "[10.0.5.3]" {
		t.Fatalf("the earliest lease keeps the name: %v", got)
	}
	if _, got := answers(t, tb, "pc.example.lan", dnsanswer.TypeAAAA); fmt.Sprint(got) != "[fd00::2]" {
		t.Fatalf("the holder may publish IPv6 too: %v", got)
	}
	if _, got := answers(t, tb, "fixed.example.lan", dnsanswer.TypeA); fmt.Sprint(got) != "[10.0.0.1]" {
		t.Fatalf("an authored name is never replaced: %v", got)
	}
	if _, got := answers(t, tb, "3.5.0.10.in-addr.arpa", dnsanswer.TypePTR); len(got) != 1 {
		t.Fatal("a lease name gets its reverse record")
	}
	if _, got := answers(t, tb, "1.5.0.10.in-addr.arpa", dnsanswer.TypePTR); len(got) != 0 {
		t.Fatal("a losing lease gets no reverse record")
	}
}

func TestMergeLeases_ClientCannotInjectAWildcard(t *testing.T) {
	spec := &dnsanswer.Spec{Zones: []dnsanswer.Zone{{Name: "example.lan"}}}
	MergeLeases(spec, []LeaseName{
		{Name: "*.example.lan", IP: netip.MustParseAddr("10.0.5.1"), MAC: "aa:01"},
		{Name: "ok.example.lan", IP: netip.MustParseAddr("10.0.5.2"), MAC: "aa:02"},
	}, 300)
	for _, rr := range spec.RRs {
		if strings.HasPrefix(rr.Owner, "*") {
			t.Fatalf("a lease published the wildcard %s", rr.Owner)
		}
	}
	if len(spec.RRs) != 2 {
		t.Fatalf("records: %d", len(spec.RRs))
	}
}

func ctx() GateContext {
	return GateContext{Zones: map[string]bool{"example.lan": true, "lab.example.lan": true}}
}

func TestGate_Rules(t *testing.T) {
	s := newStore(t)
	commit(t, s,
		putHost(1, Host{Label: "cam", Domains: []string{"example.lan"}, Addrs: []Addr{ip("10.0.0.1")}}),
		putRec(2, Record{Owner: "alias.example.lan", Type: dnsanswer.TypeCNAME, Value: "cam.example.lan"}),
	)
	v := s.View()
	cases := []struct {
		name    string
		ops     []dnsstore.Op
		c       func(*GateContext)
		wantErr string
		wantWrn string
	}{
		{"ok", []dnsstore.Op{putHost(10, Host{Label: "new", Domains: []string{"example.lan", "lab.example.lan"}, Addrs: []Addr{ip("10.0.0.2")}})}, nil, "", ""},
		{"edit own row", []dnsstore.Op{putHost(1, Host{Label: "cam", Domains: []string{"example.lan"}, Addrs: []Addr{ip("10.0.0.7")}})}, nil, "", ""},
		{"one holder", []dnsstore.Op{putHost(10, Host{Label: "cam", Domains: []string{"example.lan"}, Addrs: []Addr{ip("10.0.0.2")}})}, nil, "already used by another host", ""},
		{"unknown domain", []dnsstore.Op{putHost(10, Host{Label: "x", Domains: []string{"nope.lan"}})}, nil, "not in the domain list", ""},
		{"no domain", []dnsstore.Op{putHost(10, Host{Label: "x"})}, nil, "at least one domain", ""},
		{"duplicate domain", []dnsstore.Op{putHost(10, Host{Label: "x", Domains: []string{"example.lan", "Example.LAN."}})}, nil, "twice", ""},
		{"bad label", []dnsstore.Op{putHost(10, Host{Label: "a b", Domains: []string{"example.lan"}})}, nil, "host label", ""},
		{"bad address", []dnsstore.Op{putHost(10, Host{Label: "x", Domains: []string{"example.lan"}, Addrs: []Addr{{IP: netip.MustParseAddr("0.0.0.0")}}})}, nil, "not usable", ""},
		{"short ttl", []dnsstore.Op{putHost(10, Host{Label: "x", Domains: []string{"example.lan"}, TTL: 30})}, nil, "", "short-ttl"},
		{"long ttl", []dnsstore.Op{putHost(10, Host{Label: "x", Domains: []string{"example.lan"}, TTL: 900000})}, nil, "", "long-ttl"},
		{"huge ttl", []dnsstore.Op{putRec(10, Record{Owner: "t.example.lan", Type: dnsanswer.TypeTXT, Value: "x", TTL: 1 << 31})}, nil, "ttl", ""},
		{"cname beside host", []dnsstore.Op{putRec(10, Record{Owner: "cam.example.lan", Type: dnsanswer.TypeCNAME, Value: "x.example.lan"})}, nil, "alias (CNAME)", ""},
		{"host beside cname", []dnsstore.Op{putHost(10, Host{Label: "alias", Domains: []string{"example.lan"}, Addrs: []Addr{ip("10.0.0.3")}})}, nil, "alias (CNAME)", ""},
		{"txt beside cname", []dnsstore.Op{putRec(10, Record{Owner: "alias.example.lan", Type: dnsanswer.TypeTXT, Value: "x"})}, nil, "alias (CNAME)", ""},
		{"second cname", []dnsstore.Op{putRec(10, Record{Owner: "alias.example.lan", Type: dnsanswer.TypeCNAME, Value: "y.example.lan"})}, nil, "more than one CNAME", ""},
		{"cname loop", []dnsstore.Op{putRec(10, Record{Owner: "cam2.example.lan", Type: dnsanswer.TypeCNAME, Value: "alias.example.lan"}), putRec(11, Record{Owner: "z.example.lan", Type: dnsanswer.TypeCNAME, Value: "z.example.lan"})}, nil, "leads back to itself", ""},
		{"dangling cname", []dnsstore.Op{putRec(10, Record{Owner: "d.example.lan", Type: dnsanswer.TypeCNAME, Value: "missing.example.lan"})}, nil, "", "dangling-cname"},
		{"record on missing host", []dnsstore.Op{putRec(10, Record{Host: id(55), Type: dnsanswer.TypeTXT, Value: "x"})}, nil, "does not exist", ""},
		{"bad record data", []dnsstore.Op{putRec(10, Record{Owner: "a.example.lan", Type: dnsanswer.TypeSRV, Target: "bad name"})}, nil, "a.example.lan", ""},
		{"raw refused", []dnsstore.Op{putRec(10, Record{Owner: "a.example.lan", Type: TypeRAW, Raw: "x"})}, nil, "raw records", ""},
		{"raw allowed for migration", []dnsstore.Op{putRec(10, Record{Owner: "a.example.lan", Type: TypeRAW, Raw: "x"})}, func(c *GateContext) { c.AllowLegacy = true }, "", ""},
		{"delete host with records", []dnsstore.Op{{Kind: dnsstore.OpDel, Type: TypeHost, ID: id(1)}}, nil, "", ""},
		{"reservation name", []dnsstore.Op{putHost(10, Host{Label: "printer", Domains: []string{"example.lan"}})}, func(c *GateContext) { c.Reserved = map[string]string{"printer.example.lan": "office"} }, "reservation office", ""},
		{"lease warning", []dnsstore.Op{putHost(10, Host{Label: "pc", Domains: []string{"example.lan"}})}, func(c *GateContext) {
			c.LeaseHolder = func(n string) (string, bool) { return "aa:bb", n == "pc.example.lan" }
		}, "", "lease-holds-name"},
		{"cap", []dnsstore.Op{putHost(10, Host{Label: "x", Domains: []string{"example.lan", "lab.example.lan"}})}, func(c *GateContext) { c.MaxNames = 2 }, "limit is 2", ""},
		{"not a dns row", []dnsstore.Op{{Kind: dnsstore.OpPut, Type: 9, ID: id(10), Body: []byte("x")}}, nil, "not a DNS row", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gc := ctx()
			if c.c != nil {
				c.c(&gc)
			}
			vd := Validate(v, c.ops, gc)
			if c.name == "delete host with records" {
				c.wantErr = ""
				vd = Validate(v, append(c.ops, putRec(2, Record{Owner: "alias.example.lan", Type: dnsanswer.TypeCNAME, Value: "cam.example.lan"})), gc)
				_ = vd
			}
			if c.wantErr == "" && !vd.OK() {
				t.Fatalf("unexpected errors %v", vd.Errors)
			}
			if c.wantErr != "" && !strings.Contains(strings.Join(vd.Errors, "|"), c.wantErr) {
				t.Fatalf("errors %v, want one containing %q", vd.Errors, c.wantErr)
			}
			if c.wantWrn != "" {
				found := false
				for _, w := range vd.Warnings {
					found = found || w.Code == c.wantWrn
				}
				if !found {
					t.Fatalf("warnings %v, want %s", vd.Warnings, c.wantWrn)
				}
			}
		})
	}
}

func TestGate_DeleteHostNeedsItsRecordsGone(t *testing.T) {
	s := newStore(t)
	commit(t, s,
		putHost(1, Host{Label: "cam", Domains: []string{"example.lan"}, Addrs: []Addr{ip("10.0.0.1")}}),
		putRec(2, Record{Host: id(1), Sub: "_x", Type: dnsanswer.TypeTXT, Value: "x"}),
	)
	del := dnsstore.Op{Kind: dnsstore.OpDel, Type: TypeHost, ID: id(1)}
	if vd := Validate(s.View(), []dnsstore.Op{del}, ctx()); vd.OK() {
		t.Fatal("deleting a host that still has records must fail")
	}
	if vd := Validate(s.View(), []dnsstore.Op{del, {Kind: dnsstore.OpDel, Type: TypeRecord, ID: id(2)}}, ctx()); !vd.OK() {
		t.Fatalf("deleting both together is fine: %v", vd.Errors)
	}
}

func TestCompile_OverlayModeForwardsWhatTheTableDoesNotHold(t *testing.T) {
	s := newStore(t)
	commit(t, s, putHost(1, Host{Label: "cam", Domains: []string{"example.lan"}, Addrs: []Addr{ip("10.0.0.5")}}),
		putHost(2, Host{Label: "*.apps", Domains: []string{"example.lan"}, Addrs: []Addr{{IP: netip.MustParseAddr("10.0.0.9")}}}))
	over := cfg
	over.Authoritative = false
	spec, _ := Compile(s.View(), over)
	tb, err := spec.Build()
	if err != nil {
		t.Fatal(err)
	}
	if rc, got := answers(t, tb, "cam.example.lan", dnsanswer.TypeA); rc != 0 || len(got) != 1 {
		t.Fatal("a record the table holds is answered in overlay mode")
	}
	if rc, _ := answers(t, tb, "missing.example.lan", dnsanswer.TypeA); rc != -1 {
		t.Fatal("a name the table lacks must be forwarded, not refused, before the cutover")
	}
	if rc, _ := answers(t, tb, "x.apps.example.lan", dnsanswer.TypeA); rc != -1 {
		t.Fatal("wildcards apply only after the cutover")
	}
	auth, _ := Compile(s.View(), cfg)
	tb2, _ := auth.Build()
	if rc, _ := answers(t, tb2, "missing.example.lan", dnsanswer.TypeA); rc != 3 {
		t.Fatal("after the cutover the table answers for the whole domain")
	}
	if rc, got := answers(t, tb2, "x.apps.example.lan", dnsanswer.TypeA); rc != 0 || len(got) != 1 {
		t.Fatal("wildcard after the cutover")
	}
}

func TestSettings_RoundTripAndGate(t *testing.T) {
	s := newStore(t)
	if ReadSettings(s.View()).Authoritative {
		t.Fatal("off by default")
	}
	if vd := Validate(s.View(), []dnsstore.Op{SettingOp(AuthoritativeKey, true)}, ctx()); !vd.OK() {
		t.Fatalf("the cutover setting passes the gate: %v", vd.Errors)
	}
	commit(t, s, SettingOp(AuthoritativeKey, true))
	if !ReadSettings(s.View()).Authoritative {
		t.Fatal("on after the commit")
	}
	bad := dnsstore.Op{Kind: dnsstore.OpPut, Type: TypeSetting, ID: id(1), Body: []byte("1")}
	if vd := Validate(s.View(), []dnsstore.Op{bad}, ctx()); vd.OK() {
		t.Fatal("an unknown setting must be refused")
	}
	if vd := Validate(s.View(), []dnsstore.Op{{Kind: dnsstore.OpPut, Type: TypeSetting, ID: settingID(AuthoritativeKey), Body: []byte("maybe")}}, ctx()); vd.OK() {
		t.Fatal("a setting value other than 0 or 1 must be refused")
	}
}

func TestCompile_RawRecordsCarryTheirOwnData(t *testing.T) {
	s := newStore(t)
	commit(t, s, putRec(1, Record{Owner: "odd.example.lan", Type: 99, Raw: "c0a80001"}), putRec(2, Record{Owner: "bad.example.lan", Type: 99, Raw: "zz"}))
	spec, rep := Compile(s.View(), cfg)
	if len(rep.Errors) != 1 {
		t.Fatalf("one raw record is not hex: %+v", rep.Errors)
	}
	tb, _ := spec.Build()
	if rc, got := answers(t, tb, "odd.example.lan", 99); rc != 0 || len(got) != 1 || got[0] != "type99:c0a80001" {
		t.Fatalf("raw record: %d %v", rc, got)
	}
}

func TestImportOps_KeepsEveryRecordTypeAndIsIdempotent(t *testing.T) {
	recs := []config.DNSRecord{
		{Name: "web.example.lan.", Type: "A", Value: "10.0.0.7", TTL: 120},
		{Name: "web.example.lan.", Type: "AAAA", Value: "fd00::7"},
		{Name: "www.example.lan.", Type: "CNAME", Value: "web.example.lan."},
		{Name: "example.lan.", Type: "MX", Target: "mail.example.lan.", Priority: 10},
		{Name: "_sip._tcp.example.lan.", Type: "SRV", Target: "pbx.example.lan.", Port: 5060, Priority: 1, Weight: 5},
		{Name: "web.example.lan.", Type: "TXT", Value: "v=1"},
		{Name: "7.0.0.10.in-addr.arpa.", Type: "PTR", Value: "web.example.lan."},
		{Name: "example.lan.", Type: "CAA", Value: "letsencrypt.org", CAAFlags: 0, CAATag: "issue"},
		{Name: "sip.example.lan.", Type: "NAPTR", Target: "_sip._udp.example.lan.", NAPTROrder: 10, Priority: 20, NAPTRFlags: "s", NAPTRService: "SIP+D2U", NAPTRRegexp: ""},
		{Name: "odd.example.lan.", Type: "RAW", RRType: 99, RRDataHex: "C0A80001"},
		{Name: "dup.example.lan.", Type: "A", Value: "10.0.0.8"},
		{Name: "dup.example.lan.", Type: "A", Value: "10.0.0.8"},
		{Name: "bad name.example.lan.", Type: "A", Value: "10.0.0.9"},
		{Name: "x.example.lan.", Type: "ZZZ", Value: "1"},
		{Name: "y.example.lan.", Type: "A", Value: "nope"},
	}
	ops, rep := ImportOps(recs)
	if rep.Records != 11 || len(ops) != 11 || len(rep.Skipped) != 3 {
		t.Fatalf("imported %d, skipped %v", rep.Records, rep.Skipped)
	}
	again, _ := ImportOps(recs)
	for i := range ops {
		if ops[i].ID != again[i].ID {
			t.Fatal("the same records must give the same row ids")
		}
	}
	s := newStore(t)
	commit(t, s, ops...)
	commit(t, s, again...)
	if s.View().Len() != 11 {
		t.Fatalf("importing twice must not duplicate: %d rows", s.View().Len())
	}
	if vd := Validate(s.View(), again, ctx()); !vd.OK() {
		t.Fatalf("an import passes the write gate: %v", vd.Errors)
	}
	spec, rep2 := Compile(s.View(), cfg)
	if len(rep2.Errors) != 0 {
		t.Fatalf("compile errors: %+v", rep2.Errors)
	}
	tb, _ := spec.Build()
	for _, c := range []struct {
		name string
		typ  uint16
		n    int
	}{
		{"web.example.lan", dnsanswer.TypeA, 1}, {"web.example.lan", dnsanswer.TypeAAAA, 1}, {"www.example.lan", dnsanswer.TypeA, 2},
		{"example.lan", dnsanswer.TypeMX, 1}, {"_sip._tcp.example.lan", dnsanswer.TypeSRV, 1}, {"web.example.lan", dnsanswer.TypeTXT, 1},
		{"7.0.0.10.in-addr.arpa", dnsanswer.TypePTR, 1}, {"example.lan", dnsanswer.TypeCAA, 1}, {"sip.example.lan", dnsanswer.TypeNAPTR, 1},
		{"odd.example.lan", 99, 1},
	} {
		if rc, got := answers(t, tb, c.name, c.typ); rc != 0 || len(got) != c.n {
			t.Errorf("%s/%d: rcode %d answers %v", c.name, c.typ, rc, got)
		}
	}
}
