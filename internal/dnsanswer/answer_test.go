// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsanswer

import (
	"bytes"
	"fmt"
	"math/rand"
	"net/netip"
	"testing"
)

var lan = []Zone{{Name: "example.lan"}}

func baseTable(t testing.TB) *Table {
	return table(t, lan,
		rrA("host.example.lan", "10.0.0.1"),
		rrA("host.example.lan", "10.0.0.2"),
		rr("host.example.lan", TypeAAAA, 300, must(RDataAAAA("fd00::1"))),
		rr("example.lan", TypeMX, 300, must(RDataMX(10, "mail.example.lan"))),
		rr("host.example.lan", TypeTXT, 300, must(RDataTXT("v=test", "second"))),
		rr("_dante._tcp.example.lan", TypeSRV, 300, must(RDataSRV(1, 2, 4440, "host.example.lan"))),
		rr(ReverseName(netip.MustParseAddr("10.0.0.1")), TypePTR, 300, must(ToWire("host.example.lan"))),
		rrCNAME("alias.example.lan", "host.example.lan"),
		rrCNAME("hop2.example.lan", "alias.example.lan"),
		rrCNAME("ext.example.lan", "elsewhere.example.org"),
		rrCNAME("loop1.example.lan", "loop2.example.lan"),
		rrCNAME("loop2.example.lan", "loop1.example.lan"),
	)
}

func TestRespond_RecordTypes(t *testing.T) {
	tb := baseTable(t)
	cases := []struct {
		name  string
		qtype uint16
		want  []string
	}{
		{"host.example.lan", TypeA, []string{"10.0.0.1", "10.0.0.2"}},
		{"HOST.Example.LAN", TypeA, []string{"10.0.0.1", "10.0.0.2"}},
		{"host.example.lan", TypeAAAA, []string{"fd00::1"}},
		{"example.lan", TypeMX, []string{"10 mail.example.lan"}},
		{"host.example.lan", TypeTXT, []string{"v=test|second"}},
		{"_dante._tcp.example.lan", TypeSRV, []string{"1 2 4440 host.example.lan"}},
		{"1.0.0.10.in-addr.arpa", TypePTR, []string{"host.example.lan"}},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s/%d", c.name, c.qtype), func(t *testing.T) {
			r, st := ask(t, tb, c.name, c.qtype)
			if st != Answered || r.rcode != 0 || r.flags&0x0400 == 0 || r.flags&0x8000 == 0 {
				t.Fatalf("status %v rcode %d flags %#x", st, r.rcode, r.flags)
			}
			var got []string
			for _, a := range r.an {
				got = append(got, a.data)
			}
			if fmt.Sprint(got) != fmt.Sprint(c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestRespond_QuestionEchoedExactly(t *testing.T) {
	tb := baseTable(t)
	q := mkQuery("HoSt.ExAmPlE.lan", TypeA, false, 0)
	out, st := tb.Respond(q, nil, false)
	if st != Answered || !bytes.Equal(out[12:len(q)], q[12:]) {
		t.Fatal("the question must be copied byte for byte, including its case")
	}
	if out[0] != q[0] || out[1] != q[1] {
		t.Fatal("id not echoed")
	}
}

func TestRespond_Negative(t *testing.T) {
	tb := baseTable(t)
	r, st := ask(t, tb, "host.example.lan", 99)
	if st != Answered || r.rcode != 0 || len(r.an) != 0 || len(r.ns) != 1 || r.ns[0].typ != TypeSOA {
		t.Fatalf("nodata: %+v", r)
	}
	if want := "ns.example.lan hostmaster.example.lan 42 3600 600 86400 60"; r.ns[0].data != want || r.ns[0].ttl != 60 || r.ns[0].owner != "example.lan" {
		t.Fatalf("soa %+v", r.ns[0])
	}
	r, _ = ask(t, tb, "nothing.example.lan", TypeA)
	if r.rcode != 3 || len(r.an) != 0 || len(r.ns) != 1 || r.flags&0x0400 == 0 || r.flags&0x0100 == 0 || r.flags&0x0080 == 0 {
		t.Fatalf("nxdomain: %+v", r)
	}
}

func TestRespond_ForwardRules(t *testing.T) {
	tb := table(t, []Zone{{Name: "example.lan"}, {Name: "remote.lan", Forward: true}},
		rrA("host.example.lan", "10.0.0.1"), rrA("pinned.remote.lan", "10.9.9.9"), rrA("loose.other.lan", "10.1.1.1"))
	for _, n := range []string{"www.example.org", "missing.remote.lan", "remote.lan"} {
		if _, st := ask(t, tb, n, TypeA); st != Forward {
			t.Errorf("%s: want Forward", n)
		}
	}
	r, st := ask(t, tb, "pinned.remote.lan", TypeA)
	if st != Answered || len(r.an) != 1 || r.an[0].data != "10.9.9.9" {
		t.Fatal("an explicit record under a forwarded domain must still be answered")
	}
	r, st = ask(t, tb, "loose.other.lan", TypeA)
	if st != Answered || len(r.an) != 1 {
		t.Fatal("a free-standing record outside any zone must be answered")
	}
	if r, _ = ask(t, tb, "loose.other.lan", TypeAAAA); r.rcode != 0 || len(r.an) != 0 {
		t.Fatalf("free-standing nodata: %+v", r)
	}
	if _, st := ask(t, tb, "other.other.lan", TypeA); st != Forward {
		t.Fatal("a missing name next to a free-standing record is not ours")
	}
}

func TestRespond_Wildcards(t *testing.T) {
	tb := table(t, lan,
		rrA("*.apps.example.lan", "10.7.7.7"),
		rrA("fixed.apps.example.lan", "10.7.7.8"),
		rrA("svc.sub.apps.example.lan", "10.7.7.9"),
		rr("*.txt.example.lan", TypeTXT, 300, must(RDataTXT("w"))),
	)
	r, _ := ask(t, tb, "anything.apps.example.lan", TypeA)
	if r.rcode != 0 || len(r.an) != 1 || r.an[0].data != "10.7.7.7" || r.an[0].owner != "anything.apps.example.lan" {
		t.Fatalf("wildcard match: %+v", r)
	}
	if r, _ = ask(t, tb, "a.b.apps.example.lan", TypeA); len(r.an) != 1 || r.an[0].data != "10.7.7.7" {
		t.Fatalf("wildcard must match several labels below its parent: %+v", r)
	}
	if r, _ = ask(t, tb, "fixed.apps.example.lan", TypeA); r.an[0].data != "10.7.7.8" {
		t.Fatal("an explicit name beats the wildcard")
	}
	if r, _ = ask(t, tb, "fixed.apps.example.lan", TypeAAAA); r.rcode != 0 || len(r.an) != 0 {
		t.Fatalf("explicit name without the type is NODATA, not the wildcard: %+v", r)
	}
	if r, _ = ask(t, tb, "sub.apps.example.lan", TypeA); r.rcode != 0 || len(r.an) != 0 {
		t.Fatalf("an empty non-terminal is NODATA: %+v", r)
	}
	if r, _ = ask(t, tb, "x.sub.apps.example.lan", TypeA); r.rcode != 3 {
		t.Fatalf("below an empty non-terminal with no wildcard of its own: want NXDOMAIN, got %+v", r)
	}
	if r, _ = ask(t, tb, "x.txt.example.lan", TypeA); r.rcode != 0 || len(r.an) != 0 || len(r.ns) != 1 {
		t.Fatalf("wildcard without the type is NODATA: %+v", r)
	}
	if r, _ = ask(t, tb, "x.txt.example.lan", TypeTXT); len(r.an) != 1 {
		t.Fatalf("wildcard TXT: %+v", r)
	}
	if r, _ = ask(t, tb, "apps.example.lan", TypeA); r.rcode != 0 || len(r.an) != 0 {
		t.Fatalf("the parent of a wildcard exists as a name, so NODATA: %+v", r)
	}
}

func TestRespond_CNAME(t *testing.T) {
	tb := baseTable(t)
	r, _ := ask(t, tb, "alias.example.lan", TypeA)
	if len(r.an) != 3 || r.an[0].typ != TypeCNAME || r.an[0].data != "host.example.lan" || r.an[1].owner != "host.example.lan" {
		t.Fatalf("cname to a name in the table: %+v", r.an)
	}
	r, _ = ask(t, tb, "hop2.example.lan", TypeA)
	if len(r.an) != 4 || r.an[0].data != "alias.example.lan" || r.an[1].data != "host.example.lan" {
		t.Fatalf("two hops: %+v", r.an)
	}
	r, _ = ask(t, tb, "ext.example.lan", TypeA)
	if len(r.an) != 1 || r.an[0].data != "elsewhere.example.org" {
		t.Fatalf("cname to an outside name: %+v", r.an)
	}
	if r, _ = ask(t, tb, "alias.example.lan", TypeCNAME); len(r.an) != 1 {
		t.Fatalf("asking for the CNAME itself: %+v", r.an)
	}
	r, _ = ask(t, tb, "loop1.example.lan", TypeA)
	if len(r.an) == 0 || len(r.an) > maxChain+1 {
		t.Fatalf("a CNAME loop must stay bounded, got %d records", len(r.an))
	}
}

func TestRespond_TransferAndANY(t *testing.T) {
	tb := baseTable(t)
	if r, _ := ask(t, tb, "example.lan", TypeAXFR); r.rcode != 5 || len(r.an) != 0 {
		t.Fatalf("AXFR must be refused: %+v", r)
	}
	if r, _ := ask(t, tb, "example.lan", TypeIXFR); r.rcode != 5 {
		t.Fatal("IXFR must be refused")
	}
	if _, st := ask(t, tb, "example.org", TypeAXFR); st != Forward {
		t.Fatal("a transfer for a foreign name is not ours")
	}
	r, _ := ask(t, tb, "host.example.lan", TypeANY)
	if len(r.an) != 2 || r.an[0].typ != TypeA {
		t.Fatalf("ANY answers one record set only: %+v", r.an)
	}
}

func TestRespond_TruncationAndEDNS(t *testing.T) {
	var rrs []RR
	for i := 0; i < 80; i++ {
		rrs = append(rrs, rrA("big.example.lan", fmt.Sprintf("10.1.%d.%d", i/200, i%200+1)))
	}
	tb := table(t, lan, rrs...)
	q := mkQuery("big.example.lan", TypeA, false, 0)
	out, _ := tb.Respond(q, nil, false)
	r := parseResp(t, out)
	if r.flags&0x0200 == 0 || len(r.an) != 0 || len(out) > 512 {
		t.Fatalf("plain UDP must be cut with TC: flags %#x answers %d len %d", r.flags, len(r.an), len(out))
	}
	out, _ = tb.Respond(mkQuery("big.example.lan", TypeA, true, 4096), nil, false)
	r = parseResp(t, out)
	if r.flags&0x0200 == 0 || r.ar != 1 || len(out) > MaxUDP {
		t.Fatalf("EDNS size is capped at %d: flags %#x ar %d len %d", MaxUDP, r.flags, r.ar, len(out))
	}
	out, _ = tb.Respond(q, nil, true)
	r = parseResp(t, out)
	if r.flags&0x0200 != 0 || len(r.an) != 80 {
		t.Fatalf("TCP answers in full: flags %#x answers %d", r.flags, len(r.an))
	}
	out, _ = tb.Respond(mkQuery("host.example.lan", TypeA, true, 1232), nil, false)
	if r = parseResp(t, out); r.ar != 1 && r.rcode != 3 {
		t.Fatalf("an EDNS query gets an OPT back: %+v", r)
	}
	out, _ = tb.Respond(mkQuery("big.example.lan", 99, false, 0), nil, false)
	if r = parseResp(t, out); r.ar != 0 {
		t.Fatal("no OPT without EDNS in the query")
	}
}

func TestRespond_MalformedAndForeignQueriesAreForwarded(t *testing.T) {
	tb := baseTable(t)
	good := mkQuery("host.example.lan", TypeA, false, 0)
	mut := func(f func(q []byte) []byte) []byte { return f(append([]byte(nil), good...)) }
	bad := map[string][]byte{
		"short":        good[:7],
		"response":     mut(func(q []byte) []byte { q[2] |= 0x80; return q }),
		"opcode":       mut(func(q []byte) []byte { q[2] |= 0x28; return q }),
		"qdcount0":     mut(func(q []byte) []byte { q[5] = 0; return q }),
		"qdcount2":     mut(func(q []byte) []byte { q[5] = 2; return q }),
		"answers":      mut(func(q []byte) []byte { q[7] = 1; return q }),
		"pointer":      mut(func(q []byte) []byte { q[12] = 0xC0; return q }),
		"chaos":        mut(func(q []byte) []byte { q[len(q)-1] = 3; return q }),
		"cut":          good[:len(good)-3],
		"opt-in-query": mkQuery("host.example.lan", 41, false, 0),
	}
	for name, q := range bad {
		if _, st := tb.Respond(q, nil, false); st != Forward {
			t.Errorf("%s: want Forward", name)
		}
	}
}

func TestRespond_NoAllocations(t *testing.T) {
	tb := baseTable(t)
	buf := make([]byte, 0, 4096)
	for _, q := range [][]byte{
		mkQuery("host.example.lan", TypeA, true, 1232),
		mkQuery("nothing.example.lan", TypeA, false, 0),
		mkQuery("hop2.example.lan", TypeA, false, 0),
		mkQuery("www.example.org", TypeA, false, 0),
	} {
		if n := testing.AllocsPerRun(200, func() { tb.Respond(q, buf, false) }); n != 0 {
			t.Errorf("%d allocations per query", int(n))
		}
	}
}

func TestBuilder_DeterministicAndSpecRoundTrip(t *testing.T) {
	rrs := []RR{rrA("a.example.lan", "10.0.0.1"), rrA("a.example.lan", "10.0.0.2"), rrA("b.example.lan", "10.0.0.3"),
		rrCNAME("c.example.lan", "a.example.lan"), rrA("a.example.lan", "10.0.0.1")}
	base := table(t, lan, rrs...)
	for seed := int64(0); seed < 20; seed++ {
		r := rand.New(rand.NewSource(seed))
		shuffled := append([]RR(nil), rrs...)
		r.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		if table(t, lan, shuffled...).Digest() != base.Digest() {
			t.Fatal("the digest depends on the input order")
		}
	}
	if base.Records() != 4 {
		t.Fatalf("duplicates must collapse, got %d records", base.Records())
	}
	spec := &Spec{Zones: lan, RRs: rrs, Serial: 42, NegTTL: 60}
	enc := spec.Encode()
	dec, err := DecodeSpec(enc)
	if err != nil {
		t.Fatal(err)
	}
	tb2, err := dec.Build()
	if err != nil || tb2.Digest() != base.Digest() {
		t.Fatalf("round trip: %v", err)
	}
	for i := 0; i < len(enc); i++ {
		if _, err := DecodeSpec(enc[:i]); err == nil {
			t.Fatalf("a spec cut at %d of %d bytes must be rejected", i, len(enc))
		}
	}
}

func TestCanonicalName(t *testing.T) {
	good := map[string]string{
		"Host.Example.LAN.": "host.example.lan",
		"bücher.example":    "xn--bcher-kva.example",
		"münchen.de":        "xn--mnchen-3ya.de",
		"*.apps.example":    "*.apps.example",
		"_dante._tcp.x":     "_dante._tcp.x",
	}
	for in, want := range good {
		if got, err := CanonicalName(in); err != nil || got != want {
			t.Errorf("%q: got %q %v, want %q", in, got, err, want)
		}
	}
	long := ""
	for i := 0; i < 70; i++ {
		long += "a"
	}
	for _, in := range []string{"", ".", "a..b", "a b.example", "a.*.example", long + ".example", "ex ample", "a\x00b"} {
		if _, err := CanonicalName(in); err == nil {
			t.Errorf("%q must be rejected", in)
		}
	}
}

func TestReverseName(t *testing.T) {
	if got := ReverseName(netip.MustParseAddr("192.168.1.20")); got != "20.1.168.192.in-addr.arpa" {
		t.Fatal(got)
	}
	if got := ReverseName(netip.MustParseAddr("2001:db8::567:89ab")); got != "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa" {
		t.Fatal(got)
	}
}

func FuzzRespond(f *testing.F) {
	tb := baseTable(f)
	for _, n := range []string{"host.example.lan", "alias.example.lan", "x.example.lan", "www.example.org"} {
		f.Add(mkQuery(n, TypeA, true, 1232), false)
		f.Add(mkQuery(n, TypeANY, false, 0), true)
	}
	f.Add([]byte{}, false)
	f.Fuzz(func(t *testing.T, q []byte, tcp bool) {
		out, st := tb.Respond(q, make([]byte, 0, 1500), tcp)
		if st == Forward {
			return
		}
		r := parseResp(t, out)
		if r.id != be.Uint16(q) {
			t.Fatal("id not echoed")
		}
	})
}
