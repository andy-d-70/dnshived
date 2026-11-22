// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsanswer

import (
	"bytes"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
)

var deltaZones = []Zone{{Name: "example.lan"}, {Name: "fwd.lan", Forward: true}}

func deltaRR(owner string, typ uint16, ip string) RR {
	var rd []byte
	var err error
	if typ == TypeCNAME {
		rd, err = ToWire(ip)
	} else {
		rd, err = RDataA(ip)
	}
	if err != nil {
		panic(err)
	}
	return RR{Owner: owner, Type: typ, TTL: 300, RData: rd}
}

func buildSet(t testing.TB, rrs map[string][]RR, serial uint32) *Table {
	t.Helper()
	b := NewBuilder()
	for _, z := range deltaZones {
		if err := b.AddZone(z.Name, z.Forward); err != nil {
			t.Fatal(err)
		}
	}
	owners := make([]string, 0, len(rrs))
	for o := range rrs {
		owners = append(owners, o)
	}
	sort.Strings(owners)
	for _, o := range owners {
		for _, rr := range rrs[o] {
			if err := b.Add(rr); err != nil {
				t.Fatal(err)
			}
		}
	}
	tb, err := b.Build(serial, 60)
	if err != nil {
		t.Fatal(err)
	}
	return tb
}

func sameAnswers(t *testing.T, want, got *Table, names []string) {
	t.Helper()
	for _, n := range names {
		for _, typ := range []uint16{TypeA, TypeAAAA, TypeCNAME, TypeANY} {
			q := mkQuery(n, typ, true, 1232)
			w, ws := want.Respond(q, nil, false)
			g, gs := got.Respond(q, nil, false)
			if ws != gs || !bytes.Equal(w, g) {
				t.Fatalf("%s type %d: a rebuilt table answers %x (%v), the layered view %x (%v)", n, typ, w, ws, g, gs)
			}
		}
	}
}

func TestLive_AnswersLikeARebuildAfterAnyChanges(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	state := map[string][]RR{}
	seen := map[string]bool{"nothere.example.lan": true, "x.apps.example.lan": true, "a.b.example.lan": true, "x.fwd.lan": true, "outside.test": true}
	add := func(o string, rrs ...RR) { state[o] = rrs; seen[o] = true }
	add("*.apps.example.lan", deltaRR("*.apps.example.lan", TypeA, "10.9.9.9"))
	for i := 0; i < 40; i++ {
		o := fmt.Sprintf("h%d.example.lan", i)
		add(o, deltaRR(o, TypeA, fmt.Sprintf("10.0.0.%d", i)))
		if i%4 == 0 {
			c := "c." + o
			add(c, deltaRR(c, TypeA, "10.1.0.1"))
		}
	}
	base := buildSet(t, state, 1)
	live := NewLive(base, deltaZones, 0)
	serial := uint32(1)
	for step := 0; step < 300; step++ {
		serial++
		var ch []Change
		for k := rng.Intn(4) + 1; k > 0; k-- {
			i := rng.Intn(50)
			o := fmt.Sprintf("h%d.example.lan", i)
			switch rng.Intn(5) {
			case 0:
				if len(state["c."+o]) == 0 {
					delete(state, o)
					ch = append(ch, Change{Owner: o, Delete: true})
				}
			case 1:
				a := "alias" + fmt.Sprint(i) + ".example.lan"
				rr := deltaRR(a, TypeCNAME, fmt.Sprintf("h%d.example.lan", rng.Intn(50)))
				state[a], seen[a] = []RR{rr}, true
				ch = append(ch, Change{Owner: a, RRs: []RR{rr}})
			case 2:
				c := "c." + o
				if len(state[o]) > 0 {
					rr := deltaRR(c, TypeA, "10.2.0.2")
					state[c], seen[c] = []RR{rr}, true
					ch = append(ch, Change{Owner: c, RRs: []RR{rr}})
				}
			default:
				rr := deltaRR(o, TypeA, fmt.Sprintf("10.0.1.%d", rng.Intn(250)))
				state[o], seen[o] = []RR{rr}, true
				ch = append(ch, Change{Owner: o, RRs: []RR{rr}})
			}
		}
		if len(ch) == 0 {
			continue
		}
		if _, err := live.Apply(serial, ch); err != nil {
			t.Fatal(err)
		}
		names := make([]string, 0, len(seen))
		for n := range seen {
			names = append(names, n)
		}
		sort.Strings(names)
		sameAnswers(t, buildSet(t, state, serial), live.Table(), names)
	}
}

func TestLive_AnEmptyNonTerminalAnswersNoDataUntilRebase(t *testing.T) {
	state := map[string][]RR{"deep.sub.example.lan": {deltaRR("deep.sub.example.lan", TypeA, "10.0.0.1")}}
	live := NewLive(buildSet(t, state, 1), deltaZones, 0)
	q := mkQuery("sub.example.lan", TypeA, false, 0)
	if r, _ := live.Table().Respond(q, nil, false); r[3]&0xF != 0 {
		t.Fatal("the parent of an existing name exists")
	}
	if _, err := live.Apply(2, []Change{{Owner: "deep.sub.example.lan", Delete: true}}); err != nil {
		t.Fatal(err)
	}
	if r, _ := live.Table().Respond(q, nil, false); r[3]&0xF != 0 {
		t.Fatal("known limit: the empty non-terminal answers no data until the base is rebuilt")
	}
	if err := live.Rebase(buildSet(t, map[string][]RR{}, 2), deltaZones, 1); err != nil {
		t.Fatal(err)
	}
	if r, _ := live.Table().Respond(q, nil, false); r[3]&0xF != 3 {
		t.Fatal("after the rebuild the name is gone")
	}
}

func TestLive_RebaseKeepsOnlyNewerChanges(t *testing.T) {
	live := NewLive(buildSet(t, map[string][]RR{}, 1), deltaZones, 2)
	s1, _ := live.Apply(2, []Change{{Owner: "a.example.lan", RRs: []RR{deltaRR("a.example.lan", TypeA, "10.0.0.1")}}})
	if _, err := live.Apply(3, []Change{{Owner: "b.example.lan", RRs: []RR{deltaRR("b.example.lan", TypeA, "10.0.0.2")}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := live.Apply(4, []Change{{Owner: "c.example.lan", RRs: []RR{deltaRR("c.example.lan", TypeA, "10.0.0.3")}}}); err != nil {
		t.Fatal(err)
	}
	if !live.Full() || live.Len() != 3 {
		t.Fatalf("three changes over a limit of two: len %d full %v", live.Len(), live.Full())
	}
	base := buildSet(t, map[string][]RR{"a.example.lan": {deltaRR("a.example.lan", TypeA, "10.0.0.1")}}, 2)
	if err := live.Rebase(base, deltaZones, s1); err != nil {
		t.Fatal(err)
	}
	if live.Len() != 2 || live.Full() {
		t.Fatalf("the change the new base contains is dropped, the later ones stay: len %d", live.Len())
	}
	for n, want := range map[string]int{"a.example.lan": 1, "b.example.lan": 1, "c.example.lan": 1, "d.example.lan": 0} {
		if _, an := answerCounts(live.Table(), n); an != want {
			t.Errorf("%s: %d answers, want %d", n, an, want)
		}
	}
	if err := live.Rebase(buildSet(t, map[string][]RR{}, 5), deltaZones, 99); err != nil || live.Len() != 0 || live.Table().over != nil {
		t.Fatal("rebasing past every change leaves the plain base")
	}
}

func answerCounts(tb *Table, name string) (rcode, an int) {
	out, st := tb.Respond(mkQuery(name, TypeA, false, 0), nil, false)
	if st != Answered {
		return -1, 0
	}
	return int(out[3] & 0xF), int(out[6])<<8 | int(out[7])
}

func TestLive_ApplyRejectsBadChangesAndChangesNothing(t *testing.T) {
	live := NewLive(buildSet(t, map[string][]RR{}, 1), deltaZones, 0)
	good := Change{Owner: "ok.example.lan", RRs: []RR{deltaRR("ok.example.lan", TypeA, "10.0.0.1")}}
	for name, c := range map[string]Change{
		"not canonical":  {Owner: "Bad.example.lan", RRs: []RR{deltaRR("bad.example.lan", TypeA, "10.0.0.2")}},
		"wrong owner":    {Owner: "x.example.lan", RRs: []RR{deltaRR("y.example.lan", TypeA, "10.0.0.2")}},
		"empty owner":    {Owner: ""},
		"trailing dot":   {Owner: "x.example.lan."},
		"type 41 record": {Owner: "o.example.lan", RRs: []RR{{Owner: "o.example.lan", Type: 41, RData: []byte{1}}}},
	} {
		if _, err := live.Apply(2, []Change{good, c}); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if live.Len() != 0 || live.Table().over != nil {
			t.Fatalf("%s: a refused batch must change nothing (len %d)", name, live.Len())
		}
	}
}

func TestLive_ViewsStayConsistentWhileChangesArrive(t *testing.T) {
	state := map[string][]RR{"a.example.lan": {deltaRR("a.example.lan", TypeA, "10.0.0.1")}}
	live := NewLive(buildSet(t, state, 1), deltaZones, 0)
	var stop atomic.Bool
	var wg sync.WaitGroup
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			q := mkQuery("a.example.lan", TypeA, true, 1232)
			buf := make([]byte, 0, 1500)
			for !stop.Load() {
				out, st := live.Table().Respond(q, buf, false)
				if st != Answered || out[3]&0xF != 0 || out[7] != 1 {
					t.Errorf("a.example.lan must always answer with exactly one record")
					return
				}
			}
		}()
	}
	for i := 0; i < 400; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i>>8, i&255)
		if _, err := live.Apply(uint32(i+2), []Change{
			{Owner: "a.example.lan", RRs: []RR{deltaRR("a.example.lan", TypeA, ip)}},
			{Owner: fmt.Sprintf("n%d.example.lan", i%50), RRs: []RR{deltaRR(fmt.Sprintf("n%d.example.lan", i%50), TypeA, ip)}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()
}

func TestLive_AnsweringFromAnOverlayAllocatesNothing(t *testing.T) {
	live := NewLive(buildSet(t, map[string][]RR{"base.example.lan": {deltaRR("base.example.lan", TypeA, "10.0.0.1")}}, 1), deltaZones, 0)
	if _, err := live.Apply(2, []Change{{Owner: "new.example.lan", RRs: []RR{deltaRR("new.example.lan", TypeA, "10.0.0.2")}}}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 0, 1500)
	for _, name := range []string{"base.example.lan", "new.example.lan", "missing.example.lan", "www.example.com"} {
		q := mkQuery(name, TypeA, true, 1232)
		if n := testing.AllocsPerRun(100, func() { live.Table().Respond(q, buf, false) }); n != 0 {
			t.Errorf("%s: %v allocations per answer", name, n)
		}
	}
}
