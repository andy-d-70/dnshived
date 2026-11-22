// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsservice

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"dnshived/internal/dnsanswer"
	"dnshived/internal/dnsdata"
	"dnshived/internal/dnsfeed"
)

type feedRig struct {
	*rig
	pub  *dnsfeed.Publisher
	view atomic.Pointer[dnsanswer.Table]
	info atomic.Pointer[dnsfeed.Info]
	seen chan struct{}
}

func newFeedRig(t *testing.T, fo dnsfeed.Options) *feedRig {
	t.Helper()
	f := &feedRig{pub: dnsfeed.NewPublisher(fo), seen: make(chan struct{}, 1024)}
	dir, err := os.MkdirTemp("", "dnsfeed")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "feed.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	pubDone := make(chan struct{})
	go func() { defer close(pubDone); _ = f.pub.Serve(ctx, ln) }()
	cons := dnsfeed.NewConsumer(dnsfeed.ConsumerOptions{
		Dial: func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "unix", path) },
		OnTable: func(tb *dnsanswer.Table, i dnsfeed.Info) {
			f.view.Store(tb)
			f.info.Store(&i)
			select {
			case f.seen <- struct{}{}:
			default:
			}
		},
		MinBackoff: 5 * time.Millisecond, MaxBackoff: 20 * time.Millisecond,
	})
	consDone := make(chan struct{})
	go func() { defer close(consDone); _ = cons.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-consDone; <-pubDone })
	f.rig = openRigWith(t, t.TempDir(), 0, func(o *Options) { o.Feed = f.pub })
	return f
}

// settle waits until the reader holds what the publisher has published.
func (f *feedRig) settle() {
	f.t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		st := f.pub.Status()
		if i := f.info.Load(); i != nil && i.Epoch == st.Epoch && i.Seq == st.Seq {
			return
		}
		select {
		case <-f.seen:
		case <-deadline:
			f.t.Fatalf("the reader did not catch up with %+v (it has %+v)", f.pub.Status(), f.info.Load())
		}
	}
}

// reference builds the table the way a full rebuild does, from the same store, configuration and leases.
func (f *feedRig) reference() *dnsanswer.Table {
	f.t.Helper()
	view, in := f.svc.store.View(), f.svc.o.Input()
	spec, _ := dnsdata.Compile(view, dnsdata.CompileConfig{Zones: in.Zones, DefaultTTL: in.DefaultTTL, NegTTL: in.NegTTL, Authoritative: dnsdata.ReadSettings(view).Authoritative})
	dnsdata.MergeReserved(spec, in.ReservedNames, in.DefaultTTL)
	dnsdata.MergeLeases(spec, f.svc.o.Leases(), in.DefaultTTL)
	tb, err := spec.Build()
	if err != nil {
		f.t.Fatal(err)
	}
	return tb
}

func (f *feedRig) sameAsReference(names []string) {
	f.t.Helper()
	f.settle()
	want, got := f.reference(), f.view.Load()
	for _, n := range names {
		for _, typ := range []uint16{dnsanswer.TypeA, dnsanswer.TypeAAAA, dnsanswer.TypePTR} {
			q := query(n, typ)
			w, ws := want.Respond(q, nil, false)
			g, gs := got.Respond(q, nil, false)
			if ws != gs || string(w) != string(g) {
				f.t.Fatalf("%s type %d: a full rebuild answers %x (%v), the reader %x (%v)", n, typ, w, ws, g, gs)
			}
		}
	}
}

func TestService_FeedCarriesBaseAndLeaseChanges(t *testing.T) {
	f := newFeedRig(t, dnsfeed.Options{})
	f.settle()
	if st := f.pub.Status(); st.Epoch == 0 {
		t.Fatalf("the first build is published as a base: %+v", st)
	}
	if code, out := f.do("POST", "/api/v1/dnsstore/commit", hostBody("00000000000000000000000000000001")); code != 200 {
		t.Fatalf("commit: %d %v", code, out)
	}
	f.sameAsReference([]string{"cam-1.example.lan", "5.0.0.10.in-addr.arpa"})
	epoch := f.pub.Status().Epoch
	leases := []dnsdata.LeaseName{{Name: "phone.example.lan", IP: netip.MustParseAddr("10.0.0.50"), MAC: "02:00:00:00:00:01", LeasedAt: 1}}
	f.leases.Store(&leases)
	if err := f.svc.Rebuild(false); err != nil {
		t.Fatal(err)
	}
	st := f.pub.Status()
	if st.Epoch != epoch || st.Seq != 1 {
		t.Fatalf("a lease name is a change on top of the base, not a new base: %+v", st)
	}
	f.sameAsReference([]string{"phone.example.lan", "50.0.0.10.in-addr.arpa", "cam-1.example.lan"})
	if rc, an := answerOf(f.view.Load(), "phone.example.lan"); rc != 0 || an != 1 {
		t.Fatalf("the reader answers the lease name: rcode %d, %d answers", rc, an)
	}
	none := []dnsdata.LeaseName{}
	f.leases.Store(&none)
	if err := f.svc.Rebuild(false); err != nil {
		t.Fatal(err)
	}
	f.sameAsReference([]string{"phone.example.lan", "50.0.0.10.in-addr.arpa"})
	if _, an := answerOf(f.view.Load(), "phone.example.lan"); an != 0 {
		t.Fatal("the ended lease is gone from the reader")
	}
	if err := f.svc.Rebuild(false); err != nil || f.pub.Status().Seq != 2 {
		t.Fatalf("nothing changed, nothing is published: %+v %v", f.pub.Status(), err)
	}
}

func answerOf(tb *dnsanswer.Table, name string) (rcode, an int) {
	out, st := tb.Respond(query(name, dnsanswer.TypeA), nil, false)
	if st != dnsanswer.Answered {
		return -1, 0
	}
	return int(out[3] & 0xF), int(out[6])<<8 | int(out[7])
}

func TestService_FeedAnAuthoredChangeIsANewBase(t *testing.T) {
	f := newFeedRig(t, dnsfeed.Options{})
	f.settle()
	leases := []dnsdata.LeaseName{{Name: "phone.example.lan", IP: netip.MustParseAddr("10.0.0.50"), MAC: "02:00:00:00:00:01"}}
	f.leases.Store(&leases)
	if err := f.svc.Rebuild(false); err != nil {
		t.Fatal(err)
	}
	f.settle()
	before := f.pub.Status()
	if code, out := f.do("POST", "/api/v1/dnsstore/commit", hostBody("00000000000000000000000000000002")); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	f.settle()
	after := f.pub.Status()
	if after.Epoch != before.Epoch+1 || after.Seq != 0 {
		t.Fatalf("a store change starts a new base: before %+v after %+v", before, after)
	}
	f.sameAsReference([]string{"phone.example.lan", "cam-1.example.lan"})
}

func TestService_FeedStaysEqualToAFullRebuildUnderRandomLeaseChurn(t *testing.T) {
	f := newFeedRig(t, dnsfeed.Options{})
	if code, out := f.do("POST", "/api/v1/dnsstore/commit", hostBody("00000000000000000000000000000001")); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	names := []string{"cam-1.example.lan", "printer.example.lan", "a.example.lan", "b.example.lan", "c.example.lan", "d.example.lan"}
	var probes []string
	probes = append(probes, names...)
	for i := 1; i <= 8; i++ {
		probes = append(probes, fmt.Sprintf("%d.0.0.10.in-addr.arpa", 40+i))
	}
	rng := rand.New(rand.NewSource(11))
	for step := 0; step < 150; step++ {
		var leases []dnsdata.LeaseName
		for k := rng.Intn(6); k > 0; k-- {
			leases = append(leases, dnsdata.LeaseName{
				Name: names[rng.Intn(len(names))], IP: netip.MustParseAddr(fmt.Sprintf("10.0.0.%d", 41+rng.Intn(8))),
				MAC: fmt.Sprintf("02:00:00:00:00:%02x", rng.Intn(5)), LeasedAt: int64(rng.Intn(3)),
			})
		}
		f.leases.Store(&leases)
		if err := f.svc.Rebuild(false); err != nil {
			t.Fatal(err)
		}
		f.sameAsReference(probes)
	}
	if st := f.pub.Status(); st.Seq == 0 {
		t.Fatalf("the churn was published as changes: %+v", st)
	}
}

func TestService_FeedFallsBackToANewBaseWhenTheChangesPileUp(t *testing.T) {
	f := newFeedRig(t, dnsfeed.Options{MaxRingBytes: 600})
	f.settle()
	first := f.pub.Status().Epoch
	for i := 1; i <= 30; i++ {
		leases := []dnsdata.LeaseName{{Name: fmt.Sprintf("n%d.example.lan", i), IP: netip.MustParseAddr(fmt.Sprintf("10.0.1.%d", i)), MAC: "02:00:00:00:00:01"}}
		f.leases.Store(&leases)
		if err := f.svc.Rebuild(false); err != nil {
			t.Fatal(err)
		}
	}
	f.sameAsReference([]string{"n30.example.lan", "n1.example.lan", "30.1.0.10.in-addr.arpa"})
	if f.pub.Status().Epoch <= first {
		t.Fatal("the full ring must have produced a new base")
	}
}
