// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsfeed

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"dnshived/internal/dnsanswer"
)

var testZones = []dnsanswer.Zone{{Name: "example.lan"}}

func rr(t testing.TB, owner, ip string) dnsanswer.RR {
	t.Helper()
	rd, err := dnsanswer.RDataA(ip)
	if err != nil {
		t.Fatal(err)
	}
	return dnsanswer.RR{Owner: owner, Type: dnsanswer.TypeA, TTL: 60, RData: rd}
}

func blobOf(t testing.TB, serial uint32, rrs ...dnsanswer.RR) []byte {
	t.Helper()
	spec := &dnsanswer.Spec{Zones: testZones, RRs: rrs, Serial: serial, NegTTL: 60}
	tb, err := spec.Build()
	if err != nil {
		t.Fatal(err)
	}
	return dnsanswer.EncodeTable(spec, tb.Digest())
}

func query(name string) []byte {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	return append(q, 0, 0, 1, 0, 1)
}

func answers(t *dnsanswer.Table, name string) (rcode, n int) {
	out, st := t.Respond(query(name), nil, false)
	if st != dnsanswer.Answered {
		return -1, 0
	}
	return int(out[3] & 0xF), int(out[6])<<8 | int(out[7])
}

func sockPath(t testing.TB) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "dnsfeed")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "feed.sock")
}

type rig struct {
	t    testing.TB
	pub  *Publisher
	path string
	cons *Consumer
	got  chan viewEvent
	mu   sync.Mutex
	conn net.Conn
}

type viewEvent struct {
	t    *dnsanswer.Table
	info Info
}

func startPublisher(t testing.TB, o Options) (*Publisher, string) {
	t.Helper()
	pub := NewPublisher(o)
	path := sockPath(t)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = pub.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); <-done })
	return pub, path
}

func newRig(t testing.TB, o Options, co ConsumerOptions) *rig {
	t.Helper()
	pub, path := startPublisher(t, o)
	r := &rig{t: t, pub: pub, path: path, got: make(chan viewEvent, 256)}
	co.Dial = func(ctx context.Context) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
		r.mu.Lock()
		r.conn = c
		r.mu.Unlock()
		return c, err
	}
	co.OnTable = func(tb *dnsanswer.Table, i Info) {
		select {
		case r.got <- viewEvent{tb, i}:
		default:
		}
	}
	co.MinBackoff, co.MaxBackoff = 5*time.Millisecond, 20*time.Millisecond
	r.cons = NewConsumer(co)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = r.cons.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	return r
}

func (r *rig) next(pred func(viewEvent) bool) viewEvent {
	r.t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-r.got:
			if pred == nil || pred(ev) {
				return ev
			}
		case <-deadline:
			r.t.Fatal("timed out waiting for the reader to see the change")
		}
	}
}

func TestFeed_SnapshotThenChangesReachTheReader(t *testing.T) {
	r := newRig(t, Options{}, ConsumerOptions{})
	if err := r.pub.SetBase(blobOf(t, 1, rr(t, "a.example.lan", "10.0.0.1"))); err != nil {
		t.Fatal(err)
	}
	ev := r.next(nil)
	if rc, n := answers(ev.t, "a.example.lan"); rc != 0 || n != 1 || ev.info.Seq != 0 || ev.info.Epoch != 1 {
		t.Fatalf("first view: rcode %d answers %d info %+v", rc, n, ev.info)
	}
	if _, err := r.pub.Publish(2, []dnsanswer.Change{{Owner: "b.example.lan", RRs: []dnsanswer.RR{rr(t, "b.example.lan", "10.0.0.2")}}}); err != nil {
		t.Fatal(err)
	}
	ev = r.next(func(e viewEvent) bool { return e.info.Seq == 1 })
	if _, n := answers(ev.t, "b.example.lan"); n != 1 {
		t.Fatal("the new name answers")
	}
	if _, err := r.pub.Publish(3, []dnsanswer.Change{{Owner: "a.example.lan", Delete: true}}); err != nil {
		t.Fatal(err)
	}
	ev = r.next(func(e viewEvent) bool { return e.info.Seq == 2 })
	if rc, _ := answers(ev.t, "a.example.lan"); rc != 3 {
		t.Fatalf("the removed name is gone: rcode %d", rc)
	}
	if s := r.cons.Status(); !s.Connected || s.Seq != 2 || s.Epoch != 1 {
		t.Fatalf("status %+v", s)
	}
}

func TestFeed_ASecondBaseReplacesTheTable(t *testing.T) {
	r := newRig(t, Options{}, ConsumerOptions{})
	_ = r.pub.SetBase(blobOf(t, 1, rr(t, "old.example.lan", "10.0.0.1")))
	r.next(nil)
	_ = r.pub.SetBase(blobOf(t, 5, rr(t, "new.example.lan", "10.0.0.9")))
	ev := r.next(func(e viewEvent) bool { return e.info.Epoch == 2 })
	if _, n := answers(ev.t, "new.example.lan"); n != 1 {
		t.Fatal("the new base answers")
	}
	if rc, _ := answers(ev.t, "old.example.lan"); rc != 3 {
		t.Fatal("the old base is gone")
	}
}

func TestFeed_AReaderThatReconnectsOnlyGetsTheMissedChanges(t *testing.T) {
	r := newRig(t, Options{}, ConsumerOptions{})
	_ = r.pub.SetBase(blobOf(t, 1, rr(t, "a.example.lan", "10.0.0.1")))
	r.next(nil)
	for i := 2; i <= 3; i++ {
		name := fmt.Sprintf("n%d.example.lan", i)
		if _, err := r.pub.Publish(uint32(i), []dnsanswer.Change{{Owner: name, RRs: []dnsanswer.RR{rr(t, name, "10.0.0.5")}}}); err != nil {
			t.Fatal(err)
		}
	}
	r.next(func(e viewEvent) bool { return e.info.Seq == 2 })
	r.mu.Lock()
	_ = r.conn.Close()
	r.mu.Unlock()
	if _, err := r.pub.Publish(4, []dnsanswer.Change{{Owner: "n4.example.lan", RRs: []dnsanswer.RR{rr(t, "n4.example.lan", "10.0.0.6")}}}); err != nil {
		t.Fatal(err)
	}
	ev := r.next(func(e viewEvent) bool { return e.info.Seq == 3 })
	if _, n := answers(ev.t, "n4.example.lan"); n != 1 || ev.info.Epoch != 1 {
		t.Fatal("caught up on the same base")
	}
	for len(r.got) > 0 {
		if e := <-r.got; e.info.Seq == 0 {
			t.Fatal("a reader that is only behind must not receive the whole table again")
		}
	}
	if r.cons.Status().Reconnects == 0 {
		t.Fatal("the test did not reconnect")
	}
}

func TestPublisher_RefusesChangesWithoutABaseAndWhenTheRingIsFull(t *testing.T) {
	p := NewPublisher(Options{MaxRingBytes: 200})
	ch := []dnsanswer.Change{{Owner: "a.example.lan", RRs: []dnsanswer.RR{rr(t, "a.example.lan", "10.0.0.1")}}}
	if _, err := p.Publish(1, ch); err != ErrNoBase {
		t.Fatalf("no base: %v", err)
	}
	if err := p.SetBase(blobOf(t, 1)); err != nil {
		t.Fatal(err)
	}
	var err error
	for i := 0; i < 20 && err == nil; i++ {
		_, err = p.Publish(uint32(i+2), ch)
	}
	if err != ErrBaseNeeded {
		t.Fatalf("a full ring asks for a new base: %v", err)
	}
	if err := p.SetBase(blobOf(t, 30)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Publish(31, ch); err != nil {
		t.Fatalf("a new base makes room: %v", err)
	}
	if err := p.SetBase([]byte("not a table")); err == nil {
		t.Fatal("a damaged table is refused")
	}
}

func TestPublisher_DropsAReaderThatDoesNotKeepUp(t *testing.T) {
	pub, path := startPublisher(t, Options{QueueDepth: 2, WriteTimeout: 50 * time.Millisecond})
	_ = pub.SetBase(blobOf(t, 1))
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(appendFrame(nil, msgHello, encodeHello(hello{}))); err != nil {
		t.Fatal(err)
	}
	big := make([]dnsanswer.RR, 0, 40)
	for i := 0; i < 40; i++ {
		big = append(big, dnsanswer.RR{Owner: "big.example.lan", Type: dnsanswer.TypeTXT, TTL: 60, RData: append([]byte{255}, make([]byte, 255)...)})
		big[i].RData[1] = byte(i)
	}
	deadline := time.Now().Add(5 * time.Second)
	for i := 0; pub.Status().Dropped == 0; i++ {
		if time.Now().After(deadline) {
			t.Fatal("a reader that never reads was not dropped")
		}
		if _, err := pub.Publish(uint32(i+2), []dnsanswer.Change{{Owner: "big.example.lan", RRs: big}}); err != nil {
			if err == ErrBaseNeeded {
				_ = pub.SetBase(blobOf(t, uint32(i)))
				continue
			}
			t.Fatal(err)
		}
	}
	if pub.Status().Readers != 0 {
		t.Fatalf("the dropped reader is gone: %+v", pub.Status())
	}
}

func TestPublisher_RefusesBadHellosAndStrangers(t *testing.T) {
	var refused sync.Map
	pub, path := startPublisher(t, Options{HelloTimeout: 200 * time.Millisecond, Log: func(f string, a ...any) { refused.Store(fmt.Sprintf(f, a...), true) }})
	_ = pub.SetBase(blobOf(t, 1))
	bad := map[string][]byte{
		"garbage":     []byte("GET / HTTP/1.0\r\n\r\n"),
		"huge frame":  {0xff, 0xff, 0xff, 0x7f, 1},
		"zero frame":  {0, 0, 0, 0},
		"wrong magic": appendFrame(nil, msgHello, []byte("XXXXXXXXXXXXXXXXXXXXXX")),
		"wrong ver":   appendFrame(nil, msgHello, append([]byte(protoMagic), 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)),
		"not a hello": appendFrame(nil, msgPing),
		"silence":     nil,
	}
	for name, payload := range bad {
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		if payload != nil {
			_, _ = c.Write(payload)
		}
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if n, err := c.Read(make([]byte, 1)); n != 0 || err == nil {
			t.Errorf("%s: the publisher answered %d bytes instead of closing", name, n)
		}
		c.Close()
	}
	if pub.Status().Readers != 0 {
		t.Fatalf("no reader was admitted: %+v", pub.Status())
	}
}

func TestPublisher_PeerCredentialsDecide(t *testing.T) {
	pub, path := startPublisher(t, Options{AllowPeer: func(uid, gid uint32) bool { return false }})
	_ = pub.SetBase(blobOf(t, 1))
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write(appendFrame(nil, msgHello, encodeHello(hello{})))
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, _ := c.Read(make([]byte, 1)); n != 0 {
		t.Fatal("a refused peer gets nothing")
	}
}

type fakeServer struct {
	path   string
	hellos chan hello
	resync chan string
}

func startFake(t *testing.T, script func(c net.Conn, n int)) *fakeServer {
	t.Helper()
	f := &fakeServer{path: sockPath(t), hellos: make(chan hello, 8), resync: make(chan string, 8)}
	ln, err := net.Listen("unix", f.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for n := 0; ; n++ {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(n int) {
				defer c.Close()
				br := bufio.NewReader(c)
				typ, body, err := readFrame(br, 256)
				if err != nil || typ != msgHello {
					return
				}
				h, _ := decodeHello(body)
				f.hellos <- h
				go func() {
					for {
						typ, body, err := readFrame(br, 4096)
						if err != nil {
							return
						}
						if typ == msgResync {
							f.resync <- string(body)
						}
					}
				}()
				script(c, n)
				time.Sleep(200 * time.Millisecond)
			}(n)
		}
	}()
	return f
}

func fakeSnapshot(t *testing.T, epoch uint64, blob []byte) []byte {
	return appendFrame(nil, msgSnapshot, le.AppendUint64(nil, epoch), blob)
}

func TestConsumer_RejectsABrokenChainAndAsksForANewTable(t *testing.T) {
	blob := blobOf(t, 1, rr(t, "a.example.lan", "10.0.0.1"))
	tb, _, _ := dnsanswer.DecodeTable(blob)
	ch := []dnsanswer.Change{{Owner: "x.example.lan", RRs: []dnsanswer.RR{rr(t, "x.example.lan", "10.0.0.7")}}}
	good, _, _ := encodeDelta(1, 1, 2, ch, chainSeed(1, tb.Digest()))
	forged := append([]byte(nil), good...)
	forged[len(forged)-1] ^= 0xff
	fake := startFake(t, func(c net.Conn, n int) {
		_, _ = c.Write(fakeSnapshot(t, 1, blob))
		if n == 0 {
			_, _ = c.Write(appendFrame(nil, msgDelta, forged))
		}
	})
	var views sync.Map
	cons := NewConsumer(ConsumerOptions{
		Dial:       func(ctx context.Context) (net.Conn, error) { return net.Dial("unix", fake.path) },
		OnTable:    func(tb *dnsanswer.Table, i Info) { views.Store(i.Seq, tb) },
		MinBackoff: 5 * time.Millisecond, MaxBackoff: 10 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = cons.Run(ctx) }()
	defer func() { cancel(); <-done }()
	select {
	case reason := <-fake.resync:
		if !strings.Contains(reason, "chain") {
			t.Fatalf("resync reason %q", reason)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a delta with a broken chain must be rejected")
	}
	<-fake.hellos
	if h := <-fake.hellos; h.epoch != 0 {
		t.Fatalf("after a rejected delta the reader starts from nothing: %+v", h)
	}
	if _, ok := views.Load(uint64(1)); ok {
		t.Fatal("the forged change must never be served")
	}
}

func TestConsumer_RejectsGapsReplaysAndDeltasBeforeASnapshot(t *testing.T) {
	blob := blobOf(t, 1, rr(t, "a.example.lan", "10.0.0.1"))
	tb, _, _ := dnsanswer.DecodeTable(blob)
	ch := []dnsanswer.Change{{Owner: "x.example.lan", RRs: []dnsanswer.RR{rr(t, "x.example.lan", "10.0.0.7")}}}
	seed := chainSeed(1, tb.Digest())
	gap, _, _ := encodeDelta(1, 2, 2, ch, seed)
	wrongEpoch, _, _ := encodeDelta(7, 1, 2, ch, seed)
	for name, script := range map[string]func(c net.Conn){
		"gap": func(c net.Conn) {
			_, _ = c.Write(fakeSnapshot(t, 1, blob))
			_, _ = c.Write(appendFrame(nil, msgDelta, gap))
		},
		"wrong epoch": func(c net.Conn) {
			_, _ = c.Write(fakeSnapshot(t, 1, blob))
			_, _ = c.Write(appendFrame(nil, msgDelta, wrongEpoch))
		},
		"before snapshot":  func(c net.Conn) { _, _ = c.Write(appendFrame(nil, msgDelta, gap)) },
		"damaged snapshot": func(c net.Conn) { _, _ = c.Write(fakeSnapshot(t, 1, blob[:len(blob)-9])) },
		"short snapshot":   func(c net.Conn) { _, _ = c.Write(appendFrame(nil, msgSnapshot, []byte{1, 2})) },
		"garbage delta": func(c net.Conn) {
			_, _ = c.Write(fakeSnapshot(t, 1, blob))
			_, _ = c.Write(appendFrame(nil, msgDelta, make([]byte, 80)))
		},
	} {
		fake := startFake(t, func(c net.Conn, n int) { script(c) })
		cons := NewConsumer(ConsumerOptions{
			Dial:       func(ctx context.Context) (net.Conn, error) { return net.Dial("unix", fake.path) },
			MinBackoff: 5 * time.Millisecond, MaxBackoff: 10 * time.Millisecond,
		})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); _ = cons.Run(ctx) }()
		select {
		case <-fake.resync:
		case <-time.After(5 * time.Second):
			t.Errorf("%s: accepted", name)
		}
		cancel()
		<-done
	}
}

func TestConsumer_ARunWithNothingToConnectToStopsOnCancel(t *testing.T) {
	before := runtime.NumGoroutine()
	cons := NewConsumer(ConsumerOptions{Dial: func(ctx context.Context) (net.Conn, error) { return nil, fmt.Errorf("no publisher") }, MinBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = cons.Run(ctx) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	<-done
	if s := cons.Status(); s.Connected || s.Reconnects == 0 || !strings.Contains(s.LastError, "no publisher") {
		t.Fatalf("status %+v", s)
	}
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if runtime.NumGoroutine() > before {
		t.Fatalf("goroutines left behind: %d before, %d after", before, runtime.NumGoroutine())
	}
}

func TestDelta_RoundTripAndLimits(t *testing.T) {
	seed := chainSeed(3, [32]byte{1})
	ch := []dnsanswer.Change{
		{Owner: "a.example.lan", RRs: []dnsanswer.RR{rr(t, "a.example.lan", "10.0.0.1"), {Owner: "a.example.lan", Type: dnsanswer.TypeTXT, TTL: 5, RData: []byte{3, 'a', 'b', 'c'}}}},
		{Owner: "gone.example.lan", Delete: true},
		{Owner: "empty.example.lan"},
	}
	p, chain, err := encodeDelta(3, 9, 77, ch, seed)
	if err != nil {
		t.Fatal(err)
	}
	d, err := decodeDelta(p)
	if err != nil || d.epoch != 3 || d.seq != 9 || d.serial != 77 || d.chain != chain || len(d.changes) != 3 || chainNext(seed, d.body) != chain {
		t.Fatalf("decoded %+v %v", d, err)
	}
	if len(d.changes[0].RRs) != 2 || !d.changes[1].Delete || !d.changes[2].Delete {
		t.Fatalf("changes %+v", d.changes)
	}
	if _, _, err := encodeDelta(1, 1, 1, nil, seed); err == nil {
		t.Fatal("an empty step is refused")
	}
	if _, _, err := encodeDelta(1, 1, 1, []dnsanswer.Change{{Owner: strings.Repeat("a", 256), Delete: true}}, seed); err == nil {
		t.Fatal("an owner over 255 bytes is refused")
	}
	if _, _, err := encodeDelta(1, 1, 1, []dnsanswer.Change{{Owner: "a.lan", RRs: []dnsanswer.RR{{Owner: "other.lan", Type: 1, RData: []byte{1, 2, 3, 4}}}}}, seed); err == nil {
		t.Fatal("a record of another owner is refused")
	}
}

func FuzzDecodeDelta(f *testing.F) {
	seed := chainSeed(1, [32]byte{})
	good, _, _ := encodeDelta(1, 1, 1, []dnsanswer.Change{{Owner: "a.example.lan", RRs: []dnsanswer.RR{{Owner: "a.example.lan", Type: 1, TTL: 1, RData: []byte{1, 2, 3, 4}}}}, {Owner: "b.example.lan", Delete: true}}, seed)
	f.Add(good)
	f.Add([]byte{})
	f.Add(make([]byte, 80))
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := decodeDelta(b)
		if err == nil && len(d.changes) == 0 {
			t.Fatal("a delta without changes decoded")
		}
	})
}

func FuzzReadFrame(f *testing.F) {
	f.Add(appendFrame(nil, msgPing))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, body, err := readFrame(bufio.NewReader(strings.NewReader(string(b))), 1<<20)
		if err == nil && len(body) > 1<<20 {
			t.Fatal("frame over the limit")
		}
	})
}

func TestPublisher_AskForANewBaseWhenTooManyNamesChanged(t *testing.T) {
	p := NewPublisher(Options{MaxRingOwners: 3})
	if err := p.SetBase(blobOf(t, 1)); err != nil {
		t.Fatal(err)
	}
	change := func(names ...string) []dnsanswer.Change {
		var c []dnsanswer.Change
		for _, n := range names {
			c = append(c, dnsanswer.Change{Owner: n + ".example.lan", RRs: []dnsanswer.RR{rr(t, n+".example.lan", "10.0.0.1")}})
		}
		return c
	}
	if _, err := p.Publish(2, change("a", "b")); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Publish(3, change("a", "b", "c")); err != nil {
		t.Fatalf("changing known names again does not count twice: %v", err)
	}
	if _, err := p.Publish(4, change("d")); err != ErrBaseNeeded {
		t.Fatalf("a fourth name asks for a new base: %v", err)
	}
	if st := p.Status(); st.Seq != 2 {
		t.Fatalf("the refused change was not published: %+v", st)
	}
	if err := p.SetBase(blobOf(t, 5)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Publish(6, change("d")); err != nil {
		t.Fatalf("a new base starts counting again: %v", err)
	}
}
