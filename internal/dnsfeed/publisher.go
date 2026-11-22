// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsfeed

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"dnshived/internal/dnsanswer"
)

var (
	ErrNoBase     = errors.New("dnsfeed: no base table yet")
	ErrBaseNeeded = errors.New("dnsfeed: too many changes since the base; publish a new base")
)

// Options tune a Publisher; the zero value is usable.
type Options struct {
	// AllowPeer decides from the peer's credentials whether a connection may read the feed; nil allows root and the
	// user the publisher runs as.
	AllowPeer func(uid, gid uint32) bool
	// PingEvery is how often an idle connection is pinged (default 5 s).
	PingEvery time.Duration
	// QueueDepth is how many frames may wait for a slow reader before it is dropped (default 256).
	QueueDepth int
	// MaxRingBytes bounds the changes kept since the base for readers that reconnect (default 64 MiB).
	MaxRingBytes int
	// HelloTimeout is how long a new connection may take to say hello (default 5 s).
	HelloTimeout time.Duration
	// WriteTimeout bounds a single write to a reader (default 10 s).
	WriteTimeout time.Duration
	Log          func(format string, args ...any)
}

func (o *Options) fill() {
	if o.PingEvery <= 0 {
		o.PingEvery = 5 * time.Second
	}
	if o.QueueDepth <= 0 {
		o.QueueDepth = 256
	}
	if o.MaxRingBytes <= 0 {
		o.MaxRingBytes = 64 << 20
	}
	if o.HelloTimeout <= 0 {
		o.HelloTimeout = 5 * time.Second
	}
	if o.WriteTimeout <= 0 {
		o.WriteTimeout = 10 * time.Second
	}
	if o.Log == nil {
		o.Log = func(string, ...any) {}
	}
}

// Status is a snapshot of the publisher for the daemon's status page.
type Status struct {
	Epoch, Seq uint64
	Readers    int
	RingBytes  int
	Dropped    uint64
}

// Publisher serves the current base table and the changes since it to every reader that connects. One writer calls
// SetBase and Publish; any number of readers connect through Serve.
type Publisher struct {
	o Options

	mu        sync.Mutex
	epoch     uint64
	snapshot  []byte
	seq       uint64
	chain     [chainSize]byte
	ring      [][]byte
	ringBytes int
	sessions  map[*session]struct{}
	dropped   uint64
}

func NewPublisher(o Options) *Publisher {
	o.fill()
	return &Publisher{o: o, sessions: map[*session]struct{}{}}
}

// SetBase makes blob (a table file as dnsanswer.EncodeTable writes it) the new base. Every reader receives it as a
// full table and the changes since the old base are forgotten.
func (p *Publisher) SetBase(blob []byte) error {
	if len(blob) > maxFrame-16 {
		return fmt.Errorf("dnsfeed: table of %d bytes is over the frame limit", len(blob))
	}
	t, _, err := dnsanswer.DecodeTable(blob)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.epoch++
	p.seq = 0
	p.chain = chainSeed(p.epoch, t.Digest())
	p.snapshot = appendFrame(nil, msgSnapshot, le.AppendUint64(nil, p.epoch), blob)
	p.ring, p.ringBytes = nil, 0
	for s := range p.sessions {
		s.send(p, p.snapshot)
	}
	return nil
}

// Publish sends changes on top of the current base and returns their sequence number. It refuses with ErrBaseNeeded
// when too many changes have piled up; the caller then builds a new base and calls SetBase.
func (p *Publisher) Publish(serial uint32, changes []dnsanswer.Change) (uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.snapshot == nil {
		return 0, ErrNoBase
	}
	payload, chain, err := encodeDelta(p.epoch, p.seq+1, serial, changes, p.chain)
	if err != nil {
		return 0, err
	}
	frame := appendFrame(nil, msgDelta, payload)
	if p.ringBytes+len(frame) > p.o.MaxRingBytes {
		return 0, ErrBaseNeeded
	}
	p.seq++
	p.chain = chain
	p.ring = append(p.ring, frame)
	p.ringBytes += len(frame)
	for s := range p.sessions {
		s.send(p, frame)
	}
	return p.seq, nil
}

func (p *Publisher) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	return Status{Epoch: p.epoch, Seq: p.seq, Readers: len(p.sessions), RingBytes: p.ringBytes, Dropped: p.dropped}
}

type session struct {
	conn    net.Conn
	out     chan []byte
	initial [][]byte
	once    sync.Once
	done    chan struct{}
}

func (s *session) close() { s.once.Do(func() { close(s.done); _ = s.conn.Close() }) }

// send queues a frame without blocking; a reader that cannot keep up is dropped and reconnects.
func (s *session) send(p *Publisher, frame []byte) {
	select {
	case s.out <- frame:
	default:
		p.dropped++
		delete(p.sessions, s)
		go s.close()
	}
}

// Serve accepts readers on ln until ctx ends or ln fails, then closes every connection.
func (p *Publisher) Serve(ctx context.Context, ln net.Listener) error {
	var wg sync.WaitGroup
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-stop:
		}
		_ = ln.Close()
	}()
	var err error
	for {
		var c net.Conn
		if c, err = ln.Accept(); err != nil {
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.handle(ctx, c)
		}()
	}
	close(stop)
	p.mu.Lock()
	for s := range p.sessions {
		go s.close()
	}
	p.mu.Unlock()
	wg.Wait()
	if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (p *Publisher) handle(ctx context.Context, c net.Conn) {
	s := &session{conn: c, out: make(chan []byte, p.o.QueueDepth), done: make(chan struct{})}
	defer s.close()
	if !p.peerAllowed(c) {
		p.o.Log("[DNSFEED] refusing a reader: peer credentials not allowed")
		return
	}
	br := bufio.NewReaderSize(c, 4096)
	_ = c.SetReadDeadline(time.Now().Add(p.o.HelloTimeout))
	typ, body, err := readFrame(br, 256)
	if err != nil || typ != msgHello {
		return
	}
	h, err := decodeHello(body)
	if err != nil {
		p.o.Log("[DNSFEED] refusing a reader: %v", err)
		return
	}
	_ = c.SetReadDeadline(time.Time{})

	p.mu.Lock()
	if p.snapshot == nil {
		p.mu.Unlock()
		return
	}
	if h.epoch == p.epoch && h.seq <= p.seq {
		s.initial = append(s.initial, p.ring[h.seq:]...)
	} else {
		s.initial = append(append(s.initial, p.snapshot), p.ring...)
	}
	p.sessions[s] = struct{}{}
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.sessions, s)
		p.mu.Unlock()
	}()

	go p.write(ctx, s)
	for {
		typ, body, err := readFrame(br, 4096)
		if err != nil {
			return
		}
		switch typ {
		case msgAck, msgPing:
		case msgResync:
			p.o.Log("[DNSFEED] a reader asked for a new table: %s", string(body))
			return
		default:
			return
		}
	}
}

func (p *Publisher) write(ctx context.Context, s *session) {
	defer s.close()
	w := func(f []byte) bool {
		_ = s.conn.SetWriteDeadline(time.Now().Add(p.o.WriteTimeout))
		_, err := s.conn.Write(f)
		return err == nil
	}
	for _, f := range s.initial {
		if !w(f) {
			return
		}
	}
	tick := time.NewTicker(p.o.PingEvery)
	defer tick.Stop()
	ping := appendFrame(nil, msgPing)
	for {
		select {
		case f := <-s.out:
			if !w(f) {
				return
			}
		case <-tick.C:
			if !w(ping) {
				return
			}
		case <-s.done:
			return
		case <-ctx.Done():
			return
		}
	}
}
