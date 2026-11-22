// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsfeed

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"dnsrelay/dnsanswer"
)

// Info describes the table handed to ConsumerOptions.OnTable.
type Info struct {
	Epoch, Seq uint64
	Serial     uint32
	At         time.Time
}

// ConsumerOptions configure a Consumer.
type ConsumerOptions struct {
	// Dial opens a connection to the publisher.
	Dial func(ctx context.Context) (net.Conn, error)
	// OnTable receives every new view of the table; it must not keep the previous one in use after it returns.
	OnTable func(t *dnsanswer.Table, info Info)
	// ChangeLimit asks the publisher for a new base when this many names changed (0 = never).
	ChangeLimit int
	// IdleTimeout drops a connection that stayed silent (default 20 s; the publisher pings every 5 s).
	IdleTimeout time.Duration
	// MinBackoff and MaxBackoff bound the wait before a reconnect (defaults 100 ms and 5 s).
	MinBackoff, MaxBackoff time.Duration
	Log                    func(format string, args ...any)
}

// ConsumerStatus is a snapshot of the consumer for status pages.
type ConsumerStatus struct {
	Connected  bool
	Epoch, Seq uint64
	Names      int
	LastUpdate time.Time
	LastError  string
	Reconnects uint64
}

// Consumer keeps a table up to date from a Publisher and hands every new view to OnTable.
type Consumer struct {
	o  ConsumerOptions
	f  follower
	mu sync.Mutex
	st ConsumerStatus
}

func NewConsumer(o ConsumerOptions) *Consumer {
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = 20 * time.Second
	}
	if o.MinBackoff <= 0 {
		o.MinBackoff = 100 * time.Millisecond
	}
	if o.MaxBackoff <= 0 {
		o.MaxBackoff = 5 * time.Second
	}
	if o.Log == nil {
		o.Log = func(string, ...any) {}
	}
	return &Consumer{o: o}
}

func (c *Consumer) Status() ConsumerStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st
}

func (c *Consumer) update(f func(*ConsumerStatus)) {
	c.mu.Lock()
	f(&c.st)
	c.mu.Unlock()
}

// Run connects, follows the feed and reconnects with a growing pause until ctx ends.
func (c *Consumer) Run(ctx context.Context) error {
	backoff := c.o.MinBackoff
	for ctx.Err() == nil {
		start := time.Now()
		err := c.session(ctx)
		c.update(func(s *ConsumerStatus) {
			s.Connected = false
			s.Reconnects++
			if err != nil && ctx.Err() == nil {
				s.LastError = err.Error()
			}
		})
		if ctx.Err() != nil {
			break
		}
		c.o.Log("[DNSFEED] feed connection ended: %v", err)
		if time.Since(start) > c.o.MaxBackoff {
			backoff = c.o.MinBackoff
		}
		wait := backoff/2 + time.Duration(rand.Int63n(int64(backoff)))
		select {
		case <-time.After(wait):
		case <-ctx.Done():
		}
		backoff = min(backoff*2, c.o.MaxBackoff)
	}
	return nil
}

type follower struct {
	epoch, seq uint64
	chain      [chainSize]byte
	live       *dnsanswer.Live
}

func (c *Consumer) session(ctx context.Context) error {
	conn, err := c.o.Dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	h := hello{}
	if c.f.live != nil {
		h = hello{epoch: c.f.epoch, seq: c.f.seq}
	}
	if _, err := conn.Write(appendFrame(nil, msgHello, encodeHello(h))); err != nil {
		return err
	}
	c.update(func(s *ConsumerStatus) { s.Connected = true })
	br := bufio.NewReaderSize(conn, 1<<16)
	f := &c.f
	resync := func(reason string) error {
		_, _ = conn.Write(appendFrame(nil, msgResync, []byte(reason)))
		c.f = follower{}
		return fmt.Errorf("%s", reason)
	}
	for {
		_ = conn.SetReadDeadline(time.Now().Add(c.o.IdleTimeout))
		typ, body, err := readFrame(br, maxFrame)
		if err != nil {
			return err
		}
		switch typ {
		case msgPing:
			continue
		case msgSnapshot:
			if len(body) < 8 {
				return resync("short snapshot")
			}
			t, spec, err := dnsanswer.DecodeTable(body[8:])
			if err != nil {
				return resync("snapshot: " + err.Error())
			}
			*f = follower{epoch: le.Uint64(body), chain: chainSeed(le.Uint64(body), t.Digest()), live: dnsanswer.NewLive(t, spec.Zones, c.o.ChangeLimit)}
			c.deliver(f, t, spec.Serial)
		case msgDelta:
			if f.live == nil {
				return resync("delta before snapshot")
			}
			d, err := decodeDelta(body)
			if err != nil {
				return resync(err.Error())
			}
			if d.epoch != f.epoch || d.seq != f.seq+1 {
				return resync(fmt.Sprintf("out of order: epoch %d seq %d after epoch %d seq %d", d.epoch, d.seq, f.epoch, f.seq))
			}
			next := chainNext(f.chain, d.body)
			if next != d.chain {
				return resync(ErrChain.Error())
			}
			if _, err := f.live.Apply(d.serial, d.changes); err != nil {
				return resync("apply: " + err.Error())
			}
			f.seq, f.chain = d.seq, next
			c.deliver(f, f.live.Table(), d.serial)
			if c.o.ChangeLimit > 0 && f.live.Full() {
				return resync("too many changes since the base")
			}
		default:
			return fmt.Errorf("%w: unexpected message %d", ErrProtocol, typ)
		}
		var ack [16]byte
		le.PutUint64(ack[:], f.epoch)
		le.PutUint64(ack[8:], f.seq)
		if _, err := conn.Write(appendFrame(nil, msgAck, ack[:])); err != nil {
			return err
		}
	}
}

func (c *Consumer) deliver(f *follower, t *dnsanswer.Table, serial uint32) {
	now := time.Now()
	c.update(func(s *ConsumerStatus) {
		s.Epoch, s.Seq, s.Names, s.LastUpdate, s.LastError = f.epoch, f.seq, t.Names(), now, ""
	})
	if c.o.OnTable != nil {
		c.o.OnTable(t, Info{Epoch: f.epoch, Seq: f.seq, Serial: serial, At: now})
	}
}
