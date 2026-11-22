// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"dnsrelay/dnsanswer"
	"dnsrelay/dnsfeed"
)

const maxFeedPath = 100

var feedState struct {
	mu     sync.Mutex
	path   string
	cancel context.CancelFunc
	done   chan struct{}
	active atomic.Bool
}

var feedTablesTotal atomic.Uint64

// feedActive is true once a table has arrived through the feed; the table file is then left alone.
func feedActive() bool { return feedState.active.Load() }

// checkFeedPeer accepts only a publisher that runs as root or as the user the relay runs as.
func checkFeedPeer(c net.Conn) error {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("the feed is not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) { cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return err
	}
	if cerr != nil {
		return cerr
	}
	if cred.Uid != 0 && int(cred.Uid) != os.Geteuid() {
		return fmt.Errorf("the feed socket belongs to user %d, which is neither root nor the relay's user", cred.Uid)
	}
	return nil
}

func dialFeed(path string) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		c, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", path)
		if err != nil {
			return nil, err
		}
		if err := checkFeedPeer(c); err != nil {
			_ = c.Close()
			return nil, err
		}
		return c, nil
	}
}

// setFeedSocket follows the table feed at path; an empty path stops following. The table the feed delivered stays in
// use when the connection drops, and a later reconnect brings it up to date.
func setFeedSocket(parent context.Context, path string) {
	feedState.mu.Lock()
	defer feedState.mu.Unlock()
	if path != "" && (!filepath.IsAbs(path) || len(path) > maxFeedPath) {
		logger.Printf("[ERROR] feed_socket %q is not an absolute path of at most %d bytes; the feed stays off", path, maxFeedPath)
		path = ""
	}
	if path == feedState.path {
		return
	}
	if feedState.cancel != nil {
		feedState.cancel()
		<-feedState.done
		feedState.cancel, feedState.done = nil, nil
	}
	feedState.path = path
	if path == "" {
		if feedState.active.Swap(false) {
			if p := tablePath.Load(); p == nil || *p == "" {
				localTable.Store(nil)
			}
			logger.Printf("[INFO] table feed stopped")
		}
		return
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	feedState.cancel, feedState.done = cancel, done
	var lastEpoch uint64
	c := dnsfeed.NewConsumer(dnsfeed.ConsumerOptions{
		Dial: dialFeed(path),
		OnTable: func(t *dnsanswer.Table, i dnsfeed.Info) {
			localTable.Store(t)
			feedState.active.Store(true)
			feedTablesTotal.Add(1)
			if i.Epoch != lastEpoch {
				lastEpoch = i.Epoch
				logger.Printf("[INFO] table from the feed: %d names, %d records, epoch %d", t.Names(), t.Records(), i.Epoch)
			}
		},
		Log: func(f string, a ...any) { logThrottled("feed", f, a...) },
	})
	logger.Printf("[INFO] following the table feed at %s", path)
	go func() {
		defer close(done)
		_ = c.Run(ctx)
	}()
}
