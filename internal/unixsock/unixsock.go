// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package unixsock is the hardened local Unix-socket server shared by the dnshived helpers and the relay: one request
// per connection, bounded in time, size and concurrency, and an optional uid allowlist.
package unixsock

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Limits bounds one server. AllowUIDs empty means no uid check (the socket mode still decides access).
type Limits struct {
	MaxConns     int
	Deadline     time.Duration
	MaxRequest   int64
	DrainTimeout time.Duration
	AllowUIDs    []uint32
}

// Peer is the calling process, from SO_PEERCRED.
type Peer struct {
	UID uint32
	PID int32
}

func (p Peer) String() string {
	return fmt.Sprintf("uid=%d pid=%d", p.UID, p.PID)
}

// Conn is one accepted connection: reads stop after MaxRequest bytes, and the deadline covers the whole exchange.
type Conn struct {
	net.Conn
	reader io.Reader
}

func (c *Conn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

// Server is a listening socket with its limits.
type Server struct {
	ln       *net.UnixListener
	path     string
	dev, ino uint64
	limits   Limits
	slots    chan struct{}
	active   sync.WaitGroup
}

// Listen binds path with mode set from the start. A stale socket at the path is replaced; any other file is refused.
func Listen(path string, mode os.FileMode, limits Limits) (*Server, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("socket directory: %w", err)
	}
	if err := RemoveStale(path); err != nil {
		return nil, err
	}

	old := syscall.Umask(0o777 &^ int(mode))
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	ln.SetUnlinkOnClose(false)
	if err := os.Chmod(path, mode); err != nil {
		ln.Close()
		return nil, fmt.Errorf("chmod socket %s: %w", path, err)
	}
	st, err := os.Lstat(path)
	if err != nil {
		ln.Close()
		return nil, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		ln.Close()
		return nil, errors.New("socket identity unavailable")
	}
	return &Server{
		ln:     ln,
		path:   path,
		dev:    uint64(sys.Dev),
		ino:    sys.Ino,
		limits: limits,
		slots:  make(chan struct{}, limits.MaxConns),
	}, nil
}

// Serve accepts until Close. Each connection runs handler on its own goroutine; onDeny is told about peers outside
// AllowUIDs (their connection is closed before handler runs). It returns when the listener is closed.
func (s *Server) Serve(handler func(net.Conn), onDeny func(Peer, error)) error {
	for {
		s.slots <- struct{}{}
		conn, err := s.ln.Accept()
		if err != nil {
			<-s.slots
			if strings.Contains(err.Error(), "use of closed") {
				return nil
			}
			continue
		}
		peer, perr := PeerCred(conn)
		if len(s.limits.AllowUIDs) > 0 && !s.allowed(peer, perr) {
			onDeny(peer, perr)
			conn.Close()
			<-s.slots
			continue
		}
		s.active.Add(1)
		go func(c net.Conn) {
			defer s.active.Done()
			defer func() { <-s.slots }()
			defer c.Close()
			c.SetDeadline(time.Now().Add(s.limits.Deadline))
			handler(&Conn{Conn: c, reader: io.LimitReader(c, s.limits.MaxRequest)})
		}(conn)
	}
}

func (s *Server) allowed(peer Peer, err error) bool {
	if err != nil {
		return false
	}
	for _, uid := range s.limits.AllowUIDs {
		if peer.UID == uid {
			return true
		}
	}
	return false
}

// Close stops accepting, waits up to DrainTimeout for running handlers, and removes the socket only if the path still
// holds the socket this server created. It returns how many handlers were still running.
func (s *Server) Close() int {
	s.ln.Close()
	done := make(chan struct{})
	go func() {
		s.active.Wait()
		close(done)
	}()
	left := 0
	select {
	case <-done:
	case <-time.After(s.limits.DrainTimeout):
		left = len(s.slots)
	}
	if st, err := os.Lstat(s.path); err == nil && st.Mode()&os.ModeSocket != 0 {
		if sys, ok := st.Sys().(*syscall.Stat_t); ok && uint64(sys.Dev) == s.dev && sys.Ino == s.ino {
			os.Remove(s.path)
		}
	}
	return left
}

// PeerCred returns the calling process of a Unix connection. It fails for any other connection type.
func PeerCred(conn net.Conn) (Peer, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return Peer{}, errors.New("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return Peer{}, err
	}
	if credErr != nil {
		return Peer{}, credErr
	}
	return Peer{UID: cred.Uid, PID: cred.Pid}, nil
}

// RemoveStale removes a socket at path only when nothing answers on it. A socket that
// still accepts connections belongs to another process and is refused; so is anything that
// is not a socket, or a path whose state cannot be told.
func RemoveStale(path string) error {
	fi, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat socket %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s exists and is not a socket, refusing to remove it", path)
	}
	c, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err == nil {
		c.Close()
		return fmt.Errorf("socket %s is in use by another process", path)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("socket %s: cannot tell whether it is in use: %w", path, err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale socket %s: %w", path, err)
	}
	return nil
}
