// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package leasesync

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"time"

	"dnshived/internal/unixsock"
)

// localDialTimeout/localIOTimeout bound both sides of the local
// hook-to-daemon connection tightly.
const (
	localDialTimeout = 2 * time.Second
	localIOTimeout   = 2 * time.Second
)

// LocalEvent is the local hook-to-daemon wire message.
type LocalEvent struct {
	Action    string `json:"action"`
	MAC       string `json:"mac"`
	IP        string `json:"ip"`
	ExpiresAt int64  `json:"expires_at"`
	// Hostname is dnsmasq's own --dhcp-script positional hostname argument
	// (present only when the client actually sent one).
	Hostname string `json:"hostname,omitempty"`
}

// WriteLocalEvent is cmd/dnshived-dhcp-lease-hook's entire job: connect to
// socketPath (SocketPath in production), send one event, disconnect.
func WriteLocalEvent(socketPath string, ev LocalEvent) error {
	conn, err := net.DialTimeout("unix", socketPath, localDialTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(localIOTimeout))
	return json.NewEncoder(conn).Encode(ev)
}

func ListenLocal(socketPath string, onEvent func(LocalEvent)) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return nil, err
	}
	if err := unixsock.RemoveStale(socketPath); err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	os.Chmod(socketPath, 0o666)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed — normal shutdown path
			}
			go func() {
				defer conn.Close()
				conn.SetReadDeadline(time.Now().Add(localIOTimeout))
				var ev LocalEvent
				if err := json.NewDecoder(conn).Decode(&ev); err != nil {
					return
				}
				onEvent(ev)
			}()
		}
	}()
	return ln, nil
}
