// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcprelay

import (
	"context"
	"fmt"
	"net"
	"syscall"
)

// bindClientUDPPort opens a UDP socket on 0.0.0.0:port with SO_BROADCAST
// and SO_REUSEADDR always set, and SO_BINDTODEVICE scoped to iface when
// iface is non-empty.
func bindClientUDPPort(iface string, port int) (*net.UDPConn, error) {
	return bindUDPPort(iface, "0.0.0.0", port)
}

func bindServerFacingUDPPort(iface string, port int) (*net.UDPConn, error) {
	return bindUDPPort(iface, "127.0.0.1", port)
}

// bindReplyUDPPort opens the socket that catches the server's
// giaddr-addressed reply for one client interface.
func bindReplyUDPPort(iface string, giaddr net.IP, port int) (*net.UDPConn, error) {
	return bindUDPPort(iface, giaddr.String(), port)
}

func bindUDPPort(iface, localAddr string, port int) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			cerr := c.Control(func(fd uintptr) {
				if serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET,
					syscall.SO_BROADCAST, 1); serr != nil {
					return
				}
				if serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET,
					syscall.SO_REUSEADDR, 1); serr != nil {
					return
				}
				if iface != "" {
					serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET,
						syscall.SO_BINDTODEVICE, iface)
				}
			})
			if cerr != nil {
				return cerr
			}
			return serr
		},
	}

	pc, err := lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf("%s:%d", localAddr, port))
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}
