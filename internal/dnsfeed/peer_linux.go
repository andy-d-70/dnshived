// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsfeed

import (
	"net"
	"os"
	"syscall"
)

func (p *Publisher) peerAllowed(c net.Conn) bool {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return p.o.AllowPeer != nil && p.o.AllowPeer(^uint32(0), ^uint32(0))
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var cred *syscall.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || cerr != nil {
		return false
	}
	if p.o.AllowPeer != nil {
		return p.o.AllowPeer(cred.Uid, cred.Gid)
	}
	return cred.Uid == 0 || int(cred.Uid) == os.Geteuid()
}
