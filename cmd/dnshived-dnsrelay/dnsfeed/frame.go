// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package dnsfeed carries the DNS answer table from the daemon to the process that serves it: one full table when a
// reader connects, then the changes made on top of it, each step checked by a sequence number and a hash chain.
package dnsfeed

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	protoMagic   = "DHFD"
	protoVersion = 1
	maxFrame     = 192 << 20
)

type msgType uint8

const (
	msgHello    msgType = 1
	msgSnapshot msgType = 2
	msgDelta    msgType = 3
	msgAck      msgType = 4
	msgResync   msgType = 5
	msgPing     msgType = 6
)

var (
	ErrProtocol = errors.New("dnsfeed: protocol error")
	ErrChain    = errors.New("dnsfeed: hash chain mismatch")
	le          = binary.LittleEndian
)

func appendFrame(dst []byte, typ msgType, parts ...[]byte) []byte {
	n := 1
	for _, p := range parts {
		n += len(p)
	}
	dst = le.AppendUint32(dst, uint32(n))
	dst = append(dst, byte(typ))
	for _, p := range parts {
		dst = append(dst, p...)
	}
	return dst
}

func readFrame(r *bufio.Reader, limit int) (msgType, []byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	n := int(le.Uint32(h[:]))
	if n < 1 || n > limit {
		return 0, nil, fmt.Errorf("%w: frame of %d bytes", ErrProtocol, n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, nil, fmt.Errorf("%w: truncated frame: %v", ErrProtocol, err)
	}
	return msgType(b[0]), b[1:], nil
}

type hello struct {
	epoch, seq uint64
}

func encodeHello(h hello) []byte {
	b := append([]byte(protoMagic), 0, 0)
	le.PutUint16(b[4:], protoVersion)
	b = le.AppendUint64(b, h.epoch)
	return le.AppendUint64(b, h.seq)
}

func decodeHello(b []byte) (hello, error) {
	if len(b) != 4+2+16 || string(b[:4]) != protoMagic {
		return hello{}, fmt.Errorf("%w: hello", ErrProtocol)
	}
	if v := le.Uint16(b[4:]); v != protoVersion {
		return hello{}, fmt.Errorf("%w: version %d", ErrProtocol, v)
	}
	return hello{epoch: le.Uint64(b[6:]), seq: le.Uint64(b[14:])}, nil
}
