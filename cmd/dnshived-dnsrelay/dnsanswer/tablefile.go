// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsanswer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
)

const (
	tableMagic   = "DHTB"
	tableVersion = 1
	tableHeader  = 4 + 2 + 2 + 4 + 32 + 8
)

var (
	tableCRC = crc32.MakeTable(crc32.Castagnoli)
	ErrTable = errors.New("dnsanswer: invalid table file")
)

// EncodeTable renders the published table file: header, digest of the compiled table, the spec, a checksum.
func EncodeTable(spec *Spec, digest [32]byte) []byte {
	body := spec.Encode()
	out := make([]byte, 0, tableHeader+len(body)+4)
	out = append(out, tableMagic...)
	out = binary.LittleEndian.AppendUint16(out, tableVersion)
	out = binary.LittleEndian.AppendUint16(out, 0)
	out = binary.LittleEndian.AppendUint32(out, spec.Serial)
	out = append(out, digest[:]...)
	out = binary.LittleEndian.AppendUint64(out, uint64(len(body)))
	out = append(out, body...)
	return binary.LittleEndian.AppendUint32(out, crc32.Checksum(out, tableCRC))
}

// DecodeTable parses a table file and rebuilds the table; the digest in the file must equal the rebuilt one.
func DecodeTable(b []byte) (*Table, *Spec, error) {
	if len(b) < tableHeader+4 || string(b[:4]) != tableMagic {
		return nil, nil, fmt.Errorf("%w: header", ErrTable)
	}
	if binary.LittleEndian.Uint16(b[4:]) != tableVersion {
		return nil, nil, fmt.Errorf("%w: version %d", ErrTable, binary.LittleEndian.Uint16(b[4:]))
	}
	if crc32.Checksum(b[:len(b)-4], tableCRC) != binary.LittleEndian.Uint32(b[len(b)-4:]) {
		return nil, nil, fmt.Errorf("%w: checksum", ErrTable)
	}
	n := binary.LittleEndian.Uint64(b[tableHeader-8:])
	if n != uint64(len(b)-tableHeader-4) {
		return nil, nil, fmt.Errorf("%w: length", ErrTable)
	}
	spec, err := DecodeSpec(b[tableHeader : len(b)-4])
	if err != nil {
		return nil, nil, err
	}
	t, err := spec.Build()
	if err != nil {
		return nil, nil, err
	}
	var want [32]byte
	copy(want[:], b[12:44])
	if t.Digest() != want {
		return nil, nil, fmt.Errorf("%w: digest differs from the rebuilt table", ErrTable)
	}
	return t, spec, nil
}
