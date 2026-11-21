// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package dnsstore is the log-structured store for the cluster's DNS data: a checksummed append-only log,
// atomic snapshots and immutable sharded in-memory state, using only the standard library.
package dnsstore

import (
	"errors"
	"fmt"
)

var (
	ErrCorrupt  = errors.New("dnsstore: corrupt data")
	ErrClosed   = errors.New("dnsstore: closed")
	ErrFailed   = errors.New("dnsstore: failed after an I/O error, reopen to recover")
	ErrVersion  = errors.New("dnsstore: unsupported format version")
	ErrNoStore  = errors.New("dnsstore: no store in this directory")
	ErrStoreID  = errors.New("dnsstore: store id mismatch")
	ErrTooLarge = errors.New("dnsstore: batch or row too large")
	ErrBadBatch = errors.New("dnsstore: invalid batch")
	ErrGap      = errors.New("dnsstore: requested revision is older than the retained log")
	ErrKey      = errors.New("dnsstore: unknown key epoch")

	ErrPermissions = errors.New("dnsstore: unsafe directory permissions")

	ErrCommittedConflict = errors.New("dnsstore: a record conflicts with the committed log")
	ErrCannotTruncate    = errors.New("dnsstore: the log cannot be cut back that far")
	ErrPrevMismatch      = errors.New("dnsstore: the previous record does not match")
	ErrBehind            = errors.New("dnsstore: the log ends before the previous revision")
	ErrBadChain          = errors.New("dnsstore: record chain does not verify")
	ErrStaleTerm         = errors.New("dnsstore: record from an older term")
	ErrBackpressure      = errors.New("dnsstore: too many records are not committed yet")
	ErrNotNewer          = errors.New("dnsstore: the snapshot is not newer than the log")
)

type CorruptError struct {
	File   string
	Offset int64
	Detail string
}

func (e *CorruptError) Error() string {
	return fmt.Sprintf("dnsstore: corrupt data in %s at offset %d: %s", e.File, e.Offset, e.Detail)
}

func (e *CorruptError) Is(target error) bool { return target == ErrCorrupt }

func corrupt(file string, off int64, format string, a ...any) error {
	return &CorruptError{File: file, Offset: off, Detail: fmt.Sprintf(format, a...)}
}
