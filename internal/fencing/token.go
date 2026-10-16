// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package fencing implements the cluster authority watermark.
package fencing

import "fmt"

// Token is a monotonic cluster-authority stamp: (Epoch, Generation).
type Token struct {
	Epoch      uint64 `json:"epoch"`
	Generation uint64 `json:"generation"`
}

// Compare returns -1 if t < other, 0 if equal, +1 if t > other.
func (t Token) Compare(other Token) int {
	switch {
	case t.Epoch < other.Epoch:
		return -1
	case t.Epoch > other.Epoch:
		return 1
	case t.Generation < other.Generation:
		return -1
	case t.Generation > other.Generation:
		return 1
	default:
		return 0
	}
}

// Less reports whether t is strictly below other.
func (t Token) Less(other Token) bool { return t.Compare(other) < 0 }

// AtLeast reports whether t is >= other (i.e. not fenced out by other).
func (t Token) AtLeast(other Token) bool { return t.Compare(other) >= 0 }

// String renders the token as "epoch.generation".
func (t Token) String() string {
	return fmt.Sprintf("%d.%d", t.Epoch, t.Generation)
}
