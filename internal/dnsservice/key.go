// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsservice

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"

	"dnshived/internal/dnsstore"
)

const keyLen = 32

// LoadOrCreateKey reads the store key file, creating it with a random key on first use. The file is owner-only.
func LoadOrCreateKey(path string) (dnsstore.Keys, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		b = make([]byte, keyLen)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		if _, err := f.Write(b); err != nil {
			_ = f.Close()
			return nil, err
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if len(b) != keyLen {
		return nil, fmt.Errorf("dnsservice: key file %s holds %d bytes, want %d", path, len(b), keyLen)
	}
	if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("dnsservice: key file %s is readable by others (%v)", path, st.Mode().Perm())
	}
	return dnsstore.StaticKeys{Cur: 1, Epochs: map[uint32][]byte{1: b}}, nil
}
