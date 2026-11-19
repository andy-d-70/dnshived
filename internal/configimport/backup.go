// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package configimport

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"

	"dnshived/internal/backupcrypt"
)

const maxBackupPlaintext = 4 * MaxFileBytes

// ErrNeedPassword is returned for a file that is not plain JSON when no password was given.
var ErrNeedPassword = errors.New("this file looks like an encrypted backup: enter its password")

// LooksEncrypted reports whether data is not a plain JSON object, so it can only be a backup.
func LooksEncrypted(data []byte) bool {
	d := bytes.TrimSpace(data)
	return len(d) > 0 && d[0] != '{'
}

// ParseBackup opens an encrypted backup (the files the backup feature writes) and reads its
// configuration. The lease and reliability sections of a backup are not used.
func ParseBackup(blob []byte, password string) (*Source, error) {
	if password == "" {
		return nil, ErrNeedPassword
	}
	compressed, err := backupcrypt.Decrypt(password, blob)
	if err != nil {
		return nil, err
	}
	gr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("the decrypted content is not a backup: %w", err)
	}
	defer gr.Close()
	plain, err := io.ReadAll(io.LimitReader(gr, maxBackupPlaintext+1))
	if err != nil {
		return nil, fmt.Errorf("the decrypted content is not a backup: %w", err)
	}
	if len(plain) > maxBackupPlaintext {
		return nil, errors.New("the decrypted backup is larger than the import accepts")
	}
	return Parse(plain)
}
