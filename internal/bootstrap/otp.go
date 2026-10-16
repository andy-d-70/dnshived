// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package bootstrap

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// otpAlphabet excludes visually ambiguous characters (0/O, 1/I).
const otpAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

// otpGroups/otpGroupLen: 4 groups of 4 characters, e.g.
// "AB3F-9K2M-XQ7T-5H1P".
const (
	otpGroups   = 4
	otpGroupLen = 4
)

// GenerateOTP creates a new random bootstrap join code.
func GenerateOTP() (string, error) {
	total := otpGroups * otpGroupLen
	raw := make([]byte, total)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate otp: %w", err)
	}

	out := make([]byte, 0, total+otpGroups-1)
	for i, r := range raw {
		if i > 0 && i%otpGroupLen == 0 {
			out = append(out, '-')
		}
		out = append(out, otpAlphabet[r&0x1F])
	}
	return string(out), nil
}

// LoadOrCreateOTP returns the join code stored at path, creating it if
// missing.
func LoadOrCreateOTP(path string) (string, error) {
	if existing, err := os.ReadFile(path); err == nil {
		return strings.TrimSpace(string(existing)), nil
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("read otp file: %w", err)
	}

	otp, err := GenerateOTP()
	if err != nil {
		return "", err
	}
	tmp, err := writeSyncedTemp(filepath.Dir(path), []byte(otp), 0o640)
	if err != nil {
		return "", fmt.Errorf("persist otp: %w", err)
	}
	defer os.Remove(tmp)
	if err := os.Link(tmp, path); err != nil {
		if os.IsExist(err) {
			existing, rerr := os.ReadFile(path)
			if rerr != nil {
				return "", fmt.Errorf("read otp file: %w", rerr)
			}
			return strings.TrimSpace(string(existing)), nil
		}
		return "", fmt.Errorf("persist otp: %w", err)
	}
	return otp, nil
}

func writeSyncedTemp(dir string, data []byte, perm os.FileMode) (string, error) {
	f, err := os.CreateTemp(dir, ".otp-*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	fail := func(err error) (string, error) {
		f.Close()
		os.Remove(name)
		return "", err
	}
	if err := f.Chmod(perm); err != nil {
		return fail(err)
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}
