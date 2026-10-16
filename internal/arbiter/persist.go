// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package arbiter

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"
)

// tokensPath is where the arbiter persists its grant map across restarts.
func tokensPath(dataDir string) string {
	return filepath.Join(dataDir, "arbiter-tokens.json")
}

// loadTokens reads the persisted grant map.
func loadTokens(dataDir string) map[string]*Token {
	data, err := os.ReadFile(tokensPath(dataDir))
	if err != nil {
		return make(map[string]*Token)
	}
	var loaded map[string]*Token
	if err := json.Unmarshal(data, &loaded); err != nil {
		log.Printf("[ARBITER:WARN] arbiter-tokens file corrupt, ignoring: %v", err)
		return make(map[string]*Token)
	}
	now := time.Now()
	tokens := make(map[string]*Token, len(loaded))
	for scope, tok := range loaded {
		if tok == nil || now.After(tok.ExpiresAt) {
			continue
		}
		tokens[scope] = tok
	}
	return tokens
}

// saveTokens atomically overwrites the persisted grant map with exactly
// what's passed.
func saveTokens(dataDir string, tokens map[string]*Token) error {
	data, err := json.Marshal(tokens)
	if err != nil {
		return err
	}
	return atomicWriteFile(tokensPath(dataDir), data, 0o640)
}

// atomicWriteFile writes data to path via a temp file + fsync + rename, so
// a crash mid-write can never leave a truncated/corrupt file in path's
// place.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
