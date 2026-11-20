// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// MinSplitVersion is the first release that reads the split storage format.
// A cluster whose configuration is stored split reports every node below it.
const MinSplitVersion = "0.9.8.10"

// Storage formats of the live configuration on one node.
const (
	StorageNone   = "none"
	StorageSingle = "single"
	StorageSplit  = "split"
)

const preSplitSuffix = ".pre-split"

func manifestPath(path string) string { return filepath.Join(SplitDir(path), manifestFileName) }

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// Exists reports whether a configuration is stored at path, as one file or
// as a split directory.
func Exists(path string) bool { return fileExists(path) || fileExists(manifestPath(path)) }

// splitActive: the split directory is authoritative only while the single file
// is absent. A single file that appears next to a split directory (an adopt or
// a setup write) is newer and wins until the next start migrates it again.
func splitActive(path string) bool { return !fileExists(path) && fileExists(manifestPath(path)) }

// StorageFormat names how the configuration at path is stored.
func StorageFormat(path string) string {
	switch {
	case fileExists(path):
		return StorageSingle
	case fileExists(manifestPath(path)):
		return StorageSplit
	}
	return StorageNone
}

// StampPath is the file whose change marks a new version of the configuration
// at path: the single file, or the manifest of the split directory (it is
// rewritten by every save that changes a part).
func StampPath(path string) string {
	if splitActive(path) {
		return manifestPath(path)
	}
	return path
}

// loadSplitRetry reads the split directory again when a concurrent save left
// a part and the manifest out of step; every part is checked against the
// manifest, so a mix is detected and never used.
func loadSplitRetry(dir string) (*Cluster, error) {
	var err error
	for i := 0; i < 4; i++ {
		var c *Cluster
		if c, err = LoadSplit(dir); err == nil {
			return c, nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return nil, err
}

func copyFileExcl(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	return out.Close()
}

func canonical(c *Cluster) ([]byte, error) { return json.Marshal(c) }

// MigrateToSplit moves the configuration at path from one file to the split
// directory. It keeps a one-time copy of the file as path.pre-split, writes and
// verifies the directory (the assembled configuration must equal the original
// byte for byte in its canonical form), and only then removes the single file.
// A crash before that last step leaves both, and the single file wins. It
// reports whether anything was migrated.
func MigrateToSplit(path string) (bool, error) {
	if !fileExists(path) {
		return false, nil
	}
	c, err := Load(path)
	if err != nil {
		return false, err
	}
	want, err := canonical(c)
	if err != nil {
		return false, err
	}
	if err := copyFileExcl(path, path+preSplitSuffix); err != nil && !errors.Is(err, fs.ErrExist) {
		return false, fmt.Errorf("keep a copy of the single file: %w", err)
	}
	dir := SplitDir(path)
	if err := SaveSplit(dir, c); err != nil {
		return false, fmt.Errorf("write the split configuration: %w", err)
	}
	back, err := LoadSplit(dir)
	if err == nil {
		var got []byte
		if got, err = canonical(back); err == nil && !bytes.Equal(got, want) {
			err = errors.New("the split configuration does not reproduce the document")
		}
	}
	if err != nil {
		os.RemoveAll(dir)
		return false, fmt.Errorf("verify the split configuration: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return false, fmt.Errorf("remove the single file: %w", err)
	}
	return true, nil
}

// MigrateToSingle is the way back: it writes the single file from the split
// directory and removes the directory.
func MigrateToSingle(path string) (bool, error) {
	if !splitActive(path) {
		return false, nil
	}
	c, err := loadSplitRetry(SplitDir(path))
	if err != nil {
		return false, err
	}
	if err := saveSingle(path, c); err != nil {
		return false, err
	}
	if err := os.RemoveAll(SplitDir(path)); err != nil {
		return false, fmt.Errorf("remove the split directory: %w", err)
	}
	return true, nil
}

// Document returns the configuration at path as the JSON document a single
// file would hold, whatever the storage format.
func Document(path string) ([]byte, error) {
	c, err := Load(path)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(c, "", "  ")
}
