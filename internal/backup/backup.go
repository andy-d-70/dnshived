// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package backup implements the actual on-disk mechanics for dnshived's
// automated/manual config backups.
package backup

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"dnshived/internal/backupcrypt"
	"dnshived/internal/config"
	"dnshived/internal/reliability"
)

var filenamePattern = regexp.MustCompile(`^backup-\d{8}-\d{6}\.enc$`)

// ErrInvalidName is returned by Read/Delete for any name that doesn't
// match filenamePattern.
var ErrInvalidName = errors.New("backup: invalid backup filename")

// Info describes one backup file already on disk.
type Info struct {
	Name    string
	Size    int64
	ModTime time.Time
	// Comment is an optional, operator-typed label for a manual backup (e.g.
	// "before DNS relay cutover").
	Comment   string
	Automated bool
}

// Payload is what a backup's own plaintext (pre-compress, pre-encrypt)
// actually marshals.
type Payload struct {
	config.Cluster
	DHCPLeases  *LeaseData       `json:"dhcp_leases,omitempty"`
	Reliability *ReliabilityData `json:"reliability,omitempty"`
}

// ReliabilityData holds one node's own reliability.Store snapshots at
// backup time.
type ReliabilityData struct {
	Local map[string]reliability.Entry `json:"local,omitempty"`
	Path  map[string]reliability.Entry `json:"path,omitempty"`
}

// LeaseData is the dynamic-lease-shadow snapshot embedded in a backup.
type LeaseData struct {
	Leases []LeaseEntry `json:"leases,omitempty"`
}

// LeaseEntry mirrors internal/leasesync.SyncedLease's own JSON shape
// field-for-field.
type LeaseEntry struct {
	MAC       string `json:"mac"`
	IP        string `json:"ip"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
}

// Dir returns the directory this package reads/writes backups in, given
// the daemon's own configured dataDir.
func Dir(dataDir string) string {
	return filepath.Join(dataDir, "backups")
}

// commentPath returns the sidecar file a backup's optional comment is
// stored in.
func commentPath(dataDir, name string) string {
	return filepath.Join(Dir(dataDir), name+".comment")
}

// readComment returns name's comment, or "" if it has none — a missing
// sidecar file is the normal case (most backups have no comment), not an
// error.
func readComment(dataDir, name string) string {
	b, err := os.ReadFile(commentPath(dataDir, name))
	if err != nil {
		return ""
	}
	return string(b)
}

// ReadComment is readComment's exported form.
func ReadComment(dataDir, name string) string {
	if !filenamePattern.MatchString(name) {
		return ""
	}
	return readComment(dataDir, name)
}

// writeComment stores comment as name's sidecar file.
func writeComment(dataDir, name, comment string) error {
	if comment == "" {
		return nil
	}
	return os.WriteFile(commentPath(dataDir, name), []byte(comment), 0o640)
}

// automatedMarkerPath returns the sidecar file whose mere PRESENCE marks a
// backup as automated.
func automatedMarkerPath(dataDir, name string) string {
	return filepath.Join(Dir(dataDir), name+".auto")
}

// readAutomated reports whether name's automated marker sidecar exists —
// a missing file is the normal case for a manual backup, not an error.
func readAutomated(dataDir, name string) bool {
	_, err := os.Stat(automatedMarkerPath(dataDir, name))
	return err == nil
}

// IsAutomated is readAutomated's exported form.
func IsAutomated(dataDir, name string) bool {
	if !filenamePattern.MatchString(name) {
		return false
	}
	return readAutomated(dataDir, name)
}

// writeAutomatedMarker creates name's automated-marker sidecar file.
func writeAutomatedMarker(dataDir, name string) error {
	return os.WriteFile(automatedMarkerPath(dataDir, name), []byte{}, 0o640)
}

// List returns every backup currently on disk, newest first.
func List(dataDir string) ([]Info, error) {
	dir := Dir(dataDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []Info{}, nil
		}
		return nil, fmt.Errorf("backup: read dir: %w", err)
	}
	out := make([]Info, 0)
	for _, e := range entries {
		if e.IsDir() || !filenamePattern.MatchString(e.Name()) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, Info{Name: e.Name(), Size: fi.Size(), ModTime: fi.ModTime(), Comment: readComment(dataDir, e.Name()), Automated: readAutomated(dataDir, e.Name())})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ModTime.After(out[j].ModTime) })
	return out, nil
}

// compressPlaintext gzip-compresses data — Create's own step before
// handing off to internal/backupcrypt.Encrypt.
func compressPlaintext(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decompress reverses compressPlaintext.
func Decompress(data []byte) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("backup: gzip reader: %w", err)
	}
	defer gr.Close()
	out, err := io.ReadAll(gr)
	if err != nil {
		return nil, fmt.Errorf("backup: gunzip: %w", err)
	}
	return out, nil
}

func Create(dataDir, password string, plaintext []byte, comment string, automated bool) (Info, error) {
	dir := Dir(dataDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return Info{}, fmt.Errorf("backup: mkdir: %w", err)
	}
	compressed, err := compressPlaintext(plaintext)
	if err != nil {
		return Info{}, fmt.Errorf("backup: compress: %w", err)
	}
	blob, err := backupcrypt.Encrypt(password, compressed)
	if err != nil {
		return Info{}, fmt.Errorf("backup: encrypt: %w", err)
	}
	name := fmt.Sprintf("backup-%s.enc", time.Now().UTC().Format("20060102-150405"))
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, blob, 0o640); err != nil {
		return Info{}, fmt.Errorf("backup: write: %w", err)
	}
	if err := writeComment(dataDir, name, comment); err != nil {
		return Info{}, fmt.Errorf("backup: write comment: %w", err)
	}
	if automated {
		if err := writeAutomatedMarker(dataDir, name); err != nil {
			return Info{}, fmt.Errorf("backup: write automated marker: %w", err)
		}
	}
	fi, err := os.Stat(path)
	if err != nil {
		return Info{}, fmt.Errorf("backup: stat: %w", err)
	}
	return Info{Name: name, Size: fi.Size(), ModTime: fi.ModTime(), Comment: comment, Automated: automated}, nil
}

// Import writes raw bytes verbatim under name.
func Import(dataDir, name string, data []byte, comment string, automated bool) (Info, error) {
	if !filenamePattern.MatchString(name) {
		return Info{}, ErrInvalidName
	}
	dir := Dir(dataDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return Info{}, fmt.Errorf("backup: mkdir: %w", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o640); err != nil {
		return Info{}, fmt.Errorf("backup: write: %w", err)
	}
	if err := writeComment(dataDir, name, comment); err != nil {
		return Info{}, fmt.Errorf("backup: write comment: %w", err)
	}
	if automated {
		if err := writeAutomatedMarker(dataDir, name); err != nil {
			return Info{}, fmt.Errorf("backup: write automated marker: %w", err)
		}
	}
	fi, err := os.Stat(path)
	if err != nil {
		return Info{}, fmt.Errorf("backup: stat: %w", err)
	}
	return Info{Name: name, Size: fi.Size(), ModTime: fi.ModTime(), Comment: comment, Automated: automated}, nil
}

// Read returns the raw encrypted bytes of one backup by name.
func Read(dataDir, name string) ([]byte, error) {
	if !filenamePattern.MatchString(name) {
		return nil, ErrInvalidName
	}
	data, err := os.ReadFile(filepath.Join(Dir(dataDir), name))
	if err != nil {
		return nil, fmt.Errorf("backup: read: %w", err)
	}
	return data, nil
}

func Delete(dataDir, name string) error {
	if !filenamePattern.MatchString(name) {
		return ErrInvalidName
	}
	if err := os.Remove(filepath.Join(Dir(dataDir), name)); err != nil {
		return fmt.Errorf("backup: delete: %w", err)
	}
	os.Remove(commentPath(dataDir, name))
	os.Remove(automatedMarkerPath(dataDir, name))
	return nil
}

// Prune keeps the retain newest AUTOMATED backups and deletes the rest.
func Prune(dataDir string, retain int) error {
	if retain <= 0 {
		return nil
	}
	all, err := List(dataDir)
	if err != nil {
		return err
	}
	automated := make([]Info, 0, len(all))
	for _, info := range all {
		if info.Automated {
			automated = append(automated, info)
		}
	}
	if len(automated) <= retain {
		return nil
	}
	var firstErr error
	for _, info := range automated[retain:] {
		if err := Delete(dataDir, info.Name); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
