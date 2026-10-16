// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package leasesync

import (
	"encoding/json"
	"os"
)

// loadLeasesFile reads path as a JSON array of SyncedLease.
func loadLeasesFile(path string) ([]SyncedLease, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	var leases []SyncedLease
	if err := json.Unmarshal(data, &leases); err != nil {
		return nil, nil
	}
	return leases, nil
}

// saveLeasesFile atomically overwrites path with leases.
func saveLeasesFile(path string, leases []SyncedLease) error {
	data, err := json.Marshal(leases)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, data, 0o640)
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
