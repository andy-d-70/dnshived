// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package bootstrap detects whether a node already carries real dnshived
// identity/config.
package bootstrap

import (
	"fmt"
	"os"
	"strings"

	"dnshived/internal/daemonstatus"
)

// Paths is every location DetectExisting checks.
type Paths struct {
	ClusterConfigPath string   // e.g. /etc/dnshived/cluster.json
	ProbeConfigPath   string   // e.g. /etc/dnshived/probe.json
	WebUsersPath      string   // e.g. /etc/dnshived/webui-users.json
	DataDir           string   // e.g. /var/lib/dnshived
	Units             []string // systemd units to check for ActiveState=="active"
}

// Findings is every piece of evidence DetectExisting found that this node
// already has real config/identity, not just the first one.
type Findings struct {
	ClusterConfigPath string   // non-empty: cluster.json exists at this path
	ProbeConfigPath   string   // non-empty: probe.json exists at this path
	WebUsersPath      string   // non-empty: webui-users.json exists at this path
	DataDirEntries    []string // non-empty: filenames found directly under DataDir
	ActiveUnits       []string // non-empty: units from Paths.Units currently ActiveState=="active"
}

// Fresh reports whether no evidence of prior configuration was found —
// the only state in which a bootstrap/adopt flow may safely proceed.
func (f Findings) Fresh() bool {
	return f.ClusterConfigPath == "" &&
		f.ProbeConfigPath == "" &&
		f.WebUsersPath == "" &&
		len(f.DataDirEntries) == 0 &&
		len(f.ActiveUnits) == 0
}

// String renders a human-readable summary of what was found, for a
// bootstrap/adopt caller's refusal message.
func (f Findings) String() string {
	var parts []string
	if f.ClusterConfigPath != "" {
		parts = append(parts, "cluster config at "+f.ClusterConfigPath)
	}
	if f.ProbeConfigPath != "" {
		parts = append(parts, "probe config at "+f.ProbeConfigPath)
	}
	if f.WebUsersPath != "" {
		parts = append(parts, "web-ui users file at "+f.WebUsersPath)
	}
	if len(f.DataDirEntries) > 0 {
		parts = append(parts, fmt.Sprintf("%d file(s) in data_dir (%s)", len(f.DataDirEntries), strings.Join(f.DataDirEntries, ", ")))
	}
	if len(f.ActiveUnits) > 0 {
		parts = append(parts, "active unit(s): "+strings.Join(f.ActiveUnits, ", "))
	}
	if len(parts) == 0 {
		return "no findings"
	}
	return strings.Join(parts, "; ")
}

// DetectExisting inspects the local filesystem and systemd for evidence
// that this node has already been configured.
func DetectExisting(paths Paths) Findings {
	var f Findings

	if fileExists(paths.ClusterConfigPath) {
		f.ClusterConfigPath = paths.ClusterConfigPath
	}
	if fileExists(paths.ProbeConfigPath) {
		f.ProbeConfigPath = paths.ProbeConfigPath
	}
	if fileExists(paths.WebUsersPath) {
		f.WebUsersPath = paths.WebUsersPath
	}
	f.DataDirEntries = dataDirEntries(paths.DataDir)
	f.ActiveUnits = activeUnits(paths.Units)

	return f
}

// fileExists reports whether path is non-empty and names a regular,
// readable-or-not-but-present file.
func fileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// dataDirEntries lists filenames directly under dir.
func dataDirEntries(dir string) []string {
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// activeUnits returns the subset of units whose systemd ActiveState is
// "active" right now.
func activeUnits(units []string) []string {
	if len(units) == 0 {
		return nil
	}
	statuses := daemonstatus.QueryMany(units)
	var active []string
	for _, unit := range units {
		if statuses[unit].ActiveState == "active" {
			active = append(active, unit)
		}
	}
	return active
}
