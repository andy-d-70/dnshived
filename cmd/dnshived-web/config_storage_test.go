// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"strings"
	"testing"
)

func storageRow(role, version, storage string, formats ...string) statusRow {
	return statusRow{Status: nodeStatus{Role: role, Version: version, ConfigStorage: storage, ConfigFormats: formats}}
}

func TestConfigStorageWarning(t *testing.T) {
	both := []string{"single", "split"}
	tests := []struct {
		name string
		rows []statusRow
		want string
	}{
		{"nobody uses split", []statusRow{storageRow("core-1", "0.9.8.9", "single"), storageRow("core-2", "0.9.8.10", "single", both...)}, ""},
		{"all split", []statusRow{storageRow("core-1", "0.9.8.10", "split", both...), storageRow("core-2", "0.9.8.10", "split", both...)}, ""},
		{"one old node", []statusRow{storageRow("core-1", "0.9.8.10", "split", both...), storageRow("core-2", "0.9.8.9", "")}, "core-2 (0.9.8.9)"},
		{"two old nodes sorted", []statusRow{storageRow("core-3", "0.9.8.8", ""), storageRow("core-1", "0.9.8.10", "split", both...), storageRow("core-2", "0.9.8.9", "")}, "core-2 (0.9.8.9), core-3 (0.9.8.8)"},
		{"an unreachable node is not blamed", []statusRow{storageRow("core-1", "0.9.8.10", "split", both...), {FetchError: "down", Status: nodeStatus{Role: "core-2"}}}, ""},
		{"a probe host is not a core", []statusRow{storageRow("core-1", "0.9.8.10", "split", both...), storageRow("probe", "0.9.8.9", "")}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := configStorageWarning(tt.rows)
			if tt.want == "" {
				if got != "" {
					t.Fatalf("unexpected warning %q", got)
				}
				return
			}
			if !strings.HasPrefix(got, "CONFIG STORAGE: "+tt.want) || !strings.Contains(got, "minimum version for all nodes is 0.9.8.10") {
				t.Fatalf("warning = %q", got)
			}
		})
	}
}

func TestConfigStorageWarning_HasATooltip(t *testing.T) {
	if coherenceWarningTitle("CONFIG STORAGE: x") == "" {
		t.Error("the warning needs an explanation tooltip")
	}
}
