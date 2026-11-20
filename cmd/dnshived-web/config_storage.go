// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"slices"
	"strings"

	"dnshived/internal/config"
)

// configStorageWarning names the core nodes that are too old for the split
// configuration storage once any node in the cluster uses it. An older daemon
// reports no config_formats at all, which is how it is recognised.
func configStorageWarning(rows []statusRow) string {
	split := false
	for _, r := range rows {
		if r.FetchError == "" && r.Status.ConfigStorage == config.StorageSplit {
			split = true
		}
	}
	if !split {
		return ""
	}
	var old []string
	for _, r := range rows {
		if r.FetchError != "" || !isCoreRole(r.Status.Role) || slices.Contains(r.Status.ConfigFormats, config.StorageSplit) {
			continue
		}
		v := r.Status.Version
		if v == "" {
			v = "unknown version"
		}
		old = append(old, fmt.Sprintf("%s (%s)", r.Status.Role, v))
	}
	if len(old) == 0 {
		return ""
	}
	slices.Sort(old)
	return fmt.Sprintf("CONFIG STORAGE: %s runs a version older than %s. This cluster keeps its configuration in split form; from version %s on, the minimum version for all nodes is %s", strings.Join(old, ", "), config.MinSplitVersion, config.MinSplitVersion, config.MinSplitVersion)
}
