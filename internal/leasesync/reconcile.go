// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package leasesync

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

func Fingerprint(entries []SyncedLease) string {
	sorted := make([]SyncedLease, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].MAC < sorted[j].MAC })
	var b strings.Builder
	for _, l := range sorted {
		fmt.Fprintf(&b, "%s=%s=%d\n", l.MAC, l.IP, l.ExpiresAt)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// Conflict is a real, never-auto-resolved disagreement: the same MAC held
// at two different IPs by two different nodes' own view.
type Conflict struct {
	MAC      string
	LocalIP  string
	RemoteIP string
}

func Diff(local, remote []SyncedLease, now time.Time, grace time.Duration) (conflicts []Conflict, gaps []SyncedLease) {
	localByMAC := make(map[string]SyncedLease, len(local))
	for _, l := range local {
		localByMAC[l.MAC] = l
	}
	cutoff := now.Add(grace).Unix()
	for _, r := range remote {
		if r.ExpiresAt <= cutoff {
			continue
		}
		if l, ok := localByMAC[r.MAC]; ok {
			if l.IP != r.IP {
				conflicts = append(conflicts, Conflict{MAC: r.MAC, LocalIP: l.IP, RemoteIP: r.IP})
			}
			continue
		}
		gaps = append(gaps, r)
	}
	return conflicts, gaps
}
