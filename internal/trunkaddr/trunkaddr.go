// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package trunkaddr

import (
	"fmt"

	"dnshived/internal/config"
)

// CoreIndex is the permanent index reserved for the cluster-wide core
// DHCP/DNS pair -- never assigned to a real worker interface.
const CoreIndex = 0

const MaxIndex = 255

// Index returns parent's 1-based position in cluster.Platform.Workers (0
// is reserved for the core pair, see CoreIndex).
func Index(cluster config.Cluster, parent string) (int, error) {
	if cluster.Platform == nil {
		return 0, fmt.Errorf("trunkaddr: cluster has no platform configuration")
	}
	for i, w := range cluster.Platform.Workers {
		if w == parent {
			idx := i + 1
			if idx > MaxIndex {
				return 0, fmt.Errorf("trunkaddr: parent %q has index %d, past the addressing scheme's own %d-trunk ceiling", parent, idx, MaxIndex)
			}
			return idx, nil
		}
	}
	return 0, fmt.Errorf("trunkaddr: parent %q is not a configured worker interface", parent)
}

// DHCPAddress returns the loopback bind address central DHCP uses for idx.
func DHCPAddress(idx int) string {
	return fmt.Sprintf("127.0.%d.21", idx)
}

func DNSAddress(idx int) string {
	return fmt.Sprintf("127.0.%d.42", idx)
}
