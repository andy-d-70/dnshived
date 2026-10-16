// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"dnshived/internal/config"
	"dnshived/internal/dhcpcentralrender"
)

// dhcpConfigChanged reports whether a config push changes central DHCP's
// own rendered content.
func dhcpConfigChanged(before, after *config.Cluster) bool {
	beforeRendered, beforeErr := dhcpcentralrender.Render(*before, "")
	afterRendered, afterErr := dhcpcentralrender.Render(*after, "")
	if beforeErr != nil || afterErr != nil {
		return true
	}
	return beforeRendered != afterRendered
}
