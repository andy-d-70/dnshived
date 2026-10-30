// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import "dnshived/internal/probepin"

// probePinTransport is the transport under every web UI request to a node. Its pins are rebuilt from the probe
// hosts on each config publish.
var probePinTransport = &probepin.Router{Next: rawClusterTransport}

// probePinsOf maps each pinned probe host's TLS address to its fingerprint.
func probePinsOf(nodes []NodeConfig) map[string]string {
	pins := make(map[string]string)
	for _, n := range nodes {
		if n.TLSFingerprint != "" {
			pins[n.tlsAddr()] = n.TLSFingerprint
		}
	}
	return pins
}
