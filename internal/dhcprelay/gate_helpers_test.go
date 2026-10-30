// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcprelay

import "time"

// openTestGates authorizes every client interface of r for an hour, as the daemon would after a successful
// authorize. Production relays start closed; the packet-path tests are about forwarding, so they open the gate first.
func openTestGates(r *Relay) {
	r.gates.clockOK.Store(true)
	for _, cif := range r.clientIfaces {
		if cif.gate == nil {
			cif.gate = r.gates.scope(cif.name)
		}
		cif.gate.deadline.Store(time.Now().Add(time.Hour).UnixNano())
	}
}
