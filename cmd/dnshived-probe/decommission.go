// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"log"

	"dnshived/internal/probehelper"
)

func probeSelfDecommission(cfg *ProbeConfig, reason string) {
	log.Printf("[DECOMMISSION] starting: %s", reason)

	if cfg.ProbeHelperSocket == "" {
		log.Printf("[DECOMMISSION] no probe_helper_socket configured — cannot wipe config or tear down interfaces; aborting (nothing changed)")
		return
	}

	client := probehelper.NewClient(cfg.ProbeHelperSocket)
	if err := client.Decommission(); err != nil {
		log.Printf("[DECOMMISSION] probe-helper decommission: %v — re-execing anyway", err)
	}

	log.Printf("[DECOMMISSION] re-executing into bootstrap mode")
	probeReExecFunc()
}
