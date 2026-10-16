// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"

	"dnshived/internal/probehelper"
)

// hostOwnedProbeVLANs enumerates every real VLAN sub-interface on this
// host whose parent is one of allowed (cfg.trunkParents()).
func hostOwnedProbeVLANs(allowed []string) (map[string]knownVLAN, error) {
	out := make(map[string]knownVLAN)
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("enumerate interfaces: %w", err)
	}
	allowedSet := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		allowedSet[a] = true
	}
	for _, ifc := range ifaces {
		name := ifc.Name
		for parent := range allowedSet {
			if name == parent {
				continue
			}
			prefix := parent + "."
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			vlanID, err := strconv.Atoi(name[len(prefix):])
			if err != nil || vlanID <= 0 {
				continue
			}
			out[vlanKey(parent, vlanID)] = knownVLAN{Parent: parent, VLANID: vlanID}
		}
	}
	return out, nil
}

// reconcileOrphanVLANs is the host-driven counterpart to
// reconcileVLANInterfaces above.
func reconcileOrphanVLANs(cfg *ProbeConfig, desired map[string]knownVLAN) []string {
	if cfg.LocalOctet == 0 || cfg.ProbeHelperSocket == "" {
		return nil
	}
	hostIfaces, err := hostOwnedProbeVLANs(cfg.trunkParents())
	if err != nil {
		return nil
	}
	known := loadKnownVLANs(cfg.knownVLANsPath())

	var orphanKeys []string
	for k := range hostIfaces {
		if _, inDesired := desired[k]; inDesired {
			continue
		}
		orphanKeys = append(orphanKeys, k)
	}
	sort.Strings(orphanKeys)
	if len(orphanKeys) == 0 {
		return nil
	}

	helper := probehelper.NewClient(cfg.ProbeHelperSocket)
	var removed []string
	for _, k := range orphanKeys {
		v := hostIfaces[k]
		if err := helper.DeleteInterface(v.Parent, v.VLANID, ""); err != nil {
			log.Printf("[PROBE:VLAN:ERROR] delete orphan %s (no matching desired or known entry): %v — will retry next sweep", k, err)
			continue
		}
		log.Printf("[PROBE:VLAN:WARN] %s was not backed by any desired scope — removed", k)
		delete(known, k)
		removed = append(removed, "-"+k)
	}
	if len(removed) > 0 {
		if err := saveKnownVLANs(cfg.knownVLANsPath(), known); err != nil {
			log.Printf("[PROBE:VLAN:WARN] save known vlans after orphan sweep: %v", err)
		}
	}
	return removed
}
