// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"

	"dnshived/internal/probehelper"
)

// knownVLAN is the minimal information needed to tear a VLAN interface
// back down.
type knownVLAN struct {
	Parent string `json:"parent"`
	VLANID int    `json:"vlan_id"`
	VIP    string `json:"vip,omitempty"`
}

// vlanKey is the map key both the desired and known sets use.
func vlanKey(parent string, vlanID int) string {
	return fmt.Sprintf("%s.%d", parent, vlanID)
}

// realIfaceName is the actual host interface name for a (parent, vlanID)
// pair.
func realIfaceName(parent string, vlanID int) string {
	if vlanID == 0 {
		return parent
	}
	return fmt.Sprintf("%s.%d", parent, vlanID)
}

// loadKnownVLANs reads the persisted set.
func loadKnownVLANs(path string) map[string]knownVLAN {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var known map[string]knownVLAN
	if err := json.Unmarshal(data, &known); err != nil {
		log.Printf("[PROBE:VLAN:WARN] known-vlans file corrupt, ignoring: %v", err)
		return nil
	}
	return known
}

// saveKnownVLANs atomically overwrites the persisted set.
func saveKnownVLANs(path string, known map[string]knownVLAN) error {
	data, err := json.MarshalIndent(known, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal known vlans: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create known vlans dir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}

func desiredVLANs(byNodeID map[string]probeConfigResponse, allowed []string) map[string]knownVLAN {
	allowedSet := make(map[string]bool, len(allowed))
	for _, p := range allowed {
		allowedSet[p] = true
	}
	desired := make(map[string]knownVLAN)
	for _, resp := range byNodeID {
		for _, sc := range resp.Scopes {
			if sc.Parent == "" || !allowedSet[sc.Parent] {
				continue
			}
			desired[vlanKey(sc.Parent, sc.VLANID)] = knownVLAN{Parent: sc.Parent, VLANID: sc.VLANID, VIP: sc.VIP}
		}
	}
	return desired
}

func probeSelfAddr(vip string, vlanID, localOctet int) string {
	if vip != "" {
		if _, ipNet, err := net.ParseCIDR(vip); err == nil {
			base := ipNet.IP.To4()
			ones, _ := ipNet.Mask.Size()
			if base != nil {
				return fmt.Sprintf("%d.%d.%d.%d/%d", base[0], base[1], base[2], localOctet, ones)
			}
		}
	}
	return vlanIDFallbackAddr(vlanID, localOctet)
}

// vlanIDFallbackAddr is the VIP-unaware address scheme.
func vlanIDFallbackAddr(vlanID, localOctet int) string {
	return fmt.Sprintf("172.%d.%d.%d/24", 16+vlanID/256, vlanID%256, localOctet)
}

// reconcileVLANInterfaces constructs any VLAN interface this probe host
// should have but doesn't yet, and tears down any it has but shouldn't
// anymore.
func reconcileVLANInterfaces(cfg *ProbeConfig, byNodeID map[string]probeConfigResponse) []string {
	if cfg.LocalOctet == 0 {
		return nil // feature not enabled on this host
	}
	if cfg.ProbeHelperSocket == "" {
		// loadProbeConfig already refuses this combination at startup —
		// reachable only if that check regresses. Fail loud, not silent.
		log.Printf("[PROBE:VLAN:ERROR] local_octet is set but probe_helper_socket is empty — cannot construct/destroy VLAN interfaces")
		return nil
	}

	desired := desiredVLANs(byNodeID, cfg.trunkParents())
	known := loadKnownVLANs(cfg.knownVLANsPath())
	updated := make(map[string]knownVLAN, len(known))
	for k, v := range known {
		updated[k] = v
	}

	helper := probehelper.NewClient(cfg.ProbeHelperSocket)
	var changed []string

	// drifted: present in BOTH known and desired, but the scope's VIP changed
	// since this interface was created.
	var drifted []string
	for k, d := range desired {
		if kv, ok := known[k]; ok && kv.VIP != d.VIP {
			drifted = append(drifted, k)
		}
	}
	sort.Strings(drifted)

	// missingLive: known and desired agree (same VIP too — not a drifted
	// entry), but the interface itself doesn't actually exist on this host
	// right now.
	var missingLive []string
	for k, d := range desired {
		if kv, ok := known[k]; ok && kv.VIP == d.VIP {
			if _, err := ifaceExistsFn(realIfaceName(d.Parent, d.VLANID)); err != nil {
				missingLive = append(missingLive, k)
			}
		}
	}
	sort.Strings(missingLive)
	for _, k := range missingLive {
		log.Printf("[PROBE:VLAN:WARN] %s known but not present on this host (likely a reboot since it was last built) — reconstructing", k)
	}

	toCreate := make(map[string]bool)
	for k := range desired {
		if _, ok := known[k]; !ok {
			toCreate[k] = true
		}
	}
	for _, k := range drifted {
		toCreate[k] = true
	}
	for _, k := range missingLive {
		toCreate[k] = true
	}
	createOrder := make([]string, 0, len(toCreate))
	for k := range toCreate {
		createOrder = append(createOrder, k)
	}
	sort.Strings(createOrder)

	toRemove := make(map[string]bool)
	for k := range known {
		if _, ok := desired[k]; !ok {
			toRemove[k] = true
		}
	}
	for _, k := range drifted {
		toRemove[k] = true
	}
	removeOrder := make([]string, 0, len(toRemove))
	for k := range toRemove {
		removeOrder = append(removeOrder, k)
	}
	sort.Strings(removeOrder)

	for _, k := range removeOrder {
		v := known[k]
		addr := probeSelfAddr(v.VIP, v.VLANID, cfg.LocalOctet)
		if err := helper.DeleteInterface(v.Parent, v.VLANID, addr); err != nil {
			log.Printf("[PROBE:VLAN:ERROR] delete %s: %v — will retry next sweep", k, err)
			delete(toCreate, k)
			continue
		}
		delete(updated, k)
		changed = append(changed, "-"+k)
	}

	for _, k := range createOrder {
		if !toCreate[k] {
			continue // its paired delete above failed — retry both next sweep
		}
		v := desired[k]
		addr := probeSelfAddr(v.VIP, v.VLANID, cfg.LocalOctet)
		if err := helper.CreateInterface(v.Parent, v.VLANID, addr); err != nil {
			log.Printf("[PROBE:VLAN:ERROR] create %s (%s): %v — will retry next sweep", k, addr, err)
			continue
		}
		updated[k] = v
		changed = append(changed, "+"+k)
	}

	if len(changed) > 0 {
		if err := saveKnownVLANs(cfg.knownVLANsPath(), updated); err != nil {
			log.Printf("[PROBE:VLAN:WARN] save known vlans: %v", err)
		}
	}
	return changed
}
