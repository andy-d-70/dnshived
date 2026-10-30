// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package ifname resolves an interface name that may be a kernel altname
// (e.g. ens19 on a host booted with net.ifnames=0) to the kernel name
// that /sys, /proc/sys, SO_BINDTODEVICE and keepalived accept.
package ifname

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"
)

const cacheTTL = 30 * time.Second

type entry struct {
	kernel string
	at     time.Time
}

var (
	mu     sync.Mutex
	cache  = map[string]entry{}
	logged = map[string]string{}
)

var sysClassNet = "/sys/class/net/"

var lookupAltname = func(name string) (string, bool) {
	out, err := exec.Command("ip", "-j", "link", "show", "dev", name).Output()
	if err != nil {
		return "", false
	}
	var links []struct {
		IfName string `json:"ifname"`
	}
	if json.Unmarshal(out, &links) != nil || len(links) != 1 || links[0].IfName == "" {
		return "", false
	}
	return links[0].IfName, true
}

// Resolve returns the kernel name for name, or name itself when it is
// already a kernel name or cannot be resolved.
func Resolve(name string) string {
	if name == "" {
		return name
	}
	if _, err := os.Stat(sysClassNet + name); err == nil {
		return name
	}
	mu.Lock()
	if e, ok := cache[name]; ok && time.Since(e.at) < cacheTTL {
		mu.Unlock()
		return e.kernel
	}
	mu.Unlock()

	kernel := name
	if k, ok := lookupAltname(name); ok {
		kernel = k
	}
	mu.Lock()
	cache[name] = entry{kernel: kernel, at: time.Now()}
	if kernel != name && logged[name] != kernel {
		logged[name] = kernel
		log.Printf("[IFNAME] %s is an altname of %s — using %s", name, kernel, kernel)
	}
	mu.Unlock()
	return kernel
}

// InterfaceName is the kernel name of a scope's VLAN interface: the parent itself for VLAN 0, else "<parent>.<vlan>".
func InterfaceName(parent string, vlanID int) string {
	if vlanID == 0 {
		return parent
	}
	return fmt.Sprintf("%s.%d", parent, vlanID)
}
