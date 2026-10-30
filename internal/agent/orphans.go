// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"dnshived/internal/config"
	"dnshived/internal/helper"
	"dnshived/internal/ifname"
	"dnshived/internal/loglevel"
)

// reservedDnsmasqScopes are instance names that are never a real scope, so
// they must never be reported (or torn down) as orphans by the checks
// below.
var reservedDnsmasqScopes = map[string]bool{"core-dns": true, "core-dhcp": true}

// TrunkIface identifies one real local interface's own (local parent,
// vlanID); the helper rebuilds the interface name from both.
type TrunkIface struct {
	Parent string
	VLANID int
}

func HostOwnedTrunkInterfaces(platform *config.Platform, role string) (map[string]TrunkIface, error) {
	out := make(map[string]TrunkIface)
	if platform == nil {
		return out, nil
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("enumerate interfaces: %w", err)
	}
	localTrunks := make(map[string]string, len(platform.Workers))
	for _, canonical := range platform.Workers {
		localTrunks[platform.ResolveParent(role, canonical)] = canonical
	}
	for _, ifc := range ifaces {
		name := ifc.Name
		for local := range localTrunks {
			if name == local {
				continue
			}
			prefix := local + "."
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			suffix := name[len(prefix):]
			vlanID, err := strconv.Atoi(suffix)
			if err != nil || vlanID <= 0 {
				continue // not a <parent>.<digits> shape — not ours to touch
			}
			out[name] = TrunkIface{Parent: local, VLANID: vlanID}
		}
	}
	return out, nil
}

// ConfiguredTrunkInterfaces returns the set of real local interface names
// every entry in scopes resolves to for role.
func ConfiguredTrunkInterfaces(platform *config.Platform, role string, scopes map[string]config.ScopeConfig) map[string]bool {
	out := make(map[string]bool, len(scopes))
	for _, sc := range scopes {
		local := platform.ResolveParent(role, sc.Parent)
		out[ifname.InterfaceName(local, sc.VLANID)] = true
	}
	return out
}

// OrphanStep is one verified teardown action's own outcome.
type OrphanStep struct {
	Name   string
	OK     bool
	Detail string
}

func DeleteOrphanInterface(helperClient *helper.Client, iface, parent string, vlanID int) OrphanStep {
	if helperClient == nil {
		return OrphanStep{Name: iface, OK: false, Detail: errNoHelper.Error()}
	}
	if err := helperClient.DeleteInterfaceUnscoped(parent, vlanID); err != nil {
		return OrphanStep{Name: iface, OK: false, Detail: fmt.Sprintf("helper delete-interface-unscoped: %v", err)}
	}
	// Verify: a fresh lookup, not the call's own reported success.
	if _, err := net.InterfaceByName(iface); err == nil {
		return OrphanStep{Name: iface, OK: false, Detail: "ip link delete reported success but interface is still present"}
	}
	return OrphanStep{Name: iface, OK: true, Detail: "interface confirmed gone"}
}

func StopOrphanDnsmasqUnit(helperClient *helper.Client, scope string) error {
	if helperClient != nil {
		return helperClient.StopDnsmasqUnscoped(scope)
	}
	return errNoHelper
}

// TriggerOrphanCheck runs checkOrphans immediately and logs whatever it
// finds under the given log tag.
func (a *Agent) TriggerOrphanCheck(logTag string) {
	for _, f := range a.checkOrphans() {
		loglevel.Infof("[AGENT:%s] %s: %s", logTag, f.What, f.Detail)
	}
}

// --- *Agent wrappers: the normal in-process callers (CheckPlaneHealth, HotReloadScopes) ---

func (a *Agent) hostOwnedTrunkInterfaces() (map[string]TrunkIface, error) {
	return HostOwnedTrunkInterfaces(a.platform, a.role)
}

func (a *Agent) configuredTrunkInterfaces() map[string]bool {
	return ConfiguredTrunkInterfaces(a.platform, a.role, a.allScopes())
}

// checkOrphans is the host-vs-config sweep behind the
// "orphan_interface"/"orphan_dnsmasq_unit" PlaneHealth
// findings.
func (a *Agent) checkOrphans() []PlaneHealth {
	a.constructMu.Lock()
	defer a.constructMu.Unlock()

	var found []PlaneHealth

	hostIfaces, err := a.hostOwnedTrunkInterfaces()
	if err != nil {
		return found
	}
	configured := a.configuredTrunkInterfaces()

	var orphanNames []string
	for name := range hostIfaces {
		if !configured[name] {
			orphanNames = append(orphanNames, name)
		}
	}
	sort.Strings(orphanNames)

	for _, name := range orphanNames {
		spec := hostIfaces[name]
		step := DeleteOrphanInterface(a.helperClient, name, spec.Parent, spec.VLANID)
		if step.OK {
			found = append(found, PlaneHealth{What: "orphan_interface",
				Detail:   fmt.Sprintf("%s was not backed by any configured scope — removed (%s)", name, step.Detail),
				Healable: false})
		} else {
			found = append(found, PlaneHealth{What: "orphan_interface",
				Detail:   fmt.Sprintf("%s is not backed by any configured scope and could NOT be fully removed: %s", name, step.Detail),
				Healable: false})
		}
	}

	allScopes := a.allScopes()
	for unit := range a.unitCache().Prefixed("dnshived-dnsmasq@") {
		scope := strings.TrimSuffix(strings.TrimPrefix(unit, "dnshived-dnsmasq@"), ".service")
		if reservedDnsmasqScopes[scope] {
			continue
		}
		if _, ok := allScopes[scope]; ok {
			continue
		}
		err := StopOrphanDnsmasqUnit(a.helperClient, scope)
		a.unitsChanged()
		if err != nil {
			found = append(found, PlaneHealth{What: "orphan_dnsmasq_unit",
				Detail:   fmt.Sprintf("%s is active with no matching configured scope and could not be stopped: %v", unit, err),
				Healable: false})
			continue
		}
		found = append(found, PlaneHealth{What: "orphan_dnsmasq_unit",
			Detail:   fmt.Sprintf("%s was active with no matching configured scope — stopped", unit),
			Healable: false})
	}

	return found
}
