#!/bin/bash
set -euo pipefail

# dnshived probe host: VLAN sub-interface bring-up (fallback).
#
# dnshived-probe builds and removes its VLAN interfaces itself
# (ProbeConfig.LocalOctet, see docs/COOKBOOK.md). This script only adds
# interfaces, never removes them; use it for a probe host without
# local_octet or to pre-create a range. Idempotent.
#
# Usage:
#   sudo ./tools/probe-host-vlans.sh <octet> [vlan-start] [vlan-end]
#
# Defaults to VLANs 100-199. Addresses: 172.16.<vlan>.<octet>/24.

OCTET="${1:?usage: $0 <octet> [vlan-start] [vlan-end]}"
VLAN_START="${2:-100}"
VLAN_END="${3:-199}"
IFACE="${TRUNK_IFACE:-ens19}"

for vlan in $(seq "$VLAN_START" "$VLAN_END"); do
    sub="${IFACE}.${vlan}"
    if ! ip link show "$sub" >/dev/null 2>&1; then
        ip link add link "$IFACE" name "$sub" type vlan id "$vlan"
    fi
    if ! ip addr show "$sub" | grep -q "172.16.${vlan}.${OCTET}/24"; then
        ip addr add "172.16.${vlan}.${OCTET}/24" dev "$sub"
    fi
    ip link set "$sub" up
done
echo "$(ip -br addr show | grep -c "${IFACE}\.") VLAN sub-interface(s) up on ${IFACE}"
