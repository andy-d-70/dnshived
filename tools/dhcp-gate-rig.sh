#!/bin/bash
# dnshived — local DHCP dual-active reproduction + nftables gate proof
#
# Builds a 3-namespace rig on the local host (no VM lab, no SSH) and answers
# one question: does permanently-running dnsmasq on both workers produce
# dual-active DHCP, and does a single nftables rule per non-owning worker
# fix it?
#
# Topology, all in network namespaces on this host:
#
#   ns:dhc  client   eth0 172.16.1.99/24  ─┐
#                                          ├─ bridge dhbr0 == one VLAN segment
#   ns:dha  worker-a van  172.16.1.2/24   ─┤
#   ns:dhb  worker-b van  172.16.1.3/24   ─┘
#
#   VIP 172.16.1.1/24 assigned to whichever worker "holds" it. Both run
#   dnsmasq permanently on 'van'; exclusivity comes from an nftables rule,
#   not from which one holds the VIP.
#
# Usage:
#   ./tools/dhcp-gate-rig.sh up
#   ./tools/dhcp-gate-rig.sh baseline     # both open — proves dual-active
#   ./tools/dhcp-gate-rig.sh gated        # gate worker-b — proves exclusivity
#   ./tools/dhcp-gate-rig.sh handoff      # drop-old-then-open-new ordering
#   ./tools/dhcp-gate-rig.sh down
#
# Requires: root, ip netns, nft, dnsmasq, and builds/dnshived-dhcp-probe
# (build with `make build` first).

set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"
RUN="$HERE/run/dhcp-gate-rig"
PROBE="$HERE/builds/dnshived-dhcp-probe"
DNSHIVED="$HERE/builds/dnshived"

NS_C=dhc; NS_A=dha; NS_B=dhb
BR=dhgaterig0
NET=172.16.1
VIP=$NET.1
IP_A=$NET.2
IP_B=$NET.3
IP_C=$NET.99
RANGE_LO=$NET.100
RANGE_HI=$NET.200

ns()  { ip netns exec "$1" "${@:2}"; }
say() { printf '\033[1;36m>>> %s\033[0m\n' "$*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "must run as root"
[ -x "$PROBE" ] || die "missing $PROBE — run 'make build' first"

wns() { case "$1" in a) echo $NS_A;; b) echo $NS_B;; esac; }

# ---------------------------------------------------------------- topology

up() {
    down >/dev/null 2>&1
    mkdir -p "$RUN"

    ip link add $BR type bridge
    ip link set $BR up

    for n in $NS_C $NS_A $NS_B; do
        ip netns add $n
        ns $n ip link set lo up
    done

    _attach $NS_C c eth0 $IP_C
    _attach $NS_A a van  $IP_A
    _attach $NS_B b van  $IP_B

    say "rig up — segment $NET.0/24 on bridge $BR"
}

_attach() {
    local nsname=$1 tag=$2 newname=$3 addr=$4
    ip link add "dgr-$tag" type veth peer name "dgr-${tag}b"
    ip link set "dgr-${tag}b" master $BR
    ip link set "dgr-${tag}b" up
    ip link set "dgr-$tag" netns "$nsname"
    ns "$nsname" ip link set "dgr-$tag" name "$newname"
    ns "$nsname" ip addr add "$addr/24" dev "$newname"
    ns "$nsname" ip link set "$newname" up
}

down() {
    for n in $NS_C $NS_A $NS_B; do
        ip netns pids $n 2>/dev/null | xargs -r kill -9 2>/dev/null
        ip netns del $n 2>/dev/null
    done
    ip link del $BR 2>/dev/null
    rm -rf "$RUN"
    say "rig down"
}

# ---------------------------------------------------------------- servers

start_servers() {
    for w in a b; do
        local nsname; nsname=$(wns $w)
        local d="$RUN/$w"; mkdir -p "$d"
        cat > "$d/dnsmasq.conf" <<EOF
port=0
interface=van
bind-dynamic
dhcp-authoritative
no-ping
dhcp-range=$RANGE_LO,$RANGE_HI,255.255.255.0,12h
dhcp-leasefile=$d/leases
log-dhcp
log-facility=$d/dnsmasq.log
pid-file=$d/dnsmasq.pid
EOF
        ns "$nsname" dnsmasq --conf-file="$d/dnsmasq.conf"
    done
    sleep 0.4
    say "dnsmasq running permanently on both workers (no gate applied yet)"
}

stop_servers() {
    for w in a b; do
        local pid="$RUN/$w/dnsmasq.pid"
        [ -f "$pid" ] && kill "$(cat "$pid")" 2>/dev/null
    done
}

gate_init() {
    for w in a b; do
        local nsname; nsname=$(wns $w)
        ns "$nsname" nft add table inet dnshived 2>/dev/null
        ns "$nsname" nft add chain inet dnshived dhcp_gate \
            '{ type filter hook input priority 0; policy accept; }' 2>/dev/null
    done
}

gate_close() { # $1 = a|b — drop inbound DHCP on that worker
    local nsname; nsname=$(wns "$1")
    ns "$nsname" nft flush chain inet dnshived dhcp_gate
    ns "$nsname" nft add rule inet dnshived dhcp_gate iif van udp dport 67 drop
}

gate_open() { # $1 = a|b — allow inbound DHCP on that worker
    local nsname; nsname=$(wns "$1")
    ns "$nsname" nft flush chain inet dnshived dhcp_gate
}

probe() {
    ns $NS_C "$PROBE" --iface eth0 "$@"
}

# ---------------------------------------------------------------- scenarios

baseline() {
    up
    start_servers
    say "BASELINE — no gate, both workers answering. Expect VERDICT: DUAL-ACTIVE"
    probe --wait 3s
    local rc=$?
    [ $rc -eq 2 ] && say "confirmed: permanent dnsmasq on both workers IS dual-active" \
                   || say "UNEXPECTED: expected dual-active (exit 2), got exit $rc"
    return $rc
}

gated() {
    up
    start_servers
    gate_init
    gate_close b
    say "GATED — worker-b closed. Expect VERDICT: OK (one server)"
    probe --wait 3s
    local rc=$?
    [ $rc -eq 0 ] && say "confirmed: single nftables rule restores exclusivity" \
                   || say "UNEXPECTED: expected single-server (exit 0), got exit $rc"
    return $rc
}

handoff() {
    up
    start_servers
    gate_init
    gate_close b
    say "pre-handoff: a open, b gated"
    probe --wait 2s >/dev/null; echo "  (setup probe, ignore verdict)"

    say "step 1/2 — drop OLD owner (a) first. Both now gated: expect NO ANSWER"
    gate_close a
    probe --wait 2s
    local mid_rc=$?

    say "step 2/2 — open NEW owner (b). Expect single-server OK, server-id = worker-b"
    gate_open b
    probe --wait 2s
    local end_rc=$?

    if [ $mid_rc -eq 1 ] && [ $end_rc -eq 0 ]; then
        say "confirmed: drop-old-then-open-new never produces a dual-answer window"
    else
        say "UNEXPECTED: mid-transition exit=$mid_rc (want 1), post-handoff exit=$end_rc (want 0)"
    fi
}

# stop-close: runs the real dnshived --emergency-close-gates (what
# ExecStopPost runs) against a gate this rig opened and checks with nft
# that it is closed.
stop_close() {
    up
    gate_init
    ns $NS_A ip link add link van name van.100 type vlan id 100
    ns $NS_A ip link set van.100 up

    local d="$RUN/emergency"
    mkdir -p "$d"
    cat > "$d/cluster.json" <<EOF
{
  "schema_version": 2,
  "cluster_id": "stop-close-rig",
  "node_id": "worker-a-node",
  "role": "worker-a",
  "control_addr": "127.0.0.1:19943",
  "data_dir": "$d",
  "peers": [],
  "platform": {"mgmt": "eth0", "workers": ["van"]},
  "scopes": {
    "rigscope": {
      "parent": "van",
      "vlan_id": 100,
      "vip": "$VIP/24",
      "dhcp_range": ["$RANGE_LO", "$RANGE_HI"],
      "gateway": "$VIP",
      "upstream": ["1.1.1.1"],
      "vrrp_id": 61,
      "preferred_worker": "worker-a"
    }
  }
}
EOF

    say "gate starts open (no drop rule) — chain just created, nothing closed yet"
    if ns $NS_A nft list chain inet dnshived dhcp_gate 2>/dev/null | grep -q "van.100"; then
        say "UNEXPECTED: a drop rule for van.100 already exists before the emergency close ran"
    else
        say "confirmed: no rule for van.100 yet (open)"
    fi

    say "invoking the real binary in --emergency-close-gates mode (what ExecStopPost runs)"
    ns $NS_A "$DNSHIVED" --config "$d/cluster.json" --emergency-close-gates

    if ns $NS_A nft list chain inet dnshived dhcp_gate 2>/dev/null | grep -q "van.100"; then
        say "confirmed: emergency-close-gates left a real drop rule for van.100 — gate closed"
    else
        say "UNEXPECTED: no drop rule for van.100 found after emergency close — fix did not apply"
    fi
}

case "${1:-}" in
    up)         up ;;
    down)       stop_servers; down ;;
    baseline)   baseline ;;
    gated)      gated ;;
    handoff)    handoff ;;
    stop-close) stop_close ;;
    status)     for w in a b; do ns "$(wns $w)" ip -4 -br addr show van; done ;;
    *)
        echo "usage: $0 {up|down|baseline|gated|handoff|stop-close|status}"
        echo
        echo "  baseline    reproduce dual-active DHCP with no gate (expect exit 2)"
        echo "  gated       apply one nftables rule, prove exclusivity (expect exit 0)"
        echo "  handoff     prove drop-old-then-open-new never overlaps (silence, not dual-active)"
        echo "  stop-close  prove --emergency-close-gates (ExecStopPost) closes a real gate"
        exit 1
        ;;
esac
