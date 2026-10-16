#!/bin/bash
# dnshived: local VRRP dynamic-priority and reload test.
#
# Checks that rewriting keepalived.conf's priority and sending SIGHUP (as
# ExecReload= does) moves the VIP to the new MASTER without a restart and
# without a sustained dual-MASTER window.
#
# Topology, both in network namespaces on this host:
#
#   ns:vpa  worker-a  van  172.16.2.2/24  ─┐
#                                          ├─ bridge vprbr0 == one VLAN segment
#   ns:vpb  worker-b  van  172.16.2.3/24  ─┘
#
# VIP 172.16.2.1/24, one vrrp_instance, virtual_router_id 61, shaped like
# agent.go's keepalivedAllTmpl. keepalived runs as a raw process per
# namespace; "reload" is the SIGHUP that ExecReload= sends.
#
# Usage:
#   ./tools/vrrp-priority-rig.sh up
#   ./tools/vrrp-priority-rig.sh start        # a=100 (MASTER), b=50 (BACKUP)
#   ./tools/vrrp-priority-rig.sh status       # who holds the VIP right now
#   ./tools/vrrp-priority-rig.sh reload-swap  # a->1, b->100, SIGHUP both — proves the handover
#   ./tools/vrrp-priority-rig.sh down
#
# Requires: root, ip netns, keepalived. Tests the keepalived mechanism
# only; no dnshived code runs here.

set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"
RUN="$HERE/run/vrrp-priority-rig"

NS_A=vpa; NS_B=vpb
BR=vprbr0
NET=172.16.2
VIP=$NET.1
IP_A=$NET.2
IP_B=$NET.3
VRID=61

ns()  { ip netns exec "$1" "${@:2}"; }
say() { printf '\033[1;36m>>> %s\033[0m\n' "$*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "must run as root"
command -v keepalived >/dev/null || die "keepalived not found on PATH"

wns() { case "$1" in a) echo $NS_A;; b) echo $NS_B;; esac; }
wip() { case "$1" in a) echo $IP_A;; b) echo $IP_B;; esac; }

# ---------------------------------------------------------------- topology

up() {
    down >/dev/null 2>&1
    mkdir -p "$RUN"

    ip link add $BR type bridge
    ip link set $BR up

    for n in $NS_A $NS_B; do
        ip netns add $n
        ns $n ip link set lo up
    done

    _attach $NS_A a $IP_A
    _attach $NS_B b $IP_B

    say "rig up — segment $NET.0/24 on bridge $BR"
}

_attach() {
    local nsname=$1 tag=$2 addr=$3
    ip link add "vpr-$tag" type veth peer name "vpr-${tag}b"
    ip link set "vpr-${tag}b" master $BR
    ip link set "vpr-${tag}b" up
    ip link set "vpr-$tag" netns "$nsname"
    ns "$nsname" ip link set "vpr-$tag" name van
    ns "$nsname" ip addr add "$addr/24" dev van
    ns "$nsname" ip link set van up
}

down() {
    for w in a b; do
        local pid="$RUN/$w/keepalived.pid"
        [ -f "$pid" ] && kill "$(cat "$pid")" 2>/dev/null
    done
    for n in $NS_A $NS_B; do
        ip netns pids $n 2>/dev/null | xargs -r kill -9 2>/dev/null
        ip netns del $n 2>/dev/null
    done
    ip link del $BR 2>/dev/null
    rm -rf "$RUN"
    say "rig down"
}

# ---------------------------------------------------------------- keepalived

# render_conf w priority [advert_int_ms] [vrrp_version]: mirrors
# keepalivedAllTmpl in agent.go, one vrrp_instance. advert_int_ms defaults
# to 1000; sub-second values need vrrp_version=3.
render_conf() {
    local w=$1 priority=$2
    local advert_ms=${3:-1000}
    local version=${4:-0}
    local d="$RUN/$w"
    mkdir -p "$d"

    local advert_line
    if [ $((advert_ms % 1000)) -eq 0 ]; then
        advert_line=$((advert_ms / 1000))
    else
        advert_line=$(awk "BEGIN { printf \"%.2f\", $advert_ms/1000 }")
    fi

    local version_line=""
    if [ "$version" != "0" ]; then
        version_line="    version $version"
    fi

    cat > "$d/keepalived.conf" <<EOF
vrrp_instance DNSHIVED_rig {
    state BACKUP
    interface van
    virtual_router_id $VRID
    priority $priority
${version_line:+$version_line
}    advert_int $advert_line
    virtual_ipaddress {
        $VIP/24
    }
}
EOF
}

start() {
    render_conf a 100
    render_conf b 50
    _start_processes
    say "started — a priority=100 (expect MASTER), b priority=50 (expect BACKUP)"
    say "waiting up to 5s for initial election..."
    sleep 5
    status
}

# start-fast: like start, with version 3 and advert_int 150ms.
start_fast() {
    render_conf a 100 150 3
    render_conf b 50 150 3
    _start_processes
    say "started (FAST: version=3, advert_int=150ms) — a priority=100 (expect MASTER), b priority=50 (expect BACKUP)"
    say "waiting up to 2s for initial election..."
    sleep 2
    status
}

_start_processes() {
    for w in a b; do
        local nsname; nsname=$(wns $w)
        local d="$RUN/$w"
        # Output to a file: these processes outlive this function, and an
        # inherited pipe would block readers of this script's output.
        ns "$nsname" keepalived -n --dont-respawn -f "$d/keepalived.conf" \
            --pid "$d/keepalived.pid" --vrrp_pid "$d/keepalived-vrrp.pid" \
            --checkers_pid "$d/keepalived-checkers.pid" \
            --bfd_pid "$d/keepalived-bfd.pid" \
            --log-console > "$d/keepalived.log" 2>&1 &
    done
}

vip_holder() {
    for w in a b; do
        local nsname; nsname=$(wns $w)
        if ns "$nsname" ip -4 addr show van 2>/dev/null | grep -q "$VIP/"; then
            echo "$w"
            return
        fi
    done
    echo "none"
}

status() {
    local holder; holder=$(vip_holder)
    say "VIP $VIP held by: $holder"
    for w in a b; do
        local nsname; nsname=$(wns $w)
        local addrs; addrs=$(ns "$nsname" ip -4 -br addr show van 2>/dev/null)
        echo "  $w ($nsname): $addrs"
    done
}

# reload-swap: rewrite both configs (a: 100->1, b: 50->100), SIGHUP each,
# poll for convergence and report any sustained dual-MASTER window.
reload_swap() {
    local before; before=$(vip_holder)
    [ "$before" = "a" ] || say "WARNING: expected 'a' to hold the VIP before swap, got '$before' — run 'start' first"

    render_conf a 1
    render_conf b 100
    for w in a b; do
        local pid; pid=$(cat "$RUN/$w/keepalived.pid" 2>/dev/null)
        [ -n "$pid" ] || die "no pidfile for $w — run 'start' first"
        kill -HUP "$pid"
    done
    say "SIGHUP sent to both (a: 100->1, b: 50->100) — polling for convergence"

    local final=""
    for i in $(seq 1 15); do
        sleep 0.5
        local h; h=$(vip_holder)
        printf '  poll %2d (t~=%sms) holder=%s\n' "$i" "$((i * 500))" "$h"
        final="$h"
    done

    if [ "$final" = "b" ]; then
        say "confirmed: VIP moved to b (new higher-priority side) via reload, no restart"
    else
        say "UNEXPECTED: expected b to hold the VIP after swap, got '$final'"
    fi
}

# reload-swap-fast: like reload-swap against the start-fast configs,
# polling every 50ms.
reload_swap_fast() {
    local before; before=$(vip_holder)
    [ "$before" = "a" ] || say "WARNING: expected 'a' to hold the VIP before swap, got '$before' — run 'start-fast' first"

    render_conf a 1 150 3
    render_conf b 100 150 3
    local t0; t0=$(date +%s%N)
    for w in a b; do
        local pid; pid=$(cat "$RUN/$w/keepalived.pid" 2>/dev/null)
        [ -n "$pid" ] || die "no pidfile for $w — run 'start-fast' first"
        kill -HUP "$pid"
    done
    say "SIGHUP sent to both (a: 100->1, b: 50->100, advert_int=150ms) — polling for convergence at 50ms resolution"

    local final=""
    for i in $(seq 1 40); do
        sleep 0.05
        local h; h=$(vip_holder)
        if [ "$h" != "$final" ]; then
            local now; now=$(date +%s%N)
            printf '  t=%sms holder=%s\n' "$(( (now - t0) / 1000000 ))" "$h"
        fi
        final="$h"
    done

    if [ "$final" = "b" ]; then
        say "confirmed: VIP moved to b under version=3/advert_int=150ms — see timestamps above for actual convergence time"
    else
        say "UNEXPECTED: expected b to hold the VIP after swap, got '$final'"
    fi
}

case "${1:-}" in
    up)               up ;;
    down)             down ;;
    start)            start ;;
    start-fast)       start_fast ;;
    status)           status ;;
    reload-swap)      reload_swap ;;
    reload-swap-fast) reload_swap_fast ;;
    *)
        echo "usage: $0 {up|start|start-fast|status|reload-swap|reload-swap-fast|down}"
        echo
        echo "  up                create the 2-namespace rig"
        echo "  start             render configs (a=100, b=50), start both keepalived processes"
        echo "  start-fast        same, but version=3 + advert_int=150ms (0.9.7 Phase 4)"
        echo "  status            report which side currently holds the VIP"
        echo "  reload-swap       rewrite priorities (a->1, b->100), SIGHUP both, prove handover"
        echo "  reload-swap-fast  same, against start-fast's config, polled at 50ms resolution"
        echo "  down              tear down"
        exit 1
        ;;
esac
