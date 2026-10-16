#!/bin/bash
# dnshived: local management-VIP failover and no-relogin test.
#
# Runs real keepalived and a real dnshived-web, with the config
# internal/agent.RenderMgmtVIPConfig renders, and checks that (a) the VIP
# fails over under a simulated crash and (b) a client logged in once keeps
# getting 200s with the same session cookie from the other side.
#
# Topology, all in network namespaces on this host:
#
#   ns:mva  worker-a  van  172.16.3.2/24   priority 100 (preferred)  ─┐
#   ns:mvb  worker-b  van  172.16.3.3/24   priority 90  (standby)    ─┼─ bridge mvbr0
#   ns:mvc  client    van  172.16.3.10/24  (no VRRP role — just curls) ┘
#
#   VIP 172.16.3.1/24, virtual_router_id 61, dnshived-web listening on
#   0.0.0.0:18080 in both mva and mvb against the SAME webui-users.json,
#   which carries the session signing key (on a real cluster the users
#   document is replicated, so every core signs with the same key).
#
# Usage:
#   ./tools/mgmt-vip-rig.sh up          # netns + bridge
#   ./tools/mgmt-vip-rig.sh gen         # render real keepalived-mgmt.conf x2 + shared users file
#   ./tools/mgmt-vip-rig.sh build-web   # go build cmd/dnshived-web into the rig's run dir
#   ./tools/mgmt-vip-rig.sh start       # start both keepalived processes, wait for election
#   ./tools/mgmt-vip-rig.sh start-web   # start dnshived-web in mva and mvb
#   ./tools/mgmt-vip-rig.sh status      # who holds the VIP right now
#   ./tools/mgmt-vip-rig.sh verify      # log in once, poll with the cookie across a simulated crash
#   ./tools/mgmt-vip-rig.sh down        # tear down everything
#
# Requires: root, ip netns, keepalived, go (renders the real config and
# builds the real binary).

set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"
RUN="$HERE/run/mgmt-vip-rig"

NS_A=mva; NS_B=mvb; NS_C=mvc
BR=mvbr0
NET=172.16.3
VIP=$NET.1
IP_A=$NET.2
IP_B=$NET.3
IP_C=$NET.10
VRID=61
WEBPORT=18080
WEBUSER=admin
WEBPASS=smokepass

ns()  { ip netns exec "$1" "${@:2}"; }
say() { printf '\033[1;36m>>> %s\033[0m\n' "$*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "must run as root"
command -v keepalived >/dev/null || die "keepalived not found on PATH"
command -v go >/dev/null || die "go not found on PATH"

wns() { case "$1" in a) echo $NS_A;; b) echo $NS_B;; c) echo $NS_C;; esac; }
wip() { case "$1" in a) echo $IP_A;; b) echo $IP_B;; c) echo $IP_C;; esac; }

# ---------------------------------------------------------------- topology

up() {
    down >/dev/null 2>&1
    mkdir -p "$RUN"

    ip link add $BR type bridge
    ip link set $BR up

    for n in $NS_A $NS_B $NS_C; do
        ip netns add $n
        ns $n ip link set lo up
    done

    _attach $NS_A a $IP_A
    _attach $NS_B b $IP_B
    _attach $NS_C c $IP_C

    say "rig up — segment $NET.0/24 on bridge $BR (a=worker-a b=worker-b c=client)"
}

_attach() {
    local nsname=$1 tag=$2 addr=$3
    ip link add "mvr-$tag" type veth peer name "mvr-${tag}b"
    ip link set "mvr-${tag}b" master $BR
    ip link set "mvr-${tag}b" up
    ip link set "mvr-$tag" netns "$nsname"
    ns "$nsname" ip link set "mvr-$tag" name van
    ns "$nsname" ip addr add "$addr/24" dev van
    ns "$nsname" ip link set van up
}

down() {
    for w in a b; do
        local pid="$RUN/$w/keepalived.pid"
        [ -f "$pid" ] && kill "$(cat "$pid")" 2>/dev/null
        local webpid="$RUN/$w/web.pid"
        [ -f "$webpid" ] && kill "$(cat "$webpid")" 2>/dev/null
    done
    for n in $NS_A $NS_B $NS_C; do
        ip netns pids $n 2>/dev/null | xargs -r kill -9 2>/dev/null
        ip netns del $n 2>/dev/null
    done
    ip link del $BR 2>/dev/null
    rm -rf "$RUN"
    rm -rf "$HERE/tmp_mgmtviprig_gen"
    say "rig down"
}

# ---------------------------------------------------------------- config generation (real code, not hand-copied)

# gen: renders keepalived-mgmt.conf for worker-a and worker-b by calling
# internal/agent.RenderMgmtVIPConfig from a throwaway package inside the
# module (internal/ visibility), removed right after.
gen() {
    mkdir -p "$RUN/a" "$RUN/b"
    local gendir="$HERE/tmp_mgmtviprig_gen"
    rm -rf "$gendir"
    mkdir -p "$gendir"
    cat > "$gendir/main.go" <<EOF
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"dnshived/internal/agent"
	"dnshived/internal/config"
	"dnshived/internal/webauth"
)

func main() {
	mgmtVIP := &config.MgmtVIPConfig{VIP: "$VIP/24", VRRPID: $VRID}
	platform := &config.Platform{Mgmt: "van"}

	// No helper: rendering writes the file, the unit reload is skipped.
	for dir, role := range map[string]string{"$RUN/a": config.RoleCore1, "$RUN/b": config.RoleCore2} {
		if err := agent.New(role, "rig-"+role, 1, "rig", dir, nil, nil).RenderMgmtVIPConfig(mgmtVIP, platform); err != nil {
			panic(err)
		}
	}

	hash, err := webauth.HashPassword("$WEBPASS")
	if err != nil {
		panic(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	store := webauth.Store{SessionKey: hex.EncodeToString(key), Users: []webauth.User{{Name: "$WEBUSER", PasswordHash: hash, Role: "admin"}}}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile("$RUN/webui-users.json", data, 0o600); err != nil {
		panic(err)
	}
	fmt.Println("generated keepalived-mgmt.conf (a+b) and webui-users.json")
}
EOF
    ( cd "$HERE" && go run ./tmp_mgmtviprig_gen ) || die "gen failed"
    rm -rf "$gendir"
    say "rendered via real agent.RenderMgmtVIPConfig + webauth.HashPassword:"
    say "  $RUN/a/keepalived-mgmt.conf (priority 100)"
    say "  $RUN/b/keepalived-mgmt.conf (priority 90)"
    say "  $RUN/webui-users.json (user=$WEBUSER)"
}

build_web() {
    ( cd "$HERE" && go build -o "$RUN/dnshived-web" ./cmd/dnshived-web ) || die "build failed"
    say "built $RUN/dnshived-web"
}

# ---------------------------------------------------------------- keepalived

start() {
    for w in a b; do
        [ -f "$RUN/$w/keepalived-mgmt.conf" ] || die "no rendered config for $w — run 'gen' first"
    done
    for w in a b; do
        local nsname; nsname=$(wns $w)
        local d="$RUN/$w"
        ns "$nsname" keepalived -n --dont-respawn -f "$d/keepalived-mgmt.conf" \
            --pid "$d/keepalived.pid" --vrrp_pid "$d/keepalived-vrrp.pid" \
            --checkers_pid "$d/keepalived-checkers.pid" \
            --bfd_pid "$d/keepalived-bfd.pid" \
            --log-console > "$d/keepalived.log" 2>&1 &
    done
    say "started — a priority=100 (expect MASTER), b priority=90 (expect BACKUP)"
    say "waiting up to 5s for initial election..."
    sleep 5
    status
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

# ---------------------------------------------------------------- dnshived-web

start_web() {
    [ -x "$RUN/dnshived-web" ] || die "no dnshived-web binary — run 'build-web' first"
    [ -f "$RUN/webui-users.json" ] || die "no webui-users.json — run 'gen' first"
    for w in a b; do
        local d="$RUN/$w"
        cat > "$d/web.json" <<EOF
{
  "listen_addr": "0.0.0.0:$WEBPORT",
  "users_file": "$RUN/webui-users.json",
  "nodes": [ { "name": "unused", "addr": "127.0.0.1:1" } ]
}
EOF
        local nsname; nsname=$(wns $w)
        ns "$nsname" "$RUN/dnshived-web" -config "$d/web.json" > "$d/web.log" 2>&1 &
        echo $! > "$d/web.pid"
    done
    sleep 1
    say "started dnshived-web in both a and b, listening on :$WEBPORT (shared credentials file)"
}

# ---------------------------------------------------------------- the actual proof

# verify: from the client namespace, log in once through the VIP, then
# poll with only the session cookie, kill keepalived on the current VIP
# holder and keep polling. A redirect to /login or a 401 means the other
# side does not accept the session; a gap of more than a few seconds
# means no failover.
verify() {
    local before; before=$(vip_holder)
    _login || die "login through the VIP failed — is 'start-web' running?"
    say "current VIP holder: $before — logged in once, polling with the session cookie only"

    say "--- phase 1: baseline (no failure injected yet) ---"
    for i in 1 2 3; do
        _poll_once
        sleep 0.5
    done

    local killw="$before"
    [ "$killw" = "none" ] && die "no VIP holder before test — run 'start' first"
    local pid; pid=$(cat "$RUN/$killw/keepalived.pid" 2>/dev/null)
    [ -n "$pid" ] || die "no keepalived pid for $killw"

    say "--- phase 2: kill -9 keepalived on $killw (simulated crash) ---"
    kill -9 "$pid"

    local saw_401=0
    local saw_recovery=0
    for i in $(seq 1 30); do
        sleep 0.3
        local holder; holder=$(vip_holder)
        local code; code=$(_curl_code)
        printf '  t~=%sms holder=%-4s http=%s\n' "$((i * 300))" "$holder" "$code"
        { [ "$code" = "401" ] || [ "$code" = "303" ]; } && saw_401=1
        [ "$code" = "200" ] && [ "$holder" != "$killw" ] && saw_recovery=1
    done

    echo
    if [ "$saw_401" = "1" ]; then
        say "FAIL: the other side refused the session (401/redirect to /login) — session keys or users differ between a and b"
    elif [ "$saw_recovery" = "1" ]; then
        say "CONFIRMED: VIP moved off $killw, dnshived-web on the other side answered 200 to the SAME session cookie — no re-login needed"
    else
        say "FAIL: never saw a 200 from the surviving side after the simulated crash"
    fi
}

_poll_once() {
    local holder; holder=$(vip_holder)
    local code; code=$(_curl_code)
    printf '  holder=%-4s http=%s\n' "$holder" "$code"
}

_login() {
    rm -f "$RUN/cookies.txt"
    local code
    code=$(ns "$NS_C" curl -s -o /dev/null -m 3 -w '%{http_code}' -c "$RUN/cookies.txt" \
        --data-urlencode "username=$WEBUSER" --data-urlencode "password=$WEBPASS" --data-urlencode "next=/status" \
        "http://$VIP:$WEBPORT/login" 2>/dev/null)
    [ "$code" = "303" ] && grep -q dnshived_session "$RUN/cookies.txt" 2>/dev/null
}

_curl_code() {
    ns "$NS_C" curl -s -o /dev/null -m 1 -w '%{http_code}' -b "$RUN/cookies.txt" "http://$VIP:$WEBPORT/status" 2>/dev/null
}

case "${1:-}" in
    up)         up ;;
    down)       down ;;
    gen)        gen ;;
    build-web)  build_web ;;
    start)      start ;;
    start-web)  start_web ;;
    status)     status ;;
    verify)     verify ;;
    *)
        echo "usage: $0 {up|gen|build-web|start|start-web|status|verify|down}"
        echo
        echo "  up         create the 3-namespace rig (worker-a, worker-b, client)"
        echo "  gen        render real keepalived-mgmt.conf x2 + shared webui-users.json"
        echo "  build-web  go build cmd/dnshived-web into the rig's run dir"
        echo "  start      start both keepalived processes, wait for election"
        echo "  start-web  start dnshived-web in worker-a and worker-b"
        echo "  status     report which side currently holds the VIP"
        echo "  verify     log in once, then prove failover + no re-login with the same cookie"
        echo "  down       tear down"
        exit 1
        ;;
esac
