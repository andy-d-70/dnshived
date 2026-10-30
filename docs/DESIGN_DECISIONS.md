# Design Decisions

Short answers to questions that come up repeatedly.

## Why dnsmasq?

Battle-tested, lightweight, widely deployed DNS+DHCP in one process.
dnsmasq handles the data plane; dnshived handles coordination. No
reason to reimplement what already works.

## Why not Kea or BIND?

Kea's HA mode requires a shared lease database (PostgreSQL/MySQL). BIND
doesn't do DHCP. Both add dependencies and complexity that don't fit a
small-to-medium network appliance. dnshived has zero external
dependencies.

## Why not Raft?

Mutual exclusion doesn't require distributed consensus. A 2-of-3
witness quorum across three symmetric arbiter instances is simpler
than Raft, has fewer failure modes, and needs no leader election. Raft
solves replicated state machines; dnshived doesn't replicate state.
Each node computes authority independently from config.

## Why three nodes, not N?

Three gives majority quorum (2-of-3) at the minimum node count: any
one node can be lost and the cluster still proves exclusive authority.
All three are symmetric; any single node can serve 100% of scopes.
More than three isn't prohibited, just not needed yet.

## Why a witness?

Two nodes can each have majority quorum (2/3) without seeing each
other. Without a witness, both serve: dual active. Exclusive,
HMAC-signed tokens, granted only on 2-of-3 agreement across all three
arbiter instances, close this gap with no extra infrastructure.

## Why no database?

Configuration is a replicated deterministic seed. Every node computes
the same decisions from the same config. The only state that must
survive a restart is local: the fencing watermark and the incarnation
counter, each persisted with fsync.

## Why a JSON config file?

JSON is readable, diffable, version-controllable and parseable without
external libraries. `cluster.json` is the single source of truth on
each node. Normal changes go through the web UI, which stages a
candidate and applies it on commit (scope changes hot-reload, a few
cluster-wide fields need a restart, warned about before commit).
Hand-editing the file still works and needs a daemon restart.

## Why silence over availability?

A 15-second DNS/DHCP outage is invisible to clients (cached records,
DHCP lease renewal timers). A 15-second dual-active window can hand
out conflicting IP addresses, corrupt ARP tables and break Dante audio
streams. The recoverable failure mode is silence; the catastrophic one
is contradiction.

## Why operator-approved rebalancing, not automatic?

A scope moves between nodes without a restart, but a returning
preferred node holds instead of immediately reclaiming a scope a peer
already serves, until the operator approves the rebalance. Automatic
reclaim-on-return risks a flap storm; the operator decides timing,
dnshived executes it without disruption.

## Why stdlib-only Go?

Zero dependencies means zero supply-chain risk, zero version conflicts
and a single static binary that runs on any Linux system. The core
module builds with `CGO_ENABLED=0 go build`. The DNS relay is a
separate module so its two `golang.org/x` dependencies never reach the
core.

## Node identity colors

Every UI marks which node is which with one consistent color per role,
kept separate from health colors (ok/warn/crit) so the two are never
confused: core-1 red, core-2 blue, core-3 black (white in
`dnshived-top`), probe hosts green.

- `cmd/dnshived-web`: `--core-1`/`--core-2`/`--core-3`/`--worker-probe`
  CSS properties in `layout.go`, applied via `.node-core-N` and
  `roleClass()`; values differ per theme but keep their hue.
- `cmd/dnshived-top`: `cNodeA`/`cNodeB`/`cNodeC`, the plain (3x) ANSI
  colors, not the bright (9x) ones health status uses; applied via
  `nodeIdentityColor(role)`.

## Network plane and authority plane

Two planes, deliberately separate:

- **Network plane**, built once at startup and left running: VLAN
  interfaces, node IPs, the consolidated keepalived instance, the
  relays and the central dnsmasq pair, rendered configs. Its invariant
  is "this node is physically able to serve the scope". The DHCP gate
  is part of it and closed by default.
- **Authority plane**, changed on failover, rebalance or operator
  action: who may serve (the predicate), VRRP priority (where the VIP
  lives), DHCP gate open/closed. Its invariant is "this node should
  serve the scope right now".

Losing authority never tears down the network plane, so a failover is
a VRRP-priority write plus a gate flip, not infrastructure
construction.

```
Inputs (cluster state, FSM, leases, fencing)
  │
  ▼
scopeServeAllowed()        "May this node own the scope?"
  │                         Pure function. No I/O. No timers.
  ▼
EvaluateAntiFlap()         "Should ownership change now?"
  │                         Policy. Resets on instability.
  ▼
DesiredAuthority           { Serve: bool, Reason: string }
  │
  ├── control / execution boundary ──────────────
  ▼
ApplyDesiredAuthority()    "Make reality match the decision."
  ├── VRRP priority        (keepalived moves the VIP)
  └── DHCP gate: close the OLD owner, THEN open the NEW owner
```

A node is READY for a scope once the interface exists, the node IP is
assigned, VRRP is operational, the gate is closed, the config is
rendered and validated, and the helper is reachable.

## Why a packet-filter gate for DHCP

VIP ownership alone does not make DHCP exclusive. A DHCP server bound
to a VLAN interface answers broadcast `DHCPDISCOVER`s on that segment
whether or not it holds the VIP; VRRP only controls unicast delivery to
an address. Reproduced with `tools/dhcp-gate-rig.sh baseline`: two
servers, one VIP, two offers.

Exclusivity therefore comes from one gate per scope on every node that
must not answer. The gate is inside `dnshived-relay`: it refuses to
forward on the scope's VLAN until the relay has been authorized for that
scope with a current witness token, and it closes again on revoke or
when the authorization's deadline passes.

- Closing the old owner before opening the new one produces a short
  silent window, never a dual-answer window, because each node's gate
  is its own local default. Opening first would be a code mistake, not
  something nftables prevents, so the order is a frozen rule
  (`docs/FREEZE.md`) and verified with `dhcp-gate-rig.sh handoff`.
- A rule toggle costs ~11-12 ms through the `nft` CLI, almost all of it
  process start; irrelevant next to the reconcile tick, so no netlink
  dependency.
- dnsmasq's own `dhcp-relay=` was evaluated first and rejected: relay
  and server cannot share a host (both need port 67, and replies to a
  local `giaddr` are not relayed back out). `dnshived-relay` is a
  separate, purpose-built relay.

DNS needs no gate: a duplicate or stale DNS answer is not a safety
violation, so `dnshived-dnsrelay` answers active-active on every node.

## Lease state on failover

A new owner without the old owner's leases would re-offer different
addresses, and dnsmasq's duplicate-address ping-check costs ~3 s per
new allocation. Dynamic leases are therefore shadowed across the cores
(`internal/leasesync`) so a new owner knows them; `dhcp_no_ping` is an
optional per-scope setting for networks that prefer speed over the
ping check.

## A stopped daemon closes its gates

`dnshived.service` runs `dnshived --emergency-close-gates` as
`ExecStopPost`, revoking every scope on the relay on any stop, clean or
crash, so a dead daemon never leaves a gate open. The relay's own
deadline is the backstop if that call does not reach it.
The cost is a short serving gap (~15-20 s) on a routine restart of the
current owner, accepted as silence over contradiction.

Caveat: `systemctl kill -s KILL dnshived` kills every process in the
unit's cgroup, `ExecStopPost` included. To force-kill and keep the
safety net, use `systemctl kill --kill-who=main -s KILL dnshived` or
`kill -9 <pid>`.

**Total node death** (power loss, kernel panic) cannot run
`ExecStopPost`, and needs nothing: the dead node's DHCP is gone with
it. The survivor takes over once the dead node's witness token expires
(~15 s), the same bound as for any node that goes silent. Faster
failover for confirmed-dead nodes would need real external fencing
(hypervisor/IPMI); "nobody can reach it" is the same signal a partition
produces, so it is not used.

## Probe hosts: clients, report-only, pulled

- **Client, not cluster peer.** A probe host reads config through the
  normal API like `dnshived-web`. As a peer it would be counted as a
  voter whenever unreachable and could turn a healthy 2-of-3 quorum
  into a false "quorum lost".
- **Report-only.** A probe finding never reaches `internal/agent`: no
  gate action, no VRRP input. Most probe-only findings are network-path
  problems that moving a scope cannot fix, and acting on a less-trusted
  external signal would be a second decision path.
- **Pulled.** Each probe host runs its own probing loop and exposes a
  read-only API; `dnshived-web`/`dnshived-top` poll it like any node.

## Why a host-driven orphan sweep, not just config-diff decommission

`DecommissionRemovedScopes` diffs `known-scopes.json` against the
config, so it only knows about scopes this node itself built and later
lost from config. Interfaces left over from before a rebuild, never
recorded there, are invisible to it.

A second, independent sweep compares what is actually on the host
(interfaces under the `Platform.Workers` trunks, `dnshived-dnsmasq@*`
units) with what `cluster.json` says should exist,
and removes the rest. It runs on every `CheckPlaneHealth` tick, on
every commit, and when a scope beacon loses a peer. `Platform.Mgmt` is
never touched. See `docs/COOKBOOK.md`, "Host-driven orphan sweep".
