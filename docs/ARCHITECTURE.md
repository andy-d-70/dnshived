# Architecture

## Problem statement

Professional AV networks and VLAN-heavy environments need reliable DNS
and DHCP. Standard approaches (a single dnsmasq instance, or two with
failover scripts) fail under network partitions: when two DHCP servers
both believe they are authoritative, they hand out conflicting leases,
and the corruption can take hours to resolve.

dnshived makes dual-active operation structurally impossible, not just
unlikely.

## Design constraints

1. **Safety dominates availability.** A brief DNS/DHCP outage (15 s) is
   invisible to clients; a brief dual-active window is catastrophic.
   The system always chooses silence over contradiction.
2. **Authority must be continuously demonstrated.** Serving is re-earned
   every reconciliation tick by passing all safety checks.
3. **Evidence-based trust.** Every decision uses currently observable
   evidence: quorum, lease validity, fencing watermarks, witness tokens.
4. **Zero external dependencies.** Static binaries, stdlib-only Go core,
   no database, no message queue, no external coordination service.
5. **Configuration is a deterministic seed.** Given the same config,
   every node computes the same authority decisions independently.

## Cluster topology

```
┌───────────┐     ┌───────────┐     ┌───────────┐
│  core-1   │─────│  core-2   │─────│  core-3   │
│ dhcp relay│     │ dhcp relay│     │ dhcp relay│
│ dns relay │     │ dns relay │     │ dns relay │
│ dnsmasq   │     │ dnsmasq   │     │ dnsmasq   │
│ (central) │     │ (central) │     │ (central) │
│ keepalived│     │ keepalived│     │ keepalived│
│ arbiter   │     │ arbiter   │     │ arbiter   │
│ web UI    │     │ web UI    │     │ web UI    │
└─────┬─────┘     └─────┬─────┘     └─────┬─────┘
      └──── management VIP (3-way VRRP) ───┘
          optional: probe host(s), API clients only
```

Three symmetric nodes; any single one can serve 100% of scopes. Every
node builds every configured scope's VLAN interface.

- **DHCP:** `dnshived-relay` listens on each scope's VLAN and relays to
  one central DHCP dnsmasq per node on loopback. A per-scope nftables
  gate decides which node's relay may answer.
- **DNS:** `dnshived-dnsrelay` answers on every node (active-active, no
  gate: DNS cannot dual-conflict the way DHCP can) and forwards what it
  can't answer to the central DNS dnsmasq.
- **Witness:** every node runs an arbiter instance; a scope's witness
  token needs 2-of-3 agreement, so no single node is a point of failure.

## The authority predicate

```
scopeServeAllowed(AuthorityInputs) → (allowed, reason)
```

Five checks, evaluated in order:

| Check | What it verifies |
|-------|-----------------|
| Stable | FSM is STABLE (quorum) |
| Owned | the deterministic map assigns this scope to this node |
| Leased | valid lease, not within the safety margin |
| Unfenced | own fencing token ≥ cluster watermark |
| Witnessed | arbiter-granted exclusive token held |

All five must pass; if any fails, the scope's DHCP gate closes
immediately. The function is pure (no mutexes, no I/O) and the same one
is used by the reconcile loop, the tests, the API
(`/api/v1/authority/<scope>`) and the "Why?" drilldown in
`dnshived-top`.

## Network plane and authority plane

The network plane (VLAN interfaces, node IPs, keepalived, relays,
central dnsmasq) is built once and left running. Authority changes are
a VRRP-priority write (where the VIP lives) plus a DHCP gate flip, never
infrastructure construction or teardown. Details and reasoning:
`docs/DESIGN_DECISIONS.md`.

## Reconciliation loop

Every 5 seconds, and immediately on any peer reachability change, each
node:

1. collects cluster state (quorum, peer visibility, FSM state),
2. computes desired ownership,
3. evaluates the predicate per scope,
4. applies the result: VRRP priority, then the DHCP gate (close the old
   owner before opening the new one).

The loop is convergent: the same inputs give the same output, and
transient failures resolve on the next tick.

## Config changes

`dnshived-web` stages a change as a candidate on every node; a commit
applies it. Scope changes hot-reload without a restart; a few
cluster-wide fields need a restart, which the web UI warns about before
commit and performs one node at a time. A hand-edited `cluster.json`
needs a daemon restart. See `docs/SCOPE_LIFECYCLE.md`.

## Privilege separation

```
dnshived (controller)
    │  JSON over a Unix socket
    ▼
dnshived-helper (root)
    ├── interfaces:   create/delete-interface (+ the scope's DHCP gate)
    ├── DHCP gate:    set/get-dhcp-gate, dhcp-gate-dump
    ├── keepalived:   ensure/reload-keepalived, get-vrrp-state, vrrp-dump
    ├── relays:       restart/reload/stop-relay, -dnsrelay
    ├── central:      restart/reload-core-dhcp, -core-dns
    ├── mgmt VIP:     ensure/reload/restart/stop-mgmt-keepalived
    └── operator:     restart-daemon, restart-web, journal-tail, add-scopes
```

The controller never runs `ip`, `systemctl` or `nft` itself. The helper
validates scope-taking commands against its allowlist, executes and
logs. Founded clusters use the helper by default. Full command table:
`docs/SECURITY.md`.

## Fencing

When a node loses quorum, its fencing watermark advances. Even after
regaining quorum it cannot serve until its epoch catches up, so a node
returning from a partition never serves with stale state.

## Witness protocol

Two nodes can each have quorum (2/3) without seeing each other. Each
scope therefore also needs an exclusive, HMAC-signed witness token,
granted only on 2-of-3 agreement across the three arbiter instances.
No consensus algorithm, no database.

## Management VIP

A separate, static-priority, 3-way VRRP instance gives operators one
stable address for the web UI: core-3 preferred (110), then core-1
(100), core-2 (90). No gate, no witness; it is not a scope. The web UI
is also reachable directly on every node. Web UI auth is stateless HTTP
Basic, so a VIP move needs no re-login.

## Coordination plane

`internal/coordplane` lets `dnshived-web` post a config change once to
one node, which relays a per-node document to each peer (PSK-HMAC
signed) and returns one combined result. Opt-in via
`WebConfig.CoordinatorNode`; without it, the web UI pushes to every
node directly. See `docs/SECURITY.md`.

## Probe hosts

Optional hosts running `dnshived-probe` check every scope's real DHCP
and DNS from outside the cluster. They are API clients, not cluster
members, and only report; see `docs/DESIGN_DECISIONS.md`.
