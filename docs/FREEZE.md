# dnshived — Feature & Layout Freeze

This document is the contract: what may change, what may not, and under
which version bump. The purpose is a stable install/upgrade routine:
the binaries change between versions, the structure does not.

Four tiers, from most to least stable.

---

## Tier 1 — FROZEN (breaking requires a MAJOR version bump)

### Package graph
The internal packages (`internal/*`) form an acyclic dependency graph.
New features extend existing packages or add leaf packages; they never
introduce a cycle. The core module has no external dependencies; the
DNS relay (`cmd/dnshived-dnsrelay`) is a separate module.

### FHS paths
```
/etc/dnshived/          config: cluster.json (core node) or probe.json (probe
                        host), web.json, webui-users.json, relay.json,
                        dnsrelay.json, TLS material. cluster.json is
                        identical across nodes except identity fields.
/var/lib/dnshived/      persistent state: incarnation, fencing watermark,
                        known-scopes.json, arbiter tokens, audit log,
                        reliability history, and every config the daemon
                        renders (keepalived.conf, keepalived-mgmt.conf,
                        dnsmasq-core-dhcp.conf, dnsmasq-core-dns.conf, the
                        central hosts files, leases).
/var/log/dnshived/      reserved for file logs (the journal is primary)
/run/dnshived/          sockets/pids, tmpfs
/run/dnshived-bootstrap/  join code shared by dnshived and dnshived-probe
                        (systemd-tmpfiles)
/usr/local/bin/         every dnshived binary
```

Canonical systemd units live in `packaging/systemd/`, the single source
for both `debian/` and `rpm/dnshived.spec`, installed to
`/usr/lib/systemd/system/`.

### The three counters
```
epoch        cluster authority era. Owned by the FSM. Bumps on entering STABLE.
incarnation  node boot identity. PERSISTED (/var/lib/dnshived/incarnation),
             strictly monotonic across restarts. Never reset.
generation   config/ownership revision. Owned by the desired-state engine.
             NOT persisted: resets on restart so a rebooted node looks stale
             and defers. Advances only while STABLE.
```
Incarnation persists, generation does not, the fencing watermark
persists. Changing any of these is a major-version event.

### The safety predicate
A scope is served only while ALL hold; serving stops the instant ANY
fails (eager stop, every tick, no grace, no hysteresis):
```
1. FSM state == STABLE                       (quorum now)
2. scope owned in the authoritative desired map
3. valid lease held, not within the safety margin
4. own fencing token >= watermark            (not fenced)
5. witness token held, not within the safety margin
   (checked on the stop path; the start path acquires it before the
   gate opens)
```
Implementations may change how each condition is computed; the
predicate itself (all five, eager stop) is the contract.

It governs the authority plane only. Whether the network plane exists
(VLAN interfaces, node IPs, relays) is not a safety fact and not part of
the predicate. Anti-flap decides WHEN to act on a `true` result and
never overrides a `false` one.

### Two planes
The network plane is constructed once and persists; losing authority
never tears it down. The authority plane (VRRP priority, the DHCP gate)
is what the predicate governs.

### Gate ordering
For every scope transition the OLD owner's DHCP gate closes before the
NEW owner's opens. This produces a silent window on overlap, never a
dual-answer window (`tools/dhcp-gate-rig.sh handoff`). Nothing in the
mechanism enforces the order on its own, so it is a rule.

---

## Tier 2 — STABLE (additive only; existing shapes never change)

### HTTP API
These endpoints keep their paths and existing response fields. New
endpoints and new fields are allowed; renaming/removing fields or
changing their meaning is not.
```
GET /api/v1/status     node id/role/cluster, epoch, generation, incarnation,
                       state, healthy, watermark, serving, version
GET /api/v1/cluster    self identity + per-peer reachability/identity + quorum
POST /api/v1/ping      handshake: exchange identity
GET /api/v1/quorum     quorum verdict
GET /api/v1/fsm        state, epoch, transition history
GET /api/v1/desired    ownership map, authoritative flag, generation
GET /api/v1/leases     held leases + observed peer leases (validity + fenced)
GET /api/v1/fencing    watermark + observed peer tokens
GET /api/v1/agent      scopes currently served
GET /api/v1/authority/<scope>  five-condition predicate breakdown
GET /api/v1/readiness/<scope>  network-plane state (interface, node IP,
                       VRRP, DHCP gate, config, helper reachability)
```

**Contract break, 0.9.8.1:** dry-run was removed. `dry_run` is gone
from `/api/v1/status` and `/api/v1/agent` and from cluster.json (the
daemon strips an existing key on startup and serves). `psk` is
required, and `platform` is required once a scope exists. This is the
one deliberate exception to the rules above.

### Config schema (cluster.json)
Fields keep their names and meaning. New OPTIONAL fields with safe
defaults are allowed; no new REQUIRED fields, no meaning changes.
```
schema_version  int     forward-compat marker (unset → treated as 1)
cluster_id      string  required
node_id         string  required, unique per node
role            string  required: core-1 | core-2 | core-3
control_addr    string  required: host:9443
bind_addr       string  optional: listener bind (default: all ifaces on port)
data_dir        string  optional: state dir (default /var/lib/dnshived)
peers           []string  other nodes' control addrs
psk             string  required (since 0.9.8.1)
```

---

## Tier 3 — VERSIONED (expected to change behind the version string)

Internal logic, timer values (lease TTL/renew, probe/reconcile
intervals), config rendering, the helper's command set, systemd unit
internals, log formatting. Free to change as long as Tiers 1–2 hold.

---

## Tier 4 — The install / upgrade routine this enables

Because Tiers 1–2 are fixed, one routine works for every version:

```
1. prerm stops the running units (and leftovers from older versions)
2. install the new binaries to /usr/local/bin
3. /etc/dnshived/ is never written by the package: a host without
   cluster.json or probe.json starts in bootstrap mode; existing config
   survives every upgrade
4. /var/lib/dnshived/ is preserved; incarnation increments, the
   watermark persists
5. postinst runs dnshived-preflight (aborts on a failed check), enables
   and starts the always-on units (dnshived, dnshived-helper,
   dnshived-probe, dnshived-probe-helper); every other unit is started
   by the agent or an operator, never at boot
6. on upgrade: one ordered restart of dnshived-helper and dnshived;
   dnshived-web and its helper are restarted only if they were running
```

State and config survive upgrades; only the binaries change.

Stopping `dnshived` closes every DHCP gate it holds (`ExecStopPost`), so
upgrading the node that currently owns a scope gives that scope a
bounded gap (~15-20 s) until the new process earns STABLE again. Plan a
rolling multi-node upgrade with one node at a time.
