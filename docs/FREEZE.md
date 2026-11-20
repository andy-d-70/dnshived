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
dual-answer window. Nothing in the
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
Probe host API additions in 0.9.8.9 (new, so they follow the same rules):
`GET /api/v1/tls-info` (public, certificate proof), `POST /api/v1/rotate-token`
(TLS only), `POST /api/v1/tls` (certificate upload), `GET /api/v1/watch` and
`GET /api/v1/history`; the probe config gains the optional keys `plain_http`,
`manual_probes` and `history`.

Daemon API addition in 0.9.8.10 (new, same rules): `GET /api/v1/config/stamp`
(admin) answers `{"config_stamp": "...", "candidate_stamp": "..."}`, two opaque
tokens that change whenever `cluster.json` or the staged `candidate.json` is
replaced or written and are empty when the file does not exist. A client may
only compare them for equality; an older daemon answers 404 and the client
falls back to fetching the documents.

Daemon API additions in 0.9.8.10 (new, same rules): `POST /api/v1/candidate`
accepts the optional string `author`; the daemon keeps, per changed field, who
changed it in `candidate-authors.json` beside `candidate.json` (removed with the
candidate), and `GET /api/v1/candidate` adds the optional object `authors`
(path to name; `*` marks a unit several admins changed; absent on older
daemons). A client must treat a missing `authors` as "not recorded".

Daemon API additions in 0.9.8.10 (new, same rules): `GET /api/v1/neighbors/<scope>`
(the serving node's ARP view of the scope's VLAN) and
`POST /api/v1/neighbors/<scope>/probe` (up to 16 IPv4 host addresses inside the
scope's network, one call per scope every two seconds); both admin.

Daemon status additions in 0.9.8.10 (optional fields of `GET /api/v1/status`,
absent on older daemons): `dhcp_active` (active leases whose address lies in a
scope this node serves) and `dhcp_reserved` (reservations in the configuration),
and `config_formats` (the configuration formats the daemon reads: `single`, and
`split`, a `cluster.json.d/` directory with a manifest and one part per domain
and scope; a daemon without the field reads only the single file).

Split configuration format (read support in 0.9.8.10, nothing writes it yet): the
manifest (`manifest.json`, `format` 1) lists the parts by kind, name and content
hash; part kinds are `base`, `scope` and `domain`, and a kind a daemon does not
know is skipped, so a later version can add kinds. A part is checked against its
manifest hash when it is read. `cluster.json` stays authoritative while it exists;
the split directory is read only when the single file is missing.

Configuration import in 0.9.8.10 (new, same rules): `cluster.json` gains the optional
`parked_scopes` (scopes kept but never built or served until moved to `scopes`;
older versions ignore it), the config push body gains the optional `parked_scopes`
(absent leaves the parked scopes unchanged, a map replaces them), the v2 content hash
covers `parked_scopes` only while it is present, and the split format has a part kind
`parked`. Web UI: `GET /config/export?mode=data`, `GET /config/import` and
`POST /config/import/{upload,preview,stage}` (edit-configuration role),
`POST /scopes/parked/{enable,remove}`. Bootstrap wizard: `POST /setup/import/{upload,choose,clear}`.
An import never reads keys, tokens, certificates, trusted hosts or node identity from a file.

Config additions in 0.9.8.10 (optional, ignored by older versions): the access
list gains `blocked` (entries with a service, an address or MAC and an optional
note), and a reservation gains `client_id` (DHCP option 61) and `names` (extra
DNS names, at most eight).

Web UI additions in 0.9.8.10 (new, same rules): the DNS domains editor,
`GET /config/domains` (view role; query `d`, `q`, `show`, `sort`, `dir`, `per`,
`page`, `addname`, `addtype`) and `GET /config/domains/<name>/export` (view role),
and, with the edit-scopes role, `POST /config/domains/<name>/records/add`,
`/records/edit`, `/records/delete`, `/import`, `/import/stage`, `/apply`,
`/template` and `/mail`; every one of them stages an ordinary pending change or
only shows a preview. `GET /simulator` (view role,
read-only), `GET /users/policy` (admin; the password policy tab), `POST /hosts/check` (edit role; the on-demand ARP check) and the optional
field `user` of `GET /api/pending-summary`; the optional form fields `color` (`#rrggbb`) and `color_default=1` of `POST /nodes/rename`, the optional `color` of `POST /internal/nodes/rename`, and the optional keys `color` (per node) and `self_color` of `web.json`; `POST /config/domains/<name>/bulk` and `/bulk/stage` (edit-scopes role; form fields `action` = ttl, ttlclear, probe-on, probe-off, value, move, copy or delete, `line` repeated or `all=1` with `q` and `show`, and `ttl`, `value`, `target`; the first answers with an overview, the second stages one ordinary pending change) and the optional form field `follow=1` of `POST /config/domains/<name>/ttl`; `GET /pending/confirm?action=commit|discard` (edit-scopes role; the warning page) and the optional form fields `scope=mine` and `confirm` of `POST /pending/commit` and `POST /pending/discard`; the Security menu item opens `/users` (users
without the manage-users role are redirected to `/security`). `GET /api/footer` (view role) and
`POST /api/update-check` (edit-configuration role, form field `enabled=1`);
`web.json` gains the optional key `update_check`; the scope list and the probe
results accept `per=10|25|50|100|all` and ignore any other value.

Access list in 0.9.8.10 (new, same rules): `cluster.json` gains the optional
key `access` (mode `report` or `enforce`, the private-networks entry,
`entries` with `net`, `note`, `off` and `dns`/`dhcp`/`web` set to `allow` or
`deny`, and `hosts` with `addr`, `mac`, `note` and `dns`/`dhcp`/`web`) and the
node-local latch `access_list_active`; without the key everyone is served, as
before. A configuration push without the `access` key leaves the list
unchanged, `null` clears it. `relay.json` gains `access`, `access_always` and
a per-interface `network`; `dnsrelay.json` gains `access` and
`access_always`; both are absent until every core runs the version that has
the list, and older relays ignore them. `GET /api/v1/access` (admin) answers
the activation state, the list and the relay reports. The web interface gains
`/config/access`, `/config/access/hosts`, `/config/access/report` and
`POST /config/access/save`.

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
config_revision int     optional (0.9.8.9): raised by one on every committed
                        change, used for catch-up and the outage rules
platform.serving map    optional (0.9.8.9): interface -> bool, "use for
                        serving"; absent keeps the old behaviour (worker
                        interfaces serve, the management interface does not)
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
bounded gap (~15-20 s) until the new process earns STABLE again.

Upgrade every node, including probe hosts, in one window. Do not roll
the upgrade one node at a time: a node on this release refuses the
unsigned pings and beacons of 0.9.8.5, so the upgraded node is isolated
from the others until they follow (tested on the testlab, 2026-10-30).
An upgrade from 0.9.8.5 also removes the nftables table that release's
DHCP gate left behind, through the helper; the helper needs the
`nftables` tools for that step.
