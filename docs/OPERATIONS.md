# Operations

Daily operation, monitoring and troubleshooting. Most work happens in
the web UI; the command-line tools below are for terminals, scripts
and monitoring. Connection flags can be stored in `~/.dnshived/rc`
(`docs/SECURITY.md`, "API authentication").

## Web UI (`dnshived-web`)

Reachable at `https://<mgmt-vip>:8443/` or on any core node's own
address; ports 80/443 redirect there. Menu: Overview, Scopes (list and
topology view), Scope options, Probes, Cluster Config (settings, nodes,
daemons), DNS, Security (API tokens), Backup, Logs, and the Pending
changes button.

- **Changes are staged, then committed.** Every edit becomes a pending
  change on all nodes; nothing applies until you commit it on Pending
  changes, which shows a diff and warns if a change needs a restart.
  Scope changes hot-reload; see `docs/SCOPE_LIFECYCLE.md`.
- **Config hashes.** `config_hash` covers the settings a commit distributes
  except the sanity-check and backup settings; `config_hash_v2` also covers
  those. The Overview, the catch-up and the start-up check compare the
  second one when every core reports it, otherwise the first.
- **Config revision.** Every commit raises the cluster's config
  revision (`config_revision` in `cluster.json` and in
  `/api/v1/status`). A node that was down during a commit comes back
  with a lower revision; the web UI on the node holding the highest
  revision then pushes the current configuration to it within about two
  minutes (audit entry `config.catchup`; a node's own `node_ip` values
  are kept, never the leader's). Only a strictly lower revision with
  different content is repaired. A node at the same revision with
  different content (a hand edit) and a node that reports no revision
  (0.9.8.8 and older) are listed on the Overview page and left alone.
- **Outage rules.** Once every configured core runs the version that
  has them (the Overview says which cores are still below it), four
  rules apply: (1) a configuration commit is refused on a node that does
  not see a strict majority of the cores (HTTP 503, `no_quorum`), so an
  isolated node can never accept a change; (2) a commit staged on an
  older revision is refused on a node that is already further ahead
  (HTTP 409, `stale_base`), stage it again; (3) after a start a node
  compares its configuration with its peers before it starts scopes or
  raises its VRRP priority, waits up to 30 seconds, and then serves its
  own configuration with an "unverified" notice if nobody answers, but
  stays held while a peer has a newer configuration until the catch-up
  has run (already running scopes are never stopped by this); (4) a
  membership epoch: `dnshived --force-standalone` on the console makes a
  node the only member, and a node that sees a peer with a higher epoch
  stops serving until it is re-adopted
  (`docs/COOKBOOK.md`). After a start, the web UI also waits up to 30
  seconds for the first sync of the users before it accepts a login.
  Nothing is enforced while any core is below the required version, so a
  rolling upgrade never blocks itself. Membership edits (add, replace,
  remove a core) keep their own rules and do not change the epoch.
- **Nodes** are onboarded, replaced or offboarded from Cluster Config
  (also staged); a new host's join code is required.
- **Backups:** Back up now, automated encrypted backups replicated to
  peers, restore from a node or an uploaded file.
- **Users** (Security → manage users, admins only): `admin` can change
  everything; `scopeadmin` can change everything served to clients
  (scopes, DHCP/DNS settings, templates, local domains) and commit only
  when every staged change is within those rights; `readonly` can view.
  Users, password-reset links and mail settings are replicated between
  the cores' web UIs and apply without a commit.

## dnshived-top

Interactive terminal console; one address is enough, it finds the
others.

```sh
dnshived-top -addr <node-ip>:9443 -tls -tls-skip-verify -token-file <path>
```

| Key | Action |
|-----|--------|
| `1` | Overview: cluster health, nodes, tokens, coherence |
| `2` | Scopes: paginated list, "Why?" drilldown |
| `3` | Probes: per-scope DNS/DHCP results from the probe hosts |
| `4` | Daemons: per-node systemd units, uptime, version |
| `5` | Logs: combined event feed |
| `w` | cycle the scope drilldown |
| `Esc` | leave the drilldown |
| `n` / `p` | next / previous page |
| `PgUp` / `PgDn` | scroll |
| `←` / `→`, `a` | Logs: cycle the node filter, show all |
| `q` | quit |

Nodes are labeled by role (`core-1`/`core-2`/`core-3`). If one node
drops, the others keep refreshing. Coherence checks every 2 seconds:

- dual-active (two nodes serving one scope)
- no token, or token owner ≠ serving node
- unserved scopes
- version mismatch
- epoch divergence between stable nodes
- clock skew between this host and a node
- partition (two nodes can't see each other, both reachable from here)

### Authority drilldown ("Why?")

Shows which of the five predicate conditions pass for a scope:

```
Scope: office                    SERVING
─────────────────────────────────────────
✔ stable           state is STABLE
✔ owned            authoritative map assigns to this node
✔ leased           valid, expires in 8s
✔ unfenced         token 11.203 vs watermark 11.203
✔ witnessed        held, expires in 12s
─────────────────────────────────────────
Decision: SERVE (all conditions met)
```

## dnshived-status

Quick health check, Nagios-compatible exit codes.

```sh
dnshived-status -addr <node-ip>:9443            # summary
dnshived-status -addr <node-ip>:9443 -v 2       # detailed
dnshived-status -addr <node-ip>:9443 -watch     # live, 2 s refresh
dnshived-status -addr <node-ip>:9443 -json      # for scripts
dnshived-status -addr <node-ip>:9443 -logs all  # tail every node's events
```

## dnshived-validate

Continuous invariant check, sampling every 500 ms: mutual exclusion,
authority matching, fenced node never serves, network plane intact,
monotonic progress, version and scope-config coherence, node-IP
coherence, plus preferred-worker convergence when ownership can be
discovered at startup.

```sh
dnshived-validate -addr <node-ip>:9443                  # 60 seconds
dnshived-validate -addr <node-ip>:9443 -duration 0      # until Ctrl-C
dnshived-validate -addr <node-ip>:9443 -out /tmp/violations
```

The real DHCP dual-active check (`dhcp_dual_active`) reads the probe
hosts' results: from `-probe-addr host:9444[,host:9444]` (plus any
`-probe-pin host:port=sha256:...`), or else from `probe_hosts` in
`/etc/dnshived/web.json` when it is readable (run it
with sudo on a core). With no probe host known, the check is skipped and
the startup output says so. The cluster's readonly token works on the
probe hosts as well.

## API endpoints

All JSON. With `api_tokens` set, requests need
`Authorization: Bearer <token>` (exceptions: `docs/SECURITY.md`).
Main read endpoints:

| Endpoint | Description |
|----------|-------------|
| `/api/v1/status` | node state, serving, configured and disabled scopes, epoch, generation, version, config revision, config hash and hash v2, membership epoch, outage rules |
| `/api/v1/cluster` | peers and reachability |
| `/api/v1/cluster/snapshot` | status, system, events, daemons of every node in one call |
| `/api/v1/cluster/activation` | whether every configured core runs at least the version a later feature needs, and which nodes do not (nothing uses it yet) |
| `/api/v1/authority/<scope>` | predicate evaluation (all five checks) |
| `/api/v1/readiness/<scope>` | network-plane state for a scope |
| `/api/v1/events?n=100`, `?since_id=42` | event ring buffer |
| `/api/v1/system` | load, memory, uptime |
| `/api/v1/version` | version and schema version |
| `/api/v1/token/status` | witness token table |
| `/api/v1/daemons` | systemd unit state, uptime, version |
| `/api/v1/leases/<scope>` | DHCP leases |
| `/api/v1/health` | 200 when STABLE, 503 otherwise (for load balancers) |
| `/api/v1/ping` | peer handshake (always unauthenticated) |

Write endpoints (`/api/v1/config`, `/api/v1/candidate`, backups, node
actions, audit) need an admin token and are used by the web UI.

## SNMP

Extend scripts for Observium, LibreNMS or Nagios; installation is in
`tools/snmp/README.md`. Per node: `dnshived-health` (state, serving
count, epoch, generation, version) and `dnshived-scopes` (served
scopes). Cluster-wide: `dnshived-cluster-check <node-ip>:9443`, exit
codes 0=OK, 1=WARNING, 2=CRITICAL.

## Log levels

`log_level` in `cluster.json` (Cluster Config in the web UI):

| Level | Behavior |
|-------|----------|
| `auto` (default) | WARNING when STABLE >30 s, DEBUG when unstable |
| `debug` | everything |
| `info` | INFO and above |
| `warning` | WARNING and above |

State transitions are always logged; the event ring buffer captures
everything regardless of level.

## Config validation

```sh
dnshived --check-config --config /etc/dnshived/cluster.json
```

Checks schema, required fields, VLAN/VRRP/VIP collisions, TLS files,
PSK, token roles and log level, and reports all problems at once.
