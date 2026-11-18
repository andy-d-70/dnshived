# Operations

Daily operation, monitoring and troubleshooting. Most work happens in
the web UI; the command-line tools below are for terminals, scripts
and monitoring. Connection flags can be stored in `~/.dnshived/rc`
(`docs/SECURITY.md`, "API authentication").

## Web UI (`dnshived-web`)

Reachable at `https://<mgmt-vip>:8443/` or on any core node's own
address; ports 80/443 redirect there. Menu: the dnshived logo (Overview),
Scopes (list, topology view, defaults for new scopes), Probes, DHCP, DNS,
Security (API tokens, users, mail), Maintenance (backup, restore, export),
Cluster settings (nodes, interfaces, addresses, access list) and Logs (with the daemon
list), plus the Pending changes button. Long pages are split into tabs.

- **Changes are staged, then committed.** Every edit becomes a pending
  change on all nodes; nothing applies until you commit it on Pending
  changes, which shows a diff and warns if a change needs a restart.
  Scope changes hot-reload; see `docs/SCOPE_LIFECYCLE.md`.
- **Config hashes.** `config_hash` covers the settings a commit distributes
  except the sanity-check and backup settings; `config_hash_v2` also covers
  those and the access list (when there is one). The Overview, the catch-up and the start-up check compare the
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
- **Scope list.** A scope served by a core other than its preferred worker
  shows a `≠` marker; the tooltip names both nodes. In a scope's menu,
  "Rebalance to preferred core" is greyed out when the scope has no
  preferred worker or already runs there, and the server refuses a
  rebalance for a scope without a preferred worker (HTTP 409).
- **Scopes and Probes lists.** Both pages use the same layout: heading row, tab row, filter bar, page bar and table, with the same first columns (Scope, Worker, Interface, VLAN, Subnet, Token Owner, Status). The filter box matches name, worker, interface, VLAN and subnet (every word must occur); the chips are All, Problems and Disabled on the scope list and All and Issues on the probe results (`?q=`, `?show=problems|disabled|issues`). The probe results then show one column per probe host.
- **Long lists.** The scope list, the probe results and Recent events on the
  Overview show 10 rows (Recent events: 5) with a "Show 10 / 25 / 50 / 100 /
  all" choice above the list and a slim page bar above and below. The scope
  list and the probe results keep the sort and the choice in the address
  (`?per=25`); Recent events keeps it in the browser. A list with no more rows
  than its default shows no bar. Recent events takes the height that is left
  above the footer and scrolls inside itself.
- **Footer.** Every page ends with a fixed footer: version, cluster state, uptime
  and load of each core, the configuration revision and the newest event. The dot
  beats every two seconds while fresh cluster data arrives: green when all is
  fine, amber with warnings, red with an alert (the counts are those of the
  Overview's Needs attention card), grey and still when the data is more than 30
  seconds old. The footer reads the cached cluster snapshot (`GET /api/footer`,
  answer cached 2 seconds while the UI is in use, 20 seconds when idle) and does
  not count as UI activity.
- **Update notice.** Off until someone with the edit-configuration role turns it on
  in the footer (`web.json` key `update_check`, absent means off). Once a day the
  web UI asks GitHub for the newest release and compares it with its own
  version; the footer shows "↑ x.y.z available" with a link to the release notes.
  "Got it" silences that version in that browser. The request is one GET with a
  generic user agent, no cookies and no cluster or user data; nothing is ever
  downloaded or installed, and a host without internet access shows "update: no
  answer" and carries on.
- **Probes page.** The results refresh in place every 20 seconds while the
  Results tab is open and the page is visible; nothing else on the page
  reloads, so typed text and the open tab stay. On the Behavior tab,
  *Default DNS probe checks* takes one check per line: `NAME|TYPE`,
  `NAME/TYPE` or `NAME TYPE` (a name alone means A). Types: A, AAAA, CNAME,
  PTR, TXT, MX, SRV, NAPTR, CAA; RAW is refused because the probe cannot
  query it. At most 100 checks; international names are written in
  punycode (`xn--`). The box is checked while you type, and a refused
  save keeps your text and names each bad line. A blank box means the
  built-in `claude.ai.|A`; once any check is listed, only your list is used.
- **Nodes** are onboarded, replaced or offboarded from Cluster settings
  (also staged); a new host's join code is required.
- **Backups:** Back up now, automated encrypted backups replicated to
  peers, restore from a node or an uploaded file.
- **Users** (Security → manage users, admins only): `admin` can change
  everything; `scopeadmin` can change everything served to clients
  (scopes, DHCP/DNS settings, templates, local domains) and commit only
  when every staged change is within those rights; `readonly` can view.
  Users, password-reset links and mail settings are replicated between
  the cores' web UIs and apply without a commit.

## Access list

Cluster settings, Access: one list of who this cluster serves, for DNS, DHCP
and the web interface. The private networks (10/8, 172.16/12, 192.168/16 and
fc00::/7) are allowed by default and can be switched off. Other networks
are added in CIDR form; every entry allows or denies DNS, DHCP and the web
interface on its own, and the most specific entry decides (on equal size,
deny wins). Whitelisted hosts are served before any entry: by address for
DNS and the web interface, by MAC for DHCP (a DHCP client has no source
address yet, so DHCP is judged by the client's network, the scope's
subnet). A source that is not allowed gets no answer: the DNS relay drops
the query, the DHCP relay drops the request, the web interface closes the
connection.

- **Report only first.** The mode is *Report only* until someone switches it
  to *Enforce*: nothing is dropped, and the relays and the web interface
  count the sources that would have been dropped (page *Report and test*).
  Enter a network in the list before enforcing; a scope's own subnet is not
  added for you.
- **Always allowed.** Loopback, every scope's VIP, gateway and node
  addresses, the management VIP and the peers are served no matter what, so
  the cluster cannot cut itself off. A change that would cut the operator
  off from the web interface is refused.
- **Switches on with the last core.** The list is stored at once but handed
  to the relays and the web interface only when every configured core runs
  a version that has it (`GET /api/v1/access` names the cores that hold it
  back). An older web interface that does not know the list leaves it
  unchanged when it commits.
- **Behind a reverse proxy** the web interface sees the proxy's address, not
  the client's; forwarded-for headers are not trusted.
- The dropped-source tables hold at most 256 sources per relay; the list holds
  at most 1000 networks and 5000 hosts.

## Path beacons

Two kinds of beacons, both signed with the cluster PSK, watch the paths
between the cores:

- **Trunk beacons** (UDP port 9446, broadcast on every trunk interface,
  every 5 seconds) show which trunk interface of one core sees which
  interface of another; the Cluster paths card is built from them.
- **VLAN path beacons** (UDP port 9447, a routed unicast request and reply
  per scope and peer) check that a scope's VLAN works between the cores.
  One scheduler sends them, at most 10 per 100 ms. A healthy path is probed
  every 10 seconds; a path that missed a reply is probed again after about
  a second, and three misses in a row mean unreachable (a warning in the
  log and a local sanity check). An unreachable path is probed every
  5 seconds to notice its recovery. A scope that is rebuilt, or a trunk
  that goes up or down, probes its paths at once. With very many scopes
  the interval stretches by itself (a warning names it) instead of the
  beacons falling behind.

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
- clock skew between this host and a node (measured against the moment
  the data was fetched, flagged after two fresh readings in a row over
  5 seconds)
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
| `/api/v1/access` | (admin) whether the access list is switched on, which cores hold it back, the list, and what the relays report |
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
`tools/snmp/README.md`. Per node, the extends `dnshived-health` (script
`dnshived-node-health`: state, serving count, epoch, generation, version) and
`dnshived-scopes` (script `dnshived-node-scopes`: served scopes). Cluster-wide:
`dnshived-cluster-check <node-ip>:9443`, exit codes 0=OK, 1=WARNING, 2=CRITICAL.

## Log levels

`log_level` in `cluster.json` (Cluster settings in the web UI):

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
