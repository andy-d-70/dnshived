# Operations

Daily operation, monitoring and troubleshooting. Most work happens in
the web UI; the command-line tools below are for terminals, scripts
and monitoring. Connection flags can be stored in `~/.dnshived/rc`
(`docs/SECURITY.md`, "API authentication").

## Web UI (`dnshived-web`)

Reachable at `https://<mgmt-vip>:8443/` or on any core node's own
address; ports 80/443 redirect there. Menu: the dnshived logo (Overview),
Scopes (list, topology view, defaults for new scopes), Probes (results,
manual probes, probe hosts, history, behavior), DHCP (hosts, client
simulator, default options, option sets), DNS, Security (users, API tokens,
mail and reset, password policy), Maintenance (backup, restore, export and
import), Cluster settings (nodes, interfaces, addresses, access list) and Logs
(general, audit, daemons, daemon logs), plus the Pending changes button, a
Theme button and the account menu (your name, change password, log out). Long
pages are split into tabs. Node colours are the same everywhere: core-1 purple,
core-2 teal, core-3 brown. The footer line shows the cluster state, per-core uptime and load, the DHCP readout (active clients in the scopes the cores serve, then reservations), the configuration revision and the newest event; fields drop out at narrower widths.

- **Changes are staged, then committed.** Every edit becomes a pending
  change on all nodes; nothing applies until you commit it on Pending
  changes, which shows a diff and warns if a change needs a restart.
  Scope changes hot-reload; see `docs/SCOPE_LIFECYCLE.md`.
- **Column widths.** Drag the edge of a header cell in any list table to resize its columns; the next column gives way and the table keeps its width. The widths are kept in this browser, per page (`localStorage`, keys starting `dnshived-cols|`), so another browser or a cleared browser starts with the built-in widths. The button in the table header (or under the table) and a double click on a handle reset it.
- **Node colour and nickname.** On Cluster settings, Nodes, the menu at the right
  of a node opens *Edit name and colour…*. The colour is a numbered dot (red 1,
  blue 2, white 3, purple for a probe host by default); tick *default colour* to
  go back to the default. The dot marks the node on every page that shows a node name. Both are cosmetic, are kept in `web.json` of every web
  instance and never change a node's identity.
- **Bulk edit in the domains editor.** Tick records (the header box takes the
  shown page; "Select all" takes every record of the current search) and choose
  an action in the bar above the list: set a TTL, follow the domain's TTL,
  include in or exclude from probe checks, set one value (only for A, AAAA,
  CNAME, PTR and TXT records), move or copy to another standalone domain, or
  delete. An overview lists what changes before anything is staged; a duplicate,
  a CNAME beside other data or an invalid result refuses the whole action with
  the reason. The Default TTL form has "records follow it", which clears every
  record's own TTL in that domain. Linked domains and the DHCP names list are
  read-only here.
- **Pending changes record who changed what.** When other admins have changes
  staged, Pending changes lists each admin's changes and offers *Commit my
  changes* and *Discard my changes*; the others' changes stay staged.
  *Commit everyone's* and *Discard everyone's* first show a warning that lists
  the other admins' changes and need the words COMMIT ALL or DISCARD ALL. A
  field is the unit: a setting, a scope option, a domain's default TTL or one
  record set (host and type). Two admins changing the same record set share
  it, and so does a record added to a domain that another admin added; such a
  unit counts as nobody's own and goes live only with *Commit everyone's*.
  Your own changes are refused when they would be invalid without a change of
  someone else. With an older daemon, or a configuration too large for the
  comparison, the page keeps the single *Commit all* button.
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
- **Blocked clients.** A second list cuts single clients off: by address for
  DNS, by MAC for DHCP. A block is enforced even in *Report only*, beats a
  whitelisted host and never beats an always-allowed address. Add one from the
  Hosts row menu (Block…) or on the Blocked clients tab; at most 200 entries,
  each with an optional note. Like the rest of the list it reaches the relays
  only when every core runs a version that has it.
- **Behind a reverse proxy** the web interface sees the proxy's address, not
  the client's; forwarded-for headers are not trusted.
- The dropped-source tables hold at most 256 sources per relay; the list holds
  at most 1000 networks and 5000 hosts.

## Hosts and the client simulator

**DHCP, Hosts** lists every client of every scope in one table: active leases,
reservations and hosts that answer ARP but have neither (shown as *Unknown
static*). Search covers name, MAC, address and scope; chips filter Dynamic,
Reserved and Unknown static. The row menu offers Reserve…, Make static… or Edit…
(one small window with the address, the name, the client identifier and the
extra names), Remove reservation…, Release, Block and Simulate.

- The reservation window refuses an address outside the scope's network, the
  network and broadcast address, the scope's own address and an address another
  reservation holds. A client keeps its current lease until it renews.
- **Reservations** carry the MAC, the address and the host name, optionally a
  DHCP client identifier (option 61, for clients that ask by identifier rather
  than by MAC) and up to eight extra DNS names. Extra names are served as A
  records for the reserved address; one may not repeat the host name, another
  extra name or another reservation's host name.
- **Check now and Check shown** ask the node that serves a scope which of the
  listed addresses answer ARP: it reads its neighbor table for the scope's VLAN
  and sends one UDP datagram to port 9 from its own VLAN address to make the
  kernel resolve the address. Up to 16 addresses of the scope's own network per
  call, one call per scope every two seconds, IPv4 only, no packet to anything
  outside the scope. A host that does not answer ARP (powered off, other VLAN)
  is simply not seen.
- **Type icons** come from the manufacturer prefix of the MAC (the public IEEE
  list, generated into the web interface by `tools/gen-oui.py`). A private
  (randomized) MAC gets no guess.

**DHCP, Client simulator** shows what a client would get in a scope without
sending anything: address (a reservation inside the scope's subnet, else the
current lease, else the pool), mask, gateway, DHCP server, lease time, DNS
servers, the other options, the names it is published under and the service
records (names starting with an underscore, such as the Dante Domain Manager
discovery records) its scope and the global list hold. Pick a client by MAC,
name or address and a scope (empty: its current one); three slots compare
clients or the same client in up to three scopes. A reservation for another
network is ignored there, and the page says so. The values come from the same
function the DHCP configuration is rendered from, so the page cannot disagree
with what the nodes serve.

## Export and import

**Maintenance, Export & import** exports the configuration in four modes: all
(everything, including keys and tokens, for your own safekeeping), cluster (without
scopes), scopes, and **data** (everything the cluster replicates, without keys, tokens,
certificates or node identity: the file to copy a configuration into another cluster).

**Import a file…** reads any of them, a `cluster.json` or an encrypted backup (enter its
password; only the configuration is read, not the leases or reliability history). Choose per group what to
take: scopes (per scope), local domains, global DNS records and DNS checks, DHCP
defaults, access list, settings and platform; for each group *merge* (the default:
keep what the file does not mention, add what is new) or *replace*. Platform and settings
are off by default. The overview lists what is new, changed, removed or skipped and why;
nothing is staged until you press Stage, and nothing applies until you commit.

- Keys, API tokens, certificates, trusted hosts, node identity and the backup password in
  the file are never used.
- Existing scopes are never touched. Scopes from the file arrive **parked**.
- The access list and the platform of a running cluster are kept unless you choose replace.

**Restore** (Maintenance, Restore) puts the data of a backup into the pending change of a running cluster. The cluster key, tokens, certificate paths, trusted hosts and backup password stay the running cluster's own; only the data comes back. A backup of another cluster is refused: use Import for that. The import's platform group also takes the management VIP of the file, so tick it only when that cluster is not running.

**Parked scopes** are kept in the configuration, but no VLAN interface, VRRP or DHCP/DNS
serving is built for them. The Scopes page lists them below the table: *Enable* (one),
*Enable all*, *Remove*. Each is staged as a pending change; enabling needs the usual scope
checks (VLAN, VRRP id, addresses) to pass.

**A new cluster from a file:** on the setup wizard's review step, upload the export or backup (with its password), choose
the groups and press Save choice before Create cluster. The new cluster has its own key,
tokens and certificates. After the creation: enable the parked scopes, pair probe hosts
again, use the new monitoring token, create the web users again and let the other cores
join with the new join code. *Restore* (keep the cluster ID) needs the word RESTORE; the
page warns when control addresses from the file still answer, because the original cluster
may still be running, and the decision is yours.

## DNS domains editor

**DNS** opens on the domains editor: the local domains on the left (with the number of records; a link mark for a linked domain) and the chosen domain's records on the right. The first row adds a record: pick the type (A, AAAA, CNAME, MX, TXT, SRV, PTR, CAA), the name (`@` for the domain itself), the value (MX and SRV have priority, weight, port and target fields) and an optional TTL. The list has search over name, type and value, sorting by name, type, value or TTL, and the shared page size; the chips show all records, the static ones or the names that DHCP reservations publish (read-only; edit those under DHCP, Hosts). A row's menu edits it as a line (`TYPE|NAME|VALUE…`, the format of the text editor) or deletes it. The entry *(DHCP names)* lists every name the reservations publish, short ones included.

- Every change is staged as a pending change, like all others. A record that duplicates another, or a CNAME beside other data at the same name, is refused with a message that names the record in the way.
- **Default TTL** (next to the domain actions) is the TTL of records without their own; empty uses the DNS server default. A linked domain follows its original.
- A **linked** domain answers with the records of its original and is read-only here; edit the original, the change is copied. *Link a new domain* makes one, *Unlink* turns a link into a standalone copy.
- **Import** takes a zone file (A, AAAA, CNAME, PTR, MX, SRV, TXT, CAA) or the editor's lines, pasted or loaded from a file (at most 512 KiB and 5000 lines), and lists each record as new, duplicate, conflict or skipped. Only the new ones are staged. **Export** downloads the domain as a zone file (`.zone`); `?format=lines` gives the editor's lines.
- **Apply a record set** adds the records of a record set (the shipped Dante Domain Manager, NMOS and NDI sets, or your own) to the domain: the set's example domain `fake.lan` and `{domain}` become the domain, and the same overview shows what is new, duplicate or in conflict first.
- **Make a record set…** (row menu of an A, AAAA or CNAME record) collects what belongs to that host: its records, the aliases that point at it, the SRV records whose target it is, the TXT records of those service instances and the PTR records that list them, and stores them as a record set in the example-domain form.
- **Mail records…** builds an SPF record (the domain's mail servers, extra hosts, the policy for everything else), a DMARC record (policy, report address, percentage, alignment) and a DKIM record (selector and public key). A name may carry only one SPF and one DMARC record, so a second one is shown as a conflict. A key longer than 255 characters is stored as one value and served in 255-character parts, which resolvers join.
- A DNS check that fails in the probe detail offers **Add to <domain>…** when a local domain holds the name; it opens this editor with the name and type filled in.

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


## Sizing

Measured on three cores with 2 vCPUs each, two of them with 1 GB of RAM and one with 2 GB, and 102 scopes
(`tools/loadgen.py` stages the synthetic data and removes it again):

| Configuration | Size | Daemon idle CPU | Pages | Notes |
|---|---|---|---|---|
| empty (102 scopes) | 25 KB | 8 to 12% of a core | 40 to 200 ms | |
| 2,550 reservations, 10,000 records | 1.7 MB | about 10% | 40 to 200 ms | |
| 6,120 reservations, 45,000 records | 6.2 MB | 4 to 7% | 20 to 170 ms | daemon 125 to 150 MB, web 100 to 130 MB RSS |
| 10,200 reservations, 100,000 records | 13 MB | 6 to 16% | 25 to 370 ms | daemon about 300 MB, web 200 to 315 MB RSS; a 1 GB node uses swap |

Addresses are answered from memory at every size (a lookup took 0 ms with 118,000 host records). What a large
configuration costs is memory and the work after a change: dnsmasq is restarted for the central DNS and needs about a
minute of CPU to read 100,000 records, a commit of a 7 MB configuration takes about 7 seconds, a daemon restart about 18
seconds. Plan 2 GB of RAM per core for more than about 5,000 reservations or 50,000 records; the web UI also keeps decoded
copies of the configuration (at most 32 MiB of JSON in total).
