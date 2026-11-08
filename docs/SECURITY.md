# Security

SELinux (CentOS/Rocky) and AppArmor (Ubuntu) behavior is covered in
`docs/OS_COMPATIBILITY.md`; no custom policy is needed.

## Trust boundaries

```
Network
    │  HTTPS (self-signed by default)
    ▼
API layer: Bearer tokens with roles; peer endpoints PSK-signed and
           limited to trusted_hosts
    │  in-process calls
    ▼
Control plane (user dnshived): authority predicate, reconciliation loop
    │  Unix socket (JSON, scope allowlist)
    ▼
Helper (root): ip, nft, systemctl
    ▼
dnsmasq, keepalived, relays (data plane)
```

Each boundary trusts only the layer above it, and only for specific
operations.

## TLS

The founding wizard generates a self-signed certificate for the core
API (9443) and the web UI (8443). To use your own, set
`tls_cert`/`tls_key`:

```json
{
  "tls_cert": "/etc/dnshived/tls/cert.pem",
  "tls_key": "/etc/dnshived/tls/key.pem"
}
```

Client tools support `-tls` and `-tls-skip-verify`.

Every probe serves its API over HTTPS (9445) with its own self-signed
certificate, which the web UI pins by its SHA-256 fingerprint. When a probe
host is adopted it reports the fingerprint with a proof made from the join
code, the web UI pins it at once and then closes the probe's plain HTTP port
(9444) once the pinned API answers (`plain_http` in `probe.json`; absent means
open, so a probe adopted by an older release keeps working until it is
pinned). A probe adopted earlier is pinned from the Probes page: the probe's
public `tls-info` call, asked with a fresh nonce, returns a proof made with
each of its admin tokens, and the web UI recomputes it. Right after pinning, the
web UI replaces the probe's admin token over the pinned connection
(`POST /api/v1/rotate-token`, TLS only), because the old token was sent in
cleartext while the probe was not pinned. A certificate of your own can be
installed from the Probes page (the key travels only over the pinned
connection and is checked on the probe); the new fingerprint is pinned and the
probe serves the new certificate without a restart. `dnshived-top` and
`dnshived-validate` take the fingerprint with `-probe-pin host:port=sha256:...`.
A regenerated certificate (after a self-decommission or a state wipe) must be
pinned again.

## API authentication

Bearer tokens with roles, in `cluster.json`:

```json
{
  "api_tokens": [
    { "name": "monitoring", "token": "<hex>", "role": "readonly" },
    { "name": "operator",   "token": "<hex>", "role": "admin" }
  ]
}
```

| Role | Grants |
|---|---|
| `readonly` | every GET endpoint |
| `admin` | readonly plus every write endpoint (config, candidate, backups, node actions, audit) |
| `probe` | what a probe host reads (`/api/v1/probe-config`, token status) |
| `probe-admin` | the admin token a probe host's own API accepts |

A founded cluster always has tokens. Endpoints exempt from Bearer
tokens, because they carry their own authentication:

- `/api/v1/ping`: peer handshake. The response is HMAC-SHA256-signed
  with the cluster PSK (`X-Dnshived-Ping-Sig`) and verified before the
  peer's identity is trusted, so a spoofed peer cannot inflate the
  fencing watermark.
- `/api/v1/token/request`, `/api/v1/token/renew`: witness protocol,
  PSK-HMAC with nonce and timestamp window.
- `/api/v1/coord/config/relay`: coordination-plane relay, PSK-HMAC with
  nonce and timestamp window.
- `/api/v1/leasesync`, `/fingerprint`, `/snapshot`: peer lease sync.

Ping, the witness endpoints and lease sync also only accept callers
listed in `trusted_hosts` (the peers' addresses).

Client tools read a token from `-token-file <path>` or the
`DNSHIVED_TOKEN` environment variable, never from a command-line
argument. `dnshived-top` and `dnshived-status` also read defaults from
`~/.dnshived/rc`, which must be mode `0600` or it is refused:

```sh
# ~/.dnshived/rc
addr=<node-ip>:9443
tls=true
tls_skip_verify=true
token=<the readonly "monitoring" token from the founding wizard>
probe_addr=<probe-ip>:9444
probe_name=probe
```

## Cluster PSK

The PSK (`psk`, required) authenticates nodes to each other: witness
tokens, ping responses, the coordination-plane relay. API tokens
authenticate operators and tools. Founding generates it; to create one
by hand use `openssl rand -hex 32`. The HMAC construction lives in one
place, `internal/psksign`.

## Coordination-plane config relay

Every core node registers two routes when a PSK is configured:

- `POST /api/v1/coord/config`: the entry point, admin token required,
  exactly as privileged as `POST /api/v1/config`.
- `POST /api/v1/coord/config/relay`: node-to-node only, PSK-HMAC signed
  with anti-replay, never relays further.

The payload is one already-derived document per target node, built by
`dnshived-web`. Used only when `WebConfig.CoordinatorNode` is set;
otherwise the web UI pushes to each node directly.

## Web UI (`cmd/dnshived-web`)

A separate binary that talks to each node's API like any client, with
its own admin token. It never writes `cluster.json` itself.

- **Credentials** live in `webui-users.json`, separate from
  `cluster.json`: PBKDF2-HMAC-SHA256 (Go stdlib), 16-byte salt, 600,000
  iterations, constant-time comparison, stored as
  `salt:iterations:key`. Passwords set in the web UI, with `-reset-user` or
  with `-hash-password` follow one policy: at least 12 characters (an
  admin can set 8 to 64 on the Users page), an uppercase letter, a digit,
  a special character, five different characters, no simple sequence
  (`abcd`, `1234`, `qwer`), no repeated block, and not the user name, the
  mail address's local part or the host name. Strength is judged by length
  and variety; passwords are not checked against lists of known passwords.
  Existing passwords keep working; a login with one that does not meet the
  policy logs a line and first shows the change-password page, with a link
  to continue without changing. The same policy applies to a backup
  password set in the web UI. API tokens typed on the Security page need
  at least 32 characters, 10 different characters, no whitespace and no
  simple sequence or repeated block (existing tokens are only checked when
  changed). The mail server password is not checked: it belongs to the
  mail server. A stored hash is used only with a 16 to 64 byte salt,
  a 1 to 64 byte key and 1 to 1,200,000 rounds. Roles: `admin` (everything), `scopeadmin` (everything served to
  clients; commits refused when a staged change is outside that) and
  `readonly` (view, audit). Disabled users cannot log in.
- **Replication:** the whole users document (users, reset-link hashes,
  session key, mail settings) carries a revision and is pushed between
  the cores' web instances over `/internal/auth-doc` (cluster admin
  token, pinned cluster certificate); each instance compares with the
  others every 60 s. The higher revision wins; a node that never
  replicated merges its own users in instead of losing them. The
  revision stamp carries a hash of the content; two different documents
  with the same revision are logged and audited as `doc.conflict`, and
  one is still chosen by timestamp and origin. A received document is
  refused (HTTP 400) when its revision is out of range or it is
  oversized (more than 2,000 users, 20,000 reset tokens, fields over
  8 KiB). The probe-host list of `web.json` is replicated the same way
  over `/internal/docs/probe-hosts`, TLS only, with the same token.
- **Sessions:** a login form issues an HMAC-SHA256-signed cookie
  (`HttpOnly`, `SameSite=Lax`, `Secure` over TLS) naming the user and a
  per-user session epoch; it is valid on every core (shared key), for
  30 minutes idle and 12 hours at most. A password, role or status
  change and "sign out everywhere" bump the epoch, which ends every
  existing session at once. HTTP Basic credentials sent unprompted are
  still accepted for scripts; browsers are never challenged for them.
- **Password reset by email:** 256-bit single-use link, valid 30
  minutes, stored only as SHA-256, the same answer for unknown users,
  at most 3 requests per 15 minutes per client and per user. Security
  notifications go to the user on password, role and status changes.
  The SMTP password is write-only and is reused only while server and
  login stay unchanged. Console fallback:
  `dnshived-web -reset-user <name>` on any core (root needed).
- **Never root:** runs as `dnshived`, with only
  `CAP_NET_BIND_SERVICE` for the redirect ports 80/443.
  `dnshived-web-helper` (root, Unix socket) does its one privileged job,
  restarting `dnshived-web`.
- **Config writes** go through the candidate/commit path: the node
  validates (`ValidateExtended()`) before saving. There is no
  distributed transaction; a partial failure is shown to the operator,
  and Overview flags nodes whose config hashes differ.

## Management VIP

A separate static-priority VRRP instance for reaching the web UI, not a
scope: no gate, no witness. A momentary dual answer for HTTPS admin
traffic carries no corruption risk, so it gets none of the DHCP
machinery. Its `vrrp_id` is checked for uniqueness together with the
scopes' `vrrp_id`s.

## Audit log

`internal/auditlog`: append-only NDJSON (`{ts, actor, node_id, action,
summary}`) in `/var/lib/dnshived/audit.log`, rotated past 10 MB. The web
UI writes an entry after every config change via `POST /api/v1/audit`
(admin token); `node_id` is set by the receiving daemon, never taken
from the request. `GET /api/v1/audit` exports it. No cryptographic
integrity: a node compromised enough to falsify it is already trusted
for everything else.

## Privilege separation

`dnshived` runs as user `dnshived`; every privileged operation goes
through `dnshived-helper` (root), the only dnshived component that runs
as root. There is no direct mode: without `helper_socket` in the config
the daemon uses the default `/run/dnshived/helper.sock`. The helper logs
every operation and rejects unknown commands.

| Commands | Validation |
|---|---|
| `create-interface`, `delete-interface`, `stop-dnsmasq`, `restart-dnsmasq`, `set-dhcp-gate`, `get-dhcp-gate`, `get-vrrp-state` | scope must be in the allowlist |
| `delete-interface-unscoped`, `stop-dnsmasq-unscoped` | orphan teardown for names with no scope; interface/unit name checks only |
| `add-scopes` | grows the allowlist (never shrinks); scope-name format only |
| `ensure-keepalived`, `reload-keepalived`, `vrrp-dump`, `dhcp-gate-dump` | not scope-parameterized |
| `restart-relay`, `reload-relay`, `stop-relay`, `restart-dnsrelay`, `reload-dnsrelay`, `stop-dnsrelay` | not scope-parameterized |
| `restart-core-dhcp`, `reload-core-dhcp`, `restart-core-dns`, `reload-core-dns` | not scope-parameterized |
| `ensure-`, `reload-`, `restart-`, `stop-mgmt-keepalived`, `get-mgmt-vrrp-state` | mgmt VIP only |
| `restart-daemon`, `restart-helper`, `restart-web` | operator actions from the web UI |
| `journal-tail` | fixed unit allowlist |
| `link-up` | interface name format, interface must exist; only ever brings a link up |
| `remove-gate-rule-unscoped` | orphan gate rule with no scope; interface name format only |
| `manage-unit` | fixed action/unit list: `enable-now` dnshived-web, `enable` dnshived-helper, `disable-now` the probe, relay, keepalived and web units and any `dnshived-dnsmasq@` instance (adopt and self-decommission) |
| `reset-scope-state`, `finish-decommission` | self-decommission: drop the `add-scopes` allowlist, schedule the restart into bootstrap mode, stop the helper |

Restarts and reloads are rate-limited (reloads at most once per second,
restarts once per 5 s, daemon/helper restarts once per 10 s); a
suppressed call reports `throttled: true` instead of success.

`add-scopes` is called before every interface construction so a scope
added through the API needs no manual allowlist step. Consequence: an
admin API token alone is enough to get a new scope's interface built;
it is the same authority that writes `cluster.json`.

`dnshived --emergency-close-gates` (`ExecStopPost=+`, run as root) asks
the relay to revoke every scope over its gate socket. The relay's own
authorization deadline closes a scope if that call does not arrive.

## VRRP authentication

Each scope's VRRP instance and the management VIP authenticate their advertisements with keepalived's PASS type. The password is derived from the cluster PSK with HKDF-SHA256, per instance, and is eight characters (the VRRP limit). Without it, any host on a VLAN could take a VIP by sending advertisements with a higher priority. PASS sends the password in clear text on the segment, so it stops casual spoofing; it does not stop a determined attacker who can read the segment. AH is available in keepalived but marked "not recommended" in its manual. The rendered configs are owner-only (`0600`).

## Command line and user checks

Every binary parses its flags strictly: an unknown flag or a stray argument prints one line and the usage, and exits 2. The daemons check that they run as their service account and refuse root. The root helpers check that they run as root. Only the tools that can need root may run as root (the list is in the changelog); `dnshived-top` refuses root. A second copy of a daemon or helper refuses to start while the first holds its lock file, and a socket path is replaced only when nothing answers on it. These checks guard against mistakes; they are not a boundary against root.

## Systemd hardening

- `dnshived.service`: `User=dnshived`, only `CAP_NET_BIND_SERVICE`
  (bootstrap mode's setup wizard on :80/:443), `NoNewPrivileges`,
  `ProtectHome`, `ProtectKernelTunables`, `ProtectControlGroups`,
  `RestrictRealtime`, `LockPersonality`.
- `dnshived-helper.service`: root, `NoNewPrivileges`, `ProtectHome`,
  `ProtectKernelTunables`, `ProtectKernelModules`; `Group=dnshived` for
  its socket. Writes to `/proc/sys/net/ipv4/conf` only (`rp_filter` on
  trunk parents); the rest of `/proc/sys` stays read-only. No
  `PrivateTmp`: keepalived writes its state dump to the host's
  `/tmp/keepalived.data`, which a private `/tmp` would hide.
- `/run/dnshived` is `root:dnshived 1775`: the daemon creates its lease
  socket there, the sticky bit keeps it from replacing keepalived's
  root-owned PID files (which the helper signals).
- keepalived (scope and mgmt units): root, limited to `CAP_NET_ADMIN`,
  `CAP_NET_RAW`, `CAP_NET_BROADCAST`, `CAP_KILL`.
- dnsmasq runs as `dnshived` from the start, with `CAP_NET_BIND_SERVICE`,
  `CAP_NET_ADMIN`, `CAP_NET_RAW`; its lease script runs as `dnshived`
  too.
- keepalived and dnsmasq set no `NoNewPrivileges`: under SELinux it
  blocks their transition into `keepalived_t`/`dnsmasq_t`, and in the
  unit's `init_t` they cannot open VRRP sockets or their PID file.
- Relays, the probe daemon and the web UI run as `dnshived` with only
  `CAP_NET_BIND_SERVICE` and `NoNewPrivileges`; binding a socket to an
  interface needs no capability (Linux 5.7+, all supported systems have
  5.14+).
- `dnshived-web-helper`: root without any capability (its one command,
  `systemctl restart dnshived-web`, is authorized by uid 0 alone),
  `NoNewPrivileges`, `ProtectSystem=strict`.
- `dnshived-probe-helper`: root, limited to `CAP_NET_ADMIN`,
  `CAP_DAC_OVERRIDE`, `CAP_CHOWN`, `CAP_FOWNER`, `NoNewPrivileges`;
  `dnshived-probe-vlans@` to `CAP_NET_ADMIN`.

## LAN autodiscovery

A fresh host in bootstrap mode broadcasts a small announcement
(hostname, version, bootstrap port) every 5 s on UDP 9445; configured
core nodes listen. Deliberately unauthenticated, with a protected
management segment as the boundary:

- malformed packets are dropped silently;
- an announcement only adds an entry to a read-only, TTL-pruned list
  (`GET /api/v1/discovered-nodes`); onboarding still needs an operator
  action and the join code from the new host's console, which is never
  broadcast;
- a fake announcement can at most add a misleading row to that list.

## Threat model

| Threat | Mitigation |
|--------|-----------|
| Unauthorized API access | Bearer tokens, TLS |
| Token sniffing | TLS; `--check-config` warns about tokens without TLS |
| Forged witness tokens | HMAC-signed with the cluster PSK, 2-of-3 agreement |
| Spoofed peer handshake | PSK-signed ping responses, `trusted_hosts` |
| Privilege escalation via the daemon | privileged work only through the helper, scope allowlist |
| Rogue scope injection | helper allowlist; `add-scopes` means an admin token can extend it (same authority as writing `cluster.json`) |
| Partition-induced dual-active | witness protocol |
| Stale node serving after a partition | fencing watermark |
| Broadcast-delivered dual-active DHCP (VIP ownership does not stop broadcasts, `docs/DESIGN_DECISIONS.md`) | per-scope relay gate, closed by default, authorized only with a current witness token, old owner closed before new opens |
| Daemon forcing keepalived reloads | helper rate limits; anti-flap bounds legitimate reloads |
| Unauthorized config write via the web UI | admin role in `webui-users.json`, admin API token per node |
| Web UI credential leak on one node | same file on every node: treat as cluster-wide, as sensitive as the PSK |
| Dual answer on the management VIP during re-election | accepted: no corruption risk for HTTPS admin traffic |
| Falsified audit entries from a compromised node | not prevented; `node_id` is server-assigned |
