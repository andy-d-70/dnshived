# Cookbook

Copy-pasteable recipes for operational tasks that are not a single
button in the web UI.

## Reset a lost web-UI password

Only a PBKDF2 hash is stored, so a password cannot be shown, only
reset. In order of preference:

1. "Forgot password?" on the login page mails a reset link (needs the
   user's email address and Security → Mail & reset).
2. An admin sets a new password on the Users page.
3. On any core node (also re-enables a disabled account):

```sh
sudo /usr/local/bin/dnshived-web -reset-user admin     # prompts; or -password '...' (must meet the password policy, docs/SECURITY.md)
```

Users are replicated: the change reaches the other cores within seconds,
no restart needed.

## Remove a scope

Delete it on the Scopes page and commit on Pending changes. The scope
is torn down live, without a restart: VLAN interface, DHCP gate rule,
rendered files. Confirm:

```sh
sudo journalctl -u dnshived -n 50 | grep AGENT:DECOMMISSION
```

A hand-edited `cluster.json` needs `systemctl restart dnshived`; the
removed scope is then torn down at startup
(`DecommissionRemovedScopes`). Mechanics: `docs/SCOPE_LIFECYCLE.md`.

### Host-driven orphan sweep

Besides the config diff above, every node compares what actually
exists on the host (interfaces under the `Platform.Workers` trunks,
`dnshived-dnsmasq@*` units) with what
`cluster.json` says should exist, and removes the rest. It runs on
every plane-health tick, on every commit, and when a scope beacon loses
a peer, so stray interfaces need no manual cleanup. `Platform.Mgmt` is
never touched.

It does not run in bootstrap mode (no agent runs there); see the next
recipe.

## Return a node to bootstrap mode

Use **Offboard** on Cluster settings → Nodes and commit. The node tears down its
scopes, wipes its config and restarts in bootstrap mode with a new join
code; the survivors drop it from their peer lists.

If the node can't be offboarded through the cluster, do it by hand, in
this order, so nothing is left running unmanaged:

```sh
# 1. Remove every scope from this node's own configuration (keep everything
#    else) and restart normally, so the scopes are torn down. A node keeps its
#    configuration split; to edit it by hand write it out as one file first
#    (dnshived --config /etc/dnshived/cluster.json --print-config > cluster.json,
#    edit, copy it to /etc/dnshived/cluster.json as the dnshived user): the file
#    wins and is migrated again at the start.
sudo systemctl restart dnshived
sudo journalctl -u dnshived -n 100 | grep AGENT:DECOMMISSION
ip -o link show | grep '@'          # no VLAN sub-interfaces left

# 2. Only then remove the config (if the cluster had a management VIP,
#    its own keepalived keeps announcing it until it is stopped):
sudo systemctl stop dnshived dnshived-helper dnshived-web dnshived-keepalived-mgmt
ip -o addr show | grep -F "<the management VIP>"   # nothing may be left
sudo rm -rf /etc/dnshived/cluster.json /etc/dnshived/cluster.json.d /etc/dnshived/cluster.json.pre-split /etc/dnshived/webui-users.json /etc/dnshived/web.json
sudo systemctl start dnshived
```

Don't delete `/var/lib/dnshived` before step 1: its
`known-scopes.json` is what the teardown works from.

## Probe your own DNS names

The probe host asks every scope's DNS for a name and compares the answer. By
default it asks for `claude.ai.` (type A). To check names of your own:

1. Open **Probes → Behavior**.
2. Under *Default DNS probe checks* write one check per line, for example

   ```
   claude.ai.|A
   orf.at|A
   ```

   `orf.at/A` and `orf.at A` work too, and a name alone means A. A list that
   is not empty replaces the default, so keep `claude.ai.|A` in it if you still
   want that check.
3. The line under the box says `2 checks OK` or names the first bad line.
4. Save, then commit on Pending changes.

Every check runs against every scope, so use names that every scope can
resolve; a name only one scope's own DNS records know fails on the others.

## Probe host VLAN coverage

A probe host can only test a scope if it has an interface on that
scope's VLAN. Adoption writes everything needed into `probe.json`
(`trunk_parents`, `local_octet`, `probe_helper_socket`,
`known_vlans_path`), and `dnshived-probe` then creates and removes its
VLAN interfaces on every sweep to match the cluster's scopes. Changes
show as `[PROBE:VLAN]` log lines.

Check that the probe host's trunk NICs are administratively up; on
some cloud images only the management NIC is:

```sh
sudo ip link set <trunk-nic> up
```

If this host's NIC names differ from the cluster's, override the
helper's allowed trunks with a drop-in:

```sh
sudo mkdir -p /etc/systemd/system/dnshived-probe-helper.service.d
sudo tee /etc/systemd/system/dnshived-probe-helper.service.d/trunk-parents.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/local/bin/dnshived-probe-helper --socket /run/dnshived/probe-helper.sock --trunk-parents ens19,ens20
EOF
sudo systemctl daemon-reload
sudo systemctl restart dnshived-probe-helper
```

Fallback without `local_octet`: `tools/probe-host-vlans.sh <octet>
[vlan-start] [vlan-end]` pre-creates a fixed range (additive only),
optionally at boot via `dnshived-probe-vlans@<octet>.service`.

A single probe host is the normal case and probe hosts are optional.

## Put dnshived-web behind a reverse proxy

Every link the web UI renders is a relative path, so a proxy that
forwards to a node's HTTPS listener **without a path prefix** works
as is. A path prefix (`/dnshived/...`) is not supported.

With a management VIP configured, the web UI redirects requests whose
`Host` is not the VIP. Allow the proxy's hostname in `web.json` on
every core node:

```sh
sudo jq '.external_hosts = ["ops.example.com"]' /etc/dnshived/web.json \
  | sudo tee /etc/dnshived/web.json.tmp >/dev/null \
  && sudo mv /etc/dnshived/web.json.tmp /etc/dnshived/web.json
sudo chown dnshived:dnshived /etc/dnshived/web.json
sudo systemctl restart dnshived-web
```

The allowlist is explicit; nothing is derived from
`X-Forwarded-Host`.

## Two of three cores are gone: keep the last one serving

With the outage rules on (see `docs/OPERATIONS.md`) a node that sees fewer
than a strict majority of the configured cores refuses configuration
changes (`no_quorum`), and a restarted node waits up to 30 seconds for a
peer before it serves its own configuration unverified. If the other cores
are gone for good, make the surviving node the only member. Do this only
when you are sure the others are not still running; if they are merely cut
off, they keep serving and the same scope can be answered twice.

```sh
sudo dnshived --force-standalone     # shows what it will change, asks for the cluster id
sudo systemctl restart dnshived
```

The command removes the node's peers from `cluster.json`, raises its
membership epoch by one and writes a `cluster.force_standalone` line to
the audit log. Nothing else in the configuration changes.

When a core that was away comes back, it sees the higher epoch, stops
serving and shows `OUTAGE HOLD ... removed while away` on the Overview
page. Re-adopt it from the standalone node (Cluster settings → Nodes,
replace or onboard) so it takes over the standalone node's configuration and epoch.


## Where the configuration lives, and the way back

From 0.9.8.10 a node keeps its configuration in `/etc/dnshived/cluster.json.d/` (a manifest and one
part per domain and scope), and the single `cluster.json` is gone; a copy of it from the moment of the
migration stays as `cluster.json.pre-split`. Everything that used to read the file reads the same
document through the daemon:

```sh
sudo dnshived --config /etc/dnshived/cluster.json --print-config        # the one JSON document
sudo dnshived --config /etc/dnshived/cluster.json --check-config        # validates either format
```

Edit by hand: print the document to a file, edit it, put it at `/etc/dnshived/cluster.json` (owner
`dnshived`, mode 0600) and restart. A single file next to the directory wins, and the start migrates it
again. Go back to one file for good, for example before installing an older version, by starting the
daemon once with `--config-format single` (a systemd drop-in with `ExecStart=` and
`ExecStart=/usr/local/bin/dnshived --config /etc/dnshived/cluster.json --config-format single`), or
by restoring `cluster.json.pre-split` and removing `cluster.json.d`. A node on a version older than
0.9.8.10 cannot read the split directory; the cluster reports such a node.
