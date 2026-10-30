# Cookbook

Copy-pasteable recipes for operational tasks that are not a single
button in the web UI.

## Reset a lost web-UI password

Only a PBKDF2 hash is stored, so a password cannot be shown, only
reset. In order of preference:

1. "Forgot password?" on the login page mails a reset link (needs the
   user's email address and Cluster config → Mail).
2. An admin sets a new password on the Users page.
3. On any core node (also re-enables a disabled account):

```sh
sudo /usr/local/bin/dnshived-web -reset-user admin     # prompts; or -password '...'
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

Use **Offboard** on Cluster Config and commit. The node tears down its
scopes, wipes its config and restarts in bootstrap mode with a new join
code; the survivors drop it from their peer lists.

If the node can't be offboarded through the cluster, do it by hand, in
this order, so nothing is left running unmanaged:

```sh
# 1. Remove every scope from this node's own cluster.json (keep everything
#    else) and restart normally, so the scopes are torn down:
sudo systemctl restart dnshived
sudo journalctl -u dnshived -n 100 | grep AGENT:DECOMMISSION
ip -o link show | grep '@'          # no VLAN sub-interfaces left

# 2. Only then remove the config:
sudo systemctl stop dnshived dnshived-helper dnshived-web
sudo rm -f /etc/dnshived/cluster.json /etc/dnshived/webui-users.json /etc/dnshived/web.json
sudo systemctl start dnshived
```

Don't delete `/var/lib/dnshived` before step 1: its
`known-scopes.json` is what the teardown works from.

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
