# Recovery

What to do when things break.

## One node lost

**Symptom:** one node unreachable; the other two still see each other.

**What happens:** witness tokens need 2-of-3 agreement, so two nodes
keep serving every scope. Scopes owned by the lost node move to a
survivor once its witness token expires (~15 s). No action needed to
keep service running.

**To restore:** if the node comes back, it rejoins on its own. To
replace it with a new host:

1. Install the dnshived package on the new host. Without a config it
   starts in bootstrap mode; read its join code with
   `journalctl -u dnshived | grep "join code"`.
2. In the web UI's Cluster Config page the new host appears among the
   discovered nodes (or enter its address). Use **Inspect** to check
   it, then **Onboard as** the missing role (or **Replace** an occupied
   one) with the join code. The change is staged; commit it on Pending
   changes.

The surviving nodes push the cluster config to the new host and update
their peer lists; nothing is copied by hand. A preferred node that
returns holds until a rebalance is approved
(`docs/DESIGN_DECISIONS.md`, "operator-approved rebalancing").

## Two nodes down, one up

**Symptom:** one node STABLE but serving nothing (no quorum: 1/3).

**What happens:** correct behavior. Nobody can prove exclusive
ownership, so nothing is served.

**To restore:** bring at least one more node back. Scopes are served
again after the settling window.

## Network partition

**Symptom:** a node can't reach another directly, but both are up.

**What happens:** the witness protocol prevents dual-active regardless:
only the holder of a scope's token, granted on 2-of-3 agreement,
serves it.

**No action needed.** When the partition heals, the cluster converges.

## Complete cluster loss

Rebuild on fresh hosts: install the package on all three, found a new
cluster on one with the setup wizard and onboard the other two. If you
have a backup (web UI **Back up now** or automated backups; encrypted
with the password you set), use **Restore from a backup file** on the
new cluster to bring back the configuration, and optionally the DHCP
lease and trunk-reliability history.

Without a backup, scopes and settings have to be entered again; the
old PSK cannot be recovered, and a new cluster gets a new one.

## Daemon killed or crashed, host still up

**What happens:** the network plane (VLAN interfaces, relays,
keepalived) keeps running without the daemon. `ExecStopPost` closes
the node's DHCP gates on the way out, also on a crash. On restart the
daemon finds the plane in place and only confirms it; anything
disturbed while it was down is detected and rebuilt by the plane-health
check within seconds (`AGENT:DRIFT`, then `AGENT:HEALED` in the event
log).

**No action needed.** To force-kill and keep the gate safety net, use
`systemctl kill --kill-who=main -s KILL dnshived`, not a plain
`systemctl kill -s KILL` (see `docs/DESIGN_DECISIONS.md`, "A stopped
daemon closes its gates").

## Total node death (power loss, kernel panic)

**What happens:** nothing on that host runs any more, so nothing is
left to answer DHCP from it. The survivors take over once its witness
token expires (~15 s), the same bound as for any node that goes
silent. VRRP moves VIPs on its own, faster.

**No action needed.** See `docs/DESIGN_DECISIONS.md`, "Total node
death", for why there is no faster path.

## Lost web UI password

"Forgot password?" on the login page mails a reset link when the user
has an email address and mail is configured; an admin can also set a
new password on the Users page. Without either, run on any core node:

```sh
sudo /usr/local/bin/dnshived-web -reset-user <name>     # prompts for the new password
```

Users are replicated to every core, so once is enough and no restart is
needed. A logged-in user changes their own password on the Password
page.

## Management VIP not reachable

**What happens normally:** the management VIP is a separate,
static-priority 3-way VRRP instance (core-3 preferred), independent of
the scopes and of `dnshived.service`. If its holder goes down, the next
node takes it over in about 2 s, with no re-login.

**To diagnose:** check `systemctl status dnshived-keepalived-mgmt` on
all three nodes (it only runs where `mgmt_vip` is configured). Each
node's web UI is also reachable directly on its own address at port
8443.

## Config validation failure

```sh
dnshived --check-config --config /etc/dnshived/cluster.json
```

Reports all errors and warnings. Fix the config, re-validate, restart.

## Fencing watermark ahead of epoch

**Symptom:** after many rapid restarts, a node passes every check
except "unfenced".

**What happens:** the node waits until its epoch passes the watermark,
within a few reconcile ticks.

**No action needed.** This is the fencing mechanism working: a node
that was recently partitioned does not serve with stale state.
