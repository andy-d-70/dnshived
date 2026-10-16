# Scope Lifecycle

How a scope (one VLAN's DHCP/DNS service) is built when added to the
config and torn down when removed. For what a scope is and who may
serve it, see `docs/ARCHITECTURE.md`.

## Two paths

```
web UI change + commit (normal path)
        │
        ▼
  HotReloadScopes()              live, no restart
  ├─ removed or physically changed scope (parent, VLAN, node IP):
  │  torn down now
  ├─ added or rebuilt scope: built on the next reconcile tick
  └─ other field changes: re-rendered, no interface rebuild

hand-edited cluster.json, binary upgrade, manual restart
        │
        ▼
  systemctl restart dnshived
  1. DecommissionRemovedScopes()   tear down what is gone
  2. ConstructPlane()              build what is configured
```

Writing `cluster.json` by hand changes nothing until a restart. Both
paths use the same idempotent primitives (`createInterface`,
`deleteInterface`), and both log the same markers. Cluster-wide fields
(`Platform`, `MgmtVIP`, PSK, tokens, TLS) are not scope changes; the
few that need a restart are flagged on Pending changes.

## Desired vs actual

| File | Written by | Purpose |
|------|-----------|---------|
| `cluster.json` `.scopes` | operator (web UI or by hand) | **desired** state |
| `/var/lib/dnshived/known-scopes.json` | the daemon, on every startup and hot reload | **actual** state: what this node last built (`parent` + `vlan_id` per scope) |

At startup, anything in `known-scopes.json` but missing from
`cluster.json` is torn down. On a hot reload the old in-memory scope
set is diffed against the new one directly. Independently, the
host-driven orphan sweep removes anything on the host that no config
explains (`docs/COOKBOOK.md`, "Host-driven orphan sweep").

## Building a scope

For each configured scope, in name order (`constructScope`):

1. Close the scope's DHCP gate before the interface exists, so it is
   never up and ungated.
2. Create the VLAN sub-interface `<parent>.<vlan_id>`, bring it (and
   the parent trunk) up, assign the node IP. The scope's name is added
   to the helper's allowlist first (`add-scopes`).
3. Mark the scope ready.

Then the shared, per-node configs are re-rendered to include it: the
consolidated keepalived config (one VRRP instance per scope), the DHCP
relay, the DNS relay, the central DHCP and DNS dnsmasq. These are
rebuilt from the full scope set each time, not patched.

The gate stays closed until the authority predicate decides this node
should serve the scope. Building the plane and being allowed to answer
DHCP on it are separate decisions.

A failed step leaves the scope not ready; the reconcile loop retries it
every tick. The plane-health check uses the same path for later drift
(a deleted interface, a failed unit).

## Tearing a scope down

1. Remove the scope's DHCP gate rule and delete its VLAN interface (the
   address goes with it).
2. Remove leftover per-scope files and units from builds before the
   relay architecture, if any.
3. Re-render the shared configs without the scope.
4. Rewrite `known-scopes.json`.

The helper's allowlist only grows, so a removed scope's name stays in it
and teardown is never refused.

## Verifying either direction

| Direction | Log marker | Also visible via |
|-----------|-----------|-------------------|
| Hot reload | `AGENT:HOT_RELOAD` | event log |
| Creation | `AGENT:PLANE` | `/api/v1/status` `ready`; Scopes page |
| Removal | `AGENT:DECOMMISSION` (startup) | `/api/v1/events`, `journalctl -u dnshived` |
| Later drift | `AGENT:DRIFT` / `AGENT:HEALED` | `/api/v1/status` `plane_warnings` |

```sh
sudo journalctl -u dnshived -n 50 | grep -E 'AGENT:(HOT_RELOAD|PLANE|DECOMMISSION|DRIFT|HEALED)'
```

Both directions are safe to repeat: construction is idempotent and
retried until it succeeds; tearing down something already gone does
nothing.
