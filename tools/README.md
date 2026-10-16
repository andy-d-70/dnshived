# Tools

Everything here runs locally from the repo root, with no hardcoded
addresses and no external lab dependency.

## Build

```sh
make build          # core binaries into builds/ (dnshived, -helper, -status,
                    # -validate, -top, -dhcp-probe, -web, -web-helper, -probe,
                    # -probe-helper, -relay, -dhcp-lease-hook, -preflight)
make check-config   # validate cluster.json.example
make deb            # Debian package
make rpm            # RPM package (uses rpm-version.sh)
```

`dnshived-dnsrelay` is its own Go module (`cmd/dnshived-dnsrelay`, keeps
its `golang.org/x` dependencies out of the core) and is not part of
`make build`; build it with `go build` inside that directory.
`dnshived-dnsrelay-render` is in the core module but also not in
`make build` (`go build ./cmd/dnshived-dnsrelay-render`). `make deb` and
`make rpm` build both.

### rpm-version.sh

Derives the RPM `Version:`/`Release:` from the `debian/changelog` top
entry, like `FULL_VERSION` for the `.deb`. Called by `make rpm`.

### probe-host-vlans.sh

Pre-creates VLAN sub-interfaces on a probe host (fallback; normally
`dnshived-probe` manages them). Shipped in the packages.

## Testing — local, portable, safe to run anywhere

These three build local network namespaces to test the core safety
mechanisms directly. They need root.

### dhcp-gate-rig.sh

Reproduces DHCP dual-active and tests the nftables gate.

```sh
make build   # needs builds/dnshived-dhcp-probe
sudo ./tools/dhcp-gate-rig.sh baseline   # both workers open  → dual-active
sudo ./tools/dhcp-gate-rig.sh gated      # one nftables rule  → single server
sudo ./tools/dhcp-gate-rig.sh handoff    # drop-old-then-open-new → never dual
sudo ./tools/dhcp-gate-rig.sh down
```

Requires root (network namespaces + nftables). Uses `dnshived-dhcp-probe`,
which sends one `DHCPDISCOVER` and reports every `DHCPOFFER` in the
window — the only way to distinguish "one server via two relays" from
"two servers", which a normal DHCP client can't tell apart.

### vrrp-priority-rig.sh

Tests that rewriting `keepalived.conf`'s priority and sending SIGHUP
(as `ExecReload=` does) moves the VIP without a restart and without a
sustained dual-MASTER window. keepalived only, no dnshived code.

```sh
sudo ./tools/vrrp-priority-rig.sh up
sudo ./tools/vrrp-priority-rig.sh start        # a=100 (MASTER), b=50 (BACKUP)
sudo ./tools/vrrp-priority-rig.sh reload-swap  # a->1, b->100, SIGHUP both
sudo ./tools/vrrp-priority-rig.sh down
```

Requires root (network namespaces) and `keepalived`. Each worker's
`keepalived.log` under `run/vrrp-priority-rig/<a|b>/` shows the actual
VRRP state transitions — `Reload complete` followed by a normal
priority-comparison handover, not a restart.

### mgmt-vip-rig.sh

Tests management-VIP failover with real keepalived and two real
dnshived-web instances sharing one users file, and that a session
cookie from one side is accepted by the other after the VIP moves (no
re-login).

```sh
sudo ./tools/mgmt-vip-rig.sh up && sudo ./tools/mgmt-vip-rig.sh gen
sudo ./tools/mgmt-vip-rig.sh build-web && sudo ./tools/mgmt-vip-rig.sh start
sudo ./tools/mgmt-vip-rig.sh start-web && sudo ./tools/mgmt-vip-rig.sh verify
sudo ./tools/mgmt-vip-rig.sh down
```

## SNMP

Extend scripts for `net-snmp`'s `snmpd`; setup in `tools/snmp/README.md`.

### snmp/dnshived-node-health

SNMP extend script reporting node state, serving count, epoch, version.

### snmp/dnshived-node-scopes

SNMP extend script listing scopes served by this node.

### snmp/dnshived-cluster-check

Nagios-compatible cluster health check. Exit codes: 0=OK, 1=WARNING,
2=CRITICAL.

```sh
./tools/snmp/dnshived-cluster-check <node-ip>:9443
```
