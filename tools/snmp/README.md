# dnshived SNMP Integration

Extend scripts for monitoring dnshived via SNMP (Observium, LibreNMS,
Nagios).

## Per-node monitoring (on each core node)

### Installation

```sh
sudo cp dnshived-node-health dnshived-node-scopes /usr/local/bin/
sudo chmod +x /usr/local/bin/dnshived-node-*
```

snmpd runs as an unprivileged user (`Debian-snmp` on Debian) that
cannot read `cluster.json`, so give the scripts a readonly token in
their own file:

```sh
sudo tee /etc/dnshived/snmp-monitor.conf >/dev/null <<'EOF'
scheme=https
token=<a readonly API token, e.g. the "monitoring" token>
EOF
sudo chown root:Debian-snmp /etc/dnshived/snmp-monitor.conf
sudo chmod 0640 /etc/dnshived/snmp-monitor.conf
```

Without that file the scripts fall back to `cluster.json`, which only
works when run as root.

### snmpd.conf

```
extend dnshived-health /usr/local/bin/dnshived-node-health
extend dnshived-scopes /usr/local/bin/dnshived-node-scopes
```

Restart snmpd: `sudo systemctl restart snmpd`

### What the monitoring system sees

Discovered via `NET-SNMP-EXTEND-MIB` (Observium: Health → Unix Agent):
- **dnshived-health**: state (STABLE/DEGRADED/ISOLATED), serving count,
  epoch, generation, incarnation, version
- **dnshived-scopes**: the scopes this node serves

## Cluster-wide monitoring (on one host)

```sh
sudo cp dnshived-cluster-check /usr/local/bin/
sudo chmod +x /usr/local/bin/dnshived-cluster-check
dnshived-cluster-check <node-ip>:9443
```

Exit codes: 0=OK, 1=WARNING, 2=CRITICAL. If `dnshived-status` is
installed, the check delegates to it; otherwise it uses curl, and needs
`DNSHIVED_SCHEME=https` and `DNSHIVED_TOKEN` set on a TLS cluster with
tokens.

As an Uptime Kuma "Exec" monitor:
```
/usr/local/bin/dnshived-cluster-check <node-ip>:9443
```

## Data flow

```
Per node:      snmpd → extend → curl 127.0.0.1:9443 → monitoring (per device)
Cluster-wide:  service check → dnshived-status → all nodes → monitoring (service)
```

Per node shows each host's health next to its CPU/memory/interface
metrics; cluster-wide catches what only shows when comparing nodes
(dual-active, version mismatch, unserved scopes).
