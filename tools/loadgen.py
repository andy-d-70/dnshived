#!/usr/bin/env python3
"""Synthetic configuration load for a dnshived core node.

Run it as root ON a core node (it talks to the daemon's API on the loopback
address and reads the admin token through `dnshived --print-config`; the token is
never printed). It stages the synthetic data as a pending change on this node
only; run it on every core, then commit from the web UI (the author is
"loadtest", so the commit asks for the typed confirmation).

  loadgen.py snapshot FILE                 save the current configuration
  loadgen.py apply --domains D --hosts H --reservations R [--names N]
  loadgen.py clear                         stage the removal of all synthetic data
  loadgen.py count                         count the synthetic data in the live configuration

Synthetic data is recognised by its names (domains ld-dom-*, reservations with the
MAC prefix 02:4c:), so `apply` replaces what an earlier run staged and `clear`
removes it again without a snapshot. Reservations use free addresses only (outside
the DHCP range, the gateway, the VIP, the node addresses and existing
reservations).
"""
import argparse
import ipaddress
import json
import ssl
import subprocess
import sys
import time
import urllib.request

API = "https://127.0.0.1:9443"
CONFIG = "/etc/dnshived/cluster.json"
MAC_PREFIX = "02:4c:"
DOMAIN_PREFIX = "ld-dom-"
PAYLOAD_KEYS = [
    "psk", "trusted_hosts", "tls_cert", "tls_key", "api_tokens", "log_level", "helper_socket", "platform",
    "scopes", "parked_scopes", "probe_interval_ms", "mgmt_vip", "default_dns_checks", "global_dns_records",
    "local_domains", "scope_defaults", "default_dhcp_options", "core_dns_address", "core_dhcp_address",
    "core_dns_query_logging", "dnsrelay_cache_size", "dnsrelay_cache_max_bytes", "sanity_check_disabled",
    "access", "backup_enabled", "backup_interval_hours", "backup_retention_count", "backup_password",
    "backup_replicate_to_peers",
]


def current_config():
    try:
        raw = subprocess.check_output(["/usr/local/bin/dnshived", "--config", CONFIG, "--print-config"], stderr=subprocess.DEVNULL)
        return json.loads(raw)
    except Exception:
        with open(CONFIG) as f:
            return json.load(f)


def token(cfg):
    return [t["token"] for t in cfg["api_tokens"] if t["role"] == "admin"][0]


def call(cfg, method, path, body=None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + token(cfg), "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=300) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def live(cfg):
    status, raw = call(cfg, "GET", "/api/v1/config")
    if status != 200:
        sys.exit("GET config: %s %s" % (status, raw[:200]))
    return json.loads(raw)


def is_synthetic_reservation(r):
    return str(r.get("mac", "")).lower().startswith(MAC_PREFIX)


def free_addresses(scope):
    vip = ipaddress.ip_interface(scope["vip"])
    net = vip.network
    used = {net.network_address, net.broadcast_address, vip.ip}
    for key in ("gateway",):
        if scope.get(key):
            used.add(ipaddress.ip_address(scope[key]))
    if scope.get("node_ip"):
        used.add(ipaddress.ip_interface(scope["node_ip"]).ip)
    for v in (scope.get("node_ip_overrides") or {}).values():
        try:
            used.add(ipaddress.ip_interface(v).ip)
        except ValueError:
            pass
    lo, hi = scope.get("dhcp_range", ["", ""])
    rng = (ipaddress.ip_address(lo), ipaddress.ip_address(hi)) if lo and hi else None
    for r in scope.get("reservations") or []:
        if not is_synthetic_reservation(r):
            used.add(ipaddress.ip_address(r["ip"]))
    out = []
    for host in net.hosts():
        if host in used or int(host) % 256 < 2:
            continue
        if rng and rng[0] <= host <= rng[1]:
            continue
        out.append(host)
    return out


def build(cfg, domains, hosts, per_scope, names):
    scopes = cfg["scopes"]
    for idx, name in enumerate(sorted(scopes)):
        sc = scopes[name]
        keep = [r for r in (sc.get("reservations") or []) if not is_synthetic_reservation(r)]
        add = []
        for n, ip in enumerate(free_addresses(sc)[:per_scope]):
            tag = "s%03d-h%03d" % (idx, n)
            add.append({
                "mac": "%s%02x:%02x:%02x:%02x" % (MAC_PREFIX, idx // 256, idx % 256, n // 256, n % 256),
                "ip": str(ip),
                "hostname": "ld-" + tag,
                "names": ["alias%d-%s" % (k, tag) for k in range(names)],
            })
        merged = keep + add
        if merged:
            sc["reservations"] = merged
        else:
            sc.pop("reservations", None)
    kept = [d for d in cfg.get("local_domains") or [] if not d["name"].startswith(DOMAIN_PREFIX)]
    for d in range(domains):
        recs = []
        for h in range(hosts):
            addr = "10.%d.%d.%d" % (d % 250, (h // 250) % 250, h % 250 + 1)
            if h % 10 == 9:
                recs.append({"host": "c%04d" % h, "type": "CNAME", "value": "h%04d.%s%04d.lan." % (h - 1, DOMAIN_PREFIX, d)})
            elif h % 25 == 24:
                recs.append({"host": "t%04d" % h, "type": "TXT", "value": "v=ldtest %d.%d" % (d, h)})
            else:
                recs.append({"host": "h%04d" % h, "type": "A", "value": addr})
        kept.append({"name": "%s%04d.lan" % (DOMAIN_PREFIX, d), "records": recs})
    cfg["local_domains"] = kept
    return cfg


def count(cfg):
    res = sum(1 for s in cfg["scopes"].values() for r in (s.get("reservations") or []) if is_synthetic_reservation(r))
    doms = [d for d in cfg.get("local_domains") or [] if d["name"].startswith(DOMAIN_PREFIX)]
    recs = sum(len(d.get("records") or []) for d in doms)
    return res, len(doms), recs


def stage(cfg, desired):
    payload = {k: desired[k] for k in PAYLOAD_KEYS if k in desired}
    payload["author"] = "loadtest"
    body = json.dumps(payload)
    t0 = time.time()
    status, raw = call(cfg, "POST", "/api/v1/candidate", payload)
    return status, raw, time.time() - t0, len(body)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("count")
    sub.add_parser("clear")
    s = sub.add_parser("snapshot")
    s.add_argument("file")
    a = sub.add_parser("apply")
    a.add_argument("--domains", type=int, default=0)
    a.add_argument("--hosts", type=int, default=0)
    a.add_argument("--reservations", type=int, default=0, help="per scope")
    a.add_argument("--names", type=int, default=2, help="extra DNS names per reservation (0 to 8)")
    args = ap.parse_args()
    cfg = current_config()
    if args.cmd == "count":
        print("synthetic reservations %d, domains %d, records %d" % count(live(cfg)))
        return
    if args.cmd == "snapshot":
        with open(args.file, "w") as f:
            json.dump(live(cfg), f)
        print("saved", args.file)
        return
    desired = live(cfg)
    if args.cmd == "clear":
        build(desired, 0, 0, 0, 0)
    else:
        build(desired, args.domains, args.hosts, args.reservations, min(max(args.names, 0), 8))
    status, raw, secs, size = stage(cfg, desired)
    res, doms, recs = count(desired)
    print("staged reservations=%d domains=%d records=%d payload=%d bytes http=%s in %.2fs %s" % (res, doms, recs, size, status, secs, "" if status == 200 else raw[:300].decode("utf-8", "replace")))
    sys.exit(0 if status == 200 else 1)


if __name__ == "__main__":
    main()
