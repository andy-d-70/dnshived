# OS compatibility

`docs/INSTALL.md` covers Debian 12+, the primary target. This file
records what differs on other platforms. Every entry comes from a real
install, not from documentation.

Packages: the `.deb` (Debian) and the `.rpm` (`make rpm`, CentOS Stream
9 / Rocky Linux 9 and other RHEL-family distros with the same package
names) both contain every binary and enable the same four always-on
units (`dnshived`, `dnshived-helper`, `dnshived-probe`,
`dnshived-probe-helper`); every other unit is started by the agent or
an operator. Both were installed end to end and came up in bootstrap
mode with a join code (the `.rpm` again on CentOS Stream 9 with
0.9.8.4, SELinux Enforcing, zero AVC denials). Ubuntu has no package of its own yet: build from
source and install by hand (below).

## Quick reference

| OS | Go from the package manager | Runtime deps preinstalled? | MAC system | Gotchas |
|---|---|---|---|---|
| Debian 12+ | 12: no (use go.dev), 13: yes | no, all in apt | none | — |
| CentOS Stream 9 | yes (1.26) | no, all in `dnf` | SELinux, Enforcing | cloud image needs an x86-64-v2 CPU type; `rpm-build` for `make rpm` |
| Rocky Linux 9 | yes (1.26) | no, all in `dnf` | SELinux, Enforcing | none |
| Ubuntu 24.04 LTS | **no**: `golang-go` is 1.22, below the 1.24 minimum | `nftables` yes, `keepalived`/`dnsmasq-base` no | AppArmor, no profile for dnshived | cloud-init `admin` user |
| Ubuntu 26.04 LTS | yes (1.26) | same as 24.04 | same as 24.04 | cloud-init `admin` user, netplan `set-name` race |

## From source, any OS

What the packages do, by hand:

```sh
# 1. System user/group
groupadd --system dnshived                      # RHEL-family
useradd --system --home-dir /var/lib/dnshived --shell /sbin/nologin --gid dnshived dnshived
# Debian/Ubuntu:
# addgroup --system dnshived
# adduser --system --home /var/lib/dnshived --shell /usr/sbin/nologin --ingroup dnshived dnshived

mkdir -p /etc/dnshived /var/lib/dnshived /var/log/dnshived
chown dnshived:dnshived /var/lib/dnshived /var/log/dnshived

# 2. Binaries (make build; dnshived-dnsrelay from cmd/dnshived-dnsrelay)
install -m 0755 builds/* /usr/local/bin/
install -m 0644 debian/dnshived.tmpfiles /usr/lib/tmpfiles.d/dnshived.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/dnshived.conf

# 3. systemd units
cp packaging/systemd/*.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now dnshived-helper dnshived dnshived-probe-helper dnshived-probe

# 4. RHEL-family with SELinux Enforcing only (the .rpm does this itself)
semanage fcontext -a -t etc_t "/var/lib/dnshived/keepalived.*\.conf"
semanage fcontext -a -t dnsmasq_etc_t "/var/lib/dnshived/dnsmasq-.*\.conf"
semanage fcontext -a -t dnsmasq_etc_t "/var/lib/dnshived/reservations-.*\.conf"
semanage fcontext -a -t dnsmasq_lease_t "/var/lib/dnshived/leases-.*"
semanage fcontext -a -t dnsmasq_var_log_t "/var/lib/dnshived/dnsmasq-.*\.log"
restorecon -R /var/lib/dnshived/
```

A host with no `cluster.json` then starts in bootstrap mode: join code
in the journal, LAN discovery broadcast on UDP 9445.

## CentOS Stream 9 / Rocky Linux 9

Build on the host itself from a git checkout (`make rpm` packs the
tree with `git archive`), then install:

```sh
sudo dnf install -y nftables keepalived dnsmasq golang git rpm-build
make rpm
sudo dnf install -y ./rpmbuild/RPMS/*/dnshived-*.rpm
```

All in the stock `baseos`/`appstream` repos; `make` comes in with
`golang`. Versions seen (CentOS Stream 9, 2026-10): nftables 1.0.9,
keepalived 2.2.8, dnsmasq 2.85, golang 1.26.7.

The GenericCloud image needs `cpu: x86-64-v2-AES` (or `host`) in
Proxmox; with the default CPU type it never comes up on the network.
It ships no firewalld; on an install that runs firewalld, open the
bootstrap ports (TCP 80/443, UDP 9445) and the cluster ports before
installing (not yet tested with firewalld active).

**SELinux, tested under Enforcing.** With no dnshived policy, systemd
runs the services as `unconfined_service_t`. Interface creation, the
nftables gate, gate queries and teardown through the helper, and the
daemon's bootstrap mode all ran with zero AVC denials, under Permissive
and Enforcing, on both distros.

One real gap, now handled by the `.rpm`: keepalived and dnsmasq run in
the confined `keepalived_t`/`dnsmasq_t` domains, which cannot read a
freshly rendered file under `/var/lib/dnshived` labelled `var_lib_t`,
and no AVC is logged. The symptom is "Config files missing" for a file
that exists. The `.rpm` adds persistent fcontext rules and relabels at
install; from source, use step 4 above.

Not separately tested under Enforcing: the relays' raw-socket paths and
the probe host's VLAN handling. dnsmasq 2.85 is older than Debian's
2.90/2.91; its DHCPRELEASE/option-54 behavior has not been re-verified.

`sudo`'s `secure_path` on RHEL-family excludes `/usr/local/bin`, where
every dnshived binary lives: use full paths
(`sudo /usr/local/bin/dnshived-preflight`, `sudo /usr/local/bin/dnshived-web -reset-user ...`).

`make rpm` removes older dnshived RPMs from `rpmbuild/RPMS` before it
builds, so the install glob above always matches exactly one build.

## Ubuntu 24.04 / 26.04

```sh
sudo apt-get update
sudo apt-get install -y nftables keepalived dnsmasq-base git
```

`dnsmasq-base` 2.91 matches Debian's. On 24.04 install Go from
[go.dev/dl](https://go.dev/dl/); on 26.04 `golang-go` (1.26) is enough.

**AppArmor:** profiles are per binary and none exists for dnshived, so
everything runs unconfined. Nothing to do.

**cloud-init `admin` user:** Ubuntu's cloud image already has a group
`admin`. A cloud-init `user: admin` (e.g. Proxmox `--ciuser admin`)
makes `useradd` fail, and every later cloud-init step fails with it (no
SSH key, sometimes no network). Use another user name, e.g. `ubuntu`.

**netplan `set-name` race (seen on 26.04):** a generated netplan config
with `set-name: "eth0"` next to `match: macaddress:` can fail the
rename (logged only as a warning), leaving the static address
unapplied. Remove the `set-name:` line from
`/etc/netplan/50-cloud-init.yaml` and run `netplan apply`; the MAC
match alone selects the interface.

**Keyboard layout:** `localectl set-keymap` is not supported on
Debian/Ubuntu. Use:

```sh
echo 'XKBLAYOUT="de"' | sudo tee /etc/default/keyboard
sudo dpkg-reconfigure -f noninteractive keyboard-configuration
```

## Probe hosts, any OS

A probe host needs `dnshived-probe` and `dnshived-probe-helper` (both
in the packages). Adoption writes everything else into `probe.json`.
`dnshived-probe` runs as `dnshived` with `CAP_NET_RAW` and
`CAP_NET_BIND_SERVICE`; `dnshived-probe-helper` runs as root with
`Group=dnshived`, so the probe can use its socket (tested under SELinux
Enforcing on CentOS, no denials).

Check that the trunk NICs are up: on cloud images often only the
management NIC is configured, and VLAN creation then fails with
`RTNETLINK answers: Network is down`. Fix with
`sudo ip link set <trunk-nic> up` (and make it persistent in the
host's network config). See `docs/COOKBOOK.md`, "Probe host VLAN
coverage".
