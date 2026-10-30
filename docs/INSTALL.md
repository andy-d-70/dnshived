# Installation

How to get a release, build it, and install it on your own hosts. Only
the scripts listed in `tools/README.md` are part of this repository.

## Tested platforms

| OS | Status |
|---|---|
| Debian 12+ | Primary target, tested |
| CentOS Stream 9 / Rocky Linux 9 | Tested, `.rpm` package |
| Ubuntu 24.04 / 26.04 | Builds and runs from source; no packaged `.deb` of its own yet |

See `docs/OS_COMPATIBILITY.md` for per-OS details (SELinux, AppArmor,
gotchas).

## Packages needed

**To build:**
- Debian/Ubuntu: `debhelper` (≥13), `golang-go` ≥1.24
- RHEL-family: `golang` ≥1.24, `rpm-build`
- Ubuntu 24.04's `golang-go` is only 1.22: install Go 1.24+ from
  [go.dev/dl](https://go.dev/dl/) there.

**To run** (installed automatically as package dependencies):
- `systemd`, `iproute2` (`iproute` on RHEL-family), `adduser`
  (`shadow-utils` on RHEL-family): always required.
- `dnsmasq-base` on Debian/Ubuntu (`dnsmasq` on RHEL-family),
  `keepalived`: needed only on a core node, not on a probe-only host.
  `nftables`: recommended on a core node. The DHCP gate no longer uses
  it; it is needed only to remove the table a 0.9.8.5 install left
  behind when upgrading. Use `dnsmasq-base`, not `dnsmasq`: the full
  package enables its own `dnsmasq.service`, which takes port 53.
- Dependencies are only pulled in by `apt install ../dnshived*.deb` or
  `dnf install`. A plain `dpkg -i`/`rpm -i` skips them;
  `dnshived-preflight` runs at install time and reports anything
  missing, and stops a conflicting `dnsmasq.service`.

## Get the source

```sh
git clone https://github.com/andy-d-70/dnshived.git
cd dnshived
git checkout v0.9.8.6    # latest release
```

`main` is ongoing development past the latest tag. Don't use `v0.9.8`
(pulled) or older tags.

## Build and install: Debian / Ubuntu

```sh
sudo apt install debhelper golang-go   # see the Ubuntu 24.04 note above
make deb
sudo apt install ../dnshived*.deb      # dpkg-buildpackage writes one directory up
```

## Build and install: CentOS Stream / Rocky Linux

```sh
sudo dnf install golang rpm-build
make rpm
sudo dnf install ./rpmbuild/RPMS/*/dnshived-*.rpm
```

On RHEL-family, `sudo`'s `secure_path` excludes `/usr/local/bin`, so call
dnshived tools under sudo with their full path, e.g.
`sudo /usr/local/bin/dnshived-preflight`.

Both packages contain every binary (core daemon, helper, web UI, probe,
both relays). The role a host takes is set by the config it ends up
with (`/etc/dnshived/cluster.json` for a core node,
`/etc/dnshived/probe.json` for a probe host), not by what is installed.

## Configuration

A fresh install starts in bootstrap mode; no manual `cluster.json`
editing is needed.

1. **Get the join code.** Every fresh host prints one to the journal on
   first start, valid for either role:
   ```sh
   journalctl -u dnshived | grep "join code"
   # [BOOTSTRAP:READY] join code: XXXX-XXXX-XXXX-XXXX (the same code for a core role and for a probe role)
   ```
   This proves console access to that host and is required even for the
   first node.
2. Open `https://<node-ip>/` (self-signed, the browser will warn) or
   `http://<node-ip>/`, enter the join code and follow the wizard to
   found a new cluster or join an existing one.
3. **Save the credentials shown on the final page**; they are shown
   once: the web UI admin login, and a read-only API token (named
   `monitoring`) for `dnshived-top`/`dnshived-status`.

For a scripted setup instead, see `cluster.json.example` and validate
before deploying:

```sh
dnshived --check-config --config /etc/dnshived/cluster.json
```

## Verification

A founded cluster uses self-signed TLS and token auth, so
`dnshived-top`/`dnshived-status` need `-tls -tls-skip-verify` and a
token, or a `~/.dnshived/rc` (mode `0600`, see `docs/SECURITY.md`,
"API authentication"):

```sh
mkdir -p ~/.dnshived && cat > ~/.dnshived/rc <<EOF
addr=<node-ip>:9443
tls=true
tls_skip_verify=true
token=<the monitoring token from step 3>
EOF
chmod 600 ~/.dnshived/rc

dnshived-status -v 1          # cluster health
dnshived-status --watch       # live dashboard
dnshived-top                  # interactive console (one address is enough)
```
