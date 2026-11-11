# Tools

Small helpers that ship with, or support the build of, dnshived. Everything
runs from the repo root and needs no lab.

## Build

```sh
make build          # core binaries into builds/
make check-config   # validate cluster.json.example
make deb            # Debian package
make rpm            # RPM package (uses rpm-version.sh)
```

`dnshived-dnsrelay` is its own Go module (`cmd/dnshived-dnsrelay`, which keeps
its `golang.org/x` dependencies out of the core) and is not part of
`make build`; build it with `go build` inside that directory.
`dnshived-dnsrelay-render` is in the core module but also not in `make build`
(`go build ./cmd/dnshived-dnsrelay-render`). `make deb` and `make rpm` build
both.

## Scripts

- `rpm-version.sh` derives the RPM `Version:` and `Release:` from the top entry
  of `debian/changelog`, like the package version of the `.deb`. Called by
  `make rpm`.
- `probe-host-vlans.sh` pre-creates VLAN sub-interfaces on a probe host. It is
  a fallback; normally `dnshived-probe` manages them. Shipped in the packages
  (see the cookbook).

## SNMP

`snmp/` holds extend scripts for `net-snmp`'s `snmpd` and a Nagios-compatible
cluster check (exit codes 0 OK, 1 WARNING, 2 CRITICAL). Setup is in
`snmp/README.md`.

## Profiling build (development hosts only)

`make lab-deb` and `make lab-rpm` build packages that carry a small profiling
tool: root sends `SIGWINCH` to the daemon or the DNS relay and the process
writes a CPU, heap and goroutine profile under its state directory (mode 0600).
It is compiled in only with the `labprofile` build tag, does nothing unless a
root-owned `/etc/dnshived/lab-profile.enable` exists (its first word may set the
profile length in seconds, default 30), and the packages are named
`*.LAB-PROFILE.*` and report `[LAB PROFILE BUILD]` in `--version`. Never install
them outside a development host. `make release-guard` (`tools/release-guard.sh`)
scans packages and binaries for the tool and must pass before every release.
