# dnshived RPM spec for RHEL/CentOS/Rocky, mirroring debian/rules and the
# .deb maintainer scripts. One package with every daemon; each starts in
# bootstrap mode, so dnsmasq/keepalived/nftables are Recommends, not
# Requires (a probe-only host needs none of them).
#
# Scriptlets use plain systemctl calls rather than the systemd RPM macros.
#
# Version/Release come from tools/rpm-version.sh: a ~dev-N changelog entry
# becomes Release 0.devN.<hash> (sorts before a release), a release entry
# Release 1, both plus the dist tag.

%global core_binaries dnshived dnshived-helper dnshived-web dnshived-web-helper dnshived-top dnshived-status dnshived-validate dnshived-dhcp-probe dnshived-relay dnshived-dhcp-lease-hook dnshived-dnsrelay-render dnshived-preflight
%global probe_binaries dnshived-probe dnshived-probe-helper

# Fallback for hosts without systemd-rpm-macros; never overrides a defined
# value.
%{!?_unitdir: %global _unitdir /usr/lib/systemd/system}
%{!?_tmpfilesdir: %global _tmpfilesdir /usr/lib/tmpfiles.d}

# The Go binaries are built with -s -w, so there is no debug info for
# find-debuginfo to extract.
%global debug_package %{nil}
# Binaries report the same version string as the .deb (VERSION-N+HASH);
# the Makefile passes it in.
%{!?full_version: %global full_version %{version}-%{release}}

Name:           dnshived
Version:        %{?rpm_version}%{!?rpm_version:0.0.0}
Release:        %{?rpm_release}%{!?rpm_release:1}%{?dist}
Summary:        Clustered DNS/DHCP reliability appliance
License:        Apache-2.0
Group:          System Environment/Daemons
Packager:       Andreas Dunkl <andreas@dunkl.net>
URL:            https://github.com/andy-d-70/dnshived
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  golang >= 1.24
Requires:       systemd, shadow-utils, iproute
Recommends:     dnsmasq, keepalived, nftables
# /usr/local/bin is the frozen install path (docs/FREEZE.md Tier 1).
%global _prefix /usr/local

%description
dnshived is a lightweight, deterministic HA DNS/DHCP platform for
VLAN-heavy networks, AV/IoT environments, and SMB datacenters.

Every core node is symmetric (core-1/core-2/core-3); ownership is
gated by a five-part safety predicate (quorum, authoritative desired
state, valid lease, unfenced token, arbiter-granted witness) so a
scope is never served by two nodes at once. The same package installs
on every node, including probe hosts — real role is set purely by
which config file ends up written (/etc/dnshived/cluster.json for a
core role, /etc/dnshived/probe.json for a probe), never by which
binaries happen to be present. dnsmasq/keepalived/nftables are
Recommends, not hard Requires, since a probe-only node never needs
them.

Includes the privileged helper (dnshived-helper), the standalone
operator web UI (dnshived-web), the interactive console
(dnshived-top), a Nagios-compatible monitor (dnshived-status), the
invariant validation framework (dnshived-validate), a DHCP
dual-active detector (dnshived-dhcp-probe), a BOOTP/DHCP relay agent
(dnshived-relay), a DNS relay (dnshived-dnsrelay), and the probe host
itself (dnshived-probe + its privileged companion
dnshived-probe-helper) — none of the non-always-on units start by
default, all are opt-in/config-driven, matching the .deb's identical
enablement policy.

Every bootstrap-capable daemon (dnshived, dnshived-helper,
dnshived-probe, dnshived-probe-helper) is enabled and started on a
fresh install, sitting in its own independent, unauthenticated
bootstrap mode until something configures it. Configuring one role
(writing cluster.json OR probe.json) stops and disables whichever
OTHER role's daemon pair is now irrelevant on this same host — a
node can never simultaneously believe it's both a core role and a
probe.

%prep
%setup -q

%build
# The core module has no dependencies and builds offline; dnshived-dnsrelay
# is its own module (cmd/dnshived-dnsrelay/go.mod), built in a second step.
export CGO_ENABLED=0
mkdir -p builds
for b in %{core_binaries} %{probe_binaries}; do
    go build -ldflags "-s -w -X main.version=%{full_version}" -o builds/$b ./cmd/$b
done
( cd cmd/dnshived-dnsrelay && go build -ldflags "-s -w -X main.version=%{full_version}" -o ../../builds/dnshived-dnsrelay . )

%install
rm -rf %{buildroot}
install -D -m 0644 debian/dnshived.tmpfiles %{buildroot}%{_tmpfilesdir}/dnshived.conf
install -d %{buildroot}%{_prefix}/bin
for b in %{core_binaries} %{probe_binaries} dnshived-dnsrelay; do
    install -m 0755 builds/$b %{buildroot}%{_prefix}/bin/$b
done
install -m 0755 tools/probe-host-vlans.sh %{buildroot}%{_prefix}/bin/probe-host-vlans.sh
install -d %{buildroot}%{_sysconfdir}/dnshived
install -m 0644 cluster.json.example %{buildroot}%{_sysconfdir}/dnshived/cluster.json.example
install -m 0644 cmd/dnshived-dnsrelay/dnsrelay.json.example %{buildroot}%{_sysconfdir}/dnshived/dnsrelay.json.example

install -d %{buildroot}%{_unitdir}
for u in dnshived.service dnshived-helper.service dnshived-web.service \
         dnshived-web-helper.service dnshived-keepalived.service \
         dnshived-keepalived-mgmt.service dnshived-dnsmasq@.service \
         dnshived-relay.service dnshived-dnsrelay.service \
         dnshived-probe.service dnshived-probe-helper.service \
         dnshived-probe-vlans@.service; do
    install -m 0644 packaging/systemd/$u %{buildroot}%{_unitdir}/$u
done

%pre
getent group dnshived >/dev/null || groupadd -r dnshived
getent passwd dnshived >/dev/null || \
    useradd -r -g dnshived -d /var/lib/dnshived -s /sbin/nologin \
            -c "dnshived cluster daemon" dnshived
exit 0

%post
mkdir -p /etc/dnshived /var/lib/dnshived /var/log/dnshived
chown dnshived:dnshived /var/lib/dnshived /var/log/dnshived
systemd-tmpfiles --create %{_tmpfilesdir}/dnshived.conf || :

# A fresh install does not seed cluster.json (the node boots into
# bootstrap mode); cluster.json.example ships as schema reference.
# probe.json is written only by dnshived-probe-helper.
chown dnshived:dnshived /etc/dnshived
chown dnshived:dnshived /etc/dnshived/cluster.json 2>/dev/null || true
chmod 0640 /etc/dnshived/cluster.json 2>/dev/null || true

# Environment checks before anything starts. RPM scriptlets do not abort
# on a failing command, so the result is checked explicitly.
if ! %{_prefix}/bin/dnshived-preflight; then
    echo "dnshived-preflight failed — see above for details" >&2
    exit 1
fi

# SELinux: persistent fcontext rules for the files the daemon renders
# under /var/lib/dnshived. A dnsmasq_t/keepalived_t domain started by
# systemd cannot read files labelled var_lib_t (no AVC is logged), so
# restorecon relabels what exists; new files are labelled at creation.
if command -v semanage >/dev/null 2>&1 && command -v restorecon >/dev/null 2>&1; then
    semanage fcontext -a -t etc_t "/var/lib/dnshived/keepalived.*\.conf" 2>/dev/null || :
    semanage fcontext -a -t dnsmasq_etc_t "/var/lib/dnshived/dnsmasq-.*\.conf" 2>/dev/null || :
    semanage fcontext -a -t dnsmasq_etc_t "/var/lib/dnshived/reservations-.*\.conf" 2>/dev/null || :
    semanage fcontext -a -t dnsmasq_lease_t "/var/lib/dnshived/leases-.*" 2>/dev/null || :
    semanage fcontext -a -t dnsmasq_var_log_t "/var/lib/dnshived/dnsmasq-.*\.log" 2>/dev/null || :
    restorecon -R /var/lib/dnshived/ >/dev/null 2>&1 || :
fi

systemctl daemon-reload >/dev/null 2>&1 || :

if [ "$1" -eq 1 ]; then
    # Fresh install: enable and start the four always-on units. Every other
    # unit is started by the daemon or an operator, never at boot.
    systemctl enable --now dnshived-helper.service >/dev/null 2>&1 || :
    systemctl enable --now dnshived.service >/dev/null 2>&1 || :
    systemctl enable --now dnshived-probe-helper.service >/dev/null 2>&1 || :
    systemctl enable --now dnshived-probe.service >/dev/null 2>&1 || :
elif [ "$1" -ge 2 ]; then
    # Upgrade: one ordered restart of dnshived and dnshived-helper
    # (dnshived.service Requires= the helper; two independent restarts race on
    # the DHCP gate). The probe pair restarts independently. Ownership moves
    # to dnshived only while dnshived is stopped (a running pre-0.9.8.4 root
    # daemon would keep creating root-owned files); the lease socket an old
    # root daemon left in the sticky /run/dnshived would block the new one.
    if systemctl is-active --quiet dnshived.service; then
        systemctl stop dnshived.service >/dev/null 2>&1 || :
        chown -R dnshived:dnshived /etc/dnshived /var/lib/dnshived
        rm -f /run/dnshived/dhcp-lease.sock
        systemctl restart dnshived-helper.service >/dev/null 2>&1 || :
        systemctl start dnshived.service >/dev/null 2>&1 || :
    else
        chown -R dnshived:dnshived /etc/dnshived /var/lib/dnshived
        rm -f /run/dnshived/dhcp-lease.sock
        systemctl restart dnshived-helper.service >/dev/null 2>&1 || :
    fi
    # Restart only what is running: a plain restart also starts the
    # probe pair on core nodes, and left a running web UI on the old
    # binary.
    systemctl try-restart dnshived-probe-helper.service >/dev/null 2>&1 || :
    systemctl try-restart dnshived-probe.service >/dev/null 2>&1 || :
    systemctl try-restart dnshived-web.service dnshived-web-helper.service >/dev/null 2>&1 || :
fi
exit 0

%preun
if [ "$1" -eq 0 ]; then
    # Full removal ($1 == 0): stop and disable every unit, including
    # per-scope dnsmasq@ and probe-vlans@ instances, like debian/dnshived.prerm.
    systemctl stop dnshived.service dnshived-helper.service dnshived-web.service \
        dnshived-web-helper.service dnshived-keepalived.service \
        dnshived-keepalived-mgmt.service dnshived-relay.service \
        dnshived-dnsrelay.service dnshived-probe.service \
        dnshived-probe-helper.service >/dev/null 2>&1 || :
    systemctl disable dnshived.service dnshived-helper.service dnshived-web.service \
        dnshived-web-helper.service dnshived-keepalived.service \
        dnshived-keepalived-mgmt.service dnshived-relay.service \
        dnshived-dnsrelay.service dnshived-probe.service \
        dnshived-probe-helper.service >/dev/null 2>&1 || :
    for pattern in 'dnshived-dnsmasq@*.service' 'dnshived-probe-vlans@*.service'; do
        for unit in $(systemctl list-units --no-legend --plain \
                        "$pattern" 2>/dev/null | awk '{print $1}'); do
            systemctl stop "$unit" >/dev/null 2>&1 || :
            systemctl disable "$unit" >/dev/null 2>&1 || :
        done
    done
fi
exit 0

%postun
systemctl daemon-reload >/dev/null 2>&1 || :
exit 0

%files
%{_tmpfilesdir}/dnshived.conf
%{_prefix}/bin/dnshived
%{_prefix}/bin/dnshived-helper
%{_prefix}/bin/dnshived-web
%{_prefix}/bin/dnshived-web-helper
%{_prefix}/bin/dnshived-top
%{_prefix}/bin/dnshived-status
%{_prefix}/bin/dnshived-validate
%{_prefix}/bin/dnshived-dhcp-probe
%{_prefix}/bin/dnshived-relay
%{_prefix}/bin/dnshived-dhcp-lease-hook
%{_prefix}/bin/dnshived-dnsrelay-render
%{_prefix}/bin/dnshived-dnsrelay
%{_prefix}/bin/dnshived-preflight
%{_prefix}/bin/dnshived-probe
%{_prefix}/bin/dnshived-probe-helper
%{_prefix}/bin/probe-host-vlans.sh
%config(noreplace) %{_sysconfdir}/dnshived/cluster.json.example
%config(noreplace) %{_sysconfdir}/dnshived/dnsrelay.json.example
%doc README.md docs/INSTALL.md docs/OS_COMPATIBILITY.md
%{_unitdir}/dnshived.service
%{_unitdir}/dnshived-helper.service
%{_unitdir}/dnshived-web.service
%{_unitdir}/dnshived-web-helper.service
%{_unitdir}/dnshived-keepalived.service
%{_unitdir}/dnshived-keepalived-mgmt.service
%{_unitdir}/dnshived-dnsmasq@.service
%{_unitdir}/dnshived-relay.service
%{_unitdir}/dnshived-dnsrelay.service
%{_unitdir}/dnshived-probe.service
%{_unitdir}/dnshived-probe-helper.service
%{_unitdir}/dnshived-probe-vlans@.service
%license LICENSE

%changelog
* Tue Sep 29 2026 Andreas Dunkl <andreas@dunkl.net> - %{version}-%{release}
- Merged the dnshived-probe subpackage into this single package —
  every node now installs every daemon (core + probe), starting each
  bootstrap-capable one unconfigured; real role is decided entirely by
  which config file later gets written, not by which package was
  installed. dnsmasq/keepalived/nftables moved from Requires to
  Recommends accordingly.
* Mon Sep 28 2026 Andreas Dunkl <andreas@dunkl.net> - %{version}-%{release}
- First RPM packaging path for RHEL/CentOS/Rocky, mirroring the
  existing .deb (dnshived + dnshived-probe split, identical
  enablement policy, identical postinst/prerm behavior). Closes the
  "no RPM/.deb-equivalent packaging path exists yet" gap documented
  in docs/OS_COMPATIBILITY.md.
