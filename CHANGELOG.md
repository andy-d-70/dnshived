# dnshived Changelog

## 0.9.8.5 — released
Web UI user management and interface-detection release. Login form with sessions, three roles (admin, scopeadmin, readonly), users replicated to every core, password reset by email with SMTP settings; the pre-onboarding interface check now detects trunks and management interfaces (rp_filter on address-less trunks, and onboarding always talks to the core daemon); core nodes pin the cluster certificate; `dnshived-validate`'s dual-active check works. Verified on a freshly built cluster (3 cores incl. CentOS Stream 9, 1 probe host): founding, onboarding, users and mail, self-decommission and re-onboarding of the CentOS core with its interface names detected.

**Upgrade notes:**
- Core nodes now verify each other's certificate: every core must serve the same cluster certificate, as founding and onboarding set it up. A hand-built cluster with per-node certificates must switch to one shared certificate first.
- The web UI asks for a login once after the upgrade (form instead of the browser popup). On first start the cores merge their users files into one replicated users document; HTTP Basic credentials from scripts are still accepted.
- An existing cluster keeps resolving interface names at runtime; per-node interface names are stored the next time a node is replaced or re-onboarded.

Known issues: after a self-decommission the probe daemon stays disabled, so the host cannot be adopted as a probe host until `dnshived-probe` is started by hand, and an empty `inet dnshived` nftables table is left behind (harmless). Probe hosts keep reverse-path filtering on their trunks, which drops the cores' topology beacons there (no effect today). Not yet tested live: cluster certificate rotation and a failover with certificate pinning on; storing management names from the founding wizard (covered by tests; onboarding is verified).

- The pre-onboarding interface match detects trunks again. The candidate's probe leaves an address-less trunk with its management address as source, and on the listening node's address-less trunk the kernel's reverse-path filter (rp_filter=2, the Debian 13 default) dropped it. The helper's `link-up` now sets rp_filter=0 on an interface that carries no IPv4 address (never on the management interface or any addressed one), as scope creation already did; this also covers topology beacons on a cluster without scopes.
- Founding wizard stores each node's own management interface name (the interface the founder reaches it on) as a per-node override and shows it in the node list and review; before, every node got the founder's name, which only worked through altname resolution.
- Diagnosability: a failed interface-probe send is logged, and a trunk that heard nothing logs its rp_filter value.
- `dnshived-validate`'s DHCP dual-active check works: it asked the core nodes for probe results, which only probe hosts serve, so it never fired. It now queries the probe hosts (`-probe-addr`, or `probe_hosts` from `/etc/dnshived/web.json`) and says at startup when no probe host is known.
- The DHCP relay and DNS relay are no longer shown as inactive/dead when every scope is disabled: only enabled scopes count, and relay interfaces of disabled or removed scopes are no longer listed.
- Overview shows per trunk whether it is verified (a beacon from another core was heard on it) or only assumed. Every configured trunk is now beaconed, not only trunks that carry a scope, so a cluster without scopes is checked too.
- Core nodes verify each other's TLS certificate against the cluster certificate (as the web UI already does) instead of skipping verification. A refused peer is logged with its certificate fingerprint. **Upgrade note:** every core must serve the same cluster certificate, as founding and onboarding set it up; a hand-built cluster with per-node certificates must share one first.
- Web UI user management. Login is a form with a signed session cookie instead of the browser's password popup (logout works; the session survives a mgmt-VIP failover; 30 min idle, 12 h maximum). Admins create, edit, disable and delete users on the new Users page; roles are admin, scopeadmin (everything served to clients: scopes, DHCP/DNS settings, templates, local domains) and readonly. A scopeadmin can commit only when every staged change is within its rights. The last active admin cannot be deleted, disabled or demoted, and nobody can demote, disable or delete themselves. Every user change is written to the audit log.
- Users are replicated to every core: a change on one web instance reaches the others at once, and every instance checks the others once a minute, so a core that was down or newly added catches up by itself. The first replication merges each core's existing users instead of overwriting them. `dnshived-web -reset-user` (now also `-role scopeadmin` and `-email`) spreads the same way and no longer needs a restart.
- Password reset by email ("forgot password?" on the login page): single-use link, valid 30 minutes, the same answer whether or not the user exists, rate-limited. Users get a notification email when their password, role or status changes.
- Mail settings (Cluster config → Mail): SMTP server, port, STARTTLS/TLS/none, login, sender, optional custom CA, and the public URL used in reset links. "Test settings" checks connection, TLS and login without sending; "Send test email" sends one.
- Onboarding a core from the Discovered list could talk to the wrong daemon: a host waiting for adoption runs both the core daemon (port 80) and the probe daemon (port 9444), and the list kept whichever announced last. The interface check then got no interface bursts and no management interface, so no per-node interface names were stored. The interface check and Inspect now always contact the core daemon (port 80), as the adopt push already did, whatever port the list showed; a candidate that reports no management interface is logged.
- `make rpm` removes older dnshived RPMs from `rpmbuild/RPMS` first, so the documented `dnf install` glob installs exactly one build; the spec builds without `systemd-rpm-macros` (tmpfiles directory fallback).

## 0.9.8.4 — released
Hardening and fresh-install release. dnshived runs unprivileged, with root left only in the helpers and keepalived; RHEL/CentOS (SELinux) install and upgrade paths fixed; web UI security hardening and performance; founding wizard stores node addresses with their port, so a freshly founded cluster no longer comes up partitioned. Verified on a fresh founding (3 cores incl. CentOS Stream 9, 1 probe host, 1 scope).

Known issue: the pre-onboarding interface match still detects no trunk (all trunks show "not detected" and need "add anyway"); the cluster runs normally because each node resolves its trunk names at runtime, but no per-node interface names are stored. Being reworked into a beacon-based interface assignment.

**Upgrade note: dnshived.service no longer runs as root.** The upgrade restarts dnshived once per node (as every upgrade does) and moves ownership of /etc/dnshived and /var/lib/dnshived to dnshived:dnshived.

- Web UI security: the cluster PSK and API tokens are never sent to the browser any more (readonly users could read them, including admin tokens); fields are write-only ("leave blank to keep"). Form posts from other sites are refused (Origin/Sec-Fetch-Site check against cross-site request forgery). Failed logins are rate-limited per client address and per user, and password checks run at most two at a time. The HTTPS server has timeouts and request size limits, and every response carries security headers (no framing, nosniff, HSTS, referrer policy). Connections from the web UI to the cores and to sibling web instances verify the cluster certificate instead of skipping verification.
- Saving the cluster config in the web UI kept the per-node trunk names but dropped the per-node management interface names (added in this release).
- Founding wizard: node addresses are stored with their port (core API port for cores, 9444 for probe hosts). Typed without a port, every peer was contacted on port 443 and the new cluster came up with core-1 isolated and the probe host shown down.
- The interface match brings the listening node's trunk NICs up first. On a node in bootstrap mode, or a cluster without scopes yet, the trunks were down, so founding stored no per-node interface names and an onboard/replace would have been refused for an undetected trunk.
- Founding wizard shows the detected interface per trunk for every node and refuses a node with an undetected trunk unless "add anyway" is ticked (it used to drop that silently).
- Overview names the real reason when a node answers with something other than JSON (e.g. "HTTP 301 Moved Permanently, not JSON") instead of a raw decoder error.
- Web UI login takes the same time for unknown and known user names (an unknown name was rejected at once, a known one after the ~0.65 s password check, revealing which names exist).
- The "+ insert into this template" button for local domains works: its JavaScript argument ended the HTML attribute early (and let record text spill into the button's attributes).
- Web UI performance: a successful login stays valid without re-hashing the password until the users file changes (it re-checked PBKDF2 every 30 s, ~0.65 s per click after a pause); responses are gzip-compressed; while someone is using the UI, the cluster snapshot behind Overview is refreshed in the background, so a page never waits for the cores.
- Performance: the agent reads unit states from one shared `systemctl show` snapshot per tick instead of one process per unit and check; `/api/v1/daemons` caches version strings per binary until the binary changes; the time check reads the kernel clock state (adjtimex) instead of running timedatectl and chronyc, which also ends the chronyc SELinux denials on RHEL. Measured on a lab core before: ~107 process starts and 4.2 s CPU per minute.
- dnshived runs as user dnshived with NoNewPrivileges and one capability, CAP_NET_BIND_SERVICE, for bootstrap mode's setup wizard on ports 80/443. Root is left only in dnshived-helper and keepalived.
- Everything dnshived still did as root goes through the helper: bringing a beacon interface up (`link-up`), removing orphan DHCP gate rules (the orphan sweep called nftables directly even with a helper), enabling/stopping the web UI, helper and probe units at adopt, stopping units and clearing the helper's state at self-decommission, and scheduling the restart into bootstrap mode. A failed `link-up` is logged instead of ignored.
- The emergency gate close on stop (ExecStopPost) runs with full privileges, so its direct nftables fallback keeps working.
- Direct mode (no helper socket) is gone; the helper is always used. The daemon unit no longer needs write access to /proc/sys.
- keepalived (scope and mgmt units) keeps root but only the capabilities it uses, plus NoNewPrivileges. dnshived-helper gets NoNewPrivileges; limiting its capabilities waits for an RHEL test (restorecon).
- dnsmasq runs as dnshived from the start (never root), with only CAP_NET_BIND_SERVICE, CAP_NET_ADMIN and CAP_NET_RAW; its lease script runs as dnshived too. Under SELinux, root inside dnsmasq_t has no dac_override and could not read the dnshived-owned configs.
- /run/dnshived is group-writable for dnshived with the sticky bit, so the daemon can create its lease socket but cannot replace keepalived's PID files.
- dnshived-web-helper and dnshived-probe-helper no longer reset /run/dnshived to 755 on start (that undid the sticky group-writable mode, so dnshived could not recreate its lease socket after a web-helper start).
- dnshived-relay and dnshived-probe drop CAP_NET_RAW: binding a socket to an interface needs no capability since Linux 5.7, and every supported OS has 5.14 or newer.
- dnshived-web-helper keeps root but no capabilities at all (its only command is restarting dnshived-web), plus NoNewPrivileges and a read-only system.
- keepalived and dnsmasq units no longer set NoNewPrivileges: under SELinux it blocks their transition into keepalived_t/dnsmasq_t, so keepalived could not open VRRP sockets and dnsmasq did not start (found on CentOS Stream 9). Their capability limits stay.
- The pre-onboarding interface match never detected any trunk on a running cluster: its listener used UDP 9446, which the topology beacons already hold on every trunk, and the bind error was swallowed. Interface probes now use UDP 9448, and a failed listen is logged.
- Replace/onboard is refused (HTTP 409, nothing changed) when the interface check hears no candidate interface on a trunk; the web UI's Pending changes page offers an explicit "onboard anyway" checkbox for the commit.
- RPM binaries report the same version string as the .deb (VERSION-N+HASH); the different format made the pre-onboarding check report a version mismatch between identical builds.
- Onboard and replace store the node's real interface names: the pre-onboarding interface match (the candidate's broadcast bursts heard on the cluster's trunks) is saved per node, as founding already did; a replace drops the old node's entries. The management interface gets a per-node name too, taken from the interface the cluster reaches the candidate on.
- relay.json was written with the cluster's interface names even on a node whose names differ (the change check used the resolved names), so the relay could bind the wrong interfaces.
- RPM/SELinux: the lease file and dnsmasq log in /var/lib/dnshived get dnsmasq_lease_t/dnsmasq_var_log_t; dnsmasq_t could not write them (var_lib_t), so central DHCP could not start on RHEL-family.
- A scope VLAN that already exists under another name (same VLAN ID on the same NIC, e.g. ens19.110 after the node's names resolve to eth1) is removed and recreated under the right name instead of failing with "VLAN device already exists".
- Every node resolves configured interface names to the kernel name (a kernel altname such as ens19 on a host booted with net.ifnames=0 now maps to eth1) before using them for keepalived, beacons, rp_filter and sockets; before, `ip` accepted the altname while the rest failed.
- Self-decommission and the orphan sweep could not delete VLAN interfaces on a node whose interface names differ from the cluster's: they passed the cluster's trunk name to the helper, which then deleted a non-existent ens19.110 instead of eth1.110 and reported success.
- Self-decommission empties /var/lib/dnshived instead of failing to delete the directory itself (the non-root daemon may not remove it), and no longer asks the helper to stop the dnsmasq@ template unit.
- RPM upgrade restarts only running units: it never restarted a running web UI (it kept serving the old binary) and started the probe pair on core nodes.
- RPM: the post-install script called /usr/bin/dnshived-preflight, but the package installs to /usr/local/bin. The script aborted there, so an RPM install never set the SELinux file contexts or enabled/started any service, while dnf still reported success.
- dnshived-probe-helper and dnshived-probe-vlans@ keep root only with the capabilities they use, plus NoNewPrivileges.

## 0.9.8.3 — released
Bugfix and cleanup release. A disabled scope is shown as disabled everywhere instead of looking active; removing a scope no longer leaves phantom unreachable scope paths; Overview checks the web UI node's own services; the Scopes list no longer wraps. Comments across the code, build and packaging files shrunk (no code change), documentation brought up to date, README screenshots.

Not yet verified on a fresh founding (planned next): the 0.9.8.2 first-login, DNS-relay and discovered-node fixes.

- A disabled scope is shown as disabled everywhere instead of looking active. The daemon status lists it in a new `disabled_scopes` field. The scopes list (web and -top) shows "disabled", Overview counts it as "N disabled" instead of serving, its probe cells read "scope disabled", and the Probes line says "not probed (scope disabled)" apart from "probe switched off". Pending changes warns that the scope will be disabled and labels its rendered DHCP lines as not relayed.
- Removing a scope no longer leaves phantom "unreachable" scope paths behind on some nodes (a beacon reply still in flight re-created the removed pairing), which showed as "Cluster paths: min trust 0%, N down".
- Scopes list: Pool and Probe cells no longer wrap; the "scope disabled" explanation is a tooltip.
- The result page after disabling/enabling or deleting a scope links back to the page you came from (Scopes list or the scope page).
- Overview's daemon check includes the node serving the web UI itself (it was skipped, so the VIP holder's own services were never checked).
- Code cleanup: comments in every remaining Go file (326 files, incl. the web UI's embedded JS/CSS) shrunk to the minimum. Go sources shrink from 4.67 MB to 2.94 MB. No code change.
- README: screenshots of the web UI (Overview, Cluster paths, Scopes).
- Changelog trimmed to 0.9.8 and later; older history stays in git.
- README and INSTALL point to v0.9.8.2 instead of the pulled v0.9.8; INSTALL drops references to lab-only scripts and outdated per-scope dnsmasq wording.
- docs: ROADMAP_0.9.7.md removed; its lasting reasoning (DHCP gate, dead-daemon gate closure, total node death, probe hosts, lease state) moved into DESIGN_DECISIONS.md. FREEZE.md updated to the current code: roles core-1/2/3, the five-condition predicate, real install paths, the current install/upgrade routine.
- docs: ARCHITECTURE, RECOVERY, SECURITY, OPERATIONS and COOKBOOK rewritten against the current code: three symmetric cores instead of arbiter roles, recovery through the web UI's onboard/replace/backup instead of hand-copied config, the current token roles and auth-exempt endpoints, the real dnshived-top key map, no lab addresses or unpublished scripts. Obsolete recipes dropped (synthetic test deploys, manual loopback addresses).
- docs: OS_COMPATIBILITY, SCOPE_LIFECYCLE, TALK, tools/README and tools/snmp/README updated (no lab inventory or addresses, current build and hot-reload facts, SNMP credentials file set up by hand); CLAUDE.md doc pointers and key-file list brought up to date.
- Comments in the build, packaging and helper-script files (Makefile, debian/, rpm spec, systemd units, tools/ scripts) shrunk to the minimum. No functional change.

Known open: with every scope disabled, Overview flags dnshived-relay and dnshived-dnsrelay as inactive/dead, although the daemon stops them on purpose when no scope is eligible.

## 0.9.8.2 — released
Bugfix release for five findings from a fresh-cluster run of 0.9.8.1.
- The first Overview after founding no longer shows the node itself as NODE DOWN: a refused connection no longer marks a node dead, and one failed request is counted once.
- The DNS relay is no longer reported as a daemon issue while no scope exists.
- Config validation rejects a scope VIP equal to the management VIP or to another scope's VIP.
- A just-joined node or probe host no longer stays listed as discovered.
- Lease sync between cores works: `/api/v1/leasesync/fingerprint` and `/snapshot` got HTTP 401 from every peer, so catch-up on join and the periodic cross-node check never ran. Both are now gated by trusted_hosts only, like the lease push endpoint.
- Comments in the touched files shrunk to the minimum, no code change.

## 0.9.8.1 — released
Bugfix release for the pulled 0.9.8, from a fresh 4-VM Debian 13 install and repeated fresh-cluster runs.

**Upgrade note: dry-run is gone. A cluster that is in dry-run today starts serving real DHCP/DNS as soon as this release is installed.**

Install and packaging
- New `dnshived-preflight` runs at install time: checks required binaries and stops/masks the distro's own `dnsmasq.service`, which wildcard-binds port 53. A failed check aborts the install with a clear message. Only a wildcard bind on 53 is flagged, not dnshived's own listeners.
- `dnshived-probe` and `dnshived-probe-helper` run as the `dnshived` account (they hardcoded a non-existent `admin` user); `probe.json` is group-readable by `dnshived`.
- docs/INSTALL.md recommends `dnsmasq-base`, not `dnsmasq`.
- `dnshived-web` and `dnshived-web-helper` keep running across a package upgrade.
- Probe, probe-helper and per-scope dnsmasq units have a restart limit (10 in 5 minutes).
- One join code per fresh host, valid for either role, in `/run/dnshived-bootstrap/otp` (no longer in /tmp).
- `dnshived-web -reset-user` leaves `webui-users.json` readable by the web UI (0640, group `dnshived`).

Founding and onboarding
- A founded cluster enables privilege separation by default (`helper_socket` set); the field is no longer editable in the web UI.
- Founding derives the probe host's TLS setting from the core config, so a probe adopted at founding can fetch its configuration.
- Founding fills the probe's `trunk_parents`, and the probe helper reads them from `probe.json` live.
- New /24 scopes get suggested defaults: VIP .254, gateway .1, DHCP pool .200-.250, upstream 1.1.1.1 and 8.8.8.8. Other prefix lengths are left to the operator.
- Onboarding no longer restarts dnshived on the existing cores, keeps a configured member that is currently down, and no longer shows healthy peers as UNREACHABLE right after a start.
- A bare address without a port gets the convention port (daemon and web forms).
- An unreachable node can be force-removed from membership, behind a second confirmation.

Decommission
- A decommissioned node no longer stays "alive" on the survivors (backup-path results and trust scores cleared).
- A decommission reaches every surviving node, and re-onboarding at an old address re-adds the peer everywhere. Overview warns when nodes disagree on membership.

Network plane
- VLAN construction brings the parent trunk up first (helper, probe helper and direct mode).
- `rp_filter=0` on trunk parents (the units may write `/proc/sys/net/ipv4/conf`), so Debian 13 nodes see topology beacons on their trunks; a TRUNK PATH coherence warning names the likely cause.
- Topology beacons start on trunks added at runtime, without a restart.
- Core nodes agree on a scope's owner after a restart (observed lease holder, not own history).
- Probe coverage for untagged scopes (vlan_id 0).

DHCP and DNS
- dry-run removed: every node always serves; a legacy `dry_run` key is stripped on load (docs/FREEZE.md updated, contract break).
- Central DHCP renders option 54 (the scope VIP) and option 6 (every configured core's address) explicitly, and the relay keeps option 54 at the VIP, so renewals survive a failover.
- The probe accepts the scope VIP as a legitimate DHCP server: no false ROGUE DHCP.
- The dead per-scope `upstream` field is removed everywhere; the cluster-wide upstream stays.
- VIP, gateway, node_ip and DHCP range may not be a subnet's network or broadcast address.

Web UI
- Saving a change no longer drops the management VIP: keepalived-mgmt is reloaded only when its config changed, and a VIP change moves the address without a fresh election. `vip_host` follows the VIP live, and the Saving page finds the UI at the new VIP.
- Ports 80/443 redirect to the web UI (`CAP_NET_BIND_SERVICE` only, never root).
- The wizard no longer suggests the network address as VIP.
- Inline "probe now" button on the Probes tab.
- Cluster paths lists VLAN paths under their trunk, collapsed, with an unreachable count.

## 0.9.8 — released
Full node symmetry (core-1/core-2/core-3) and 2-of-3 arbiter quorum closing the arbiter single-point-of-failure — any one node, including the one holding the mgmt VIP, can now be lost without interrupting DHCP/DNS. A step-by-step founding/onboarding wizard replaces manual `cluster.json` editing. Automated encrypted backups with peer replication. DNS relay replaces DNAT. Decommission hardening and orphan-scope sweeping on both core nodes and probe hosts. A PSK-signed per-scope liveness beacon with shared live-address resolution. A cluster-settings save no longer restarts every node at once with no sequencing — most settings apply live, and the few that still need a restart do so one node at a time with a pre-commit warning. A preferred worker now holds instead of immediately reclaiming a scope a peer is already serving, unless an operator explicitly approves the rebalance. Real RPM packaging alongside the `.deb`, verified end to end on CentOS Stream 9 and Rocky Linux 9. `dnshived-top`/`dnshived-status` can read connection defaults from `~/.dnshived/rc` instead of repeating flags every run.
